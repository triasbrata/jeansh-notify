import { afterAll, beforeAll, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import worker, { type Env, type ServiceAccount, signJwt } from "./index";

const TOKEN_URL = "https://oauth2.googleapis.com/token";
const FCM_URL = "https://fcm.googleapis.com/v1/projects/test-project/messages:send";
const P256 = { name: "ECDSA", namedCurve: "P-256" };
const HOST = "1788717544349041";

let rsa: CryptoKeyPair;
let sa: ServiceAccount;
let env: Env;
let kv: Map<string, string>;
let ttls: Map<string, number>;
let fcmCalls: { auth: string | null; body: any }[];
let fcmReply: () => Response;

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const sha256 = (data: string | Uint8Array) => new Bun.CryptoHasher("sha256").update(data);
const hex = (s: string) => sha256(s).digest("hex");
const unb64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const pem = (der: Uint8Array) =>
	`-----BEGIN PRIVATE KEY-----\n${b64(der).replace(/.{64}/g, "$&\n")}\n-----END PRIVATE KEY-----\n`;
const hostKeys = () => [...kv.keys()].filter((k) => k.startsWith("k:"));

function verifyJwt(jwt: string) {
	const [head, claims, sig] = jwt.split(".");
	return crypto.subtle.verify(
		"RSASSA-PKCS1-v1_5",
		rsa.publicKey,
		unb64url(sig ?? ""),
		new TextEncoder().encode(`${head}.${claims}`),
	);
}

// What FCM answers when it refuses a message.
const fcmError = (status: number, errorCode: string) => () =>
	Response.json(
		{
			error: {
				code: status,
				message: "raw FCM words",
				status: "SOMETHING",
				details: [{ "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", errorCode }],
			},
		},
		{ status },
	);

function limiter(max: number) {
	const seen = new Map<string, number>();
	return {
		async limit({ key }: { key: string }) {
			seen.set(key, (seen.get(key) ?? 0) + 1);
			return { success: seen.get(key)! <= max };
		},
	};
}

beforeAll(async () => {
	rsa = (await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	sa = {
		project_id: "test-project",
		client_email: "relay@test-project.iam.gserviceaccount.com",
		private_key: pem(new Uint8Array((await crypto.subtle.exportKey("pkcs8", rsa.privateKey)) as ArrayBuffer)),
	};

	// Google and FCM. The token endpoint, like Google's, only takes a JWT signed
	// by the service account's key.
	globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
		const url = String(input);
		if (url === TOKEN_URL) {
			const form = new URLSearchParams(String(init?.body));
			const ok =
				form.get("grant_type") === "urn:ietf:params:oauth:grant-type:jwt-bearer" &&
				(await verifyJwt(form.get("assertion") ?? ""));
			return ok ? Response.json({ access_token: "ya29.test", expires_in: 3599 }) : new Response("no", { status: 400 });
		}
		if (url === FCM_URL) {
			fcmCalls.push({ auth: new Headers(init?.headers).get("authorization"), body: JSON.parse(String(init?.body)) });
			return fcmReply();
		}
		throw new Error(`unexpected fetch ${url}`);
	}) as unknown as typeof fetch;
});

beforeEach(() => {
	kv = new Map();
	ttls = new Map();
	fcmCalls = [];
	fcmReply = () => Response.json({ name: "projects/test-project/messages/1" });
	directStatus = 200;
	env = {
		FCM_SERVICE_ACCOUNT: JSON.stringify(sa),
		KEYS: {
			get: async (k) => kv.get(k) ?? null,
			put: async (k, v, o) => {
				kv.set(k, v);
				if (o) ttls.set(k, o.expirationTtl);
			},
			delete: async (k) => void kv.delete(k),
		},
		REGISTER_LIMIT: limiter(10),
		SEND_LIMIT: limiter(30),
	};
});

const call = (method: string, path: string, init: { headers?: Record<string, string>; body?: string } = {}) =>
	worker.fetch(new Request(`https://jeansh-notify.brata.cloud${path}`, { method, ...init }), env);

type Key = { id: string; pair: CryptoKeyPair; spki: Uint8Array; pkcs8: Uint8Array };

// A key pair the way the phone makes one, with its id worked out from the spec.
async function newKey(): Promise<Key> {
	const pair = (await crypto.subtle.generateKey(P256, true, ["sign", "verify"])) as CryptoKeyPair;
	const spki = new Uint8Array((await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer);
	const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
	return { id: "jnk_" + sha256(spki).digest("base64url").slice(0, 32), pair, spki, pkcs8 };
}

const register = (fields: object, ip = "203.0.113.7") =>
	call("POST", "/v1/register", {
		headers: { "cf-connecting-ip": ip, "content-type": "application/json" },
		body: JSON.stringify(fields),
	});

// A key registered for host, with FCM's dry run forgotten.
async function registered(host = HOST, token = "fcm-token-1") {
	const key = await newKey();
	expect((await register({ token, publicKey: b64(key.spki), host })).status).toBe(200);
	fcmCalls = [];
	return key;
}

// SNAP's yyyy-MM-ddTHH:mm:ssTZD, at a UTC offset of hours.
function snapTime(ms = Date.now(), hours = 7) {
	const local = new Date(ms + hours * 3600_000).toISOString().slice(0, 19);
	return `${local}${hours < 0 ? "-" : "+"}${String(Math.abs(hours)).padStart(2, "0")}:00`;
}

// WebCrypto's r‖s as the DER openssl writes: SEQUENCE { INTEGER r, INTEGER s }.
function toDer(raw: Uint8Array) {
	const int = (half: Uint8Array) => {
		let i = 0;
		while (i < 31 && half[i] === 0) i++;
		const v = [...half.subarray(i)];
		if (v[0]! & 0x80) v.unshift(0);
		return [0x02, v.length, ...v];
	};
	const seq = [...int(raw.subarray(0, 32)), ...int(raw.subarray(32))];
	return new Uint8Array([0x30, seq.length, ...seq]);
}

type Options = {
	body?: string;
	time?: string;
	id?: string;
	/** The body sent, when it isn't the one signed. */
	sent?: string;
	/** The X-PARTNER-ID sent, when it isn't the signing key's. */
	as?: string;
	/** The METHOD:PATH signed, when it isn't the one called. */
	signs?: string;
};

// The headers and body of a request signed SNAP-style with key.
async function sign(key: Key, method: string, path: string, o: Options = {}) {
	const body = o.body ?? "";
	const time = o.time ?? snapTime();
	const id = o.id ?? crypto.randomUUID();
	const text = `${o.signs ?? `${method}:${path}`}:${hex(body)}:${time}:${id}`;
	const raw = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.pair.privateKey, new TextEncoder().encode(text));
	return {
		headers: {
			"x-partner-id": o.as ?? key.id,
			"x-timestamp": time,
			"x-external-id": id,
			"x-signature": b64(toDer(new Uint8Array(raw))),
			"content-type": "application/json",
		},
		body: (o.sent ?? body) || undefined,
	};
}

const signed = async (key: Key, method: string, path: string, o: Options = {}) =>
	call(method, path, await sign(key, method, path, o));
const send = (key: Key, fields: unknown, o: Options = {}) =>
	signed(key, "POST", "/v1/send", { body: JSON.stringify(fields), ...o });
const revoke = (key: Key, o: Options = {}) => signed(key, "DELETE", "/v1/key", o);
const error = async (res: Response | Promise<Response>) => {
	const r = await res;
	return [r.status, ((await r.json()) as { error: string }).error];
};

const message = (data: Record<string, string>) => ({
	message: {
		token: "fcm-token-1",
		data,
		notification: { title: data.title, body: data.body },
		android: { priority: "high" },
	},
});

test("register dry-runs the token with FCM and stores the public key under its key id", async () => {
	const key = await newKey();
	const res = await register({ token: "fcm-token-1", publicKey: b64(key.spki), host: HOST });
	expect(res.status).toBe(200);
	expect((await res.json()) as object).toEqual({ keyId: key.id });
	expect(key.id).toMatch(/^jnk_[A-Za-z0-9_-]{32}$/);
	expect(fcmCalls).toEqual([
		{ auth: "Bearer ya29.test", body: { validate_only: true, message: { token: "fcm-token-1" } } },
	]);
	expect([...kv.keys()]).toEqual([`k:${key.id}`]);
	expect(JSON.parse(kv.get(`k:${key.id}`)!)).toEqual({
		publicKey: b64(key.spki),
		token: "fcm-token-1",
		host: HOST,
		created: expect.any(String),
	});
});

test("registering the same key again answers the same id and takes the new token", async () => {
	const key = await registered(HOST, "old-token");
	const res = await register({ token: "new-token", publicKey: b64(key.spki), host: HOST });
	expect((await res.json()) as object).toEqual({ keyId: key.id });
	expect([...kv.keys()]).toEqual([`k:${key.id}`]);
	expect(JSON.parse(kv.get(`k:${key.id}`)!).token).toBe("new-token");
});

test("register refuses a public key that isn't an ECDSA P-256 SPKI, before FCM", async () => {
	const key = await newKey();
	const p384 = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign"])) as CryptoKeyPair;
	const spki = async (k: CryptoKey) => b64(new Uint8Array((await crypto.subtle.exportKey("spki", k)) as ArrayBuffer));
	for (const publicKey of [
		undefined,
		5,
		"",
		"not base64!",
		await spki(p384.publicKey),
		await spki(rsa.publicKey),
		b64(key.pkcs8),
		b64(key.spki.subarray(0, 90)),
		b64(crypto.getRandomValues(new Uint8Array(91))),
	]) {
		expect(await error(register({ token: "fcm-token-1", publicKey, host: HOST }))).toEqual([
			400,
			"publicKey must be the base64 SPKI DER of an ECDSA P-256 key",
		]);
	}
	expect(fcmCalls).toEqual([]);
	expect(kv.size).toBe(0);
});

test("register refuses a missing token or host without asking FCM", async () => {
	const publicKey = b64((await newKey()).spki);
	for (const body of [
		{ publicKey, host: HOST },
		{ token: 5, publicKey, host: HOST },
		{ token: "", publicKey, host: HOST },
		{ token: "t", publicKey },
		{ token: "t", publicKey, host: "" },
		{ token: "t", publicKey, host: "x".repeat(101) },
		null,
		"nope",
	]) {
		expect((await register(body as object)).status).toBe(400);
	}
	expect((await call("POST", "/v1/register", { body: "{" })).status).toBe(400);
	expect(fcmCalls).toEqual([]);
	expect(kv.size).toBe(0);
});

test("register refuses a token FCM calls invalid and stores nothing", async () => {
	const publicKey = b64((await newKey()).spki);
	for (const reply of [fcmError(400, "INVALID_ARGUMENT"), fcmError(404, "UNREGISTERED")]) {
		fcmReply = reply;
		expect(await error(register({ token: "not-a-token", publicKey, host: HOST }))).toEqual([
			400,
			"FCM does not accept this token",
		]);
	}
	expect(kv.size).toBe(0);
});

test("register is rate-limited per client IP", async () => {
	const fields = { token: "t", publicKey: b64((await newKey()).spki), host: HOST };
	for (let i = 0; i < 10; i++) expect((await register(fields, "203.0.113.7")).status).toBe(200);
	expect((await register(fields, "203.0.113.7")).status).toBe(429);
	expect((await register(fields, "203.0.113.8")).status).toBe(200);
});

test("send pushes the old tool's FCM message, with hostId from the key and never from the body", async () => {
	const key = await registered();
	const res = await send(key, { title: "Build", body: "build done", host: "evil", hostId: "evil" });
	expect(res.status).toBe(200);
	expect((await res.json()) as object).toEqual({ ok: true });
	expect((await send(key, { body: "  done  ", title: " " })).status).toBe(200);
	expect(fcmCalls).toStrictEqual([
		{ auth: "Bearer ya29.test", body: message({ hostId: HOST, title: "Build", body: "build done" }) },
		{ auth: "Bearer ya29.test", body: message({ hostId: HOST, title: "Jeansh", body: "done" }) },
	]);
});

test("a signature made by the openssl CLI verifies", async () => {
	const key = await registered();
	const dir = mkdtempSync(join(tmpdir(), "jeansh-test-"));
	try {
		writeFileSync(join(dir, "key.pem"), pem(key.pkcs8), { mode: 0o600 });
		const body = JSON.stringify({ title: "Build", body: "signed by openssl" });
		const time = snapTime();
		const id = crypto.randomUUID();
		const openssl = Bun.spawnSync(["openssl", "dgst", "-sha256", "-sign", join(dir, "key.pem")], {
			stdin: new TextEncoder().encode(`POST:/v1/send:${hex(body)}:${time}:${id}`),
		});
		expect(openssl.exitCode).toBe(0);
		const headers = { "x-partner-id": key.id, "x-timestamp": time, "x-external-id": id };
		const res = await call("POST", "/v1/send", { headers: { ...headers, "x-signature": b64(openssl.stdout) }, body });
		expect(res.status).toBe(200);
		expect(fcmCalls.map((c) => c.body.message.data.body)).toEqual(["signed by openssl"]);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("a signature whose r or s is shorter than 32 bytes verifies", async () => {
	const key = await registered();
	// One signature in about 128 has an r or s starting with a zero byte, which
	// DER then writes shorter.
	for (let i = 0; i < 5000; i++) {
		const req = await sign(key, "POST", "/v1/send", { body: '{"body":"short"}' });
		const der = Uint8Array.from(atob(req.headers["x-signature"]), (c) => c.charCodeAt(0));
		if (der[3]! >= 32 && der[5 + der[3]!]! >= 32) continue;
		expect((await call("POST", "/v1/send", req)).status).toBe(200);
		return;
	}
	throw new Error("no short signature in 5000 tries");
});

test("a signed request is checked for its key, then its time, then its signature, then its external id", async () => {
	const key = await registered();
	const stale = snapTime(Date.now() - 305_000);
	expect(await error(call("POST", "/v1/send", { body: '{"body":"hi"}' }))).toEqual([401, "unknown key"]);
	expect(await error(send(await newKey(), { body: "hi" }, { time: stale, sent: "x" }))).toEqual([401, "unknown key"]);
	expect(await error(send(key, { body: "hi" }, { time: stale, sent: "x" }))).toEqual([401, "stale or bad timestamp"]);
	const id = crypto.randomUUID();
	expect((await send(key, { body: "hi" }, { id })).status).toBe(200);
	expect(await error(send(key, { body: "hi" }, { id, sent: "x" }))).toEqual([401, "bad signature"]);
	expect(await error(send(key, { body: "hi" }, { id }))).toEqual([409, "duplicate X-EXTERNAL-ID"]);
	expect(fcmCalls.length).toBe(1);
});

test("any change to a signed request is 401 bad signature, before FCM", async () => {
	const key = await registered();
	const other = await registered("other-host", "fcm-token-2");
	const good = await sign(key, "POST", "/v1/send", { body: '{"body":"hi"}' });
	const raw = new Uint8Array(64).fill(7);
	for (const res of [
		send(key, { body: "ls" }, { sent: JSON.stringify({ body: "rm" }) }),
		send(key, { body: "hi" }, { sent: JSON.stringify({ body: "hi" }) + " " }),
		send(other, { body: "hi" }, { as: key.id }),
		send(key, { body: "hi" }, { signs: "DELETE:/v1/key" }),
		call("POST", "/v1/send", { ...good, headers: { ...good.headers, "x-signature": "" } }),
		call("POST", "/v1/send", { ...good, headers: { ...good.headers, "x-signature": "not base64!" } }),
		call("POST", "/v1/send", { ...good, headers: { ...good.headers, "x-signature": b64(raw) } }),
	]) {
		expect(await error(res)).toEqual([401, "bad signature"]);
	}
	expect(fcmCalls).toEqual([]);
	expect((await call("POST", "/v1/send", good)).status).toBe(200);
});

test("a timestamp more than 300 s off, or not in SNAP's format, is 401", async () => {
	const key = await registered();
	const now = Date.now();
	for (const time of [
		snapTime(now - 305_000),
		snapTime(now + 305_000),
		snapTime(now, 0).replace("+00:00", ""),
		snapTime(now).replace("+07:00", "+0700"),
		snapTime(now).replace("T", " "),
		String(Math.floor(now / 1000)),
		"yesterday",
		"",
	]) {
		expect(await error(send(key, { body: "hi" }, { time }))).toEqual([401, "stale or bad timestamp"]);
	}
	for (const time of [
		snapTime(now),
		snapTime(now - 290_000),
		snapTime(now + 290_000),
		snapTime(now, -5),
		snapTime(now, 0),
		new Date(now).toISOString(),
	]) {
		expect((await send(key, { body: "hi" }, { time })).status).toBe(200);
	}
});

test("a replayed request is 409, and external ids are kept per key for 10 minutes", async () => {
	const a = await registered();
	const b = await registered("other-host", "fcm-token-2");
	const id = "build-1788717544-a1b2";
	const req = await sign(a, "POST", "/v1/send", { body: '{"body":"hi"}', id });
	expect((await call("POST", "/v1/send", req)).status).toBe(200);
	expect(await error(call("POST", "/v1/send", req))).toEqual([409, "duplicate X-EXTERNAL-ID"]);
	expect(ttls.get(`n:${a.id}:${id}`)).toBe(600);
	expect((await send(b, { body: "hi" }, { id })).status).toBe(200);
	expect(fcmCalls.length).toBe(2);
});

test("X-EXTERNAL-ID must be 16 to 64 characters of A-Z, a-z, 0-9 and -", async () => {
	const key = await registered();
	for (const id of ["", "x".repeat(15), "x".repeat(65), "has space 123456", "under_score_12345", "dot.ted.12345678"]) {
		expect((await send(key, { body: "hi" }, { id })).status).toBe(400);
	}
	for (const id of ["x".repeat(16), "X-y-Z-0123456789".repeat(4)]) {
		expect((await send(key, { body: "hi" }, { id })).status).toBe(200);
	}
});

test("send answers 400 for bad input, before FCM", async () => {
	const key = await registered();
	for (const fields of [
		{},
		{ body: "   " },
		{ body: "x".repeat(1001) },
		{ body: "hi", title: "x".repeat(101) },
		{ body: 5 },
		{ body: "hi", title: 5 },
		["body"],
		null,
	]) {
		expect((await send(key, fields)).status).toBe(400);
	}
	expect((await signed(key, "POST", "/v1/send", { body: "{" })).status).toBe(400);
	expect((await signed(key, "POST", "/v1/send")).status).toBe(400);
	expect(fcmCalls).toEqual([]);
	expect((await send(key, { body: "x".repeat(1000), title: "x".repeat(100) })).status).toBe(200);
	expect((await send(key, { body: "hi", title: null })).status).toBe(200);
});

test("signed requests are rate-limited per key, after the external id is checked", async () => {
	const a = await registered();
	const b = await registered("other-host", "fcm-token-2");
	const id = crypto.randomUUID();
	expect((await send(a, { body: "hi" }, { id })).status).toBe(200);
	for (let i = 1; i < 30; i++) expect((await send(a, { body: "hi" })).status).toBe(200);
	expect((await send(a, { body: "hi" })).status).toBe(429);
	expect((await send(a, { body: "hi" }, { id })).status).toBe(409);
	expect((await revoke(a)).status).toBe(429);
	expect((await send(b, { body: "hi" })).status).toBe(200);
});

test("send answers 410 and deletes the key when FCM says the token is unregistered", async () => {
	const key = await registered();
	fcmReply = fcmError(404, "UNREGISTERED");
	expect((await send(key, { body: "hi" })).status).toBe(410);
	expect(hostKeys()).toEqual([]);
	expect(await error(send(key, { body: "hi" }))).toEqual([401, "unknown key"]);
});

test("send answers 502 for other FCM failures, without FCM's own words", async () => {
	const key = await registered();
	fcmReply = fcmError(500, "INTERNAL");
	const res = await send(key, { body: "hi" });
	expect(res.status).toBe(502);
	const text = await res.text();
	expect(text).not.toContain("raw FCM words");
	expect(JSON.parse(text)).toEqual({ error: "FCM returned HTTP 500 INTERNAL" });
	expect(hostKeys()).toEqual([`k:${key.id}`]);
});

test("a DELETE /v1/key signed with the key revokes it, and nothing else can", async () => {
	const key = await registered();
	const other = await registered("other-host", "fcm-token-2");
	expect((await call("DELETE", "/v1/key")).status).toBe(401);
	expect((await call("DELETE", "/v1/key", { headers: { authorization: `Bearer ${key.id}` } })).status).toBe(401);
	expect(await error(revoke(other, { as: key.id }))).toEqual([401, "bad signature"]);
	expect(await error(revoke(key, { signs: "POST:/v1/send" }))).toEqual([401, "bad signature"]);
	expect(hostKeys().sort()).toEqual([`k:${key.id}`, `k:${other.id}`].sort());

	const res = await revoke(key);
	expect(res.status).toBe(204);
	expect(await res.text()).toBe("");
	expect(hostKeys()).toEqual([`k:${other.id}`]);
	expect(await error(send(key, { body: "hi" }))).toEqual([401, "unknown key"]);
	expect(await error(revoke(key))).toEqual([401, "unknown key"]);
});

test("the old Authorization: Bearer key is gone, and anything else is 404", async () => {
	const key = await registered();
	const bearer = { headers: { authorization: `Bearer ${key.id}` }, body: '{"body":"hi"}' };
	expect(await error(call("POST", "/v1/send", bearer))).toEqual([401, "unknown key"]);
	for (const [method, path] of [
		["GET", "/v1/send"],
		["GET", "/"],
		["POST", "/v1/keys"],
		["PUT", "/v1/key"],
		["DELETE", "/v1/register"],
	] as const) {
		expect(await error(call(method, path))).toEqual([404, "not found"]);
	}
	expect(fcmCalls).toEqual([]);
});

test("the service-account JWT carries a verifiable RS256 signature", async () => {
	const jwt = await signJwt(sa, 1_700_000_000);
	expect(await verifyJwt(jwt)).toBe(true);

	const [head, claims, sig] = jwt.split(".") as [string, string, string];
	const decode = (part: string) => JSON.parse(new TextDecoder().decode(unb64url(part)));
	expect(decode(head)).toEqual({ alg: "RS256", typ: "JWT" });
	expect(decode(claims)).toEqual({
		iss: sa.client_email,
		scope: "https://www.googleapis.com/auth/firebase.messaging",
		aud: TOKEN_URL,
		iat: 1_700_000_000,
		exp: 1_700_003_600,
	});
	const forged = btoa(JSON.stringify({ ...decode(claims), iss: "someone@else" })).replace(/=+$/, "");
	expect(await verifyJwt(`${head}.${forged}.${sig}`)).toBe(false);
});

// notify.sh, against one local server standing in for both the app's forwarded
// port (/direct/...) and the relay, which is this Worker in front of fake FCM.
let directStatus = 200;
const hits: { path: string; headers: Record<string, string>; fields?: Record<string, string> }[] = [];
const server = Bun.serve({
	hostname: "127.0.0.1",
	port: 0,
	async fetch(req) {
		const path = new URL(req.url).pathname;
		const headers = Object.fromEntries(req.headers.entries());
		if (!path.startsWith("/direct/")) {
			hits.push({ path, headers });
			return worker.fetch(req, env);
		}
		hits.push({ path, headers, fields: Object.fromEntries(new URLSearchParams(await req.text())) });
		return new Response("{}", { status: directStatus });
	},
});
afterAll(() => server.stop());
const base = `http://127.0.0.1:${server.port}`;

// Runs notify.sh with its own TMPDIR, and lists what it left there.
async function notify(args: string[], vars: Record<string, string>, path = process.env.PATH ?? "/usr/bin:/bin") {
	hits.length = 0;
	const tmp = mkdtempSync(join(tmpdir(), "jeansh-notify-"));
	try {
		const proc = Bun.spawn(["/bin/sh", join(import.meta.dir, "..", "notify.sh"), ...args], {
			env: { PATH: path, TMPDIR: tmp, JEANSH_RELAY: base, ...vars },
			stdout: "pipe",
			stderr: "pipe",
		});
		const [code, out, err] = await Promise.all([
			proc.exited,
			new Response(proc.stdout).text(),
			new Response(proc.stderr).text(),
		]);
		return { code, out, err, left: readdirSync(tmp) };
	} finally {
		rmSync(tmp, { recursive: true, force: true });
	}
}

// What Jeansh passes to host 42's shells.
async function host42() {
	const key = await registered("42");
	const vars = {
		LC_SSHBOX_KEY: `${key.id}:${b64(key.pkcs8)}`,
		LC_SSHBOX_NOTIFY_URL: `${base}/direct/v1/send`,
		LC_SSHBOX_NOTIFY_SECRET: "direct-secret",
	};
	return { key, vars };
}

test("notify.sh goes straight to the app when it answers, with only the direct secret", async () => {
	const { vars } = await host42();
	const r = await notify(["-title", "Build", "build", "done"], vars);
	expect(r).toMatchObject({ code: 0, out: "sshbox-notify: sent directly to Jeansh\n", left: [] });
	expect(hits).toEqual([
		{
			path: "/direct/v1/send",
			headers: expect.objectContaining({ authorization: "Bearer direct-secret" }),
			fields: { body: "build done", title: "Build" },
		},
	]);
	expect(hits[0]!.headers["x-partner-id"]).toBeUndefined();
	expect(fcmCalls).toEqual([]);
});

test("notify.sh falls back to the relay, signed with the host's key, when the app refuses", async () => {
	const { key, vars } = await host42();
	directStatus = 500;
	const r = await notify(["-title=Build", "build done"], vars);
	expect(r).toMatchObject({ code: 0, out: "sshbox-notify: sent through the relay\n", left: [] });
	expect(hits.map((h) => h.path)).toEqual(["/direct/v1/send", "/v1/send"]);
	const relay = hits[1]!.headers;
	expect(relay).toMatchObject({ "x-partner-id": key.id, "content-type": "application/json" });
	expect(relay["x-timestamp"]).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$/);
	expect(relay["x-external-id"]).toMatch(/^[0-9a-f]{32}$/);
	expect(relay.authorization).toBeUndefined();
	expect(fcmCalls.map((c) => c.body.message.data)).toEqual([{ hostId: "42", title: "Build", body: "build done" }]);
});

test("notify.sh falls back when the forwarded port is gone, and escapes any text into JSON", async () => {
	const { vars } = await host42();
	const text = 'say "hi" \\ C:\\path\n\ttabbed \x1b[1mbold\x1b[0m\r é 🚀 %s $HOME `x`\n\nend';
	// Nothing listens on port 1.
	const r = await notify(["-title", 'Deploy "prod"', text], { ...vars, LC_SSHBOX_NOTIFY_URL: "http://127.0.0.1:1/v1/send" });
	expect(r).toMatchObject({ code: 0, out: "sshbox-notify: sent through the relay\n", left: [] });
	expect(hits.map((h) => h.path)).toEqual(["/v1/send"]);
	expect(fcmCalls.map((c) => c.body.message.data)).toEqual([{ hostId: "42", title: 'Deploy "prod"', body: text }]);
});

test("notify.sh fails only when every way failed, and says why the relay refused", async () => {
	const { key, vars } = await host42();
	directStatus = 500;
	fcmReply = fcmError(500, "INTERNAL");
	let r = await notify(["done"], vars);
	expect(r).toMatchObject({ code: 1, out: "", left: [] });
	expect(r.err).toContain('the relay did not take it either: {"error":"FCM returned HTTP 500 INTERNAL"} (HTTP 502)');
	expect(hits.map((h) => h.path)).toEqual(["/direct/v1/send", "/v1/send"]);

	kv.delete(`k:${key.id}`);
	r = await notify(["done"], vars);
	expect(r.code).toBe(1);
	expect(r.err).toContain('{"error":"unknown key"} (HTTP 401)');
});

test("notify.sh says what is missing without LC_SSHBOX_KEY", async () => {
	const r = await notify(["done"], {});
	expect(r.code).toBe(1);
	expect(r.err).toContain("LC_SSHBOX_KEY is not set");
	expect(hits).toEqual([]);
});

test("notify.sh says so when openssl is missing", async () => {
	const { vars } = await host42();
	const r = await notify(["done"], { LC_SSHBOX_KEY: vars.LC_SSHBOX_KEY }, "/nonexistent");
	expect(r.code).toBe(1);
	expect(r.err).toContain("openssl is not installed");
	expect(hits).toEqual([]);
});

test("notify.sh refuses a key openssl can't read, and leaves no key file behind", async () => {
	const r = await notify(["done"], { LC_SSHBOX_KEY: "jnk_x:bm90IGEga2V5" });
	expect(r).toMatchObject({ code: 1, left: [] });
	expect(r.err).toContain("could not sign with LC_SSHBOX_KEY");
	expect(hits).toEqual([]);
});
