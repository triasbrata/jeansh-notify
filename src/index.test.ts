import { beforeAll, beforeEach, expect, test } from "bun:test";
import worker, { type Env, type ServiceAccount, signJwt } from "./index";

const TOKEN_URL = "https://oauth2.googleapis.com/token";
const FCM_URL = "https://fcm.googleapis.com/v1/projects/test-project/messages:send";

let keys: CryptoKeyPair;
let sa: ServiceAccount;
let env: Env;
let kv: Map<string, string>;
let fcmCalls: { auth: string | null; body: any }[];
let fcmReply: () => Response;

const hex = (s: string) => new Bun.CryptoHasher("sha256").update(s).digest("hex");
const unb64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

function verifyJwt(jwt: string) {
	const [head, claims, sig] = jwt.split(".");
	return crypto.subtle.verify(
		"RSASSA-PKCS1-v1_5",
		keys.publicKey,
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
	keys = (await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", keys.privateKey)) as ArrayBuffer);
	const pem = btoa(String.fromCharCode(...der)).replace(/.{64}/g, "$&\n");
	sa = {
		project_id: "test-project",
		client_email: "relay@test-project.iam.gserviceaccount.com",
		private_key: `-----BEGIN PRIVATE KEY-----\n${pem}\n-----END PRIVATE KEY-----\n`,
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
	fcmCalls = [];
	fcmReply = () => Response.json({ name: "projects/test-project/messages/1" });
	env = {
		FCM_SERVICE_ACCOUNT: JSON.stringify(sa),
		KEYS: {
			get: async (k) => kv.get(k) ?? null,
			put: async (k, v) => void kv.set(k, v),
			delete: async (k) => void kv.delete(k),
		},
		REGISTER_LIMIT: limiter(10),
		SEND_LIMIT: limiter(30),
	};
});

const call = (method: string, path: string, init: { headers?: Record<string, string>; body?: string } = {}) =>
	worker.fetch(new Request(`https://jeansh-notify.brata.cloud${path}`, { method, ...init }), env);

const register = (token: string, ip = "203.0.113.7") =>
	call("POST", "/v1/register", {
		headers: { "cf-connecting-ip": ip, "content-type": "application/json" },
		body: JSON.stringify({ token }),
	});

async function keyFor(token = "fcm-token-1") {
	const { key } = (await (await register(token)).json()) as { key: string };
	fcmCalls = [];
	return key;
}

const sendForm = (key: string, fields: Record<string, string>) =>
	call("POST", "/v1/send", {
		headers: { authorization: `Bearer ${key}`, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(fields).toString(),
	});

const sendJson = (key: string, fields: unknown) =>
	call("POST", "/v1/send", {
		headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
		body: JSON.stringify(fields),
	});

test("register dry-runs the token with FCM and stores only a hash of the key", async () => {
	const res = await register("fcm-token-1");
	expect(res.status).toBe(200);
	const { key } = (await res.json()) as { key: string };
	expect(key).toMatch(/^jnk_[A-Za-z0-9_-]{43}$/);
	expect(fcmCalls).toEqual([
		{ auth: "Bearer ya29.test", body: { validate_only: true, message: { token: "fcm-token-1" } } },
	]);
	expect([...kv.keys()]).toEqual([hex(key)]);
	expect(JSON.parse(kv.get(hex(key))!)).toEqual({ token: "fcm-token-1", created: expect.any(String) });
	expect(JSON.stringify([...kv])).not.toContain(key.slice(4));
});

test("register rejects a token FCM calls invalid and stores nothing", async () => {
	for (const reply of [fcmError(400, "INVALID_ARGUMENT"), fcmError(404, "UNREGISTERED")]) {
		fcmReply = reply;
		const res = await register("not-a-token");
		expect(res.status).toBe(400);
		expect((await res.json()) as object).toEqual({ error: expect.any(String) });
	}
	expect(kv.size).toBe(0);
});

test("register rejects a missing token without asking FCM", async () => {
	for (const body of ["{}", '{"token": 5}', '{"token": ""}', "null", "nope"]) {
		const res = await call("POST", "/v1/register", { headers: { "cf-connecting-ip": "203.0.113.7" }, body });
		expect(res.status).toBe(400);
	}
	expect(fcmCalls).toEqual([]);
});

test("register is rate-limited per client IP", async () => {
	for (let i = 0; i < 10; i++) expect((await register("t", "203.0.113.7")).status).toBe(200);
	expect((await register("t", "203.0.113.7")).status).toBe(429);
	expect((await register("t", "203.0.113.8")).status).toBe(200);
});

test("send builds the old tool's FCM message, with and without host, from form and JSON", async () => {
	const key = await keyFor("fcm-token-1");
	const message = (data: Record<string, string>) => ({
		message: {
			token: "fcm-token-1",
			data,
			notification: { title: data.title, body: data.body },
			android: { priority: "high" },
		},
	});
	for (const sendWith of [sendForm, sendJson]) {
		fcmCalls = [];
		const res = await sendWith(key, { host: "1788717544349041", title: "Build", body: "build done" });
		expect(res.status).toBe(200);
		expect((await res.json()) as object).toEqual({ ok: true });
		expect((await sendWith(key, { body: "  done  ", title: " " })).status).toBe(200);
		expect(fcmCalls).toStrictEqual([
			{ auth: "Bearer ya29.test", body: message({ hostId: "1788717544349041", title: "Build", body: "build done" }) },
			{ auth: "Bearer ya29.test", body: message({ title: "Jeansh", body: "done" }) },
		]);
	}
});

test("send answers 401 without a known key, before FCM", async () => {
	expect((await call("POST", "/v1/send", { body: "body=hi" })).status).toBe(401);
	expect((await sendForm("fcm-token-1", { body: "hi" })).status).toBe(401);
	expect((await sendForm("jnk_unknown", { body: "hi" })).status).toBe(401);
	expect(fcmCalls).toEqual([]);
});

test("send answers 400 for bad input, before FCM", async () => {
	const key = await keyFor();
	const bad = [
		await sendForm(key, {}),
		await sendForm(key, { body: "   " }),
		await sendForm(key, { body: "x".repeat(1001) }),
		await sendForm(key, { body: "hi", title: "x".repeat(101) }),
		await sendForm(key, { body: "hi", host: "x".repeat(101) }),
		await sendJson(key, { body: 5 }),
		await sendJson(key, ["body"]),
		await call("POST", "/v1/send", {
			headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
			body: "{",
		}),
	];
	expect(bad.map((r) => r.status)).toEqual(bad.map(() => 400));
	expect(fcmCalls).toEqual([]);
	expect((await sendForm(key, { body: "x".repeat(1000), title: "x".repeat(100) })).status).toBe(200);
});

test("send is rate-limited per key", async () => {
	const a = await keyFor("token-a");
	const b = await keyFor("token-b");
	for (let i = 0; i < 30; i++) expect((await sendForm(a, { body: "hi" })).status).toBe(200);
	expect((await sendForm(a, { body: "hi" })).status).toBe(429);
	expect((await sendForm(b, { body: "hi" })).status).toBe(200);
});

test("send answers 410 and deletes the key when FCM says the token is unregistered", async () => {
	const key = await keyFor();
	fcmReply = fcmError(404, "UNREGISTERED");
	expect((await sendForm(key, { body: "hi" })).status).toBe(410);
	expect(kv.size).toBe(0);
	expect((await sendForm(key, { body: "hi" })).status).toBe(401);
});

test("send answers 502 for other FCM failures, without FCM's own words", async () => {
	const key = await keyFor();
	fcmReply = fcmError(500, "INTERNAL");
	const res = await sendForm(key, { body: "hi" });
	expect(res.status).toBe(502);
	const text = await res.text();
	expect(text).not.toContain("raw FCM words");
	expect(JSON.parse(text)).toEqual({ error: "FCM returned HTTP 500 INTERNAL" });
	expect(kv.size).toBe(1);
});

test("delete is idempotent", async () => {
	const key = await keyFor();
	const del = () => call("DELETE", "/v1/key", { headers: { authorization: `Bearer ${key}` } });
	expect((await del()).status).toBe(204);
	expect(kv.size).toBe(0);
	expect((await del()).status).toBe(204);
	expect((await sendForm(key, { body: "hi" })).status).toBe(401);
	expect((await call("DELETE", "/v1/key")).status).toBe(401);
});

test("anything else is 404", async () => {
	for (const [method, path] of [
		["GET", "/v1/send"],
		["GET", "/"],
		["POST", "/v1/keys"],
		["PUT", "/v1/key"],
	] as const) {
		expect((await call(method, path)).status).toBe(404);
	}
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
