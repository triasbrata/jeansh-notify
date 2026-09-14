// Jeansh push relay.
//
// The app makes a key pair for each host, registers the public key here with
// the phone's FCM token, and hands the private key to that host. The host signs
// each request with it, SNAP-style, and the relay sends the message to the
// phone through FCM HTTP v1, signed in with a service account that servers never
// see. Which host sent it comes from the key, never from the message.

interface Limiter {
	limit(options: { key: string }): Promise<{ success: boolean }>;
}

// The bindings, typed by the methods used, so tests can pass plain fakes.
export interface Env {
	/** The Firebase service account JSON, as text. */
	FCM_SERVICE_ACCOUNT: string;
	/**
	 * k:<keyId> -> Entry, one per host key;
	 * n:<keyId>:<X-EXTERNAL-ID> -> "1", for 10 minutes, the external ids seen.
	 */
	KEYS: {
		get(key: string): Promise<string | null>;
		put(key: string, value: string, options?: { expirationTtl: number }): Promise<void>;
		delete(key: string): Promise<void>;
	};
	/** Keyed by client IP. */
	REGISTER_LIMIT: Limiter;
	/** Keyed by key id. */
	SEND_LIMIT: Limiter;
}

export interface ServiceAccount {
	project_id: string;
	client_email: string;
	private_key: string;
}

type Entry = { publicKey: string; token: string; host: string; created: string };

const SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
// FCM error codes that mean the token itself is no good.
const BAD_TOKEN = ["INVALID_ARGUMENT", "UNREGISTERED", "SENDER_ID_MISMATCH"];
const P256 = { name: "ECDSA", namedCurve: "P-256" };
// SNAP's yyyy-MM-ddTHH:mm:ssTZD, also with milliseconds or Z.
const TIMESTAMP = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{3})?(Z|[+-]\d\d:\d\d)$/;
// How far X-TIMESTAMP may be from now, either way. External ids are kept for
// twice that, so one can't come back while its timestamp is still accepted.
const SKEW = 300;

export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		const route = `${req.method} ${new URL(req.url).pathname}`;
		if (route === "POST /v1/register") return register(req, env);
		if (route === "POST /v1/send") return send(req, env);
		if (route === "DELETE /v1/key") return revoke(req, env);
		return fail(404, "not found");
	},
};

async function register(req: Request, env: Env): Promise<Response> {
	const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
	if (!(await env.REGISTER_LIMIT.limit({ key: ip })).success) return fail(429, "too many requests");

	const { token, publicKey, host } = ((await req.json().catch(() => null)) ?? {}) as Record<string, unknown>;
	if (typeof token !== "string" || !token || token.length > 4096) {
		return fail(400, "token must be an FCM registration token");
	}
	if (typeof host !== "string" || !host || host.length > 100) {
		return fail(400, "host must be a host id of at most 100 characters");
	}
	let der: Uint8Array<ArrayBuffer>;
	try {
		der = unb64(typeof publicKey === "string" ? publicKey : "");
		await importKey(der);
	} catch {
		return fail(400, "publicKey must be the base64 SPKI DER of an ECDSA P-256 key");
	}

	const check = await fcm(env, { validate_only: true, message: { token } });
	if (check.status === 404 || BAD_TOKEN.includes(check.code)) return fail(400, "FCM does not accept this token");
	if (check.status !== 200) return fcmFailed(check);

	// ponytail: whoever holds the public key can re-register it with another
	// token; the key never leaves the phone and the relay, so that is the phone.
	const keyId = "jnk_" + b64url(await digest(der)).slice(0, 32);
	const entry: Entry = { publicKey: b64(der), token, host, created: new Date().toISOString() };
	await env.KEYS.put(`k:${keyId}`, JSON.stringify(entry));
	return json(200, { keyId });
}

async function send(req: Request, env: Env): Promise<Response> {
	const auth = await verified(req, env);
	if (auth instanceof Response) return auth;
	const input = readMessage(auth.body);
	if (typeof input === "string") return fail(400, input);
	const { title, body } = input;
	const { token, host } = auth.entry;

	// The same message the old per-server Go tool sent. The notification half
	// is what Android shows while the app is in the background; the data half
	// survives the tap, so the app can open the host.
	const res = await fcm(env, {
		message: {
			token,
			data: { hostId: host, title, body },
			notification: { title, body },
			android: { priority: "high" },
		},
	});
	if (res.status === 200) return json(200, { ok: true });
	if (res.status === 404 || res.code === "UNREGISTERED") {
		await env.KEYS.delete(`k:${auth.keyId}`);
		return fail(410, "the phone is no longer registered with FCM; this key is deleted");
	}
	return fcmFailed(res);
}

async function revoke(req: Request, env: Env): Promise<Response> {
	const auth = await verified(req, env);
	if (auth instanceof Response) return auth;
	await env.KEYS.delete(`k:${auth.keyId}`);
	return new Response(null, { status: 204 });
}

// The key and body of a request signed SNAP-style, or the answer refusing it.
async function verified(
	req: Request,
	env: Env,
): Promise<{ keyId: string; entry: Entry; body: Uint8Array<ArrayBuffer> } | Response> {
	const header = (name: string) => req.headers.get(name) ?? "";
	const keyId = header("x-partner-id");
	const stored = /^jnk_[\w-]{32}$/.test(keyId) ? await env.KEYS.get(`k:${keyId}`) : null;
	if (!stored) return fail(401, "unknown key");

	const time = header("x-timestamp");
	if (!TIMESTAMP.test(time) || !(Math.abs(Date.parse(time) - Date.now()) <= SKEW * 1000)) {
		return fail(401, "stale or bad timestamp");
	}
	const externalId = header("x-external-id");
	if (!/^[A-Za-z0-9-]{16,64}$/.test(externalId)) {
		return fail(400, "X-EXTERNAL-ID must be 16 to 64 of A-Z, a-z, 0-9 and -");
	}

	const entry = JSON.parse(stored) as Entry;
	const body = new Uint8Array(await req.arrayBuffer());
	const text = [req.method, new URL(req.url).pathname, hex(await digest(body)), time, externalId].join(":");
	if (!(await verify(entry.publicKey, header("x-signature"), text))) return fail(401, "bad signature");

	// ponytail: KV is eventually consistent, so a replay landing on another
	// Cloudflare location within about a minute may pass; a Durable Object
	// would make this strict.
	const seen = `n:${keyId}:${externalId}`;
	if ((await env.KEYS.get(seen)) !== null) return fail(409, "duplicate X-EXTERNAL-ID");
	if (!(await env.SEND_LIMIT.limit({ key: keyId })).success) return fail(429, "too many requests");
	await env.KEYS.put(seen, "1", { expirationTtl: 2 * SKEW });
	return { keyId, entry, body };
}

// Whether signature, the base64 DER that openssl writes, signs text with the
// base64 SPKI publicKey.
async function verify(publicKey: string, signature: string, text: string): Promise<boolean> {
	try {
		const raw = derToRaw(unb64(signature));
		const key = await importKey(unb64(publicKey));
		return !!raw && (await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, raw, encode(text)));
	} catch {
		return false;
	}
}

// DER's SEQUENCE { INTEGER r, INTEGER s } as the 64-byte r‖s WebCrypto takes.
// Each integer is at most 33 bytes, so every length is a single byte.
function derToRaw(der: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> | null {
	if (der[0] !== 0x30 || der[1] !== der.length - 2) return null;
	const raw = new Uint8Array(64);
	let at = 2;
	for (const half of [0, 32]) {
		if (der[at] !== 0x02) return null;
		const len = der[at + 1] ?? 0;
		let int = der.subarray(at + 2, at + 2 + len);
		at += 2 + len;
		while (int.length > 32 && int[0] === 0) int = int.subarray(1);
		if (!int.length || int.length > 32) return null;
		raw.set(int, half + 32 - int.length);
	}
	return at === der.length ? raw : null;
}

const importKey = (spki: Uint8Array<ArrayBuffer>) => crypto.subtle.importKey("spki", spki, P256, false, ["verify"]);

// The send fields, or what is wrong with them.
function readMessage(bytes: Uint8Array<ArrayBuffer>): { title: string; body: string } | string {
	let parsed: unknown;
	try {
		parsed = JSON.parse(new TextDecoder().decode(bytes));
	} catch {
		return "expected a JSON object";
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "expected a JSON object";
	const fields = parsed as Record<string, unknown>;
	const title = fields.title ?? "";
	const body = fields.body ?? "";
	if (typeof title !== "string" || typeof body !== "string") return "title and body must be strings";
	if (!body.trim()) return "body is required";
	if (body.trim().length > 1000) return "body is longer than 1000 characters";
	if (title.trim().length > 100) return "title is longer than 100 characters";
	return { body: body.trim(), title: title.trim() || "Jeansh" };
}

type FcmResult = { status: number; code: string };
type FcmError = { error?: { status?: string; details?: { errorCode?: string }[] } };

// FCM's HTTP status (0 when FCM or Google's sign-in could not be used) and its
// error code, such as UNREGISTERED.
async function fcm(env: Env, payload: object): Promise<FcmResult> {
	try {
		const auth = await accessToken(env);
		const res = await fetch(`https://fcm.googleapis.com/v1/projects/${auth.project}/messages:send`, {
			method: "POST",
			headers: { authorization: `Bearer ${auth.token}`, "content-type": "application/json" },
			body: JSON.stringify(payload),
		});
		if (res.ok) return { status: 200, code: "" };
		if (res.status === 401) cached = undefined;
		const err = (await res.json().catch(() => null)) as FcmError | null;
		const code = err?.error?.details?.find((d) => d.errorCode)?.errorCode ?? err?.error?.status ?? "";
		// Only ever an enum such as UNREGISTERED, never FCM's own words.
		return { status: res.status, code: /^[A-Z_]{1,40}$/.test(code) ? code : "" };
	} catch (e) {
		console.error("fcm:", e instanceof Error ? e.message : "failed");
		return { status: 0, code: "" };
	}
}

function fcmFailed({ status, code }: FcmResult): Response {
	const reason = status ? `FCM returned HTTP ${status}${code && " " + code}` : "FCM is unavailable";
	console.warn(reason);
	return fail(502, reason);
}

let cached: { token: string; project: string; until: number } | undefined;

// An access token for FCM, kept until five minutes before it expires.
async function accessToken(env: Env) {
	if (cached && Date.now() < cached.until) return cached;
	let sa: ServiceAccount;
	try {
		sa = JSON.parse(env.FCM_SERVICE_ACCOUNT);
	} catch {
		// Not JSON.parse's own message: it quotes the text it choked on.
		throw new Error("FCM_SERVICE_ACCOUNT is missing or not JSON");
	}
	const res = await fetch(TOKEN_URL, {
		method: "POST",
		body: new URLSearchParams({
			grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
			assertion: await signJwt(sa, Math.floor(Date.now() / 1000)),
		}),
	});
	if (!res.ok) throw new Error(`Google refused the service account: HTTP ${res.status}`);
	const { access_token, expires_in } = (await res.json()) as { access_token: string; expires_in: number };
	cached = { token: access_token, project: sa.project_id, until: Date.now() + (expires_in - 300) * 1000 };
	return cached;
}

// The RS256 JWT that Google's token endpoint trades for an access token.
export async function signJwt(sa: ServiceAccount, now: number): Promise<string> {
	const der = unb64(sa.private_key.replace(/-----[A-Z ]+-----|\s/g, ""));
	const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, [
		"sign",
	]);
	const part = (o: object) => b64url(encode(JSON.stringify(o)));
	const claims = { iss: sa.client_email, scope: SCOPE, aud: TOKEN_URL, iat: now, exp: now + 3600 };
	const input = `${part({ alg: "RS256", typ: "JWT" })}.${part(claims)}`;
	const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, encode(input));
	return `${input}.${b64url(new Uint8Array(sig))}`;
}

const encode = (text: string) => new TextEncoder().encode(text);
const unb64 = (text: string) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const b64url = (bytes: Uint8Array) => b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const digest = async (data: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.digest("SHA-256", data));

const json = (status: number, data: unknown) =>
	new Response(JSON.stringify(data) + "\n", { status, headers: { "content-type": "application/json" } });
const fail = (status: number, error: string) => json(status, { error });
