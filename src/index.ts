// Jeansh push relay.
//
// The app registers its FCM token and gets a relay key back. A server posts a
// message with that key, and the relay sends it to the phone through FCM HTTP
// v1, signed in with a service account that servers never see.

interface Limiter {
	limit(options: { key: string }): Promise<{ success: boolean }>;
}

// The bindings, typed by the methods used, so tests can pass plain fakes.
export interface Env {
	/** The Firebase service account JSON, as text. */
	FCM_SERVICE_ACCOUNT: string;
	/** SHA-256 hex of a relay key -> {"token": FCM token, "created": ISO time}. */
	KEYS: {
		get(key: string): Promise<string | null>;
		put(key: string, value: string): Promise<void>;
		delete(key: string): Promise<void>;
	};
	/** Keyed by client IP. */
	REGISTER_LIMIT: Limiter;
	/** Keyed by relay key hash. */
	SEND_LIMIT: Limiter;
}

export interface ServiceAccount {
	project_id: string;
	client_email: string;
	private_key: string;
}

const SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
// FCM error codes that mean the token itself is no good.
const BAD_TOKEN = ["INVALID_ARGUMENT", "UNREGISTERED", "SENDER_ID_MISMATCH"];
const NO_KEY = "expected Authorization: Bearer jnk_…";

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

	const { token } = ((await req.json().catch(() => null)) ?? {}) as { token?: unknown };
	if (typeof token !== "string" || !token || token.length > 4096) {
		return fail(400, "token must be an FCM registration token");
	}

	const check = await fcm(env, { validate_only: true, message: { token } });
	if (check.status === 404 || BAD_TOKEN.includes(check.code)) return fail(400, "FCM does not accept this token");
	if (check.status !== 200) return fcmFailed(check);

	const key = "jnk_" + b64url(crypto.getRandomValues(new Uint8Array(32)));
	await env.KEYS.put(await sha256(key), JSON.stringify({ token, created: new Date().toISOString() }));
	return json(200, { key });
}

async function send(req: Request, env: Env): Promise<Response> {
	const hash = await keyHash(req);
	if (!hash) return fail(401, NO_KEY);
	if (!(await env.SEND_LIMIT.limit({ key: hash })).success) return fail(429, "too many requests");
	const stored = await env.KEYS.get(hash);
	if (!stored) return fail(401, "unknown relay key");

	const input = await readFields(req);
	if (typeof input === "string") return fail(400, input);
	const { body, title, host } = input;
	const { token } = JSON.parse(stored) as { token: string };

	// The same message the old per-server Go tool sent. The notification half
	// is what Android shows while the app is in the background; the data half
	// survives the tap, so the app can open the host.
	const res = await fcm(env, {
		message: {
			token,
			data: host ? { hostId: host, title, body } : { title, body },
			notification: { title, body },
			android: { priority: "high" },
		},
	});
	if (res.status === 200) return json(200, { ok: true });
	if (res.status === 404 || res.code === "UNREGISTERED") {
		await env.KEYS.delete(hash);
		return fail(410, "the phone is no longer registered with FCM; this key is deleted");
	}
	return fcmFailed(res, hash);
}

async function revoke(req: Request, env: Env): Promise<Response> {
	const hash = await keyHash(req);
	if (!hash) return fail(401, NO_KEY);
	await env.KEYS.delete(hash);
	return new Response(null, { status: 204 });
}

async function keyHash(req: Request): Promise<string | null> {
	const key = /^bearer\s+(jnk_[\w-]+)$/i.exec(req.headers.get("authorization") ?? "")?.[1];
	return key ? sha256(key) : null;
}

// The send fields, or what is wrong with them.
async function readFields(req: Request): Promise<{ body: string; title: string; host: string } | string> {
	let raw: Record<string, unknown>;
	if (req.headers.get("content-type")?.includes("json")) {
		const parsed: unknown = await req.json().catch(() => null);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "expected a JSON object";
		raw = parsed as Record<string, unknown>;
	} else {
		raw = Object.fromEntries(new URLSearchParams(await req.text()));
	}

	const text = (name: string) => {
		const value = raw[name] ?? "";
		return typeof value === "string" ? value.trim() : null;
	};
	const body = text("body");
	const title = text("title");
	const host = text("host");
	if (body === null || title === null || host === null) return "body, title and host must be strings";
	if (!body) return "body is required";
	if (body.length > 1000) return "body is longer than 1000 characters";
	if (title.length > 100) return "title is longer than 100 characters";
	if (host.length > 100) return "host is longer than 100 characters";
	return { body, title: title || "Jeansh", host };
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

function fcmFailed({ status, code }: FcmResult, hash = ""): Response {
	const reason = status ? `FCM returned HTTP ${status}${code && " " + code}` : "FCM is unavailable";
	console.warn(reason, hash && `key ${hash.slice(0, 8)}`);
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
	const der = Uint8Array.from(atob(sa.private_key.replace(/-----[A-Z ]+-----|\s/g, "")), (c) => c.charCodeAt(0));
	const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, [
		"sign",
	]);
	const part = (o: object) => b64url(new TextEncoder().encode(JSON.stringify(o)));
	const claims = { iss: sa.client_email, scope: SCOPE, aud: TOKEN_URL, iat: now, exp: now + 3600 };
	const input = `${part({ alg: "RS256", typ: "JWT" })}.${part(claims)}`;
	const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(input));
	return `${input}.${b64url(new Uint8Array(sig))}`;
}

const b64url = (bytes: Uint8Array) =>
	btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");

async function sha256(text: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

const json = (status: number, data: unknown) =>
	new Response(JSON.stringify(data) + "\n", { status, headers: { "content-type": "application/json" } });
const fail = (status: number, error: string) => json(status, { error });
