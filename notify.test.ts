import { afterAll, expect, test } from "bun:test";

// One local server stands in for both the app's forwarded port (/direct/...)
// and the relay (/relay/...), recording what each got.
let status: Record<string, number> = {};
const hits: { path: string; auth: string | null; fields: Record<string, string> }[] = [];
const server = Bun.serve({
	hostname: "127.0.0.1",
	port: 0,
	async fetch(req) {
		const path = new URL(req.url).pathname;
		const fields = Object.fromEntries(new URLSearchParams(await req.text()));
		hits.push({ path, auth: req.headers.get("authorization"), fields });
		return new Response("{}", { status: status[path] ?? 200 });
	},
});
afterAll(() => server.stop());

const base = `http://127.0.0.1:${server.port}`;
const app = {
	LC_SSHBOX_TOKEN: "jnk_relaykey",
	LC_SSHBOX_HOST_ID: "42",
	LC_SSHBOX_NOTIFY_URL: `${base}/direct/v1/send`,
	LC_SSHBOX_NOTIFY_SECRET: "direct-secret",
};
const direct = (fields: Record<string, string>) => ({ path: "/direct/v1/send", auth: "Bearer direct-secret", fields });
const relay = (fields: Record<string, string>) => ({ path: "/relay/v1/send", auth: "Bearer jnk_relaykey", fields });

async function notify(args: string[], env: Record<string, string>) {
	hits.length = 0;
	const proc = Bun.spawn(["sh", `${import.meta.dir}/notify.sh`, ...args], {
		env: { PATH: process.env.PATH ?? "/usr/bin:/bin", JEANSH_RELAY: `${base}/relay`, ...env },
		stdout: "pipe",
		stderr: "pipe",
	});
	const [code, out, err] = await Promise.all([
		proc.exited,
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
	]);
	return { code, out, err };
}

test("notify.sh goes straight to the app when it answers, with only the direct secret", async () => {
	status = {};
	const r = await notify(["-title", "Build", "build", "done"], app);
	expect(r).toMatchObject({ code: 0, out: "sshbox-notify: sent directly to Jeansh\n" });
	expect(hits).toEqual([direct({ body: "build done", title: "Build" })]);
});

test("notify.sh falls back to the relay, with only the relay key, when the app refuses", async () => {
	status = { "/direct/v1/send": 500 };
	const r = await notify(["-title=Build", "-host", "7", "build done"], app);
	expect(r).toMatchObject({ code: 0, out: "sshbox-notify: sent through the relay\n" });
	expect(hits).toEqual([
		direct({ body: "build done", title: "Build" }),
		relay({ body: "build done", title: "Build", host: "7" }),
	]);
});

test("notify.sh falls back to the relay when the forwarded port is gone", async () => {
	status = {};
	// Nothing listens on port 1.
	const r = await notify(["done"], { ...app, LC_SSHBOX_NOTIFY_URL: "http://127.0.0.1:1/v1/send" });
	expect(r).toMatchObject({ code: 0, out: "sshbox-notify: sent through the relay\n" });
	expect(hits).toEqual([relay({ body: "done", host: "42" })]);
});

test("notify.sh fails only when every way failed", async () => {
	status = { "/direct/v1/send": 500, "/relay/v1/send": 502 };
	const r = await notify(["done"], app);
	expect(r.code).toBe(1);
	expect(r.out).toBe("");
	expect(hits.map((h) => h.path)).toEqual(["/direct/v1/send", "/relay/v1/send"]);
});

test("notify.sh says what is missing without LC_SSHBOX_TOKEN", async () => {
	const r = await notify(["done"], {});
	expect(r.code).toBe(1);
	expect(r.err).toContain("LC_SSHBOX_TOKEN is not set");
	expect(hits).toEqual([]);
});
