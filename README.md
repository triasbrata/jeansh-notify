# jeansh-notify

A push relay for **Jeansh**, an Android SSH app. When a slow job on a server
finishes, one `curl` from that server puts a notification on your phone, and
tapping it opens that host's terminal in Jeansh.

Sending a push through Firebase Cloud Messaging needs the app's Firebase
service account, which can't be handed out to every server. So Jeansh registers
the phone's FCM token here and gets back a relay key. Servers send with that
key, and the relay, a Cloudflare Worker, signs in to FCM with the service
account and delivers.

## Send a notification

```sh
curl -fsS https://jeansh-notify.brata.cloud/v1/send \
  -H "Authorization: Bearer $LC_SSHBOX_TOKEN" \
  --data-urlencode "host=$LC_SSHBOX_HOST_ID" \
  --data-urlencode "title=Build" \
  --data-urlencode "body=build done"
```

For example, `make && curl …` at the end of a build.

### Where the variables come from

Jeansh passes these to every shell it opens:

| Variable | What it is |
|---|---|
| `LC_SSHBOX_TOKEN` | this phone's relay key (`jnk_…`) |
| `LC_SSHBOX_HOST_ID` | the host a tap on the notification opens |
| `LC_SSHBOX_NOTIFY_URL` | `http://127.0.0.1:<port>/v1/send` on the server, a port Jeansh forwards back to itself over the SSH connection |
| `LC_SSHBOX_NOTIFY_SECRET` | the secret for that port, new for each connection |

The server has to accept them:

- **OpenSSH:** `AcceptEnv LC_*` in `sshd_config`. Debian and Ubuntu ship with it.
- **Tailscale SSH:** add `"acceptEnv": ["LC_SSHBOX_*"]` to your SSH rule in the
  tailnet policy, for example:

  ```json
  "ssh": [{
    "action": "accept",
    "src": ["autogroup:member"],
    "dst": ["autogroup:self"],
    "users": ["autogroup:nonroot"],
    "acceptEnv": ["LC_SSHBOX_*"]
  }]
  ```

Reconnect from Jeansh after changing either, then check with
`echo $LC_SSHBOX_TOKEN`.

## Two ways to deliver

- **Direct.** While Jeansh is connected, post to `$LC_SSHBOX_NOTIFY_URL` with
  `Authorization: Bearer $LC_SSHBOX_NOTIFY_SECRET` and the same `body` and
  `title` fields. The message reaches the app over the SSH connection itself,
  without Google or this relay.
- **Relay.** Post to this relay with `LC_SSHBOX_TOKEN`, as above. The relay
  pushes through FCM, so it works when the app is in the background or closed.

The direct port goes stale when the connection drops or the app goes away, so
`sshbox-notify` tries direct first and falls back to the relay.

## sshbox-notify

`notify.sh` does both ways in POSIX `sh` and `curl`, nothing else. Install it on
the server as `sshbox-notify`:

```sh
curl -fsSL https://raw.githubusercontent.com/triasbrata/jeansh-notify/main/notify.sh -o sshbox-notify
install -m 755 sshbox-notify /usr/local/bin/    # or ~/.local/bin
```

```sh
sshbox-notify "build done"
sshbox-notify -title Deploy -host 1788717544349041 "done in 4m"
```

- When `LC_SSHBOX_NOTIFY_URL` and `LC_SSHBOX_NOTIFY_SECRET` are set, it tries
  direct first, giving up after 2 seconds to connect or 5 in all.
- On any failure there, or when they aren't set, it sends through the relay
  with `LC_SSHBOX_TOKEN`, and `-host` or else `LC_SSHBOX_HOST_ID`.
- Each secret goes only to its own endpoint, and to `curl` on stdin, so it never
  shows in `ps`.
- It prints which way delivered, and exits non-zero only when every way failed.
  Without `LC_SSHBOX_TOKEN` it says what the server is missing.
- `JEANSH_RELAY` points it at another relay.

## API

Base URL `https://jeansh-notify.brata.cloud`. Errors come back as
`{"error": "…"}`.

### `POST /v1/register`

The app calls this. The body is `{"token": "<FCM registration token>"}`. The
relay checks the token with an FCM dry run, then answers `{"key": "jnk_…"}`.

| Status | When |
|---|---|
| 200 | `{"key": "jnk_…"}` |
| 400 | no token, or FCM says it is invalid |
| 429 | more than 10 registrations a minute from one IP |

### `POST /v1/send`

Send `Authorization: Bearer <key>`, with a form-encoded or JSON body:

- `body`: required, trimmed, up to 1000 characters;
- `title`: optional, up to 100 characters, `Jeansh` when missing;
- `host`: optional, the host a tap opens, up to 100 characters.

| Status | When |
|---|---|
| 200 | `{"ok": true}` |
| 400 | bad input |
| 401 | no key, or an unknown one |
| 410 | FCM says the phone is no longer registered; the key is deleted |
| 429 | more than 30 sends a minute with one key |
| 502 | FCM failed; the error gives only its HTTP status and error code |

### `DELETE /v1/key`

Send `Authorization: Bearer <key>`. This deletes the key and answers 204, also
when it was already gone.

Anything else answers 404.

## What the relay stores

One entry per key, in Workers KV: the SHA-256 of the key, pointing to
`{"token": "<FCM token>", "created": "<time>"}`. The key itself is never stored,
and keys, FCM tokens, messages and the service account are never logged.
Messages pass through and aren't kept.

**Reset notification key** in Jeansh revokes the phone's key here, so servers
that still hold it can no longer send.

## Deploy your own

A relay can only reach phones whose FCM tokens come from the same Firebase
project as its service account. So run your own only alongside your own build of
the app.

```sh
bun install
bunx wrangler kv namespace create KEYS    # put its id in wrangler.jsonc
bunx wrangler secret put FCM_SERVICE_ACCOUNT < service-account.json
bunx wrangler deploy
```

- The service account JSON comes from the Firebase console: Project settings →
  Service accounts → Generate new private key. A service account with only the
  **Firebase Cloud Messaging API Admin** role is enough, and safer than the
  default Admin SDK one.
- The two rate limiters' `namespace_id`s in `wrangler.jsonc` must not clash with
  other Workers in your account.
- Add your domain to `wrangler.jsonc` as a route, then point `sshbox-notify` at
  it with `JEANSH_RELAY`.

## Development

```sh
bun install
bun test             # FCM and Google are mocked; no accounts needed
bun run typecheck
```
