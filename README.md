# jeansh-notify

A push relay for **Jeansh**, an Android SSH app. When a slow job on a server
finishes, `sshbox-notify` on that server puts a notification on your phone, and
tapping it opens that host's terminal in Jeansh.

Sending a push through Firebase Cloud Messaging needs the app's Firebase
service account, which can't be handed out to every server. So the relay, a
Cloudflare Worker, holds it. Jeansh makes a key pair for each host, registers
the public key here with the phone's FCM token, and passes the private key to
that host when it connects. The host signs every request with its key, the way
Indonesia's SNAP payment API signs requests, and the relay checks the signature
against the registered key before it sends. The notification opens the host
the key was registered for, so a server can only ever notify as itself.

## Send a notification

```sh
sshbox-notify "build done"
sshbox-notify -title Deploy "done in 4m"
```

For example, `make && sshbox-notify "build done"` at the end of a build.

### Where the variables come from

Jeansh passes these to every shell it opens:

| Variable | What it is |
|---|---|
| `LC_SSHBOX_KEY` | this host's key, `<key id>:<base64 PKCS#8 DER private key>` (ECDSA P-256) |
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
`echo ${LC_SSHBOX_KEY%%:*}`, which prints only the key id.

Each host has its own key. **Deleting the host in Jeansh revokes its key** here,
so that server can no longer send, and no other host's key is affected.

## Two ways to deliver

- **Direct.** While Jeansh is connected, post to `$LC_SSHBOX_NOTIFY_URL` with
  `Authorization: Bearer $LC_SSHBOX_NOTIFY_SECRET` and form-encoded `body` and
  `title` fields. The message reaches the app over the SSH connection itself,
  without Google or this relay.
- **Relay.** Post to this relay, signed with `LC_SSHBOX_KEY`, as described
  under [Signing](#signing). The relay pushes through FCM, so it works when the
  app is in the background or closed.

The direct port goes stale when the connection drops or the app goes away, so
`sshbox-notify` tries direct first and falls back to the relay.

## sshbox-notify

`notify.sh` does both ways in POSIX `sh` with `curl` and `openssl` (OpenSSL 1.1
or later, or LibreSSL as on macOS). Install it on the server as
`sshbox-notify`:

```sh
curl -fsSL https://raw.githubusercontent.com/triasbrata/jeansh-notify/main/notify.sh -o sshbox-notify
install -m 755 sshbox-notify /usr/local/bin/    # or ~/.local/bin
```

- When `LC_SSHBOX_NOTIFY_URL` and `LC_SSHBOX_NOTIFY_SECRET` are set, it tries
  direct first, giving up after 2 seconds to connect or 5 in all.
- On any failure there, or when they aren't set, it signs the message with
  `LC_SSHBOX_KEY` and sends it through the relay.
- No secret shows in `ps`. The direct secret goes to `curl` on stdin, and the
  key goes to `openssl` in a temporary file only you can read, deleted when the
  script exits.
- It prints which way delivered, and exits non-zero only when every way failed.
  Then it says why: that `LC_SSHBOX_KEY` or `openssl` is missing, or the
  relay's error.
- `JEANSH_RELAY` points it at another relay.

## API

Base URL `https://jeansh-notify.brata.cloud`. Errors come back as
`{"error": "…"}`, and anything not listed here answers 404.

### Signing

`POST /v1/send` and `DELETE /v1/key` are signed the way SNAP (Standar Nasional
Open API Pembayaran) signs requests, with the host's ECDSA P-256 key:

| Header | Value |
|---|---|
| `X-PARTNER-ID` | the key id, `jnk_…` |
| `X-TIMESTAMP` | now, as SNAP's `yyyy-MM-ddTHH:mm:ssTZD`, e.g. `2026-09-14T08:15:30+07:00` (`Z` and milliseconds are accepted too) |
| `X-EXTERNAL-ID` | 16 to 64 characters of `A-Z`, `a-z`, `0-9` and `-`, new for every request |
| `X-SIGNATURE` | base64 of the DER ECDSA signature, as `openssl dgst -sha256 -sign` writes it |

The string to sign is

```
<METHOD>:<PATH>:<lowercase hex SHA-256 of the body>:<X-TIMESTAMP>:<X-EXTERNAL-ID>
```

for example `POST:/v1/send:9f2c…e41a:2026-09-14T08:15:30+07:00:4b1d9c0e7a2f4e61`.
The hash is over the exact bytes of the body sent. A request with no body, such
as `DELETE /v1/key`, hashes the empty string:
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

The relay checks, in this order:

| Status | `error` | When |
|---|---|---|
| 401 | `unknown key` | no `X-PARTNER-ID`, or no such key: never registered, revoked, or deleted after a 410 |
| 401 | `stale or bad timestamp` | `X-TIMESTAMP` isn't in the format, or is more than 300 seconds from the relay's clock |
| 400 | `X-EXTERNAL-ID must be …` | `X-EXTERNAL-ID` is missing or not in the format |
| 401 | `bad signature` | the signature isn't the key's over this string, for example because the body, method or path changed |
| 409 | `duplicate X-EXTERNAL-ID` | the key already used this external id in the last 10 minutes |
| 429 | `too many requests` | more than 30 signed requests a minute with one key |

A 401 `stale or bad timestamp` from a request that looks right usually means the
server's clock is off; check it with `date -u`.

### Sign with openssl and curl

What `sshbox-notify` does, by hand:

```sh
umask 077
printf '%s\n' '-----BEGIN PRIVATE KEY-----' "$(printf '%s\n' "${LC_SSHBOX_KEY#*:}" | fold -w 64)" \
  '-----END PRIVATE KEY-----' > key.pem

body='{"title":"Build","body":"build done"}'
ts=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)
id=$(openssl rand -hex 16)
hash=$(printf '%s' "$body" | openssl dgst -sha256 | sed 's/^.*= *//')
sig=$(printf 'POST:/v1/send:%s:%s:%s' "$hash" "$ts" "$id" | openssl dgst -sha256 -sign key.pem | openssl base64 -A)
rm -f key.pem

curl -sS https://jeansh-notify.brata.cloud/v1/send \
  -H "X-PARTNER-ID: ${LC_SSHBOX_KEY%%:*}" -H "X-TIMESTAMP: $ts" \
  -H "X-EXTERNAL-ID: $id" -H "X-SIGNATURE: $sig" \
  -H 'Content-Type: application/json' --data-binary "$body"
```

`--data-binary` sends the body byte for byte, so it still matches its hash.

### `POST /v1/register`

The app calls this for each host key. It isn't signed. The body is

```json
{"token": "<FCM registration token>", "publicKey": "<base64 SPKI DER>", "host": "<host id>"}
```

with an ECDSA P-256 public key and a host id of at most 100 characters. The
relay checks the token with an FCM dry run, and answers the key id:
`jnk_` and the first 32 characters of the unpadded base64url SHA-256 of the
SPKI DER. Registering the same key again answers the same id and takes the new
token.

| Status | When |
|---|---|
| 200 | `{"keyId": "jnk_…"}` |
| 400 | no token or host, a public key that isn't ECDSA P-256, or a token FCM says is invalid |
| 429 | more than 10 registrations a minute from one IP |
| 502 | FCM failed; the error gives only its HTTP status and error code |

### `POST /v1/send`

Signed. The body is JSON:

- `body`: required, trimmed, up to 1000 characters;
- `title`: optional, up to 100 characters, `Jeansh` when missing.

A tap on the notification opens the host the key was registered for. Nothing in
the body can change that.

| Status | When |
|---|---|
| 200 | `{"ok": true}` |
| 400 | bad input |
| 401, 409, 429 | see [Signing](#signing) |
| 410 | FCM says the phone is no longer registered; the key is deleted |
| 502 | FCM failed; the error gives only its HTTP status and error code |

### `DELETE /v1/key`

Signed with the key to revoke, with no body. The relay deletes the key and
answers 204. After that the key can't sign anything, so asking again answers
401 `unknown key`.

## What the relay stores

In Workers KV:

- `k:<key id>` → `{"publicKey", "token", "host", "created"}`, one per host key;
- `n:<key id>:<X-EXTERNAL-ID>`, for 10 minutes, the external ids each key used.

Private keys never reach the relay. Keys, signatures, FCM tokens and messages
are never logged, and messages pass through without being kept.

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
- Change the route in `wrangler.jsonc` to your own domain, then point
  `sshbox-notify` at it with `JEANSH_RELAY`.
- To deploy on every push, connect the repo in the Cloudflare dashboard
  (Workers & Pages → the Worker → Settings → Build): set the build command to
  `bun run typecheck`, the deploy command to `bunx wrangler deploy` and the
  build variable `BUN_VERSION` to `1.4.0`. This relay deploys that way from
  `main`, and a type error stops the deploy. The secret and the KV data stay on
  the Worker between deploys.

## Development

```sh
bun install
bun test             # FCM and Google are mocked; sshbox-notify's tests need curl and openssl
bun run typecheck
```
