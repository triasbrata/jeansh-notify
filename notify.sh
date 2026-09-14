#!/bin/sh
# sshbox-notify: put a notification on the phone running Jeansh.
#
#   sshbox-notify "build done"
#   sshbox-notify -title Deploy "done in 4m"
#
# It tries the app directly first, through the port Jeansh forwards back over
# the SSH connection (LC_SSHBOX_NOTIFY_URL, LC_SSHBOX_NOTIFY_SECRET), and falls
# back to the relay, signing the request with this host's key (LC_SSHBOX_KEY)
# through openssl. Each secret goes only to its own endpoint and never shows up
# in ps: the direct secret goes to curl on stdin, and the key to openssl in a
# file only this user can read, deleted on exit.
#
# Install: install -m 755 notify.sh /usr/local/bin/sshbox-notify

relay=${JEANSH_RELAY:-https://jeansh-notify.brata.cloud}

usage() {
	echo "usage: sshbox-notify [-title TITLE] message..." >&2
	exit 2
}

title=
while [ $# -gt 0 ]; do
	case $1 in
	-title | --title) [ $# -ge 2 ] || usage; title=$2; shift 2 ;;
	-title=* | --title=*) title=${1#*=}; shift ;;
	--) shift; break ;;
	-?*) usage ;;
	*) break ;;
	esac
done
msg=$*
[ -n "$msg" ] || usage

if [ -n "${LC_SSHBOX_NOTIFY_URL:-}" ] && [ -n "${LC_SSHBOX_NOTIFY_SECRET:-}" ]; then
	set -- --data-urlencode "body=$msg"
	[ -z "$title" ] || set -- "$@" --data-urlencode "title=$title"
	if printf 'Authorization: Bearer %s\n' "$LC_SSHBOX_NOTIFY_SECRET" |
		curl -fsS -o /dev/null -H @- --connect-timeout 2 -m 5 "$@" "$LC_SSHBOX_NOTIFY_URL"; then
		echo "sshbox-notify: sent directly to Jeansh"
		exit 0
	fi
	echo "sshbox-notify: Jeansh did not answer directly, trying the relay" >&2
fi

if [ -z "${LC_SSHBOX_KEY:-}" ]; then
	cat >&2 <<'EOF'
sshbox-notify: LC_SSHBOX_KEY is not set, so there is no key to sign for the relay with.
Jeansh passes it when it connects, if the server accepts it: sshd needs
"AcceptEnv LC_*" (the Debian and Ubuntu default), and Tailscale SSH needs
"acceptEnv": ["LC_SSHBOX_*"] in the tailnet policy. Reconnect after changing either.
EOF
	exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
	echo "sshbox-notify: openssl is not installed, and the relay needs it to sign with LC_SSHBOX_KEY" >&2
	exit 1
fi

# $1 as a JSON string: quotes, backslashes and control characters escaped.
json() {
	printf '%s' "$1" | LC_ALL=C awk '
		BEGIN {
			for (i = 1; i < 32; i++) esc[sprintf("%c", i)] = sprintf("\\u%04x", i)
			esc["\\"] = "\\\\"; esc["\""] = "\\\""
		}
		NR > 1 { s = s "\\n" }
		{ for (i = 1; i <= length($0); i++) { c = substr($0, i, 1); if (c in esc) c = esc[c]; s = s c } }
		END { printf "\"%s\"", s }'
}
data="{\"body\":$(json "$msg")"
[ -z "$title" ] || data="$data,\"title\":$(json "$title")"
data="$data}"

# LC_SSHBOX_KEY is <key id>:<base64 PKCS#8 DER>; openssl wants it as PEM.
umask 077
pem=$(mktemp) || exit 1
trap 'rm -f "$pem"' EXIT
trap 'exit 1' HUP INT TERM
printf '%s\n' '-----BEGIN PRIVATE KEY-----' "$(printf '%s\n' "${LC_SSHBOX_KEY#*:}" | fold -w 64)" \
	'-----END PRIVATE KEY-----' >"$pem"

# SNAP-style: sign METHOD:PATH:sha256(body):X-TIMESTAMP:X-EXTERNAL-ID.
stamp=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)
id=$(openssl rand -hex 16)
hash=$(printf '%s' "$data" | openssl dgst -sha256 | sed 's/^.*= *//')
sig=$(printf 'POST:/v1/send:%s:%s:%s' "$hash" "$stamp" "$id" | openssl dgst -sha256 -sign "$pem" | openssl base64 -A)
if [ -z "$sig" ]; then
	echo "sshbox-notify: could not sign with LC_SSHBOX_KEY" >&2
	exit 1
fi

res=$(printf 'X-PARTNER-ID: %s\nX-TIMESTAMP: %s\nX-EXTERNAL-ID: %s\nX-SIGNATURE: %s\nContent-Type: application/json\n' \
	"${LC_SSHBOX_KEY%%:*}" "$stamp" "$id" "$sig" |
	curl -sS -w ' (HTTP %{http_code})' -H @- --data-binary "$data" "$relay/v1/send" | tr -d '\n')
case $res in
*'(HTTP 200)')
	echo "sshbox-notify: sent through the relay"
	exit 0
	;;
esac
printf 'sshbox-notify: the relay did not take it either: %s\n' "$res" >&2
exit 1
