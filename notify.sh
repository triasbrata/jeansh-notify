#!/bin/sh
# sshbox-notify: put a notification on the phone running Jeansh.
#
#   sshbox-notify "build done"
#   sshbox-notify -title Deploy -host 1788717544349041 "done in 4m"
#
# It tries the app directly first, through the port Jeansh forwards back over
# the SSH connection (LC_SSHBOX_NOTIFY_URL, LC_SSHBOX_NOTIFY_SECRET), and falls
# back to the relay (LC_SSHBOX_TOKEN, LC_SSHBOX_HOST_ID). Each secret goes only
# to its own endpoint, and to curl on stdin, so it never shows up in ps.
#
# Install: install -m 755 notify.sh /usr/local/bin/sshbox-notify

relay=${JEANSH_RELAY:-https://jeansh-notify.brata.cloud}

usage() {
	echo "usage: sshbox-notify [-title TITLE] [-host HOST_ID] message..." >&2
	exit 2
}

title=
host=${LC_SSHBOX_HOST_ID:-}
while [ $# -gt 0 ]; do
	case $1 in
	-title | --title) [ $# -ge 2 ] || usage; title=$2; shift 2 ;;
	-title=* | --title=*) title=${1#*=}; shift ;;
	-host | --host) [ $# -ge 2 ] || usage; host=$2; shift 2 ;;
	-host=* | --host=*) host=${1#*=}; shift ;;
	--) shift; break ;;
	-?*) usage ;;
	*) break ;;
	esac
done
msg=$*
[ -n "$msg" ] || usage

set -- --data-urlencode "body=$msg"
[ -z "$title" ] || set -- "$@" --data-urlencode "title=$title"

if [ -n "${LC_SSHBOX_NOTIFY_URL:-}" ] && [ -n "${LC_SSHBOX_NOTIFY_SECRET:-}" ]; then
	if printf 'Authorization: Bearer %s\n' "$LC_SSHBOX_NOTIFY_SECRET" |
		curl -fsS -o /dev/null -H @- --connect-timeout 2 -m 5 "$@" "$LC_SSHBOX_NOTIFY_URL"; then
		echo "sshbox-notify: sent directly to Jeansh"
		exit 0
	fi
	echo "sshbox-notify: Jeansh did not answer directly, trying the relay" >&2
fi

if [ -z "${LC_SSHBOX_TOKEN:-}" ]; then
	cat >&2 <<'EOF'
sshbox-notify: LC_SSHBOX_TOKEN is not set, so there is no relay key to send with.
Jeansh passes it when it connects, if the server accepts it: sshd needs
"AcceptEnv LC_*" (the Debian and Ubuntu default), and Tailscale SSH needs
"acceptEnv": ["LC_SSHBOX_*"] in the tailnet policy. Reconnect after changing either.
EOF
	exit 1
fi

[ -z "$host" ] || set -- "$@" --data-urlencode "host=$host"
if printf 'Authorization: Bearer %s\n' "$LC_SSHBOX_TOKEN" |
	curl -fsS -o /dev/null -H @- "$@" "$relay/v1/send"; then
	echo "sshbox-notify: sent through the relay"
	exit 0
fi
echo "sshbox-notify: the relay did not take it either" >&2
exit 1
