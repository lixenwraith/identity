#!/bin/sh
# Build and deploy identity from this checkout: deploy/identity.env's settings with
# the node's IDENTITY_DB_URL and IDENTITY_STORE_FILE carried over, the database
# migrated before the new binary starts, the previous binary, env and unit kept as
# .previous and restored if the new service does not come up, and a first install
# that does not come up removed. --render prints the env file it would install.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
render_only=false
case ${1:-} in
	-h|--help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	--render) render_only=true ;;
	'') ;;
	*) echo "usage: $0 [--render]" >&2; exit 2 ;;
esac

binary=/usr/local/bin/identity
installed_env=/etc/identity/identity.env
installed_unit=/etc/systemd/system/identity.service
installed_sysusers=/etc/sysusers.d/identity.conf
password_file=/etc/identity/db-password
source_unit=$repo_root/deploy/identity.service
source_env=$repo_root/deploy/identity.env
source_sysusers=$repo_root/deploy/identity.sysusers
backup_binary=/usr/local/libexec/identity.previous
backup_env=/etc/identity/identity.env.previous
backup_unit=/etc/systemd/system/identity.service.previous

# The repository's settings plus the node's IDENTITY_DB_URL and IDENTITY_STORE_FILE,
# which name the jail or the file and are filled in on the node alone, so the
# installed file carries them over. A file store needs no jail.
installed_value() {
	sudo cat "$installed_env" | sed -n "s/^$1=//p" | tail -n 1
}
render_env() {
	store_file=$(installed_value IDENTITY_STORE_FILE)
	url=$(installed_value IDENTITY_DB_URL)
	if [ -z "$store_file" ]; then
		case $url in
			''|*'<jail-address>'*)
				echo "$0: $installed_env names no jail in IDENTITY_DB_URL and no IDENTITY_STORE_FILE; fill one in first" >&2
				return 1 ;;
		esac
	fi
	grep -v '^IDENTITY_DB_URL=\|^IDENTITY_STORE_FILE=' "$source_env"
	printf 'IDENTITY_STORE_FILE=%s\n' "$store_file"
	printf 'IDENTITY_DB_URL=%s\n' "$url"
}
if [ "$render_only" = true ]; then
	render_env
	exit
fi

test "$(git -C "$repo_root" rev-parse --show-toplevel)" = "$repo_root"
if [ -n "$(git -C "$repo_root" status --porcelain)" ]; then
	echo "$0: the identity worktree differs from HEAD" >&2
	exit 1
fi
# /etc/identity is root:identity 0750, so an operator account cannot stat inside
# it and an installed file would read as missing without sudo. A file store has
# no database password.
sudo test -f "$installed_env" ||
	{ echo "$0: missing installed file: $installed_env (deploy/README.md)" >&2; exit 1; }
store_file=$(installed_value IDENTITY_STORE_FILE)
[ -n "$store_file" ] || sudo test -f "$password_file" ||
	{ echo "$0: missing installed file: $password_file (deploy/README.md)" >&2; exit 1; }
for source in "$source_unit" "$source_env" "$source_sysusers"; do
	[ -r "$source" ] || { echo "$0: missing source: $source" >&2; exit 1; }
done
# A first install has no binary or unit to keep; an update keeps both.
first_install=true
if sudo test -f "$binary" && sudo test -f "$installed_unit"; then
	first_install=false
	systemctl is-active --quiet identity.service || {
		echo "$0: identity.service must be active before an update" >&2
		exit 1
	}
fi

stage_root=$(mktemp -d "${TMPDIR:-/tmp}/identity-update.XXXXXX")
service_stopped=false
rollback_required=false
uninstall_required=false
# A first install that failed is taken away, or the next run would see an update
# of a service that never ran.
uninstall() {
	echo "$0: first install failed; removing it" >&2
	sudo journalctl -u identity.service -n 5 --no-pager -o cat >&2 || true
	sudo systemctl disable --now identity.service >/dev/null 2>&1 || true
	sudo rm -f -- "$binary" "$installed_unit"
	sudo systemctl daemon-reload
	sudo systemctl reset-failed identity.service >/dev/null 2>&1 || true
}
rollback() {
	echo "$0: update failed; restoring the previous identity" >&2
	sudo journalctl -u identity.service -n 5 --no-pager -o cat >&2 || true
	sudo systemctl stop identity.service >/dev/null 2>&1 || true
	sudo install -o root -g root -m 0755 "$backup_binary" "$binary"
	sudo install -o root -g identity -m 0640 "$backup_env" "$installed_env"
	sudo install -o root -g root -m 0644 "$backup_unit" "$installed_unit"
	sudo systemctl daemon-reload
	sudo systemctl start identity.service
}
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$status" -ne 0 ]; then
		if [ "$rollback_required" = true ]; then
			rollback || status=1
		elif [ "$uninstall_required" = true ]; then
			uninstall || status=1
		elif [ "$service_stopped" = true ]; then
			sudo systemctl start identity.service || status=1
		fi
	fi
	case "$stage_root" in
		*/identity-update.*) rm -rf -- "$stage_root" || status=1 ;;
		*) echo "$0: refusing unsafe cleanup path: $stage_root" >&2; status=1 ;;
	esac
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

render_env >"$stage_root/identity.env.next"

make -C "$repo_root" release
[ -x "$repo_root/bin/identity" ]

# The schema the new binary expects, applied with the node's own role before it
# starts: nothing when current; in split mode the jail's owner applies it first
# (schema/README.md) and this confirms the version. A file store is brought to
# the binary's format by the service itself, as the identity user, at start.
if [ -z "$store_file" ]; then
	db_url=$(sed -n 's/^IDENTITY_DB_URL=//p' "$stage_root/identity.env.next")
	db_ca=$(sed -n 's/^IDENTITY_DB_CA_FILE=//p' "$stage_root/identity.env.next")
	set -- migrate -db-url "$db_url" -db-password-file "$password_file"
	[ -z "$db_ca" ] || set -- "$@" -db-ca-file "$db_ca"
	sudo "$repo_root/bin/identity" "$@"
fi

sudo install -o root -g root -m 0644 "$source_sysusers" "$installed_sysusers"
sudo systemd-sysusers

if [ "$first_install" = false ]; then
	echo "pausing sign-ins for the identity cutover"
	sudo systemctl stop identity.service
	service_stopped=true
	sudo install -D -o root -g root -m 0755 "$binary" "$backup_binary"
	sudo install -o root -g identity -m 0640 "$installed_env" "$backup_env"
	sudo install -o root -g root -m 0644 "$installed_unit" "$backup_unit"
	rollback_required=true
else
	uninstall_required=true
fi

sudo install -o root -g root -m 0755 "$repo_root/bin/identity" "$binary"
sudo install -o root -g identity -m 0640 "$stage_root/identity.env.next" "$installed_env"
sudo install -o root -g root -m 0644 "$source_unit" "$installed_unit"
sudo systemctl daemon-reload
if [ "$first_install" = true ]; then
	sudo systemctl enable --now identity.service
else
	sudo systemctl start identity.service
fi

# The service connects to the database before it listens, so the probe waits
# for it: a route outside the table is the one 404, and a token nobody holds
# names no account.
listen=$(sed -n 's/^IDENTITY_LISTEN=//p' "$stage_root/identity.env.next")
introspect=$(sed -n 's/^IDENTITY_INTROSPECT_LISTEN=//p' "$stage_root/identity.env.next")
tries=0
until [ "$(curl --connect-timeout 2 --max-time 5 -s -o /dev/null -w '%{http_code}' \
	"http://${listen:-127.0.0.1:9082}/vif/api/auth/update-probe")" = 404 ]; do
	tries=$((tries + 1))
	[ "$tries" -lt 40 ] || { echo "$0: identity did not answer on ${listen:-127.0.0.1:9082}" >&2; exit 1; }
	sleep 0.5
done
systemctl is-active --quiet identity.service
token=$(head -c 32 /dev/urandom | base64 | tr -d '=+/\n')
curl --connect-timeout 2 --max-time 5 -fsS -X POST -H 'Content-Type: application/json' \
	-d "{\"token\":\"$token\"}" "http://${introspect:-127.0.0.1:9083}/introspect" | grep -qx '{"account":null}'
sudo cmp -s "$source_unit" "$installed_unit"
sudo cmp -s "$repo_root/bin/identity" "$binary"
sudo cat "$installed_env" | cmp -s "$stage_root/identity.env.next" -

rollback_required=false
uninstall_required=false
service_stopped=false
echo "updated identity at revision $(git -C "$repo_root" rev-parse HEAD)"
