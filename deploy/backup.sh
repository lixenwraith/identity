#!/usr/bin/env bash
# Nightly logical backup of the identity database, run on the jail as postgres
# over the Unix socket: pg_dump --format=custom into IDENTITY_BACKUP_DIR (default
# backups/ in the postgres home), kept IDENTITY_BACKUP_KEEP days (default 14).
# Installed as /usr/local/sbin/identity-backup and scheduled by cron
# (deploy/README.md); the restore is schema/README.md's.
set -euo pipefail
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
((BASH_VERSINFO[0] >= 5)) || { echo "identity-backup: bash 5 or newer is required" >&2; exit 1; }

dir=${IDENTITY_BACKUP_DIR:-${HOME:?HOME is unset; set IDENTITY_BACKUP_DIR}/backups}
keep=${IDENTITY_BACKUP_KEEP:-14}
[[ $keep =~ ^[0-9]+$ ]] || { echo "identity-backup: IDENTITY_BACKUP_KEEP must be a number of days" >&2; exit 2; }
umask 077
mkdir -p "$dir"

# Written beside its final name and renamed when whole, so a dump cut short by
# a reboot is never mistaken for a backup; a failed run leaves nothing behind.
target="$dir/identity-$(date -u +%Y%m%dT%H%M%SZ).dump"
trap 'rm -f -- "$target.partial"' EXIT
pg_dump --format=custom --dbname=identity --file="$target.partial"
mv -- "$target.partial" "$target"
trap - EXIT
find "$dir" -name 'identity-*.dump' -type f -mtime "+$keep" -delete
