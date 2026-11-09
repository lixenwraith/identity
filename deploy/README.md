# deploy

The service's files on the node and the backup on the jail. Nothing here names
a machine: `<jail-address>` and `<node-address>` are the deployment's to fill
in. The database side is [schema/README.md](../schema/README.md).

## Where each file lands

- `identity.sysusers`: `/etc/sysusers.d/identity.conf`, root 0644, then
  `systemd-sysusers`; the locked system user and group `identity`, home
  `/var/lib/identity`, no shell.
- `identity.env`: `/etc/identity/identity.env`, `root:identity` 0640; the
  settings the unit renders as flags. `/etc/identity` itself is `root:identity`
  0750.
- `/etc/identity/db-password`: `root:root` 0600, the role's password as
  `setup.sql` received it, one line. The unit loads it as a systemd credential,
  so the service reads it from the credentials directory and never from its
  environment or arguments.
- `/etc/identity/db-ca.crt`: root 0644, the jail's server certificate or its
  issuer's; `-db-ca-file`.
- `identity.service`: `/etc/systemd/system/identity.service`, root 0644; a
  hardened unit with `StateDirectory=identity` (the decoy key, 0600, made at
  first start), `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`, no
  capability, 256 MiB.
- The binary: `/usr/local/bin/identity`, root 0755, from `make release`;
  `update-identity.sh` installs it, with the unit and the sysusers file, and
  keeps the previous binary as `/usr/local/libexec/identity.previous`, the
  previous settings and unit as `.previous` beside the installed ones.
- `backup.sh`: on the jail, `/usr/local/sbin/identity-backup`, root 0555; bash 5.

## The node

The settings, the password and the certificate are placed by hand, once; the
binary, the unit and the system user come from `update-identity.sh`, on the
first install and on every update. The jail's database is provisioned first
([schema/README.md](../schema/README.md)).

```sh
node# systemd-sysusers deploy/identity.sysusers
node# install -d -o root -g identity -m 0750 /etc/identity
node# install -o root -g identity -m 0640 deploy/identity.env /etc/identity/identity.env    # then fill in <jail-address>
node# install -o root -g root -m 0600 /dev/null /etc/identity/db-password                    # then paste the role's password
node# install -o root -g root -m 0644 server.crt /etc/identity/db-ca.crt
node$ deploy/update-identity.sh
```

The script refuses a worktree that differs from HEAD, builds `make release`,
runs `identity migrate` with the node's own role (nothing when the schema is
current; in split mode the jail's owner migrates first and this confirms the
version), installs the sysusers file, the binary, the settings rendered from
`deploy/identity.env` with the installed `IDENTITY_DB_URL` carried over, and
the unit, then starts the service and probes it: a route outside the table
answers `404` and `POST /introspect` with a random token answers
`{"account":null}`. On an update it stops the service first and keeps the
previous binary, settings and unit, restored if the new service does not
answer; a first install that does not answer is removed, so the next run
installs afresh; the restart pauses sign-ins and account tickets alone, so it needs no
empty fleet. `--render` prints the settings it would install.
`journalctl -u identity` holds the JSON log, which names no credential. Where
the router forwards `/vif/api/auth/` to and where it asks its question are the
router's settings (vif's `deploy/guest/vif-router.env`): `IDENTITY_LISTEN` and
`IDENTITY_INTROSPECT_LISTEN` here.

The operator's commands run on the node as root with the installed settings,
the password read from the terminal:

```sh
node# . /etc/identity/identity.env && identity account add alice -db-url "$IDENTITY_DB_URL" -db-password-file /etc/identity/db-password -db-ca-file "$IDENTITY_DB_CA_FILE"
node# systemctl restart identity    # an account added or reset is loaded at the next start
```

`account list`, `disable`, `enable`, `reset` and `delete` take the same flags.

## Without PostgreSQL

A deployment too small for a database, or a test node, keeps the accounts in
one JSON file under the unit's state directory, rewritten whole on each change
and held by the running service. Install the settings file with
`IDENTITY_STORE_FILE=/var/lib/identity/store.json` and skip the password and
certificate; the unit expects both, so a drop-in lets it start without them:

```sh
node# systemctl edit identity    # then paste:
[Unit]
ConditionPathExists=
ConditionPathExists=/etc/identity/identity.env
[Service]
LoadCredential=
```

`deploy/update-identity.sh` then builds, installs and probes as above, without
a migration: the service makes the file at first start and brings it to its
format itself. An operator's `account` command that changes the file runs
while the service is stopped, since the service holds the file; `account
list` reads beside it. Back the file up as any file: it holds verifiers and
token hashes, never a password, but a copy signs nobody in and still names
every account.

## The jail

Nightly at 03:30 as `postgres`, keeping 14 days under the postgres home's
`backups/`:

```sh
jail# install -o root -g wheel -m 0555 deploy/backup.sh /usr/local/sbin/identity-backup
jail# install -d -o postgres -g postgres -m 0700 /var/db/postgres/backups
jail# cat > /usr/local/etc/cron.d/identity-backup <<'CRON'
SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
30	3	*	*	*	postgres	IDENTITY_BACKUP_DIR=/var/db/postgres/backups /usr/local/sbin/identity-backup
CRON
```

Copy the dumps off the jail. The restore is in
[schema/README.md](../schema/README.md#backups).
