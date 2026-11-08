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
- The binary: `/usr/local/bin/identity`, root 0755, from `make release`.
- `backup.sh`: on the jail, `/usr/local/sbin/identity-backup`, root 0555; bash 5.

## The node

```sh
node$ make release
node# install -o root -g root -m 0755 bin/identity /usr/local/bin/identity
node# install -o root -g root -m 0644 deploy/identity.sysusers /etc/sysusers.d/identity.conf && systemd-sysusers
node# install -d -o root -g identity -m 0750 /etc/identity
node# install -o root -g identity -m 0640 deploy/identity.env /etc/identity/identity.env    # then fill in <jail-address>
node# install -o root -g root -m 0600 /dev/null /etc/identity/db-password                    # then paste the role's password
node# install -o root -g root -m 0644 server.crt /etc/identity/db-ca.crt
node# install -o root -g root -m 0644 deploy/identity.service /etc/systemd/system/identity.service
node# systemctl daemon-reload && systemctl enable --now identity
node$ curl -sS -X POST -H 'Content-Type: application/json' -d '{"token":"x"}' http://127.0.0.1:9083/introspect
```

The last line answers in the error form (`501 not_implemented` from the
scaffold); `journalctl -u identity` holds the JSON log, which names no
credential. Where the router forwards `/vif/api/auth/` to and where it asks
its question are the router's settings (vif's `deploy/guest/vif-router.env`):
`IDENTITY_LISTEN` and `IDENTITY_INTROSPECT_LISTEN` here.

An update installs the new binary and restarts the unit; the service's restart
pauses sign-ins and account tickets alone, so it needs no empty fleet. Keep
the previous binary as `/usr/local/bin/identity.previous` and restore it the
same way if the new one does not come up.

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
