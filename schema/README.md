# The database

What the jail's administrator provisions for the identity service, once, and
how a migration lands. The service connects as the role `identity` to the
database `identity`, schema `identity`, over TLS with SCRAM-SHA-256, from the
node alone. `setup.sql` creates the role, the database and the schema; the
numbered files are the migrations, applied in order; `deploy/backup.sh` is the
nightly `pg_dump`. Addresses here are placeholders.

## Files

- `setup.sql`: the role `identity` (login, SCRAM password, 12 connections, no
  other right), the database (`template0`, builtin `C.UTF-8`), `public`
  revoked, the schema, `search_path` and the statement, lock and
  idle-in-transaction timeouts on the role. `-v split=true` makes a `NOLOGIN`
  owner role, `identity_owner`, that owns the schema while `identity` only
  reads and writes rows.
- `001_init.sql`: version 1, the tables `accounts`, `verifiers` and
  `sign_ins`, the one-row `schema_version`, and the grants the runtime role
  needs on them. Each later migration is the next number, records its own
  version and grants what it creates; `schema.Migrations` refuses a gap.
- `schema.go`: embeds the files, so the binary carries the schema it expects
  and refuses to start on any other version.

## The server, on the jail

1. Install and initialize, as PostgreSQL's own documentation says, with
   `--auth-local=peer --auth-host=reject` so nothing is admitted until the
   lines below are.
2. Give the server a certificate the node can verify, a self-signed one for
   its internal address or name, kept 0600 by `postgres`:

   ```sh
   jail# openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
       -subj '/CN=<jail-address>' -addext 'subjectAltName=IP:<jail-address>' \
       -keyout server.key -out server.crt
   ```

   A name in place of the address takes `DNS:<name>` and the node dials that
   name. The certificate (never the key) is copied to the node as
   `/etc/identity/db-ca.crt`; an issuer-signed certificate copies the issuer's
   instead.
3. In `postgresql.conf`: `listen_addresses = '<jail-address>'`, `ssl = on`,
   `ssl_cert_file` and `ssl_key_file` naming the files above, and
   `password_encryption = scram-sha-256`.
4. In `pg_hba.conf`, the administrator over the socket and the service over
   TLS from the node's address; a line that matches nothing is a refusal:

   ```
   # TYPE    DATABASE  USER      ADDRESS             METHOD
   local     all       postgres                      peer
   hostssl   identity  identity  <node-address>/32   scram-sha-256
   ```

5. Reload, then provision. The role's password is generated into a 0600 file
   and reaches `psql` as a variable, so it is in neither this repository nor
   the shell history; the same file's content becomes the node's
   `/etc/identity/db-password`:

   ```sh
   jail# (umask 077; openssl rand -base64 24 > /root/identity.db-password)
   jail# su -m postgres -c "psql -X -d postgres -v password=\"'\$(cat /root/identity.db-password)'\" -f schema/setup.sql"
   ```

   Split mode adds `-v split=true`.
6. Migrate, as the schema's owner, each file in one transaction and in order:

   ```sh
   jail# su -m postgres -c "psql -X -1 -d identity -c 'SET ROLE identity' -f schema/001_init.sql"          # owner mode
   jail# su -m postgres -c "psql -X -1 -d identity -c 'SET ROLE identity_owner' -f schema/001_init.sql"    # split mode
   ```

   In owner mode the node may migrate instead, with the role's own connection:
   `identity migrate -db-url ... -db-password-file ... -db-ca-file ...`, which
   `deploy/update-identity.sh` runs before each update and which applies
   nothing when the schema is current. The service checks the version at start
   and refuses any other; in split mode an upgrade that adds a migration is
   applied here, as the owner, before the update.

## Verifying

```sh
jail# su -m postgres -c "psql -X -d identity -Atc 'SELECT version FROM identity.schema_version'"   # 1
jail# su -m postgres -c "psql -X -d identity -c '\dt identity.*'"                                 # accounts, schema_version, sign_ins, verifiers
jail# su -m postgres -c "psql -X -d identity -c '\drds'"                                          # identity: search_path and timeouts
jail# sockstat -4 -6 -l | grep postgres                                                           # the internal address alone
```

From the node, the role connects over TLS and nothing else does:

```sh
node$ psql 'postgres://identity@<jail-address>:5432/identity?sslmode=verify-full&sslrootcert=/etc/identity/db-ca.crt' -Atc 'SHOW search_path'   # identity
node$ psql 'postgres://identity@<jail-address>:5432/postgres?sslmode=verify-full&sslrootcert=/etc/identity/db-ca.crt' -c 'SELECT 1'            # refused by pg_hba
```

Administration uses the `postgres` account over the socket. Its `search_path`
does not include `identity`, so every statement names the schema
(`identity.accounts`). What the tables hold:

- `identity.schema_version`: one row, the applied version.
- `identity.accounts`: `account_id`, the lowercase `name`, `created_at`,
  `disabled_at` (set when the operator disables the account).
- `identity.verifiers`: one row an account, the salt, the Argon2id parameters,
  `stored_key` and `server_key`. No password is stored anywhere.
- `identity.sign_ins`: one row a device, the SHA-256 of the token, the device's
  name, `last_seen_at` and `expires_at`.

Deleting an account takes its verifier and sign-ins with it; deleting a
sign-in row signs that device out at its next request.

## Backups

`deploy/backup.sh` runs `pg_dump --format=custom` as `postgres` and keeps 14
days (`IDENTITY_BACKUP_KEEP`); [deploy/README.md](../deploy/README.md) installs
and schedules it. Restore into a freshly provisioned database:

```sh
jail# su -m postgres -c 'pg_restore --no-owner --role=identity -d identity <dump>'   # --role=identity_owner in split mode
```
