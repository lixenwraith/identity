<p align="center">
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.27.3-00ADD8?style=flat&logo=go" alt="Go"></a>
  <a href="https://opensource.org/licenses/BSD-3-Clause"><img src="https://img.shields.io/badge/License-BSD_3--Clause-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Status-v0.2.1-blue" alt="Status: v0.2.1">
</p>

# identity

The account service for [vif](https://github.com/lixenwraith/vif): registration,
sign-in by Argon2-SCRAM, one sign-in per device with its revocation, and one
loopback question for the router, which account does this token name. It is
generic, so [chess](https://github.com/lixenwraith/chess) can adopt it as its
account service in a session of its own, and the game binary never names a
database driver.

**Status: v0.2.1, the service as designed.** The routes, the PostgreSQL client
on the standard library, a file store for a deployment too small for a
database, the operator's commands, the hourly sweep and the deployment's
updater, each tested against the file and against a real PostgreSQL.
[doc/todo.md](doc/todo.md) lists what remains: the budget's readings, the
jail's address filter, and an operator's change reaching the running service
without a restart.

## How it fits

- The router forwards `/vif/api/auth/` to this service byte for byte over
  loopback, as it forwards the log stream; the service answers nothing outside
  that prefix and binds no public port.
- On a second loopback listener the forward never reaches, the router asks
  `POST /introspect` once per account ticket: which account a sign-in token
  names. A renewal of the sign-in past half its life rides the same request.
- The game's `:login <site>` and `:logout`, and the site's lobby page, are its
  clients; a page keeps its sign-in in an `HttpOnly`, `Secure`,
  `SameSite=Strict` cookie scoped to `/vif/`, a terminal in a 0600 file,
  Android in private storage.
- Accounts live in PostgreSQL 18 in a FreeBSD jail, reached from the node over
  the host's internal network with TLS and a SCRAM-SHA-256 role password read
  from a 0600 file. The client is the service's own, on the standard library.
  A deployment too small for a database keeps them in one JSON file instead
  (`-store-file`), rewritten whole on each change.
- Nothing here is a JWT. `lixenwraith/auth` is taken for Argon2id and SCRAM,
  and for nothing else.

## What it holds, and never holds

- The KDF runs on the player's device. Registration sends the derived
  credential (`auth.Credential.Export`), checked against the deployment's one
  Argon2id profile (64 MiB, 3 passes, 4 lanes by default) and a name policy;
  the service runs no KDF at any rate of sign-ins or registrations. The one
  server-side Argon2 is the operator's password reset.
- A verifier is what is stored: the salt, the parameters, `StoredKey` and
  `ServerKey`. Never a password, never a salted password.
- A sign-in is opaque: 32 random bytes whose SHA-256 the service stores, one
  per device, named, revocable one by one, sliding over 30 days and renewed past
  half its life. A copy of the table signs nobody in.
- An unknown name and a known one take one path: the SCRAM server's decoy key,
  made once and kept 0600 in the state directory, keeps an unknown name's
  challenge stable across restarts.
- Budgets per client address, believed from the router's loopback address
  alone; a `-max-accounts` cap; every body bounded before it is decoded; every
  refusal one JSON form; no credential in a log line.
- Recovery is an operator's reset. There is no email.

## Build and run

```sh
make build        # bin/identity; plain make lists the targets
make verify       # vet, gofmt, the tests, the static and linux/arm64 builds
bin/identity -h
```

```sh
bin/identity \
    -db-url 'postgres://identity@<jail-address>:5432/identity?sslmode=verify-full' \
    -db-password-file /etc/identity/db-password \
    -db-ca-file /etc/identity/db-ca.crt
```

The operator's commands take the same store flags, after the command:
`identity migrate` applies the embedded migrations; `identity account add
<name>` reads a password from the terminal, or from standard input when it is
not one, and derives the credential on the server under the configured
profile; `account disable|enable|delete <name>`, `account reset <name>` (a new
credential, every sign-in deleted) and `account list`. An account added or
reset is loaded by the service at its next start.

The handler, introspection, command and store tests run against a file store
in a temporary directory, and against PostgreSQL when `IDENTITY_TEST_DB_URL`
(the service's URL form), `IDENTITY_TEST_DB_CA` (the server's certificate) and
`IDENTITY_TEST_DB_PASSWORD_FILE` (the role's password, a 0600 file) name one;
the client's own tests need it and skip without it. CI runs everything against
PostgreSQL 18 with TLS turned on (`.github/workflows/test.yml` sets the server
up).

The flags, each with its default in `-h`:

- `-listen` (`127.0.0.1:9082`): the `/vif/api/auth/` listener the router
  forwards to; `-introspect-listen` (`127.0.0.1:9083`): the router's question.
  Both must bind a loopback address, and they must differ.
- `-state-dir` (`/var/lib/identity`, or systemd's `$STATE_DIRECTORY`): the
  decoy key's directory, 0700; the key is made at first start.
- `-store-file`: the absolute path of a JSON file holding the accounts in
  place of PostgreSQL, 0600, made at first start and held by the running
  service; the database flags are then ignored, and an operator's change runs
  while the service is stopped (`account list` reads beside it).
- `-db-url`: `postgres://user@host[:port]/database[?sslmode=verify-full]`. A
  password in it, any other `sslmode` or any other parameter is refused.
  `-db-password-file`: the role's password, a 0600 file. `-db-ca-file`: the PEM
  certificate the server is verified against, its own or its issuer's; empty
  trusts the system roots. `-db-pool` (10): connections held at most.
- `-kdf-memory` (65536 KiB), `-kdf-time` (3), `-kdf-threads` (4): the one
  profile every credential is derived under.
- `-max-accounts` (0, no cap); `-client-address-header` (`X-Real-IP`): the
  header the router forwards the player's address in; `-log-level` (`info`);
  `-version`.

Logs are JSON lines on standard output, one record a refusal at `debug`, never
a credential.

## The API

[doc/api.md](doc/api.md) is the contract. In short, under `/vif/api/auth/`:

- `POST register`: a name and a derived credential; `201` with the account's id.
- `POST login`, two steps: the client first, answered with the challenge; the
  client final with the device's name, answered with the server final and the
  sign-in, a bearer token or, for a page that asked, a cookie.
- `POST logout`; `GET me` (id, name, the sign-ins by device);
  `DELETE sign-ins/<id>`.
- On the introspection listener, `POST /introspect` with a token, answered with
  the account's id and name, or with none.

An error is `{"error":{"code":"…","message":"…"}}`, the router's own form.

## Deployment

The repository describes the architecture, never a machine; addresses are
placeholders. [deploy/README.md](deploy/README.md) says where each file lands.

- The node runs the service as the system user `identity` under
  `deploy/identity.service`: `ProtectSystem=strict`, a `StateDirectory` for the
  decoy key, the database password loaded as a systemd credential, two loopback
  listeners, no capability. `deploy/identity.env` holds its settings and no
  secret. `deploy/update-identity.sh` builds from the checkout, migrates the
  schema, keeps the previous binary, settings and unit, restarts and probes
  both listeners, restoring the previous service if the new one does not
  answer.
- The jail runs PostgreSQL 18: the database, schema and role `identity`,
  `hostssl` and SCRAM-SHA-256 from the node's address alone, the server's
  certificate copied to the node. [schema/README.md](schema/README.md) is the
  procedure, `schema/setup.sql` the provisioning, `schema/001_init.sql` the
  first migration, `deploy/backup.sh` the nightly `pg_dump`. Without a jail,
  `IDENTITY_STORE_FILE` names the file instead ([deploy/README.md](deploy/README.md)).

## Documentation

- [Design](doc/design.md): the service's decisions, its packages, each flow,
  its security posture and the deployment's roles.
- [API](doc/api.md): every route, request and answer.
- [Agent notes](doc/agent-notes.md): what working on this repository teaches
  that no document states.
- [To do](doc/todo.md): what remains, in order.
- [AGENTS.md](AGENTS.md): the working rules.

The decisions this service serves are vif's, in
[its authentication and session design](https://github.com/lixenwraith/vif/blob/main/doc/auth-session-design.md):
D8 to D11, D17, §7.5, §8 (phase 5) and §9.

## System requirements

- Linux with systemd on the node (Arch Linux in production), FreeBSD for the
  jail's PostgreSQL 18 and the backup script (bash 5).
- To build: Go 1.27.3, and GNU make or BSD make.

## License

BSD 3-Clause License
