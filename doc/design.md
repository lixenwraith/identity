# Identity service design

What the service decided and why, how its packages fit, how each flow runs,
what it refuses and where it runs. The decisions it inherits are vif's
([authentication and session design](https://github.com/lixenwraith/vif/blob/main/doc/auth-session-design.md),
D8 to D11, D17, §7.5, §8 phase 5, §9); the ones below are the service's own,
each with the alternative it passed over. What remains is §5 and
[todo.md](todo.md).

## 0. Decisions

- **D1. The PostgreSQL client is the service's own, on the standard library**
  (`internal/pg`): the version 3 protocol over `crypto/tls`, SCRAM-SHA-256 SASL
  on `crypto/pbkdf2` and `crypto/hmac`, the simple and extended query protocols
  with text results, a pool of ten. The schema is three tables; pgx's dozen
  modules are what chess carries and this service does not need, and a driver
  is the largest dependency a service this small could take. The client speaks
  `SCRAM-SHA-256` without channel binding and verifies the server's certificate
  instead (`verify-full` is the only mode), and sends the password as given
  without SASLprep, so the role's password is printable ASCII, which `openssl
  rand -base64` produces. The SCRAM arithmetic is pinned to RFC 7677's vectors.
- **D2. A sign-in is opaque.** 32 random bytes in the bearer alphabet, whose
  SHA-256 the store keeps; one per device, named, revocable one by one, sliding
  over 30 days and renewed past half its life on the router's question. A JWT
  would spare the lookup the router makes once per account ticket, 170 a second
  at the launch-day rate and nothing at rest, and would cost revocation, a key
  and a second mechanism beside the store that exists anyway (vif's D7).
- **D3. Verifiers, never passwords.** The device derives the Argon2id-SCRAM
  credential under the deployment's one profile and sends it at registration;
  the store keeps the salt, the parameters, `StoredKey` and `ServerKey` in a row
  of their own, apart from the account, so a reset replaces one row and an
  account listing never carries key material. The service runs no KDF: at any
  rate of sign-ins or registrations the server side is one HMAC, where chess's
  shape, Argon2id on the server, serves two sign-ins a second at 256 MiB. The
  one server-side Argon2 is the operator's reset.
- **D4. Two loopback listeners.** The router forwards `/vif/api/auth/` byte for
  byte, so whatever the public path reaches, this listener must be safe to
  publish; the router's own question lives on a second socket the forward never
  reaches. Two sockets rather than one path check: no filter rule and no prefix
  comparison stands between the public and the router's authority. Both bind a
  loopback literal, refused otherwise at start.
- **D5. A decoy key in the state directory.** `auth.NewScramServerWithDecoyKey`
  needs 32 secret bytes that outlive the process, so an unknown name's challenge
  is the same salt on every restart and a probe cannot tell an account from
  none. The service makes the key at first start, 0600 under
  `StateDirectory=identity`, and reads it as it reads every secret: a regular
  file no other user can open. The key is not in the database: it is the one
  secret the service has, and the database's compromise should not hand it over.
- **D6. One error form, the router's.** `{"error":{"code","message"}}` on every
  refusal of both listeners, so the page that reads the router's answers reads
  the service's with the same code; `Cache-Control: no-store` on all of them.
- **D7. Roles and privileges.** A database, a schema and a login role all named
  `identity`, as chess lays its own out; the role has `CONNECT`, `USAGE` and
  the rows, `search_path` and the statement, lock and idle-in-transaction
  timeouts set on it; `public` revoked. Optional split: a `NOLOGIN` owner that
  migrates and a runtime role that reads and writes rows, each migration
  granting what it creates. From the node the role authenticates with
  SCRAM-SHA-256 over `hostssl` from one address; no other TCP client is
  admitted. Each migration records its own version, so psql on the jail and
  the store's `Migrate` are one mechanism.
- **D8. Budgets by the router's address.** The service sees one peer, the
  router, so the player's address comes in the header the router forwards
  (`-client-address-header`), believed only when the peer is loopback;
  registration, sign-in and deletion are bounded per address as chess bounds
  them (5, 10 and 5 a minute), accounts by `-max-accounts`, in-flight
  handshakes by the SCRAM server's 4096, and every body by 4096 bytes before it
  is decoded. The table is logwisp's shape: a burst, a rate, an IPv6 address
  counted by its /64; a sign-in's attempt is refunded on success and kept on
  failure, and an exchange without its proof is abandoned after the handshake
  timeout, so an address holds at most its burst of them.
- **D9. A name has one spelling.** Lowercase, `^[a-z][a-z0-9_-]{0,31}$`, checked
  by the store and by the schema alike, so what the coordinator copies onto a
  roster entry (vif's D15) needs no escaping and two spellings are one account.
- **D10. Logs hold no credential.** JSON lines on standard output for the
  journal, a refusal at `debug` with its status, code and client address, a
  start and a stop at `info`; never a token, a proof, a password or a URL with
  one. The service's logs stay off the public log stream.

## 1. Shape

```
cmd/identity          flags → config; wires the rest; two http.Servers; the sweep; shutdown;
                      the operator's migrate and account commands
internal/config       the flags and their checks; ReadSecretFile; the KDF profile
internal/pg           the PostgreSQL client: Config, ParseURL, TLSConfig, Pool, Tx, Rows, Error
internal/store        accounts, verifiers, sign-ins: one statement a method; Migrate, CheckSchema
internal/api          /vif/api/auth/: the routes table, the handlers, the budgets, Refusal, ReadJSON
internal/introspect   POST /introspect on the second listener
internal/dbtest       the test database the environment names; a test skips without one
internal/version      the build's identity
schema                setup.sql, the numbered migrations, Migrations()
```

Dependencies point down: `api` and `introspect` use `store`, `store` uses `pg`
and `schema`, `config` uses `pg` for the URL's check, `introspect` uses `api`
for the error form, and the tests use `dbtest`, which uses `pg`. `cmd/identity`
alone knows every package. The only module beyond the standard library is
`lixenwraith/auth`, for `Credential`, `ScramServer` and the SCRAM message types
the API carries.

## 2. Flows

- **Registration.** The body is bounded and decoded; the name is normalized;
  the credential is imported (`auth.ImportCredential`), validated and held to
  the one KDF profile and to its `username` equalling the name; the store
  creates the account and its verifier under one advisory lock with the cap;
  the SCRAM server takes the credential; `201` with the id.
- **Sign-in.** The client first is passed to `ScramServer.ProcessClientFirstMessage`
  under the address's budget, with the name as the client spelled it, and
  answered with the challenge; an exchange whose proof never comes is released
  with `Abandon` after the handshake timeout. The proof goes to
  `ProcessClientFinalMessage`; a verified one, for an account still enabled,
  makes a token (`api.NewToken`), a sign-in row with the token's hash, the
  device's name and a 30-day expiry, and answers the server final with the
  token, or with the cookie for a page.
- **Introspection.** The router posts a token; the store finds the live sign-in
  of an enabled account by its hash, or none; past half the lifetime the row's
  `last_seen_at` and `expires_at` slide forward and the answer says `renewed`.
- **Logout and revocation.** The presented token's row is deleted, or one of the
  account's own by id; a later request with that token is `401`, and the router
  mints no account ticket from it. A pass already in a session is left to the
  session's rule (vif's D13).
- **The account's view.** `me` lists the account and its live sign-ins, the
  presented one marked, so a device list is what the player revokes from.
- **The operator's reset.** The CLI derives a new credential on the server, the
  one place Argon2 runs here, replaces the verifier and deletes every sign-in.
  Disabling an account keeps its rows and refuses its sign-ins at the proof
  and at introspection; deleting it cascades. A verifier added or reset
  reaches the running service at its next start, which loads them all and
  refuses one derived under another profile than its flags name.
- **The sweep.** Once an hour the service deletes the sign-ins past their
  expiry; no lookup finds them before that, so this is housekeeping.

## 3. Posture

The threats of vif's §6 that reach this service, and the part that meets each:

- Guessing and enumerating accounts: one path for a known and an unknown name
  (the decoy key, D5), one KDF profile (D3), per-address budgets (D8), a
  constant-time comparison of every proof and signature.
- Exhausting the server's KDF memory: there is no server KDF (D3); the proof
  path is one HMAC, bounded by the SCRAM server's 4096 handshakes of 30 s.
- A token read off the wire: it crosses TLS alone; the router strips it before
  the pod; a stolen one is revoked from the device list, and the store's copy is
  a hash (D2).
- A database copy: verifiers and token hashes; no password, no token, not the
  decoy key (D3, D5).
- Something other than the router reaching the service: both listeners are
  loopback (D4); the address header is believed from loopback alone (D8); the
  unit holds no capability, a read-only system and one writable directory.
- A malformed or oversized request: bounded before decoding, JSON declared and
  strict, unknown fields refused (D8); timeouts on every read and write.

## 4. Deployment

In roles, never machines (the host, the jail's network and the site's edge are
configured outside this repository):

- **The node** runs `identity` as a system user of its own under
  `deploy/identity.service`: the state directory for the decoy key, the
  database password as a systemd credential, two loopback listeners, under 256
  MiB. Its update needs no empty fleet, since its restart pauses only sign-ins
  and account tickets.
- **The jail** runs PostgreSQL 18 on the host's internal network with the
  server's certificate, `hostssl` and SCRAM-SHA-256 for the role from the node's
  address alone, provisioned by `schema/setup.sql`, migrated by the numbered
  files, backed up nightly by `deploy/backup.sh` ([schema/README.md](../schema/README.md)).
- **The router** forwards `/vif/api/auth/` to the first listener, asks the
  second once per account ticket, and mints from a page's cookie only on a
  request whose `Origin` is its own.

## 5. What remains

The service is built as designed: the `pg` client, the handlers and their
budgets, introspection, the operator's commands, the sweep and the deployment's
updater, each tested against a real PostgreSQL. [todo.md](todo.md) holds what
is left, in order: the readings §9 asks for (RSS at 10,000 verifiers, the
launch-day introspection rate); the jail's address as an `IPAddressAllow`
drop-in once the deployment names it; a way for an operator's add or reset to
reach the running service without a restart.
