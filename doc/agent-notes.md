# Agent Notes

What agents working on this repository learned that no rule in
[AGENTS.md](../AGENTS.md) and no design document states: facts that cost a
session time to rediscover, and how to check them. Read it before starting.
When a task teaches you one, add it in the same PR, one bullet under its topic.
Keep it short: delete a note that proves wrong, whose trap is gone, or that a
document or a code comment now states, and link that instead.

## Toolchain

- With `GOTOOLCHAIN=auto` the `go` on `PATH` switches to the version `go.mod`
  names, downloading it once; the `gofmt` on `PATH` does not, which is why
  `make fmt-check` runs the toolchain's own.

## The file store

- `store.File` holds its lock on `<path>.lock`, never on the store file: each
  write lands by rename, so a lock on the file itself would be on the inode
  the rename retires. A read-only open takes no lock and sees a complete file,
  since the rename is atomic.
- Every change is applied to a copy and written before the copy becomes the
  store, so a failed write leaves memory and disk agreeing. The tests of
  `store` run over both backends (`backends`); the handler and command tests
  take `storetest.Open`, a file unless the environment names a database.
- A test holding a `*store.File` holds its lock: the command test releases it
  around each `cli` call (`Target.Reopen`) and reads the fresh handle after,
  never one kept from before.

## The PostgreSQL client

- `internal/pg/scram_test.go` pins the client to RFC 7677 §3's exchange (user
  `user`, password `pencil`, both nonces given): a change to the arithmetic
  fails there before it fails against a server.
- PostgreSQL ignores the username inside the SCRAM client-first message and
  uses the startup packet's; libpq sends an empty one. This client sends the
  role name, which the server accepts and the auth message then carries on
  both sides.
- `crypto/pbkdf2.Key` takes the password as a `string` and returns an error
  with the key, unlike `x/crypto/pbkdf2`.
- The SSLRequest's answer is one bare byte, `S` or `N`, with no length or
  type; every message after the TLS handshake has the five-byte head. The
  startup message takes run-time settings as parameters, which is how the
  client pins `DateStyle`, `TimeZone` and `bytea_output` to what `scanText`
  reads: a timestamptz prints as `2006-01-02 15:04:05.999999+00`, with no `T`
  and the offset in hours alone, and Go's `time.Parse` takes the fraction
  without a layout for it.
- A `COMMIT` in a transaction a failed statement aborted answers the tag
  `ROLLBACK` and no error; `Tx.Commit` reads the tag. After an error in the
  extended protocol the server discards until `Sync`, so the reader runs to
  `ReadyForQuery` either way.
- A statement cancelled by its context is ended by closing the socket; the
  socket's own deadline trails the context's by a second, or the read's error
  is a bare `i/o timeout` instead of `context.DeadlineExceeded`.
- `Query` reads the whole result before it returns, so `Rows` holds no
  connection; a temporary table lives on one connection, so a test that needs
  one across statements runs them in a `Tx`.

## The SCRAM server

- `auth.ScramServer` keys credentials by the exact username string and the
  proof covers the spelling the client sent, so the credential's `username`
  must be the lowercase name and the client signs in with it; the handler
  passes the sign-in's spelling through verbatim and an unknown one gets the
  decoy. Until the first credential is loaded the decoy challenge advertises
  auth's default profile, not the configured one.
- The server's own sweep evicts a handshake every 15 s once it is 30 s old;
  the handler's `Abandon` after `handshakeTimeout` frees it at 30 s sharp,
  and a test shortens that variable instead of waiting.

## Tests

- `httptest.NewRequest` sets `RemoteAddr` to `192.0.2.1:1234`, not loopback; a
  test of what a loopback peer may do sets `RemoteAddr` itself.
- `http.NewResponseController(w).SetReadDeadline` returns `ErrNotSupported` on
  an `httptest.ResponseRecorder`; the handlers ignore that error on purpose.
- `auth.NewCredential` at the default cost allocates 64 MiB a call; tests pass
  `auth.WithMemory(8*1024), auth.WithTime(1)`, and a handler under test takes
  the same profile in `Options.KDF`, or every registration is refused.
- The database tests share one database, so `dbtest.Pool` holds a `flock` on
  a file in the temporary directory for the test's duration; the packages'
  test processes serialize there, not on an advisory lock, whose wait the
  role's `lock_timeout` would cut short. `go test ./...` runs them all with
  the three variables set; `pg`'s own tests are `package pg_test`, since
  `dbtest` imports `pg`.
- A local server: `initdb` refuses to run as root, so run it as `postgres` in
  a directory that user can reach (the scratchpad's parents are 0700 root);
  `ssl=on` with a certificate whose `subjectAltName` is `IP:127.0.0.1`, since
  `verify-full` checks the URL's host against it; `pg_hba.conf` with
  `hostssl identity identity 127.0.0.1/32 scram-sha-256`. The sandbox ships
  PostgreSQL 16, whose `CREATE DATABASE` lacks the builtin locale provider
  `setup.sql` names for 18: drop the `LOCALE_PROVIDER` and `BUILTIN_LOCALE`
  lines in a local copy, and nothing else.
- In CI the `postgres:18` service container starts without TLS and the client
  speaks nothing else, so a step copies a certificate for `localhost` in with
  `docker cp` (the container is `job.services.postgres.id`), turns `ssl` on
  with `ALTER SYSTEM` and `pg_reload_conf()`, both reloadable, and runs
  `setup.sql`; production stays `verify-full` only, with no test-only mode in
  the client.
- A workflow GitHub cannot evaluate fails with no jobs and the file's path as
  its name, which is all the API shows. A job's `env` has no `runner` context
  (`${{ runner.temp }}` there rejects the file); a step's `env` has, so the
  database variables sit on the test step.

## Design

- §10 of vif's catalog names no identity package, which is why the client is
  `internal/pg` and the rest is named by what it does.
- The sign-in cookie is scoped to `/vif/`, not `/vif/api/`: the router reads
  it on the browser route's upgrade at `/vif/ws/<id>`, which a narrower path
  would never carry it to.
