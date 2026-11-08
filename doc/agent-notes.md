# Agent Notes

What agents working on this repository learned that no rule in
[AGENTS.md](../AGENTS.md) and no design document states: facts that cost a
session time to rediscover, and how to check them. Read it before starting.
When a task teaches you one, add it in the same PR, one bullet under its topic.
Keep it short: delete a note that proves wrong, whose trap is gone, or that a
document or a code comment now states, and link that instead.

## Toolchain

- The `gofmt` on a container's `PATH` can be older than the module's Go; run
  `"$(go env GOROOT)/bin/gofmt" -l`, which `make fmt-check` does. With
  `GOTOOLCHAIN=auto` the `go` on `PATH` switches to the version `go.mod`
  names, downloading it once.
- `go mod tidy` drops `lixenwraith/auth` from `go.mod` while no package imports
  it yet; the store, the api and the config do, so a tidy after any of them
  compiles keeps it.
- `lixenwraith/auth` v0.5.2 is the first release with `ScramServer.Abandon`,
  which frees a handshake whose client dropped after the challenge.

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

## Tests

- `httptest.NewRequest` sets `RemoteAddr` to `192.0.2.1:1234`, not loopback; a
  test of what a loopback peer may do sets `RemoteAddr` itself.
- `http.NewResponseController(w).SetReadDeadline` returns `ErrNotSupported` on
  an `httptest.ResponseRecorder`; the handlers ignore that error on purpose.
- `auth.NewCredential` at the default cost allocates 64 MiB a call; tests pass
  `auth.WithMemory(8*1024), auth.WithTime(1)`.

## Design

- The design of record is vif's `doc/auth-session-design.md`; this repository's
  `doc/design.md` adds the service's own decisions. §10 of vif's catalog names
  no identity package, which is why the client is `internal/pg` and the rest is
  named by what it does.
