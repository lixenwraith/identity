# The HTTP API

What the service answers, on two loopback listeners. The router forwards
`/vif/api/auth/` to the first byte for byte and asks the second itself; neither
is reachable from outside the node. In the scaffold every route bounds and
decodes its request as described and then answers `501 not_implemented`.

## Common

- Every request body is JSON, declared `Content-Type: application/json` (else
  `415 content_type`), at most 4096 bytes (else `413 request_too_large`), one
  document with no field the route does not name (else `400 malformed_request`).
- A refusal is `{"error":{"code":"…","message":"…"}}`, the router's own form,
  with `Cache-Control: no-store`. A wrong method is `405 method_not_allowed`
  with `Allow`; a path outside the routes is `404 not_found`.
- A signed-in request carries its token as `Authorization: Bearer <token>` or,
  from a page, in the `vif_sign_in` cookie (`HttpOnly`, `Secure`,
  `SameSite=Strict`, path `/vif/api/`). A request with neither, or with a
  revoked or expired token, is `401 unauthorized`.
- Budgets per client address, the one the router forwards in the configured
  header: `429 too_many_attempts` with `Retry-After` past 5 registrations, 10
  sign-ins or 5 deletions a minute. A service that cannot answer (the store or
  the SCRAM server down) is `503 busy`.
- Timestamps are RFC 3339 in UTC; ids are UUIDs.

## `POST /vif/api/auth/register`

The name and the credential the device derived under the deployment's one KDF
profile (`auth.Credential.Export`: `username`, `salt`, `argon_time`,
`argon_memory`, `argon_threads`, `stored_key`, `server_key`). The service runs
no KDF.

```json
{"name": "alice", "credential": {"username": "alice", "salt": "…", "argon_time": 3,
  "argon_memory": 65536, "argon_threads": 4, "stored_key": "…", "server_key": "…"}}
```

- `201` `{"id": "…", "name": "alice"}`. The name is stored in lowercase: 1 to 32
  of `a-z`, `0-9`, `_` and `-`, starting with a letter; it must equal the
  credential's `username`.
- `400 invalid_name`, `400 invalid_credential` (not the profile, a malformed
  key), `409 name_taken`, `503 accounts_full` at `-max-accounts`.

## `POST /vif/api/auth/login`

Two steps on the package's own Argon2-SCRAM protocol (`lixenwraith/auth`),
each one request. Only a verified server final authenticates; the client
checks `final.server_signature` before trusting the token.

The client first:

```json
{"client_first": {"username": "alice", "client_nonce": "…"}}
```

- `200` `{"challenge": {"full_nonce": "…", "salt": "…", "argon_time": 3,
  "argon_memory": 65536, "argon_threads": 4}}`. An unknown name receives a
  stable decoy challenge and fails at the proof as a wrong password does.

The proof, with the device's name and, for a page, `"session": "cookie"`:

```json
{"proof": {"full_nonce": "…", "client_proof": "…"}, "device": "laptop", "session": "cookie"}
```

- `200` `{"final": {"server_signature": "…", "username": "alice"},
  "token": "…", "expires_in": 2592000}`; with `session: cookie` the token is
  the `vif_sign_in` cookie instead and the body has no `token`.
- `401 unauthorized` for a wrong proof, an unknown name, an expired challenge
  or a disabled account alike; `400 malformed_request` for a body with both
  steps or neither, or a device name past 64 characters.

## `POST /vif/api/auth/logout`

Signed in; no body. Revokes the presented sign-in and clears the cookie.
`204`.

## `GET /vif/api/auth/me`

Signed in. The account and its live sign-ins, the presented one marked.

```json
{"id": "…", "name": "alice", "sign_ins": [
  {"id": "…", "device": "laptop", "created_at": "…", "last_seen_at": "…", "expires_at": "…", "current": true}]}
```

## `DELETE /vif/api/auth/sign-ins/<id>`

Signed in. Revokes one of the account's own sign-ins; another account's is
`404 not_found`, as is an id that is not a UUID. `204`.

## `POST /introspect`, on the introspection listener

The router's question, at most 1024 bytes:

```json
{"token": "…"}
```

- `200` `{"account": {"id": "…", "name": "alice"}}` for a live sign-in of an
  enabled account, with `"renewed": true` when the sign-in slid forward on this
  question (past half of its 30 days); `200` `{"account": null}` for any other
  token. The router mints an account ticket from the first and an anonymous
  one from the second.
- `400 malformed_request` without a token.
