# To Do

Planned work, in order. Each item names what to build, how it fits the seams
in place, and how to verify it. Finished items leave this list for the design
document.

1. **The `pg` wire protocol.** `Open` dials with `ConnectTimeout`, sends
   `SSLRequest`, upgrades with `Config.TLS`, sends the startup message
   (`user`, `database`, `application_name=identity`), runs the SASL exchange
   with the `scram` client already in place, then reads `ParameterStatus`,
   `BackendKeyData` and `ReadyForQuery`. `Exec` without arguments is the simple
   query; with arguments Parse, Bind (text parameters), Describe, Execute and
   Sync, results in text. `Rows.Scan` converts as its comment promises; `Error`
   is parsed from `ErrorResponse` fields `S`, `C`, `M`, `D` and `n`. The pool
   holds `MaxConns` connections, checks one at `Open`, and drops a connection
   whose statement failed on the wire. Verify with an integration test against
   PostgreSQL 18 (chess's `test.yml` service shape; skip without the
   connection the environment names) that migrates a fresh database with
   `schema/001_init.sql`, round-trips a verifier and a sign-in, and reads a
   unique violation as `IsUniqueViolation`.
2. **The handlers behind `api.routes`.** Registration (`ImportCredential`, the
   profile and name checks, `store.CreateAccount`, `ScramServer.AddCredential`),
   sign-in in two steps with `Abandon` for a dropped client, `NewToken`, the
   sign-in row and the cookie for `session: cookie`; logout, `me` and the
   deletion over the presented token. The per-address table in logwisp's
   `netacl.Table` shape, with chess's bounds. Verify with handler tests over a
   store on the integration database, and the error paths in `doc/api.md`.
3. **Introspection.** `store.SignInByToken`, the renewal past half the lifetime
   (`RenewSignIn`), `{"account": null}` for any other token. Verify with the
   same database.
4. **The operator CLI** (`identity migrate`, `identity account add|disable|
   enable|reset|list|delete`): the password prompted, never passed; the reset
   derives with `auth.NewCredential` under the configured profile, replaces the
   verifier and deletes every sign-in. The deploy README then names it in place
   of psql for migrations in owner mode.
5. **The expired sign-in sweep**: `DeleteExpiredSignIns` on a timer, hourly.
6. **The deployment's helper**: an updater in the shape of vif's
   `update-vif-router.sh`, keeping `.previous`, without the empty-fleet gate;
   `IPAddressAllow` for the jail's address as a drop-in once the deployment
   names it. The readings §9 asks for: RSS at 10,000 verifiers loaded and under
   the launch-day rate of 170 introspections a second.
