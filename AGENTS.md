# Working rules

It is the contract, not a suggestion.

Read [doc/agent-notes.md](doc/agent-notes.md) before starting: it holds what earlier
agents learned that neither these rules nor [doc/design.md](doc/design.md) state.
When a task teaches you something the next agent would otherwise rediscover, add it
there in the same PR.

## Comments

- A comment block is **at most 5 lines**. If the explanation needs more, the code
  is wrong or the explanation belongs in `doc/`.
- One line is the default. Comment *why*, never *what* — the code says what.
- No narrative, no history ("this used to…", "the plan proposed…"), no restating
  the diff, no essays on design philosophy. Git log and `doc/` hold those.
- No dates, commit or PR references, or plan/phase labels in comments. Multi-step
  work is tracked in `doc/todo.md`, never in code.
- No comment on a self-evident function. `// Lookup returns the address` above
  `func Lookup` is noise.
- Package doc blocks: 5 lines. Files do not get their own prologue.

## Files

- Do not create a file for one or a few helpers. Put them next to what uses them,
  or, if shared, in the package's main or type file.
- A new file needs a new concept, not a new function.
- Prefer editing an existing file over adding one.
- When you edit a file, bring its comments up to these rules.

## Scope

- Implement what was asked. Do not add tables, indirection, telemetry, tests or
  abstraction that nothing asked for.
  Exception: a task that explicitly invites additions gets the obvious ones, each
  named in the PR body; ask before any that is not obvious.
- One mechanism per problem. Two mechanisms doing one job is a bug or a refactor
  opportunity.
- Delete before adding. If a change is net-positive lines for a fix, justify it.
- Reverting an existing API to "improve" it is not a fix. Leave working code alone.
- Per-kind data lives in one table indexed by its kind (`api.routes`, one row a
  resource); a new kind adds a row, never a switch or a parallel field.
- The service is at v0: a change may break the API, the schema or a flag, and
  takes the next minor version; never hold or narrow a fix for backward
  compatibility. A schema change is a new migration all the same.

## Tests

- One test per rule, named for the rule. No test that restates another.
- Test comments follow the 5-line limit.
- Do not pin lists that a human has to hand-maintain unless the pin prevents a
  real regression.
- Collapse tests: when a broader test covers a narrower one, delete the narrower
  one or do not add it. No test for simple behaviour that is unlikely to fail or
  is already exercised elsewhere.
- A test derives a credential at a low Argon2 cost (`auth.WithMemory`,
  `auth.WithTime`); the default costs 64 MiB a derivation.
- A test of the store or of `pg` against a database needs one: it skips without
  the connection its environment names, and CI provides a PostgreSQL 18 service.

## Docs and commits

- Docs are short. Condense when you touch them; append only for a new concept or
  scope.
- Docs are read in terminals, where a Markdown table renders as its source. Lay
  tabular content out as a nested list; a matrix of figures goes in a fenced code
  block with its columns aligned by spaces, which the terminal keeps.
- The repository describes the architecture, never a machine: docs, scripts and
  examples use placeholders (`<jail-address>`, `<node-address>`) for addresses,
  node names and credentials. The host, the jail's network and the site's edge
  are configured outside this repository; ask for the specific output rather than
  guess at them.
- A gap you are deferring goes in `doc/todo.md`: extend the item it belongs to, or
  add a concise one in the file's pattern.
- PR bodies: what changed, why, how it was verified.
- A change made for performance reports its measurement, before and after, in the
  PR body: the reading, the shape it was taken in, and the benefit in the unit the
  user feels (RSS, CPU, latency). A projection is not a result.
- Commits start with the area in lowercase and say what, as a sentence
  (`store: a sign-in's renewal slides its expiry`).
- One task, one branch, one PR. Divide the work into commits on that branch; do not
  split it across stacked PRs or multiple branches.
- Work that continues after its PR merged starts again from the latest main; never
  stack new commits on merged history.
- Once a PR is merged or closed unmerged, delete its branch on GitHub and locally
  if this session can. A session that cannot says so once in its report and leaves
  the branch; it never retries.

## Gates

`go build ./...`, `go vet ./...`, `gofmt -l` with the toolchain's own gofmt
(`make fmt-check`) and `go test ./...`; `make verify` runs them with the static and
`linux/arm64` builds and `bash -n deploy/backup.sh`.
- Do not run `-race` tests unless investigating a known/suspected race issue; CI
  runs them.
- A change to a SQL file is applied to a fresh PostgreSQL 18 before it lands, and
  `schema.Migrations` must still list the files without a gap.

## Identity

- The design is vif's `doc/auth-session-design.md` (D8 to D11, D17, §7.5, §8
  phase 5, §9); `doc/design.md` records this service's own decisions. A change
  that contradicts either changes the decision first, in the document.
- The service holds verifiers and token hashes: never a password, a salted
  password or a token. A new column, log field, error message or debug line is
  checked against that before it lands, and a refusal names no credential.
- `internal/pg` is the PostgreSQL client, on the standard library alone:
  `crypto/tls`, `crypto/pbkdf2`, `crypto/hmac`. No driver, no `database/sql`.
  `Exec` without arguments is one simple query and may hold several statements
  (a migration); with arguments it is prepared and bound, so no value is ever
  spliced into SQL. Its SCRAM client is pinned to RFC 7677's vectors.
- Every statement lives in `internal/store`, one method each, unqualified names
  resolved by the role's `search_path`. A schema change is a new `schema/NNN_*.sql`
  that records its own version and grants the runtime role what it needs; a
  released migration is never edited.
- The HTTP surface is `api.routes`. Every body is bounded (`api.MaxBody`) and
  declared JSON before it is decoded; unknown fields are refused; every refusal
  is an `api.Refusal`, the router's `{"error":{"code","message"}}`; the
  introspection listener uses the same form.
- Both listeners bind loopback alone (`config.Validate`), and the client address
  is believed from the router's header on a loopback peer alone
  (`Handler.clientAddr`). Per-address budgets count that address.
- The KDF runs on the device. The service derives a credential only in the
  operator's reset; registration checks the credential against the one profile
  (`config.KDF`) and refuses another, since a mixed population tells a prober
  which accounts exist. `auth.ScramServer` holds every verifier and the decoy
  key, which lives in the state directory alone.
- Secrets reach the process through files: `config.ReadSecretFile` (a regular
  file, 0600, trimmed) for the database password and the decoy key; never a flag
  value, an environment variable or a URL.
- Comparisons of secrets are constant time (`crypto/subtle`, `hmac.Equal`), and
  an unknown name costs what a wrong password does.
- The budget is §9's: under 256 MiB, a pool of ten connections, one HMAC a
  proof. A change that moves either reports its reading.
