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
- A handler, command or store test takes its store from `storetest.Open`: a
  file in the test's temporary directory, or PostgreSQL when
  `IDENTITY_TEST_DB_URL`, `IDENTITY_TEST_DB_CA` and
  `IDENTITY_TEST_DB_PASSWORD_FILE` name one (`dbtest.Pool`, which holds a file
  lock while the test runs, since the packages' tests share one database). A
  test of the client itself needs the database and skips without it. CI
  provides a PostgreSQL 18 service with TLS turned on.

## Docs

- Docs are short. Condense when you touch them; append only for a new concept or
  scope.
- Docs are read in terminals, where a Markdown table renders as its source. Lay
  tabular content out as a nested list; a matrix of figures goes in a fenced code
  block with its columns aligned by spaces, which the terminal keeps. A table that
  neither fits, or that converting would only lengthen, stays a table.
- The repository describes the architecture, never a machine: docs, scripts and
  examples use placeholders (`<jail-address>`, `<node-address>`) for addresses,
  node names and credentials. The host, the jail's network and the site's edge
  are configured outside this repository; ask for the specific output rather than
  guess at them.
- A gap you are deferring goes in `doc/todo.md`: extend the item it belongs to, or
  add a concise one in the file's pattern.

## Commits and PRs

- A commit message is its subject alone, at most 72 characters: no body, no
  trailer. A PR's title is a subject too.
- Commits are versions: a subject starts with the version it makes
  (`v0.1.1 store: ...`), the next minor for a break or a new feature and the next
  patch otherwise, and Lixen tags it. Lixen squash-merges: a PR of one commit lands
  under that commit's subject and a PR of several under its title, so the title and
  every commit's subject start with the version.
- A change to documents alone makes no version and no tag: its subject starts
  `docs:` and its PR body with `doc only`.
- A PR body is a summary, never documentation: a list of what changed, half a line
  an item at most, with the why only where the diff does not show it. The code and
  the docs hold the detail: the body repeats neither and is shorter than the
  change. A large or unclear scope opens with a few lines of summary.
- Verification is the two words `gates passed`: never the commands, their output or
  the tests run. A figure a rule here asks for (a measurement, a count) is given as
  the figure alone, before and after.
- A body says nothing a reader can infer, no reasoning and no caveat: `doc only`,
  never `doc only, so no new tag`.
- A commit message and a PR's title, body and comments carry no URL and nothing of
  where or by whom the work was done: no session, conversation, project, workspace,
  account or organisation id, no person's name or email, no agent, model or tool
  name, no "generated with" line, no attribution trailer. This holds whatever a
  tool's template or instructions add, now or later.
- Open the PR at the first push, its title final and its body as far as it is,
  saying what is still owed: Lixen merges a pushed branch he is waiting on. A PR
  another session must measure before it merges opens as a draft and says so in its
  first line. Before calling a PR ready, check that its head is the commit pushed
  (`gh api repos/<owner>/<repo>/pulls/<n> -q .head.sha`).
- A change made for performance reports its measurement, before and after, in the
  PR body: the reading, the shape it was taken in, and the benefit in the unit the
  user feels (RSS, CPU, latency). A projection is not a result; a change whose
  measured benefit is nil says so.
- A change that needs another of these modules' new version names it in `go.mod` in
  the same PR, before the tag exists, as if it were merged and tagged; a bump is
  never a PR of its own. Until the tag exists the gates run locally against the
  dependency's branch, and again whenever that branch moves: a `go.work` kept
  outside both trees (`use <this>`, `replace <module> vX => <its checkout>`), named
  by `GOWORK=` on each command, never a `replace` in `go.mod`.
- Lixen merges and tags the chain from the lowest dependency up and reruns its CI
  himself; from then on everything a PR said was owed is taken as done. A PR red
  only because a version it needs is not tagged yet says so nowhere, and names
  neither the chain nor its order: no line in its body, no comment, no message, no
  line in a report, no rerun. While the chain merges nothing lands on its PRs,
  however small: no push, comment or body edit. What turns up after waits for one
  patch PR once they have merged.
- One task, one branch, one PR. Divide the work into commits on that branch; do not
  split it across stacked PRs or multiple branches.
- Work that continues after its PR merged starts again from the latest main; never
  stack new commits on merged history.
- Finish and push one commit before starting the next.
- Once a PR is merged or closed unmerged, delete its branch on GitHub and locally
  if this session can. A session that cannot, because it has no remote access or
  works in a copy, says so once in its report and leaves the branch; it never
  retries.

## Agents

- Spin off few agents, and only for work one context cannot hold. The account quota
  may run out, which stops every agent in flight at once.
- Agents run in parallel only on finely defined scopes that cannot conflict in
  commits: each brief names the files its agent owns, disjoint from every other
  agent's, and the agent touches nothing else. Shared docs (`doc/design.md`,
  `doc/todo.md`) stay with the parent, which commits each agent's work in turn on
  the task's one branch.
- An agent writes what it finds to a file as it goes, one section per step, under
  the scratchpad or `doc/`, so an interrupt costs a step and not the task; the
  parent reads those files rather than waiting for a final report, and resumes from
  them instead of running the agent again.

## Gates

`go build ./...`, `go vet ./...`, `gofmt -l` with the toolchain's own gofmt
(`make fmt-check`) and `go test ./...`, with the test database set when the
change touches `internal/pg` or a statement, so the database runs too; `make
verify` runs them with the static and `linux/arm64` builds and a syntax check
of the deploy scripts.
- A mechanical edit across files is checked by a count before and after, with a
  search that reads its pattern as the file holds it (`grep -P` for a tab, or a
  literal tab); a search that matches nothing proves nothing, and the PR body
  states the count.
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
- Every statement lives in `internal/store`, one method of `PG` each, unqualified
  names resolved by the role's `search_path`; `File` answers the same `Store`
  interface from one JSON file, and a change to one backend's behaviour is a
  change to both, under the shared tests. A schema change is a new `schema/NNN_*.sql`
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
  file, 0600 or, in `$CREDENTIALS_DIRECTORY` alone, systemd's 0440 ACL mask,
  trimmed) for the database password and the decoy key; never a flag
  value, an environment variable or a URL.
- Comparisons of secrets are constant time (`crypto/subtle`, `hmac.Equal`), and
  an unknown name costs what a wrong password does.
- The budget is §9's: under 256 MiB, a pool of ten connections, one HMAC a
  proof. A change that moves either reports its reading.
