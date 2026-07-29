# Full compatibility suite sharding

Issue #3 replaces the single opaque `jest --runInBand` invocation with six
checked-in semantic groups from `config/full-suite-groups.json`:

| Group | Stable scope |
|---|---|
| `core-fsm` | FSM, ledger, schema, integrity, stable reads, and transaction invariants |
| `git-worktree` | mechanical P1, Git refs, worktree bootstrap, and write sets |
| `recovery-rotation` | crash recovery, expiry, leases, store recovery, and protocol/runtime rotation |
| `source-handoff` | export/import, checkpoint fencing, source compatibility, and Codex handoff |
| `github-resource` | canonical GitHub/resource contracts, canaries, preclaims, and browser resource server |
| `usability-security` | CLI usability, preflight, capabilities, evidence, rejection containment, and redaction |

Large single-file suites have multiple named semantic entries. Jest reports every
test in every entry result, including unmatched tests as pending. After the last
entry for a file, the runner fails unless every discovered test executed exactly
once. This makes the selection mechanically exhaustive without adding
`skip`, `retry`, or randomized shard allocation.

## Measured first-pass baseline

The candidate started at `55aba02dbb289b0782fac1a5a7f4a8639826918e`.
Validation used an untracked, read-only `node_modules` tree installed by
`CI=1 pnpm install --frozen-lockfile` in a separate clone at that exact commit.
The candidate never stages that symlink. The original 34-file Jest command and
the instrumented groups were measured on the same host and dependency tree:

| Base suite/measurement | Observed duration | Result and use |
|---|---:|---|
| original `pnpm test:full` inventory | 972.190 s | 34 suites / 939 tests; no heartbeat or current-suite output |
| `goalControl.test.ts` | 24.731 s | split into four semantic entries |
| `goalControlProtocolRotation.test.ts` | 16.417 s | split into four semantic entries |
| `goalControlSourceHandoff.test.ts` | 43.772 s | split into four semantic entries |
| `goalControlUsability.test.ts` | 11.440 s | split into three semantic entries |
| `goalControlSecurity.test.ts` | 18.817 s | split by its five top-level semantic describes |
| `goalControlPreflight.test.ts` | 10.278 s | isolated entry in usability/security |

| Instrumented group | Observed duration | Executed tests | Partition errors |
|---|---:|---:|---:|
| `core-fsm` | 88.021 s | 208 | 0 |
| `git-worktree` | 99.511 s | 178 | 0 |
| `recovery-rotation` | 88.717 s | 146 | 0 |
| `source-handoff` | 258.697 s | 137 | 0 |
| `github-resource` | 267.305 s | 126 | 0 |
| `usability-security` | 72.310 s | 151 | 0 |

Source handoff and GitHub/resource, and Git/worktree and recovery/rotation, were
run in pairs, so these are conservative local balancing observations rather
than isolated CI timings. The original and instrumented runs fail existing
isolation/SIGKILL assertions on this candidate-worktree host with
`TEST_MODE_FORBIDDEN`; those failures are retained and reported. No coverage is
skipped or retried. All six groups still produced JUnit, timings, redacted
diagnostics, heartbeats for long entries, and an empty exactly-once partition
error set. Exact acceptance PASS/FAIL remains the fresh GitHub CI result.

## Budget and observability contract

- Every shard has a checked-in ceiling of 1,200 seconds (20 minutes).
- The Full CI job has a 30-minute ceiling: the manifest validator parses the
  checked-in workflow and rejects less than the 20-minute runner ceiling plus
  a named 600-second setup/post margin for checkout, install, validation, and
  artifact uploads.
- PR CI fetches the base commit and rejects increases to the global or per-group
  budget. Pull requests select `pull_request.base.sha`; pushes to `main` select
  `event.before`. CI rejects empty and all-zero bases, while explicit local
  validation may run without a base. A base that predates this manifest uses
  the documented initial 20-minute ceiling rather than silently claiming a
  comparison.
- Manifest validation parses the actual Full `strategy.matrix.group` list and
  rejects omissions, renames, extras, and duplicates relative to the exact six
  checked-in groups.
- Budget-base validation parses the active Full workflow step structurally. It
  requires exactly one named validation step and the four exact active `env`
  values; commented, moved, duplicated, renamed, missing, or altered wiring is
  rejected. The required step may not use `if` or `continue-on-error`, and must
  contain exactly one active `run: pnpm verify:full-suite-groups`.
- The runner's own timeout fires before GitHub's 30-minute job timeout, prints
  the active PID, current semantic step, and full revision, terminates the whole
  child process group, and writes a mode-0600 redacted diagnostic. Termination
  remains awaited through bounded SIGTERM grace and SIGKILL escalation, and
  completes only after the process-group liveness probe reports it gone.
- A timeout stops the group after confirmed teardown. Any signal, escalation,
  or liveness failure is a fatal entry/group result: the runner updates the
  uploadable diagnostic with the redacted cleanup error and signal state,
  detaches unreaped handles, and never starts the next semantic entry.
- If the group budget expires between entries, the runner writes the same
  failure-artifact class with the previous/next step, null active PID, full
  revision, and an explicit timeout reason before exiting.
- A heartbeat names the group and current entry at most every 15 seconds.
- Each group writes JUnit XML, timings JSON, total duration, entry durations,
  executed-test counts, and the slowest 20 tests.
- Failure artifacts contain only recursively redacted output tails. Capability,
  authorization, cookie, password, secret, and token keys/values are removed
  before console or artifact emission. Header and assignment forms use the same
  complete-value redaction, including `Authorization:`/`Authorization=` and
  `Cookie:`/`Cookie=`.
- `pnpm test:full` runs the six groups sequentially for local reproduction.
  `pnpm test:full:shard -- --group <id>` is the stable CI entry.
- `pnpm check` adds only the sub-second manifest/policy validation and preserves
  the immutable-base Fast Jest selection. The runner's 30 behavioral tests run
  in Full and remain directly invocable for focused validation. In the matched
  local tree, the exact immutable-base Fast selection passed 46/46; the candidate
  preserves that selection. The matched `pnpm check` reached the pre-existing
  binding tests after 46/46 Fast passes and failed on the same host isolation
  condition described above; the full command took 49.69 seconds, within the
  roadmap's two-minute Core fast budget.
