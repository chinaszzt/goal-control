# TASK-example · Control-plane shadow-mode example

> Immutable packet revision `1`. This file contains static task semantics only.
> Runtime state, thread identities, current HEADs, evidence, and leases belong in the git common-dir control store and launch manifest.
> This is a documentation template, not an init-ready packet: placeholder repository identities
> and HEAD values must be replaced, committed, and re-hashed in the controlled repository.

## Identity

- Goal: `example-goal`
- Task: `TASK-example`
- Packet revision: `1`
- Supersedes: NONE
- Issue: N/A (documentation fixture)
- Base branch: `main`
- Frozen base HEAD: `<replace-with-full-40-hex-host-base-head>`
- Prerequisite tasks: NONE
- Parallel group: `example-wave-1`
- Peer tasks: NONE
- Integration order: `1`

## Authoritative sources

- Constitution: `<host-constitution-path>`
- Host policy: `<host-policy-path>@<sha256>`
- Protocol pack: `<host-protocol-pack-manifest-path>@<sha256>`
- Goal manifest: `docs/planning/goals/example/manifest.json`
- Shared protocol: `docs/planning/session-protocol/shared.md`
- Role protocol: `docs/planning/session-protocol/captain.md`

## Scope

### Must deliver

- Demonstrate a machine-readable task packet reference in shadow mode.
- Keep every runtime identity and mutable status outside this packet.
- Bind all generated evidence to this packet revision/hash and one full task HEAD.

### Non-goals

- Do not create, message, or archive a real Codex thread.
- Do not access a real account, tenant, browser profile, or customer record.
- Do not change application behavior.

### Do not touch

- Business source files.
- Production credentials or user profiles.
- Session JSONL transcripts.

## Implementation contract

1. A CAPTAIN reads this packet and the Goal manifest.
2. The control plane validates role, event identity, actor sequence, CAS revision, control epoch, packet hash, and full HEAD before accepting an event.
3. The CAPTAIN executes only the action returned by the control plane and records the result as a new structured event.
4. FOREMAN receives only a hard blocker, a ready-for-merge summary, or an incident summary.

## Seam contract

| Seam | Producer | Consumer | Contract | Failure behavior |
|---|---|---|---|---|
| `SEAM-example-event` | CAPTAIN | control plane | Event envelope is validated against the registered role/thread and bound to packet hash + full HEAD. | Reject without changing accepted state. |
| `SEAM-example-evidence` | DEV/REVIEW/RECEIPT | CAPTAIN | Evidence records carry the same packet hash and full HEAD as the transition they support. | Mark stale and refuse downstream transition. |

## Acceptance ownership

| AC | Observable result | This task owns | Evidence | Final owner |
|---|---|---|---|---|
| `AC-example-001` | Shadow mode reports the legal next action without mutating external systems. | All | CLI fixture output | `TASK-example` |
| `AC-example-002` | A stale packet hash or short HEAD is rejected and accepted state is unchanged. | All | Automated negative-path test | `TASK-example` |

## Deterministic preflight

- Packet bytes match the SHA-256 recorded in the Goal and launch manifests.
- Repository, base branch, base HEAD, worktree, branch, and task HEAD match the launch manifest.
- Required resource leases are active and owned by this task/role.
- Fast gate, Full CI, scoped AC audit, REVIEW, and RECEIPT evidence all bind the same packet hash and full HEAD.

## Environment and data

- Mode: `SHADOW`
- Write permission: none
- Test identities: aliases only; no PII or credentials

## Resource requirements

| Resource key rule | Access | Purpose |
|---|---|---|
| `preview-port:example-preview-port` | `EXCLUSIVE` | Keep the example preview/proxy port group single-owner; the concrete port is runtime metadata, not part of this declared key. |
| `browser-profile:example-browser-profile` | `EXCLUSIVE` | Keep browser state isolated from every other task. |
| `test-data:example-readonly-fixture` | `SHARED_READ` | Demonstrate explicitly shareable, read-only fixture access. |

The actual lease IDs, fencing tokens, allocated port, and profile path are runtime data and must not be written back into this packet.

## Hard-stop categories

- `BLOCKED_SECURITY`
- `BLOCKED_EXTERNAL_FACT`
- `ENV_IDENTITY_INCIDENT`

No role may downgrade or clear these holds without the required durable release evidence.

## Exit criteria

- Manifest, event, launch, evidence, and resource records validate against their schemas.
- Illegal role/state transitions, duplicate divergent events, stale CAS/epoch/hash/HEAD, and resource conflicts fail closed.
- Generated status/ledger can be rebuilt from accepted events alone.
