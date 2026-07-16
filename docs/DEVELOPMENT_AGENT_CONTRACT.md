# Development agent contract

Status: canonical Stage 0A contract

## Roles

| Agent | Ownership |
|---|---|
| Agent 0 | contracts, canonical docs, root config, integration, release and deployment |
| Agent 1 | control plane, registry projection, budgets and IPC |
| Agent 2 | runner, artifacts, checkpoints and sandbox |
| Agent 3 | market adapters, fixtures and validator conformance |
| Agent 4 | security adapters, fixtures and validator conformance |
| Agent 5 | assurance drafts, adversarial tests, operations and recovery |

At most Agent 0 plus three child agents may be active. Agent 5 writes under `docs/drafts/assurance/`; Agent 0 alone promotes a draft to canonical documentation.

## StageEnvelope

Every worker stage must declare:

- stage and agent IDs;
- objective and executable blocker;
- exact base and contract SHA;
- branch and worktree;
- read-set, write-set, and forbidden scope;
- dependency hashes;
- acceptance commands;
- risk class, stop condition, expected receipt, and rollback.

No edit is allowed before the worker verifies these invariants.

## Ownership and branches

- One stage has one coherent outcome and one non-overlapping write-set.
- Branch format: `codex/bridge-a<agent-id>-<stage-id>`.
- A branch closes after its `IntegrationReceipt`.
- Frozen contracts change only through Agent 0, an RFC, version bump, migration policy, and conformance tests.
- Canonical docs, root configuration, CI, generated schemas, lockfiles, and migration numbering belong to Agent 0.

## Handoff

A worker returns:

- git head before/after;
- contracts consumed;
- files and artifacts changed;
- exact commands, exit codes, and final results;
- evidence-backed claims;
- known not-done items, risks, and compatibility notes;
- status `ready_for_agent0_audit` or `blocked_validation_failed`.

Workers do not declare global green, push/merge unless explicitly authorized, deploy, or write canonical scientific outcomes.

## Integration

Agent 0 verifies ownership, diff boundaries, secret/privacy scans, focused tests, negative tests, and dependency hashes. An accepted stage requires a non-force push or PR, green remote CI on the exact integration head, and an `IntegrationReceipt` before a new base is issued.

## Safety stop

Stop immediately on a deterministic mismatch, secret/private-data detection, authority ambiguity, contract drift, dirty-path collision, stale base, or evidence-integrity failure. Preserve evidence and continue only an independent safe tail.
