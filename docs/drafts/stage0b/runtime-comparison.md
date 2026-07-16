# Stage 0B runtime comparison — Agent 2 draft

Status: `DRAFT_FOR_AGENT0_AUDIT`
Owner: Agent 2
Source: two owned runtime snapshots inspected read-only at tracked HEAD
Scope boundary: domain-neutral runtime behavior only; no source extraction
Evidence status: 72 focused candidate tests passed; Bridge conformance remains unimplemented
Next action: Agent 0 issues source freezes and canonical reuse decisions

## Executive recommendation

Select exactly one canonical mechanical runtime owner: `bridge_job_ledger`.

Compose it as follows:

```text
Bridge Permit + AttemptLease gate
→ one atomic claim and monotonic fencing owner
→ deterministic chunk runner
→ verified checkpoint manifests
→ untrusted staging
→ trusted ingestion
→ artifact durability
→ ExecutionReceipt published last
→ independent domain validator
```

The owned durable runtime is the stronger basis for the job ledger, fencing,
checkpoint and deterministic resume behavior. The owned control runtime is the
stronger basis for the fail-closed authority front door, replay protection,
concurrency admission and conservative no-replay recovery.

Do not preserve both run ledgers. Dual ownership would create disagreement
about the current lease, completion state and recovery authority.

## Capability decisions proposed to Agent 0

| Capability | Recommendation | Proposed owner | Reason |
|---|---|---|---|
| Mutable control-file durability | Extract then harden | `bridge_durable_fs` | Small atomic replacement is reusable; add regular-file and no-follow defenses. |
| Job ledger, checkpoints and fencing | Adapter; select one owner | `bridge_job_ledger` | Existing resumable runtime already proves WAL, immutable checkpoints, fences and resume equality. |
| CAS and staging | Reject both as complete CAS; adapt publication primitive | `bridge_trusted_ingestor` | One candidate has strong exclusive immutable publication, but neither implements the frozen Bridge staging and classification boundary. |
| Receipts | Bridge-native adapters only | `researchd` | Frozen Bridge schemas must remain canonical; only integrity patterns are reusable. |
| Recovery | Compose policies in one ledger | `bridge_job_ledger` | Resume deterministic chunks; park or fail ambiguous non-resumable starts without replay. |

These are proposed decisions, not a `ReuseDecisionReceipt`, and they carry no
canonical reuse authority.

## Evidence summary

### Owned control runtime

Observed strengths:

- atomic file replacement with file and parent-directory durability;
- hash-chained mission, issuance and run records;
- exact decision/lease binding;
- short-lived leases, nonce and replay rejection;
- atomic concurrency reservation;
- deterministic interruption seams;
- conservative recovery that does not replay ambiguous work.

Observed limits:

- no chunk checkpoint contract;
- no monotonic fencing epoch;
- no indexed RNG;
- full-ledger replacement grows with history;
- private schemas do not conform to Bridge v1;
- no trusted staging-to-CAS boundary.

### Owned durable runtime

Observed strengths:

- SQLite WAL with full synchronization;
- immutable job spec hashes;
- leases bound to attempt, worker and boot identity;
- monotonic fencing tokens and heartbeat expiry;
- content-hashed immutable checkpoints;
- deterministic indexed chunk seeds;
- corrupt-checkpoint rejection before resumed adapter work;
- resumed and uninterrupted result-SHA equality;
- exclusive regular-file publication and exact-winner adoption;
- content-addressed recovery and soak receipt patterns.

Observed limits:

- private schemas do not conform to Bridge v1;
- no Bridge Permit, policy, approval or budget binding before claim;
- validation currently executes inside the runner boundary;
- no D0–D3 payload classification enforcement;
- no frozen `StagingEnvelope`/trusted-ingestor separation;
- not a complete global CAS: quota, retention, garbage collection and orphan
  reconciliation are incomplete;
- host paths are used where the public Bridge requires portable opaque refs;
- offline container and network denial are outside the primitive.

## Required architecture boundary

The runner may check only mechanical integrity:

- schema shape;
- output completeness;
- deterministic bindings;
- checkpoint and artifact hashes;
- forbidden authority fields.

It must not determine or apply a scientific outcome. A pinned domain validator
emits `ValidationReceipt`; the domain registry writer is the only outcome
writer. Bridge retains only permitted references and hashes.

For D2/D3 checkpoints, Bridge stores only `CheckpointManifest.payload_ref` and
the assertion that the payload is in the Domain Vault. D2/D3 bytes never enter
Bridge CAS or staging.

## Mandatory gaps before extraction or implementation

1. Agent 0 must issue a `SourceFreezeReceipt` for each selected snapshot.
2. Public-release ownership and licensing must be recorded before owned code
   enters the public repository.
3. Private schemas must map explicitly to frozen Bridge v1 contracts.
4. Permit, policy, approval and budget bindings must be checked before claim.
5. `AttemptLease` must use a fencing epoch and opaque fencing token.
6. Trusted ingestion must separate runner staging from artifact publication.
7. Receipt-last ordering must cover files and canonical state, including crash
   windows between filesystem and database commits.
8. Timestamps must bind wall time, monotonic time and boot identity.
9. SQLite WAL backup, restore and corruption behavior needs a dedicated drill.
10. CAS quota, retention, orphan reconciliation and garbage collection need
    explicit bounded policies.
11. Runner isolation must prove no network and enforced resource limits.
12. Path outputs must become portable refs and must not disclose host layout.

## Minimal conformance suite

The first runtime implementation is not admissible until tests prove:

1. invalid, expired, replayed or mismatched Permit/Lease causes zero writes;
2. concurrent claim has exactly one winner;
3. stale fencing cannot checkpoint, stage or complete;
4. indexed RNG and resumed output equal uninterrupted output by SHA;
5. corrupt checkpoints stop before adapter work;
6. every file/database/receipt crash boundary recovers without false success;
7. receipt appears only after artifacts and canonical state are durable;
8. D2/D3 bytes are rejected while Domain Vault refs are accepted;
9. symlinks, non-regular files, short writes and disk-full fail closed;
10. workers cannot emit or apply scientific outcomes;
11. a boot change fences the old attempt and monitoring resumes;
12. WAL backup/restore preserves event and checkpoint integrity;
13. orphan reconciliation is idempotent and bounded by quota;
14. the offline runner has no network and cannot escape resource limits.

## Draft decision boundary

This comparison supports three likely canonical decisions:

```text
ADAPTER: owned control gate patterns before every claim
ADAPTER/EXTRACT: owned durable job ledger and publication patterns
REJECT AS COMPLETE: either candidate as a ready-made Bridge CAS
```

Agent 0 must still bind exact sources, licenses, tests, rollback and canonical
owners in `ReuseDecisionReceipt` objects. Until then, no code extraction is
authorized.
