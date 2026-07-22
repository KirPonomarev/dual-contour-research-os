# ADR 0010: mission-bound paired research ingress

Status: accepted for `P04_RESEARCH_INGRESS_ADDITIVE_REPAIR_V1`.

## Context

Frozen P04 v1 correctly validates two independent `DomainExportBinding/1.0.0`
objects and submits two frozen-shape `SourceTrigger` objects through one local
collector. It intentionally has no research-mission field and its accepted
receipts must remain valid. The Recovery Plan v3.1 mission therefore could not
bind the current Market and Security exports to downstream MaterialEvents and
model reservations. The root condition is
`BLOCKED_INGRESS_CONTRACT_VERSION`, not missing provider capability.

## Decision

Keep `DomainExportBinding/1.0.0`, `OperationalActionEnvelope/1.0.0`,
`SourceTrigger/1.0.0`, `MaterialEvent/1.0.0`, and the hash-bound
`tools/physical_release_control.py` byte-identical. Add two strict contracts:

- `ResearchMissionEnvelope/1.0.0` binds the plan, mission, content-addressed
  artifact and the exact prepared Kimi request as the same hash-bound object,
  three project fingerprints and runtime heads, two exact export
  binding hashes, paired execution identity, expected domains, expiry,
  provider boundary, stop/rollback rules, and zero live/domain/canonical
  authority.
- `ResearchIngressActionEnvelope/1.0.0` binds that exact mission envelope to
  host, service, collector UID, paired execution, provider cap, and zero-write
  ingress boundary.

The additive `tools/research_ingress_control.py` imports the frozen P04
validators and receipt primitives. One O_EXCL-protected invocation validates
both current domain exports, creates exactly two deterministic frozen-shape
SourceTriggers, and then queues one mission. Each trigger carries the same
`registered:research-mission/<sha256>` evidence ref plus its own exact domain
binding ref. The existing MaterialEvent minter copies those refs unchanged.

Protocol 1.3 adds only mission-specific commands. The authenticated collector
may queue a fully validated mission after both MaterialEvents exist; it cannot
reserve a model call. The existing advisor timer invokes one bounded Scout
advance before its normal WIP=1 dispatch lookup. Researchd remains the sole
writer and uses the existing model broker for the exact sequence:

1. `SCOUT_FAST` → `deepseek-v4-flash`, effort max;
2. `RESEARCH_WORKER` → `deepseek-v4-pro`, effort max;
3. `CRITIC_PRIMARY` → `kimi-k3-max`, effort max;
4. `CRITIC_DEEP` → `gpt-5.6-sol-xhigh`, effort xhigh;
5. `CHIEF_SCIENTIST` → `gpt-5.6-sol-xhigh`, effort xhigh.

Fallback and caller-selected binding are denied. An unavailable exact role
returns `WAIT_PROVIDER`/`PARKED`; it never substitutes another model.

## Durability and recovery

Researchd publishes sanitized D0/D1 mission/request bytes to its existing
private input CAS. Immutable mission manifests, per-role reservation receipts,
and one terminal model-chain receipt use O_EXCL creation under the existing
runtime root. Broker state remains in the existing append-only ledger. A crash
after reservation recovers the exact request by its SHA; the next Scout tick
observes the existing call and cannot reserve a duplicate. A SENT call retains
the existing conservative UNKNOWN recovery rule.

The connected worker still keeps raw provider envelopes in its owner-only
private CAS. For mission calls only, it returns the already-extracted D0/D1
text with the content ref; researchd verifies the hash and stores it in the
input CAS so later bounded roles can consume prior results. Requests include
the prepared Kimi request SHA, bounded excerpts, and exact full CAS refs. No raw response, credential, domain
payload, or private available-binding inventory enters Git.

## Authority and consequences

Ingress itself performs `provider_calls=0`, `domain_writes=0`,
`canonical_writes=0`, and grants no live authority. Model outputs remain C3
untrusted proposals. The model-chain terminal receipt is not scientific
promotion or a domain write; independent evidence adjudication and any later
domain implementation still require their existing authorities.

This repair changes the Bridge runtime image and the existing advisor/worker
surface, so physical activation requires a new exact image identity, bounded
Bridge-only ActionEnvelope, preserved ledger/rollback, and post-restart
verification. It does not require Market or Security deployment or restart.

## Rejected alternatives

- Adding mission fields to domain-owned v1 payloads: rejected as a frozen
  contract and authority violation.
- Inventing `use_count` in `OperationalActionEnvelope/1.0.0`: rejected; replay
  is enforced by mission/action identity, broker idempotency, and O_EXCL
  receipts.
- One synthetic combined SourceTrigger: rejected because it erases the two
  domain owners and cross-domain swap checks.
- Manual/direct model reservation or provider calls: rejected because it
  bypasses the organism and cannot prove the required lineage.
- A new broker, daemon, queue, or writer: rejected as unnecessary; the current
  AF_UNIX, researchd, ledger, CAS, broker, timer, and worker are sufficient.
