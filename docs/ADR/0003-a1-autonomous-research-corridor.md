# RFC 0001: A1 bounded autonomous research corridor

Status: accepted — A1 contracts frozen
Owner: Agent 0  
Scope: public, domain-neutral control-plane contracts  
Runtime status: implemented and acceptance-tested for the frozen offline/shadow product scope; final deployment and operational proof remain pending

## Decision

The next autonomous capability is a bounded A1 corridor, not a second organism, ledger, scheduler, queue, or scientific registry. It extends the existing durable control plane with exactly four public contracts:

1. `MaterialEvent` — a trusted, deterministic statement that an external or endogenous trigger is worth processing within a bounded energy lineage.
2. `CandidateSpecDraft` — an untrusted research proposal with a falsifiable question, exact evidence references, resource request, taint, and frozen code/context identity.
3. `AdmissionReceipt` — the deterministic allow, reject, or park result bound to a frozen admission snapshot and exact ledger revision.
4. `CapabilityProofReceipt` — independent evidence for a precise frozen scope. It never grants authority and never means that a capability is proven forever.

The schemas are additive to the frozen Core catalog. They do not change the scientific ownership boundary: the Bridge stores operational memory and references; domain registry writers alone create or mutate domain scientific truth.

## Trusted route

```text
untrusted SourceTrigger
→ deterministic MaterialityGate
→ trusted MaterialEvent
→ AITask / ProposalEnvelope
→ CandidateSpecDraft
→ frozen AdmissionSnapshot
→ deterministic AdmissionReceipt
→ existing JobSpec
→ BudgetReservation
→ one-use Permit
→ AttemptLease
→ L0 execution
→ ExecutionReceipt
→ domain-owned ValidationReceipt
→ LearningDecisionProposal
→ WAIT_AUTHORITY
```

An external collector cannot mint a trusted `MaterialEvent`. A model cannot admit its own draft. An `AdmissionReceipt` is not execution authority. The existing permit authority remains the only issuer of exact, bounded execution authority.

## Autonomy boundary

Within pre-authorized A1 policy, the organism may discover public or already registered material, generate proposals, reject or park unsafe proposals, run bounded sandbox experiments through the existing durable executor, remember failures, propose follow-up experiments, and expose its current state. It stops at `WAIT_AUTHORITY` before promotion, publication, canonical mutation, deployment, true holdout release, live trading, or live security execution.

This is the technical meaning of organism-level self-awareness in this system: every durable component declares identity, owner, inputs, outputs, authority, dependencies, health evidence, freshness, taint, budget, and stop behavior in machine-readable state. It is not a claim of consciousness and it never overrides policy or human authority.

## Frozen identities

Three identities are intentionally distinct:

- `object_id` identifies a durable content object;
- payload `receipt_id` identifies a decision/evidence receipt;
- `transport_idempotency_key` deduplicates delivery and retry.

Admission additionally binds candidate bytes, `AdmissionSnapshot`, ledger revision, Core and A1 catalogs, policy, context, release identity, and algorithm version. Equal frozen inputs yield the same decision identity. Changed inputs require a new receipt.

## Taint and evidence

`SHADOW_UNAPPLIED` is inherited. Shadow-derived knowledge may create only shadow-derived work until an authorized domain writer applies a validated decision. Model agreement is not independent evidence. Exact content deduplication and semantic novelty remain separate mechanisms; the latter never collapses identities or grants authority.

Evidence independence is multidimensional. Candidate drafts group evidence by provenance instead of pretending that several outputs from one model family are independent replications.

## Deterministic policy

`a1_sandbox_policy_v1` is fail-closed. It admits only named cheap research classes over synthetic, public sanitized, or already registered D1 references. Required fields include estimand, null, falsifier, stop condition, evidence references, independence groups, VCS identity, policy, and context.

The policy rejects private APIs, secret or account material, unregistered private data, true unseen holdouts, live actions, publication, external side effects, canonical writes, deploy/reboot/service-kill operations, unbounded network, authority escalation, and stale or mixed code identity. Budget exhaustion parks work. Unknown model-call outcomes preserve the reservation and require reconciliation; they do not auto-retry or silently release budget.

## Profiles

The A1 catalog hashes and binds ten machine-readable profiles:

| Profile | Purpose |
|---|---|
| writer/issuer matrix | exact owner, writer, issuer, and non-authority rules |
| sandbox policy | allowlist, hard denies, limits, idempotency, and UNKNOWN semantics |
| reason-code registry | deterministic decisions, parser bounds, and disclosure classes |
| authority corridor | trusted trigger route and all authority transitions |
| integrity profiles | current byte serialization behavior; no false JCS claim |
| IPC compatibility | 1.1 legacy plus additive 1.2 roles and deprecation rules |
| environment compatibility | exact proof dimensions across development, CI, and VPS shadow |
| storage coverage | one durable Bridge order, domain-owned truth, and replay coverage |
| evaluator exposure | feedback-query budgets and adaptive-probing controls |
| model role registry | replaceable role bindings with model outputs always untrusted |

## Model intelligence overlay

The initial role bindings use cheap models for scouting and routine research, an independent critic for falsification, stronger critics for material candidates, and a chief-scientist role for portfolio synthesis. These are replaceable bindings, not constitutional model names. A reserved arbiter slot remains disabled until shadow evaluation.

No model may assign its own role, create reason codes, reserve or release budget, admit work, issue permits, mutate canonical state, or treat consensus as evidence. Same-family effort levels are explicitly correlated.

## Capability proof

Capability maturity is reported separately from live pulse:

```text
DECLARED → OBSERVED → NEGATIVE_PROBE_PASSED → ENFORCEMENT_PROVEN
```

The evidence receipt can say only `PASS_FOR_FROZEN_SCOPE`, `FAILED`, `INCONCLUSIVE`, `STALE`, or `REVOKED`. Any drift in code, configuration, policy, schema, evaluator, tests, data, environment, or critical dependency invalidates the applicable proof scope.

## Compatibility and migration

Existing integrity behavior is recorded exactly. Sorted JSON is not declared equivalent to RFC 8785/JCS. A JCS change requires its own versioned migration and dual-read plan.

IPC 1.1 remains supported for operators during a measured deprecation window. IPC 1.2 adds separate collector and scout submission roles. Neither role can mint trusted events.

## Contract-freeze evidence

The freeze gate requires deterministic schema regeneration, exact profile hashes, strict envelopes and payloads, unchanged Core catalog bytes, authority and taint invariants, focused negative tests, full repository tests, clean diff, public-data scan, exact-head remote CI, and a separate Agent 0 freeze receipt. These checks are now mandatory through `make contracts` and `A1_CONTRACTS_FROZEN.json`.

No runtime module consumes the A1 contracts until that authority receipt is issued and E1 stage envelopes are pinned to its exact integration base.

## Non-goals

- no domain scientific payloads or domain truth in the public repository;
- no second event ledger, scheduler, database, queue, swarm, or vector database;
- no autonomous promotion or canonical mutation;
- no live trading or live security execution;
- no JCS migration in this stage;
- no claim that model intelligence or a passing test creates authority.
