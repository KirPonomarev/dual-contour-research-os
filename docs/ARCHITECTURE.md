# Public architecture boundary

The system has six logical planes:

1. Governance — policy, contracts, authority and promotion.
2. Domain — scientific semantics, data, validators and canonical outcomes.
3. Bridge control — admission, queue, leases, budgets and mechanical state.
4. Execution — bounded offline runners and durable checkpoints.
5. Validation — independent checks and immutable validation receipts.
6. Evolution — replication, learning decisions and governed mutation proposals.

The public repository implements domain-neutral Bridge contracts and control-plane primitives. Domain repositories remain canonical owners of scientific truth and sensitive artifacts.

These six planes are logical trust and ownership boundaries, not a count of operating-system processes or deployable services. A runtime may implement several planes in one process, but it may not collapse their authority boundaries.

Canonical flow:

```text
source reference
→ hypothesis/protocol reference
→ admission and budget reservation
→ Permit and AttemptLease
→ offline execution and checkpoint
→ staging and trusted ingestion
→ ExecutionReceipt
→ ValidationReceipt
→ domain registry writer applies outcome
→ domain receipts referenced by Bridge
→ LearningDecision
```

Bridge success is mechanical, never scientific. A validator proposes an outcome; a domain-owned registry writer applies it.

## Additive A1 corridor

The frozen A1 contract layer adds bounded autonomous discovery without adding a second ledger, scheduler, database, or scientific registry:

```text
untrusted SourceTrigger
→ deterministic MaterialityGate
→ MaterialEvent
→ untrusted CandidateSpecDraft
→ frozen AdmissionSnapshot at an exact ledger revision
→ deterministic AdmissionReceipt
→ existing JobSpec / BudgetReservation / Permit / AttemptLease
→ bounded L0 execution
→ ValidationReceipt
→ LearningDecisionProposal
→ WAIT_AUTHORITY
```

Collectors and models cannot mint trusted events, admit their own proposals, issue permits, or write canonical scientific state. `AdmissionReceipt` proves a policy decision, not execution authority. `CapabilityProofReceipt` reports evidence only as `PASS_FOR_FROZEN_SCOPE` and always carries `grants_authority=false`.

Bridge operational memory and domain scientific truth remain separate. `SHADOW_UNAPPLIED` taint is inherited: shadow-derived knowledge can generate only shadow work until an authorized domain writer applies a validated outcome.
