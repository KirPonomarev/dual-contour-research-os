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

## Product intelligence and evolution overlay

The later product stages extend the same ledger and authority corridor; they do not add a second orchestrator, event order, scheduler, writable agent memory, or scientific registry:

```text
typed operational memory
→ Knowledge Fabric / Idea Tree / failure and conflict memory
→ bounded Research Agenda and Portfolio
→ capped model council with independent critique
→ falsification and multidimensional replication
→ outcome-to-next-event feedback
→ gap miner and MutationProposal
→ frozen champion/challenger evaluation
→ shadow/canary regression evaluation
→ WAIT_AUTHORITY
```

The model intelligence overlay binds replaceable roles rather than permanent vendor authority. Cheap worker routes perform bounded proposal work; independent critic routes challenge it; deep-review and Chief Scientist routes advise on material cases. The deterministic broker reserves budget before egress, records `SENT` durably, preserves ambiguous calls as `UNKNOWN`, commits raw responses privately before parsing, and requires explicit reconciliation. Models cannot select their own roles, admit candidates, issue permits, change budgets, apply mutations, or write canonical truth.

Generated-execution support is an isolation contract and launch-plan validator, feature-off by default. It contains no embedded process runner, Docker client, network client, dynamic-code primitive, or automatic rollback. E5 transfers only declassified `MethodCard` metadata into recipient shadow evaluation; adoption remains with Human and Domain Authority.

## Operational self-model

The self-model is operational and non-anthropomorphic. Versioned source declarations identify each active runtime cell's owner, plane, inputs, outputs, dependencies, access, authority ceiling, budget, heartbeat, recovery path, kill switch, evidence stage, and next transition. The topology validator rejects orphan edges, duplicate producers, unbounded cycles, mismatched deployment projections, and authority overclaims. `OrganismState` is durable; `PulseSample` is a deterministic read-only projection and cannot turn stale or merely declared evidence green.

Higher-order E2–E5 evaluators are bounded library/tool capabilities referenced by immutable phase receipts. They do not become additional long-running writers merely because their code exists. The deployable topology therefore remains separate from the capability/evidence graph.

## Product and operational evidence

### V2.5.2 physical release and post-release assurance

V2.4 froze and qualified the exact R17 runtime on disposable and isolated
targets. V2.5.2 then restored the intended physical boundary and completed the
permanent namespaced VPS deployment, dual-domain remote functional E2E,
restart, controlled reboot, encrypted backup, isolated restore, rollback
readiness, monitoring, sanitized evidence integration and independent
physical closeout. A subsequent fail-closed cleanup-integrity repair was
independently re-audited and sealed by the superseding Agent-0 closeout.

```text
PLAN_ID=DCR_OS_AUTONOMOUS_V2_3_NO_BRAKES_20260719
PLAN_VERSION=2.5.2-physical-release-final
STATUS=RELEASE_DONE_PHYSICAL_FUNCTIONAL_CLOSEOUT_REPAIRED
PRODUCT_CODE_COMPLETE=true
PRODUCT_DONE=true
RELEASE_DONE=true
MASTER_PLAN_DONE=true
PHYSICALLY_DEPLOYED=true
BRIDGE_RUNTIME_HEALTHY=true
RELEASE_EVIDENCE_VALID=true
PRODUCT_FUNCTIONAL_RELEASE=PASS
OPERATIONALLY_PROVEN=false
POST_RELEASE_ASSURANCE=DEGRADED_MONITORING
TIMED_WINDOWS=POST_RELEASE_NONBLOCKING_INCOMPLETE
DONE_REQUIRES=SATISFIED_P06B2_SUPERSEDING_CLOSEOUT
```

The completion state is bound to the immutable R17 runtime subject and the
V2.5.2 evidence head. Later evidence-only, control-plane or advisor commits do
not advance the deployed runtime identity. `OPERATIONALLY_PROVEN` remains
false because the 24-hour, 48-hour, seven-day and 14-day assurance windows are
still post-release and are not claimed complete.

`PRODUCT_IMPLEMENTATION_COMPLETE` means the public code, contracts, documentation, deterministic tests, hostile probes, phase receipts, frozen application candidate, and fail-closed deployment corridor are integrated on one exact remote head. It does not mean the release is deployed or operationally proven.

The following sequence is retained as historical architecture. V2.5.2
completed its immediate deployment and recovery portion; the elapsed windows
remain post-release assurance:

```text
fresh Human DeploymentApprovalReceipt
→ exact offline deployment
→ backup / restore / restart / rollback drills
→ separate deterministic-substrate and provider observation windows
→ 14-day burn-in with at least 200 bounded jobs
→ final Definition of Done
```

No product test, model consensus, GitHub review, or local image build may substitute for those operational receipts.
