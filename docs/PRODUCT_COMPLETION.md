# Product completion boundary — V2.4 fast working release

Current status: `V2.4_FAST_WORKING_RELEASE_IN_PROGRESS`.

V2.4 defines Product Done and Release Done together at F12. R08B freezes the
exact release subject; R08C proves its full functional loop; F09 freezes
current evidence; F10 proves a clean disposable Linux installation; F11 proves
isolated recovery; F12-A seals the Git evidence and F12-B independently audits
that immutable head outside Git. No earlier stage may claim `DONE`.

Live/VPS deployment, live restore/rollback/reboot and the 24-hour, 48-hour,
seven-day and 14-day observation windows are outside this plan. They remain
valuable later operational evidence, but they do not delay V2.4 Product Done
or Release Done. The terminal V2.4 state must preserve
`PHYSICALLY_DEPLOYED=false` and `OPERATIONALLY_PROVEN=false`.

```text
PLAN_ID=DCR_OS_AUTONOMOUS_V2_3_NO_BRAKES_20260719
PLAN_VERSION=2.4.0-fast-working-release
STATUS=IN_PROGRESS
PRODUCT_CODE_COMPLETE=true
PRODUCT_DONE=false
RELEASE_DONE=false
REAL_BOUNDED_RESEARCH_OPERATION_READY=false
MASTER_PLAN_DONE=false
PHYSICALLY_DEPLOYED=false
OPERATIONALLY_PROVEN=false
TIMED_WINDOWS=OUT_OF_SCOPE
LIVE_VPS_DEPLOYMENT=OUT_OF_SCOPE
DONE_REQUIRES=F12_B_INDEPENDENT_AUDIT_PASS
```

## Historical checkpoint retained

Status: `SUPERSEDED_REPAIR_REQUIRED`

Historical checkpoint: `PRODUCT_IMPLEMENTATION_COMPLETE_CANDIDATE` at `37f6712`

The historical checkpoint and its receipts remain immutable provenance, but they no longer close product implementation or authorize deployment. Independent exact-runtime probes found known product defects that the repository suite and integrity-only release validators did not exercise. A replacement release must repair and physically prove the complete production A1 route before `PRODUCT_DONE` can be asserted.

## Correction findings

- The frozen runtime config has an empty policy resolver, so an otherwise valid JobSpec fails authority resolution.
- `researchd` does not wire a production A1 backend.
- production Collector and Scout roles are absent from daemon IPC composition.
- deployment smoke verifies `status` rather than a functional JobSpec or full A1 cycle.
- the referenced E2 CapabilityProof code hash is stale for the candidate bundle.
- the final-freeze validator checks saved JSON integrity but not complete subject currentness.
- connected provider and real source edges are not physically closed into the autonomous runtime.

The additive supersession receipt at `docs/receipts/release/r00-superseded-release.json` denies use of the old candidate without rewriting any historical manifest or receipt.

## Historically implemented component scope

- E0: Core and additive A1 contracts, ownership, writers/issuers, integrity profiles and compatibility are frozen.
- E1: trusted materiality, deterministic admission, durable authority corridor, bounded offline L0 execution, independent validation, atomic feedback, replay, operational self-model, provider-neutral model broker, connected shadow routes and hostile assurance are integrated.
- E2: Knowledge Fabric, bounded agenda/portfolio selection, capped council, falsification, replication, failure/conflict memory, replay capacity and measured-scoped uplift are integrated.
- E3: gap mining, versioned genome, proposal-only mutations, frozen champion/challenger evaluation, shadow/canary regression detection and human-only promotion are integrated.
- E4: feature-off generated-execution isolation metadata and selected receipt attestation/anchoring are integrated without embedding a privileged executor.
- E5: declassified MethodCard creation, recipient-shadow evaluation and governed transfer up to `WAIT_HUMAN_DOMAIN_AUTHORITY` are integrated.
- S38/S38-R1/S39-R1: the application candidate is frozen; the exact offline A1 deployment corridor, namespace/supervisor policy, one-shot authority ordering, backup/restore inputs, and predecessor probe are prepared and fail closed.

## Historical component capability claims

```text
AUTONOMOUS_IDEA_GENERATION=true_for_frozen_shadow_scope
AUTONOMOUS_A1_SANDBOX_ADMISSION=true
AUTONOMOUS_BOUNDED_TESTING=true
AUTONOMOUS_REPLICATION=true_for_frozen_shadow_scope
AUTONOMOUS_FAILURE_MEMORY=true
AUTONOMOUS_MUTATION_PROPOSALS=true_for_frozen_shadow_scope
AUTONOMOUS_SHADOW_EVALUATION=true_for_frozen_scope
AUTONOMOUS_CANONICAL_MUTATION=false
AUTONOMOUS_PROMOTION=false
HUMAN_OR_DOMAIN_AUTHORITY_REQUIRED=true
LIVE_TRADING=false
AUTONOMOUS_LIVE_SECURITY=false
```

These claims describe component or shadow evidence only. They are not current proof of a deployable autonomous runtime. `SHADOW_UNAPPLIED` inheritance remains mandatory. Consensus is not evidence, and no model may self-assign, admit, reserve budget, issue a permit, promote, deploy, or write scientific truth.

## Historical evidence retained

- immutable Core, A1 and E5 catalogs and their freeze validators;
- phase IntegrationReceipts and scoped CapabilityProofReceipts through S38;
- the S38 final application-candidate manifest;
- S38-R1 operational rebind and S39-R1 fail-closed predecessor repair;
- complete public unit/hostile/authority/replay/release tests;
- release blueprint, release identity, isolation, readiness and final-freeze validators;
- secret/privacy/public-repository scans over the exact product-completion diff.

## Historical pre-V2.4 replacement requirements

The following are known product and physical-completion requirements, not elapsed-time observation:

- production runtime config, authenticated roles and non-empty frozen policy resolution;
- durable A1 backend and complete admission/execution/validation/feedback loop;
- real source and connected-provider edges with single-writer accounting;
- exact-image AF_UNIX functional and hostile E2E;
- current capability proofs and a currentness-aware final freeze;
- replacement release freeze and successful physical deployment;
- full remote A1 E2E, monitoring, backup, two restores, restart, provider failure and rollback proof.

Under the historical plan, deployment, remote E2E and recovery were part of
those product conditions. Only after they passed could the finished product
start its separate operational windows: 24-hour substrate, 48-hour provider,
seven-day integrated and 14-day/200-job final burn-in. V2.4 supersedes that
gating sequence without deleting its evidence history: only disposable and
isolated physical proof remains in release scope, while live and timed work is
out of scope.

The historical checkpoint's honest state remains
`SUPERSEDED_REPAIR_REQUIRED / DEPLOYMENT_DENIED`. The current V2.4 state is
separately `IN_PROGRESS`; no local unit test, CI result, saved receipt
integrity, image build or GitHub review substitutes for R08C/F10/F11 physical
evidence or the independent F12 audit.
