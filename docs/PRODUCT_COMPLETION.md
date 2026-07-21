# Product completion boundary — V2.5.2 physical release

Current status: `RELEASE_DONE_PHYSICAL_FUNCTIONAL_CLOSEOUT_REPAIRED`.

The completed V2.4/F12 work proves the immutable R17 runtime candidate, its
portable image, clean installation, isolated recovery, and independent Git
audit. V2.5.2 restored and satisfied the intended physical boundary: the exact
R17 image is installed in its permanent, collision-free VPS namespace; both
domain-owned immutable exports traversed the single local ingress and AF_UNIX
runtime boundary; and restart, controlled reboot, encrypted backup, clean
restore, rollback readiness, monitoring, exact-head CI and independent
physical audit passed on bound identities. The terminal cleanup-integrity
repair also passed a fresh independent delta audit and superseding closeout.

Only elapsed-time observation windows are post-release. The 24-hour, 48-hour,
seven-day, and 14-day windows may run alongside real bounded work after
release and do not block the physical release verdict. They cannot substitute
for any immediate physical gate.

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
LIVE_VPS_DEPLOYMENT=COMPLETE
DONE_REQUIRES=SATISFIED_P06B2_SUPERSEDING_CLOSEOUT
```

This is a release statement, not a claim of completed burn-in. The 24-hour,
48-hour, seven-day and 14-day windows remain incomplete and non-blocking, so
`OPERATIONALLY_PROVEN` stays false. Point-in-time domain incidents belong to
current owner-controlled health receipts and do not rewrite this immutable
release verdict.

## Current release identity separation

- Immutable runtime subject: `0394d6c9e327eceb62f738eca90be3ece015ba79`, tree `636fda24cbb2da567fb23a4d44fa865ae74ac4bc`.
- Portable image: `sha256:e6db8ab087e18b13ac357a751a2e7318c3abb81a4f2af459c930a630ddc65577`.
- Maintenance control head: created by the protected P01 delivery and never represented as runtime bytes.
- Final evidence head: `4ecffe992e1654e10cac15473d45ba3103b074f2`, created only after physical evidence was sanitized and delivered.

If a runtime input changes, a new runtime subject and image are required. A
control-only or evidence-only commit never relabels or silently rebuilds R17.

## Physical Product Done gates

Product Done and Release Done require all of the following on the exact bound
host and namespace:

1. one transport-only ingress principal and zero public Bridge listeners;
2. independently provenance-bound, immutable, current Market and Security exports;
3. exact R17 carrier load and persistent rootless service activation;
4. physical Market and Security shadow E2E with no domain canonical writes;
5. same-release restart, controlled reboot, encrypted backup, isolated clean restore, and rollback readiness;
6. green monitoring, exact-head protected delivery, and sanitized receipts;
7. an independent physical audit followed by Agent 0 closeout.

These gates were satisfied as a hash-bound chain. No test fixture, local
image, CI result, deploy exit code, timer state or old receipt would satisfy
them alone.

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

Under the older plan, deployment, remote E2E and recovery were part of those
product conditions. Only after they passed could the finished product start
its separate operational windows: 24-hour substrate, 48-hour provider,
seven-day integrated and 14-day/200-job final burn-in. V2.4 temporarily moved
the live deployment boundary out of scope; V2.5.2 additively corrects that
decision without deleting any evidence history. Permanent deployment and the
short physical proof chain are release gates again, while only the elapsed
observation windows remain post-release.

The historical checkpoint's honest state remains
`SUPERSEDED_REPAIR_REQUIRED / DEPLOYMENT_DENIED`. It was superseded rather
than rewritten. The current V2.5.2 state is
`RELEASE_DONE_PHYSICAL_FUNCTIONAL_CLOSEOUT_REPAIRED`: permanent deployment,
domain E2E, recovery and independent physical audit are complete, while the
long post-release assurance windows remain in progress. Commits after the
final evidence head do not implicitly alter or redeploy the R17 runtime.
