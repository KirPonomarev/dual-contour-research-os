# Dual-Contour Autonomous Research OS

A governed research control plane for two isolated scientific domains: market research and authorized white-hat security research.

The public repository contains only domain-neutral contracts, control-plane code, synthetic fixtures, tests, and sanitized documentation. Domain data, trading strategies, vulnerability evidence, secrets, private targets, sealed holdouts, and the private master plan are intentionally excluded.

## Current status

`V2.5.2_PHYSICAL_FUNCTIONAL_RELEASE_DONE`

The narrow V2.4 qualification and the corrective V2.5.2 physical-release plan
are complete. The exact R17 runtime was deployed to its permanent VPS
namespace, exercised through both domain boundaries, recovery-tested and
accepted by an independent physical audit plus an Agent-0 superseding
closeout. The elapsed 24-hour, 48-hour, seven-day and 14-day assurance windows
continue after release and do not block the physical functional release.

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

`OPERATIONALLY_PROVEN=false` is deliberate: release completion does not claim
that the longer assurance windows or every named milestone mechanism have
finished. Current live health must be read from the latest owner-controlled
health receipts rather than inferred from this repository snapshot.

Historical correction marker retained as immutable provenance, not current
state: `SUPERSEDED_REPAIR_REQUIRED + PRODUCT_REPAIR_IN_PROGRESS`.

The Core and additive A1 public contracts remain frozen and verified by `make contracts`. Historical E0–E5 component work remains immutable provenance, but independent exact-runtime probes found that the S38 deployment target cannot execute the production A1 route: its policy resolver is empty, the daemon does not wire the durable A1 backend or Collector/Scout roles, its deployment smoke proves only `status`, and its E2 proof is stale.

The old candidate `b2c2e6a8…` is preserved as a historical object but is
machine-denied as a deployment target by an additive supersession receipt.
That historical correction required a replacement exact image and physical
proof. V2.4 first qualified the replacement on disposable/isolated targets;
V2.5.2 then restored and completed the permanent deployment, immediate remote
functional proof and recovery gates. See [Product completion
boundary](docs/PRODUCT_COMPLETION.md).

The deployed release identity remains the immutable R17 runtime subject.
Later evidence, control-plane or model-advisor commits do not relabel, rebuild
or implicitly deploy that runtime.

## Product boundary

- Autonomous reasoning and offline research are allowed inside bounded policy.
- Autonomous agenda selection, falsification, replication, failure memory, and shadow mutation evaluation are bounded and proposal-only.
- Model roles are versioned and replaceable; provider output never grants admission, budget, permit, promotion, or canonical authority.
- Generated code has no network access.
- Validators issue receipts but do not write canonical scientific outcomes.
- Domain-owned registry writers remain the only scientific-truth writers.
- Live trading, autonomous live security actions, publication, and authority escalation are out of scope.

## Public/private boundary

This repository may contain:

- versioned schemas and receipts;
- deterministic control-plane primitives;
- synthetic or public fixtures;
- adapters with no embedded private data;
- conformance, adversarial, recovery, and acceptance tests.

It must never contain:

- credentials, cookies, tokens, private URLs, or account data;
- raw vulnerability evidence or undisclosed findings;
- proprietary trading strategies or private datasets;
- D2/D3 payloads, sealed holdouts, or checkpoint bytes;
- the private implementation master plan.

## Development

```bash
make contracts
make test
```

`make contracts` verifies both immutable freeze chains, regenerates schemas deterministically, checks ownership coverage, and rejects A1 profile or authority drift.

`make test` additionally exercises the complete public product acceptance suite. Passing local tests or CI proves the frozen product scope only; it does not claim deployment or burn-in evidence.

See `AGENTS.md` and `docs/DEVELOPMENT_AGENT_CONTRACT.md` before changing the repository.

## License

Public visibility does not grant reuse rights. A project license will be selected explicitly before the first reusable implementation release.
