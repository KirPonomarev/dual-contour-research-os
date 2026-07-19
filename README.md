# Dual-Contour Autonomous Research OS

A governed research control plane for two isolated scientific domains: market research and authorized white-hat security research.

The public repository contains only domain-neutral contracts, control-plane code, synthetic fixtures, tests, and sanitized documentation. Domain data, trading strategies, vulnerability evidence, secrets, private targets, sealed holdouts, and the private master plan are intentionally excluded.

## Current status

`SUPERSEDED_REPAIR_REQUIRED + PRODUCT_REPAIR_IN_PROGRESS`

The Core and additive A1 public contracts remain frozen and verified by `make contracts`. Historical E0–E5 component work remains immutable provenance, but independent exact-runtime probes found that the S38 deployment target cannot execute the production A1 route: its policy resolver is empty, the daemon does not wire the durable A1 backend or Collector/Scout roles, its deployment smoke proves only `status`, and its E2 proof is stale.

The old candidate `b2c2e6a8…` is preserved as a historical object but is machine-denied as a deployment target by an additive supersession receipt. Product completion now requires a replacement exact image, full AF_UNIX A1 E2E, current capability proofs, physical deployment and recovery proof before any observation window begins. See [Product completion boundary](docs/PRODUCT_COMPLETION.md).

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
