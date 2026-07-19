# Dual-Contour Autonomous Research OS

A governed research control plane for two isolated scientific domains: market research and authorized white-hat security research.

The public repository contains only domain-neutral contracts, control-plane code, synthetic fixtures, tests, and sanitized documentation. Domain data, trading strategies, vulnerability evidence, secrets, private targets, sealed holdouts, and the private master plan are intentionally excluded.

## Current status

`PRODUCT_IMPLEMENTATION_COMPLETE_CANDIDATE + OPERATIONAL_PROOF_PENDING`

The Core and additive A1 public contracts are frozen and verified by `make contracts`. The bounded product implementation through E1–E5 is integrated: trusted discovery and admission, durable offline execution, operational self-model, model-role routing, research portfolio and replication, shadow evolution, generated-execution isolation metadata, attestation, and governed MethodCard transfer. Every model or evolutionary output remains untrusted and non-authoritative.

Product completion is distinct from operational proof. The frozen application candidate and its deployment corridor are prepared, but final A1 deployment, recovery drills, observation windows, the 14-day burn-in, and the final `DONE` transition remain pending their explicit human and operational gates. See [Product completion boundary](docs/PRODUCT_COMPLETION.md).

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
