# Dual-Contour Autonomous Research OS

A governed research control plane for two isolated scientific domains: market research and authorized white-hat security research.

The public repository contains only domain-neutral contracts, control-plane code, synthetic fixtures, tests, and sanitized documentation. Domain data, trading strategies, vulnerability evidence, secrets, private targets, sealed holdouts, and the private master plan are intentionally excluded.

## Current status

`CORE_CONTRACTS_FROZEN + A1_CONTRACTS_FROZEN`

The Core and additive A1 public contracts are frozen and verified by `make contracts`. The A1 runtime corridor is not yet implemented or enabled; implementation proceeds only through pinned E1 StageEnvelopes. Existing Stage 4 substrate code is present, but production deployment proof and soak evidence remain incomplete until their explicit gates pass.

## Product boundary

- Autonomous reasoning and offline research are allowed inside bounded policy.
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

See `AGENTS.md` and `docs/DEVELOPMENT_AGENT_CONTRACT.md` before changing the repository.

## License

Public visibility does not grant reuse rights. A project license will be selected explicitly before the first reusable implementation release.
