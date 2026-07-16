# Dual-Contour Autonomous Research OS

A governed research control plane for two isolated scientific domains: market research and authorized white-hat security research.

The public repository contains only domain-neutral contracts, control-plane code, synthetic fixtures, tests, and sanitized documentation. Domain data, trading strategies, vulnerability evidence, secrets, private targets, sealed holdouts, and the private master plan are intentionally excluded.

## Current status

`STAGE_0A_CONTRACT_FREEZE`

No worker implementation is admitted until the repository emits a verified `CONTRACTS_FROZEN` receipt.

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

See `AGENTS.md` and `docs/DEVELOPMENT_AGENT_CONTRACT.md` before changing the repository.

## License

Public visibility does not grant reuse rights. A project license will be selected explicitly before the first reusable implementation release.
