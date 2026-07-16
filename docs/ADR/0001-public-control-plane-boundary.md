# ADR-0001: Public domain-neutral control plane

Status: accepted for Stage 0A

## Decision

Keep the public repository limited to domain-neutral contracts, control-plane primitives, synthetic fixtures, tests, and sanitized operations material. Keep the private master plan, domain data, strategies, vulnerability evidence, holdouts, and canonical scientific registries outside this repository.

The Bridge owns mechanical execution state only. Domain registry writers own scientific outcomes. External/live authority never derives from successful autonomous research.

## Consequences

- Security and Market repositories integrate through pinned adapters and receipts.
- Public development can proceed without disclosing sensitive research.
- Reuse requires source freeze, provenance, license, conformance, and security gates.
- A clean public clone must be sufficient to run contract and synthetic-fixture tests without private dependencies.
