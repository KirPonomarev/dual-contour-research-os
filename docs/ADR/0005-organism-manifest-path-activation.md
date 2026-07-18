# ADR 0005: activate the reserved organism manifest module

Status: accepted for S11 ownership amendment verification

## Context

The frozen ownership registry reserves `src/research_bridge/organism.py` for
Agent 5. S11 begins the approved E1C operational self-model: a pure,
non-authoritative manifest projector and topology validator over existing
source declarations. The reserved path must therefore become live canonical
ownership before the worker implementation can pass the fail-closed contract
gate.

## Decision

Promote only `src/research_bridge/organism.py` from `reserved_future_paths` to
`canonical_owners`, retaining Agent 5. The implementation remains a library:
it may read versioned public declarations, build an immutable manifest, and
reject topology or evidence inconsistencies. It may not observe live state,
start or stop processes, mutate runtime data, grant authority, call a model or
provider, add a service, deploy, or apply scientific outcomes.

The manifest cardinality comes exclusively from versioned source documents;
the module may not hardcode a cell or process count. Evidence progresses only
through `DECLARED`, `OBSERVED`, `NEGATIVE_PROBE_PASSED`, and
`ENFORCEMENT_PROVEN`; declaration alone never implies enforcement.

## Consequences

- Agent 5 may implement the bounded S11 manifest and hostile topology tests.
- Agent 0 remains the sole amendment and integration authority.
- The amendment adds no consciousness claim, model authority, domain writer,
  canonical mutation, live trading, live security, deploy/reboot, D2/D3, or
  production authority.
