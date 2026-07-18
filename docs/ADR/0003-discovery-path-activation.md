# ADR 0003: activate the reserved discovery module ownership

Status: accepted for S02 ownership amendment verification

## Context

The frozen ownership registry reserves `src/research_bridge/discovery.py` for
Agent 1. S02 begins the approved E1A Scout fixture route, so the path must move
from the future reservation set to live canonical ownership before any worker
implementation can pass the fail-closed contract gate.

## Decision

Promote only `src/research_bridge/discovery.py` from `reserved_future_paths` to
`canonical_owners`, retaining Agent 1 as its owner. No other path, authority,
contract, dependency, runtime service, or domain boundary changes.

The promotion is integrated before the Agent 1 runtime stage. The existing
validator remains unchanged and will require the path to become live in that
next pinned stage; it will fail closed if the canonical path is absent or is
owned by more than one pattern.

## Consequences

- Agent 1 may implement the bounded, local discovery fixture in its declared
  S02 write-set.
- Agent 0 remains the only integration and amendment authority.
- This amendment grants no model-provider, execution, scientific, deployment,
  live-trading, live-security, D2/D3, or canonical-domain mutation authority.
