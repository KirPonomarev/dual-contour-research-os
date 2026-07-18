# ADR 0006: activate the reserved model broker module

Status: accepted for S15 ownership amendment verification

## Context

The frozen ownership registry reserves `src/research_bridge/model_broker.py`
for Agent 1. S15 begins the approved E1D1 model intelligence overlay: a
provider-neutral role registry and conservative durable model-call state
machine. The path must become live canonical ownership before implementation.

## Decision

Promote only `src/research_bridge/model_broker.py` from
`reserved_future_paths` to `canonical_owners`, retaining Agent 1. The broker
must reuse the frozen A1 model-role profile and the existing single global
Bridge ledger. It may hold only D0/D1 references and bounded untrusted model
bytes. It must reserve budget before egress, durably mark SENT before a
provider adapter is invoked, preserve UNKNOWN without automatic retry or
budget release, commit raw response bytes before SUCCEEDED, and reconcile
usage explicitly.

The module is provider-neutral. Real provider adapters, credentials, secret
storage and connected shadow calls remain separate later stages. Registry
bindings are replaceable versioned configuration, never model self-assignment
or authority.

## Consequences

- Agent 1 may implement the bounded S15 registry, broker and additions to the
  existing global ledger.
- Agent 0 remains the sole amendment and integration authority; Agent 5 owns
  independent hostile assurance.
- The amendment adds no second database, queue, scheduler or event order; no
  provider credential; no D2/D3 or holdout egress; no admission, Permit,
  scientific, canonical, deployment, live trading or live security authority.
