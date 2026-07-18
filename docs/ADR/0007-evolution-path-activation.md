# ADR 0007: activate the reserved evolution module

Status: accepted for S24 ownership amendment verification

## Context

The frozen ownership registry reserves `src/research_bridge/evolution.py` for
Agent 1. S24 begins the approved E2/E3 evolution track: a bounded agenda and
portfolio selector followed by council, replication, memory, gap-mining and
champion/challenger stages. The path must become live canonical ownership
before any implementation.

## Decision

Promote only `src/research_bridge/evolution.py` from `reserved_future_paths`
to `canonical_owners`, retaining Agent 1. The module must consume immutable,
typed operational-memory views and deterministic budget/capacity inputs. It
may emit only bounded non-authoritative plans, decisions and shadow evidence.

It must not create a second event ledger, scheduler, queue, vector database or
shared writable agent memory. It cannot mint trusted `MaterialEvent` objects,
raise budgets, remove `SHADOW_UNAPPLIED`, write domain scientific truth,
promote canonical state, call models or networks by itself, deploy, trade,
execute live security work or publish.

## Consequences

- Agent 1 may implement the bounded S24–S37 evolution algorithms in the
  activated module under separate StageEnvelopes and leases.
- Agent 0 remains the ownership, integration and release authority; Agent 5
  independently tests hostile inputs, replay, authority and fault boundaries.
- Each stage remains additive and must prove its own deterministic bounds.
  Activation itself grants no runtime, model, scientific, canonical or live
  authority.
