# ADR 0004: activate the synthetic Market fixture adapter path

Status: accepted for S03 ownership amendment verification

## Context

S03 requires a domain-owned, public synthetic fixture boundary for freezing a
Bridge `CandidateSpecDraft` into `HypothesisCard` and `ProtocolSnapshot`
objects without giving the Bridge scientific-writer authority. The registry
already reserves `adapters/market/**` for Agent 3, so that existing reservation
is the narrowest compliant location.

## Decision

Promote only `adapters/market/**` from `reserved_future_paths` to
`canonical_owners`, retaining Agent 3. The first live implementation is a D0
synthetic fixture: no private Market data, strategy, account material, live
API, trading action, canonical Market ledger, or true holdout is permitted.

Agent 1 owns only the deterministic Bridge-side `FreezeProjection`. Agent 3's
pinned fixture writer alone issues the synthetic domain objects. All resulting
knowledge is marked `SHADOW_UNAPPLIED`; it cannot become canonical scientific
truth or a `LearningDecision`.

## Consequences

- The Bridge remains a proposal and reference plane, not a domain writer.
- The fixture proves writer separation and exact binding only for public
  synthetic scope.
- Real domain authority, D2/D3, execution, promotion, publication, deployment,
  live trading and live security remain denied.
