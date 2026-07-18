# ADR 0002: validate live ownership paths and reserve future roots explicitly

Status: accepted for E0 amendment verification

## Context

The frozen ownership registry assigned Bridge modules to directory globs such
as `src/research_bridge/control/**` even though the implementation consists of
flat files such as `src/research_bridge/control.py`.  The Stage 0A validator
checked only the branch pattern and child-agent limit, so a stale ownership map
could remain marked `frozen` without owning the files workers actually edit.

This is an authority ambiguity and blocks issuance of A1 worker
`StageEnvelope` objects.

## Decision

Ownership schema `1.1.0` separates:

- `canonical_owners`: patterns that must match at least one live repository
  path;
- `reserved_future_paths`: paths that must not be live yet;
- `root_only`: live paths that only Agent 0 may change.

The contract gate now evaluates tracked and visible untracked repository paths.
Every live path must match exactly one canonical or root-only pattern.  Empty
canonical patterns, live reserved paths, overlaps, invalid owners, and unsafe
patterns fail closed.

The original `CONTRACTS_FROZEN` receipt remains immutable.  A separate
`OWNERSHIP_REGISTRY_AMENDMENT` receipt binds its original ownership hash to the
new registry hash and the exact pre-amendment Git base.  The normal
`IntegrationReceipt` and exact-head CI process still determine whether the
amendment is accepted into an integration base.

Bridge source modules use exact file ownership.  New source roots must be
reserved first and promoted to canonical ownership in a later Agent 0
amendment when implementation begins.

## Consequences

- An ownership registry can no longer be frozen while pointing only at
  nonexistent implementation directories.
- Worker write-set collisions become mechanically detectable before A1 work.
- Future domain adapter roots remain explicit without pretending that they are
  currently implemented.
- This amendment grants no new execution, domain, deployment, or scientific
  authority.
