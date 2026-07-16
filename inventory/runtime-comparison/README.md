# Runtime comparison inventory

Status: draft evidence for Agent 0
Owner: Agent 2
Source: read-only review of two owned, tracked runtime snapshots
Evidence status: focused candidate tests green; source freeze and public-release provenance pending
Next action: Agent 0 audits `comparison.json` and issues any canonical reuse decisions

## Scope

This inventory compares only domain-neutral durability, runner, checkpoint,
fencing, staging, receipt and recovery behavior. It contains no copied source,
private filenames, domain targets, strategies, datasets, evidence, secrets or
D2/D3 payloads.

`comparison.json` is decision evidence, not a `ReuseDecisionReceipt`. It may
not be used to extract or publish owned code until Agent 0 binds each candidate
to a `SourceFreezeReceipt` and records public-release authorization.

## Conclusion

Use one Bridge-owned job ledger. Adapt the stronger resumable chunk,
checkpoint and fencing behavior into that ledger, while placing the existing
fail-closed Permit and Lease behavior in front of every claim. Neither owned
candidate is a complete Bridge CAS; only the immutable publication pattern is
ready to inform a minimal trusted-ingestion adapter.

Canonical scientific validation remains outside the runner. A worker may
perform mechanical output checks, but only a pinned domain validator emits a
`ValidationReceipt`, and only the domain registry writer applies an outcome.
