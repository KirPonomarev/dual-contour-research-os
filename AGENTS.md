# Agent operating contract

This repository is the public, domain-neutral control plane for Dual-Contour Autonomous Research OS.

## Canonical boundary

- The private master plan is not stored here.
- Security Researcher and Crypto Market Lab remain separate domain owners.
- This repository stores contracts and references, never D2/D3 payloads or domain scientific truth.
- Validators emit immutable `ValidationReceipt` objects. Only domain registry writers apply scientific outcomes.
- Bridge code must not provide live trading, autonomous live security execution, publication, or authority escalation.

## Mandatory startup

1. Read this file and `docs/DEVELOPMENT_AGENT_CONTRACT.md`.
2. Run `git status --short --branch`.
3. Run `make contracts`.
4. Verify the assigned StageEnvelope, base SHA, contract SHA, branch, worktree, write-set, stop condition, and acceptance commands.
5. Stop if the worktree is dirty outside the declared write-set or a contract/ownership collision exists.

## Stage authority

- Before `CONTRACTS_FROZEN`, only Agent 0 may edit the repository.
- After freeze, a worker needs a machine-readable StageEnvelope and ownership lease.
- Branches are stage-scoped: `codex/bridge-a<agent-id>-<stage-id>`.
- Permanent agent branches and shared worktree edits are forbidden.
- No worker may edit frozen contracts, canonical docs, root config, CI, lockfiles, or migrations.

## Public-repository safety

Never commit secrets, private evidence, account material, raw exploit corpora, target-specific findings, trading strategies, private datasets, sealed holdouts, D2/D3 payloads, or runtime databases/checkpoints.

All examples and fixtures must be synthetic, public, sanitized, and non-actionable outside an authorized laboratory.

## Reuse-first

No non-trivial component is implemented without a `ReuseDecisionReceipt`:

1. internal adapter;
2. owned versioned package extraction;
3. pinned permissive dependency;
4. small audited vendor import;
5. minimal missing glue.

Unknown/no-license code is rejected. External code requires pinned provenance, notices, license text, dependency review, SBOM, security tests, and rollback.

## Integration

Every accepted stage follows:

```text
audited commit
→ non-force push / PR
→ exact-head remote CI green
→ IntegrationReceipt
→ next pinned base
```

Workers return evidence; only Agent 0 integrates, promotes canonical drafts, deploys, or declares a gate green.
