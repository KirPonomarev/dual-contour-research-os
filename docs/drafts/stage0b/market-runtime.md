# Sanitized Market runtime inventory

Status: `DRAFT_FOR_AGENT_0`

Owner: Agent 3 inventory; Agent 0 remains the canonical receipt and integration writer.

Scope: read-only inventory of a private Market domain repository at one committed Git SHA. No source code, local paths, worktree filenames, strategies, experiments, datasets, evidence, credentials, or D2/D3 payloads were copied.

## Repository finding

The logical `crypto-market-lab` repository is a credible canonical Market repository candidate. The inspected committed HEAD matched its configured upstream (`ahead=0`, `behind=0`). The remote default branch is `main`, while the inspected branch name is deliberately represented only by a SHA-256 reference because it carries domain-workstream context.

The working checkout was dirty: 27 tracked changes and four untracked entries. None were selected. The candidate freeze is therefore the committed HEAD only. Aggregate manifests and dispositions are recorded in `inventory/market/source-freeze-candidate.json`; Agent 0 must re-observe them before issuing any canonical `SourceFreezeReceipt`.

The selected commit did not contain a root `LICENSE` file. This observation does not decide ownership, but it means public code copying is not authorized by this inventory. Reuse must start with an adapter to the private domain owner. Extraction into the public Bridge requires an explicit owner/licensing decision and a canonical `ReuseDecisionReceipt`.

## Candidate capabilities

The committed source contains evidence leads for all requested capability families:

- append-only ledgers;
- storage lifecycle;
- Trial Registry;
- backtest primitives;
- chronological replay and temporal-order checks;
- dataset-integrity and lineage checks;
- evidence routing and quality controls;
- preregistration and protocol freeze;
- soak, checkpoint, resume, recovery, and rollback;
- domain validators and validator conformance.

The counts and evidence-manifest hashes in `inventory/market/reusable-capabilities.json` establish candidate presence, not semantic correctness. Before reuse, each selected capability still needs source-level review, dependency/license review, synthetic conformance fixtures, failure tests, and an Agent 0 `ReuseDecisionReceipt`.

## Ownership boundary

The Market domain remains canonical owner of datasets, Trial Registry state, backtest semantics, preregistration, validator semantics, scientific outcomes, and domain artifacts. A Bridge adapter may exchange typed references and receipts only.

The allowed direction is:

```text
Bridge JobSpec / Permit / AttemptLease
→ pinned Market adapter
→ Market-owned execution or validator
→ immutable receipt
→ Market domain registry writer applies the outcome
→ Bridge stores hash/ref only
```

The Bridge must not copy Market scientific truth, accept domain payloads, or infer a scientific result from process success.

## Agent 0 decisions still required

1. Confirm or reject `crypto-market-lab` as the canonical Market repository.
2. Select the canonical branch independently of the inspected feature branch.
3. Re-observe dirty aggregates and issue the canonical `SourceFreezeReceipt`.
4. Pick capability owners and issue one `ReuseDecisionReceipt` per admitted component.
5. Decide whether reuse is adapter-only or an explicitly licensed owned-package extraction.
6. Define synthetic conformance packs before any adapter implementation.

No implementation authority is created by this inventory.
