# Sanitized security runtime reuse inventory

Status: `READY_FOR_AGENT0_REVIEW`

Source or target: logical source `security-domain-runtime-source`, pinned to commit `c88ffdb3e90971f1b2369f11ebe3a44d46d20470`; read-only inspection only. The remote URL is intentionally not published and the observed branch has no configured upstream.

Scope boundary: domain-neutral runtime primitives, strict schemas, and conformance patterns only. This draft contains no target or program identity, private URL, raw diff, evidence, secret, live-action material, or D2/D3 payload. No source code was copied.

Evidence status: source anchors are content-addressed; the focused source test pack passed 87 tests with zero failures; source worktree state is represented only by aggregate counts and path-manifest hashes. The source repository was not changed.

Owner/agent role: Agent 1, Security runtime inventory.

Next action: Agent 0 audits the candidates, resolves ownership and licensing, then issues one `ReuseDecisionReceipt` per accepted or rejected component. Nothing in this draft authorizes extraction or implementation.

## Result

Nine reusable capability families were found:

| Candidate | Value | Recommended handling | Main gap |
|---|---|---|---|
| Durable atomic replace | file and directory durability with failure injection | extract a small owned primitive | add Bridge staging, fencing and classification |
| Hash-chained event ledger | strict events, legal transitions and tamper detection | adapt ledger core | source states differ from Bridge execution states |
| Governed runner recovery | atomic reservation, no-replay recovery and concurrency exclusion | reuse patterns through a typed adapter | source actions are domain-runtime specific |
| Decision/Lease gate | pure fail-closed authority evaluation | extract after schema adapter tests | Permit and AttemptLease are not schema aliases |
| Decision validator | expiry, limits and review negative cases | port conformance cases only | generation contains domain-policy assumptions |
| Lease issuance ledger | exact confirmation and replay-resistant short leases | adapt after issuer-boundary review | key custody and authority protocol must be frozen first |
| Authorization proposal/review | approval remains separate from execution authority | reuse the separation pattern | map to frozen Bridge approval contracts |
| Backup/restore integrity | byte-identical restore and hostile-manifest denial | reuse tests and Domain Vault pattern | sensitive payload cannot enter Bridge storage |
| Release freeze gate | immutable release identity and bounded exceptions | reuse the gate pattern | bind all Bridge release/config/policy/schema/image hashes |

The highest-value, lowest-coupling candidates are durable atomic replacement and the pure Decision/Lease gate. The runner and ledgers require adapters. Decision generation, backup implementation, and release gating must not be copied wholesale because they carry source-runtime or repository policy.

## Source-freeze observation

The pinned source has no tracked changes. It has 15 top-level untracked status entries expanding to 496 files. Their path manifest is hash-bound, but names and bytes are deliberately not published.

- Four top-level entries are parked for owner classification or canonical-repository proof.
- Eleven are excluded as report/output, dependency-install, or workspace-control artifacts.
- Zero untracked entries are admitted for import.

This is a candidate, not a canonical `SourceFreezeReceipt`. Agent 0 must resolve parked entries before dirty or untracked material can influence reuse.

## Contract and test projection

The source contracts provide reusable shapes for strict state events, execution decisions, short leases, run receipts, non-authoritative authorization proposals, review receipts that cannot issue authority, and hash-bound issuance records. They are evidence for design reuse, not permission to alias schemas. Bridge contracts remain canonical and frozen.

Any accepted adapter must prove:

```text
source object
→ strict source validation
→ explicit field/state mapping
→ frozen Bridge contract validation
→ negative tests for dropped authority or widened scope
```

The 87-test focused pack covers durability boundaries, tamper detection, illegal transitions, dry-run behavior, lease expiry and replay, action/proof binding, concurrency, recovery without replay, non-authoritative approval, hostile backup manifests, restore integrity, and release-freeze exceptions.

## Explicitly not done

- no source code extraction;
- no canonical `SourceFreezeReceipt`;
- no `ReuseDecisionReceipt`;
- no runtime adapter;
- no authority-key or secret handling;
- no source-repository mutation;
- no claim that source contracts are directly compatible with Bridge contracts.
