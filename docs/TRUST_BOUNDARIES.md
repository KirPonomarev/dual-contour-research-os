# Trust and data boundaries

## Data classes

| Class | Meaning | Public Bridge policy |
|---|---|---|
| D0 | public | allowed with provenance |
| D1 | sanitized internal metadata | allowed with retention/redaction policy |
| D2 | domain-confidential | manifest/hash/ref only; payload stays in Domain Vault |
| D3 | restricted/secret/holdout | manifest/hash/ref only; no Bridge or model egress |

## Trust classes

- Untrusted: sources, model output, generated code, worker staging.
- Mechanically trusted: `researchd`, event writer, budget ledger, artifact ingestor.
- Scientifically trusted: pinned domain validators, but only as receipt issuers.
- Canonical truth writers: domain registry writers.
- Human authority: operator approvals for external/live actions, policy, deployment, and promotion.

## Hard boundaries

- Generated-code runners are offline and rootless.
- Connected actions require a separate typed executor and explicit approval.
- Workers cannot write Bridge SQLite or domain registries.
- Validators cannot apply outcomes.
- Bridge never stores D2/D3 payloads or sealed holdout bytes.
- Cross-contour paths, identifiers, prompts, logs, backups, and artifact reads are deny by default.
