# Stage 0B permissive dependency license/security shortlist

- Status: `draft_for_agent0`
- Source: public primary upstream, PyPI and GitHub Advisory Database records checked at `2026-07-16T19:47:04Z`
- Scope boundary: generic public Bridge plumbing only; no dependency was installed, vendored, locked or adopted
- Evidence status: exact source distributions and license bytes verified; transitive packages are not yet pinned or fully audited
- Next action: Agent 0 decides whether to issue a canonical `ReuseDecisionReceipt` for `jsonschema`; all other candidates remain parked or rejected
- Owner/agent role: Agent 5 assurance draft; Agent 0 alone may promote or adopt

## Decision

Keep the MVP dependency surface almost empty.

| Capability | Decision | Result |
|---|---|---|
| CLI, logging, SQLite, hashes/tokens, Unix IPC, process control, atomic files and locking | `ADOPT` stdlib | `argparse`, `logging/json`, `sqlite3`, `hashlib/hmac/secrets`, `socket/subprocess/resource/signal`, `os/pathlib/tempfile/fcntl` |
| Canonical runtime JSON Schema validation | `ADOPT` candidate | `jsonschema==4.26.0`, only after exact transitive lock/audit and Agent 0 receipt |
| Connected model-provider HTTP transport | `PARK` | `httpx==0.28.1` only when the separate connected broker exists |
| Second typed validation/serialization layer | `REJECT` for MVP | `pydantic==2.13.4` duplicates schema authority and imports a large native core |
| Application-level asymmetric crypto | `PARK` | `cryptography==49.0.0` only after a concrete approved signing/certificate requirement |
| CLI/logging/retry/web/locking frameworks | `REJECT` for MVP | stdlib and durable state machines cover the frozen need |

`ADOPT` in this draft is a recommendation, not adoption authority. The repository still has `dependencies = []`; this stage creates no lockfile and no canonical `ReuseDecisionReceipt`.

## Why `jsonschema` is the only early candidate

The public contracts are already canonical JSON Schemas. `jsonschema` implements Draft 2020-12 and avoids building a partial validator that silently disagrees with the schemas. Version `4.26.0` is production/stable, supports Python 3.14, and its PyPI source distribution is linked by a trusted-publishing attestation to tag `v4.26.0` at commit `a7277432b0f7bcd0551f6e589d30457017125df4`.

This is not a zero-cost dependency. Its required set is:

```text
attrs>=22.2.0
jsonschema-specifications>=2023.03.6
referencing>=0.28.4
rpds-py>=0.25.0
```

`rpds-py` is native Rust. Therefore Agent 0 must not add `jsonschema` from this draft alone. Adoption requires exact versions and artifact hashes for all four dependencies, SPDX/license verification, fresh advisory scans, SBOM/notices, and negative tests. Initial installation must exclude both optional format extras. Where a canonical contract requires stricter date/time or identifier semantics, explicit fail-closed checks remain necessary because JSON Schema format handling is not automatically an assertion.

## Candidate evidence

### `jsonschema==4.26.0` — recommend `ADOPT` after receipt

- Canonical upstream: [python-jsonschema/jsonschema](https://github.com/python-jsonschema/jsonschema).
- Pin: tag `v4.26.0`, commit `a7277432b0f7bcd0551f6e589d30457017125df4`.
- PyPI sdist SHA-256: `0c26707e2efad8aa1bfc5b7ce170f3fccc2e4918ff85989ba9ffa9facb2be326`; local download matched.
- Actual license: `MIT`; `COPYING` SHA-256 `4f92a015a13c4d1a040bef018aa13430b4f1bc73b41b16bb846c346766de7439`.
- The sdist `COPYING` was byte-identical to the [license at the pinned commit](https://github.com/python-jsonschema/jsonschema/blob/a7277432b0f7bcd0551f6e589d30457017125df4/COPYING).
- PyPI exact-version vulnerability array: `0`; GitHub Advisory Database exact-version results: `0`; package-history results: `0` at audit time.
- TCB posture: medium; the unpacked sdist contains approximately 11,163 Python/Rust/C/H source lines, before its four direct dependencies.
- Rollback: remove the pinned package set while retaining the same canonical schemas and serialized envelopes.

### `httpx==0.28.1` — `PARK`

- Canonical upstream: [encode/httpx](https://github.com/encode/httpx).
- Pin: tag `0.28.1`, commit `26d48e0634e6ee9cdc0533996db289ce4b430177`.
- PyPI sdist SHA-256: `75e98c5f16b0f35b567856f597f06ff2270a374470a5c2392242528e3e3e42fc`; local download matched.
- Actual license: `BSD-3-Clause`; `LICENSE.md` SHA-256 `4ec59d544f12b5f539a3a716fd321ac58ccd8030b465221f2c880200cdf28d8d`.
- The sdist license was byte-identical to the [license at the pinned commit](https://github.com/encode/httpx/blob/26d48e0634e6ee9cdc0533996db289ce4b430177/LICENSE.md).
- Required dependencies: `anyio`, `certifi`, `httpcore==1.*`, `idna`; no optional extras should be enabled by default.
- The source distribution was not published with a PyPI provenance attestation. The GitHub release tag is pinned, but a future adoption still needs an independent source-to-sdist release audit.
- Exact version advisory queries returned `0`; package history contains `GHSA-h8pj-cxx2-jfg2`, which does not affect `0.28.1` according to the exact query.
- It fits strict timeouts and pooling in a future typed connected broker. It must never enter the offline runner import graph.

### `pydantic==2.13.4` — `REJECT` for MVP

- Canonical upstream: [pydantic/pydantic](https://github.com/pydantic/pydantic).
- Pin: tag `v2.13.4`, commit `cf67d4b3193c3fe43ede18612ed62785eee11382`.
- PyPI sdist SHA-256: `c40756b57adaa8b1efeeced5c196f3f3b7c435f90e84ea7f443901bec8099ef6`; local download matched and PyPI attests the source commit.
- Actual license: `MIT`; `LICENSE` SHA-256 `a9e186f3ca16b5eef84318e7a701721351a00cb7b8ae3a4394b67b49e3529ef3`; sdist and [pinned upstream](https://github.com/pydantic/pydantic/blob/cf67d4b3193c3fe43ede18612ed62785eee11382/LICENSE) match.
- Required dependencies include compiled `pydantic-core==2.46.4`, `annotated-types`, `typing-extensions`, and `typing-inspection`.
- Exact version advisory queries returned `0`; package history contains two older advisories.
- The unpacked sdist source footprint is approximately 114,752 Python/Rust/C/H lines. More importantly, it risks creating a second schema and serialization authority beside the canonical language-neutral contracts.

### `cryptography==49.0.0` — `PARK`

- Canonical upstream: [pyca/cryptography](https://github.com/pyca/cryptography).
- Pin: tag `49.0.0`, commit `e300bbe2f1bec75e5ee7e0ab7b196958831b3db6`.
- PyPI sdist SHA-256: `f89660a348f4f78a92366240a61404e337586ef7f5909a2fef59ca88ef505493`; local download matched and PyPI attests the source commit.
- Actual license expression: `Apache-2.0 OR BSD-3-Clause`. Umbrella `LICENSE` SHA-256: `3e0c7c091a948b82533ba98fd7cbb40432d6f1a9acbf85f5922d2f99a93ae6bb`; `LICENSE.APACHE`: `aac73b3148f6d1d7111dbca32099f68d26c644c6813ae1e4f05f6579aa2663fe`; `LICENSE.BSD`: `602c4c7482de6479dd2e9793cda275e5e63d773dacd1eca689232ab7008fb4fb`.
- The sdist umbrella license and [pinned upstream](https://github.com/pyca/cryptography/blob/e300bbe2f1bec75e5ee7e0ab7b196958831b3db6/LICENSE) match.
- Exact version advisory queries returned `0`; package history contains 21 advisories, including wheel/OpenSSL issues. That history is not an indictment of the current version, but it makes rapid patching and exact wheel provenance part of the operational cost.
- The MVP already gets SHA-256/HMAC/random identifiers from stdlib, TLS from the runtime, and encrypted off-host backup from deployment tooling. No application signing requirement has been approved.

## Security interpretation

“No known advisories” means only that both official query surfaces returned no record affecting the exact version at the recorded audit time. It does not mean safe forever, and it says nothing about an unresolved future transitive lock. A release gate must rerun the exact-version queries and scan the complete lock/SBOM.

Package-history counts are context, not current findings. Historical advisories listed above did not appear in exact-version results for the proposed pins.

## Required adoption gate

For any candidate Agent 0 later accepts:

```text
capability need
→ canonical ReuseDecisionReceipt
→ exact direct and transitive lock
→ artifact hashes and source provenance
→ actual license files and notices
→ fresh exact-version advisory scan
→ SBOM
→ focused security/failure/conformance tests
→ rollback proof
```

Unknown license, missing provenance, an unreviewed extra, or an affected locked version fails closed.

## Primary sources

- [PyPI JSON: jsonschema 4.26.0](https://pypi.org/pypi/jsonschema/4.26.0/json) and [release page](https://pypi.org/project/jsonschema/4.26.0/)
- [PyPI JSON: httpx 0.28.1](https://pypi.org/pypi/httpx/0.28.1/json), [release page](https://pypi.org/project/httpx/0.28.1/), and [official tag object](https://api.github.com/repos/encode/httpx/git/ref/tags/0.28.1)
- [PyPI JSON: pydantic 2.13.4](https://pypi.org/pypi/pydantic/2.13.4/json) and [release page](https://pypi.org/project/pydantic/2.13.4/)
- [PyPI JSON: cryptography 49.0.0](https://pypi.org/pypi/cryptography/49.0.0/json) and [release page](https://pypi.org/project/cryptography/49.0.0/)
- [GitHub Advisory Database REST API](https://docs.github.com/en/rest/security-advisories/global-advisories)

The machine-readable inventory records every exact query URL, hash and recommendation.
