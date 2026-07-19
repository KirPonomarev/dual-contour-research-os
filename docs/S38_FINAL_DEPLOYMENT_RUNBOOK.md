# S38 final candidate deployment corridor

Status: operational repair candidate. This document grants no deployment,
reboot, restore, VPS, production, live-domain or canonical authority.

## Why the repair exists

The immutable S38 source candidate is
`b2c2e6a8c4e0a364ef82e8e51540433aa91430d4` with tree
`7d6bd1e13d651950cced23dfe75a24946a3218fc`. The historical Stage 4
controller and `ReleaseManifest` are bound to an older S4 image and the
`research-os-bridge-*` namespace. They cannot be used for S39. S38-R1 keeps
the application candidate unchanged and adds only the missing operational
binding.

## Non-circular authority order

1. `verify-static` proves the exact S38 commit/tree, policy, config, dependency
   lock and final A1 unit. It performs no remote action.
2. `prepare` builds the historical candidate locally for `linux/amd64`, checks
   image labels/user and the complete frozen Debian package inventory, and
   writes a private image archive, derived SPDX SBOM, operational
   `ReleaseManifest` and `FinalImageBuildReceipt`. These artifacts remain
   outside Git and grant no deployment authority.
3. Human review of PR #25 is required before any VPS mutation. Under that
   reviewed scope, the operator obtains a current encrypted `BackupReceipt`
   and a clean-target `RestoreReceipt` using the existing restic controller.
4. Only after steps 1–3 does a human issue one HMAC-authenticated
   `DeploymentApprovalReceipt`, bound to the exact operational manifest,
   restore receipt, environment and exact-head CI. Its lifetime is at most
   300 seconds.
5. The final deploy command performs read-only SSH/rootless-Docker preflight,
   proves both predecessor service and container are stopped, and durably
   consumes the one-shot approval. Only then may it create directories,
   transfer the image or config, create the A1 volumes, install the unit or
   start the service.
6. Any failure after consumption requires a new human approval. Replay,
   automatic retry, predecessor coexistence and approval-free deployment are
   denied.

## Local-only preparation

Use an existing private directory with no previous outputs:

```sh
python3 tools/final_deployment_rebind.py verify-static
python3 tools/final_deployment_rebind.py prepare --output-dir /operator/private/s38-final
python3 tools/final_deployment_rebind.py verify-prepared --output-dir /operator/private/s38-final
```

The command may use only the configured local Docker engine. It does not read
SSH configuration, contact a VPS, discover keys or emit secrets.

## Runtime evidence and approval

Use `tools/release_backup_restore.py` for the encrypted backup and clean
restore. Use `tools/issue_deployment_approval.py` only after the operational
manifest and restore receipt exist. Supply the operator HMAC key through a
file descriptor; never place it in argv, Git, `.env`, logs or a receipt.

The exact CI reference must identify both run and SHA, for example
`github-actions:<run>@<sha>`. The approval output must be a fresh owner-only
path and must remain outside Git.

## Approved deploy invocation shape

The actual SSH alias, known-hosts file, approval key, backup repository and
receipt paths are private operator inputs and must never be committed. The
deployment controller requires all of them explicitly:

```sh
python3 tools/final_deployment_rebind.py deploy \
  --ssh-alias '<authorized-config-alias>' \
  --known-hosts '<owner-only-known-hosts>' \
  --release-manifest '<private>/final-operational-release-manifest.json' \
  --archive '<private>/final-release-image.tar' \
  --archive-sha256 '<exact-sha256>' \
  --backup-receipt '<private>/backup.json' \
  --restore-receipt '<private>/restore.json' \
  --approval-receipt '<private>/approval.json' \
  --approval-ledger '<private>/deployment-approval.sqlite3' \
  --trusted-issuer-id '<reviewed-issuer>' \
  --trusted-key-id '<reviewed-key-id>' \
  --remote-ci-ref 'github-actions:<run>@<sha>' \
  --receipt '<private>/deployment.json'
```

The default key descriptor is stdin. The tool emits only a bounded status and
never echoes the key, nonce, host locator or receipt contents.

## Hard denies

- no automatic human approval or PR review;
- no predecessor and A1 writer coexistence;
- no remote mutation before durable approval consumption;
- no force-push, sudo bypass, host reboot or destructive restore;
- no networked runtime, published port, live trading, autonomous live
  security, publication or canonical scientific mutation;
- no claim that a local build, synthetic restore proof or open PR is deployed
  operational evidence.
