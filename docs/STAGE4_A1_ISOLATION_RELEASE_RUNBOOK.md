# Stage 4 → A1 isolation release runbook

Status: candidate packet only. It does not authorize deployment, reboot, sudo, restore, rollback, promotion, canonical mutation, trading, or security execution.

## Boundary

The predecessor `research-os-bridge.service` owns `research-os-bridge-*` mutable namespaces. The A1 candidate owns `research-os-a1-*`. They must never run concurrently. A1 remains an additive path inside one Bridge process, one durable ledger, and one writer; the separate names prevent an unapproved candidate from opening or mutating the predecessor state.

There is exactly one restart supervisor for the candidate: user systemd. Docker is pinned to `--restart=no`; systemd uses `Restart=on-failure`.

## VPS-only preflight

Run only on the authorized VPS as the rootless service user. Do not run these commands on a workstation and do not add a host, account, password, token, or private path to this repository.

```sh
systemctl --user is-active docker.service
systemctl --user is-enabled research-os-bridge.service
systemctl --user is-enabled research-os-a1-bridge.service
docker container inspect research-os-bridge --format '{{json .State.Running}}'
docker container inspect research-os-a1-bridge --format '{{json .State.Running}}'
docker volume inspect research-os-bridge-runtime research-os-bridge-config
docker volume inspect research-os-a1-runtime research-os-a1-config
```

Preflight is green only when at most one Bridge service/container is active, the candidate unit hash matches the packet, the immutable release/image/policy/config/schema bindings match, backup evidence is current, and a clean restore proof exists.

## Same-release R0 recovery

R0 permits only the already installed same release, image, policy, config and schema. It cannot install files, switch a release, create a second writer, restore a different snapshot, or consume deployment approval.

```sh
systemctl --user restart research-os-a1-bridge.service
systemctl --user is-active research-os-a1-bridge.service
docker container inspect research-os-a1-bridge --format '{{json .Config.Labels}}'
docker container inspect research-os-a1-bridge --format '{{json .HostConfig.RestartPolicy}}'
```

If any immutable binding differs, stop. The action is no longer R0.

## Changed release cutover

A changed release requires a valid, unconsumed `DeploymentApprovalReceipt`, exact-head green CI, verified backup and clean-restore receipts, an immutable release manifest, and a rollback target. The operator must stop and disable the predecessor before enabling the candidate. Automatic cutover is forbidden.

```sh
systemctl --user disable --now research-os-bridge.service
systemctl --user is-active research-os-bridge.service
systemctl --user enable --now research-os-a1-bridge.service
systemctl --user is-active research-os-a1-bridge.service
```

These are operator commands, not pre-authorized agent actions. A failed verification requires a receipted rollback; never run both services to recover.
