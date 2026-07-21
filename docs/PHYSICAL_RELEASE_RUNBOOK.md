# V2.5.2 physical release runbook

This runbook governs the control layer only. The immutable runtime remains R17
at Git SHA `0394d6c9e327eceb62f738eca90be3ece015ba79`, tree
`636fda24cbb2da567fb23a4d44fa865ae74ac4bc`, and portable image
`sha256:e6db8ab087e18b13ac357a751a2e7318c3abb81a4f2af459c930a630ddc65577`.
Loading that carrier into the qualified Docker engine produces the exact
engine-local ID
`sha256:d1f56e933a8e498ae9e3a1f70ba0e764785a0de44d6f702f7e1945c3621b671f`.
Receipts retain the portable identity; rendered Docker commands use the bound
engine-local identity. Neither may be replaced by a tag.
The maintenance head is a separate control identity and must never be used to
relabel or rebuild that image.

## Hard boundaries

- Use exactly one ingress process running as `collector:uid:10002`.
- Submit only through the runtime's local AF_UNIX socket. Open no Bridge TCP/UDP listener.
- Consume Market and Security exports read-only and independently validate each domain owner, project fingerprint, runtime head, schema/version, data class, content hash, size, timestamp, freshness limit, immutable snapshot identity, and locator fingerprint.
- Never parse or transform domain payloads in the ingress. The SourceTrigger carries only hashes, immutable references, timestamps, and a sanitized availability summary.
- Never write Market or Security stores, apply scientific outcomes, trade, perform live security execution, publish, or escalate authority.
- Never directly execute `tools/pre_soak_deploy.py` or `tools/final_deployment_rebind.py`. The former defaults to an old release; the latter is a superseded S38 controller.
- Store host locators, SSH aliases, export paths, ActionEnvelopes, and operational receipts outside Git with mode `0600`.

## Control commands

Repository-only verification:

```sh
make physical-release-control
```

Validate a private producer registry and one bound export:

```sh
python3 tools/physical_release_control.py validate-registry --registry "$REGISTRY"
python3 tools/physical_release_control.py validate-export \
  --registry "$REGISTRY" --domain market \
  --binding "$MARKET_BINDING" --payload "$MARKET_PAYLOAD"
```

The `security` invocation is structurally identical and uses the independently
produced Security binding and immutable payload. A binding fails closed if it
is missing, stale, mutable, swapped, hash-mismatched, produced by another
runtime/project, or grants live/canonical authority.

Perform a no-mutation deploy binding check:

```sh
python3 tools/physical_release_control.py deploy-preflight \
  --profile "$PRIVATE_DEPLOY_PROFILE" \
  --envelope "$PRIVATE_ACTION_ENVELOPE"
```

The private `PhysicalReleaseControlProfile/v1` binds the exact R17 release,
tree, portable image, engine-local image, 47,947,776-byte carrier with SHA-256 `46e12e35...`, carrier
amendment, config, policy, unit template, strict known-hosts file, host
fingerprint, one service/container/volume namespace, and zero public
listeners. The `OperationalActionEnvelope/v1` additionally constrains the
exact project fingerprints, action, host, service, paths/users/ports, artifact
hashes, budget, expiry, stop conditions, backup identity, rollback target, and
forbidden boundaries.

After P02 freezes those private inputs and host prerequisites pass, deploy via:

```sh
python3 tools/physical_release_control.py deploy \
  --profile "$PRIVATE_DEPLOY_PROFILE" \
  --envelope "$PRIVATE_ACTION_ENVELOPE" \
  --deployment-receipt "$PRIVATE_DEPLOYMENT_RECEIPT" \
  --action-receipt "$PRIVATE_ACTION_RECEIPT"
```

This wrapper constructs a new exact-R17 bundle and calls only the already
owned, bounded low-level rootless deployment controller with the final A1
namespace. It verifies the carrier byte-for-byte, checks all frozen template
hashes, renders the exact R17 tokens, uses strict SSH host-key checking, loads
the content-addressed image, rejects a conflicting writer, and writes
owner-only non-overwriting receipts. It does not discover credentials, use
sudo, reboot the host, rebuild an image, alter domain services, or claim that a
successful deploy alone is Release Done.

The deploy path verifies carrier identity `46e12e35...`, portable identity
`e6db8ab...`, and loaded Docker identity `d1f56e...`, then renders the service
with `d1f56e...`. This mapping is frozen evidence, not an image rebuild.

The final unit uses only host-level hardening that the bound rootless user
systemd can execute. Persistent-unit probes proved that `PrivateDevices`,
`ProtectClock`, `ProtectKernelLogs`, and `ProtectKernelModules` fail before
`ExecStartPre` with `218/CAPABILITIES` on that user manager, so those four
host-wrapper directives are intentionally omitted. This does not change the
runtime image or container sandbox: the exact Docker command still requires
`--network=none`, `--read-only`, `--cap-drop=ALL`, and
`--security-opt=no-new-privileges:true`; all compatible systemd restrictions
remain enabled. Any host migration must re-run a persistent-unit compatibility
probe rather than silently adding or removing hardening.

Run one ingress cycle only after the service and both current immutable export
bindings are proven:

```sh
python3 tools/physical_release_control.py ingress-once \
  --registry "$REGISTRY" \
  --market-binding "$MARKET_BINDING" --market-payload "$MARKET_PAYLOAD" \
  --security-binding "$SECURITY_BINDING" --security-payload "$SECURITY_PAYLOAD" \
  --socket /var/lib/research-os/researchd.sock \
  --envelope "$PRIVATE_INGRESS_ACTION_ENVELOPE" \
  --expected-host-fingerprint "$BOUND_HOST_FINGERPRINT" \
  --receipt "$PRIVATE_INGRESS_RECEIPT"
```

The process refuses to run unless its effective UID is exactly `10002`. It
submits deterministic, retry-safe SourceTrigger requests for both domains and
records only provenance and response digests; no raw export content enters the
receipt.

## Stop and rollback rules

Stop before mutation if any project, host, carrier, image, profile, envelope,
export, prerequisite, service namespace, backup identity, or write-set binding
differs. Stop if more than one ingress/writer is active or any public Bridge
listener exists. Do not weaken CI, contracts, provenance, host-key checking,
permissions, or runtime isolation to continue.

P01 rollback is a Git revert of the control layer only. Physical rollback in
later sprints is limited to the exact Bridge namespace and preserved backup;
Market and Security services and stores are never rollback targets. Failed
receipts remain immutable and a correction receives a new identity.

## Release boundary

Deployment is followed by two physical domain shadow E2Es, same-release
restart, controlled reboot, backup/restore, monitoring, protected evidence
delivery, independent physical audit, and Agent 0 closeout. Only that complete
chain may set `PRODUCT_DONE=true` and `RELEASE_DONE=true`. Long observation
windows start after release and are nonblocking.
