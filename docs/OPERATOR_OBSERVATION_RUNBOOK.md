# Post-Product-Done observation runbook

Status: canonical pre-start procedure. No observation timer is started by this document.

## Boundary

The 24-hour, 48-hour, seven-day and 14-day windows are post-product operational evidence. They begin only after the exact deployed release has a current `PRODUCT_DONE` receipt. They do not delay `PRODUCT_DONE`, do not authorize product repair, and do not grant deployment, restore, reboot, canonical mutation, external action or paging authority.

The only valid sequence is:

```text
PRODUCT_DONE
→ SUBSTRATE_24H
→ PROVIDER_48H
→ INTEGRATED_7D
→ FINAL_14D
```

Every window is independent. Time, counters and workload from an earlier window are never credited to a later one.

## Pre-start gate

Before creating an `ObservationWindowStart` document, the operator must verify all of the following on the deployed host and in the private evidence store:

1. The exact release, tree, image, config, policy, provider profile, schema, SBOM and environment fingerprint matches the current `PRODUCT_DONE` subject.
2. The previous window has a valid `PASS` closeout, except for `SUBSTRATE_24H`.
3. No incident is active and all zero-tolerance counters are zero.
4. Every required proof remains valid through the planned end timestamp of the new window.
5. The threshold object is byte-identical to [observation-window-policy-v1.json](../provenance/observation-window-policy-v1.json); thresholds are never selected retrospectively.
6. The private evidence manifest already exists and contains only hashes and typed locators in the public start document.
7. Monitoring and backup timers are active, but no window timer has started before the start receipt is validated.

Validate the policy and a private start candidate:

```text
python3 tools/observation_window_gate.py validate-policy \
  --policy provenance/observation-window-policy-v1.json

python3 tools/observation_window_gate.py validate-start \
  --policy provenance/observation-window-policy-v1.json \
  --start /private/evidence/window-start.json
```

For every window after `SUBSTRATE_24H`, also pass `--previous-closeout /private/evidence/previous-closeout.json`. The same predecessor argument is mandatory when validating that window's checkpoints and closeout so the sequential release binding is never silently dropped.

The timer may start only at the exact validated `planned_start_at`. If the command fails or that timestamp is missed, discard the candidate and issue a new start document with a future timestamp.

## Checkpoints

The monitor produces cumulative counters; a runtime restart never resets them. Each `ObservationWindowCheckpoint` must:

- bind the exact start, policy and fingerprint;
- increase its index by one and use a strictly later timestamp;
- preserve or increase every cumulative counter;
- keep every zero-tolerance counter at zero;
- carry cumulative opened, closed and active incident refs;
- carry cumulative reset refs, with the `runtime_resets` delta exactly equal to new reset refs;
- bind the current monitor-chain head and a private evidence manifest digest.

Validate the first checkpoint without `--previous-checkpoint`; pass the preceding checkpoint for all later samples:

```text
python3 tools/observation_window_gate.py validate-checkpoint \
  --policy provenance/observation-window-policy-v1.json \
  --start /private/evidence/window-start.json \
  --checkpoint /private/evidence/checkpoint-current.json \
  --previous-checkpoint /private/evidence/checkpoint-previous.json
```

Duplicate input in the same monitor interval is idempotent. A later interval over an unchanged input is a new monitoring tick and must expose clock or heartbeat staleness.

## Incident and reset rules

An incident ref is opened on the first non-green condition. It remains active until a separately evidenced resolution closes the same ref. A closeout requires the cumulative opened and closed sets to be equal and the active set to be empty.

The following invalidate the current window and require a new start after correction:

- release, image, config, policy, provider, schema, SBOM or environment drift;
- any zero-tolerance counter above zero;
- unexplained counter decrease or reset;
- a product code/config repair, deployment change or changed proof subject;
- loss of monitor-chain continuity or private evidence integrity;
- an unresolved critical or high product finding.

A same-release process restart may remain inside the window only when the cumulative counter continues, a unique reset ref is recorded, the fingerprint is unchanged and no zero-tolerance event occurred. Restore, rollback, changed release and changed configuration never receive automatic window credit.

## Window-specific evidence

- `SUBSTRATE_24H` is provider-independent; provider call delta must be exactly zero.
- `PROVIDER_48H` requires real bounded provider calls, completed cycles and reconciled accounting.
- `INTEGRATED_7D` requires daily distributed substrate/provider/cycle evidence.
- `FINAL_14D` requires at least 200 bounded jobs, at least 14 real cycles and workload in every daily bucket.

The exact minimum samples, checkpoints, backups, restarts, calls, cycles and distribution buckets are frozen in the policy document. Zero work, a short interval, missing buckets or counters borrowed from an earlier window always fail.

## Closeout

The closeout candidate must use the exact planned end timestamp, include every ordered checkpoint ref, conserve job/cycle/provider deltas across every frozen bucket, bind proofs valid at closeout, and close all incidents.

```text
python3 tools/observation_window_gate.py validate-closeout \
  --policy provenance/observation-window-policy-v1.json \
  --start /private/evidence/window-start.json \
  --checkpoint /private/evidence/checkpoint-0001.json \
  --checkpoint /private/evidence/checkpoint-0002.json \
  --closeout /private/evidence/window-closeout.json
```

Pass every checkpoint in order. The abbreviated example above is not sufficient for a real window.
For every window after `SUBSTRATE_24H`, append the same `--previous-closeout /private/evidence/previous-closeout.json` argument to both checkpoint and closeout commands.

## Public evidence boundary

Raw logs, host paths, runtime databases, account data, repository locators, credential material and provider responses remain outside Git. Public integration receives only sanitized timestamps, bounded counters, hashes and normalized refs. The validator writes nothing and prints only a green object identity or a stable failure reason.

No current window is active at this checkpoint. Long observation begins only after the product release and recovery gates explicitly establish `PRODUCT_DONE`.
