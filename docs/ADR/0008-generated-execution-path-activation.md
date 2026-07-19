# ADR 0008: activate the generated-execution isolation module

Status: accepted for S33 ownership amendment verification

## Context

S33 introduces a feature-off L1/L2 generated-code isolation boundary after the
proposal-only E3 gate. The existing L0 runner must remain unchanged and no
embedded subprocess, container daemon or unrestricted interpreter may enter the
Bridge. A separate Agent 2 path is required so the gate and result validator do
not widen the already frozen L0 implementation.

## Decision

Activate only `src/research_bridge/generated_execution.py` under Agent 2 while
retaining the compatible registry schema version. The module may validate
D0-only generated-artifact provenance, exact parent
JobSpec/Permit/AttemptLease inheritance, an attested rootless OCI backend
descriptor, immutable L1/L2 launch metadata, bounded result metadata, CAS output
references and a descriptive rollback proposal.

The module is feature-off by default and contains no executor, subprocess,
Docker API, network client, host mount, device access or dynamic-code primitive.
L3 is not registered. It cannot read code bytes, run generated code, apply a
rollback, deploy, write canonical state, access private/live data or grant
authority.

## Consequences

- Agent 2 may implement the additive isolation gate under an exact StageEnvelope.
- An external executor is never trusted merely because it is registered; its
  frozen isolation descriptor, image, attestation, fence and result remain
  mandatory inputs to validation.
- Agent 5 hostile assurance covers path, network, resource, artifact, CAS,
  fence, L3 and authority probes.
- Removing the module and disabling the feature returns the system to the
  existing L0-only execution surface.
