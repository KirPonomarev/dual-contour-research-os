"""Pure, non-authoritative organism manifest and topology validation.

The manifest describes the current bounded control-plane cells.  It does not
start processes, mutate runtime state, grant authority, or infer enforcement
from a declaration.  Component and process cardinality always comes from the
versioned source documents.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping, Sequence


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_GIT_REF_RE = re.compile(r"^git:[a-f0-9]{40}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*:[^\s]{1,1024}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_STAGE_ORDER = {
    "DECLARED": 0,
    "OBSERVED": 1,
    "NEGATIVE_PROBE_PASSED": 2,
    "ENFORCEMENT_PROVEN": 3,
}
_PLANES = frozenset({"governance", "domain-fixture", "bridge-control", "execution", "validation", "evolution"})
_AUTHORITY_CEILINGS = frozenset(
    {
        "OBSERVE_AND_MINT_MATERIAL_EVENT_ONLY",
        "DETERMINISTIC_A1_ADMISSION_ONLY",
        "PREAUTHORIZED_A1_MECHANICAL_AUTHORITY_ONLY",
        "OFFLINE_L0_EXECUTION_ONLY",
        "IMMUTABLE_VALIDATION_RECEIPT_ONLY",
        "SHADOW_OPERATIONAL_MEMORY_ONLY",
        "NON_AUTHORITATIVE_EVIDENCE_ONLY",
        "UNTRUSTED_MODEL_EGRESS_ONLY",
    }
)
_NETWORK_MODES = frozenset(
    {"NONE", "LOCAL_IPC_ONLY", "PUBLIC_SOURCE_FETCH_ONLY", "CONNECTED_PROVIDER_EGRESS_ONLY"}
)
_LIFECYCLES = frozenset(
    {"DAEMON", "ON_DEMAND_IN_PROCESS", "ON_DEMAND_OFFLINE_TOOL", "ON_DEMAND_CONNECTED_WORKER", "SYNTHETIC_FIXTURE"}
)
_SOURCE_KEYS = frozenset({"schema_id", "schema_version", "source_id", "subject_ref", "policy_ref", "components"})
_PROJECTION_KEYS = frozenset({"schema_id", "schema_version", "projection_id", "subject_ref", "processes"})
_COMPONENT_KEYS = frozenset(
    {
        "component_id", "owner", "plane", "implementation_refs", "inputs", "outputs", "dependencies",
        "access", "authority_ceiling", "budget_ref", "policy_refs", "heartbeat", "recovery", "kill_switch",
        "proof_ref", "evidence", "next_transition", "cycle_bound",
    }
)
_PROCESS_KEYS = frozenset(
    {"process_id", "service_ref", "component_ids", "isolation", "lifecycle", "observed_ref"}
)
_DOCUMENT_KEYS = frozenset(
    {"schema_id", "schema_version", "object_id", "issued_at", "issuer", "contour", "classification", "payload", "integrity"}
)
_PAYLOAD_KEYS = frozenset(
    {
        "subject_ref", "source_id", "source_sha256", "deployment_projection_id",
        "deployment_projection_sha256", "policy_ref", "manifest_status", "components", "processes",
        "edges", "evidence_stage_summary", "grants_authority",
    }
)
_LIFECYCLE_STATES = frozenset(
    {"WAIT_DATA", "REJECTED", "GENERATING", "ADMITTED_A1", "RUNNING", "LEARNED", "WAIT_AUTHORITY", "PARKED"}
)
_STATE_FACT_KEYS = frozenset(
    {
        "ledger_sequence", "lifecycle_state", "state_ref", "reason_codes", "queue",
        "shadow_taint", "ai_enabled", "source", "proof_refs", "environment_ref", "updated_at",
    }
)
_STATE_PAYLOAD_KEYS = _STATE_FACT_KEYS | frozenset(
    {"manifest_ref", "manifest_subject_ref", "projected_at", "grants_authority"}
)
_QUEUE_KEYS = frozenset({"runnable", "waiting_authority", "parked", "oldest_event_at"})
_PULSE_POLICY_KEYS = frozenset(
    {
        "schema_id", "schema_version", "policy_id", "freshness_warn_seconds", "freshness_red_seconds",
        "queue_warn_count", "queue_red_count", "queue_age_warn_seconds", "queue_age_red_seconds",
    }
)
_PULSE_PAYLOAD_KEYS = frozenset(
    {
        "organism_state_ref", "manifest_ref", "policy_id", "policy_sha256", "policy_limits",
        "sampled_at", "state_updated_at", "environment_ref", "lifecycle_state", "ai_enabled", "queue",
        "state_age_seconds", "queue_age_seconds", "capability_assessments", "traffic_light", "health_state",
        "reason_codes", "side_effects", "grants_authority",
    }
)
_CAPABILITY_ASSESSMENT_KEYS = frozenset(
    {"capability_id", "status", "environment_ref", "critical", "reason_codes", "proof_ref"}
)
_CAPABILITY_STATUSES = frozenset({"PASS_FOR_FROZEN_SCOPE", "FAILED", "INCONCLUSIVE", "STALE", "REVOKED"})


class OrganismManifestError(RuntimeError):
    """A source document, topology, or manifest failed closed."""


class OrganismStateError(OrganismManifestError):
    """A durable state or read-only pulse sample failed closed."""


def load_json_document(path: Path) -> dict[str, object]:
    """Read one regular JSON file and reject duplicate object keys."""

    if not path.is_file() or path.is_symlink():
        raise OrganismManifestError(f"manifest source is not a regular file: {path}")

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise OrganismManifestError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OrganismManifestError(f"cannot read manifest source: {path}") from exc
    if not isinstance(value, dict):
        raise OrganismManifestError("manifest source root must be an object")
    return value


def build_manifest_from_files(
    source_path: Path,
    deployment_projection_path: Path,
    *,
    issued_at: str,
    repository_root: Path,
) -> Mapping[str, object]:
    """Load the two versioned sources and issue one immutable manifest."""

    return build_organism_manifest(
        load_json_document(source_path),
        load_json_document(deployment_projection_path),
        issued_at=issued_at,
        repository_root=repository_root,
    )


def build_organism_manifest(
    source: Mapping[str, object],
    deployment_projection: Mapping[str, object],
    *,
    issued_at: str,
    repository_root: Path | None = None,
) -> Mapping[str, object]:
    """Validate content-addressed sources and construct a zero-authority manifest."""

    source_value = _validate_source(source, repository_root=repository_root)
    projection_value = _validate_projection(deployment_projection, repository_root=repository_root)
    if source_value["subject_ref"] != projection_value["subject_ref"]:
        raise OrganismManifestError("source and deployment projection bind different subjects")

    components = source_value["components"]
    processes = projection_value["processes"]
    assert isinstance(components, list) and isinstance(processes, list)
    edges = _validate_topology(components, processes)
    stages = Counter(str(component["evidence"]["stage"]) for component in components)  # type: ignore[index]
    summary = {stage: stages.get(stage, 0) for stage in _STAGE_ORDER}
    payload = {
        "subject_ref": source_value["subject_ref"],
        "source_id": source_value["source_id"],
        "source_sha256": canonical_json_sha256(source_value),
        "deployment_projection_id": projection_value["projection_id"],
        "deployment_projection_sha256": canonical_json_sha256(projection_value),
        "policy_ref": source_value["policy_ref"],
        "manifest_status": "DECLARATIVE_NON_AUTHORITATIVE",
        "components": components,
        "processes": processes,
        "edges": edges,
        "evidence_stage_summary": summary,
        "grants_authority": False,
    }
    digest = canonical_json_sha256(payload)
    document = {
        "schema_id": "OrganismManifest",
        "schema_version": "1.0.0",
        "object_id": f"organism-manifest:{digest}",
        "issued_at": _timestamp(issued_at),
        "issuer": "deterministic-topology-projector",
        "contour": "governance",
        "classification": "D1_INTERNAL_SANITIZED",
        "payload": payload,
        "integrity": {
            "profile_id": "core-json-sha256-v1",
            "payload_sha256": digest,
            "parent_refs": sorted(
                {
                    str(payload["subject_ref"]),
                    f"source:sha256:{payload['source_sha256']}",
                    f"deployment-projection:sha256:{payload['deployment_projection_sha256']}",
                    str(payload["policy_ref"]),
                }
            ),
        },
    }
    validate_organism_manifest(document, repository_root=repository_root)
    return _freeze(document)


def validate_organism_manifest(
    manifest: Mapping[str, object], *, repository_root: Path | None = None
) -> dict[str, object]:
    """Validate an issued manifest without writing or observing live state."""

    document = _exact(manifest, _DOCUMENT_KEYS, "organism manifest")
    if (
        document["schema_id"] != "OrganismManifest"
        or document["schema_version"] != "1.0.0"
        or document["issuer"] != "deterministic-topology-projector"
        or document["contour"] != "governance"
        or document["classification"] != "D1_INTERNAL_SANITIZED"
    ):
        raise OrganismManifestError("organism manifest identity is invalid")
    _timestamp(document["issued_at"])
    payload = _exact(document["payload"], _PAYLOAD_KEYS, "organism manifest payload")
    if payload["manifest_status"] != "DECLARATIVE_NON_AUTHORITATIVE" or payload["grants_authority"] is not False:
        raise OrganismManifestError("organism manifest cannot grant authority or claim runtime enforcement")
    _git_ref(payload["subject_ref"], "payload.subject_ref")
    _identifier(payload["source_id"], "payload.source_id")
    _identifier(payload["deployment_projection_id"], "payload.deployment_projection_id")
    for name in ("source_sha256", "deployment_projection_sha256"):
        _sha256(payload[name], f"payload.{name}")
    _reference(payload["policy_ref"], "payload.policy_ref")
    components = _component_array(payload["components"], repository_root=repository_root)
    processes = _process_array(payload["processes"], repository_root=repository_root)
    expected_edges = _validate_topology(components, processes)
    if payload["edges"] != expected_edges:
        raise OrganismManifestError("manifest edge projection mismatch")
    stages = Counter(str(component["evidence"]["stage"]) for component in components)  # type: ignore[index]
    expected_summary = {stage: stages.get(stage, 0) for stage in _STAGE_ORDER}
    if payload["evidence_stage_summary"] != expected_summary:
        raise OrganismManifestError("evidence stage summary mismatch")
    digest = canonical_json_sha256(payload)
    if document["object_id"] != f"organism-manifest:{digest}":
        raise OrganismManifestError("organism manifest object identity mismatch")
    integrity = _exact(document["integrity"], frozenset({"profile_id", "payload_sha256", "parent_refs"}), "integrity")
    if integrity["profile_id"] != "core-json-sha256-v1":
        raise OrganismManifestError("manifest integrity profile is invalid")
    observed = _sha256(integrity["payload_sha256"], "integrity.payload_sha256")
    if not hmac.compare_digest(observed, digest):
        raise OrganismManifestError("manifest payload integrity mismatch")
    parents = _string_array(integrity["parent_refs"], "integrity.parent_refs", allow_empty=False)
    required_parents = {
        str(payload["subject_ref"]),
        f"source:sha256:{payload['source_sha256']}",
        f"deployment-projection:sha256:{payload['deployment_projection_sha256']}",
        str(payload["policy_ref"]),
    }
    if set(parents) != required_parents:
        raise OrganismManifestError("manifest parent refs are incomplete or excessive")
    return document


def _validate_source(source: Mapping[str, object], *, repository_root: Path | None) -> dict[str, object]:
    value = _exact(source, _SOURCE_KEYS, "manifest source")
    if value["schema_id"] != "OrganismManifestSource" or value["schema_version"] != "1.0.0":
        raise OrganismManifestError("manifest source schema is invalid")
    _identifier(value["source_id"], "source_id")
    _git_ref(value["subject_ref"], "subject_ref")
    _reference(value["policy_ref"], "policy_ref")
    value["components"] = _component_array(value["components"], repository_root=repository_root)
    return value


def _validate_projection(projection: Mapping[str, object], *, repository_root: Path | None) -> dict[str, object]:
    value = _exact(projection, _PROJECTION_KEYS, "deployment projection")
    if value["schema_id"] != "OrganismDeploymentProjection" or value["schema_version"] != "1.0.0":
        raise OrganismManifestError("deployment projection schema is invalid")
    _identifier(value["projection_id"], "projection_id")
    _git_ref(value["subject_ref"], "subject_ref")
    value["processes"] = _process_array(value["processes"], repository_root=repository_root)
    return value


def _component_array(value: object, *, repository_root: Path | None) -> list[dict[str, object]]:
    if not isinstance(value, (list, tuple)) or not value:
        raise OrganismManifestError("components must be a non-empty array")
    components: list[dict[str, object]] = []
    ids: set[str] = set()
    for index, raw in enumerate(value):
        component = _exact(raw, _COMPONENT_KEYS, f"components[{index}]")
        component_id = _identifier(component["component_id"], f"components[{index}].component_id")
        if component_id in ids:
            raise OrganismManifestError("component IDs must be unique")
        ids.add(component_id)
        _identifier(component["owner"], f"components[{index}].owner")
        if component["plane"] not in _PLANES:
            raise OrganismManifestError("component plane is invalid")
        component["implementation_refs"] = _repo_refs(
            component["implementation_refs"], f"components[{index}].implementation_refs", repository_root
        )
        component["inputs"] = _string_array(component["inputs"], f"components[{index}].inputs", allow_empty=True)
        component["outputs"] = _string_array(component["outputs"], f"components[{index}].outputs", allow_empty=False)
        component["dependencies"] = _id_array(component["dependencies"], f"components[{index}].dependencies")
        component["access"] = _validate_access(component["access"], f"components[{index}].access")
        if component["authority_ceiling"] not in _AUTHORITY_CEILINGS:
            raise OrganismManifestError("component authority ceiling is invalid or overbroad")
        _reference(component["budget_ref"], f"components[{index}].budget_ref")
        component["policy_refs"] = _reference_array(component["policy_refs"], f"components[{index}].policy_refs")
        component["heartbeat"] = _validate_heartbeat(component["heartbeat"], f"components[{index}].heartbeat")
        component["recovery"] = _validate_recovery(component["recovery"], f"components[{index}].recovery")
        component["kill_switch"] = _validate_kill_switch(component["kill_switch"], f"components[{index}].kill_switch")
        _repo_ref(component["proof_ref"], f"components[{index}].proof_ref", repository_root)
        component["evidence"] = _validate_evidence(component["evidence"], f"components[{index}].evidence", repository_root)
        component["next_transition"] = _validate_next_transition(
            component["next_transition"], f"components[{index}].next_transition"
        )
        component["cycle_bound"] = _validate_cycle_bound(component["cycle_bound"], f"components[{index}].cycle_bound")
        components.append(component)
    return components


def _process_array(value: object, *, repository_root: Path | None) -> list[dict[str, object]]:
    if not isinstance(value, (list, tuple)) or not value:
        raise OrganismManifestError("processes must be a non-empty array")
    result: list[dict[str, object]] = []
    ids: set[str] = set()
    for index, raw in enumerate(value):
        process = _exact(raw, _PROCESS_KEYS, f"processes[{index}]")
        process_id = _identifier(process["process_id"], f"processes[{index}].process_id")
        if process_id in ids:
            raise OrganismManifestError("process IDs must be unique")
        ids.add(process_id)
        _repo_ref(process["service_ref"], f"processes[{index}].service_ref", repository_root)
        process["component_ids"] = _id_array(process["component_ids"], f"processes[{index}].component_ids", allow_empty=False)
        _text(process["isolation"], f"processes[{index}].isolation")
        if process["lifecycle"] not in _LIFECYCLES:
            raise OrganismManifestError("process lifecycle is invalid")
        if process["observed_ref"] is not None:
            _repo_ref(process["observed_ref"], f"processes[{index}].observed_ref", repository_root)
        result.append(process)
    return result


def _validate_topology(
    components: Sequence[Mapping[str, object]], processes: Sequence[Mapping[str, object]]
) -> list[dict[str, str]]:
    component_by_id = {str(component["component_id"]): component for component in components}
    component_ids = set(component_by_id)
    mapped = [str(component_id) for process in processes for component_id in process["component_ids"]]  # type: ignore[index]
    if set(mapped) != component_ids or len(mapped) != len(set(mapped)):
        raise OrganismManifestError("deployment projection must map every component exactly once")

    producers: dict[str, str] = {}
    consumers: dict[str, list[str]] = defaultdict(list)
    edges: set[tuple[str, str, str]] = set()
    graph: dict[str, set[str]] = {component_id: set() for component_id in component_ids}
    for component_id, component in component_by_id.items():
        for dependency in component["dependencies"]:  # type: ignore[union-attr]
            if dependency not in component_ids:
                raise OrganismManifestError(f"orphan component dependency: {dependency}")
            graph[str(dependency)].add(component_id)
            edges.add((str(dependency), component_id, "dependency"))
        for channel in component["outputs"]:  # type: ignore[union-attr]
            if channel in producers:
                raise OrganismManifestError(f"channel has multiple producers: {channel}")
            producers[str(channel)] = component_id
        for channel in component["inputs"]:  # type: ignore[union-attr]
            consumers[str(channel)].append(component_id)

    for channel, targets in consumers.items():
        if channel.startswith("external:"):
            continue
        producer = producers.get(channel)
        if producer is None:
            raise OrganismManifestError(f"orphan input channel: {channel}")
        for target in targets:
            graph[producer].add(target)
            edges.add((producer, target, f"channel:{channel}"))
    for channel in producers:
        if channel.startswith("terminal:"):
            continue
        if channel not in consumers:
            raise OrganismManifestError(f"orphan output channel: {channel}")

    for cycle in _strongly_connected_cycles(graph):
        bounds = [component_by_id[component_id]["cycle_bound"] for component_id in cycle]
        if any(bound is None for bound in bounds):
            raise OrganismManifestError(f"unbounded topology cycle: {','.join(sorted(cycle))}")
        identities = {canonical_json_sha256(bound) for bound in bounds}
        if len(identities) != 1:
            raise OrganismManifestError("cycle members do not share one frozen bound")

    return [
        {"from": source, "to": target, "kind": kind}
        for source, target, kind in sorted(edges)
    ]


def _strongly_connected_cycles(graph: Mapping[str, set[str]]) -> list[set[str]]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    cycles: list[set[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in graph[node]:
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])
        if lowlinks[node] == indices[node]:
            members: set[str] = set()
            while True:
                member = stack.pop()
                on_stack.remove(member)
                members.add(member)
                if member == node:
                    break
            if len(members) > 1 or (len(members) == 1 and node in graph[node]):
                cycles.append(members)

    for node in graph:
        if node not in indices:
            visit(node)
    return cycles


def _validate_access(value: object, label: str) -> dict[str, object]:
    access = _exact(value, frozenset({"read_refs", "write_refs", "network"}), label)
    access["read_refs"] = _reference_array(access["read_refs"], f"{label}.read_refs", allow_empty=True)
    access["write_refs"] = _reference_array(access["write_refs"], f"{label}.write_refs", allow_empty=True)
    if access["network"] not in _NETWORK_MODES:
        raise OrganismManifestError(f"{label}.network is invalid")
    return access


def _validate_heartbeat(value: object, label: str) -> dict[str, object]:
    heartbeat = _exact(value, frozenset({"mode", "freshness_seconds"}), label)
    if heartbeat["mode"] not in {"EVENT_SEQUENCE", "LEASE", "ON_INVOCATION", "NONE"}:
        raise OrganismManifestError(f"{label}.mode is invalid")
    freshness = heartbeat["freshness_seconds"]
    if freshness is not None and (not isinstance(freshness, int) or isinstance(freshness, bool) or not 1 <= freshness <= 86400):
        raise OrganismManifestError(f"{label}.freshness_seconds is invalid")
    if heartbeat["mode"] == "NONE" and freshness is not None:
        raise OrganismManifestError(f"{label} NONE cannot claim freshness")
    return heartbeat


def _validate_recovery(value: object, label: str) -> dict[str, object]:
    recovery = _exact(value, frozenset({"mode", "authority_ceiling"}), label)
    if recovery["mode"] not in {"REPLAY_DURABLE_LEDGER", "RETRY_EXACT_INPUT", "REBUILD_FROM_SOURCE", "NONE"}:
        raise OrganismManifestError(f"{label}.mode is invalid")
    if recovery["authority_ceiling"] not in {"PREAUTHORIZED_R0_ONLY", "OPERATOR_REQUIRED", "NONE"}:
        raise OrganismManifestError(f"{label}.authority_ceiling is invalid")
    return recovery


def _validate_kill_switch(value: object, label: str) -> dict[str, object]:
    switch = _exact(value, frozenset({"ref", "effect"}), label)
    _reference(switch["ref"], f"{label}.ref")
    if switch["effect"] not in {"STOP_COMPONENT_CORE_CONTINUES", "STOP_NEW_AI_WORK_CORE_CONTINUES", "DENY_NEW_ATTEMPTS"}:
        raise OrganismManifestError(f"{label}.effect is invalid")
    return switch


def _validate_evidence(value: object, label: str, repository_root: Path | None) -> dict[str, object]:
    evidence = _exact(value, frozenset({"stage", "observed_ref", "negative_probe_ref", "enforcement_ref"}), label)
    stage = evidence["stage"]
    if stage not in _STAGE_ORDER:
        raise OrganismManifestError(f"{label}.stage is invalid")
    refs = ("observed_ref", "negative_probe_ref", "enforcement_ref")
    required = _STAGE_ORDER[str(stage)]
    for position, name in enumerate(refs, start=1):
        ref = evidence[name]
        if position <= required:
            _repo_ref(ref, f"{label}.{name}", repository_root)
        elif ref is not None:
            raise OrganismManifestError(f"{label}.{name} skips the progressive evidence sequence")
    return evidence


def _validate_next_transition(value: object, label: str) -> dict[str, object]:
    transition = _exact(value, frozenset({"state", "requires"}), label)
    _text(transition["state"], f"{label}.state")
    transition["requires"] = _reference_array(transition["requires"], f"{label}.requires", allow_empty=True)
    return transition


def _validate_cycle_bound(value: object, label: str) -> dict[str, object] | None:
    if value is None:
        return None
    bound = _exact(value, frozenset({"max_iterations", "stop_condition_ref"}), label)
    maximum = bound["max_iterations"]
    if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 256:
        raise OrganismManifestError(f"{label}.max_iterations is invalid")
    _reference(bound["stop_condition_ref"], f"{label}.stop_condition_ref")
    return bound


def project_organism_state(
    facts: Mapping[str, object],
    manifest: Mapping[str, object],
    *,
    projected_at: str,
) -> Mapping[str, object]:
    """Project immutable lifecycle state from already durable facts."""

    manifest_value = validate_organism_manifest(manifest)
    fact_value = _validate_state_facts(facts)
    projected = _format_time(_parse_time(projected_at, "projected_at"))
    if _parse_time(fact_value["updated_at"], "updated_at") > _parse_time(projected, "projected_at"):
        raise OrganismStateError("durable state cannot be updated after projection")
    payload = {
        **fact_value,
        "manifest_ref": manifest_value["object_id"],
        "manifest_subject_ref": manifest_value["payload"]["subject_ref"],
        "projected_at": projected,
        "grants_authority": False,
    }
    digest = canonical_json_sha256(payload)
    parents = sorted(
        set(
            [
                str(payload["manifest_ref"]),
                str(payload["manifest_subject_ref"]),
                str(payload["state_ref"]),
                *[str(ref) for ref in payload["proof_refs"]],
            ]
        )
    )
    document = {
        "schema_id": "OrganismState",
        "schema_version": "1.0.0",
        "object_id": f"organism-state:{digest}",
        "issued_at": projected,
        "issuer": "deterministic-organism-state-projector",
        "contour": "governance",
        "classification": "D1_INTERNAL_SANITIZED",
        "payload": payload,
        "integrity": {
            "profile_id": "core-json-sha256-v1",
            "payload_sha256": digest,
            "parent_refs": parents,
        },
    }
    validate_organism_state(document)
    return _freeze(document)


def project_organism_state_from_ledger(
    ledger: object,
    manifest: Mapping[str, object],
    *,
    projected_at: str,
    environment_ref: str,
    ai_enabled: bool,
) -> Mapping[str, object]:
    """Derive state from existing read-only ledger APIs; never add a writer."""

    for method in (
        "event_count", "storage_coverage_manifest", "feedback_projection_coverage", "replay_feedback"
    ):
        if not callable(getattr(ledger, method, None)):
            raise OrganismStateError(f"ledger lacks required read API: {method}")
    before = ledger.event_count()
    storage = ledger.storage_coverage_manifest()
    feedback = ledger.feedback_projection_coverage()
    replay = ledger.replay_feedback()
    if storage["global_sequence_last"] != replay.ledger_sequence_last:
        raise OrganismStateError("ledger coverage and replay sequence disagree")
    environment = _reference(environment_ref, "environment_ref")
    projected = _format_time(_parse_time(projected_at, "projected_at"))
    completion_count = ledger.event_count("complete")
    after = ledger.event_count()
    if before != after or replay.side_effects is not False:
        raise OrganismStateError("organism state observation attempted a durable write")
    feedback_count = replay.feedback_bundle_count
    if (
        isinstance(completion_count, bool)
        or not isinstance(completion_count, int)
        or completion_count < 0
        or isinstance(feedback_count, bool)
        or not isinstance(feedback_count, int)
        or feedback_count < 0
    ):
        raise OrganismStateError("terminal and feedback counts are invalid")

    idea: dict[str, object] | None = None
    outbox: dict[str, object] | None = None
    queue: dict[str, object] | None = None
    if feedback:
        if set(feedback) != {"outcome_dispositions", "experiences", "idea_tree", "feedback_outbox"}:
            raise OrganismStateError("durable feedback coverage is incomplete")
        idea = _latest_projection_entry(feedback["idea_tree"], "idea_tree")
        outbox = _latest_projection_entry(feedback["feedback_outbox"], "feedback_outbox")
        outbox_entries = feedback["feedback_outbox"]["entries"]
        if not isinstance(outbox_entries, Mapping):
            raise OrganismStateError("feedback outbox entries are invalid")
        queue = _queue_from_outbox(outbox_entries)

    terminal_imbalance = completion_count > feedback_count
    duplicate_runnable = queue is not None and queue["runnable"] > 1
    if terminal_imbalance or duplicate_runnable:
        parked = max(0, completion_count - feedback_count) + int(duplicate_runnable)
        assert parked > 0
        observed_queue = (
            {"runnable": 0, "waiting_authority": 0, "parked": parked, "oldest_event_at": projected}
            if queue is None
            else {
                **queue,
                "parked": int(queue["parked"]) + parked,
            }
        )
        reasons = ["TERMINAL_FEEDBACK_IMBALANCE"] if terminal_imbalance else []
        if completion_count > feedback_count:
            reasons.append("COMPLETED_WITHOUT_VALIDATED_FEEDBACK")
        if duplicate_runnable:
            reasons.append("MULTIPLE_RUNNABLE_PRODUCERS")
        facts = {
            "ledger_sequence": replay.ledger_sequence_last,
            "lifecycle_state": "PARKED",
            "state_ref": (
                str(outbox["object_id"])
                if outbox is not None
                else f"ledger:sequence-{replay.ledger_sequence_last}"
            ),
            "reason_codes": reasons,
            "queue": observed_queue,
            "shadow_taint": (
                str(idea["shadow_taint"]) if idea is not None else "SHADOW_UNAPPLIED"
            ),
            "ai_enabled": ai_enabled,
            "source": "DURABLE_LEDGER_REPLAY",
            "proof_refs": [
                f"replay:{replay.replay_sha256}",
                f"ledger:terminal-balance-{completion_count}-{feedback_count}",
            ],
            "environment_ref": environment,
            "updated_at": (
                str(outbox["issued_at"]) if outbox is not None else projected
            ),
        }
        return project_organism_state(facts, manifest, projected_at=projected)

    if not feedback:
        facts = {
            "ledger_sequence": replay.ledger_sequence_last,
            "lifecycle_state": "WAIT_DATA",
            "state_ref": f"ledger:sequence-{replay.ledger_sequence_last}",
            "reason_codes": ["NO_DURABLE_FEEDBACK"],
            "queue": {"runnable": 0, "waiting_authority": 0, "parked": 0, "oldest_event_at": None},
            "shadow_taint": "NONE",
            "ai_enabled": ai_enabled,
            "source": "DURABLE_LEDGER_REPLAY",
            "proof_refs": [f"replay:{replay.replay_sha256}"],
            "environment_ref": environment,
            "updated_at": projected,
        }
        return project_organism_state(facts, manifest, projected_at=projected)

    assert idea is not None and outbox is not None and queue is not None
    if outbox.get("status") == "RUNNABLE" and outbox.get("runnable_count") == 1:
        lifecycle = "GENERATING"
        reasons = ["DURABLE_RUNNABLE_TRIGGER"]
    elif outbox.get("parked_gap_refs"):
        lifecycle = "PARKED"
        reasons = ["BOUNDED_GAP_PARKED"]
    elif outbox.get("status") == "WAIT_AUTHORITY" and outbox.get("runnable_count") == 0:
        lifecycle = "WAIT_AUTHORITY"
        reasons = ["WAITING_HUMAN_AUTHORITY"]
    else:
        raise OrganismStateError("latest durable outbox state is inconsistent")
    if idea.get("state") not in {"GENERATING", "WAIT_AUTHORITY"}:
        raise OrganismStateError("latest durable idea state is outside the proven corridor")
    if lifecycle == "GENERATING" and idea.get("state") != "GENERATING":
        raise OrganismStateError("durable idea and outbox lifecycle disagree")
    if lifecycle in {"WAIT_AUTHORITY", "PARKED"} and idea.get("state") != "WAIT_AUTHORITY":
        raise OrganismStateError("durable terminal idea and outbox disagree")
    facts = {
        "ledger_sequence": replay.ledger_sequence_last,
        "lifecycle_state": lifecycle,
        "state_ref": idea["object_id"],
        "reason_codes": reasons,
        "queue": queue,
        "shadow_taint": idea["shadow_taint"],
        "ai_enabled": ai_enabled,
        "source": "DURABLE_LEDGER_REPLAY",
        "proof_refs": [f"replay:{replay.replay_sha256}"],
        "environment_ref": environment,
        "updated_at": idea["updated_at"],
    }
    return project_organism_state(facts, manifest, projected_at=projected)


def validate_organism_state(state: Mapping[str, object]) -> dict[str, object]:
    """Validate content identity and lifecycle semantics of durable state."""

    document = _exact(state, _DOCUMENT_KEYS, "organism state")
    if (
        document["schema_id"] != "OrganismState"
        or document["schema_version"] != "1.0.0"
        or document["issuer"] != "deterministic-organism-state-projector"
        or document["contour"] != "governance"
        or document["classification"] != "D1_INTERNAL_SANITIZED"
    ):
        raise OrganismStateError("organism state identity is invalid")
    issued = _format_time(_parse_time(document["issued_at"], "issued_at"))
    payload = _validate_state_payload(document["payload"])
    if payload["projected_at"] != issued:
        raise OrganismStateError("organism state issuance and projection time differ")
    digest = canonical_json_sha256(payload)
    if document["object_id"] != f"organism-state:{digest}":
        raise OrganismStateError("organism state object identity mismatch")
    integrity = _exact(document["integrity"], frozenset({"profile_id", "payload_sha256", "parent_refs"}), "integrity")
    if integrity["profile_id"] != "core-json-sha256-v1":
        raise OrganismStateError("organism state integrity profile is invalid")
    if not hmac.compare_digest(_sha256(integrity["payload_sha256"], "integrity.payload_sha256"), digest):
        raise OrganismStateError("organism state payload integrity mismatch")
    expected_parents = {
        str(payload["manifest_ref"]), str(payload["manifest_subject_ref"]), str(payload["state_ref"]),
        *[str(ref) for ref in payload["proof_refs"]],
    }
    if set(_string_array(integrity["parent_refs"], "integrity.parent_refs", allow_empty=False)) != expected_parents:
        raise OrganismStateError("organism state parent refs mismatch")
    return document


def validate_pulse_policy(policy: Mapping[str, object]) -> dict[str, object]:
    value = _exact(policy, _PULSE_POLICY_KEYS, "pulse policy")
    if value["schema_id"] != "PulsePolicy" or value["schema_version"] != "1.0.0":
        raise OrganismStateError("pulse policy schema is invalid")
    _identifier(value["policy_id"], "policy_id")
    for name in (
        "freshness_warn_seconds", "freshness_red_seconds", "queue_warn_count", "queue_red_count",
        "queue_age_warn_seconds", "queue_age_red_seconds",
    ):
        value[name] = _bounded_nonnegative(value[name], name, maximum=31_536_000)
    for warn, red in (
        ("freshness_warn_seconds", "freshness_red_seconds"),
        ("queue_warn_count", "queue_red_count"),
        ("queue_age_warn_seconds", "queue_age_red_seconds"),
    ):
        if value[warn] >= value[red]:
            raise OrganismStateError(f"pulse policy requires {warn} < {red}")
    return value


def sample_pulse(
    state: Mapping[str, object],
    manifest: Mapping[str, object],
    capability_assessments: Sequence[Mapping[str, object]],
    policy: Mapping[str, object],
    *,
    sampled_at: str,
) -> Mapping[str, object]:
    """Create a deterministic, zero-write health sample separate from durable state."""

    state_document = validate_organism_state(state)
    manifest_document = validate_organism_manifest(manifest)
    state_payload = state_document["payload"]
    if (
        state_payload["manifest_ref"] != manifest_document["object_id"]
        or state_payload["manifest_subject_ref"] != manifest_document["payload"]["subject_ref"]
    ):
        raise OrganismStateError("pulse inputs bind different manifest identities")
    policy_value = validate_pulse_policy(policy)
    capabilities = _validate_capability_assessments(capability_assessments)
    sample_time = _format_time(_parse_time(sampled_at, "sampled_at"))
    limits = {
        name: policy_value[name]
        for name in (
            "freshness_warn_seconds", "freshness_red_seconds", "queue_warn_count", "queue_red_count",
            "queue_age_warn_seconds", "queue_age_red_seconds",
        )
    }
    health = _derive_pulse_health(state_payload, capabilities, limits, sample_time)
    payload = {
        "organism_state_ref": state_document["object_id"],
        "manifest_ref": manifest_document["object_id"],
        "policy_id": policy_value["policy_id"],
        "policy_sha256": canonical_json_sha256(policy_value),
        "policy_limits": limits,
        "sampled_at": sample_time,
        "state_updated_at": state_payload["updated_at"],
        "environment_ref": state_payload["environment_ref"],
        "lifecycle_state": state_payload["lifecycle_state"],
        "ai_enabled": state_payload["ai_enabled"],
        "queue": state_payload["queue"],
        "state_age_seconds": health["state_age_seconds"],
        "queue_age_seconds": health["queue_age_seconds"],
        "capability_assessments": capabilities,
        "traffic_light": health["traffic_light"],
        "health_state": health["health_state"],
        "reason_codes": health["reason_codes"],
        "side_effects": False,
        "grants_authority": False,
    }
    digest = canonical_json_sha256(payload)
    document = {
        "schema_id": "PulseSample",
        "schema_version": "1.0.0",
        "object_id": f"pulse-sample:{digest}",
        "issued_at": sample_time,
        "issuer": "read-only-pulse-projector",
        "contour": "governance",
        "classification": "D1_INTERNAL_SANITIZED",
        "payload": payload,
        "integrity": {
            "profile_id": "core-json-sha256-v1",
            "payload_sha256": digest,
            "parent_refs": sorted(
                {
                    str(payload["organism_state_ref"]), str(payload["manifest_ref"]),
                    f"pulse-policy:sha256:{payload['policy_sha256']}",
                    *[str(item["proof_ref"]) for item in capabilities],
                }
            ),
        },
    }
    validate_pulse_sample(document)
    return _freeze(document)


def validate_pulse_sample(sample: Mapping[str, object]) -> dict[str, object]:
    document = _exact(sample, _DOCUMENT_KEYS, "pulse sample")
    if (
        document["schema_id"] != "PulseSample"
        or document["schema_version"] != "1.0.0"
        or document["issuer"] != "read-only-pulse-projector"
        or document["contour"] != "governance"
        or document["classification"] != "D1_INTERNAL_SANITIZED"
    ):
        raise OrganismStateError("pulse sample identity is invalid")
    issued = _format_time(_parse_time(document["issued_at"], "issued_at"))
    payload = _exact(document["payload"], _PULSE_PAYLOAD_KEYS, "pulse payload")
    for name in ("organism_state_ref", "manifest_ref"):
        _reference(payload[name], name)
    _identifier(payload["policy_id"], "policy_id")
    _sha256(payload["policy_sha256"], "policy_sha256")
    limits = _exact(
        payload["policy_limits"],
        frozenset(
            {
                "freshness_warn_seconds", "freshness_red_seconds", "queue_warn_count", "queue_red_count",
                "queue_age_warn_seconds", "queue_age_red_seconds",
            }
        ),
        "policy_limits",
    )
    embedded_policy = validate_pulse_policy(
        {"schema_id": "PulsePolicy", "schema_version": "1.0.0", "policy_id": payload["policy_id"], **limits}
    )
    if payload["policy_sha256"] != canonical_json_sha256(embedded_policy):
        raise OrganismStateError("pulse policy digest does not bind embedded limits")
    if payload["sampled_at"] != issued:
        raise OrganismStateError("pulse sampled_at differs from issuance")
    _parse_time(payload["state_updated_at"], "state_updated_at")
    _reference(payload["environment_ref"], "environment_ref")
    if payload["lifecycle_state"] not in _LIFECYCLE_STATES or not isinstance(payload["ai_enabled"], bool):
        raise OrganismStateError("pulse lifecycle or AI mode is invalid")
    queue = _validate_queue(payload["queue"])
    capabilities = _validate_capability_assessments(payload["capability_assessments"])
    expected = _derive_pulse_health(
        {
            "updated_at": payload["state_updated_at"], "environment_ref": payload["environment_ref"],
            "lifecycle_state": payload["lifecycle_state"], "ai_enabled": payload["ai_enabled"], "queue": queue,
        },
        capabilities,
        limits,
        issued,
    )
    for name in ("state_age_seconds", "queue_age_seconds", "traffic_light", "health_state", "reason_codes"):
        if payload[name] != expected[name]:
            raise OrganismStateError(f"pulse {name} is misleading")
    if payload["side_effects"] is not False or payload["grants_authority"] is not False:
        raise OrganismStateError("pulse cannot have side effects or grant authority")
    digest = canonical_json_sha256(payload)
    if document["object_id"] != f"pulse-sample:{digest}":
        raise OrganismStateError("pulse object identity mismatch")
    integrity = _exact(document["integrity"], frozenset({"profile_id", "payload_sha256", "parent_refs"}), "integrity")
    if integrity["profile_id"] != "core-json-sha256-v1":
        raise OrganismStateError("pulse integrity profile is invalid")
    if not hmac.compare_digest(_sha256(integrity["payload_sha256"], "integrity.payload_sha256"), digest):
        raise OrganismStateError("pulse payload integrity mismatch")
    expected_parents = {
        str(payload["organism_state_ref"]), str(payload["manifest_ref"]),
        f"pulse-policy:sha256:{payload['policy_sha256']}",
        *[str(item["proof_ref"]) for item in capabilities],
    }
    if set(_string_array(integrity["parent_refs"], "integrity.parent_refs", allow_empty=False)) != expected_parents:
        raise OrganismStateError("pulse parent refs mismatch")
    return document


def _validate_state_facts(facts: object) -> dict[str, object]:
    value = _exact(facts, _STATE_FACT_KEYS, "organism state facts")
    value["ledger_sequence"] = _bounded_nonnegative(value["ledger_sequence"], "ledger_sequence", maximum=9_007_199_254_740_991)
    lifecycle = value["lifecycle_state"]
    if lifecycle not in _LIFECYCLE_STATES:
        raise OrganismStateError("organism lifecycle state is invalid")
    _reference(value["state_ref"], "state_ref")
    value["reason_codes"] = _reason_array(value["reason_codes"], "reason_codes", allow_empty=False)
    value["queue"] = _validate_queue(value["queue"])
    if value["shadow_taint"] not in {"NONE", "SHADOW_UNAPPLIED"}:
        raise OrganismStateError("organism state shadow taint is invalid")
    if not isinstance(value["ai_enabled"], bool):
        raise OrganismStateError("organism AI mode must be boolean")
    if value["source"] not in {"DURABLE_LEDGER_REPLAY", "FROZEN_CONTROLLER_SNAPSHOT"}:
        raise OrganismStateError("organism state source is invalid")
    value["proof_refs"] = _reference_array(value["proof_refs"], "proof_refs", allow_empty=False)
    _reference(value["environment_ref"], "environment_ref")
    value["updated_at"] = _format_time(_parse_time(value["updated_at"], "updated_at"))
    _validate_lifecycle_queue(value)
    return value


def _validate_state_payload(payload: object) -> dict[str, object]:
    value = _exact(payload, _STATE_PAYLOAD_KEYS, "organism state payload")
    facts = _validate_state_facts({name: value[name] for name in _STATE_FACT_KEYS})
    _reference(value["manifest_ref"], "manifest_ref")
    _git_ref(value["manifest_subject_ref"], "manifest_subject_ref")
    projected = _format_time(_parse_time(value["projected_at"], "projected_at"))
    if _parse_time(facts["updated_at"], "updated_at") > _parse_time(projected, "projected_at"):
        raise OrganismStateError("state update occurs after projection")
    if value["grants_authority"] is not False:
        raise OrganismStateError("organism state cannot grant authority")
    return {**facts, "manifest_ref": value["manifest_ref"], "manifest_subject_ref": value["manifest_subject_ref"], "projected_at": projected, "grants_authority": False}


def _validate_lifecycle_queue(value: Mapping[str, object]) -> None:
    lifecycle = value["lifecycle_state"]
    queue = value["queue"]
    assert isinstance(queue, Mapping)
    runnable = queue["runnable"]
    waiting = queue["waiting_authority"]
    parked = queue["parked"]
    if lifecycle in {"WAIT_DATA", "REJECTED", "LEARNED"} and any((runnable, waiting, parked)):
        raise OrganismStateError(f"{lifecycle} cannot claim queued work")
    if lifecycle == "GENERATING" and runnable == 0:
        raise OrganismStateError("GENERATING requires runnable work")
    if lifecycle == "WAIT_AUTHORITY" and waiting == 0:
        raise OrganismStateError("WAIT_AUTHORITY requires a durable authority wait")
    if lifecycle == "PARKED" and parked == 0:
        raise OrganismStateError("PARKED requires a durable parked item")
    if value["ai_enabled"] is False and lifecycle in {"GENERATING", "ADMITTED_A1", "RUNNING"}:
        raise OrganismStateError("AI_OFF cannot claim active autonomous work")
    if lifecycle == "LEARNED" and (
        value["shadow_taint"] != "NONE" or "DOMAIN_APPLIED" not in value["reason_codes"]
    ):
        raise OrganismStateError("LEARNED requires an applied domain outcome without shadow taint")


def _validate_queue(value: object) -> dict[str, object]:
    queue = _exact(value, _QUEUE_KEYS, "queue")
    for name in ("runnable", "waiting_authority", "parked"):
        queue[name] = _bounded_nonnegative(queue[name], f"queue.{name}", maximum=1_000_000)
    total = sum(int(queue[name]) for name in ("runnable", "waiting_authority", "parked"))
    if queue["oldest_event_at"] is None:
        if total:
            raise OrganismStateError("non-empty queue requires oldest_event_at")
    else:
        queue["oldest_event_at"] = _format_time(_parse_time(queue["oldest_event_at"], "queue.oldest_event_at"))
        if total == 0:
            raise OrganismStateError("empty queue cannot claim oldest_event_at")
    return queue


def _latest_projection_entry(projection: object, label: str) -> dict[str, object]:
    value = _exact(projection, frozenset({"schema_id", "schema_version", "count", "latest_ref", "entries"}), label)
    entries = value["entries"]
    if not isinstance(entries, Mapping) or value["count"] != len(entries) or not entries:
        raise OrganismStateError(f"{label} projection entries are invalid")
    matches = [entry for entry in entries.values() if isinstance(entry, Mapping) and entry.get("object_id") == value["latest_ref"]]
    if len(matches) != 1:
        raise OrganismStateError(f"{label} latest_ref is not unique")
    return _copy(matches[0])  # type: ignore[return-value]


def _queue_from_outbox(entries: Mapping[str, object]) -> dict[str, object]:
    runnable = waiting = parked = 0
    event_times: list[str] = []
    for raw in entries.values():
        if not isinstance(raw, Mapping):
            raise OrganismStateError("durable outbox record is invalid")
        status = raw.get("status")
        count = raw.get("runnable_count")
        if status == "RUNNABLE" and count == 1:
            runnable += 1
        elif status == "WAIT_AUTHORITY" and count == 0:
            waiting += 1
        else:
            raise OrganismStateError("durable outbox queue state is invalid")
        parked_refs = raw.get("parked_gap_refs")
        if not isinstance(parked_refs, (list, tuple)):
            raise OrganismStateError("durable parked refs are invalid")
        parked += len(parked_refs)
        event_times.append(_format_time(_parse_time(raw.get("issued_at"), "outbox.issued_at")))
    return {
        "runnable": runnable,
        "waiting_authority": waiting,
        "parked": parked,
        "oldest_event_at": min(event_times) if event_times else None,
    }


def _validate_capability_assessments(value: object) -> list[dict[str, object]]:
    if not isinstance(value, (list, tuple)):
        raise OrganismStateError("capability assessments must be an array")
    result: list[dict[str, object]] = []
    ids: set[str] = set()
    for index, raw in enumerate(value):
        item = _exact(raw, _CAPABILITY_ASSESSMENT_KEYS, f"capability_assessments[{index}]")
        capability_id = _text(item["capability_id"], f"capability_assessments[{index}].capability_id")
        if _REASON_RE.fullmatch(capability_id) is None or capability_id in ids:
            raise OrganismStateError("capability IDs must be unique normalized constants")
        ids.add(capability_id)
        if item["status"] not in _CAPABILITY_STATUSES:
            raise OrganismStateError("capability assessment status is invalid")
        _reference(item["environment_ref"], f"capability_assessments[{index}].environment_ref")
        if not isinstance(item["critical"], bool):
            raise OrganismStateError("capability critical flag must be boolean")
        item["reason_codes"] = _reason_array(
            item["reason_codes"], f"capability_assessments[{index}].reason_codes", allow_empty=True
        )
        _reference(item["proof_ref"], f"capability_assessments[{index}].proof_ref")
        result.append(item)
    return sorted(result, key=lambda item: str(item["capability_id"]))


def _derive_pulse_health(
    state: Mapping[str, object],
    capabilities: Sequence[Mapping[str, object]],
    limits: Mapping[str, object],
    sampled_at: str,
) -> dict[str, object]:
    sampled = _parse_time(sampled_at, "sampled_at")
    updated = _parse_time(state["updated_at"], "state.updated_at")
    if sampled < updated:
        raise OrganismStateError("pulse cannot sample before durable state update")
    state_age = int((sampled - updated).total_seconds())
    queue = _validate_queue(state["queue"])
    oldest = queue["oldest_event_at"]
    queue_age = 0
    if oldest is not None:
        oldest_time = _parse_time(oldest, "queue.oldest_event_at")
        if sampled < oldest_time:
            raise OrganismStateError("pulse cannot sample before queued work exists")
        queue_age = int((sampled - oldest_time).total_seconds())
    severity = 0
    reasons: set[str] = set()
    lifecycle = state["lifecycle_state"]
    if lifecycle == "WAIT_DATA":
        reasons.add("WAIT_DATA_HEALTHY")
    elif lifecycle == "REJECTED":
        reasons.add("REJECTED_POLICY_HEALTHY")
    elif lifecycle == "WAIT_AUTHORITY":
        severity = 1
        reasons.add("WAITING_HUMAN_AUTHORITY")
    elif lifecycle == "PARKED":
        severity = 1
        reasons.add("BOUNDED_WORK_PARKED")
    else:
        reasons.add("ACTIVE_STATE_OBSERVED")
    if state["ai_enabled"] is False:
        reasons.add("AI_OFF_CORE_OPERATIONAL")
    if not capabilities:
        severity = max(severity, 1)
        reasons.add("CAPABILITY_EVIDENCE_ABSENT")
    for capability in capabilities:
        if capability["status"] != "PASS_FOR_FROZEN_SCOPE":
            severity = max(severity, 2 if capability["critical"] else 1)
            reasons.add("CAPABILITY_NOT_CURRENT")
        if capability["environment_ref"] != state["environment_ref"]:
            severity = max(severity, 2 if capability["critical"] else 1)
            reasons.add("ENVIRONMENT_COMPATIBILITY_MISMATCH")
    if state_age >= limits["freshness_red_seconds"]:
        severity = 2
        reasons.add("STATE_STALE")
    elif state_age >= limits["freshness_warn_seconds"]:
        severity = max(severity, 1)
        reasons.add("STATE_AGING")
    queue_count = sum(int(queue[name]) for name in ("runnable", "waiting_authority", "parked"))
    if queue_count >= limits["queue_red_count"] or queue_age >= limits["queue_age_red_seconds"]:
        severity = 2
        reasons.add("QUEUE_STUCK")
    elif queue_count >= limits["queue_warn_count"] or queue_age >= limits["queue_age_warn_seconds"]:
        severity = max(severity, 1)
        reasons.add("QUEUE_PRESSURE")
    traffic = ("GREEN", "YELLOW", "RED")[severity]
    if severity == 2:
        health = "UNHEALTHY"
    elif severity == 1:
        health = "WAIT_AUTHORITY" if lifecycle == "WAIT_AUTHORITY" else "PARKED" if lifecycle == "PARKED" else "DEGRADED"
    elif state["ai_enabled"] is False:
        health = "AI_OFF_CORE_OPERATIONAL"
    elif lifecycle == "WAIT_DATA":
        health = "HEALTHY_WAIT_DATA"
    elif lifecycle == "REJECTED":
        health = "HEALTHY_REJECTED"
    else:
        health = "HEALTHY_ACTIVE"
    return {
        "state_age_seconds": state_age,
        "queue_age_seconds": queue_age,
        "traffic_light": traffic,
        "health_state": health,
        "reason_codes": sorted(reasons),
    }


def _reason_array(value: object, label: str, *, allow_empty: bool) -> list[str]:
    values = _string_array(value, label, allow_empty=allow_empty)
    if any(_REASON_RE.fullmatch(item) is None for item in values):
        raise OrganismStateError(f"{label} contains an invalid reason code")
    return values


def _bounded_nonnegative(value: object, label: str, *, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise OrganismStateError(f"{label} must be a bounded non-negative integer")
    return value


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise OrganismStateError(f"{label} must be RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise OrganismStateError(f"{label} must be RFC3339 UTC") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise OrganismStateError(f"{label} must be UTC")
    return parsed.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json_sha256(value: object) -> str:
    try:
        raw = json.dumps(
            _copy(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OrganismManifestError("manifest contains non-canonical JSON data") from exc
    return hashlib.sha256(raw).hexdigest()


def _repo_refs(value: object, label: str, repository_root: Path | None) -> list[str]:
    refs = _string_array(value, label, allow_empty=False)
    for index, ref in enumerate(refs):
        _repo_ref(ref, f"{label}[{index}]", repository_root)
    return refs


def _repo_ref(value: object, label: str, repository_root: Path | None) -> str:
    ref = _reference(value, label)
    if not ref.startswith("repo:"):
        raise OrganismManifestError(f"{label} must be a repository reference")
    relative = ref.removeprefix("repo:")
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise OrganismManifestError(f"{label} escapes the repository")
    if repository_root is not None:
        root = repository_root.resolve()
        target = (root / path).resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise OrganismManifestError(f"{label} escapes the repository") from exc
        if not target.is_file():
            raise OrganismManifestError(f"{label} target does not exist")
    return ref


def _reference_array(value: object, label: str, allow_empty: bool = False) -> list[str]:
    refs = _string_array(value, label, allow_empty=allow_empty)
    for index, ref in enumerate(refs):
        _reference(ref, f"{label}[{index}]")
    return refs


def _id_array(value: object, label: str, allow_empty: bool = True) -> list[str]:
    items = _string_array(value, label, allow_empty=allow_empty)
    for index, item in enumerate(items):
        _identifier(item, f"{label}[{index}]")
    return items


def _string_array(value: object, label: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, (list, tuple)) or (not allow_empty and not value):
        raise OrganismManifestError(f"{label} must be a string array")
    result = [_text(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise OrganismManifestError(f"{label} must contain unique values")
    return result


def _reference(value: object, label: str) -> str:
    text = _text(value, label)
    if _REF_RE.fullmatch(text) is None:
        raise OrganismManifestError(f"{label} is not a normalized reference")
    return text


def _identifier(value: object, label: str) -> str:
    text = _text(value, label)
    if _ID_RE.fullmatch(text) is None:
        raise OrganismManifestError(f"{label} is not a normalized identifier")
    return text


def _git_ref(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_REF_RE.fullmatch(value) is None:
        raise OrganismManifestError(f"{label} must bind an exact Git commit")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise OrganismManifestError(f"{label} must be lowercase SHA-256")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("Z") or "T" not in value:
        raise OrganismManifestError("issued_at must be RFC3339 UTC")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 2048:
        raise OrganismManifestError(f"{label} must be bounded normalized text")
    return value


def _exact(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise OrganismManifestError(f"{label} shape mismatch")
    return _copy(value)  # type: ignore[return-value]


def _copy(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_copy(item) for item in value]
    return value


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


__all__ = [
    "OrganismManifestError", "OrganismStateError", "build_manifest_from_files", "build_organism_manifest",
    "validate_organism_manifest", "project_organism_state", "project_organism_state_from_ledger",
    "validate_organism_state", "validate_pulse_policy", "sample_pulse", "validate_pulse_sample",
    "load_json_document", "canonical_json_sha256",
]
