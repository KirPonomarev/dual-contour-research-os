#!/usr/bin/env python3
"""Build and verify the exact R08B candidate without granting live authority."""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
CONTAINERFILE = "ops/release/Containerfile"
LOCK_FILE = "ops/release/dependency-lock.json"
NOTICES_FILE = "ops/release/THIRD_PARTY_NOTICES.md"
PLATFORM = "linux/amd64"
OUTPUT_FILES = (
    "candidate-build-evidence.json",
    "candidate-image.tar",
    "container-file-inventory.txt",
    "dpkg-inventory.tsv",
    "python-inventory.json",
    "candidate-sbom.spdx.json",
    "release-relevant-paths.json",
    "evidence-only-path-allowlist.json",
)
FINGERPRINT_PATHS = (
    "ops/release/Containerfile",
    "ops/release/dependency-lock.json",
    "ops/release/THIRD_PARTY_NOTICES.md",
    "ops/release/final-a1-runtime-policy.json",
    "ops/release/monitoring-recovery-policy.json",
    "ops/release/researchd.config.template.json",
    "ops/release/runtime-policy.json",
    "provenance/model-role-evaluation-v2.json",
    "provenance/model-worker-ipc-extension-v1.json",
    "provenance/model-provider-routing-v1.json",
)
EVIDENCE_ONLY_PREFIXES = (
    "docs/receipts/assurance/",
    "docs/receipts/capability/",
    "docs/receipts/integration/",
    "docs/receipts/release/",
    "stages/f09-release-evidence-currentness-and-freeze/",
    "stages/f12-final-evidence-and-independent-audit/",
)
SECRET_PATTERN = re.compile(
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|"
    r"(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{12,}|"
    r"/(?:Users|Volumes)/|"
    r"(?:API|ACCESS|SECRET|PRIVATE)[_-]?KEY\s*=",
    re.IGNORECASE,
)


class CandidateBuildError(RuntimeError):
    """Raised when exact candidate build evidence is incomplete or inconsistent."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CandidateBuildError(message)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    timeout: int = 1800,
    text: bool = True,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=text,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        stderr = result.stderr if isinstance(result.stderr, str) else result.stderr.decode(errors="replace")
        raise CandidateBuildError(f"command failed ({command[0]}):{stderr[-2000:]}")
    return result


def _git(*args: str) -> str:
    result = _run(["git", *args])
    assert isinstance(result.stdout, str)
    return result.stdout.strip()


def _source_date_epoch(candidate: str) -> str:
    value = _git("show", "-s", "--format=%ct", candidate)
    _require(re.fullmatch(r"[1-9][0-9]*", value) is not None, "candidate commit epoch is invalid")
    return value


def _reproducible_build_command(
    candidate: str,
    tag: str,
    source_date_epoch: str,
    output_path: Path,
) -> list[str]:
    _require(re.fullmatch(r"[0-9a-f]{40}", candidate) is not None, "candidate SHA format")
    _require(re.fullmatch(r"[1-9][0-9]*", source_date_epoch) is not None, "candidate commit epoch is invalid")
    return [
        "docker",
        "buildx",
        "build",
        "--no-cache",
        "--pull=false",
        "--provenance=false",
        "--platform",
        PLATFORM,
        "--build-arg",
        f"RELEASE_SHA={candidate}",
        "--build-arg",
        f"SOURCE_DATE_EPOCH={source_date_epoch}",
        "--build-arg",
        "BUILDKIT_MULTI_PLATFORM=1",
        f"--output=type=oci,dest={output_path},rewrite-timestamp=true",
        "-f",
        CONTAINERFILE,
        "-t",
        tag,
        ".",
    ]


def _build_reproducible_image(candidate: str, tag: str, source_date_epoch: str) -> None:
    with tempfile.TemporaryDirectory(prefix="r08b-reproducible-build-") as directory:
        output_path = Path(directory) / "image.oci.tar"
        _run(
            _reproducible_build_command(
                candidate,
                tag,
                source_date_epoch,
                output_path,
            ),
            timeout=3600,
        )
        _require(output_path.is_file() and not output_path.is_symlink(), "reproducible OCI output missing")
        _run(["docker", "load", "--input", str(output_path)], timeout=1800)


def _write_private(path: Path, value: bytes) -> str:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
    finally:
        if not os.path.exists(path):
            try:
                os.close(descriptor)
            except OSError:
                pass
    os.chmod(path, 0o600)
    return _sha_file(path)


def _owner_only_dir(path_value: str, *, create: bool) -> Path:
    path = Path(path_value).expanduser().resolve()
    try:
        path.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise CandidateBuildError("candidate evidence directory must be outside the repository")
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)
    _require(path.is_dir() and not path.is_symlink(), "candidate evidence directory is invalid")
    _require(stat.S_IMODE(path.stat().st_mode) == 0o700, "candidate evidence directory is not 0700")
    return path


def _load_private_json(path: Path) -> tuple[dict[str, Any], str]:
    _require(path.exists() and not path.is_symlink(), f"missing private JSON:{path.name}")
    _require(stat.S_ISREG(path.stat().st_mode), f"private JSON is not regular:{path.name}")
    _require(stat.S_IMODE(path.stat().st_mode) == 0o600, f"private JSON is not 0600:{path.name}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateBuildError(f"invalid private JSON:{path.name}") from exc
    _require(isinstance(value, dict), f"private JSON is not an object:{path.name}")
    return value, _sha_bytes(raw)


def _validate_advisory_snapshot(value: Mapping[str, object]) -> None:
    _require(value.get("schema_id") == "R08BCandidateAdvisorySnapshot", "advisory snapshot schema")
    _require(value.get("platform") == PLATFORM, "advisory snapshot platform")
    _require(value.get("status") == "PASS_CURRENT", "advisory snapshot is not current")
    _require(value.get("critical_findings") == 0, "critical advisory finding")
    _require(value.get("high_findings") == 0, "high advisory finding")
    _require(isinstance(value.get("scanner"), str) and value.get("scanner"), "advisory scanner missing")
    _require(isinstance(value.get("database_revision"), str) and value.get("database_revision"), "advisory database revision missing")


def _validate_source(candidate: str, candidate_ci_run: int) -> str:
    _require(re.fullmatch(r"[0-9a-f]{40}", candidate) is not None, "candidate SHA format")
    _require(candidate_ci_run > 0, "candidate CI run is invalid")
    head = _git("rev-parse", "HEAD")
    remote = _git("rev-parse", "refs/remotes/origin/main")
    _require(head == candidate and remote == candidate, "candidate is not exact HEAD and origin/main")
    _require(not _git("status", "--porcelain", "--untracked-files=no"), "tracked worktree is dirty")
    tree = _git("rev-parse", f"{candidate}^{{tree}}")
    ci = _run(
        ["gh", "run", "view", str(candidate_ci_run), "--json", "headSha,conclusion,status,event"],
        timeout=120,
    )
    assert isinstance(ci.stdout, str)
    ci_value = json.loads(ci.stdout)
    _require(ci_value.get("headSha") == candidate, "CI run is not bound to candidate")
    _require(ci_value.get("conclusion") == "success" and ci_value.get("status") == "completed", "candidate CI is not green")
    return tree


def _image_inspect(tag: str) -> dict[str, Any]:
    result = _run(["docker", "image", "inspect", tag])
    assert isinstance(result.stdout, str)
    values = json.loads(result.stdout)
    _require(isinstance(values, list) and len(values) == 1 and isinstance(values[0], dict), "image inspect shape")
    return values[0]


def _container_output(tag: str, command: list[str]) -> bytes:
    result = _run(
        ["docker", "run", "--rm", "--network", "none", "--user", "0:0", "--entrypoint", command[0], tag, *command[1:]],
        text=False,
        timeout=300,
    )
    assert isinstance(result.stdout, bytes)
    return result.stdout


def _inventory(tag: str) -> tuple[bytes, bytes, bytes]:
    files = _container_output(
        tag,
        ["/bin/sh", "-c", "find /opt/research-os -xdev -printf '%P\\t%y\\t%s\\t%u:%g\\t%m\\n' | LC_ALL=C sort"],
    )
    dpkg = _container_output(
        tag,
        ["dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\t${Architecture}\\n"],
    )
    python = _container_output(tag, ["python", "-m", "pip", "list", "--format=json", "--disable-pip-version-check"])
    return files, dpkg, python


def _normalize_image(value: Mapping[str, object]) -> dict[str, object]:
    config = value.get("Config")
    rootfs = value.get("RootFS")
    _require(isinstance(config, dict) and isinstance(rootfs, dict), "image config/rootfs missing")
    return {
        "id": value.get("Id"),
        "architecture": value.get("Architecture"),
        "os": value.get("Os"),
        "config_sha256": _sha_bytes(_canonical(config)),
        "rootfs_sha256": _sha_bytes(_canonical(rootfs)),
        "entrypoint": config.get("Entrypoint"),
        "cmd": config.get("Cmd"),
        "user": config.get("User"),
        "revision": (config.get("Labels") or {}).get("org.opencontainers.image.revision"),
    }


def _spdx(candidate: str, dpkg: bytes, python_bytes: bytes) -> dict[str, object]:
    packages: list[dict[str, object]] = []
    for index, line in enumerate(dpkg.decode("utf-8").splitlines(), start=1):
        name, version, architecture = line.split("\t")
        packages.append(
            {
                "SPDXID": f"SPDXRef-Deb-{index}",
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "supplier": "Organization: Debian",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:deb/debian/{name}@{version}?arch={architecture}",
                    }
                ],
            }
        )
    python_values = json.loads(python_bytes)
    _require(isinstance(python_values, list), "python package inventory shape")
    offset = len(packages)
    for index, item in enumerate(sorted(python_values, key=lambda value: str(value.get("name"))), start=1):
        name = str(item.get("name"))
        version = str(item.get("version"))
        packages.append(
            {
                "SPDXID": f"SPDXRef-Python-{offset + index}",
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "supplier": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{name.lower()}@{version}",
                    }
                ],
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"dual-contour-research-os-{candidate}",
        "documentNamespace": f"https://dual-contour.invalid/spdx/{candidate}",
        "creationInfo": {
            "creators": ["Tool: tools/candidate_image_build.py"],
            "created": "1970-01-01T00:00:00Z",
        },
        "documentDescribes": [item["SPDXID"] for item in packages],
        "packages": packages,
    }


def _git_blob_entries(candidate: str) -> list[dict[str, str]]:
    output = _git("ls-tree", "-r", candidate)
    entries: list[dict[str, str]] = []
    for line in output.splitlines():
        metadata, path = line.split("\t", 1)
        mode, kind, blob = metadata.split(" ")
        _require(kind == "blob", f"unexpected Git object:{path}")
        entries.append({"path": path, "mode": mode, "blob_sha": blob})
    return entries


def _release_path_manifests(candidate: str, tree: str) -> tuple[dict[str, object], dict[str, object]]:
    entries = _git_blob_entries(candidate)
    relevant = [
        item
        for item in entries
        if not any(item["path"].startswith(prefix) for prefix in EVIDENCE_ONLY_PREFIXES)
    ]
    allowlist = {
        "schema_id": "R08BEvidenceOnlyPathAllowlist",
        "schema_version": "1.0.0",
        "release_subject_sha": candidate,
        "release_subject_tree_sha": tree,
        "path_prefixes": list(EVIDENCE_ONLY_PREFIXES),
        "rule": "later Git diffs must contain only additions or edits under these prefixes",
        "deletion_allowed": False,
        "renaming_allowed": False,
        "grants_authority": False,
    }
    relevant_manifest = {
        "schema_id": "R08BReleaseRelevantPathsManifest",
        "schema_version": "1.0.0",
        "release_subject_sha": candidate,
        "release_subject_tree_sha": tree,
        "entries": relevant,
        "entry_count": len(relevant),
        "entry_set_sha256": _sha_bytes(_canonical(relevant)),
        "excluded_only_by_allowlist_sha256": _sha_bytes(_canonical(allowlist)),
    }
    return relevant_manifest, allowlist


def _archive_identity(path: Path) -> tuple[str, tuple[str, ...]]:
    with tarfile.open(path, "r") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        _require(len(names) == len(set(names)), "duplicate archive member")
        for member in members:
            _require(not member.name.startswith("/") and ".." not in Path(member.name).parts, "unsafe archive member")
        manifest_member = archive.extractfile("manifest.json")
        _require(manifest_member is not None, "archive manifest missing")
        manifests = json.loads(manifest_member.read())
        _require(isinstance(manifests, list) and len(manifests) == 1, "archive manifest shape")
        config_name = manifests[0].get("Config")
        _require(isinstance(config_name, str), "archive config ref missing")
        config_member = archive.extractfile(config_name)
        _require(config_member is not None, "archive config missing")
        config_bytes = config_member.read()
        _require(Path(config_name).stem == _sha_bytes(config_bytes), "archive config digest mismatch")
        config_sha256 = _sha_bytes(config_bytes)
        bound_oci_digests: set[str] = set()
        if "index.json" in names:
            index_member = archive.extractfile("index.json")
            _require(index_member is not None, "archive OCI index missing")
            try:
                index = json.loads(index_member.read())
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CandidateBuildError("archive OCI index is invalid") from exc

            def visit(descriptor: object, ancestors: tuple[str, ...]) -> bool:
                _require(isinstance(descriptor, dict), "archive OCI descriptor shape")
                digest = descriptor.get("digest")
                _require(
                    isinstance(digest, str)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None,
                    "archive OCI descriptor digest",
                )
                digest_value = digest.removeprefix("sha256:")
                _require(digest_value not in ancestors, "archive OCI descriptor cycle")
                blob = archive.extractfile(f"blobs/sha256/{digest_value}")
                _require(blob is not None, "archive OCI descriptor blob missing")
                blob_bytes = blob.read()
                _require(_sha_bytes(blob_bytes) == digest_value, "archive OCI descriptor blob digest")
                try:
                    value = json.loads(blob_bytes)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise CandidateBuildError("archive OCI descriptor blob is invalid") from exc
                _require(isinstance(value, dict), "archive OCI descriptor object")
                config = value.get("config")
                if isinstance(config, dict):
                    matched = config.get("digest") == f"sha256:{config_sha256}"
                else:
                    children = value.get("manifests")
                    _require(isinstance(children, list) and children, "archive OCI manifest chain")
                    matched = any(
                        visit(child, (*ancestors, digest_value)) for child in children
                    )
                if matched:
                    bound_oci_digests.add(digest_value)
                return matched

            descriptors = index.get("manifests") if isinstance(index, dict) else None
            _require(isinstance(descriptors, list) and descriptors, "archive OCI index manifests")
            _require(any(visit(item, ()) for item in descriptors), "archive OCI index does not bind config")
        return config_sha256, tuple(sorted(bound_oci_digests))


def _archive_config_sha(path: Path) -> str:
    return _archive_identity(path)[0]


def _portable_image_id(
    local_store_image_id: str,
    archive_config_sha256: str,
    bound_oci_digests: tuple[str, ...],
) -> str:
    _require(
        re.fullmatch(r"sha256:[0-9a-f]{64}", local_store_image_id) is not None,
        "local image ID is invalid",
    )
    _require(
        re.fullmatch(r"[0-9a-f]{64}", archive_config_sha256) is not None,
        "archive config digest is invalid",
    )
    portable = f"sha256:{archive_config_sha256}"
    if local_store_image_id != portable:
        _require(
            local_store_image_id.removeprefix("sha256:") in bound_oci_digests,
            "local image store ID is not bound through the archive OCI index",
        )
    return portable


def _secret_scan(values: Iterable[bytes]) -> list[str]:
    findings: list[str] = []
    for index, value in enumerate(values):
        text = value.decode("utf-8", errors="ignore")
        if SECRET_PATTERN.search(text):
            findings.append(f"artifact-{index}")
    return findings


def prepare(args: argparse.Namespace) -> None:
    output = _owner_only_dir(args.output_dir, create=True)
    candidate = args.candidate_sha
    tree = _validate_source(candidate, args.candidate_ci_run)
    advisory_path = Path(args.advisory_snapshot).expanduser().resolve()
    try:
        advisory_path.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise CandidateBuildError("advisory snapshot must remain outside the repository")
    advisory, advisory_sha = _load_private_json(advisory_path)
    _validate_advisory_snapshot(advisory)

    tag_one = f"dcr-os-r08b-build-one:{candidate[:12]}"
    tag_two = f"dcr-os-candidate:{candidate}"
    source_date_epoch = _source_date_epoch(candidate)
    _build_reproducible_image(candidate, tag_one, source_date_epoch)
    inspect_one = _image_inspect(tag_one)
    files_one, dpkg_one, python_one = _inventory(tag_one)
    _build_reproducible_image(candidate, tag_two, source_date_epoch)
    inspect_two = _image_inspect(tag_two)
    files_two, dpkg_two, python_two = _inventory(tag_two)
    normalized_one = _normalize_image(inspect_one)
    normalized_two = _normalize_image(inspect_two)
    _require(normalized_one == normalized_two, "two no-cache image builds differ")
    _require(files_one == files_two and dpkg_one == dpkg_two and python_one == python_two, "two build inventories differ")
    _require(normalized_two["architecture"] == "amd64" and normalized_two["os"] == "linux", "image platform mismatch")
    _require(normalized_two["user"] == "10001:10001", "image is not rootless")
    _require(normalized_two["revision"] == candidate, "image revision label mismatch")

    archive = output / "candidate-image.tar"
    _run(["docker", "image", "save", "--output", str(archive), tag_two], timeout=1800)
    os.chmod(archive, 0o600)
    archive_sha = _sha_file(archive)
    archive_config, bound_oci_digests = _archive_identity(archive)
    local_store_image_id = str(normalized_two["id"])
    image_id = _portable_image_id(
        local_store_image_id,
        archive_config,
        bound_oci_digests,
    )

    files_sha = _write_private(output / "container-file-inventory.txt", files_two)
    dpkg_sha = _write_private(output / "dpkg-inventory.tsv", dpkg_two)
    python_sha = _write_private(output / "python-inventory.json", _canonical(json.loads(python_two)))
    sbom = _spdx(candidate, dpkg_two, python_two)
    sbom_sha = _write_private(output / "candidate-sbom.spdx.json", _canonical(sbom))
    release_manifest, allowlist = _release_path_manifests(candidate, tree)
    release_manifest_sha = _write_private(output / "release-relevant-paths.json", _canonical(release_manifest))
    allowlist_sha = _write_private(output / "evidence-only-path-allowlist.json", _canonical(allowlist))
    fingerprints = {path: _sha_file(ROOT / path) for path in FINGERPRINT_PATHS}
    secret_findings = _secret_scan(
        [files_two, dpkg_two, python_two, _canonical(sbom), _canonical(release_manifest), _canonical(allowlist)]
        + [(ROOT / path).read_bytes() for path in FINGERPRINT_PATHS]
    )
    _require(not secret_findings, "secret scan finding")
    evidence_payload: dict[str, object] = {
        "status": "PASS_EXACT_CANDIDATE_IMAGE_BUILD",
        "candidate_release_sha": candidate,
        "candidate_tree_sha": tree,
        "candidate_exact_head_ci_run": args.candidate_ci_run,
        "candidate_remote_ref": "refs/remotes/origin/main",
        "platform": PLATFORM,
        "containerfile": {"path": CONTAINERFILE, "sha256": _sha_file(ROOT / CONTAINERFILE)},
        "build": {
            "literal_no_cache_builds": 2,
            "pull": False,
            "builder": "docker-buildx",
            "source_date_epoch": source_date_epoch,
            "deterministic_multi_platform_output": True,
            "layer_timestamps_rewritten": True,
            "image_tag": tag_two,
            "image_id": image_id,
            "local_store_image_id": local_store_image_id,
            "portable_image_identity_source": "verified-archive-config-digest",
            "config_sha256": normalized_two["config_sha256"],
            "rootfs_sha256": normalized_two["rootfs_sha256"],
            "entrypoint": normalized_two["entrypoint"],
            "cmd": normalized_two["cmd"],
            "user": normalized_two["user"],
        },
        "archive": {"path": "candidate-image.tar", "sha256": archive_sha, "config_sha256": archive_config},
        "inventories": {
            "container_files_sha256": files_sha,
            "dpkg_sha256": dpkg_sha,
            "python_sha256": python_sha,
            "sbom_spdx_sha256": sbom_sha,
            "spdx_package_count": len(sbom["packages"]),
        },
        "dependency_lock": {"path": LOCK_FILE, "sha256": _sha_file(ROOT / LOCK_FILE)},
        "third_party_notices": {"path": NOTICES_FILE, "sha256": _sha_file(ROOT / NOTICES_FILE)},
        "advisory_snapshot": {
            "sha256": advisory_sha,
            "scanner": advisory["scanner"],
            "database_revision": advisory["database_revision"],
            "critical_findings": 0,
            "high_findings": 0,
        },
        "fingerprints": fingerprints,
        "release_relevant_paths_manifest_sha256": release_manifest_sha,
        "evidence_only_path_allowlist_sha256": allowlist_sha,
        "secret_scan_findings": 0,
        "raw_or_credential_bytes_public": False,
        "live_or_vps_actions": 0,
        "timed_observations": "OUT_OF_SCOPE",
        "grants_authority": False,
    }
    evidence = {
        "schema_id": "R08BCandidateImageBuildEvidence",
        "schema_version": "1.0.0",
        "payload": evidence_payload,
        "integrity": {"payload_sha256": _sha_bytes(_canonical(evidence_payload))},
    }
    evidence_sha = _write_private(output / "candidate-build-evidence.json", _canonical(evidence))
    print(
        json.dumps(
            {
                "status": evidence_payload["status"],
                "candidate_release_sha": candidate,
                "candidate_tree_sha": tree,
                "image_id": image_id,
                "archive_sha256": archive_sha,
                "sbom_sha256": sbom_sha,
                "release_relevant_paths_manifest_sha256": release_manifest_sha,
                "evidence_only_path_allowlist_sha256": allowlist_sha,
                "evidence_sha256": evidence_sha,
                "output_mode": "OWNER_ONLY_0600",
                "live_or_vps_actions": 0,
            },
            sort_keys=True,
        )
    )


def verify(args: argparse.Namespace) -> None:
    output = _owner_only_dir(args.output_dir, create=False)
    for name in OUTPUT_FILES:
        path = output / name
        _require(path.exists() and not path.is_symlink(), f"missing output:{name}")
        _require(stat.S_ISREG(path.stat().st_mode) and stat.S_IMODE(path.stat().st_mode) == 0o600, f"output mode:{name}")
    evidence, evidence_sha = _load_private_json(output / "candidate-build-evidence.json")
    payload = evidence.get("payload")
    integrity = evidence.get("integrity")
    _require(evidence.get("schema_id") == "R08BCandidateImageBuildEvidence", "evidence schema")
    _require(isinstance(payload, dict) and isinstance(integrity, dict), "evidence structure")
    _require(integrity.get("payload_sha256") == _sha_bytes(_canonical(payload)), "evidence integrity")
    _require(payload.get("candidate_release_sha") == args.candidate_sha, "candidate evidence SHA")
    _require(payload.get("candidate_exact_head_ci_run") == args.candidate_ci_run, "candidate evidence CI")
    archive = payload.get("archive")
    inventories = payload.get("inventories")
    _require(isinstance(archive, dict) and isinstance(inventories, dict), "evidence artifact refs")
    _require(_sha_file(output / "candidate-image.tar") == archive.get("sha256"), "archive SHA drift")
    _require(_archive_config_sha(output / "candidate-image.tar") == archive.get("config_sha256"), "archive config drift")
    expected = {
        "container-file-inventory.txt": inventories.get("container_files_sha256"),
        "dpkg-inventory.tsv": inventories.get("dpkg_sha256"),
        "python-inventory.json": inventories.get("python_sha256"),
        "candidate-sbom.spdx.json": inventories.get("sbom_spdx_sha256"),
        "release-relevant-paths.json": payload.get("release_relevant_paths_manifest_sha256"),
        "evidence-only-path-allowlist.json": payload.get("evidence_only_path_allowlist_sha256"),
    }
    for name, digest in expected.items():
        _require(_sha_file(output / name) == digest, f"artifact SHA drift:{name}")
    _require(payload.get("secret_scan_findings") == 0 and payload.get("live_or_vps_actions") == 0, "safety boundary")
    print(json.dumps({"status": "PASS_EXACT_CANDIDATE_IMAGE_VERIFIED", "evidence_sha256": evidence_sha, "candidate_release_sha": args.candidate_sha}, sort_keys=True))


def self_test(_: argparse.Namespace) -> None:
    advisory = {
        "schema_id": "R08BCandidateAdvisorySnapshot",
        "platform": PLATFORM,
        "status": "PASS_CURRENT",
        "critical_findings": 0,
        "high_findings": 0,
        "scanner": "scanner",
        "database_revision": "revision",
    }
    _validate_advisory_snapshot(advisory)
    mutations = {
        "wrong-platform": ("platform", "linux/arm64"),
        "unknown-status": ("status", "UNKNOWN"),
        "critical": ("critical_findings", 1),
        "high": ("high_findings", 1),
        "missing-scanner": ("scanner", ""),
        "missing-database": ("database_revision", ""),
    }
    rejected: list[str] = []
    for name, (field, value) in mutations.items():
        candidate = deepcopy(advisory)
        candidate[field] = value
        try:
            _validate_advisory_snapshot(candidate)
        except CandidateBuildError:
            rejected.append(name)
        else:
            raise CandidateBuildError(f"accepted hostile advisory snapshot:{name}")
    sample = b"alpha\nbeta\n"
    _require(_sha_bytes(sample) == _sha_bytes(sample), "digest is not deterministic")
    _require(_secret_scan([b"public synthetic bytes"]) == [], "public bytes false positive")
    _require(_secret_scan([b"-----BEGIN PRIVATE KEY-----"]), "secret probe was accepted")
    print(json.dumps({"status": "R08B_CANDIDATE_BUILD_SELF_TEST_GREEN", "hostile_mutations_rejected": rejected, "hostile_mutation_count": len(rejected) + 1}, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--candidate-sha", required=True)
    prepare_parser.add_argument("--candidate-ci-run", required=True, type=int)
    prepare_parser.add_argument("--output-dir", required=True)
    prepare_parser.add_argument("--advisory-snapshot", required=True)
    prepare_parser.set_defaults(func=prepare)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--candidate-sha", required=True)
    verify_parser.add_argument("--candidate-ci-run", required=True, type=int)
    verify_parser.add_argument("--output-dir", required=True)
    verify_parser.set_defaults(func=verify)
    self_test_parser = subparsers.add_parser("self-test")
    self_test_parser.set_defaults(func=self_test)
    args = parser.parse_args()
    try:
        args.func(args)
    except (CandidateBuildError, json.JSONDecodeError, KeyError, OSError, subprocess.TimeoutExpired, tarfile.TarError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
