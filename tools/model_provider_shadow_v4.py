#!/usr/bin/env python3
"""Bounded connected-provider shadow runner for D0/sanitized D1 only.

This Agent-0 tool is intentionally outside the Bridge runtime import graph. It
uses the existing deterministic router, durable model-call broker, ledger and
CAS. Credentials are read only from the frozen environment-variable names and
are never serialized or printed. There is no retry path.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
from typing import Callable, Mapping
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.cas import ContentAddressedStore  # noqa: E402
from research_bridge.ledger import JobLedger  # noqa: E402
from research_bridge.model_broker import (  # noqa: E402
    KnownProviderFailure,
    ModelBudgetPolicy,
    ModelCallBroker,
    ModelCallSpec,
    ModelProviderRouting,
    ModelRoleRegistry,
    ProviderAccounting,
)


LEGACY_PROFILE_PATH = ROOT / "provenance" / "model-provider-connected-shadow-v1.json"
PROFILE_PATH = ROOT / "provenance" / "model-provider-connected-shadow-v2.json"
PROFILE_V2_PATH = PROFILE_PATH
CURRENT_PROFILE_PATH = ROOT / "provenance" / "model-provider-connected-shadow-v3.json"
ADVISOR_PROFILE_PATH = ROOT / "provenance" / "model-provider-connected-shadow-v4.json"
ROUTING_PATH = ROOT / "provenance" / "model-provider-routing-v1.json"
ADVISOR_ROUTING_PATH = ROOT / "provenance" / "model-provider-routing-v2.json"
ROLE_PATH = ROOT / "contracts" / "a1" / "v1" / "profiles" / "model_role_registry_v1.json"
_PROFILE_KEYS = {
    "profile_id", "schema_version", "status", "allowed_input_classes",
    "forbidden_input_classes", "max_request_bytes", "max_response_bytes",
    "timeout_seconds", "bindings", "invariants",
}
_LEGACY_BINDING_KEYS = {
    "provider_slot", "credential_env", "endpoint", "protocol", "api_model",
    "request_options", "source",
}
_BINDING_KEYS = _LEGACY_BINDING_KEYS | {"provider", "context_window"}
_ALLOWED_ENDPOINTS = {
    "https://api.deepseek.com/chat/completions",
    "https://open.bigmodel.cn/api/paas/v4/chat/completions",
    "https://api.openai.com/v1/responses",
    "https://openrouter.ai/api/v1/chat/completions",
    "https://api.moonshot.ai/v1/chat/completions",
}
_ALLOWED_PROTOCOLS = {"OPENAI_CHAT_COMPLETIONS", "OPENAI_RESPONSES"}
_EXPECTED_LEGACY_BINDING_SHAPES = {
    "deepseek-v4-flash": {
        "provider_slot": "DEEPSEEK_API", "credential_env": "DEEPSEEK_API_KEY",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "protocol": "OPENAI_CHAT_COMPLETIONS", "api_model": "deepseek-v4-flash",
        "request_options": {"thinking": {"type": "disabled"}, "reasoning_effort": "high"},
        "source": "https://api-docs.deepseek.com/api/create-chat-completion",
    },
    "deepseek-v4-pro": {
        "provider_slot": "DEEPSEEK_API", "credential_env": "DEEPSEEK_API_KEY",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "protocol": "OPENAI_CHAT_COMPLETIONS", "api_model": "deepseek-v4-pro",
        "request_options": {"thinking": {"type": "enabled"}, "reasoning_effort": "high"},
        "source": "https://api-docs.deepseek.com/api/create-chat-completion",
    },
    "glm-5.2-max": {
        "provider_slot": "GLM_API", "credential_env": "ZHIPU_API_KEY",
        "endpoint": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "protocol": "OPENAI_CHAT_COMPLETIONS", "api_model": "glm-5.2",
        "request_options": {"thinking": {"type": "enabled"}, "reasoning_effort": "max"},
        "source": "https://docs.bigmodel.cn/cn/guide/models/text/glm-5.2",
    },
    "gpt-5.6-sol-xhigh": {
        "provider_slot": "OPENAI_API", "credential_env": "OPENAI_API_KEY",
        "endpoint": "https://api.openai.com/v1/responses",
        "protocol": "OPENAI_RESPONSES", "api_model": "gpt-5.6-sol",
        "request_options": {"reasoning": {"effort": "xhigh"}, "store": False},
        "source": "https://developers.openai.com/api/docs/models/gpt-5.6-sol",
    },
    "gpt-5.6-sol-max": {
        "provider_slot": "OPENAI_API", "credential_env": "OPENAI_API_KEY",
        "endpoint": "https://api.openai.com/v1/responses",
        "protocol": "OPENAI_RESPONSES", "api_model": "gpt-5.6-sol",
        "request_options": {"reasoning": {"effort": "max"}, "store": False},
        "source": "https://developers.openai.com/api/docs/models/gpt-5.6-sol",
    },
}
_EXPECTED_BINDING_SHAPES = {
    "deepseek-v4-flash": {
        "provider": "deepseek", "provider_slot": "DEEPSEEK_API",
        "credential_env": "DEEPSEEK_API_KEY",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "protocol": "OPENAI_CHAT_COMPLETIONS", "api_model": "deepseek-v4-flash",
        "context_window": None,
        "request_options": {"thinking": {"type": "disabled"}, "reasoning_effort": "high"},
        "source": "https://api-docs.deepseek.com/api/create-chat-completion",
    },
    "deepseek-v4-pro": {
        "provider": "deepseek", "provider_slot": "DEEPSEEK_API",
        "credential_env": "DEEPSEEK_API_KEY",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "protocol": "OPENAI_CHAT_COMPLETIONS", "api_model": "deepseek-v4-pro",
        "context_window": None,
        "request_options": {"thinking": {"type": "disabled"}, "reasoning_effort": "high"},
        "source": "https://api-docs.deepseek.com/api/create-chat-completion",
    },
    "glm-5.2-max": {
        "provider": "zhipu", "provider_slot": "GLM_API",
        "credential_env": "ZHIPU_API_KEY",
        "endpoint": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "protocol": "OPENAI_CHAT_COMPLETIONS", "api_model": "glm-5.2",
        "context_window": None,
        "request_options": {"thinking": {"type": "enabled"}, "reasoning_effort": "max"},
        "source": "https://docs.bigmodel.cn/cn/guide/models/text/glm-5.2",
    },
    "gpt-5.6-sol-xhigh": {
        "provider": "openrouter", "provider_slot": "OPENROUTER_API",
        "credential_env": "OPENROUTER_API_KEY",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "protocol": "OPENAI_CHAT_COMPLETIONS", "api_model": "openai/gpt-5.6-sol",
        "context_window": 1_000_000,
        "request_options": {"reasoning": {"effort": "low"}},
        "source": "https://openrouter.ai/openai/gpt-5.6-sol/",
    },
    "gpt-5.6-sol-max": {
        "provider": "openai", "provider_slot": "OPENAI_API",
        "credential_env": "OPENAI_API_KEY",
        "endpoint": "https://api.openai.com/v1/responses",
        "protocol": "OPENAI_RESPONSES", "api_model": "gpt-5.6-sol",
        "context_window": None,
        "request_options": {"reasoning": {"effort": "max"}, "store": False},
        "source": "https://developers.openai.com/api/docs/models/gpt-5.6-sol",
    },
}
_EXPECTED_BINDING_SHAPES_V2 = copy.deepcopy(_EXPECTED_BINDING_SHAPES)
_EXPECTED_BINDING_SHAPES_V2["deepseek-v4-pro"]["request_options"]["thinking"]["type"] = "enabled"
_EXPECTED_BINDING_SHAPES_V2["gpt-5.6-sol-xhigh"]["request_options"]["reasoning"]["effort"] = "xhigh"
_EXPECTED_BINDING_SHAPES_V4 = copy.deepcopy(_EXPECTED_BINDING_SHAPES)
_EXPECTED_BINDING_SHAPES_V4["gpt-5.6-sol-xhigh"]["request_options"]["reasoning"]["effort"] = "xhigh"
_EXPECTED_BINDING_SHAPES_V4.pop("gpt-5.6-sol-max")
_EXPECTED_BINDING_SHAPES_V4["kimi-k3-max"] = {
    "provider": "moonshot", "provider_slot": "MOONSHOT_API",
    "credential_env": "MOONSHOT_API_KEY",
    "endpoint": "https://api.moonshot.ai/v1/chat/completions",
    "protocol": "OPENAI_CHAT_COMPLETIONS", "api_model": "kimi-k3",
    "context_window": 1_048_576,
    "request_options": {"reasoning_effort": "max"},
    "source": "https://api.moonshot.ai/v1/models/kimi-k3",
}

_OPENROUTER_CREDENTIAL_ENV = "OPENROUTER_API_KEY"
_OPENROUTER_KEYCHAIN_SERVICE = "ai.shared.openrouter"
_OPENROUTER_KEYCHAIN_ACCOUNT = "OPENROUTER_API_KEY"
_KEYCHAIN_COMMAND = (
    "/usr/bin/security", "find-generic-password",
    "-s", _OPENROUTER_KEYCHAIN_SERVICE,
    "-a", _OPENROUTER_KEYCHAIN_ACCOUNT,
    "-w",
)


class ShadowProviderError(RuntimeError):
    pass


def _valid_credential(value: str) -> bool:
    return bool(value) and len(value) <= 16_384 and not any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in value
    )


class CredentialResolver:
    """Resolve credentials without ever serializing values or error details."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = os.environ if environment is None else environment
        self._cache: dict[str, str] = {}

    def resolve(self, credential_env: str) -> str:
        if credential_env in self._cache:
            return self._cache[credential_env]
        environment_value = self._environment.get(credential_env)
        if environment_value is not None:
            value = environment_value if _valid_credential(environment_value) else ""
            self._cache[credential_env] = value
            return value
        value = ""
        if credential_env == _OPENROUTER_CREDENTIAL_ENV and sys.platform == "darwin":
            try:
                result = subprocess.run(
                    list(_KEYCHAIN_COMMAND),
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise ShadowProviderError("provider credential lookup failed closed") from None
            candidate = result.stdout.rstrip("\r\n") if result.returncode == 0 else ""
            value = candidate if _valid_credential(candidate) else ""
        self._cache[credential_env] = value
        return value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, object]:
    """Decode one provider object without duplicate keys or non-finite numbers."""

    def reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ShadowProviderError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise ShadowProviderError(f"{label} contains a non-finite number")

    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ShadowProviderError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ShadowProviderError(f"{label} must be a JSON object")
    return value


def _load_json_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ShadowProviderError("provider shadow profile is unreadable") from exc
    if not isinstance(value, dict):
        raise ShadowProviderError("provider shadow profile must be an object")
    return value


class ConnectedShadowProfile:
    def __init__(self, path: Path = PROFILE_PATH) -> None:
        value = _load_json_object(path)
        if set(value) != _PROFILE_KEYS:
            raise ShadowProviderError("provider shadow profile keys drifted")
        profile_id = value["profile_id"]
        if profile_id not in {
            "model-provider-connected-shadow-v1",
            "model-provider-connected-shadow-v2",
            "model-provider-connected-shadow-v3",
            "model-provider-connected-shadow-v4",
        }:
            raise ShadowProviderError("provider shadow profile id drifted")
        if value["allowed_input_classes"] != ["D0", "D1"]:
            raise ShadowProviderError("provider shadow privacy scope widened")
        if value["forbidden_input_classes"] != ["D2", "D3", "sealed-holdout"]:
            raise ShadowProviderError("provider shadow forbidden scope drifted")
        for name in ("max_request_bytes", "max_response_bytes", "timeout_seconds"):
            if type(value[name]) is not int or not 1 <= value[name] <= 16_777_216:
                raise ShadowProviderError(f"provider shadow {name} is invalid")
        binding_keys = (
            _LEGACY_BINDING_KEYS
            if profile_id == "model-provider-connected-shadow-v1"
            else _BINDING_KEYS
        )
        expected_shapes = (
            _EXPECTED_LEGACY_BINDING_SHAPES
            if profile_id == "model-provider-connected-shadow-v1"
            else _EXPECTED_BINDING_SHAPES_V2
            if profile_id == "model-provider-connected-shadow-v2"
            else _EXPECTED_BINDING_SHAPES_V4
            if profile_id == "model-provider-connected-shadow-v4"
            else _EXPECTED_BINDING_SHAPES
        )
        bindings = value["bindings"]
        expected_binding_names = {
            "deepseek-v4-flash", "deepseek-v4-pro", "glm-5.2-max",
            "gpt-5.6-sol-xhigh", "gpt-5.6-sol-max",
        }
        if profile_id == "model-provider-connected-shadow-v4":
            expected_binding_names.remove("gpt-5.6-sol-max")
            expected_binding_names.add("kimi-k3-max")
        if not isinstance(bindings, dict) or set(bindings) != expected_binding_names:
            raise ShadowProviderError("provider shadow binding set drifted")
        normalized: dict[str, dict[str, object]] = {}
        for name, item in bindings.items():
            if not isinstance(item, dict) or set(item) != binding_keys:
                raise ShadowProviderError("provider shadow binding shape drifted")
            if item["endpoint"] not in _ALLOWED_ENDPOINTS:
                raise ShadowProviderError("provider shadow endpoint is not allowlisted")
            if item["protocol"] not in _ALLOWED_PROTOCOLS:
                raise ShadowProviderError("provider shadow protocol is not allowlisted")
            if item != expected_shapes[name]:
                raise ShadowProviderError("provider shadow binding semantics drifted")
            credential = item["credential_env"]
            if not isinstance(credential, str) or not credential.endswith("_API_KEY"):
                raise ShadowProviderError("provider credential environment name is invalid")
            normalized[name] = copy.deepcopy(item)
        invariants = value["invariants"]
        required_true = {
            "caller_cannot_select_binding", "credential_value_never_enters_request_ledger_or_output",
            "raw_response_is_private_CAS_only", "real_call_requires_existing_pre_authorized_provider_balance",
        }
        if not isinstance(invariants, dict) or any(invariants.get(key) is not True for key in required_true):
            raise ShadowProviderError("provider shadow invariant drifted")
        if invariants.get("automatic_retry") is not False:
            raise ShadowProviderError("provider shadow cannot retry automatically")
        if profile_id in {
            "model-provider-connected-shadow-v2",
            "model-provider-connected-shadow-v3",
            "model-provider-connected-shadow-v4",
        } and (
            invariants.get("openrouter_credential_precedence")
            != "environment_then_macos_keychain"
            or invariants.get("openrouter_gateway_is_not_model_independence_evidence") is not True
            or invariants.get("actual_upstream_provider_is_not_attested_by_requested_model_slug") is not True
        ):
            raise ShadowProviderError("OpenRouter safety invariant drifted")
        self.path = path
        self.profile_id = str(profile_id)
        self.sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        self.max_request_bytes = int(value["max_request_bytes"])
        self.max_response_bytes = int(value["max_response_bytes"])
        self.timeout_seconds = int(value["timeout_seconds"])
        self.bindings = normalized

    def binding(self, name: str) -> dict[str, object]:
        try:
            return copy.deepcopy(self.bindings[name])
        except KeyError as exc:
            raise ShadowProviderError("provider shadow binding is unknown") from exc

    def available_bindings(self, environment: Mapping[str, str]) -> frozenset[str]:
        return frozenset(
            name for name, item in self.bindings.items()
            if bool(environment.get(str(item["credential_env"]), "").strip())
        )

    def resolved_available_bindings(self, resolver: CredentialResolver) -> frozenset[str]:
        return frozenset(
            name for name, item in self.bindings.items()
            if bool(resolver.resolve(str(item["credential_env"])))
        )


def build_request_bytes(binding: Mapping[str, object], prompt: bytes, max_tokens: int) -> bytes:
    if not isinstance(prompt, bytes) or not prompt or len(prompt) > 32_768:
        raise ShadowProviderError("shadow prompt must be 1..32768 bytes")
    try:
        text = prompt.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ShadowProviderError("shadow prompt must be UTF-8") from exc
    if type(max_tokens) is not int or not 1 <= max_tokens <= 16_384:
        raise ShadowProviderError("shadow max_tokens must be 1..16384")
    options = copy.deepcopy(binding["request_options"])
    if not isinstance(options, dict):
        raise ShadowProviderError("provider request options are invalid")
    protocol = binding["protocol"]
    if protocol == "OPENAI_CHAT_COMPLETIONS":
        payload = {
            "model": binding["api_model"], "messages": [{"role": "user", "content": text}],
            "max_tokens": max_tokens, "stream": False, **options,
        }
    elif protocol == "OPENAI_RESPONSES":
        payload = {
            "model": binding["api_model"], "input": text,
            "max_output_tokens": max_tokens, **options,
        }
    else:
        raise ShadowProviderError("provider request protocol is unsupported")
    return _canonical_bytes(payload)


Transport = Callable[[str, str, bytes, int, int], tuple[int, Mapping[str, str], bytes]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _http_post(endpoint: str, api_key: str, body: bytes, timeout: int, maximum: int) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json", "Accept": "application/json"},
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect()
    )
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise ShadowProviderError("provider Content-Length is invalid") from exc
            if declared_length < 0 or declared_length > maximum:
                raise ShadowProviderError("provider response exceeds declared bound")
        body_bytes = response.read(maximum + 1)
        if len(body_bytes) > maximum:
            raise ShadowProviderError("provider response exceeds streaming bound")
        selected_headers = {
            key.lower(): value for key, value in response.headers.items()
            if key.lower() in {"x-request-id", "request-id", "openai-request-id"}
        }
        return int(response.status), selected_headers, body_bytes


class HTTPRawAdapter:
    def __init__(self, model_binding: str, binding: Mapping[str, object], api_key: str, *, timeout: int, maximum: int, transport: Transport = _http_post) -> None:
        if not api_key or any(character.isspace() for character in api_key):
            raise ShadowProviderError("provider credential is absent or malformed")
        self.model_binding = model_binding
        self._binding = dict(binding)
        self._api_key = api_key
        self._timeout = timeout
        self._maximum = maximum
        self._transport = transport

    def invoke_raw(self, *, call_id: str, request_bytes: bytes, max_tokens: int) -> bytes:
        status, headers, body = self._transport(
            str(self._binding["endpoint"]), self._api_key, request_bytes,
            self._timeout, self._maximum,
        )
        if type(status) is not int or not 100 <= status <= 599 or not isinstance(body, bytes) or not body:
            raise ShadowProviderError("provider transport returned an invalid envelope")
        if len(body) > self._maximum:
            raise ShadowProviderError("provider response exceeds adapter bound")
        if not isinstance(headers, Mapping) or len(headers) > 3 or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or len(key) > 64
            or len(value) > 512
            for key, value in headers.items()
        ):
            raise ShadowProviderError("provider response headers are invalid")
        return _canonical_bytes({
            "binding": self.model_binding, "protocol": self._binding["protocol"],
            "http_status": status, "headers": dict(headers),
            "body_base64": base64.b64encode(body).decode("ascii"),
        })


class HTTPResponseParser:
    def __init__(self, model_binding: str, protocol: str) -> None:
        self.model_binding = model_binding
        self._protocol = protocol

    def parse_response(self, *, raw_response: bytes, response_ref: str, max_tokens: int) -> ProviderAccounting:
        try:
            envelope = _strict_json_object(
                raw_response, label="provider response envelope"
            )
            if set(envelope) != {"binding", "protocol", "http_status", "headers", "body_base64"}:
                raise ValueError
            if envelope["binding"] != self.model_binding or envelope["protocol"] != self._protocol:
                raise ValueError
            if not isinstance(envelope["body_base64"], str):
                raise ValueError
            body = base64.b64decode(envelope["body_base64"], validate=True)
            value = _strict_json_object(body, label="provider response body")
        except (ValueError, TypeError, KeyError) as exc:
            raise ShadowProviderError("provider response envelope is malformed") from exc
        receipt_ref = "provider-response:sha256:" + hashlib.sha256(body).hexdigest()
        status = envelope["http_status"]
        if type(status) is not int:
            raise ShadowProviderError("provider HTTP status is invalid")
        if status < 200 or status >= 300:
            raise KnownProviderFailure("HTTP_" + str(status), provider_receipt_ref=receipt_ref)
        response_id = value.get("id")
        if not isinstance(response_id, str) or not response_id or len(response_id) > 512:
            raise ShadowProviderError("provider success response identity is invalid")
        usage = value.get("usage")
        if (
            not isinstance(usage, dict)
            or type(usage.get("total_tokens")) is not int
            or not 0 <= usage["total_tokens"] <= 1_000_000_000
        ):
            raise ShadowProviderError("provider success usage is invalid")
        if self._protocol == "OPENAI_CHAT_COMPLETIONS":
            choices = value.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                raise ShadowProviderError("chat completion output is invalid")
        elif self._protocol == "OPENAI_RESPONSES":
            if not isinstance(value.get("output"), list) or not value["output"]:
                raise ShadowProviderError("Responses API output is invalid")
        return ProviderAccounting(usage["total_tokens"], None, receipt_ref)


class CASCommitter:
    def __init__(self, root: Path, *, quota_bytes: int) -> None:
        self._root = root
        self._store = ContentAddressedStore(root, quota_bytes=quota_bytes)

    def commit_response(self, raw_response: bytes) -> str:
        digest = hashlib.sha256(raw_response).hexdigest()
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=self._root, prefix=".provider-response-", delete=False) as handle:
                handle.write(raw_response)
                handle.flush()
                os.fsync(handle.fileno())
                temporary = Path(handle.name)
            return self._store.publish(
                temporary, expected_sha256=digest, expected_size_bytes=len(raw_response)
            ).ref
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def _outside_repository(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    raise ShadowProviderError("private runtime storage must be outside the public repository")


def _stage_tag(profile: ConnectedShadowProfile) -> str:
    if profile.profile_id == "model-provider-connected-shadow-v1":
        return "s17"
    if profile.profile_id == "model-provider-connected-shadow-v4":
        return "kmax-kimi-k3-max-routing"
    return "s24-r2-openrouter"


def _preflight(profile: ConnectedShadowProfile) -> int:
    available = profile.resolved_available_bindings(CredentialResolver())
    bindings = {
        name: ("CONFIGURED_UNPROVEN" if name in available else "WAIT_CREDENTIAL")
        for name in sorted(profile.bindings)
    }
    print(json.dumps({"profile_sha256": profile.sha256, "bindings": bindings, "secrets_printed": False}, sort_keys=True))
    return 0


def _init_ledger(args: argparse.Namespace, profile: ConnectedShadowProfile) -> int:
    """Create a new private fixture-only A1 ledger for connected shadow proof."""

    ledger_path = _outside_repository(Path(args.ledger))
    if ledger_path.exists():
        raise ShadowProviderError("shadow ledger bootstrap requires a new path")
    ledger_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    stage_tag = _stage_tag(profile)
    payload = {
        "capability": stage_tag.upper().replace("-", "_") + "_CONNECTED_SHADOW_LEDGER_BOOTSTRAP",
        "fixture_only": True,
        "grants_authority": False,
        "profile_sha256": profile.sha256,
        "scope": "LOCAL_PRIVATE_D0_SHADOW_ONLY",
        "shadow_status": "SHADOW_UNAPPLIED",
    }
    payload_sha256 = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    document = {
        "schema_id": "CapabilityProofReceipt",
        "schema_version": "1.0.0",
        "object_id": "capability-proof:" + stage_tag + "-shadow-bootstrap:" + profile.sha256,
        "issued_at": args.event_at,
        "issuer": {
            "id": "agent-0-" + stage_tag + "-shadow-bootstrap",
            "authority_class": "fixture-only-non-authoritative",
        },
        "contour": "governance",
        "classification": "D0",
        "payload": payload,
        "integrity": {
            "profile_id": "core-json-sha256-v1",
            "payload_sha256": payload_sha256,
            "parent_refs": ["profile:sha256:" + profile.sha256],
        },
    }
    projections = {
        name: {
            "count": 1 if name == "capabilities" else 0,
            "fixture_only": True,
            "grants_authority": False,
            "marker": stage_tag + "-connected-shadow-bootstrap-v1",
            "shadow_only": True,
        }
        for name in ("admissions", "candidates", "capabilities", "material_events")
    }
    try:
        with JobLedger(ledger_path) as ledger:
            record = ledger.append_a1_bundle(
                objects=[document],
                projections=projections,
                idempotency_key=stage_tag + "-shadow-bootstrap:" + profile.sha256,
                event_at=args.event_at,
            )
            if not ledger.verify_chain() or not ledger.verify_a1_coverage():
                raise ShadowProviderError("shadow ledger bootstrap verification failed")
    except Exception:
        ledger_path.unlink(missing_ok=True)
        raise
    os.chmod(ledger_path, 0o600)
    print(
        json.dumps(
            {
                "status": "INITIALIZED_PRIVATE_FIXTURE_LEDGER",
                "event_sequence": record.event.sequence,
                "object_ids": list(record.object_ids),
                "profile_sha256": profile.sha256,
                "classification": "D0",
                "fixture_only": True,
                "grants_authority": False,
                "trusted_material_events": 0,
                "network_calls": 0,
                "credential_access": False,
                "secrets_printed": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _run(args: argparse.Namespace, profile: ConnectedShadowProfile) -> int:
    prompt_path = Path(args.prompt_file)
    if prompt_path.is_symlink() or not prompt_path.is_file():
        raise ShadowProviderError("prompt file must be a regular non-symlink file")
    credential_resolver = CredentialResolver()
    available = profile.resolved_available_bindings(credential_resolver)
    role_sha = hashlib.sha256(ROLE_PATH.read_bytes()).hexdigest()
    routing_path = (
        ADVISOR_ROUTING_PATH
        if profile.profile_id == "model-provider-connected-shadow-v4"
        else ROUTING_PATH
    )
    routing_sha = hashlib.sha256(routing_path.read_bytes()).hexdigest()
    stage_tag = _stage_tag(profile)
    base_registry = ModelRoleRegistry(ROLE_PATH, expected_profile_sha256=role_sha, binding_revision=stage_tag + "-connected-" + profile.sha256[:16])
    router = ModelProviderRouting(
        routing_path,
        expected_profile_sha256=routing_sha,
        role_registry=base_registry,
    )
    decision = router.route(args.role, args.classification, available_bindings=available)
    if decision.status != "ROUTED" or decision.binding is None:
        print(json.dumps({"role": args.role, "status": decision.status, "secrets_printed": False}, sort_keys=True))
        return 20
    binding = profile.binding(decision.binding)
    request_bytes = build_request_bytes(binding, prompt_path.read_bytes(), args.max_tokens)
    if len(request_bytes) > profile.max_request_bytes:
        raise ShadowProviderError("provider request exceeds frozen bound")
    registry = ModelRoleRegistry(
        ROLE_PATH, expected_profile_sha256=role_sha,
        binding_revision=stage_tag + "-connected-" + profile.sha256[:16],
        binding_overrides={args.role: decision.binding},
    )
    ledger_path = _outside_repository(Path(args.ledger))
    cas_root = _outside_repository(Path(args.cas_root))
    policy_digest = hashlib.sha256((profile.sha256 + ":policy").encode()).hexdigest()
    scope_digest = hashlib.sha256(str(cas_root).encode()).hexdigest()
    credential = credential_resolver.resolve(str(binding["credential_env"]))
    with JobLedger(ledger_path) as ledger:
        broker = ModelCallBroker(
            registry=registry, ledger=ledger,
            budget_policy=ModelBudgetPolicy(
                "budget-policy:sha256:" + policy_digest,
                "budget-scope:sha256:" + scope_digest,
                1, args.max_tokens, args.max_cost_units,
            ),
        )
        spec = ModelCallSpec(
            role=args.role,
            role_assignment_ref="role-assignment:" + stage_tag + "-shadow:" + profile.sha256,
            classification=args.classification,
            request_bytes=request_bytes,
            max_tokens=args.max_tokens,
            max_cost_units=args.max_cost_units,
            expires_at=args.expires_at,
            idempotency_key=args.idempotency_key,
        )
        prepared = broker.prepare(spec, event_at=args.event_at)
        completed = broker.execute_raw(
            prepared.call_id, request_bytes=request_bytes,
            adapter=HTTPRawAdapter(
                decision.binding, binding, credential,
                timeout=profile.timeout_seconds,
                maximum=profile.max_response_bytes,
            ),
            response_committer=CASCommitter(cas_root, quota_bytes=args.cas_quota_bytes),
            response_parser=HTTPResponseParser(decision.binding, str(binding["protocol"])),
            event_at=args.event_at,
        )
        snapshot = ledger.model_call_state(completed.call_id).snapshot
    print(json.dumps({
        "call_id": completed.call_id, "state": completed.state,
        "binding": decision.binding, "used_fallback": decision.used_fallback,
        "provider_gateway": binding.get("provider", "legacy-unrecorded"),
        "requested_model": binding["api_model"],
        "actual_upstream_provider_status": "NOT_ATTESTED",
        "response_ref": snapshot["response_ref"], "actual_tokens": snapshot["actual_tokens"],
        "actual_cost_units": snapshot["actual_cost_units"],
        "requires_cost_reconciliation": snapshot["actual_cost_units"] is None,
        "auto_retry": snapshot["auto_retry"], "secrets_printed": False,
    }, sort_keys=True))
    return 0 if completed.state == "SUCCEEDED" else 30


def _reconcile(args: argparse.Namespace, profile: ConnectedShadowProfile) -> int:
    """Apply exact operator/provider billing evidence to one terminal call.

    This path performs no network or credential access. It only closes an
    existing reservation after the caller supplies exact provider-side usage
    and a portable billing receipt reference. Exact replay is idempotent;
    conflicting replay fails closed in the existing broker.
    """

    ledger_path = _outside_repository(Path(args.ledger))
    role_sha = hashlib.sha256(ROLE_PATH.read_bytes()).hexdigest()
    registry = ModelRoleRegistry(
        ROLE_PATH,
        expected_profile_sha256=role_sha,
        binding_revision=_stage_tag(profile) + "-connected-" + profile.sha256[:16],
    )
    policy_digest = hashlib.sha256((profile.sha256 + ":reconcile-policy").encode()).hexdigest()
    scope_digest = hashlib.sha256(str(ledger_path).encode()).hexdigest()
    with JobLedger(ledger_path) as ledger:
        broker = ModelCallBroker(
            registry=registry,
            ledger=ledger,
            budget_policy=ModelBudgetPolicy(
                "budget-policy:sha256:" + policy_digest,
                "budget-scope:sha256:" + scope_digest,
                1,
                max(1, args.actual_tokens),
                max(1, args.actual_cost_units),
            ),
        )
        completed = broker.reconcile(
            args.call_id,
            actual_tokens=args.actual_tokens,
            actual_cost_units=args.actual_cost_units,
            provider_receipt_ref=args.provider_receipt_ref,
            event_at=args.event_at,
            idempotency_key=args.idempotency_key,
        )
        snapshot = ledger.model_call_state(completed.call_id).snapshot
    print(
        json.dumps(
            {
                "call_id": completed.call_id,
                "state": completed.state,
                "actual_tokens": snapshot["actual_tokens"],
                "actual_cost_units": snapshot["actual_cost_units"],
                "provider_receipt_ref": snapshot["provider_receipt_ref"],
                "ambiguous_usage": snapshot["ambiguous_usage"],
                "budget_released": snapshot["budget_released"],
                "network_calls": 0,
                "credential_access": False,
                "secrets_printed": False,
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("v2", "v3", "v4"), default="v2")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight")
    init_ledger = subparsers.add_parser("init-ledger")
    init_ledger.add_argument("--ledger", required=True)
    init_ledger.add_argument("--event-at", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--role", required=True, choices=("SCOUT_FAST", "RESEARCH_WORKER", "CRITIC_PRIMARY", "CRITIC_DEEP", "CHIEF_SCIENTIST"))
    run.add_argument("--classification", required=True, choices=("D0", "D1"))
    run.add_argument("--prompt-file", required=True)
    run.add_argument("--ledger", required=True)
    run.add_argument("--cas-root", required=True)
    run.add_argument("--event-at", required=True)
    run.add_argument("--expires-at", required=True)
    run.add_argument("--idempotency-key", required=True)
    run.add_argument("--max-tokens", type=int, default=64)
    run.add_argument("--max-cost-units", type=int, default=1)
    run.add_argument("--cas-quota-bytes", type=int, default=16_777_216)
    reconcile = subparsers.add_parser("reconcile")
    reconcile.add_argument("--ledger", required=True)
    reconcile.add_argument("--call-id", required=True)
    reconcile.add_argument("--actual-tokens", type=int, required=True)
    reconcile.add_argument("--actual-cost-units", type=int, required=True)
    reconcile.add_argument("--provider-receipt-ref", required=True)
    reconcile.add_argument("--event-at", required=True)
    reconcile.add_argument("--idempotency-key", required=True)
    args = parser.parse_args(argv)
    try:
        profile = ConnectedShadowProfile(
            {
                "v2": PROFILE_PATH,
                "v3": CURRENT_PROFILE_PATH,
                "v4": ADVISOR_PROFILE_PATH,
            }[args.profile]
        )
        if args.command == "preflight":
            return _preflight(profile)
        if args.command == "init-ledger":
            return _init_ledger(args, profile)
        if args.command == "reconcile":
            return _reconcile(args, profile)
        return _run(args, profile)
    except Exception as exc:
        print(json.dumps({"status": "FAILED_CLOSED", "error_type": type(exc).__name__, "secrets_printed": False}, sort_keys=True), file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
