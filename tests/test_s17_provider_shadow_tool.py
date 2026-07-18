from __future__ import annotations

import base64
from contextlib import redirect_stdout
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import model_provider_shadow as shadow  # noqa: E402
from research_bridge.model_broker import (  # noqa: E402
    KnownProviderFailure,
    ModelCallBroker,
    ProviderAccounting,
)
from tests.test_s15_model_registry_broker import (  # noqa: E402
    AT,
    AT_SENT,
    policy,
    registry,
    seeded_ledger,
    spec,
)


def envelope(binding: str, protocol: str, status: int, body: dict) -> bytes:
    return json.dumps(
        {
            "binding": binding,
            "protocol": protocol,
            "http_status": status,
            "headers": {"x-request-id": "synthetic-request"},
            "body_base64": base64.b64encode(
                json.dumps(body, separators=(",", ":")).encode()
            ).decode(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


class ProviderShadowToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.temp_path = Path(self.temporary.name)
        self.profile = shadow.ConnectedShadowProfile()

    def test_profile_is_strict_and_exact_official_api_ids_are_separate_from_logical_bindings(self) -> None:
        self.assertEqual(
            self.profile.sha256,
            "4ac18aaa960d78ee0103cd199f411067aca46fceb11efa8e0045c53f57c5affd",
        )
        self.assertEqual(
            self.profile.binding("glm-5.2-max")["api_model"], "glm-5.2"
        )
        self.assertEqual(
            self.profile.binding("gpt-5.6-sol-xhigh")["api_model"],
            "gpt-5.6-sol",
        )
        self.assertEqual(
            self.profile.binding("gpt-5.6-sol-max")["request_options"],
            {"reasoning": {"effort": "max"}, "store": False},
        )
        value = json.loads(shadow.PROFILE_PATH.read_text())
        value["bindings"]["glm-5.2-max"]["endpoint"] = "https://attacker.invalid"
        mutated = self.temp_path / "profile.json"
        mutated.write_text(json.dumps(value))
        with self.assertRaises(shadow.ShadowProviderError):
            shadow.ConnectedShadowProfile(mutated)

    def test_request_codecs_are_canonical_bounded_and_do_not_accept_private_classes(self) -> None:
        chat = json.loads(
            shadow.build_request_bytes(
                self.profile.binding("deepseek-v4-pro"), b"public synthetic", 16
            )
        )
        self.assertEqual(chat["model"], "deepseek-v4-pro")
        self.assertEqual(chat["thinking"], {"type": "enabled"})
        self.assertFalse(chat["stream"])
        responses = json.loads(
            shadow.build_request_bytes(
                self.profile.binding("gpt-5.6-sol-xhigh"), b"public synthetic", 16
            )
        )
        self.assertEqual(responses["model"], "gpt-5.6-sol")
        self.assertEqual(responses["reasoning"], {"effort": "xhigh"})
        self.assertFalse(responses["store"])
        with self.assertRaises(shadow.ShadowProviderError):
            shadow.build_request_bytes(
                self.profile.binding("deepseek-v4-pro"), b"x", 4097
            )
        main_source = inspect.getsource(shadow.main)
        self.assertIn('choices=("D0", "D1")', main_source)
        self.assertNotIn('add_argument("--binding"', main_source)

    def test_preflight_reports_presence_only_and_never_secret_values(self) -> None:
        secret = "synthetic-secret-never-print"
        output = io.StringIO()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": secret}, clear=True):
            with redirect_stdout(output):
                code = shadow._preflight(self.profile)
        text = output.getvalue()
        self.assertEqual(code, 0)
        self.assertNotIn(secret, text)
        value = json.loads(text)
        self.assertEqual(value["bindings"]["deepseek-v4-pro"], "CONFIGURED_UNPROVEN")
        self.assertEqual(value["bindings"]["glm-5.2-max"], "WAIT_CREDENTIAL")
        self.assertFalse(value["secrets_printed"])

    def test_transport_adapter_envelopes_status_headers_and_body_without_secret(self) -> None:
        secret = "synthetic-secret-never-serialize"
        observed: dict[str, object] = {}

        def transport(endpoint: str, api_key: str, body: bytes, timeout: int, maximum: int):  # type: ignore[no-untyped-def]
            observed.update(endpoint=endpoint, api_key=api_key, body=body, timeout=timeout, maximum=maximum)
            return 200, {"x-request-id": "request-1"}, b'{"id":"response-1"}'

        binding = self.profile.binding("deepseek-v4-flash")
        adapter = shadow.HTTPRawAdapter(
            "deepseek-v4-flash", binding, secret,
            timeout=self.profile.timeout_seconds,
            maximum=self.profile.max_response_bytes,
            transport=transport,
        )
        raw = adapter.invoke_raw(
            call_id="model-call:" + "a" * 64,
            request_bytes=b'{"synthetic":true}',
            max_tokens=1,
        )
        self.assertEqual(observed["api_key"], secret)
        self.assertNotIn(secret.encode(), raw)
        decoded = json.loads(raw)
        self.assertEqual(decoded["http_status"], 200)
        self.assertEqual(decoded["headers"], {"x-request-id": "request-1"})
        self.assertIsNone(
            shadow._NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://attacker.invalid")
        )

    def test_parsers_validate_protocol_output_usage_and_conserve_http_failures(self) -> None:
        chat_parser = shadow.HTTPResponseParser(
            "deepseek-v4-pro", "OPENAI_CHAT_COMPLETIONS"
        )
        result = chat_parser.parse_response(
            raw_response=envelope(
                "deepseek-v4-pro",
                "OPENAI_CHAT_COMPLETIONS",
                200,
                {
                    "id": "chat-1",
                    "choices": [{"message": {"content": "synthetic"}}],
                    "usage": {"total_tokens": 7},
                },
            ),
            response_ref="cas:sha256:" + "1" * 64,
            max_tokens=8,
        )
        self.assertEqual(result.actual_tokens, 7)
        self.assertIsNone(result.actual_cost_units)
        responses_parser = shadow.HTTPResponseParser(
            "gpt-5.6-sol-max", "OPENAI_RESPONSES"
        )
        self.assertEqual(
            responses_parser.parse_response(
                raw_response=envelope(
                    "gpt-5.6-sol-max", "OPENAI_RESPONSES", 200,
                    {"id": "resp-1", "output": [{"type": "message"}], "usage": {"total_tokens": 9}},
                ),
                response_ref="cas:sha256:" + "2" * 64,
                max_tokens=8,
            ).actual_tokens,
            9,
        )
        with self.assertRaises(KnownProviderFailure):
            chat_parser.parse_response(
                raw_response=envelope(
                    "deepseek-v4-pro", "OPENAI_CHAT_COMPLETIONS", 429,
                    {"error": {"message": "synthetic"}},
                ),
                response_ref="cas:sha256:" + "3" * 64,
                max_tokens=8,
            )
        with self.assertRaises(shadow.ShadowProviderError):
            chat_parser.parse_response(
                raw_response=b'{"malformed":true}',
                response_ref="cas:sha256:" + "4" * 64,
                max_tokens=8,
            )

    def test_private_cas_committer_is_exact_and_repo_paths_are_denied(self) -> None:
        root = self.temp_path / "cas"
        committer = shadow.CASCommitter(root, quota_bytes=1024)
        raw = b'{"private":"synthetic-provider-envelope"}'
        expected = "cas:sha256:" + hashlib.sha256(raw).hexdigest()
        self.assertEqual(committer.commit_response(raw), expected)
        self.assertEqual(committer.commit_response(raw), expected)
        with self.assertRaises(shadow.ShadowProviderError):
            shadow._outside_repository(ROOT / "runtime")
        self.assertEqual(shadow._outside_repository(self.temp_path), self.temp_path.resolve())

    def test_fake_connected_end_to_end_uses_existing_broker_and_retains_cost_reservation(self) -> None:
        database = self.temp_path / "shadow.sqlite3"
        events: list[str] = []
        body = {
            "id": "chat-e2e",
            "choices": [{"message": {"content": "synthetic result"}}],
            "usage": {"total_tokens": 5},
        }

        def transport(endpoint: str, api_key: str, request: bytes, timeout: int, maximum: int):  # type: ignore[no-untyped-def]
            events.append("transport")
            return 200, {"x-request-id": "e2e"}, json.dumps(body).encode()

        binding = self.profile.binding("deepseek-v4-flash")
        request = shadow.build_request_bytes(binding, b"public synthetic", 8)
        with seeded_ledger(database) as ledger:
            broker = ModelCallBroker(registry=registry(), ledger=ledger, budget_policy=policy())
            call = spec(request=request, key="s17-shadow-e2e")
            handle = broker.prepare(call, event_at=AT)
            completed = broker.execute_raw(
                handle.call_id,
                request_bytes=request,
                adapter=shadow.HTTPRawAdapter(
                    "deepseek-v4-flash", binding, "synthetic-key",
                    timeout=1, maximum=1024, transport=transport,
                ),
                response_committer=shadow.CASCommitter(self.temp_path / "e2e-cas", quota_bytes=4096),
                response_parser=shadow.HTTPResponseParser(
                    "deepseek-v4-flash", "OPENAI_CHAT_COMPLETIONS"
                ),
                event_at=AT_SENT,
            )
            self.assertEqual(events, ["transport"])
            self.assertEqual(completed.state, "SUCCEEDED")
            state = ledger.model_call_state(handle.call_id).snapshot
            self.assertEqual(state["actual_tokens"], 5)
            self.assertIsNone(state["actual_cost_units"])
            self.assertTrue(state["ambiguous_usage"])
            self.assertFalse(state["budget_released"])
            self.assertFalse(state["auto_retry"])

    def test_public_files_contain_no_credential_values_or_provider_responses(self) -> None:
        text = "\n".join(
            path.read_text()
            for path in (
                shadow.PROFILE_PATH,
                ROOT / "tools" / "model_provider_shadow.py",
                ROOT / "docs" / "receipts" / "source-freeze" / "s17-official-provider-api-shapes.json",
                ROOT / "docs" / "receipts" / "reuse" / "s17-connected-provider-shadow-tool.json",
            )
        ).lower()
        for forbidden in (
            "sk-proj-", "sk-ant-", "bearer synthetic", "private provider response",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
