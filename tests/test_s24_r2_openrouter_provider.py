from __future__ import annotations

import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import model_provider_shadow as shadow  # noqa: E402
from research_bridge.model_broker import ModelCallBroker  # noqa: E402
from tests.test_s15_model_registry_broker import (  # noqa: E402
    AT,
    AT_SENT,
    policy,
    registry,
    seeded_ledger,
    spec,
)


class OpenRouterProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profile = shadow.ConnectedShadowProfile()

    def test_v2_profile_is_exact_and_v1_remains_immutable_and_readable(self) -> None:
        self.assertEqual(self.profile.profile_id, "model-provider-connected-shadow-v2")
        self.assertEqual(
            self.profile.sha256,
            "63ae65247d61b918aced080e6419609459ebcbf4a3384ea29f2617e65597258c",
        )
        binding = self.profile.binding("gpt-5.6-sol-xhigh")
        self.assertEqual(binding["provider"], "openrouter")
        self.assertEqual(binding["provider_slot"], "OPENROUTER_API")
        self.assertEqual(binding["credential_env"], "OPENROUTER_API_KEY")
        self.assertEqual(
            binding["endpoint"], "https://openrouter.ai/api/v1/chat/completions"
        )
        self.assertEqual(binding["api_model"], "openai/gpt-5.6-sol")
        self.assertEqual(binding["context_window"], 1_000_000)
        self.assertEqual(binding["request_options"], {"reasoning": {"effort": "xhigh"}})
        legacy = shadow.ConnectedShadowProfile(shadow.LEGACY_PROFILE_PATH)
        self.assertEqual(legacy.profile_id, "model-provider-connected-shadow-v1")
        self.assertEqual(
            legacy.sha256,
            "4ac18aaa960d78ee0103cd199f411067aca46fceb11efa8e0045c53f57c5affd",
        )

    def test_openrouter_request_is_exact_canonical_bounded_chat_completion(self) -> None:
        request = shadow.build_request_bytes(
            self.profile.binding("gpt-5.6-sol-xhigh"),
            b"public synthetic falsification request",
            17,
        )
        self.assertEqual(
            request,
            json.dumps(
                {
                    "model": "openai/gpt-5.6-sol",
                    "messages": [
                        {"role": "user", "content": "public synthetic falsification request"}
                    ],
                    "max_tokens": 17,
                    "stream": False,
                    "reasoning": {"effort": "xhigh"},
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode(),
        )

    def test_environment_has_precedence_and_never_invokes_keychain(self) -> None:
        sentinel = "synthetic-openrouter-env-secret"
        with patch.object(shadow.sys, "platform", "darwin"):
            with patch.object(shadow.subprocess, "run") as run:
                resolver = shadow.CredentialResolver({"OPENROUTER_API_KEY": sentinel})
                self.assertEqual(resolver.resolve("OPENROUTER_API_KEY"), sentinel)
                self.assertEqual(resolver.resolve("OPENROUTER_API_KEY"), sentinel)
        run.assert_not_called()

    def test_macos_keychain_fallback_uses_exact_captured_command_and_cache(self) -> None:
        sentinel = "synthetic-openrouter-keychain-secret"
        completed = subprocess.CompletedProcess(
            list(shadow._KEYCHAIN_COMMAND), 0, stdout=sentinel + "\n", stderr=""
        )
        with patch.object(shadow.sys, "platform", "darwin"):
            with patch.object(shadow.subprocess, "run", return_value=completed) as run:
                resolver = shadow.CredentialResolver({})
                self.assertEqual(resolver.resolve("OPENROUTER_API_KEY"), sentinel)
                self.assertEqual(resolver.resolve("OPENROUTER_API_KEY"), sentinel)
        run.assert_called_once_with(
            list(shadow._KEYCHAIN_COMMAND),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(
            shadow._KEYCHAIN_COMMAND,
            (
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                "ai.shared.openrouter",
                "-a",
                "OPENROUTER_API_KEY",
                "-w",
            ),
        )

    def test_malformed_environment_does_not_fall_through_or_leak(self) -> None:
        sentinel = "synthetic secret with whitespace"
        with patch.object(shadow.sys, "platform", "darwin"):
            with patch.object(shadow.subprocess, "run") as run:
                resolver = shadow.CredentialResolver({"OPENROUTER_API_KEY": sentinel})
                self.assertEqual(resolver.resolve("OPENROUTER_API_KEY"), "")
        run.assert_not_called()

    def test_keychain_failure_is_sanitized_and_preflight_never_emits_secret(self) -> None:
        sentinel = "synthetic-openrouter-never-emit"
        with patch.object(shadow.sys, "platform", "darwin"):
            with patch.object(
                shadow.subprocess, "run", side_effect=OSError(sentinel)
            ):
                with self.assertRaises(shadow.ShadowProviderError) as raised:
                    shadow.CredentialResolver({}).resolve("OPENROUTER_API_KEY")
        self.assertNotIn(sentinel, str(raised.exception))

        completed = subprocess.CompletedProcess(
            list(shadow._KEYCHAIN_COMMAND), 0, stdout=sentinel + "\n", stderr=""
        )
        output = io.StringIO()
        with patch.object(shadow.sys, "platform", "darwin"):
            with patch.object(shadow.subprocess, "run", return_value=completed):
                with patch.dict(shadow.os.environ, {}, clear=True):
                    with redirect_stdout(output):
                        self.assertEqual(shadow._preflight(self.profile), 0)
        rendered = output.getvalue()
        self.assertNotIn(sentinel, rendered)
        self.assertEqual(
            json.loads(rendered)["bindings"]["gpt-5.6-sol-xhigh"],
            "CONFIGURED_UNPROVEN",
        )

    def test_openrouter_chat_parser_accepts_usage_but_keeps_cost_unsettled(self) -> None:
        body = json.dumps(
            {
                "id": "openrouter-synthetic-response",
                "choices": [{"message": {"content": "synthetic"}}],
                "usage": {"total_tokens": 11, "cost": 0.000001},
            },
            separators=(",", ":"),
        ).encode()
        envelope = json.dumps(
            {
                "binding": "gpt-5.6-sol-xhigh",
                "protocol": "OPENAI_CHAT_COMPLETIONS",
                "http_status": 200,
                "headers": {"x-request-id": "synthetic-openrouter-request"},
                "body_base64": base64.b64encode(body).decode(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        accounting = shadow.HTTPResponseParser(
            "gpt-5.6-sol-xhigh", "OPENAI_CHAT_COMPLETIONS"
        ).parse_response(
            raw_response=envelope,
            response_ref="cas:sha256:" + hashlib.sha256(envelope).hexdigest(),
            max_tokens=17,
        )
        self.assertEqual(accounting.actual_tokens, 11)
        self.assertIsNone(accounting.actual_cost_units)
        self.assertTrue(str(accounting.provider_receipt_ref).startswith("provider-response:sha256:"))

    def test_durable_sent_precedes_openrouter_egress_and_budget_stays_reserved(self) -> None:
        database = self.root / "openrouter.sqlite3"
        request = shadow.build_request_bytes(
            self.profile.binding("gpt-5.6-sol-xhigh"), b"public synthetic", 16
        )
        body = json.dumps(
            {
                "id": "openrouter-e2e",
                "choices": [{"message": {"content": "synthetic"}}],
                "usage": {"total_tokens": 7},
            }
        ).encode()
        with seeded_ledger(database) as ledger:
            broker = ModelCallBroker(
                registry=registry(
                    revision="s24-r2-openrouter-test",
                    overrides={"CRITIC_DEEP": "gpt-5.6-sol-xhigh"},
                ),
                ledger=ledger,
                budget_policy=policy(active=1, tokens=16, cost=1),
            )
            prepared = broker.prepare(
                spec(
                    role="CRITIC_DEEP",
                    request=request,
                    key="s24-r2-openrouter-sent-before-egress",
                    max_tokens=16,
                    max_cost=1,
                ),
                event_at=AT,
            )
            observed_states: list[str] = []

            def transport(*_args):  # type: ignore[no-untyped-def]
                observed_states.append(
                    str(ledger.model_call_state(prepared.call_id).snapshot["state"])
                )
                return 200, {"x-request-id": "synthetic-e2e"}, body

            completed = broker.execute_raw(
                prepared.call_id,
                request_bytes=request,
                adapter=shadow.HTTPRawAdapter(
                    "gpt-5.6-sol-xhigh",
                    self.profile.binding("gpt-5.6-sol-xhigh"),
                    "synthetic-key",
                    timeout=1,
                    maximum=4096,
                    transport=transport,
                ),
                response_committer=shadow.CASCommitter(
                    self.root / "cas", quota_bytes=16_384
                ),
                response_parser=shadow.HTTPResponseParser(
                    "gpt-5.6-sol-xhigh", "OPENAI_CHAT_COMPLETIONS"
                ),
                event_at=AT_SENT,
            )
            state = ledger.model_call_state(completed.call_id).snapshot
        self.assertEqual(observed_states, ["SENT"])
        self.assertEqual(completed.state, "SUCCEEDED")
        self.assertIsNone(state["actual_cost_units"])
        self.assertTrue(state["ambiguous_usage"])
        self.assertFalse(state["budget_released"])
        self.assertFalse(state["auto_retry"])


if __name__ == "__main__":
    unittest.main()
