"""Minimal local CLI for the offline researchd AF_UNIX protocol."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
import socket
import sys
from typing import Any, TextIO
import uuid

from .control import ControlError, ControlRequest
from .ipc import IPCError, decode_message, encode_message


_DEFAULT_PROTOCOL_VERSION = "1.1"
_PROTOCOL_VERSIONS = ("1.1", "1.2")
_REQUEST_MAXIMUM_BYTES = 65_536
_RESPONSE_MAXIMUM_BYTES = 262_144
_DEADLINE_SECONDS = 5.0
_SUCCESS_KEYS = frozenset({"version", "request_id", "ok", "command", "result"})


class ResearchctlError(RuntimeError):
    """A local CLI input, transport, or response validation failure."""


class _LocalInputError(ResearchctlError):
    pass


class _TransportError(ResearchctlError):
    pass


class _DaemonFailure(ResearchctlError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _LocalInputError("command arguments are invalid")


def run(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Execute one researchctl command and return its frozen exit code."""

    input_stream = stdin if stdin is not None else sys.stdin
    output_stream = stdout if stdout is not None else sys.stdout
    error_stream = stderr if stderr is not None else sys.stderr
    try:
        arguments = _parser().parse_args(argv)
        request = _request(arguments, input_stream)
        response = _round_trip(arguments.socket_path, request)
        _validate_success(response, request)
        encoded = encode_message(
            response,
            maximum_bytes=_RESPONSE_MAXIMUM_BYTES,
        )
        output_stream.write(encoded.decode("ascii"))
        output_stream.flush()
        return 0
    except _LocalInputError:
        _write_error(error_stream, "local input rejected")
        return 2
    except (ControlError, json.JSONDecodeError, UnicodeError, ValueError, TypeError):
        _write_error(error_stream, "local input rejected")
        return 2
    except _DaemonFailure:
        _write_error(error_stream, "daemon rejected request")
        return 4
    except (IPCError, _TransportError):
        _write_error(error_stream, "local transport failed")
        return 3


def main() -> None:
    raise SystemExit(run())


def _parser() -> _Parser:
    parser = _Parser(prog="researchctl", add_help=True)
    parser.add_argument("--socket", dest="socket_path", required=True)
    parser.add_argument("--request-id")
    parser.add_argument(
        "--protocol-version",
        choices=_PROTOCOL_VERSIONS,
        default=_DEFAULT_PROTOCOL_VERSION,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("status")

    pause = commands.add_parser("pause")
    pause.add_argument("--reason", required=True)
    pause.add_argument("--authority-ref", required=True)
    pause.add_argument("--idempotency-key", required=True)

    resume = commands.add_parser("resume")
    resume.add_argument("--approval-ref", required=True)
    resume.add_argument("--idempotency-key", required=True)

    submit = commands.add_parser("submit")
    submit.add_argument("--idempotency-key", required=True)

    lookup = commands.add_parser("lookup")
    lookup.add_argument("--job-spec-ref", required=True)
    return parser


def _request(arguments: argparse.Namespace, input_stream: TextIO) -> ControlRequest:
    request_id = arguments.request_id or f"request-{uuid.uuid4().hex}"
    command = arguments.command
    if command == "status":
        wire_command = "status"
        idempotency_key = f"read-{request_id}"
        payload: dict[str, object] = {}
    elif command == "pause":
        wire_command = "pause_global"
        idempotency_key = arguments.idempotency_key
        payload = {
            "reason": arguments.reason,
            "authority_ref": arguments.authority_ref,
        }
    elif command == "resume":
        wire_command = "resume_global"
        idempotency_key = arguments.idempotency_key
        payload = {"approval_ref": arguments.approval_ref}
    elif command == "submit":
        wire_command = "submit"
        idempotency_key = arguments.idempotency_key
        payload = _submit_payload(input_stream)
    elif command == "lookup":
        wire_command = "lookup"
        idempotency_key = f"read-{request_id}"
        payload = {"job_spec_ref": arguments.job_spec_ref}
    else:  # pragma: no cover - argparse enforces the closed command set.
        raise _LocalInputError("unsupported command")

    return ControlRequest(
        version=arguments.protocol_version,
        request_id=request_id,
        idempotency_key=idempotency_key,
        command=wire_command,
        payload=payload,
    )


def _submit_payload(input_stream: TextIO) -> dict[str, object]:
    try:
        text = input_stream.read(_REQUEST_MAXIMUM_BYTES + 1)
    except Exception as exc:
        raise _LocalInputError("submit input is unavailable") from exc
    if not isinstance(text, str):
        raise _LocalInputError("submit input must be text")
    try:
        encoded = text.encode("utf-8")
    except UnicodeError as exc:
        raise _LocalInputError("submit input is not UTF-8") from exc
    if not encoded or len(encoded) > _REQUEST_MAXIMUM_BYTES:
        raise _LocalInputError("submit input size is invalid")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ResearchctlError) as exc:
        raise _LocalInputError("submit input is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != {"job_spec", "permit", "lease"}:
        raise _LocalInputError("submit input keys are invalid")
    if any(not isinstance(value[name], dict) for name in ("job_spec", "permit", "lease")):
        raise _LocalInputError("submit authority values must be objects")
    return value


def _round_trip(socket_path: object, request: ControlRequest) -> dict[str, object]:
    if not isinstance(socket_path, str) or not socket_path or "\x00" in socket_path:
        raise _LocalInputError("socket path is invalid")
    outbound = encode_message(request.to_mapping())
    connection: socket.socket | None = None
    try:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if connection.family != socket.AF_UNIX:
            raise _TransportError("AF_UNIX is unavailable")
        connection.settimeout(_DEADLINE_SECONDS)
        connection.connect(socket_path)
        connection.sendall(outbound)
        frame = bytearray()
        while True:
            remaining = _RESPONSE_MAXIMUM_BYTES + 1 - len(frame)
            if remaining <= 0:
                raise _TransportError("response exceeds its bound")
            block = connection.recv(min(16_384, remaining))
            if not block:
                break
            frame.extend(block)
            if len(frame) > _RESPONSE_MAXIMUM_BYTES:
                raise _TransportError("response exceeds its bound")
    except _TransportError:
        raise
    except (OSError, TimeoutError) as exc:
        raise _TransportError("AF_UNIX round trip failed") from exc
    finally:
        if connection is not None:
            connection.close()
    if not frame:
        raise _DaemonFailure("daemon returned no success response")
    try:
        return decode_message(
            bytes(frame),
            maximum_bytes=_RESPONSE_MAXIMUM_BYTES,
        )
    except IPCError as exc:
        raise _TransportError("daemon response is invalid") from exc


def _validate_success(
    response: Mapping[str, object],
    request: ControlRequest,
) -> None:
    if set(response) != _SUCCESS_KEYS:
        raise _TransportError("success response shape is invalid")
    if (
        response.get("version") != request.version
        or response.get("request_id") != request.request_id
        or response.get("command") != request.command
        or response.get("ok") is not True
        or not isinstance(response.get("result"), Mapping)
    ):
        raise _TransportError("success response binding is invalid")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _LocalInputError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(value: str) -> Any:
    raise _LocalInputError("non-finite JSON value")


def _write_error(stream: TextIO, message: str) -> None:
    stream.write(message + "\n")
    stream.flush()


if __name__ == "__main__":
    main()


__all__ = ["ResearchctlError", "run", "main"]
