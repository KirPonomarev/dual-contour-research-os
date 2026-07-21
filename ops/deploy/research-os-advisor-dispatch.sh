#!/bin/sh
# research-os-advisor-dispatch — host-side oneshot advisor dispatch.
#
# Queries researchd for RESERVED model calls via docker exec into the
# network-none Core container, writes an atomic dispatch JSON, starts
# the connected-worker template unit, and waits for completion.
#
# POSIX sh (dash) compatible.  No bashisms.
#
# Security:
#   - AI_OFF marker instantly prohibits new calls.
#   - flock prevents concurrent dispatch (WIP=1).
#   - Dispatch files are mode 0600, owner-only.
#   - Provider failure does NOT stop Core.
#   - Result is advisory, never admission/permit/canonical truth.
#   - Idempotent: re-running on a completed call does zero network calls.
#   - Socket absence is a terminal error, not "no work".

set -eu

# --- Configuration -----------------------------------------------------------

CORE_CONTAINER="${RESEARCH_OS_CORE_CONTAINER:-research-os-a1-bridge}"
DISPATCH_DIR="${RESEARCH_OS_DISPATCH_DIR:-${HOME}/.local/share/research-os/connected-dispatch}"
AI_OFF_MARKER="${RESEARCH_OS_AI_OFF:-${HOME}/.config/research-os/AI_OFF}"
LOCK_DIR="${RESEARCH_OS_LOCK_DIR:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/research-os}"
WORKER_UNIT_TEMPLATE="research-os-connected-worker@.service"
MAX_WAIT_SECONDS="${RESEARCH_OS_DISPATCH_TIMEOUT:-1800}"

# --- Helpers -----------------------------------------------------------------

log() {
    printf '%s [advisor-dispatch] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

die() {
    log "FATAL: $*"
    exit 1
}

# --- Preflight ---------------------------------------------------------------

# AI_OFF check — instant prohibition
if [ -e "${AI_OFF_MARKER}" ]; then
    log "AI_OFF marker present — dispatch prohibited"
    exit 0
fi

# Core container must be running
CORE_RUNNING=$(docker inspect --format='{{.State.Running}}' "${CORE_CONTAINER}" 2>/dev/null) || {
    die "CORE_UNAVAILABLE: cannot inspect container ${CORE_CONTAINER}"
}
if [ "${CORE_RUNNING}" != "true" ]; then
    die "CORE_UNAVAILABLE: container ${CORE_CONTAINER} is not running"
fi

# Ensure dispatch directory exists
mkdir -p "${DISPATCH_DIR}"
chmod 0700 "${DISPATCH_DIR}"

# Ensure lock directory exists
mkdir -p "${LOCK_DIR}"
chmod 0700 "${LOCK_DIR}"

# --- WIP=1 Lock (flock) ------------------------------------------------------

LOCK_FILE="${LOCK_DIR}/advisor-dispatch.lock"
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
    log "Another dispatch is active (flock held) — skipping"
    exit 0
fi

# --- Query researchd for RESERVED calls via docker exec ----------------------

query_reserved_calls() {
    # Use docker exec to query Core's AF_UNIX socket from inside the container.
    # The connected_worker UID (10004) is an allowed actor for this command.
    docker exec --user 10004:10001 "${CORE_CONTAINER}" python3 -c '
import json, socket, sys, hashlib

SOCK = "/var/lib/research-os/researchd.sock"
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(SOCK)
except (OSError, socket.error) as e:
    print(json.dumps({"status": "CONTROL_SOCKET_UNAVAILABLE", "error": str(e)}))
    sys.exit(1)

request = {
    "version": "1.2",
    "request_id": hashlib.sha256(b"advisor-dispatch:list-reserved").hexdigest(),
    "idempotency_key": "advisor-dispatch:list-reserved",
    "command": "list_reserved_model_calls",
    "payload": {"maximum": 1}
}
frame = json.dumps(request, separators=(",", ":")).encode() + b"\n"
try:
    s.sendall(frame)
    s.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    s.close()
except (OSError, socket.error) as e:
    print(json.dumps({"status": "IPC_PROTOCOL_ERROR", "error": str(e)}))
    sys.exit(1)

try:
    response = json.loads(b"".join(chunks))
except (json.JSONDecodeError, ValueError) as e:
    print(json.dumps({"status": "MALFORMED_RESPONSE", "error": str(e)}))
    sys.exit(1)

if not response.get("ok"):
    print(json.dumps({"status": "AUTHORIZATION_ERROR", "error": response.get("error", "unknown")}))
    sys.exit(1)

result = response.get("result", {})
print(json.dumps(result, separators=(",", ":")))
' 2>/dev/null
}

QUERY_RESULT=$(query_reserved_calls) || {
    # docker exec itself failed
    die "CORE_UNAVAILABLE: docker exec into ${CORE_CONTAINER} failed"
}

# Parse the query result status
QUERY_STATUS=$(printf '%s' "${QUERY_RESULT}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","UNKNOWN"))' 2>/dev/null) || {
    die "MALFORMED_RESPONSE: cannot parse query result"
}

case "${QUERY_STATUS}" in
    NO_RESERVED_CALLS)
        log "No RESERVED model calls — nothing to dispatch"
        exit 0
        ;;
    FOUND)
        # Continue to dispatch
        ;;
    CONTROL_SOCKET_UNAVAILABLE)
        die "CONTROL_SOCKET_UNAVAILABLE: Core socket not reachable"
        ;;
    IPC_PROTOCOL_ERROR)
        die "IPC_PROTOCOL_ERROR: ${QUERY_RESULT}"
        ;;
    AUTHORIZATION_ERROR)
        die "AUTHORIZATION_ERROR: ${QUERY_RESULT}"
        ;;
    MALFORMED_RESPONSE)
        die "MALFORMED_RESPONSE: ${QUERY_RESULT}"
        ;;
    *)
        die "UNKNOWN_STATUS: ${QUERY_STATUS}"
        ;;
esac

# --- Dispatch each RESERVED call sequentially --------------------------------

dispatch_one() {
    CALL_JSON="$1"
    CALL_ID=$(printf '%s' "${CALL_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["call_id"])' 2>/dev/null) || {
        log "ERROR: cannot parse call_id from reserved call"
        return 1
    }
    DISPATCH_TOKEN=$(printf '%s' "${CALL_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dispatch_token"])' 2>/dev/null) || {
        log "ERROR: cannot parse dispatch_token"
        return 1
    }

    # Sanitize call_id for use as systemd instance name
    INSTANCE_NAME=$(printf '%s' "${CALL_ID}" | sed 's/[^A-Za-z0-9._-]/-/g' | cut -c1-200)

    DISPATCH_FILE="${DISPATCH_DIR}/${INSTANCE_NAME}.json"

    # Build dispatch JSON for the worker
    python3 -c '
import json, sys

call = json.loads(sys.argv[1])
dispatch = {
    "schema_id": "ModelWorkerDispatch",
    "schema_version": "1.0.0",
    "call_id": call["call_id"],
    "dispatch_token": call["dispatch_token"],
    "request_body": call.get("request_body", ""),
    "model_binding": call.get("model_binding", ""),
    "classification": call.get("classification", "D0"),
    "max_tokens": call.get("max_tokens", 512),
    "expires_at": call.get("expires_at", ""),
    "worker_ipc_extension_sha256": "03d91f027bb6975c55d84acaef188546bcd24af9944a72f4ff9314296399d07a"
}
print(json.dumps(dispatch, indent=2))
' "${CALL_JSON}" > "${DISPATCH_FILE}.tmp"

    chmod 0600 "${DISPATCH_FILE}.tmp"
    mv "${DISPATCH_FILE}.tmp" "${DISPATCH_FILE}"

    log "Dispatching ${CALL_ID} as instance ${INSTANCE_NAME}"

    # Start the worker template unit (user-level only, no system fallback)
    if systemctl --user start "${WORKER_UNIT_TEMPLATE%.service}@${INSTANCE_NAME}.service" 2>/dev/null; then
        log "Worker started for ${INSTANCE_NAME}"
    else
        log "WARNING: could not start worker for ${INSTANCE_NAME}"
        rm -f "${DISPATCH_FILE}"
        return 1
    fi

    # Wait for worker to complete (oneshot — systemd tracks completion)
    WAITED=0
    while [ "${WAITED}" -lt "${MAX_WAIT_SECONDS}" ]; do
        STATE=$(systemctl --user is-active "research-os-connected-worker@${INSTANCE_NAME}.service" 2>/dev/null) || STATE="inactive"
        case "${STATE}" in
            inactive|failed|deactivating)
                break
                ;;
        esac
        sleep 5
        WAITED=$((WAITED + 5))
    done

    if [ "${WAITED}" -ge "${MAX_WAIT_SECONDS}" ]; then
        log "WARNING: worker ${INSTANCE_NAME} timed out after ${MAX_WAIT_SECONDS}s"
    else
        log "Worker ${INSTANCE_NAME} completed (state: ${STATE})"
    fi

    # Clean up dispatch file
    rm -f "${DISPATCH_FILE}"
    return 0
}

# Extract reserved calls and dispatch sequentially
CALL_COUNT=$(printf '%s' "${QUERY_RESULT}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count",0))' 2>/dev/null) || CALL_COUNT=0

if [ "${CALL_COUNT}" -eq 0 ]; then
    log "No calls to dispatch"
    exit 0
fi

IDX=0
while [ "${IDX}" -lt "${CALL_COUNT}" ]; do
    # Re-check AI_OFF before each call
    if [ -e "${AI_OFF_MARKER}" ]; then
        log "AI_OFF marker appeared — stopping dispatch"
        break
    fi

    CALL_JSON=$(printf '%s' "${QUERY_RESULT}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
calls = data.get('reserved_calls', [])
if ${IDX} < len(calls):
    print(json.dumps(calls[${IDX}], separators=(',', ':')))
" 2>/dev/null) || {
        log "ERROR: cannot extract call at index ${IDX}"
        IDX=$((IDX + 1))
        continue
    }

    dispatch_one "${CALL_JSON}" || log "Dispatch failed for call at index ${IDX} — continuing"
    IDX=$((IDX + 1))
done

log "Dispatch cycle complete (${IDX} calls processed)"
exit 0
