#!/bin/sh
# research-os-advisor-dispatch — host-side oneshot advisor dispatch.
#
# Queries researchd for RESERVED model calls, writes an atomic dispatch
# JSON, starts the connected-worker template unit, waits for completion,
# and cleans up.  WIP=1: a lock file prevents concurrent dispatch.
#
# This script is NOT a daemon.  It is invoked by a systemd timer or
# manually by the operator.  It exits 0 on success or no-work, and
# non-zero only on unexpected errors.
#
# Security:
#   - AI_OFF marker instantly prohibits new calls.
#   - Lock file prevents concurrent dispatch (WIP=1).
#   - Dispatch files are mode 0600, owner-only.
#   - Provider failure does NOT stop Core.
#   - Result is advisory, never admission/permit/canonical truth.
#   - Idempotent: re-running on a completed call does zero network calls.

set -eu

# --- Configuration -----------------------------------------------------------

RUNTIME_ROOT="${RESEARCH_OS_RUNTIME_ROOT:-/var/lib/research-os}"
DISPATCH_DIR="${RESEARCH_OS_DISPATCH_DIR:-${HOME}/.local/share/research-os/connected-dispatch}"
AI_OFF_MARKER="${RESEARCH_OS_AI_OFF:-${HOME}/.config/research-os/AI_OFF}"
LOCK_FILE="${RESEARCH_OS_DISPATCH_LOCK:-/run/research-os/advisor-dispatch.lock}"
CONTROL_SOCKET="${RUNTIME_ROOT}/researchd.sock"
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

cleanup_lock() {
    rm -f "${LOCK_FILE}" 2>/dev/null || true
}

# --- Preflight ---------------------------------------------------------------

# AI_OFF check — instant prohibition
if [ -e "${AI_OFF_MARKER}" ]; then
    log "AI_OFF marker present — dispatch prohibited"
    exit 0
fi

# Control socket must exist
if [ ! -S "${CONTROL_SOCKET}" ]; then
    log "Control socket not found at ${CONTROL_SOCKET} — Core not running"
    exit 0
fi

# Ensure dispatch directory exists
mkdir -p "${DISPATCH_DIR}"
chmod 0700 "${DISPATCH_DIR}"

# --- WIP=1 Lock --------------------------------------------------------------

if [ -e "${LOCK_FILE}" ]; then
    LOCK_AGE=$(( $(date +%s) - $(stat -c %Y "${LOCK_FILE}" 2>/dev/null || echo 0) ))
    if [ "${LOCK_AGE}" -lt "${MAX_WAIT_SECONDS}" ]; then
        log "Another dispatch is active (lock age ${LOCK_AGE}s) — skipping"
        exit 0
    fi
    log "Stale lock detected (age ${LOCK_AGE}s) — removing"
    rm -f "${LOCK_FILE}"
fi

# Acquire lock
trap cleanup_lock EXIT
if ! (set -o noclobber; echo "$$" > "${LOCK_FILE}") 2>/dev/null; then
    log "Could not acquire lock — concurrent dispatch"
    trap - EXIT
    exit 0
fi

# --- Query researchd for RESERVED calls --------------------------------------

# Use researchctl or direct IPC to list RESERVED model calls.
# The dispatch script queries the control socket for pending advisor calls.
# If no RESERVED calls exist, exit cleanly.

query_reserved_calls() {
    # Query via researchctl if available, otherwise via Python IPC helper
    if command -v researchctl >/dev/null 2>&1; then
        researchctl --socket "${CONTROL_SOCKET}" model list-reserved 2>/dev/null || true
    else
        python3 -c "
import json, socket, sys, hashlib

sock_path = '${CONTROL_SOCKET}'
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    request = {
        'version': '1.2',
        'request_id': hashlib.sha256(b'advisor-dispatch:query').hexdigest(),
        'idempotency_key': 'advisor-dispatch:query:reserved',
        'command': 'list_reserved_model_calls',
        'payload': {}
    }
    frame = json.dumps(request, separators=(',', ':')).encode() + b'\n'
    s.sendall(frame)
    s.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    s.close()
    response = json.loads(b''.join(chunks))
    if response.get('ok'):
        calls = response.get('result', {}).get('reserved_calls', [])
        for call in calls:
            print(json.dumps(call, separators=(',', ':')))
except Exception:
    pass
" 2>/dev/null || true
    fi
}

RESERVED_CALLS=$(query_reserved_calls)

if [ -z "${RESERVED_CALLS}" ]; then
    log "No RESERVED model calls — nothing to dispatch"
    exit 0
fi

# --- Dispatch each RESERVED call sequentially --------------------------------

dispatch_one() {
    CALL_JSON="$1"
    CALL_ID=$(printf '%s' "${CALL_JSON}" | python3 -c "import json,sys; print(json.load(sys.stdin)['call_id'])" 2>/dev/null) || {
        log "Could not parse call_id from reserved call"
        return 1
    }

    # Sanitize call_id for use as systemd instance name
    INSTANCE_NAME=$(printf '%s' "${CALL_ID}" | tr ':/' '--' | tr -cd 'A-Za-z0-9._-')

    DISPATCH_FILE="${DISPATCH_DIR}/${INSTANCE_NAME}.json"

    # Write dispatch JSON atomically (mode 0600)
    TMPFILE="${DISPATCH_DIR}/.${INSTANCE_NAME}.tmp"
    printf '%s' "${CALL_JSON}" > "${TMPFILE}"
    chmod 0600 "${TMPFILE}"
    mv "${TMPFILE}" "${DISPATCH_FILE}"

    log "Dispatching ${CALL_ID} as instance ${INSTANCE_NAME}"

    # Start the worker template unit
    if systemctl --user start "${WORKER_UNIT_TEMPLATE/.service/}@${INSTANCE_NAME}.service" 2>/dev/null; then
        log "Worker started for ${INSTANCE_NAME}"
    else
        # Try system-level systemctl if user-level fails
        if systemctl start "research-os-connected-worker@${INSTANCE_NAME}.service" 2>/dev/null; then
            log "Worker started (system) for ${INSTANCE_NAME}"
        else
            log "WARNING: Could not start worker for ${INSTANCE_NAME}"
            rm -f "${DISPATCH_FILE}"
            return 1
        fi
    fi

    # Wait for worker to complete (oneshot — systemd tracks completion)
    WAITED=0
    while [ "${WAITED}" -lt "${MAX_WAIT_SECONDS}" ]; do
        if ! systemctl is-active --quiet "research-os-connected-worker@${INSTANCE_NAME}.service" 2>/dev/null; then
            break
        fi
        sleep 5
        WAITED=$((WAITED + 5))
    done

    if [ "${WAITED}" -ge "${MAX_WAIT_SECONDS}" ]; then
        log "WARNING: Worker ${INSTANCE_NAME} timed out after ${MAX_WAIT_SECONDS}s"
    else
        log "Worker ${INSTANCE_NAME} completed"
    fi

    # Clean up dispatch file
    rm -f "${DISPATCH_FILE}"
    return 0
}

# Process calls sequentially (WIP=1 enforced by lock)
printf '%s\n' "${RESERVED_CALLS}" | while IFS= read -r CALL_LINE; do
    [ -z "${CALL_LINE}" ] && continue

    # Re-check AI_OFF before each call
    if [ -e "${AI_OFF_MARKER}" ]; then
        log "AI_OFF marker appeared — stopping dispatch"
        break
    fi

    dispatch_one "${CALL_LINE}" || log "Dispatch failed for one call — continuing"
done

log "Dispatch cycle complete"
exit 0
