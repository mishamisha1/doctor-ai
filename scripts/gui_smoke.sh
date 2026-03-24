#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ADDR="${DOCTOR_GUI_ADDR:-127.0.0.1:19560}"
BASE="http://$ADDR"
LOG_TMP="/tmp/doctor-gui-smoke.log"
PID_FILE="/tmp/doctor-gui-smoke.pid"

cleanup() {
  if [[ -f "$PID_FILE" ]]; then
    kill "$(cat "$PID_FILE")" >/dev/null 2>&1 || true
    wait "$(cat "$PID_FILE")" >/dev/null 2>&1 || true
    rm -f "$PID_FILE"
  fi
}
trap cleanup EXIT

DOCTOR_GUI_ADDR="$ADDR" ./dist/doctor-gui >"$LOG_TMP" 2>&1 &
echo $! > "$PID_FILE"

ready=0
for _ in {1..40}; do
  if curl -sS -o /tmp/gui-smoke.out -w '%{http_code}' "$BASE/api/status" | grep -q '^200$'; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "GUI did not become ready on $BASE"
  tail -n 40 "$LOG_TMP" || true
  exit 1
fi

check_get() {
  local path="$1"
  local code
  code="$(curl -sS -o /tmp/gui-smoke.out -w '%{http_code}' "$BASE$path")"
  echo "GET $path -> $code"
  [[ "$code" == "200" ]]
}

check_post() {
  local path="$1"
  local data="${2:-}"
  local code
  if [[ -n "$data" ]]; then
    code="$(curl -sS -o /tmp/gui-smoke.out -w '%{http_code}' -X POST -d "$data" "$BASE$path")"
  else
    code="$(curl -sS -o /tmp/gui-smoke.out -w '%{http_code}' -X POST "$BASE$path")"
  fi
  echo "POST $path -> $code"
  [[ "$code" == "200" ]]
}

# Core tabs/endpoints
check_get "/"
check_get "/api/status"
check_get "/api/startup-check"
check_get "/api/scan-history"
check_get "/api/quick-check"
check_get "/api/events-tail"
check_get "/api/custom-scan"
check_get "/api/auto-protect-preview?profile=monitor"
check_post "/api/lab-generate" "scenario=mixed&count=5"
check_post "/api/lab-analyze"
check_get "/api/lab-timeline"
check_get "/api/quarantine-hashes"
check_get "/api/driver-report"
check_get "/api/log-health"

# Agent logging sanity
check_get "/api/agent"
sleep 2
check_get "/api/log-health"
check_get "/api/events-tail"

echo "GUI smoke check passed."
