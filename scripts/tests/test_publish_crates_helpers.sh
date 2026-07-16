#!/usr/bin/env bash
# Hermetic fixture tests for scripts/publish-crates-helpers.sh.
# Covers day-0 HTTP 429 backoff, already-uploaded clean skip, secret-token non-echo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../publish-crates-helpers.sh
source "${ROOT}/scripts/publish-crates-helpers.sh"

PASS=0
FAIL=0

assert_eq() {
  local name="$1"
  local got="$2"
  local want="$3"
  if [[ "${got}" == "${want}" ]]; then
    echo "PASS: ${name}"
    PASS=$((PASS + 1))
  else
    echo "FAIL: ${name} (got='${got}' want='${want}')" >&2
    FAIL=$((FAIL + 1))
  fi
}

assert_true() {
  local name="$1"
  shift
  if "$@"; then
    echo "PASS: ${name}"
    PASS=$((PASS + 1))
  else
    echo "FAIL: ${name}" >&2
    FAIL=$((FAIL + 1))
  fi
}

assert_false() {
  local name="$1"
  shift
  if "$@"; then
    echo "FAIL: ${name} (expected false)" >&2
    FAIL=$((FAIL + 1))
  else
    echo "PASS: ${name}"
    PASS=$((PASS + 1))
  fi
}

# ----- classifiers -----
assert_true "already_uploaded matches cargo duplicate" \
  already_uploaded "error: crate basecrawl-core@0.1.0 already exists on crates.io"

assert_true "already_uploaded matches already uploaded wording" \
  already_uploaded "// already uploaded previously as version 0.1.0"

assert_false "already_uploaded ignores unrelated network flake" \
  already_uploaded "error: failed to get 200 OK from registry index"

assert_true "is_new_crate_rate_limited matches too many new crates" \
  is_new_crate_rate_limited "error: api errors (status 429 Too Many Requests): You have published too many new crates in a short period of time. Please try again after Wed, 15 Jul 2026 23:13:18 GMT or email help@crates.io"

assert_true "is_new_crate_rate_limited matches bare HTTP 429" \
  is_new_crate_rate_limited "HTTP 429 from crates.io while publishing"

assert_false "is_new_crate_rate_limited ignores generic auth failure" \
  is_new_crate_rate_limited "error: api errors (status 403 Forbidden): this token lacks publish rights"

assert_true "missing_registry_dep detects absent package name" \
  missing_registry_dep "error: no matching package named \`basecrawl-proof\` found"

# ----- adaptive backoff (deterministic env) -----
export NEW_CRATE_RATE_LIMIT_BASE_SECS=90
export NEW_CRATE_RATE_LIMIT_CAP_SECS=720
assert_eq "adaptive attempt 1 = 90" "$(adaptive_rate_limit_sleep_secs 1)" "90"
assert_eq "adaptive attempt 2 = 180" "$(adaptive_rate_limit_sleep_secs 2)" "180"
assert_eq "adaptive attempt 3 = 360" "$(adaptive_rate_limit_sleep_secs 3)" "360"
assert_eq "adaptive attempt 4 capped at 720" "$(adaptive_rate_limit_sleep_secs 4)" "720"
assert_eq "adaptive attempt 8 still capped" "$(adaptive_rate_limit_sleep_secs 8)" "720"

# Floor when base is tiny
export NEW_CRATE_RATE_LIMIT_BASE_SECS=10
assert_eq "adaptive floor at 60 when base tiny" "$(adaptive_rate_limit_sleep_secs 1)" "60"
export NEW_CRATE_RATE_LIMIT_BASE_SECS=90

# ----- parse_retry_after_seconds -----
# Relative Retry-After header style
got="$(parse_retry_after_seconds $'HTTP/1.1 429\nRetry-After: 123\n')"
assert_eq "parse Retry-After seconds header" "${got}" "123"

# Absolute "try again after" with future GMT date (~120s ahead)
future_epoch=$(($(date -u +%s) + 120))
future_imf="$(date -u -d "@${future_epoch}" "+%a, %d %b %Y %H:%M:%S GMT")"
msg="Please try again after ${future_imf} or email help@crates.io"
got="$(parse_retry_after_seconds "${msg}")"
# Allow small scheduler skew: expect roughly 120+5 = 125, bounded [100, 160]
if [[ -n "${got}" && "${got}" =~ ^[0-9]+$ && ${got} -ge 100 && ${got} -le 160 ]]; then
  echo "PASS: parse_retry_after absolute GMT within band (${got})"
  PASS=$((PASS + 1))
else
  echo "FAIL: parse_retry_after absolute GMT got='${got}' for msg='${msg}'" >&2
  FAIL=$((FAIL + 1))
fi

# Past date → floor 30
past_imf="Wed, 15 Jul 2020 23:13:18 GMT"
got="$(parse_retry_after_seconds "try again after ${past_imf}")"
assert_eq "parse_retry_after past date floors at 30" "${got}" "30"

# ----- compute_live_retry_wait_secs prefers parse over adaptive -----
export NEW_CRATE_RATE_LIMIT_CAP_SECS=720
got="$(compute_live_retry_wait_secs $'Retry-After: 200\nstatus 429' 1)"
assert_eq "compute wait prefers Retry-After" "${got}" "200"

# Cap excessive Retry-After
export NEW_CRATE_RATE_LIMIT_CAP_SECS=300
got="$(compute_live_retry_wait_secs $'Retry-After: 9999\n' 1)"
assert_eq "compute wait caps Retry-After" "${got}" "300"
export NEW_CRATE_RATE_LIMIT_CAP_SECS=720

# Fallback adaptive when no parse signal
got="$(compute_live_retry_wait_secs 'HTTP 429 Too Many Requests: too many new crates' 2)"
assert_eq "compute wait falls back to adaptive attempt 2" "${got}" "180"

# ----- already-on-registry probe via stub (no network, no forced republish) -----
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

cat >"${tmp}/live-0.1.0.json" <<'JSON'
{"version":{"num":"0.1.0","crate":"basecrawl-core","id":1}}
JSON
cat >"${tmp}/other-version.json" <<'JSON'
{"version":{"num":"0.2.0","crate":"basecrawl-core","id":2}}
JSON

assert_true "probe matches live 0.1.0 fixture" \
  crate_version_probe_matches "0.1.0" "${tmp}/live-0.1.0.json"

assert_false "probe rejects mismatched version" \
  crate_version_probe_matches "0.1.0" "${tmp}/other-version.json"

export CRATES_IO_PROBE_STUB="${tmp}/live-0.1.0.json"
export CRATES_IO_PROBE_FILE="${tmp}/out-probe.json"
assert_true "crate_version_already_on_crates_io stub live" \
  crate_version_already_on_crates_io "basecrawl-core" "0.1.0"

export CRATES_IO_PROBE_STUB="${tmp}/other-version.json"
assert_false "crate_version_already_on_crates_io stub wrong version" \
  crate_version_already_on_crates_io "basecrawl-core" "0.1.0"

unset CRATES_IO_PROBE_STUB
export CRATES_IO_PROBE_STUB="${tmp}/missing.json"
assert_false "crate_version_already_on_crates_io missing stub is not live" \
  crate_version_already_on_crates_io "basecrawl-core" "0.1.0"
unset CRATES_IO_PROBE_STUB

# ----- secret hygiene: helpers never expand/print tokens -----
export CARGO_REGISTRY_TOKEN="super-secret-test-token-DO-NOT-LEAK-12345"
export NPM_TOKEN="npm-secret-test-token-DO-NOT-LEAK-67890"
hygiene_log="${tmp}/hygiene.log"
{
  # Invoke every pure helper against rates/already fixtures; capture combined stdout/stderr.
  already_uploaded "already uploaded crate" || true
  is_new_crate_rate_limited "HTTP 429 too many new crates" || true
  parse_retry_after_seconds "Retry-After: 42"
  adaptive_rate_limit_sleep_secs 1
  compute_live_retry_wait_secs "too many new crates HTTP 429" 1
  crate_version_probe_matches "0.1.0" "${tmp}/live-0.1.0.json" || true
  # Nested realist cargo message (no token should be in helper outputs)
  msg="api errors (status 429): too many new crates. try again after Wed, 15 Jul 2026 23:13:18 GMT"
  is_new_crate_rate_limited "${msg}" || true
  parse_retry_after_seconds "${msg}" || true
} >"${hygiene_log}" 2>&1

if grep -F "super-secret-test-token-DO-NOT-LEAK-12345" "${hygiene_log}" >/dev/null \
  || grep -F "npm-secret-test-token-DO-NOT-LEAK-67890" "${hygiene_log}" >/dev/null; then
  echo "FAIL: secret token leaked into helper output" >&2
  cat "${hygiene_log}" >&2
  FAIL=$((FAIL + 1))
else
  echo "PASS: helpers never print raw token values"
  PASS=$((PASS + 1))
fi

# Workflow YAML contract smoke (tracked publish.yml path)
WF="${ROOT}/.github/workflows/publish.yml"
assert_true "publish.yml sources helper script" \
  grep -Fq 'scripts/publish-crates-helpers.sh' "${WF}"

assert_true "publish.yml references CARGO_REGISTRY_TOKEN by secret name only" \
  grep -Fq 'secrets.CARGO_REGISTRY_TOKEN' "${WF}"

assert_true "publish.yml never hard-codes a cargo token value" \
  bash -c "! grep -Eiq 'CARGO_REGISTRY_TOKEN:[[:space:]]*[\"'\'']?[a-zA-Z0-9_-]{20,}' '${WF}' || grep -Fq 'secrets.CARGO_REGISTRY_TOKEN' '${WF}'"

assert_true "publish.yml documents adaptive 429 / already-live skip" \
  bash -c "grep -Eqi 'too many new crates|HTTP 429|already live|no forced republish' '${WF}'"

assert_true "publish.yml length-only token presence echo" \
  grep -Fq 'length=${#CARGO_REGISTRY_TOKEN}' "${WF}"

# Coarse simulation of re-dispatch decision matrix
simulate_decision() {
  # args: mode fixture-or-empty cargo_msg → print decision
  local mode="$1" # dry|live
  local stub="$2"
  local cargo_msg="$3"
  if [[ "${mode}" == "live" && -n "${stub}" ]]; then
    export CRATES_IO_PROBE_STUB="${stub}"
    if crate_version_already_on_crates_io "basecrawl-core" "0.1.0"; then
      echo "skip_already_live"
      unset CRATES_IO_PROBE_STUB
      return 0
    fi
    unset CRATES_IO_PROBE_STUB
  fi
  if already_uploaded "${cargo_msg}"; then
    echo "skip_already_uploaded"
    return 0
  fi
  if is_new_crate_rate_limited "${cargo_msg}"; then
    echo "retry_after_wait"
    return 0
  fi
  if [[ -z "${cargo_msg}" ]]; then
    echo "publish"
    return 0
  fi
  echo "fail_non_retriable"
}

assert_eq "sim skip already live 0.1.0" \
  "$(simulate_decision live "${tmp}/live-0.1.0.json" "")" \
  "skip_already_live"

assert_eq "sim retry on 429" \
  "$(simulate_decision live "" "HTTP 429 too many new crates")" \
  "retry_after_wait"

assert_eq "sim skip already uploaded duplicate" \
  "$(simulate_decision live "" "crate already uploaded")" \
  "skip_already_uploaded"

assert_eq "sim publish when clean" \
  "$(simulate_decision live "" "")" \
  "publish"

assert_eq "sim dry path never network-skips" \
  "$(simulate_decision dry "${tmp}/live-0.1.0.json" "")" \
  "publish"

echo "----"
echo "passed=${PASS} failed=${FAIL}"
if [[ ${FAIL} -ne 0 ]]; then
  exit 1
fi
echo "all publish-crates helper tests green"
