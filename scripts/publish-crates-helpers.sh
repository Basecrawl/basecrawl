# shellcheck shell=bash
# Shared helpers for ordered crates.io publish with day-0 rate-limit hardening.
#
# Sourced by:
#   - .github/workflows/publish.yml (live/dry cargo publish loop)
#   - scripts/tests/test_publish_crates_helpers.sh (hermetic fixture tests)
#
# Rules:
#   - Never print CARGO_REGISTRY_TOKEN / NPM_TOKEN (secret names and lengths only upstream).
#   - No forced republish of versions already live for the tag/version under upload.
#   - Adaptive wait/retry on HTTP 429 "too many new crates" / "try again after".
#   - "already exists|already uploaded" is a clean continue for re-dispatch after partial upload.

missing_registry_dep() {
  printf '%s\n' "$1" | grep -Eqi 'no matching package named|failed to select a version for the requirement'
}

already_uploaded() {
  printf '%s\n' "$1" | grep -Eqi 'already exists|already uploaded'
}

is_new_crate_rate_limited() {
  # crates.io hobby limit on first-time package *names*, not version bumps of live crates.
  printf '%s\n' "$1" | grep -Eqi \
    'too many new crates|rate limit|HTTP 429|status( code)? 429|error 429|try again after|Retry-After'
}

parse_retry_after_seconds() {
  # Prefer cargo's "try again after <IMF-fix date>" over crude fixed sleeps.
  # Prints integer seconds (>0) or empty if no parseable absolute/relative signal.
  local msg="$1"
  local when epoch_now epoch_when delta
  when="$(
    printf '%s\n' "${msg}" \
      | sed -nE 's/.*try again after[[:space:]]+([A-Za-z]{3},[[:space:]]+[0-9]{1,2}[[:space:]]+[A-Za-z]{3}[[:space:]]+[0-9]{4}[[:space:]]+[0-9:]+[[:space:]]+GMT).*/\1/ip' \
      | head -n1
  )"
  if [[ -n "${when}" ]]; then
    epoch_when="$(date -u -d "${when}" +%s 2>/dev/null || true)"
    epoch_now="$(date -u +%s)"
    if [[ -n "${epoch_when}" && "${epoch_when}" =~ ^[0-9]+$ ]]; then
      delta=$((epoch_when - epoch_now + 5))
      if [[ ${delta} -lt 30 ]]; then
        delta=30
      fi
      printf '%s' "${delta}"
      return 0
    fi
  fi
  when="$(
    printf '%s\n' "${msg}" \
      | sed -nE 's/.*Retry-After:[[:space:]]*([0-9]+).*/\1/ip' \
      | head -n1
  )"
  if [[ -n "${when}" && "${when}" =~ ^[0-9]+$ ]]; then
    printf '%s' "${when}"
    return 0
  fi
  return 0
}

adaptive_rate_limit_sleep_secs() {
  # attempt is 1-based. Cap so a full multi-crate day-0 chain can finish in one GHA job.
  local attempt="$1"
  local base="${NEW_CRATE_RATE_LIMIT_BASE_SECS:-90}"
  local cap="${NEW_CRATE_RATE_LIMIT_CAP_SECS:-720}"
  local exp=1
  local i
  for ((i = 1; i < attempt; i++)); do
    exp=$((exp * 2))
  done
  local secs=$((base * exp))
  if [[ ${secs} -gt ${cap} ]]; then
    secs=${cap}
  fi
  # Floor so short blips still wait for index/limit windows.
  if [[ ${secs} -lt 60 ]]; then
    secs=60
  fi
  printf '%s' "${secs}"
}

crate_version_probe_matches() {
  # Pure classifier for crates.io exact-version JSON fixtures (no network).
  # Args: want_version json_path
  local want="$1"
  local path="$2"
  python3 - "${want}" "${path}" <<'PY'
import json, pathlib, sys
want = sys.argv[1]
path = pathlib.Path(sys.argv[2])
try:
    data = json.loads(path.read_text())
except Exception:
    sys.exit(1)
num = None
if isinstance(data, dict):
    v = data.get("version") or {}
    if isinstance(v, dict):
        num = v.get("num")
if num is None:
    sys.exit(1)
sys.exit(0 if str(num) == want else 1)
PY
}

crate_version_already_on_crates_io() {
  # Polite crates.io API probe (never uses or logs tokens). 200 + matching number → live.
  # Optional CRATES_IO_PROBE_STUB=path/to.json for hermetic tests (skips network).
  local name="$1"
  local ver="$2"
  local probe_file="${CRATES_IO_PROBE_FILE:-/tmp/crates-io-probe.json}"
  local code

  if [[ -n "${CRATES_IO_PROBE_STUB:-}" ]]; then
    if [[ ! -f "${CRATES_IO_PROBE_STUB}" ]]; then
      return 1
    fi
    cp "${CRATES_IO_PROBE_STUB}" "${probe_file}"
    crate_version_probe_matches "${ver}" "${probe_file}"
    return $?
  fi

  code="$(
    curl -sS -o "${probe_file}" -w "%{http_code}" \
      -A "basecrawl-publish-workflow (+https://github.com/BaseIntelligence/basecrawl)" \
      "https://crates.io/api/v1/crates/${name}/${ver}" \
      || true
  )"
  if [[ "${code}" != "200" ]]; then
    return 1
  fi
  crate_version_probe_matches "${ver}" "${probe_file}"
}

compute_live_retry_wait_secs() {
  # Choose wait for a single live 429 attempt: prefer parse_retry_after, else adaptive backoff.
  local msg="$1"
  local attempt="$2"
  local parsed wait_secs cap
  parsed="$(parse_retry_after_seconds "${msg}" || true)"
  if [[ -n "${parsed}" && "${parsed}" =~ ^[0-9]+$ ]]; then
    wait_secs="${parsed}"
    cap="${NEW_CRATE_RATE_LIMIT_CAP_SECS:-720}"
    if [[ ${wait_secs} -gt ${cap} ]]; then
      wait_secs=${cap}
    fi
    printf '%s' "${wait_secs}"
    return 0
  fi
  adaptive_rate_limit_sleep_secs "${attempt}"
}
