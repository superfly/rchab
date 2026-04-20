#!/bin/bash
set -euo pipefail

# tier3/04-buildpacks-matrix.sh — Run `pack build` through a local rchab
# container for a given (builder, fixture) pair. Intended to be invoked from a
# CI matrix row or locally with env vars set.
#
# Inputs (env vars):
#   IMAGE           — rchab image tag to use (default: flyio/rchab:test)
#   BUILDER         — CNB builder image, e.g. heroku/builder:24
#   FIXTURE_DIR     — absolute path to one of tests/fixtures/buildpacks/<lang>/
#   RUNTIME_VERSION — version string substituted into *.tmpl files
#   EXPECT_FAIL     — when set to 1, a failing `pack build` exits 0 with a
#                     "still broken" banner. If it *succeeds* while marked
#                     EXPECT_FAIL=1, we exit 5 (non-zero) so the matrix row
#                     surfaces as red and someone updates the matrix config
#                     to drop the expected-fail marker.
#
# Exit codes:
#   0  expected outcome (success when EXPECT_FAIL=0, failure when EXPECT_FAIL=1)
#   2  invalid inputs (missing fixture dir or pack CLI)
#   3  rchab container didn't come up
#   4  pack build produced an image without an entrypoint/cmd
#   5  unexpected success (pack succeeded on a row marked EXPECT_FAIL=1)
#   *  pack exit code on an unexpected failure

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

IMAGE="${IMAGE:-flyio/rchab:test}"
BUILDER="${BUILDER:?BUILDER env var is required}"
FIXTURE_DIR="${FIXTURE_DIR:?FIXTURE_DIR env var is required}"
RUNTIME_VERSION="${RUNTIME_VERSION:?RUNTIME_VERSION env var is required}"
EXPECT_FAIL="${EXPECT_FAIL:-0}"

if [[ ! -d "${FIXTURE_DIR}" ]]; then
  echo "FIXTURE_DIR does not exist: ${FIXTURE_DIR}" >&2
  exit 2
fi

if ! command -v pack >/dev/null 2>&1; then
  echo "pack CLI not found on PATH. Install via buildpacks/github-actions/setup-pack or https://buildpacks.io/docs/install-pack/" >&2
  exit 2
fi

SCRATCH="$(mktemp -d)"
trap 'rm -rf "${SCRATCH}"' EXIT

# Copy fixture, rendering .tmpl files with envsubst-style substitution.
# We intentionally only substitute ${RUNTIME_VERSION} to avoid accidentally
# expanding things like ${PORT:-3000} inside Procfile, which must stay literal.
render_fixture() {
  local src="$1"
  local dst="$2"
  local f
  while IFS= read -r -d '' f; do
    local rel="${f#${src}/}"
    local out_path="${dst}/${rel}"
    mkdir -p "$(dirname "${out_path}")"
    if [[ "${rel}" == *.tmpl ]]; then
      # Drop .tmpl suffix
      out_path="${dst}/${rel%.tmpl}"
      sed "s|\${RUNTIME_VERSION}|${RUNTIME_VERSION}|g" "${f}" >"${out_path}"
    else
      cp "${f}" "${out_path}"
    fi
  done < <(find "${src}" -type f -print0)
}

render_fixture "${FIXTURE_DIR}" "${SCRATCH}"

echo "=== tier3/04-buildpacks-matrix ==="
echo "  image:   ${IMAGE}"
echo "  builder: ${BUILDER}"
echo "  fixture: ${FIXTURE_DIR}"
echo "  runtime: ${RUNTIME_VERSION}"
echo "  expect_fail: ${EXPECT_FAIL}"
echo

# Dump rchab logs on any failure path.
# Also tee to a file under /tmp so CI can upload them as artifacts.
LOG_FILE="/tmp/rchab-test-$(echo "${BUILDER}-${RUNTIME_VERSION}" | tr '/:.' '___').log"
dump_logs() {
  if is_container_running; then
    echo
    echo "--- rchab container logs (last 200 lines) ---"
    docker logs --tail 200 rchab-test 2>&1 | tee "${LOG_FILE}" || true
    echo "----------------------------------------------"
    echo "Full logs written to ${LOG_FILE}"
  fi
}

# Teardown whether we fail or succeed
cleanup() {
  stop_rchab_container
  rm -rf "${SCRATCH}"
}
trap cleanup EXIT

# Start fresh: ensure no leftover container
stop_rchab_container 2>/dev/null || true

start_rchab_container "${IMAGE}"

# Sanity-ping the proxy so we fail fast if rchab didn't come up.
if ! curl -sf --max-time 10 http://127.0.0.1:2375/v1.44/version >/dev/null; then
  echo "rchab did not respond on 127.0.0.1:2375" >&2
  dump_logs
  exit 3
fi

TAG="rchab-buildpacks-test:${RUNTIME_VERSION}-$$"
PACK_STATUS=0
DOCKER_HOST=tcp://127.0.0.1:2375 pack build "${TAG}" \
  --builder "${BUILDER}" \
  --path "${SCRATCH}" \
  --pull-policy if-not-present \
  --trust-extra-buildpacks || PACK_STATUS=$?

if [[ ${PACK_STATUS} -eq 0 ]]; then
  # pack succeeded — verify the image has an entrypoint/cmd and clean up tag
  ENTRY="$(DOCKER_HOST=tcp://127.0.0.1:2375 docker inspect --format '{{.Config.Entrypoint}} {{.Config.Cmd}}' "${TAG}" 2>/dev/null || true)"
  if [[ -z "${ENTRY}" || "${ENTRY}" == "[] []" || "${ENTRY}" == "<no value>" ]]; then
    echo "pack build succeeded but image ${TAG} has no entrypoint/cmd" >&2
    dump_logs
    exit 4
  fi

  if [[ "${EXPECT_FAIL}" == "1" ]]; then
    echo
    echo "🎉 UNEXPECTED SUCCESS: builder=${BUILDER} runtime=${RUNTIME_VERSION} was marked EXPECT_FAIL=1 but pack build succeeded."
    echo "Remove the expected-fail marker for this matrix row."
    # Exit non-zero so CI surfaces the change. The row moved from 'broken' to
    # 'works' and the matrix config hasn't caught up.
    exit 5
  fi

  echo
  echo "✓ pack build succeeded: ${BUILDER} / runtime=${RUNTIME_VERSION}"
  echo "  image: ${TAG}"
  echo "  entrypoint/cmd: ${ENTRY}"
  exit 0
else
  if [[ "${EXPECT_FAIL}" == "1" ]]; then
    echo
    echo "⚠️  EXPECTED FAILURE: builder=${BUILDER} runtime=${RUNTIME_VERSION} failed as predicted (pack exit=${PACK_STATUS})."
    echo "This row is marked EXPECT_FAIL=1 — treat as informational."
    exit 0
  fi

  echo
  echo "✗ pack build FAILED: ${BUILDER} / runtime=${RUNTIME_VERSION} (pack exit=${PACK_STATUS})"
  dump_logs
  exit "${PACK_STATUS}"
fi
