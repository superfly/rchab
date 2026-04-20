#!/bin/bash
set -euo pipefail

# test-buildpacks-deploy.sh — Create a minimal Rack app and optionally deploy it
# via flyctl deploy --remote-only to test buildpacks with rchab.
#
# Usage:
#   ./test-buildpacks-deploy.sh [options]
#
# Options:
#   --deploy            Run flyctl deploy --remote-only against local rchab
#   --builder <image>   Builder image (default: heroku/builder:24)
#   --app-name <name>   Fly app name (default: buildpacks-test)
#   --outdir <path>     Output directory (default: /tmp/rchab-buildpacks-test-<timestamp>)
#   --cleanup           Remove temp dir after deploy

BUILDER="heroku/builder:24"
APP_NAME="buildpacks-test"
OUTDIR=""
DEPLOY=false
CLEANUP=false
FLY="fly"

while [[ $# -gt 0 ]]; do
  case "$1" in
  --deploy)
    DEPLOY=true
    shift
    ;;
  --builder)
    BUILDER="$2"
    shift 2
    ;;
  --app-name)
    APP_NAME="$2"
    shift 2
    ;;
  --outdir)
    OUTDIR="$2"
    shift 2
    ;;
  --fly)
    FLY="$2"
    shift 2
    ;;
  --cleanup)
    CLEANUP=true
    shift
    ;;
  -h | --help)
    sed -n '3,/^$/s/^# \?//p' "$0"
    exit 0
    ;;
  *)
    echo "Unknown option: $1" >&2
    exit 1
    ;;
  esac
done

if [[ -z "$OUTDIR" ]]; then
  OUTDIR="/tmp/rchab-buildpacks-test-$(date +%s)"
fi

echo "=== Buildpacks Deploy Test ==="
echo "Builder:  ${BUILDER}"
echo "App name: ${APP_NAME}"
echo "Output:   ${OUTDIR}"
echo "Fly:      ${FLY}"
echo ""

mkdir -p "${OUTDIR}"

# --- Gemfile ---
cat >"${OUTDIR}/Gemfile" <<'EOF'
source 'https://rubygems.org'

ruby '~> 3.3'

gem 'rack', '~> 3.0'
gem 'puma', '~> 6.4'
gem 'rackup', '~> 2.1'
EOF

# --- Gemfile.lock ---
# Pre-generated so the script has zero external dependencies (no Ruby/bundler needed).
cat >"${OUTDIR}/Gemfile.lock" <<'EOF'
GEM
  remote: https://rubygems.org/
  specs:
    nio4r (2.7.0)
    puma (6.4.3)
      nio4r (~> 2.0)
    rack (3.0.11)
    rackup (2.1.0)
      rack (>= 3)
      webrick (~> 1.8)
    webrick (1.8.2)

PLATFORMS
  ruby

DEPENDENCIES
  puma (~> 6.4)
  rack (~> 3.0)
  rackup (~> 2.1)

RUBY VERSION
   ruby 3.3.5p100

BUNDLED WITH
   2.5.6
EOF

# --- config.ru ---
cat >"${OUTDIR}/config.ru" <<'RUBY'
app = proc do |_env|
  [200, { 'content-type' => 'text/plain' }, ["Hello from buildpacks test\n"]]
end

run app
RUBY

# --- Procfile ---
cat >"${OUTDIR}/Procfile" <<'EOF'
web: bundle exec puma -p ${PORT:-3000}
EOF

# --- fly.toml ---
cat >"${OUTDIR}/fly.toml" <<EOF
app = '${APP_NAME}'
primary_region = 'iad'

[build]
  builder = '${BUILDER}'
  buildpacks = ['heroku/ruby']

[env]
  PORT = "3000"

[http_service]
  internal_port = 3000
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 0
EOF

echo "Created app files:"
ls -1 "${OUTDIR}"
echo ""

if [[ "$DEPLOY" == true ]]; then
  echo "Deploying via flyctl deploy --remote-only..."
  echo ""
  (
    cd "${OUTDIR}"
    FLY_REMOTE_BUILDER_HOST_WG=1 \
      FLY_RCHAB_OVERRIDE_HOST=tcp://127.0.0.1:2375 \
      LOG_LEVEL=debug \
      $FLY deploy --remote-only
  )
else
  echo "To deploy against local rchab, run:"
  echo ""
  echo "  cd ${OUTDIR}"
  echo "  FLY_REMOTE_BUILDER_HOST_WG=1 FLY_RCHAB_OVERRIDE_HOST=tcp://127.0.0.1:2375 LOG_LEVEL=debug fly deploy --remote-only"
  echo ""
  echo "Or re-run this script with --deploy."
fi

if [[ "$CLEANUP" == true ]]; then
  echo ""
  echo "Cleaning up ${OUTDIR}..."
  rm -rf "${OUTDIR}"
fi
