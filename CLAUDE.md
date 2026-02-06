# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is rchab?

**Remote Controlled Hot Air Balloon** — a Docker proxy that provides remote Docker build infrastructure for Fly.io. When users run `flyctl deploy --remote-only`, flyctl provisions an rchab instance as the organization's remote builder. It runs inside a Fly Machine, managing its own Docker daemon and exposing a proxied Docker API with auth and storage management.

## Architecture

The application has two main layers:

1. **Container (root level)** — Dockerfile builds a multi-stage image based on `docker:25.0.5-alpine3.20`. It bundles dockerd, buildx, overlaybd (accelerated container images), and the Go proxy binary. The entrypoint runs `docker-entrypoint.d/` scripts (Docker data dir setup, sysctl tuning) then starts the proxy.

2. **`dockerproxy/` (Go application)** — An HTTP reverse proxy that sits in front of dockerd. All source files are in a single flat package (`package main`):
   - `main.go` — HTTP server setup, reverse proxy to dockerd (`localhost:2376`), auto-shutdown idle timer, path filtering, middleware chain (logging → HTTPS upgrade → auth → handler)
   - `auth.go` — Bearer token auth against the Fly API; validates the requesting app belongs to the same org as the builder. Results are cached with `go-cache`.
   - `dockerd.go` — Launches and manages the dockerd process, health-checks it, watches for active builds (Docker containers + buildkit/runc processes) to keep the machine alive.
   - `storage.go` — Disk space monitoring and Docker pruning (images, volumes, build cache) when usage exceeds thresholds.
   - `overlaybd.go` — Handler for converting Docker images to overlaybd format.
   - `error.go` / `error_test.go` — Insufficient storage error helper.

**Key HTTP endpoints:**
- `/` — Reverse proxy to dockerd (filtered by `allowedPaths` regex list, though filtering is currently disabled via `noFilter = true`)
- `/flyio/v1/extendDeadline` — Extends the auto-shutdown timer, prunes if storage is low
- `/flyio/v1/prune` — Triggers Docker resource pruning
- `/flyio/v1/buildOverlaybdImage` — Converts images to overlaybd format
- `/flyio/v1/settings` — Returns builder capabilities

**Two HTTP servers run simultaneously:**
- `:8080` — Public-facing with auth + HTTPS middleware (fronted by Fly's proxy)
- `:2375` — Raw Docker proxy (no auth, used over 6PN internal network)

**Auto-shutdown:** The machine shuts itself down after 10 minutes of inactivity. Active Docker containers and buildkit (runc) processes reset the timer.

## Build & Development Commands

### Local development (requires Vagrant — manages its own Docker daemon)
```shell
vagrant up              # provision VM with Docker + Go
vagrant ssh
cd rchab
make run-local-no-auth  # run without auth (for local testing)
```

### Build Docker image
```shell
make build-docker                # build locally (linux/amd64)
make build-and-push-docker       # build and push to flyio/rchab registry
```

### Run Go tests
```shell
cd dockerproxy && go test ./...
```

### Test with flyctl locally
```shell
FLY_REMOTE_BUILDER_HOST_WG=1 FLY_RCHAB_OVERRIDE_HOST=tcp://127.0.0.1:2375 LOG_LEVEL=debug fly deploy --remote-only
```

### Test with an organization
```shell
fly orgs builder update <your_org> <image_ref>
```

## Environment Variables

| Variable | Purpose |
|---|---|
| `NO_DOCKERD` | Skip launching dockerd (use existing) |
| `NO_AUTH` | Disable auth middleware |
| `NO_APP_NAME` | Skip org membership check |
| `NO_HTTPS` | Disable HTTPS redirect |
| `LOG_LEVEL` | Logrus log level (default: `info`) |
| `FLY_APP_NAME` | Builder's own app name (set by Fly runtime) |
| `DATA_DIR` | Data directory path |

## CI/CD

GitHub Actions (`.github/workflows/ci.yaml`) builds and pushes the Docker image to DockerHub (`flyio/rchab`) on every branch push and tag. PRs only build without pushing. Fly.io staff must make an internal update for the new image to become the default builder.

## Key Dependencies

- Go 1.21, Docker 24.0.7
- `github.com/superfly/flyctl/api` — Fly API client for auth
- `github.com/gorilla/handlers` — HTTP logging middleware
- `github.com/minio/minio/pkg/disk` — Disk usage info
- `github.com/patrickmn/go-cache` — In-memory auth cache
- `github.com/mitchellh/go-ps` — Process listing (buildkit detection)
