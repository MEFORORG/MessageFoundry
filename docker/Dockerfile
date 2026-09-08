# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
# syntax=docker/dockerfile:1
#
# MessageFoundry headless ENGINE image (ADR 0017 "container fast-follow").
#
# This image is the headless ENGINE only: a pure asyncio/uvicorn/SQLite service with no GUI dependency
# (see docs/CONTAINER-EXPOSURE-EVALUATION.md). The browser ops console is a separately-versioned optional
# wheel (messagefoundry-webconsole) that is NOT installed here, so a container serve soft-degrades to the
# JSON API only with a warning (ADR 0143). PySide6 is never in the image either — it now backs only the
# standalone test harness, a host-side GUI client that reaches the engine over the HTTP API.
#
# Build the slim default (core + SQLite store):
#     docker build -f docker/Dockerfile -t messagefoundry .
# Build the SQL Server variant (adds the OS-level MS ODBC Driver 18 + the [sqlserver] extra, for the
# SQL Server store OR the DATABASE / db_lookup connectors):
#     docker build -f docker/Dockerfile --target runtime-sqlserver -t messagefoundry:sqlserver .
#
# Both install from per-profile, hash-locked requirements (docker/locks/*.lock) — NOT the all-extras
# requirements.lock, which would drag the harness's PySide6 + dev tools into a runtime image. The locks
# are kept in sync with uv.lock by the DEP-1 step in .github/workflows/security.yml.

# Pinned to Debian 12 "bookworm": a mature base whose Microsoft ODBC repo (the -sqlserver variant) is
# well-supported. Debian 13 "trixie" signs its MS repo with a key absent from the legacy microsoft.asc
# bundle, which trixie's strict `sqv` then rejects — bookworm avoids that. Bump deliberately, not by
# floating the tag. (For stronger supply-chain integrity, pin by digest: python:3.14-slim-bookworm@sha256:…)
ARG PYTHON_VERSION=3.14
ARG DEBIAN_RELEASE=bookworm

# ---- builder-base: build the engine wheel from source (shared by both profiles) ------------------
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS builder-base
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /src
# Only what the wheel build needs (version is single-sourced from messagefoundry/__init__.py; PEP 639
# license-files are LICENSE + NOTICE). Copying these before the package keeps the layer cache warm.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY messagefoundry ./messagefoundry
# Use the base image's bundled pip (don't fetch an unpinned pip into the hash-locked build path).
RUN python -m pip install build \
 && python -m build --wheel --outdir /wheels .

# ---- builder (core / SQLite): venv = core deps (hash-locked) + the engine wheel ------------------
FROM builder-base AS builder
COPY docker/locks/requirements-core.lock /tmp/req.lock
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes -r /tmp/req.lock \
 && /opt/venv/bin/pip install --no-deps /wheels/messagefoundry-*.whl

# ---- builder-sqlserver: venv = core+sqlserver deps (hash-locked) + the engine wheel --------------
FROM builder-base AS builder-sqlserver
COPY docker/locks/requirements-sqlserver.lock /tmp/req.lock
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes -r /tmp/req.lock \
 && /opt/venv/bin/pip install --no-deps /wheels/messagefoundry-*.whl

# ---- runtime-base: hardened common runtime (no venv yet — copied by the final stages) ------------
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS runtime-base
# tini = a real PID 1 that forwards SIGTERM, so `docker stop` triggers uvicorn's graceful shutdown ->
# the ASGI lifespan -> engine.stop() (drains MLLP clients within _CLIENT_SHUTDOWN_GRACE). Without it a
# shell PID 1 would swallow SIGTERM and the stop would be ungraceful. curl = the HEALTHCHECK probe.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini curl \
 && rm -rf /var/lib/apt/lists/*
# Non-root, fixed UID. /var/lib/mefor is the ONLY path the engine writes under a read-only root fs:
# the SQLite store lives there, and WAL writes -wal/-shm SIBLING files next to the DB, so it must be a
# writable DIRECTORY (a single writable file mount is not enough). /config is the read-only config-repo
# mount. Everything else stays read-only; /tmp is provided as a tmpfs at run time.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin mefor \
 && mkdir -p /var/lib/mefor /config \
 && chown -R 10001:10001 /var/lib/mefor /config
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Absolute store path on the writable volume — independent of WORKDIR, so a read-only root fs is fine.
    MEFOR_STORE_PATH=/var/lib/mefor/messagefoundry.db \
    # Anchor per-environment env() value files at the mounted config repo (env()s resolve under
    # /config/environments/<env>.toml) regardless of WORKDIR — avoids silently-empty env() values.
    MEFOR_ENVIRONMENTS_BASE_DIR=/config
# WORKDIR is writable so a relative File-output / store path still lands on the volume, not a read-only layer.
WORKDIR /var/lib/mefor
USER 10001
# API (in-process TLS / plaintext-behind-proxy) + MLLP data plane. Documentation only; publish per topology.
EXPOSE 8443 8765 2575
# Liveness probe: GET /health is tokenless and always 200 (it answers even before the engine finishes
# starting, so it is a pure liveness signal, not readiness; there is no unauthenticated readiness
# endpoint).
#
# ONE ARM, https ONLY. There is deliberately NO cleartext fallback: it would downgrade the probe to
# http on any TLS failure, so a container with broken TLS still reported healthy. Why that is a
# defect on a shipped artifact is recorded once, in BACKLOG #1179.
#
# PORT: this reads ONE of the four precedence layers. load_settings resolves CLI > env > file >
# default; the probe reads MEFOR_API_PORT (the env override for [api].port) and falls back to the
# engine's own default, 8765. compose and docker/k8s/*.yaml both move the port to 8443 that way, so
# the probe follows them. THE OTHER TWO LAYERS ARE INVISIBLE TO IT: `serve --port 9443` in an
# overridden command, or [api].port in the mounted /config, leaves a working engine behind a
# permanently failing probe. Move the port either of those ways and override this HEALTHCHECK too
# (a compose `healthcheck:` block, or `docker run --health-cmd`). Under `supervise --shards` each
# shard binds <base>+offset, so this probe covers the base shard only. The k8s manifests declare
# their own probe and never consult this one.
#
# -k IS NOT THE FALLBACK. Since ADR 0172 an engine with no configured certificate mints a
# self-signed pair and serves https, so the container presents an untrusted cert on its own
# loopback. -k skips VERIFICATION on a hop that never leaves the container's network namespace; it
# does not skip encryption and it cannot reach a cleartext socket.
#
# NOT COVERED, deliberately: [api].tls_terminated_upstream, where a proxy terminates TLS in front
# and the engine speaks plaintext to it. ADR 0172 mints nothing there, so that deployment must
# override this HEALTHCHECK rather than have the image infer a plaintext hop from a TLS failure.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS -k "https://127.0.0.1:${MEFOR_API_PORT:-8765}/health" || exit 1
# tini reaps + forwards signals; `messagefoundry` is the engine CLI. Default prints serve usage; real
# deployments override the command, e.g.:  serve --config /config --env prod
ENTRYPOINT ["tini", "--", "messagefoundry"]
CMD ["serve", "--help"]

# ---- runtime-sqlserver: the default runtime + the OS-level Microsoft ODBC Driver 18 -------------
# pyodbc (pulled transitively by the [sqlserver] extra's aioodbc) needs the OS-level msodbcsql18 +
# unixODBC, which are NOT pip-installable. Same Microsoft apt repo the CI sql-server leg and
# scripts/dev/sqlserver-docker.ps1 use. Only adopters using the SQL Server store or the DATABASE /
# db_lookup connectors need this variant; the slim default avoids the Microsoft EULA layer + bloat.
FROM runtime-base AS runtime-sqlserver
USER root
# The prod.list pins `signed-by=/usr/share/keyrings/microsoft-prod.gpg`, so the key must be DEARMORED
# to exactly that path (a key in trusted.gpg.d is ignored when signed-by is set; modern apt's `sqv`
# then can't verify the repo). $VERSION_ID resolves to the pinned Debian release (12).
# curl comes from runtime-base; gnupg is only needed to dearmor the key, so purge it afterward to keep
# it out of the final image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends gnupg ca-certificates \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
 && curl -fsSL "https://packages.microsoft.com/config/debian/$(. /etc/os-release; echo "$VERSION_ID")/prod.list" \
      -o /etc/apt/sources.list.d/mssql-release.list \
 && apt-get update \
 && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 unixodbc \
 && apt-get purge -y gnupg && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder-sqlserver --chown=10001:10001 /opt/venv /opt/venv
USER 10001

# ---- runtime (slim default) — LAST stage, so a bare `docker build` produces the slim image -------
FROM runtime-base AS runtime
COPY --from=builder --chown=10001:10001 /opt/venv /opt/venv
