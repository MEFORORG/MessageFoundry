# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
# syntax=docker/dockerfile:1
#
# TEST-ONLY smoke image: the runtime engine image + a baked minimal config and a self-contained MLLP
# sender. This is NOT the shipped image — production mounts config read-only; here we COPY it so the
# config dir is root-owned mode 0755 (the engine refuses a group/world-writable config source, which a
# Docker-Desktop bind mount surfaces as 0o777). Built by the docker-smoke CI leg on top of the real image:
#     docker build -f docker/Dockerfile -t messagefoundry:ci .
#     docker build -f docker/smoke/Dockerfile --build-arg BASE=messagefoundry:ci -t messagefoundry:smoke .

ARG BASE=messagefoundry:ci
FROM ${BASE}
# COPY (not mount), owned by the engine's UID and mode 0755. _assert_safe_config_source refuses a
# config dir/module that is group/world-writable OR owned by a different uid than the engine process
# (it executes the *.py as the service account) — so the ownership must be 10001, not root. This is
# also the recommended PRODUCTION pattern: bake the adopter config repo into a derived image rather
# than bind-mounting (a bind mount must itself be owned by uid 10001 and not group/world-writable).
COPY --chown=10001:10001 docker/smoke/config /config
COPY --chown=10001:10001 docker/smoke/send_adt.py /smoke/send_adt.py
