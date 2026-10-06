# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
# COPY (not mount), ROOT-owned, so this leg runs the layout docker/README.md recommends: the engine
# (uid 10001) executes a config its own account cannot rewrite. _assert_safe_config_source trusts an
# owner that is root or the engine's uid and refuses a group/world-writable one (vault BACKLOG #2759).
COPY docker/smoke/config /config
COPY --chown=10001:10001 docker/smoke/send_adt.py /smoke/send_adt.py
