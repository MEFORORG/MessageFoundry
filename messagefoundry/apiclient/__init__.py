# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Qt-free, FastAPI-free client library for the MessageFoundry localhost API (ADR 0088).

:class:`EngineClient` is a small, synchronous, typed wrapper over the engine's REST API. It
depends only on ``httpx`` (+ the optional ``truststore`` for OS-trust-store TLS, imported lazily)
and the pure pydantic response models in :mod:`messagefoundry.api.models` /
:mod:`messagefoundry.api.auth_models` — it imports neither PySide6 nor FastAPI, so it is reusable
by the headless load/acceptance harness and any future client without dragging a GUI or the server
into the process. It is the sole engine-client entrypoint since the PySide6 desktop console (and its
``messagefoundry.console.client`` shim) were retired in favour of the web console (BACKLOG #103).
"""

from __future__ import annotations

from messagefoundry.apiclient.client import ApiError, EngineClient

__all__ = ["EngineClient", "ApiError"]
