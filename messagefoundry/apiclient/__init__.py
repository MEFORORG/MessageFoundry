# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Qt-free, FastAPI-free client library for the MessageFoundry localhost API (ADR 0088).

:class:`EngineClient` is a small, synchronous, typed wrapper over the engine's REST API. It
depends only on ``httpx`` (+ the optional ``truststore`` for OS-trust-store TLS, imported lazily)
and the pure pydantic response models in :mod:`messagefoundry.api.models` /
:mod:`messagefoundry.api.auth_models` — it imports neither PySide6 nor FastAPI, so it is reusable
by the PySide6 console, the headless load/acceptance harness, and any future client without
dragging a GUI or the server into the process.

The console re-exports these names from :mod:`messagefoundry.console.client` (a thin shim) so its
existing imports keep working.
"""

from __future__ import annotations

from messagefoundry.apiclient.client import ApiError, EngineClient

__all__ = ["EngineClient", "ApiError"]
