# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Thin re-export shim: the API client now lives in :mod:`messagefoundry.apiclient` (ADR 0088).

The client body moved to :mod:`messagefoundry.apiclient.client` — the canonical Qt-free /
FastAPI-free engine-client library, shared by the console, the harness, and future clients. This
module re-exports the same public names (and the module-private helpers the console/harness/tests
reference) so every existing ``from messagefoundry.console.client import ...`` keeps working with no
behaviour change.
"""

from __future__ import annotations

from messagefoundry.apiclient.client import (
    ApiError,
    EngineClient,
    _assert_safe_transport,
    _build_verify_context,
    _decode,
    _decode_list,
    _error_detail,
)

__all__ = ["EngineClient", "ApiError"]

# The module-private helpers are intentionally re-exported (not in ``__all__``) because existing
# console code and tests import them by name from this shim's historical path.
_ = (
    _assert_safe_transport,
    _build_verify_context,
    _decode,
    _decode_list,
    _error_detail,
)
