# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""PySide6 admin console for MessageFoundry.

A thin desktop client over the localhost API (:mod:`messagefoundry.api`): a channel
dashboard (start/stop), a message browser with an HL7 parse-tree viewer and delivery/
audit trail, and replay. The console never touches the store or engine directly — it
speaks only HTTP, so the same UI drives in-process, local-daemon, and (later) remote
engines.

The API client (:mod:`.client`) is independent of Qt and unit-testable on its own; the
widgets (:mod:`.widgets`) are imported lazily so importing this package doesn't require
PySide6 unless you actually open the GUI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Static-only re-export: mypy --strict still resolves the names, but at runtime they load lazily
    # via __getattr__ below, so importing this package (or find_spec'ing a sibling submodule like
    # service_control) no longer hard-requires the [console] extra's httpx. Mirrors the
    # lazy-truststore import already in client.py and the lazy-pydantic api/__init__ convention.
    from messagefoundry.console.client import ApiError, EngineClient

__all__ = ["EngineClient", "ApiError"]


def __getattr__(name: str) -> object:
    if name in __all__:
        from messagefoundry.console import client

        return getattr(client, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
