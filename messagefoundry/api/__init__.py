"""Localhost engine API (FastAPI): channel deploy/start/stop, message tracking &
search, replay, live stats over WebSocket. This is the only surface the PySide6
console talks to, so local vs remote operation is transparent to the UI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = ["create_app", "create_managed_app"]

if TYPE_CHECKING:
    from messagefoundry.api.app import create_app, create_managed_app


def __getattr__(name: str) -> Any:
    # PEP 562 lazy export: importing `messagefoundry.api` (e.g. a sibling's pure Pydantic models)
    # must NOT eagerly pull FastAPI + the whole engine into the importing process — the GUI console
    # imports api.models/api.auth_models and shouldn't drag the server in (review low-17). Resolve
    # create_app/create_managed_app only when actually accessed.
    if name in __all__:
        from messagefoundry.api import app

        return getattr(app, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
