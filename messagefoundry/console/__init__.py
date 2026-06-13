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

from messagefoundry.console.client import ApiError, EngineClient

__all__ = ["EngineClient", "ApiError"]
