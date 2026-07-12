# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure helpers for the per-message metadata bag (BACKLOG #150, ADR 0081).

The ``messages.metadata`` column is a single encrypted JSON object per message. It carries two kinds of
key: engine-internal keys (ADR 0013 correlation lineage — ``correlation_id`` / ``correlation_root_id`` /
``correlation_depth`` / ``passthrough_from`` / ``reingress_of_seq``) and, under a reserved ``"user"``
sub-key, the operator/handler-attached bag written by :class:`~messagefoundry.config.wiring.SetMeta`.

These two functions are the ONLY places that shape that split, shared by every store backend (so the
merge can never drift across SQLite / Postgres / SQL Server) and by the API (so the internal keys never
leak). They are pure: no I/O, no crypto — the caller decrypts before and encrypts after.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any


def merge_user_metadata(existing_json: str | None, meta_ops: Sequence[tuple[str, str]]) -> str:
    """Merge ``SetMeta`` writes into a message's decrypted metadata JSON, under the reserved ``"user"``
    sub-key, and return the new JSON string.

    Any non-``user`` keys already present (ADR 0013 correlation lineage) are preserved untouched. Within
    one message the same key is last-writer-wins. ``existing_json`` may be ``None``/empty (no metadata
    yet) or a non-object (defensively treated as empty). Caller passes decrypted JSON in and encrypts the
    result out — this function does neither."""
    parsed: dict[str, Any] = {}
    if existing_json:
        try:
            loaded = json.loads(existing_json)
        except (TypeError, ValueError):
            loaded = None
        if isinstance(loaded, dict):
            parsed = loaded
    user: dict[str, Any] = dict(parsed.get("user") or {})
    for key, value in meta_ops:
        user[key] = value
    parsed["user"] = user
    return json.dumps(parsed)


def user_metadata(metadata_json: str | None) -> str | None:
    """The public, read-only user bag from a message's decrypted metadata JSON: the ``"user"`` sub-key
    re-serialized as a JSON string, or ``None`` when there is none.

    This is the API's ONLY view of the metadata column — it strips the engine-internal correlation-lineage
    keys so they never surface (they would otherwise leak on pass-through / re-ingressed children). Returns
    ``None`` for absent/empty/unparseable metadata or an empty user bag, so the wire field is ``null``
    rather than ``"{}"`` when nothing was attached."""
    if not metadata_json:
        return None
    try:
        loaded = json.loads(metadata_json)
    except (TypeError, ValueError):
        return None
    if not isinstance(loaded, dict):
        return None
    user = loaded.get("user")
    if not isinstance(user, dict) or not user:
        return None
    return json.dumps(user)
