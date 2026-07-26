# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Read/write the ``[security]`` section of the service-settings TOML — the comment/format-preserving
editor behind the ``security`` CLI (ADR 0118; the VS Code ``[security]`` GUI editor shells it).

The ``[security]`` switches are **pure data** (booleans/ints/strings and string lists such as
``allowed_client_networks`` — no code), so — like
``connections.toml`` (ADR 0007) and ``[[alerts.rules]]`` (ADR 0014) — they are GUI-manageable. A write
touches only the ``[security]`` table and leaves every other section's comments + formatting byte-stable,
hence ``tomlkit`` rather than a plain serializer. Each mutation validates that the whole settings file
still loads (the same ``load_settings`` path the engine uses — which also **rejects the relocated legacy
keys**), and writes atomically (temp + replace, owner-only perms) with rollback, so a bad edit never
lands. Validation is injected as a callback so this module stays free of the settings/engine import graph
(and is trivially testable); the ``security`` CLI builds the callback from ``load_settings``.

Note: the service-settings TOML is read at engine **startup**, so an edited switch takes effect on the
next engine restart (``POST /config/reload`` re-runs the ``--config`` graph, not ``[security]``).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import tomlkit

Validate = Callable[[Path], None]


class SecurityEditError(ValueError):
    """A ``[security]`` edit was rejected: a malformed update or a file that wouldn't load (e.g. a value
    that fails validation, or a relocated legacy key). Raised with an operator-facing message."""


def read_security(service_config: str | Path) -> dict[str, Any]:
    """The ``[security]`` table as authored in ``service_config`` (``{}`` if the file or the ``[security]``
    table is absent). These are the EXPLICITLY-set switches — a caller resolves the secure defaults for
    the unset ones. Comment/format trivia is not returned (values only)."""
    path = Path(service_config)
    if not path.is_file():
        return {}
    doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    sec = doc.get("security")
    return dict(sec.unwrap()) if sec is not None else {}


def set_security(
    service_config: str | Path, updates: Mapping[str, Any], *, validate: Validate
) -> dict[str, Any]:
    """Merge ``updates`` into the ``[security]`` table (creating the file + table if needed), validate the
    whole file still loads, then write comment-preservingly. A value of ``None`` **removes** that key
    (resets it to its secure default). Raises :class:`SecurityEditError` if the result wouldn't load —
    leaving the TOML untouched. Only the ``[security]`` table is edited; other sections are byte-stable."""
    if not isinstance(updates, Mapping):
        raise SecurityEditError("security updates must be a JSON object of {key: value}")
    path = Path(service_config)
    original = path.read_text(encoding="utf-8") if path.is_file() else None
    doc = tomlkit.parse(original) if original is not None else tomlkit.document()

    sec = doc.get("security")
    if sec is None:
        sec = tomlkit.table()
        doc["security"] = sec
    for key, value in updates.items():
        if value is None:
            if key in sec:
                del sec[key]
        else:
            sec[key] = value
    # Drop an emptied [security] table so a full reset-to-defaults leaves no bare header behind.
    if not len(sec):
        del doc["security"]

    _write_validated(path, tomlkit.dumps(doc), original, validate)
    return {"op": "set", "keys": list(updates.keys())}


# --- internals ---------------------------------------------------------------


def _write_validated(path: Path, new_text: str, original: str | None, validate: Validate) -> None:
    """Atomically write ``new_text``, validate the file loads, and roll back to ``original`` on failure
    (delete it if it didn't exist before)."""
    _atomic_write(path, new_text)
    try:
        validate(path)
    except SecurityEditError:
        raise
    except BaseException as exc:
        if original is None:
            path.unlink(missing_ok=True)
        else:
            _atomic_write(path, original)
        raise SecurityEditError(str(exc)) from exc
    _secure_file(path)


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _secure_file(path: Path) -> None:
    # Owner-only permissions (defence in depth). Reuse the store's primitive; tolerate its absence.
    from messagefoundry.store.store import _secure_file as _secure

    _secure(path)
