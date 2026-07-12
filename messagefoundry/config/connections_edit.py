# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Write ``connections.toml`` — the comment/format-preserving editor behind the ``connection`` CLI
(ADR 0007).

The file is edited by hand **and** by the VS Code GUI, so a write must touch only the target
connection and leave every other table's comments + formatting byte-stable — hence ``tomlkit``
(style-preserving) rather than a plain serializer. Each mutation **validates the whole config dir**
(load + the connector/egress build-check) BEFORE it persists, and writes atomically (temp + replace,
owner-only perms); if validation fails the prior content is restored, so a bad edit never lands.

The validation is injected as a callback so this module stays free of service-settings/engine imports
(and is trivially testable); the ``connection`` CLI builds the callback from ``load_config`` +
``build_check_registry`` against the local ``[egress]`` allowlist and active environment.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

import tomlkit

from messagefoundry.config.connections_file import CONNECTIONS_FILE_NAME
from messagefoundry.config.wiring import WiringError

# Scalar fields written (in this order) at the top of a connection table; sub-tables (settings/retry/
# buildup) follow. Only keys present in the input are emitted — the loader rejects misplaced ones.
_SCALAR_FIELDS = (
    "name",
    "transport",
    "router",
    "content_type",
    "ack_mode",
    "ack_after",
    "strict",
    "hl7_version",
    "strict_timeout_s",
    "ordering",
    "internal_error",
    "simulate",
)
_SUB_TABLES = ("settings", "retry", "buildup")

Validate = Callable[[Path], None]


def list_connections(config_dir: str | Path) -> list[dict[str, Any]]:
    """The data-authored connections in ``config_dir``'s ``connections.toml`` (``[]`` if none).

    Each entry is a plain dict with a ``direction`` key added — the editable set the GUI manages
    (code-first ``inbound()``/``outbound()`` connections are read-only and not listed here)."""
    path = _path(config_dir)
    if not path.is_file():
        return []
    doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = []
    for direction in ("inbound", "outbound"):
        for table in doc.get(direction, []):
            entry = dict(table.unwrap())
            entry["direction"] = direction
            out.append(entry)
    return out


def upsert_connection(
    config_dir: str | Path, obj: dict[str, Any], *, validate: Validate
) -> dict[str, Any]:
    """Insert or replace the connection described by ``obj`` (the connection as a JSON object).

    Replaces the same-named entry in place (preserving every *other* table's comments) or appends a
    new one. Validates the whole dir before persisting; raises :class:`WiringError` on bad input or a
    config that wouldn't load (a duplicate vs. a code-first name, unknown router, egress-denied host,
    …) — leaving ``connections.toml`` untouched."""
    _validate_input(obj)
    path = _path(config_dir)
    original = path.read_text(encoding="utf-8") if path.is_file() else None
    doc = tomlkit.parse(original) if original is not None else tomlkit.document()

    direction = obj["direction"]
    aot = doc.get(direction)
    if aot is None:
        aot = tomlkit.aot()
        doc[direction] = aot
    new_table = _build_table(obj)
    for index in range(len(aot)):
        if aot[index].get("name") == obj["name"]:
            aot[index] = new_table  # replace in place — other entries' trivia untouched
            break
    else:
        aot.append(new_table)

    _write_validated(path, tomlkit.dumps(doc), original, validate)
    return {"op": "upsert", "direction": direction, "name": obj["name"]}


def remove_connection(config_dir: str | Path, name: str, *, validate: Validate) -> dict[str, Any]:
    """Remove the data-authored connection ``name``. Raises :class:`WiringError` if it isn't in
    ``connections.toml`` (a code-first connection can't be removed here)."""
    path = _path(config_dir)
    if not path.is_file():
        raise WiringError(f"no {CONNECTIONS_FILE_NAME} in {config_dir}")
    original = path.read_text(encoding="utf-8")
    doc = tomlkit.parse(original)

    removed = False
    for direction in ("inbound", "outbound"):
        aot = doc.get(direction)
        if aot is None:
            continue
        for index in range(len(aot)):
            if aot[index].get("name") == name:
                del aot[index]
                removed = True
                break
        if removed:
            break
    if not removed:
        raise WiringError(
            f"connection {name!r} is not in {CONNECTIONS_FILE_NAME} "
            "(a code-authored connection can't be removed here)"
        )

    _write_validated(path, tomlkit.dumps(doc), original, validate)
    return {"op": "remove", "name": name}


# --- internals ---------------------------------------------------------------


def _path(config_dir: str | Path) -> Path:
    return Path(config_dir) / CONNECTIONS_FILE_NAME


def _validate_input(obj: Any) -> None:
    if not isinstance(obj, dict):
        raise WiringError("connection must be a JSON object")
    if obj.get("direction") not in ("inbound", "outbound"):
        raise WiringError("connection 'direction' must be 'inbound' or 'outbound'")
    if not isinstance(obj.get("name"), str) or not obj["name"]:
        raise WiringError("connection 'name' must be a non-empty string")
    if not isinstance(obj.get("transport"), str) or not obj["transport"]:
        raise WiringError("connection 'transport' must be a non-empty string")


def _build_table(obj: dict[str, Any]) -> Any:
    table = tomlkit.table()
    for key in _SCALAR_FIELDS:
        if obj.get(key) is not None:
            table[key] = obj[key]
    for key in _SUB_TABLES:
        value = obj.get(key)
        if value:
            table[key] = _sub_table(value)
    return table


def _sub_table(data: dict[str, Any]) -> Any:
    sub = tomlkit.table()
    for key, value in data.items():
        sub[key] = _toml_value(value)
    return sub


def _toml_value(value: Any) -> Any:
    """A nested dict (an ``env()`` ref like ``{env = "k"}``, or REST headers) becomes an inline table;
    everything else is written verbatim."""
    if isinstance(value, dict):
        inline = tomlkit.inline_table()
        for key, item in value.items():
            inline[key] = item
        return inline
    return value


def _write_validated(path: Path, new_text: str, original: str | None, validate: Validate) -> None:
    """Atomically write ``new_text``, validate the dir, and roll back to ``original`` on failure."""
    _atomic_write(path, new_text)
    try:
        validate(path.parent)
    except BaseException:
        if original is None:
            path.unlink(missing_ok=True)
        else:
            _atomic_write(path, original)
        raise
    _secure_file(path)


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _secure_file(path: Path) -> None:
    # Owner-only permissions (defence in depth). Reuse the store's primitive; tolerate its absence.
    from messagefoundry.store.store import _secure_file as _secure

    _secure(path)
