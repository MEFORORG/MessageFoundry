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

The write schema below is **verified against the read schema** (#234): the loader's
``_INBOUND_KEYS``/``_OUTBOUND_KEYS`` (``connections_file.py``) are the source of truth, and
``tests/test_connections_file.py::test_write_schema_matches_read_schema_per_direction`` pins
set-equality — so a key added to the read schema and not here **fails a test** instead of being
silently deleted by the next GUI/CLI save (the #234 data-loss bug this closes).
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from datetime import date, datetime, time
from pathlib import Path
from typing import Any

import tomlkit

from messagefoundry.config.connections_file import (
    _INBOUND_KEYS,
    _OUTBOUND_KEYS,
    CONNECTIONS_FILE_NAME,
)
from messagefoundry.config.wiring import WiringError

# Scalar (and array — TOML requires a table's key-values before its sub-table headers) fields,
# written in this order at the top of a connection table. Only keys present in the input are emitted;
# _validate_input rejects anything the direction's READ schema doesn't accept, fail-loud (#234).
_SCALAR_FIELDS = (
    # The original writer's 14 scalars keep their relative order — stable diffs on files it produced.
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
    # Lifecycle flags (#115 auto_start, #233/ADR 0111 deployed). A flag absent from this whitelist is
    # SILENTLY DROPPED on the next GUI/CLI save — so a not-deployed connection would quietly redeploy
    # itself the first time an operator edited it in the editor.
    "auto_start",
    "deployed",
    # Operator "object of interest" flag (#131, ADR 0007 amendment) — the FIRST console-settable key
    # written through this seam. Absent from this whitelist it would be silently dropped on the next save.
    "flagged",
    # Cosmetic "Waiting for Reply" pre-display delay (#136, ADR 0065 amendment) — outbound-only, seconds.
    "waiting_display_delay",
    # --- #234: every key below was in the READ schema but not written — a GUI/CLI save silently
    # deleted it (19 per-direction slots / 16 distinct keys, counting the sub-tables below). Grouped
    # by feature, appended after the legacy order.
    # Listener binding + peer gating. Dropping source_ip_allowlist was a SECURITY regression — a save
    # silently widened the accept surface. (An array is a TOML key-value, so it belongs up here.)
    "bind_address",
    "source_ip_allowlist",
    # Per-connection event-log capture overrides (#46).
    "capture_ack",
    "capture_connection_errors",
    # Retention (#34, ADR 0027) + embedded-document pruning (#47, ADR 0042).
    "messages_days",
    "dead_letter_days",
    "prune_documents_after",
    "prune_documents_min_bytes",
    # Very-large-message streaming (#149, ADR 0105).
    "stream_threshold_bytes",
    "max_message_bytes",
    # DR priority tier (#61, ADR 0048) + engine-shard partition tag (ADR 0037/0073).
    "priority",
    "shard",
)
# Sub-tables follow the scalars. ``schedule`` is deliberately LAST — it nests ``windows`` as an array
# of inline tables, visually the heaviest entry, so the simple knobs stay greppable above it.
_SUB_TABLES = (
    "settings",
    "retry",
    "buildup",
    # --- #234: sub-tables the read schema accepted but the old writer dropped.
    "stall",
    "batch",
    "metadata",  # a casualty on BOTH directions — including inbound
    "schedule",
)

# ``direction`` is deliberately in NEITHER tuple: it is the array-of-tables header the entry lives
# under ([[inbound]]/[[outbound]]), not a table key — the loader's ``_reject_unknown``
# (connections_file.py) hard-fails any table carrying it, so emitting it would poison the file.
#
# Belt-and-braces import-time drift check. The CI guard OF RECORD is the pytest parity test named in
# the module docstring — a bare ``assert`` vanishes under ``python -O``, so this is a fail-fast
# convenience, never the gate.
assert set(_SCALAR_FIELDS) | set(_SUB_TABLES) == _INBOUND_KEYS | _OUTBOUND_KEYS
assert "direction" not in _SCALAR_FIELDS + _SUB_TABLES

Validate = Callable[[Path], None]


def list_connections(config_dir: str | Path) -> list[dict[str, Any]]:
    """The data-authored connections in ``config_dir``'s ``connections.toml`` (``[]`` if none).

    Each entry is a plain dict with a ``direction`` key added — the editable set the GUI manages
    (code-first ``inbound()``/``outbound()`` connections are read-only and not listed here).

    Entries are **JSON-safe by construction** (#234 Phase 2): TOML-native date/time values (a
    hand-authored ``start = 07:00:00``, which tomlkit unwraps to ``datetime.time``) are canonicalized
    to ISO strings recursively **at this boundary** — deliberately here and NOT via a ``default=``
    hook on the CLI's ``_print_json`` (``__main__.py`` is unchanged), so the CLI, the IDE's
    ``runJson``, and direct Python callers all see the same canonical form. The string form is
    read-schema-legal on write-back (pydantic re-parses ISO strings — ``ActiveWindow.start``/``end``)."""
    path = _path(config_dir)
    if not path.is_file():
        return []
    doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = []
    for direction in ("inbound", "outbound"):
        for table in doc.get(direction, []):
            entry = {key: _jsonable(value) for key, value in table.unwrap().items()}
            entry["direction"] = direction
            out.append(entry)
    return out


def _jsonable(value: Any) -> Any:
    """Canonicalize a TOML-unwrapped value for the list boundary: ``datetime``/``date``/``time``
    become ISO-8601 strings (``HH:MM:SS`` for a time), containers recurse, everything else passes
    verbatim. Those are the only non-JSON types ``tomllib``/tomlkit can yield, so the result is
    always ``json.dumps``-able."""
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    return value


def upsert_connection(
    config_dir: str | Path, obj: dict[str, Any], *, validate: Validate
) -> dict[str, Any]:
    """Insert or replace the connection described by ``obj`` (the connection as a JSON object).

    Replaces the same-named entry in place (preserving every *other* table's comments) or appends a
    new one. The replacement is a **full replace** of the named table: a key absent from ``obj`` is
    *removed* from the file (ADR 0007's one-file/two-equal-editors contract — merge-on-absent was
    evaluated under #234 and rejected; the GUI sends the whole object). Validates the whole dir
    before persisting; raises :class:`WiringError` on bad input (including any key the direction's
    read schema does not accept — never silently dropped, #234) or a config that wouldn't load (a
    duplicate vs. a code-first name, unknown router, egress-denied host, …) — leaving
    ``connections.toml`` untouched."""
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
            # Update the EXISTING table object key-wise. Assigning ``aot[index] = new_table`` swaps
            # the whole table out, and tomlkit discards the trivia around it: the edited table's own
            # inline comments AND the leading comment block of the FOLLOWING entry (which tomlkit
            # carries as trivia on the array body, not on the next table). A no-op save therefore
            # deleted the documentation of a connection the user never touched. Mutating in place
            # keeps every comment that is not attached to a value we actually change.
            _apply_table(aot[index], new_table)
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
    direction = obj.get("direction")
    if direction not in ("inbound", "outbound"):
        raise WiringError("connection 'direction' must be 'inbound' or 'outbound'")
    if not isinstance(obj.get("name"), str) or not obj["name"]:
        raise WiringError("connection 'name' must be a non-empty string")
    if not isinstance(obj.get("transport"), str) or not obj["transport"]:
        raise WiringError("connection 'transport' must be a non-empty string")
    # Fail-loud unknown keys (#234), mirroring the loader's _reject_unknown message shape. Validated
    # against the DIRECTION-APPROPRIATE read schema: a cross-direction key (``retry`` on an inbound)
    # must fail here — a union check would silently pass it through to a confusing whole-file load
    # error after the write. The old behaviour (silently dropping anything unrecognized) was the #234
    # data-loss bug.
    allowed = _INBOUND_KEYS if direction == "inbound" else _OUTBOUND_KEYS
    extra = set(obj) - allowed - {"direction"}
    if extra:
        raise WiringError(
            f"{direction} connection {obj['name']!r}: unknown key(s) {', '.join(sorted(extra))} "
            f"(allowed: {', '.join(sorted(allowed))})"
        )
    for key in _SUB_TABLES:
        if key in obj and obj[key] is not None and not isinstance(obj[key], dict):
            # Fail as the CLI's WiringError contract (message mirroring the loader's), not an
            # AttributeError traceback out of _sub_table mid-write.
            raise WiringError(
                f"{direction} connection {obj['name']!r}: [{key}] must be a table (a JSON object)"
            )


def _build_table(obj: dict[str, Any]) -> Any:
    # ``direction`` is used by the caller to pick the [[inbound]]/[[outbound]] array and is never
    # emitted as a key — it is in neither tuple (see the note above the tuples).
    table = tomlkit.table()
    for key in _SCALAR_FIELDS:
        if obj.get(key) is not None:
            table[key] = _toml_value(obj[key])
    for key in _SUB_TABLES:
        value = obj.get(key)
        # ``is not None`` (not truthiness) so an explicit-empty table survives the round-trip; only
        # an ABSENT/null key is omitted — and full-replace then removes it from the file.
        if value is not None:
            table[key] = _sub_table(value)
    return table


def _apply_table(existing: Any, new_table: Any) -> None:
    """Make ``existing`` hold exactly ``new_table``'s keys, touching as few items as possible.

    Full-replace semantics (ADR 0007) are preserved -- a key absent from ``new_table`` is removed --
    but a key whose value is UNCHANGED is left completely alone, so its inline comment and spacing
    survive. That is what makes a no-op save byte-identical instead of a whole-file reflow."""
    for key in [key for key in list(existing.keys()) if key not in new_table]:
        del existing[key]
    for key, value in new_table.items():
        if key in existing and _same_value(existing[key], value):
            continue  # untouched -> its trivia (e.g. a trailing "# ..." comment) is preserved
        if key in existing and _is_table_like(existing[key]) and _is_table_like(value):
            # Recurse so a one-scalar change inside `settings = { host = ..., port = ... }` rewrites
            # only that scalar, keeping the table's shape (inline vs section) and its inner spacing.
            _apply_table(existing[key], value)
            continue
        existing[key] = value


def _plain(item: Any) -> Any:
    """The plain Python value behind a tomlkit item (which carries formatting trivia with it)."""
    unwrap = getattr(item, "unwrap", None)
    return unwrap() if callable(unwrap) else item


def _same_value(current: Any, new: Any) -> bool:
    """Compare a tomlkit item against a freshly built one by VALUE, ignoring formatting."""
    try:
        return bool(_plain(current) == _plain(new))
    except Exception:  # pragma: no cover - defensive: an exotic item type compares as "changed"
        return False


def _is_table_like(item: Any) -> bool:
    """A TOML table in either shape -- `settings = { ... }` or a `[outbound.settings]` section."""
    return isinstance(item, (tomlkit.items.Table, tomlkit.items.InlineTable))


def _sub_table(data: dict[str, Any]) -> Any:
    sub = tomlkit.table()
    for key, value in data.items():
        sub[key] = _toml_value(value)
    return sub


def _toml_value(value: Any) -> Any:
    """A nested dict (an ``env()`` ref like ``{env = "k"}``, REST headers, a schedule window) becomes
    an inline table; a list becomes a TOML array — a list of dicts (``schedule.windows``) an array of
    inline tables (#234); everything else is written verbatim."""
    if isinstance(value, dict):
        inline = tomlkit.inline_table()
        for key, item in value.items():
            inline[key] = _toml_value(item)
        return inline
    if isinstance(value, list):
        array = tomlkit.array()
        for item in value:
            array.append(_toml_value(item))
        return array
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
    # A UNIQUE per-write temp in the SAME directory (same filesystem → os.replace is atomic), so two
    # concurrent writers — the console→TOML seam and the `connection` CLI in a separate process — never
    # clobber a shared ``<name>.tmp``. ``mkstemp`` creates it owner-only from the instant it exists (no
    # create-then-chmod window); the final file inherits those perms on replace, and _secure_file
    # re-asserts them belt-and-braces. On any failure the temp is removed rather than left behind.
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f"{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        # newline="" so the bytes tomlkit produced are written verbatim. Without it Python's default
        # translation rewrites every "\n" as "\r\n" on Windows, so saving one connection reflowed an
        # LF-committed connections.toml into CRLF and turned a one-key edit into a whole-file diff.
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _secure_file(path: Path) -> None:
    # Owner-only permissions (defence in depth). Reuse the store's primitive; tolerate its absence.
    from messagefoundry.store.store import _secure_file as _secure

    _secure(path)
