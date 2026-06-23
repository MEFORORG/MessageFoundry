# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Write the ``[[alerts.rules]]`` tables in the service-settings TOML — the comment/format-preserving
editor behind the ``alert`` CLI (ADR 0014; the VS Code "New Alert" command shells it).

Alert rules are **pure data** (a typed :class:`~messagefoundry.config.settings.AlertRule`, never
code/expression), authored by hand **and** by the GUI, so a write must touch only the rule list and
leave every other section's comments + formatting byte-stable — hence ``tomlkit`` (style-preserving)
rather than a plain serializer. Each mutation **re-loads the whole settings file** (the same
``load_settings`` path the engine uses) BEFORE it persists, and writes atomically (temp + replace,
owner-only perms); if the result wouldn't load, the prior content is restored, so a bad edit never
lands.

Like ``connections_edit``, the validation is injected as a callback so this module stays free of the
settings/engine import graph (and is trivially testable); the ``alert`` CLI builds the callback from
``load_settings``. **Rules are an ordered list** — "first match wins" — so they're addressed by
position (``add`` appends, ``remove`` takes an ``index``), not by name the way connections are.

Note: the service-settings TOML is read at engine **startup**, so an authored rule takes effect on
the next engine restart — ``POST /config/reload`` re-runs the ``--config`` graph, not ``[alerts]``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

import tomlkit

#: Scalar/array fields written (in this order) for one rule. Only keys present in the input are
#: emitted, and only ``None`` is treated as absent — an empty ``transports = []`` (the "suppress"
#: outcome) is a real value and IS written. Mirrors ``settings.AlertRule``'s field order.
_RULE_FIELDS = (
    "event_type",
    "connection",
    "min_depth",
    "min_oldest_seconds",
    "severity",
    "transports",
    "cooldown_seconds",
)

Validate = Callable[[Path], None]


class AlertRuleError(ValueError):
    """An alert-rule edit was rejected: a malformed rule/file, a missing file, or an out-of-range
    index. Raised with an operator-facing message (the CLI surfaces it as ``{"error": ...}``)."""


def list_rules(service_config: str | Path) -> list[dict[str, Any]]:
    """The operator-authored ``[[alerts.rules]]`` in ``service_config`` (``[]`` if the file or the
    ``[alerts].rules`` table is absent). Each entry is the rule as a plain dict with its ordinal
    ``index`` added — the positional handle the GUI uses for ``remove``."""
    path = Path(service_config)
    if not path.is_file():
        return []
    doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    rules = _existing_rules(doc)
    if rules is None:
        return []
    out: list[dict[str, Any]] = []
    for index, table in enumerate(rules):
        entry = dict(table.unwrap())
        entry["index"] = index
        out.append(entry)
    return out


def add_rule(
    service_config: str | Path, obj: dict[str, Any], *, validate: Validate
) -> dict[str, Any]:
    """Append the rule described by ``obj`` to ``[[alerts.rules]]`` (creating the file + ``[alerts]``
    table if needed). Validates the whole file loads before persisting; raises
    :class:`AlertRuleError` on bad input or a file that wouldn't load — leaving the TOML untouched.

    Appending (not name-keyed replace) is deliberate: rules are an ordered "first match wins" list,
    so a new rule goes last; reordering/editing is remove + re-add (mirrors a connection rename)."""
    _validate_input(obj)
    path = Path(service_config)
    original = path.read_text(encoding="utf-8") if path.is_file() else None
    doc = tomlkit.parse(original) if original is not None else tomlkit.document()

    alerts = doc.get("alerts")
    if alerts is None:
        alerts = tomlkit.table()
        doc["alerts"] = alerts
    rules = alerts.get("rules")
    if rules is None:
        rules = tomlkit.aot()
        alerts["rules"] = rules
    rules.append(_build_table(obj))

    _write_validated(path, tomlkit.dumps(doc), original, validate)
    return {"op": "add", "index": len(rules) - 1}


def remove_rule(service_config: str | Path, index: int, *, validate: Validate) -> dict[str, Any]:
    """Remove the rule at ordinal ``index`` from ``[[alerts.rules]]``. Raises :class:`AlertRuleError`
    if the file/table is absent or the index is out of range (every other table's trivia survives)."""
    path = Path(service_config)
    if not path.is_file():
        raise AlertRuleError(f"no settings file at {path}")
    original = path.read_text(encoding="utf-8")
    doc = tomlkit.parse(original)
    rules = _existing_rules(doc)
    if rules is None or not 0 <= index < len(rules):
        raise AlertRuleError(f"no alert rule at index {index}")
    del rules[index]

    _write_validated(path, tomlkit.dumps(doc), original, validate)
    return {"op": "remove", "index": index}


# --- internals ---------------------------------------------------------------


def _existing_rules(doc: Any) -> Any:
    """The ``[[alerts.rules]]`` array-of-tables in ``doc``, or ``None`` if ``[alerts]`` or its
    ``rules`` table is absent."""
    alerts = doc.get("alerts")
    if alerts is None:
        return None
    return alerts.get("rules")


def _validate_input(obj: Any) -> None:
    if not isinstance(obj, dict):
        raise AlertRuleError("alert rule must be a JSON object")
    if "index" in obj:
        # `index` is the read-only ordinal `list` adds for addressing; it's not a rule field
        # (AlertRule forbids extras), so a round-tripped entry must drop it before `add`.
        raise AlertRuleError("alert rule must not carry an 'index' field")


def _build_table(obj: dict[str, Any]) -> Any:
    table = tomlkit.table()
    for key in _RULE_FIELDS:
        if obj.get(key) is not None:  # None = field absent; [] (suppress) is a real value, kept
            table[key] = obj[key]
    return table


def _write_validated(path: Path, new_text: str, original: str | None, validate: Validate) -> None:
    """Atomically write ``new_text``, validate the file loads, and roll back to ``original`` on
    failure (delete it if it didn't exist before)."""
    _atomic_write(path, new_text)
    try:
        validate(path)
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
