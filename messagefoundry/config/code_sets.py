# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Managed, hot-reloadable **code sets** (reference lookup tables) for the message graph.

A code-first Router/Handler often needs a reference table — an Epic diet code → a food-service
system value, a facility code → a downstream mnemonic. Hand-maintained Python dicts in the config dir work, but they
aren't operated like config: they don't reload with the graph, they aren't surfaced as data, and an
edit means a code change. A **code set** is the managed alternative: drop a ``codesets/<name>.csv``
or ``codesets/<name>.toml`` next to the config bundle, then look it up with ``code_set("name")``.

A code set is **read-only reference data** — one frozen :class:`CodeSet` instance is shared by every
transform, so a Router/Handler must never mutate it. The lookup itself is pure (key in → value out),
which keeps it compatible with the staged-pipeline **pure-re-run** invariant (ADR 0001 / CLAUDE.md
§2). **One caveat:** a hot-reload that *changes* a code set between a run and a crash-re-run can make
the re-run derive a different output than the original. That is acceptable for reference data (a code
set is intentionally operator-editable, and a reload is an explicit, audited act) — but it is the one
way a transform's output can legitimately differ across a re-run, so document it where you document
the transform.

**Location.** ``codesets/`` is resolved **relative to the ``--config`` dir** (a config bundle carries
its own reference tables and reloads with it) — distinct from ``environments/`` (cwd-level endpoint
values for :func:`~messagefoundry.config.wiring.env`). A missing ``codesets/`` dir is fine (no code
sets); a referenced-but-missing *name* fails **loud** (:class:`~messagefoundry.config.wiring.WiringError`),
exactly like a missing ``env()`` key — surfaced by ``validate`` / ``check`` / reload.

**Formats** (auto-detected by extension; the code-set NAME is the filename stem):

* **CSV** — a header row; the **first column is the lookup key**. If exactly one other column remains,
  the value is that scalar (``str``); if several remain, the value is a ``dict`` ``{header: cell}``.
  Read via :class:`csv.DictReader`. A duplicate key is a load error (fail loud).
* **TOML** — a flat table ``key = value`` → ``{key: scalar}`` (mirroring
  :mod:`messagefoundry.config.environments`); a nested table value → ``{key: {…}}``. Read via
  :mod:`tomllib`.

**Resolution.** :func:`~messagefoundry.config.wiring.load_config` loads every code set into a registry
and makes it the **active** set *before* importing config modules (so a module-top-level
``DIET = code_set("epic_diets")`` resolves), and the :class:`RegistryRunner` re-publishes the live
registry's set while a Router/Handler runs (so a call-time ``code_set("epic_diets").get(x)`` inside a
handler resolves too). A reload swaps the active set atomically. Use :func:`activated` to scope an
active set; :func:`set_active` to publish one outside a ``with`` block.
"""

from __future__ import annotations

import csv
import logging
import tomllib
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

__all__ = [
    "CODESETS_DIR_NAME",
    "CodeSet",
    "load_code_set",
    "load_code_sets",
    "code_set",
    "set_active",
    "activated",
    "CodeSetError",
]

#: The code-set directory name, resolved relative to the ``--config`` dir.
CODESETS_DIR_NAME = "codesets"

_log = logging.getLogger(__name__)


class CodeSetError(ValueError):
    """A code set is malformed, has a duplicate key, or was referenced but doesn't exist.

    A subclass of :class:`ValueError`; :func:`messagefoundry.config.wiring.code_set` re-raises these
    as :class:`~messagefoundry.config.wiring.WiringError` so a bad/missing code set is surfaced by
    ``validate`` / ``check`` / reload exactly like a missing ``env()`` key (fail loud)."""


class CodeSet(Mapping[str, Any]):
    """A frozen, read-only reference table: ``name`` + an immutable ``key → value`` mapping.

    Behaves like a read-only ``dict`` (``cs[key]``, ``cs.get(key, default)``, ``key in cs``,
    ``len(cs)``, iteration) but rejects mutation — one instance is shared across every transform, so
    reference data can't be edited from a handler. ``cs[missing]`` raises a :class:`KeyError` naming
    the code set; ``cs.get(missing, default)`` returns the default."""

    __slots__ = ("_name", "_data")

    def __init__(self, name: str, data: Mapping[str, Any]) -> None:
        self._name = name
        self._data: dict[str, Any] = dict(data)

    @property
    def name(self) -> str:
        return self._name

    def __getitem__(self, key: str) -> Any:
        try:
            return self._data[key]
        except KeyError:
            # Name the code set so a miss is self-explanatory in a transform traceback.
            raise KeyError(f"key {key!r} not in code set {self._name!r}") from None

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"CodeSet(name={self._name!r}, entries={len(self._data)})"


# --- loading -----------------------------------------------------------------


def load_code_set(path: str | Path) -> CodeSet:
    """Load one ``.csv``/``.toml`` file into a :class:`CodeSet` (the NAME is the file stem).

    Auto-detects the format by extension. Raises :class:`CodeSetError` (naming the file) for an
    unknown extension, a malformed file, or a duplicate key — never silently drops data."""
    path = Path(path)
    name = path.stem
    suffix = path.suffix.lower()
    if suffix == ".csv":
        data = _load_csv(path)
    elif suffix == ".toml":
        data = _load_toml(path)
    else:
        raise CodeSetError(
            f"code set {path.name!r}: unsupported extension {suffix!r} (use .csv or .toml)"
        )
    return CodeSet(name, data)


def load_code_sets(codesets_dir: str | Path) -> dict[str, CodeSet]:
    """Load every ``*.csv``/``*.toml`` in ``codesets_dir`` into a ``{name: CodeSet}`` registry.

    A missing directory is **not** an error (returns ``{}`` — a config bundle need not ship any code
    sets). Two files producing the same name (e.g. ``diets.csv`` and ``diets.toml``) is a
    :class:`CodeSetError` (ambiguous), as is any malformed file."""
    codesets_dir = Path(codesets_dir)
    if not codesets_dir.is_dir():
        return {}
    out: dict[str, CodeSet] = {}
    # Sorted for a deterministic load order, so a clash error names a stable "first" file.
    for path in sorted(codesets_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() not in (".csv", ".toml"):
            continue
        cs = load_code_set(path)
        if cs.name in out:
            raise CodeSetError(
                f"duplicate code set name {cs.name!r} in {codesets_dir} — two files (different "
                "extensions) resolve to the same name; rename one"
            )
        out[cs.name] = cs
    return out


def _load_csv(path: Path) -> dict[str, Any]:
    """CSV with a header row: first column = key; one other column → scalar, several → ``{header: cell}``."""
    data: dict[str, Any] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields = reader.fieldnames
        if not fields:
            raise CodeSetError(f"code set {path.name!r}: empty CSV (no header row)")
        key_field, *value_fields = fields
        if not value_fields:
            raise CodeSetError(
                f"code set {path.name!r}: CSV needs a key column plus at least one value column"
            )
        single = len(value_fields) == 1
        for row in reader:
            key = row.get(key_field)
            if key is None:
                continue  # short/blank row — DictReader fills missing cells with None
            if key in data:
                raise CodeSetError(f"code set {path.name!r}: duplicate key {key!r}")
            if single:
                data[key] = row.get(value_fields[0])
            else:
                data[key] = {vf: row.get(vf) for vf in value_fields}
    return data


def _load_toml(path: Path) -> dict[str, Any]:
    """Flat TOML table → ``{key: scalar}``; a nested table value → ``{key: {…}}`` (mirrors environments)."""
    try:
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        raise CodeSetError(f"code set {path.name!r}: invalid TOML — {exc}") from exc
    # tomllib already rejects duplicate keys (TOMLDecodeError), so no extra dup check is needed.
    return dict(raw)


# --- active-set holder + accessor --------------------------------------------

# The active code sets, as a ContextVar so import-time (load_config publishes the set, then imports
# config modules in the same thread/context) AND call-time (the RegistryRunner re-publishes the live
# set around a router/handler run) both resolve, and a reload swaps cleanly by resetting the var (no
# stale set leaks — unlike a bare module-global, a ContextVar's reset token restores the prior value
# even if loads/reloads overlap). Defaults to None = "no active set" (a code_set() call then fails
# loud) rather than {} so "no codesets dir" and "called outside a load/run" stay distinguishable.
_active: ContextVar[dict[str, CodeSet] | None] = ContextVar("mefor_active_code_sets", default=None)


def set_active(code_sets: dict[str, CodeSet] | None) -> Any:
    """Publish ``code_sets`` as the active set and return a reset token (pass it to :func:`reset`).

    Used by callers that can't bracket the active span with a ``with`` (e.g. an async worker that
    publishes around a single transform call). Prefer :func:`activated` where a ``with`` block fits."""
    return _active.set(code_sets)


def reset(token: Any) -> None:
    """Restore the active set to what it was before the matching :func:`set_active`."""
    _active.reset(token)


@contextmanager
def activated(code_sets: dict[str, CodeSet] | None) -> Iterator[None]:
    """Make ``code_sets`` the active set for the duration of the ``with`` block, then restore.

    The loader brackets config-module import with this; a runner brackets each router/handler run with
    it — so ``code_set()`` resolves both at import time and at call time, and the prior set is always
    restored (clean swap, no leak)."""
    token = _active.set(code_sets)
    try:
        yield
    finally:
        _active.reset(token)


def code_set(name: str) -> CodeSet:
    """Return the active code set ``name`` (a frozen, read-only :class:`CodeSet`).

    Call it at a config module's top level to capture a table once (``DIET = code_set("epic_diets")``)
    or inside a handler at call time (``code_set("epic_diets").get(x)``) — both resolve against the
    set the loader/runner has published. A missing code set raises :class:`CodeSetError` (fail loud);
    :func:`messagefoundry.config.wiring.code_set` (the authoring surface) re-raises it as a
    :class:`~messagefoundry.config.wiring.WiringError`."""
    active = _active.get()
    if active is None:
        raise CodeSetError(
            f"code_set({name!r}) called with no active code sets — code sets resolve only while a "
            "config bundle is being loaded or its graph is running (load it via load_config())"
        )
    try:
        return active[name]
    except KeyError:
        available = ", ".join(sorted(active)) or "(none)"
        raise CodeSetError(
            f"no such code set {name!r} — expected a file codesets/{name}.csv or "
            f"codesets/{name}.toml relative to the --config dir; available: {available}"
        ) from None
