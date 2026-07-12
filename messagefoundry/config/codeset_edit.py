# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Write ``codesets/<name>.csv`` — the writer behind the ``codeset`` CLI / VS Code grid editor.

A **code set** is read-only reference data the loader (:mod:`messagefoundry.config.code_sets`) reads
from ``codesets/<name>.csv`` (or ``.toml``) under the ``--config`` dir. This module is the editing
twin of :mod:`messagefoundry.config.connections_edit`: it lets an operator (and the VS Code grid)
list / show / upsert / rename / remove those tables. The on-disk authored format is **CSV-first**
(``upsert`` always writes ``.csv``); ``.toml`` code sets are read-only here (hand-authored / legacy).

The writer mirrors the loader's rules **exactly** so a file it produces always loads: the first
column is the lookup key, at least one value column is required, no duplicate keys, and a stem that
collides with an existing ``.toml`` is rejected (the same ambiguity the loader fails loud on). The
final authority is the loader itself — after an atomic, owner-only write, the candidate file is
re-loaded via :func:`~messagefoundry.config.code_sets.load_code_set`; any failure rolls the prior
content back (or unlinks a brand-new file), so a bad edit never lands.

The post-write check is injected as a ``validate`` callback (so the CLI passes the *real* loader and
this module stays trivially testable), exactly as ``connections_edit`` does. The name-safety,
structural, and stem-collision checks run **before** any filesystem touch.
"""

from __future__ import annotations

import csv
import io
import ntpath
import os
from pathlib import Path
from typing import Any, Callable

from messagefoundry.config.code_sets import (
    CODESETS_DIR_NAME,
    CodeSet,
    CodeSetError,
    UnmappedPolicy,
    is_policy_sidecar,
    load_code_set,
    load_code_sets,
)
from messagefoundry.config.wiring import WiringError

#: Extensions the loader recognises (the writer only ever *writes* ``.csv``; both are read).
_SUPPORTED_EXTS = (".csv", ".toml")


def _policy_detail(policy: UnmappedPolicy) -> dict[str, Any]:
    """The unmapped-value policy (#162) as a JSON-ready dict for the grid editor to SHOW."""
    return {"kind": policy.kind.value, "default_value": policy.default_value}


#: Run after a write to prove the file loads; the CLI passes the real loader. It receives the written
#: ``.csv`` path and raises on any problem (which triggers a rollback).
Validate = Callable[[Path], None]


# --- read paths --------------------------------------------------------------


def list_code_sets(config_dir: str | Path) -> list[dict[str, Any]]:
    """Every code set under ``<config_dir>/codesets/`` as a SUMMARY dict (``[]`` if the dir is absent).

    Sorted by ``name`` ascending (deterministic; mirrors :func:`load_code_sets`' sorted iteration).
    Raises :class:`WiringError` on a malformed file, a duplicate-key file, a stem collision, or an
    OSError reading the dir — the same fail-loud surface the loader gives."""
    codesets_dir = _codesets_dir(config_dir)
    if not codesets_dir.is_dir():
        return []
    # load_code_sets is the authority for duplicate-stem / malformed-file errors; reuse it so `list`
    # fails loud exactly like a reload would, rather than papering over a broken table.
    registry = _load_all(codesets_dir)
    summaries: list[dict[str, Any]] = []
    for path in _iter_code_set_files(codesets_dir):
        summaries.append(_summary(path, registry[path.stem].name, registry))
    summaries.sort(key=lambda s: s["name"])
    return summaries


def show_code_set(config_dir: str | Path, name: str) -> dict[str, Any]:
    """The DETAIL/grid for code set ``name`` (``codesets/<name>.csv`` else ``.toml``).

    Raises :class:`WiringError` if ``name`` is missing, no such file exists, or the file is malformed
    / has a duplicate key (the loader's wording)."""
    if not name:
        raise WiringError("--name is required for `codeset show`")
    codesets_dir = _codesets_dir(config_dir)
    # The operator-supplied name is untrusted: a read path must reject traversal (`../../x`, drive,
    # embedded ext) BEFORE building a filesystem path, or a `show` could read any .csv/.toml on disk.
    _validate_name(codesets_dir, name)
    path = _existing_path(codesets_dir, name)
    fmt = "csv" if path.suffix.lower() == ".csv" else "toml"
    cs = _load_one(path)
    if fmt == "csv":
        columns, rows = _read_csv_grid(path)
    else:
        # A TOML code set is read-only in the grid; best-effort headers from the loaded mapping.
        columns, rows = _toml_grid(cs)
    return {
        "name": name,
        "format": fmt,
        "columns": columns,
        "rows": rows,
        # Additive (SUMMARY-only fields), tolerated by the writer on upsert; handy for the webview.
        "value_columns": columns[1:],
        "shape": _shape(len(columns) - 1),
        "entries": len(cs),
        # #162: the declared unmapped-value policy, SHOWN read-only in the grid (authored via the
        # <name>.policy.toml sidecar for v1). Absent sidecar ⇒ {"kind": "none", ...}.
        "policy": _policy_detail(cs.policy),
    }


# --- write paths -------------------------------------------------------------


def upsert_code_set(
    config_dir: str | Path,
    name: Any,
    columns: Any,
    rows: Any,
    *,
    validate: Validate,
) -> dict[str, Any]:
    """Insert-or-replace ``codesets/<name>.csv`` from a header row + data rows (all cells strings).

    Validates the name (safety), the structure (>=1 value column, unique non-empty headers, no
    duplicate keys; a blank-key row carrying data is rejected, a fully-blank row dropped), and the
    stem (no colliding ``.toml``) **before** writing. Writes atomically with owner-only perms, then re-loads the file via ``validate`` as the
    final authority; on any failure the prior content is restored (or a brand-new file unlinked).
    Raises :class:`WiringError` on bad input or a file that wouldn't load."""
    headers = _validate_columns(name, columns)
    emitted = _validate_rows(name, headers, rows)
    codesets_dir = _codesets_dir(config_dir)
    _validate_name(codesets_dir, name)
    _reject_toml_collision(codesets_dir, name)

    path = codesets_dir / f"{name}.csv"
    # Capture prior content as BYTES so a rollback restores the file byte-for-byte (CSV line
    # terminators are \r\n; a text round-trip through universal-newline translation would not).
    original = path.read_bytes() if path.is_file() else None
    text = _build_csv_text(headers, emitted)
    _write_validated(path, text, original, validate)

    # The written file is now proven loadable; count its keys for the RESULT.
    entries = len(_load_one(path))
    return {"op": "upsert", "name": name, "format": "csv", "entries": entries}


def rename_code_set(
    config_dir: str | Path, old: str, new: str, *, validate: Validate
) -> dict[str, Any]:
    """Rename ``codesets/<old>.<ext>`` to ``codesets/<new>.<same ext>`` (atomic ``os.replace``).

    ``new`` is checked with the same name-safety rules as ``upsert``; the rename is rejected if **any**
    supported file already exists for ``new`` (a stem collision). Raises :class:`WiringError` if
    ``old``/``new`` is missing, the source is absent, ``new`` is unsafe, or the stem collides."""
    if not old:
        raise WiringError("--name is required for `codeset rename`")
    if not new:
        raise WiringError("--to is required for `codeset rename`")
    codesets_dir = _codesets_dir(config_dir)
    src = _existing_path(codesets_dir, old)
    _validate_name(codesets_dir, new)
    # For a rename, ANY supported file for the new stem is a collision (unlike upsert, which may
    # overwrite the same-stem .csv).
    if _existing_path_or_none(codesets_dir, new) is not None:
        raise WiringError(_collision_message(new, codesets_dir))

    dest = codesets_dir / f"{new}{src.suffix}"
    # Referent pre-flight (#152): a code set is named by string literals in the Router/Handler modules
    # that call code_set("old"). PLAN the referent rewrite BEFORE moving the file — the plan is built
    # from the loaded graph while "old" still resolves (the loader would otherwise fail on a
    # code_set("old") capture whose table just vanished). impact.py owns the tokenize-safe rewriter, so
    # it is never duplicated here. Best-effort + additive: the file rename is the core operation, so a
    # config that doesn't load leaves the result byte-identical to the pre-#152 shape.
    plan = _plan_code_set_referents(config_dir, old, new)
    os.replace(src, dest)
    result: dict[str, Any] = {"op": "rename", "name": old, "to": new}
    if plan is not None:
        from messagefoundry.config import impact

        rewritten = len(impact.apply_rename(plan))
        if rewritten:
            result["referents_rewritten"] = rewritten
    return result


def remove_code_set(config_dir: str | Path, name: str, *, validate: Validate) -> dict[str, Any]:
    """Delete ``codesets/<name>.csv`` (else ``.toml``). Raises :class:`WiringError` if ``name`` is
    missing or no such file exists.

    ``validate`` is accepted for signature symmetry with the other mutators (a delete has nothing to
    re-load) and is intentionally unused."""
    del validate  # a delete leaves nothing to re-validate; kept for a uniform mutator signature
    if not name:
        raise WiringError("--name is required for `codeset remove`")
    codesets_dir = _codesets_dir(config_dir)
    # The operator-supplied name is untrusted: a delete path must reject traversal (`../../x`, drive,
    # embedded ext) BEFORE building a filesystem path, or a `remove` could unlink any file on disk.
    _validate_name(codesets_dir, name)
    path = _existing_path(codesets_dir, name)
    # Delete pre-flight (#152): surface the live Router/Handler referents that will now dangle (a
    # code_set("name") that no longer resolves). Computed BEFORE the unlink — while "name" still
    # resolves — because the reverse index only builds a code_set edge for a *registered* table, so a
    # reload after the file is gone would find no referrers. Mirrors the rename path (plan-before-move).
    # Best-effort + additive: the delete is the core op, so an unloadable graph yields no referrers.
    dangling = _code_set_referrers(config_dir, name)
    path.unlink()
    result: dict[str, Any] = {"op": "remove", "name": name}
    if dangling:
        result["referrers"] = dangling
    return result


# --- structural validation ---------------------------------------------------


def _validate_columns(name: Any, columns: Any) -> list[str]:
    """Validate the DETAIL ``name``/``columns`` and return the header list (key first)."""
    if not isinstance(name, str) or not name:
        raise WiringError("code set 'name' must be a non-empty string")
    if not isinstance(columns, list) or len(columns) < 2:
        # Mirror the loader's "key column plus at least one value column" requirement.
        raise WiringError(
            f"code set {name!r}: CSV needs a key column plus at least one value column"
        )
    seen: set[str] = set()
    for header in columns:
        if not isinstance(header, str) or not header:
            raise WiringError(f"code set {name!r}: column headers must be non-empty strings")
        if header in seen:
            # A duplicate header makes csv.DictReader ambiguous on read — reject it like the loader.
            raise WiringError(f"code set {name!r}: duplicate column header {header!r}")
        seen.add(header)
    return list(columns)


def _validate_rows(name: str, headers: list[str], rows: Any) -> list[list[str]]:
    """Validate ``rows`` against ``headers``, drop content-free rows, and reject duplicate keys.

    Returns the surviving rows (each right-padded to ``len(headers)``). A fully-blank row is dropped
    (a harmless empty grid row); a row with value cells but a blank key is rejected (fail loud) —
    never silently dropped."""
    if not isinstance(rows, list):
        raise WiringError(f"code set {name!r}: 'rows' must be a list")
    width = len(headers)
    emitted: list[list[str]] = []
    keys: set[str] = set()
    for i, row in enumerate(rows):
        if not isinstance(row, list):
            raise WiringError(f"code set {name!r}: row {i} must be a list of strings")
        for cell in row:
            if not isinstance(cell, str):
                raise WiringError(f"code set {name!r}: every cell must be a string")
        if len(row) > width:
            raise WiringError(f"code set {name!r}: row {i} has more cells than columns")
        # Right-pad a short row with "" (the loader fills missing cells the same way).
        padded = [*row, *([""] * (width - len(row)))]
        key = padded[0]
        if key == "":
            # A content-free row (every cell blank) is a harmless empty grid row — drop it, the way
            # the loader skips a genuinely blank CSV line. But a row carrying VALUE cells under a
            # blank key is real data: reject it loud rather than silently drop it (CLAUDE.md: never
            # accept-and-drop). The loader itself would store such a row under an empty-string key —
            # never what an operator means in a translation table — so the writer refuses to author
            # one.
            if any(cell != "" for cell in padded):
                raise WiringError(
                    f"code set {name!r}: row {i} has values but a blank {headers[0]!r} key column"
                )
            continue
        if key in keys:
            raise WiringError(f"code set {name!r}: duplicate key {key!r}")
        keys.add(key)
        emitted.append(padded)
    return emitted


# --- name safety + collisions ------------------------------------------------


def _validate_name(codesets_dir: Path, name: str) -> None:
    """Reject a ``name`` that is not a safe bare filename, BEFORE any filesystem touch.

    Order matters (most-specific message wins): path separators, ``..``/dot-only, absolute / drive,
    embedded extension, empty/whitespace, then a final resolved-path containment check."""
    if not isinstance(name, str) or not name.strip():
        raise WiringError("code set name must be a non-empty string")
    # Reject control characters (NUL, tab, newline, DEL, …) before they reach a filesystem call: an
    # embedded NUL makes Path.resolve() raise a bare ValueError the CLI's except clause can't catch
    # (crashing with no JSON on stdout), and none belong in a bare file stem regardless.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        raise WiringError(f"code set name {name!r} must not contain control characters")
    if "/" in name or "\\" in name:
        raise WiringError(f"code set name {name!r} must not contain a path separator")
    if name == "." or name == ".." or ".." in name:
        raise WiringError(f"code set name {name!r} must not contain '..'")
    if os.path.isabs(name) or _has_drive(name):
        raise WiringError(f"code set name {name!r} must be a bare file stem, not a path")
    if Path(name).suffix != "":
        raise WiringError(f"code set name {name!r} must be a bare stem (no .csv/.toml extension)")
    # Defence in depth: the resolved target must stay directly inside codesets/. (A separator/`..`
    # would already have been rejected; this catches any residual escape.)
    target = (codesets_dir / f"{name}.csv").resolve()
    if target.parent != codesets_dir.resolve():
        raise WiringError(f"code set name {name!r} escapes the codesets directory")


def _has_drive(name: str) -> bool:
    """A Windows drive prefix (``C:``...), detected with Windows semantics on **every** host.

    ``os.path.splitdrive`` is a no-op on POSIX, so a name like ``C:evil`` would slip through on a
    Linux runner while being rejected on Windows — a config bundle is portable, so the check must be
    OS-independent. ``ntpath`` always applies Windows drive rules."""
    return ntpath.splitdrive(name)[0] != ""


def _reject_toml_collision(codesets_dir: Path, name: str) -> None:
    """For an upsert: reject if a ``codesets/<name>.toml`` exists (the ``.csv`` is the overwrite
    target, allowed). Mirrors the loader's duplicate-stem fail-loud."""
    if (codesets_dir / f"{name}.toml").exists():
        raise WiringError(_collision_message(name, codesets_dir))


def _collision_message(name: str, codesets_dir: Path) -> str:
    # The LITERAL load_code_sets duplicate-name message, so the operator sees the same wording.
    return (
        f"duplicate code set name {name!r} in {codesets_dir} — two files (different "
        "extensions) resolve to the same name; rename one"
    )


# --- path helpers ------------------------------------------------------------


def _codesets_dir(config_dir: str | Path) -> Path:
    return Path(config_dir) / CODESETS_DIR_NAME


def _iter_code_set_files(codesets_dir: Path) -> list[Path]:
    """Sorted ``*.csv``/``*.toml`` files in ``codesets_dir`` (deterministic, mirrors the loader)."""
    return [
        p
        for p in sorted(codesets_dir.iterdir())
        # Skip the #162 <name>.policy.toml sidecars — they are policy metadata, not code sets. Only a
        # TRUE sidecar (companion code set present) is skipped; a standalone x.policy.toml still lists
        # as a code set, mirroring the loader (code_sets.is_policy_sidecar).
        if p.is_file() and p.suffix.lower() in _SUPPORTED_EXTS and not is_policy_sidecar(p)
    ]


def _existing_path(codesets_dir: Path, name: str) -> Path:
    """The on-disk file for ``name`` (``.csv`` preferred over ``.toml``), or raise the loader's
    no-such-code-set error."""
    path = _existing_path_or_none(codesets_dir, name)
    if path is None:
        raise WiringError(
            f"no such code set {name!r} — expected a file codesets/{name}.csv or "
            f"codesets/{name}.toml relative to the --config dir"
        )
    return path


def _existing_path_or_none(codesets_dir: Path, name: str) -> Path | None:
    for ext in _SUPPORTED_EXTS:
        candidate = codesets_dir / f"{name}{ext}"
        if candidate.is_file():
            return candidate
    return None


def _load_all(codesets_dir: Path) -> dict[str, CodeSet]:
    """Run the real loader over the dir (fail-loud on malformed/duplicate/collision).

    Translate the loader's :class:`CodeSetError` to :class:`WiringError` so a read path raises the
    one exception type the CLI catches (the message is preserved verbatim — the loader's wording)."""
    try:
        return load_code_sets(codesets_dir)
    except CodeSetError as exc:
        raise WiringError(str(exc)) from exc


def _load_one(path: Path) -> CodeSet:
    """Load a single code-set file, translating :class:`CodeSetError` to :class:`WiringError`."""
    try:
        return load_code_set(path)
    except CodeSetError as exc:
        raise WiringError(str(exc)) from exc


# --- summaries / grids -------------------------------------------------------


def _summary(path: Path, name: str, registry: dict[str, CodeSet]) -> dict[str, Any]:
    """A SUMMARY dict for the code set at ``path`` (already loaded into ``registry``)."""
    cs = registry[name]
    if path.suffix.lower() == ".csv":
        columns, _ = _read_csv_grid(path)
        value_columns = columns[1:]
        return {
            "name": name,
            "format": "csv",
            "key": columns[0],
            "columns": columns,
            "value_columns": value_columns,
            "shape": _shape(len(value_columns)),
            "entries": len(cs),
            "policy": _policy_detail(cs.policy),  # #162
        }
    # TOML: best-effort header derivation (read-only in the grid).
    columns, _ = _toml_grid(cs)
    value_columns = columns[1:] if columns else []
    return {
        "name": name,
        "format": "toml",
        "key": columns[0] if columns else "",
        "columns": columns,
        "value_columns": value_columns,
        "shape": _shape(len(value_columns)),
        "entries": len(cs),
        "policy": _policy_detail(cs.policy),  # #162
    }


def _shape(value_column_count: int) -> str:
    return "scalar" if value_column_count == 1 else "dict"


def _read_csv_grid(path: Path) -> tuple[list[str], list[list[str]]]:
    """The raw CSV as (headers, rows) — every cell a string, short rows right-padded to the header
    width. Used by ``show`` (and SUMMARY header derivation); the loader is the disposition authority,
    this is purely for grid presentation."""
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        all_rows = list(reader)
    if not all_rows:
        return [], []
    headers = [str(h) for h in all_rows[0]]
    width = len(headers)
    rows: list[list[str]] = []
    for raw in all_rows[1:]:
        cells = [str(c) for c in raw]
        if len(cells) < width:
            cells = [*cells, *([""] * (width - len(cells)))]
        elif len(cells) > width:
            cells = cells[:width]
        rows.append(cells)
    return headers, rows


def _toml_grid(cs: Any) -> tuple[list[str], list[list[str]]]:
    """Best-effort header grid for a TOML code set (read-only in the webview).

    A scalar-valued table → ``["key", "value"]``; a dict-valued table → ``["key", *sorted-subkeys]``.
    Non-string values are stringified for display. Returns ``([], [])`` when no grid can be derived."""
    items = list(cs.items())
    if not items:
        return [], []
    first_value = items[0][1]
    if isinstance(first_value, dict):
        subkeys: list[str] = []
        for _, value in items:
            if isinstance(value, dict):
                for sub in value:
                    if sub not in subkeys:
                        subkeys.append(str(sub))
        columns = ["key", *subkeys]
        rows = [
            [
                str(key),
                *[str(value.get(sub, "")) if isinstance(value, dict) else "" for sub in subkeys],
            ]
            for key, value in items
        ]
        return columns, rows
    columns = ["key", "value"]
    rows = [[str(key), str(value)] for key, value in items]
    return columns, rows


# --- CSV writing + atomic write ----------------------------------------------

# CSV formula-injection (CWE-1236 / ASVS 1.2.10): a spreadsheet treats a cell beginning with one of
# these as a formula, so an operator who opens codesets/<name>.csv in Excel/Sheets could execute one.
# A leading "'" forces the cell to be read as literal text on open. Mirrors harness/load/report.py.
_CSV_FORMULA_TRIGGERS = frozenset("=+-@\t\r\x00")


def _spreadsheet_safe(value: str) -> str:
    """Neutralize a leading formula trigger so a cell can't execute when the CSV is opened in a
    spreadsheet.

    NOTE (round-trip caveat): the codeset CSV is *also* re-parsed by the loader
    (:func:`~messagefoundry.config.code_sets.load_code_set`), which reads cells verbatim. So for a
    cell an operator deliberately begins with one of :data:`_CSV_FORMULA_TRIGGERS`, the loaded value
    carries the defensive ``'`` prefix (e.g. a value ``-5`` round-trips as ``'-5``). This is accepted:
    codeset cells are operator-authored reference data (never PHI / attacker-influenced), and a
    healthcare code-translation key/value that legitimately starts with ``=+-@``/tab/NUL is
    pathological. The far more common alphanumeric cell is untouched (byte-identical round-trip)."""
    return "'" + value if value[:1] in _CSV_FORMULA_TRIGGERS else value


def _build_csv_text(headers: list[str], rows: list[list[str]]) -> str:
    """Render ``headers`` + ``rows`` to CSV text using the stdlib default dialect.

    ``newline=""`` + the default dialect quotes a cell that contains ``,``/``"``/newline — symmetric
    with the loader's ``csv.DictReader(..., newline="")``. Every cell is additionally run through
    :func:`_spreadsheet_safe` (ASVS 1.2.10) so a formula-trigger cell can't execute if the file is
    later opened in a spreadsheet — see that helper's round-trip caveat."""
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow([_spreadsheet_safe(h) for h in headers])
    for row in rows:
        writer.writerow([_spreadsheet_safe(cell) for cell in row])
    return buf.getvalue()


def _write_validated(path: Path, new_text: str, original: bytes | None, validate: Validate) -> None:
    """Atomically write ``new_text``, run ``validate`` (the real loader), roll back on failure.

    ``original`` is the prior file's exact bytes (``None`` for a brand-new file); a rollback restores
    them byte-for-byte, or unlinks a file that didn't exist before."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, new_text.encode("utf-8"))
    try:
        validate(path)
    except BaseException:
        if original is None:
            path.unlink(missing_ok=True)
        else:
            _atomic_write(path, original)
        raise
    _secure_file(path)


def _atomic_write(path: Path, data: bytes) -> None:
    # Write bytes verbatim (no newline translation) so CSV \r\n terminators survive a write/rollback.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _secure_file(path: Path) -> None:
    # Owner-only permissions (defence in depth; a code set can carry sensitive mappings). Reuse the
    # store's primitive, identical to connections_edit.
    from messagefoundry.store.store import _secure_file as _secure

    _secure(path)


# --- #152 referent pre-flight composition ------------------------------------


def _plan_code_set_referents(config_dir: str | Path, old: str, new: str) -> Any:
    """The :class:`~messagefoundry.config.impact.RenamePlan` rewriting a code set's ``code_set("old")``
    referents to ``new``, or ``None`` when the graph can't be loaded / ``old`` isn't referenced. Built
    while ``old`` still resolves (call BEFORE moving the file). The tokenize-safe rewriter lives in
    :mod:`messagefoundry.config.impact` and is never duplicated here."""
    registry = _load_referent_registry(config_dir)
    if registry is None:
        return None
    from messagefoundry.config import impact

    try:
        return impact.plan_rename(registry, config_dir, "code_set", old, new)
    except WiringError:
        return None


def _code_set_referrers(config_dir: str | Path, name: str) -> list[dict[str, str]]:
    """The live Router/Handler referrers of code set ``name`` (delete pre-flight), as JSON dicts.
    Best-effort: an unloadable config yields ``[]``."""
    registry = _load_referent_registry(config_dir)
    if registry is None:
        return []
    from messagefoundry.config import impact
    from messagefoundry.config.reachability import build_reference_index

    index = build_reference_index(registry)
    return [
        {"referrer_kind": r.referrer_kind, "referrer": r.referrer}
        for r in impact.delete_impact(index, "code_set", name)
    ]


def _load_referent_registry(config_dir: str | Path) -> Any:
    """Load the config graph for the referent pre-flight, or ``None`` if it can't be loaded.

    The code-set edit itself is standalone data (validated by re-loading the one file); the referent
    pre-flight additionally needs the wired graph. Loading executes config modules, so a broken /
    absent graph must never fail the core code-set operation — swallow and skip."""
    from messagefoundry.config.wiring import load_config

    try:
        return load_config(config_dir)
    except (WiringError, FileNotFoundError, OSError, ValueError):
        return None
