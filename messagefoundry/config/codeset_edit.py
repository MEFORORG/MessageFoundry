# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Write ``codesets/<name>.csv`` — the writer behind the ``codeset`` CLI / VS Code grid editor.

A **code set** is read-only reference data the loader (:mod:`messagefoundry.config.code_sets`) reads
from ``codesets/<name>.csv`` (or ``.toml``) under the ``--config`` dir. This module is the editing
twin of :mod:`messagefoundry.config.connections_edit`: it lets an operator (and the VS Code grid)
list / show / upsert / rename / remove those tables. The on-disk authored format is **CSV-first**
(``upsert`` always writes ``.csv``); ``.toml`` code sets are read-only here (hand-authored / legacy).

The writer mirrors the loader's rules **exactly** so a file it produces always loads: the first
column is the lookup key, at least one value column is required, no duplicate keys, and a stem that
collides with an existing ``.toml`` is rejected (the same ambiguity the loader fails loud on). The
final authority is the loader itself — the new table is written to an owner-only candidate beside the
live file and loaded via :func:`~messagefoundry.config.code_sets.load_code_set` BEFORE it replaces the
live file, so a bad edit never touches it, and the write holds a cross-process lock
(:mod:`messagefoundry.config.atomic_edit`, vault BACKLOG #2782).

The post-write check is injected as a ``validate`` callback (so the CLI passes the *real* loader and
this module stays trivially testable), exactly as ``connections_edit`` does. The name-safety,
structural, and stem-collision checks run **before** any filesystem touch.
"""

from __future__ import annotations

import csv
import io
import logging
import ntpath
import os
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from messagefoundry.config import atomic_edit
from messagefoundry.config.code_sets import (
    CODESETS_DIR_NAME,
    CodeSet,
    CodeSetError,
    UnmappedPolicy,
    _policy_sidecar_path,
    is_policy_sidecar,
    load_code_set,
    load_code_sets,
)
from messagefoundry.config.wiring import WiringError
from messagefoundry.controlchars import has_control_char
from messagefoundry.path_reach import is_absent
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.spreadsheet import SPREADSHEET_FORMULA_TRIGGERS, spreadsheet_safe

if TYPE_CHECKING:
    from messagefoundry.config.impact import PreparedRename

_log = logging.getLogger(__name__)

#: Extensions the loader recognises (the writer only ever *writes* ``.csv``; both are read).
_SUPPORTED_EXTS = (".csv", ".toml")


def _policy_detail(policy: UnmappedPolicy) -> dict[str, Any]:
    """The unmapped-value policy (#162) as a JSON-ready dict for the grid editor to SHOW."""
    return {"kind": policy.kind.value, "default_value": policy.default_value}


#: Run before a write to prove the file loads; the CLI passes the real loader. It receives the
#: CANDIDATE ``.csv`` (the live file's name, in a private directory beside it, with the policy sidecar
#: copied next to it) and raises on any problem, which leaves the live file untouched. A rename,
#: whose bytes do not change, passes the LIVE source table in place instead, ``.csv`` or ``.toml``,
#: its sidecar already beside it, so a validator must only read the path it is given.
Validate = Callable[[Path], None]


# --- read paths --------------------------------------------------------------


def list_code_sets(config_dir: str | Path) -> list[dict[str, Any]]:
    """Every code set under ``<config_dir>/codesets/`` as a SUMMARY dict (``[]`` if the dir is absent).

    Sorted by ``name`` ascending (deterministic; mirrors :func:`load_code_sets`' sorted iteration).
    Raises :class:`WiringError` on a malformed file, a duplicate-key file, a stem collision, or an
    OSError reading the dir — the same fail-loud surface the loader gives."""
    codesets_dir = _codesets_dir(config_dir)
    if not atomic_edit.is_dir(codesets_dir, refused_error=WiringError):
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
    create: bool = False,
) -> dict[str, Any]:
    """Insert-or-replace ``codesets/<name>.csv`` from a header row + data rows (all cells strings).

    Validates the name (safety), the structure (>=1 value column, unique non-empty headers, no
    duplicate keys; a blank-key row carrying data is rejected, a fully-blank row dropped), and the
    stem (no colliding ``.toml``) **before** writing. Loads an owner-only candidate via ``validate`` as
    the final authority and only then replaces the live file, so on any failure the live file is
    untouched (and a brand-new one never created). Raises :class:`WiringError` on bad input or a file
    that wouldn't load.

    ``create`` distinguishes a *create*-flavored save from an *edit* (#240). When ``create`` is True
    the save refuses if **any** supported file already exists for the stem (a ``.csv`` OR ``.toml``) —
    a create must not silently overwrite an existing code set (the same collision class the connection
    wizard/form now refuse, PR #1081). The default (``create=False``) is the edit/overwrite path:
    the same-stem ``.csv`` is the overwrite target and only a ``.toml`` stem collision is rejected."""
    headers = _validate_columns(name, columns)
    emitted = _validate_rows(name, headers, rows)
    codesets_dir = _codesets_dir(config_dir)
    _validate_name(codesets_dir, name)
    path = codesets_dir / f"{name}.csv"
    if not atomic_edit.is_dir(codesets_dir, refused_error=WiringError):
        with atomic_edit.refused_as(path, WiringError, "create its directory"):
            codesets_dir.mkdir(parents=True, exist_ok=True)
    # The existence checks sit inside the lock with the write, so a concurrent create of the same stem
    # cannot pass the check between them.
    with _directory_lock(codesets_dir):
        # On an edit too: the gate refuses a table it cannot stat, which is not one to overwrite.
        existing = _existing_path_or_none(codesets_dir, name)
        if create and existing is not None:
            # A create must not silently overwrite an existing code set — refuse loud (mirrors the
            # wizard/form collision refusal, PR #1081). An edit (create=False) overwrites the .csv.
            raise WiringError(_create_collision_message(name, codesets_dir))
        _reject_toml_collision(path)

        text = _build_csv_text(headers, emitted)
        _write_validated(path, text, validate)

        # The written file is now proven loadable; count its keys for the RESULT.
        entries = len(_load_one(path))
    return {"op": "upsert", "name": name, "format": "csv", "entries": entries}


def rename_code_set(
    config_dir: str | Path, old: str, new: str, *, validate: Validate
) -> dict[str, Any]:
    """Rename ``codesets/<old>.<ext>`` to ``codesets/<new>.<same ext>`` (atomic ``os.replace``),
    moving its ``<old>.policy.toml`` sidecar (#162) to ``<new>.policy.toml`` with it.

    **Both** ``old`` and ``new`` are checked with the same name-safety rules as ``upsert``; the rename
    is rejected if **any** supported file already exists for ``new`` (a stem collision), or if
    ``<new>.policy.toml`` exists: beside the renamed table it would become that table's policy, or
    be overwritten by the moving one (BACKLOG #5776). ``validate`` loads the source table with its
    sidecar before anything moves; the bytes do not change and ``new`` is a checked bare stem, so a
    table that loads there loads under the new name. Raises :class:`WiringError` on at least a
    missing or unsafe ``old``/``new``, an absent source, a stem or sidecar collision, and a
    reference rewrite the rename cannot make (see ``docs/CODESETS.md``); a refusal ``validate``
    raises propagates as it is."""
    if not old:
        raise WiringError("--name is required for `codeset rename`")
    if not new:
        raise WiringError("--to is required for `codeset rename`")
    codesets_dir = _codesets_dir(config_dir)
    # The rename SOURCE is untrusted too, and it builds a filesystem path at ``_existing_path``, so it
    # must clear the same rules as ``new`` BEFORE that lookup, exactly as show/remove do with theirs.
    # Otherwise a traversal ``old`` resolves outside codesets/ and the ``os.replace`` below MOVES that
    # file in, contents intact. Kept after the empty-argument checks so the `--name is required`
    # wording still wins for an empty name (``_validate_name`` has its own, less specific message).
    _validate_name(codesets_dir, old)
    _existing_path(codesets_dir, old)
    _validate_name(codesets_dir, new)
    # One lock for the directory covers both names, so a concurrent upsert or remove of either stem
    # cannot land between the checks and the move (vault BACKLOG #2782). The source is looked up
    # again under it, since it may have gone while this waited.
    with _directory_lock(codesets_dir):
        src = _existing_path(codesets_dir, old)
        # For a rename, ANY supported file for the new stem is a collision (unlike upsert, which
        # may overwrite the same-stem .csv), an extension in another case included.
        if any(
            atomic_edit.is_file(codesets_dir / f"{new}{ext}", refused_error=WiringError)
            for ext in _SUPPORTED_EXTS
        ) or _case_variant(codesets_dir, new):
            raise WiringError(_collision_message(new, codesets_dir))
        # Anything else at those names, such as a folder, refuses the move with a misleading
        # error, or stays beside the renamed table.
        for ext in _SUPPORTED_EXTS:
            if _taken(other := codesets_dir / f"{new}{ext}"):
                raise WiringError(
                    f"cannot rename code set {old!r} to {new!r}: {_rel(other)} already exists "
                    "and is not a code set file; rename or remove it first"
                )

        dest = codesets_dir / f"{new}{src.suffix}"
        # A <new>.policy.toml with no <new> table is a standalone code set: beside the renamed table
        # it would silently become its policy, and a moving sidecar would overwrite it (#5776).
        dest_sidecar = _policy_sidecar_path(dest)
        if _taken(dest_sidecar):
            raise WiringError(
                f"cannot rename code set {old!r} to {new!r}: {dest_sidecar.name} already exists in "
                f"{codesets_dir} and would become the renamed table's policy; rename or remove it "
                "first"
            )
        # The injected loader's word on the table and its policy before anything moves (S10-52).
        # The referent plan below loads the whole config again, which refuses the same table; this
        # call keeps the callback's contract and gives the earlier, narrower refusal.
        validate(src)
        # Referent pre-flight (#152): a code set is named by string literals in the Router/Handler
        # modules that call code_set("old"). PLAN the referent rewrite BEFORE moving the file — the
        # plan is built from the loaded graph while "old" still resolves (the loader would otherwise
        # fail on a code_set("old") capture whose table just vanished). impact.py owns the
        # tokenize-safe rewriter, so it is never duplicated here. A config that does not load has
        # referents nobody can find, so the rename refuses rather than move the file under them
        # (BACKLOG #5980).
        plan = _plan_code_set_referents(config_dir, old, new)
        if plan.unresolved:
            # A referrer the planner could not rewrite would still read the old name once the file
            # moved, so the table would vanish under it. Refuse before anything moves (BACKLOG #5980).
            named = ", ".join(f"{r.referrer_kind} {r.referrer!r}" for r in plan.unresolved)
            raise WiringError(
                f"cannot rename code set {old!r} to {new!r}: {len(plan.unresolved)} reference(s) "
                f"cannot be rewritten and would still read the old name: {named}. Nothing was "
                "changed; rewrite those references by hand, or run `messagefoundry-toolkit impact "
                f"--config <dir> code_set {old} --rename-to {new}` to see the plan"
            )
        from messagefoundry.config import impact

        # Checked against the files before the table moves: a referent file that changed since
        # the plan refuses here, with nothing moved (BACKLOG #5980).
        prepared = impact.prepare_rename(plan)
        had_sidecar = atomic_edit.is_file(_policy_sidecar_path(src), refused_error=WiringError)
        # Where table and policy belong if the rename must be undone by hand. Built before the
        # move, so the move's return leads straight into the try that undoes it.
        home = _pair(src, had_sidecar)
        result: dict[str, Any] = {"op": "rename", "name": old, "to": new}
        try:
            _move_with_sidecar(src, dest, has_sidecar=had_sidecar)
        except _SplitPairError as exc:
            raise WiringError(
                f"{exc}. No reference was rewritten, so they still name {old!r}: put the table "
                f"back as {_rel(src)}, and any policy as {_rel(_policy_sidecar_path(src))}, by hand"
            ) from exc
        # The referent rewrite stays under the lock: a second rename planned between the move
        # and the rewrite would read literals naming a table that is already gone.
        try:
            rewritten = len(impact.write_rename(prepared))
        except impact.RenameWriteError as exc:
            # A file the write could not restore, read again: one that holds the bytes the plan
            # read names the old table after all, and one that cannot be read counts as left,
            # as after an interrupt.
            unrestored = set(exc.unrestored)
            still_new = [f for f in impact.rewritten_files(prepared) if f in unrestored]
            if still_new:
                # A reference that may be left naming the new table would lose it to a move back,
                # so the code set stays. The message names the files config-relative, and the
                # error by its type only.
                left, others = _reference_split(config_dir, prepared, still_new)
                raise WiringError(
                    f"cannot rename code set {old!r} to {new!r}: a reference write failed "
                    f"({_cause_name(exc)}), and these could not be restored and may still name "
                    f"{new!r}: {left}. The code set stays as {_pair(dest, had_sidecar)}; these "
                    f"name {old!r}: {others}. Rewrite the references to one name by hand, and "
                    f"move the code set to match: to keep {old!r}, put it back as {home}"
                ) from exc
            # A write failed and the files written were restored, so the table moves back to the
            # name they read. The move back is never undone: a half that fails leaves what moved
            # under the old name, which is where the references read it.
            try:
                _move_with_sidecar(dest, src, roll_back=False, has_sidecar=had_sidecar)
            except _SplitPairError as back:
                # Its text ends with where each file is.
                raise WiringError(
                    f"{exc}. Moving the code set back then failed ({back}), while its references "
                    f"still name {old!r}: put it back as {home} by hand"
                ) from exc
            raise WiringError(f"{exc}. The code set was moved back to {home}") from exc
        except BaseException:
            # An interrupt (Ctrl-C, SystemExit) or an unexpected error. write_rename restores only
            # what was cut off inside a write, so an interrupt after a write returned, or while
            # its locks were released, can leave references naming the new table. Read the files:
            # the table goes back only when none is left rewritten, so table and references agree.
            rewritten_left = impact.rewritten_files(prepared)
            if rewritten_left:
                left, others = _reference_split(config_dir, prepared, rewritten_left)
                _log.error(
                    "code set rename interrupted: %s left naming %r, so the code set stays as %s; "
                    "these still name %r: %s",
                    left,
                    new,
                    _pair(dest, had_sidecar),
                    old,
                    others,
                )
                raise
            try:
                _move_with_sidecar(dest, src, roll_back=False, has_sidecar=had_sidecar)
            except _SplitPairError as back:
                # The error's type only: its text may carry a host path.
                _log.error(
                    "code set rename interrupted: moving the code set back failed (%s), so %s; "
                    "its references name %r, so put it back as %s by hand",
                    _cause_name(back),
                    back.layout,
                    old,
                    home,
                )
            raise
        if rewritten:
            result["referents_rewritten"] = rewritten
    return result


def remove_code_set(config_dir: str | Path, name: str, *, validate: Validate) -> dict[str, Any]:
    """Delete ``codesets/<name>.csv`` (else ``.toml``) and its ``<name>.policy.toml`` sidecar
    (#162), which left behind would load as a standalone code set (BACKLOG #5776). A sidecar a
    second same-stem table still reads (a duplicate the loader refuses) is kept. Raises
    :class:`WiringError` on at least a missing ``name``, no such file, and a sidecar that could not
    be deleted after the table was.

    ``validate`` is accepted for signature symmetry with the other mutators (a delete has nothing to
    re-load) and is intentionally unused."""
    del validate  # a delete leaves nothing to re-validate; kept for a uniform mutator signature
    # Here, not at module top, so importing the config layer does not import the auth package.
    from messagefoundry.restricted_file import unlink_generated

    if not name:
        raise WiringError("--name is required for `codeset remove`")
    codesets_dir = _codesets_dir(config_dir)
    # The operator-supplied name is untrusted: a delete path must reject traversal (`../../x`, drive,
    # embedded ext) BEFORE building a filesystem path, or a `remove` could unlink any file on disk.
    _validate_name(codesets_dir, name)
    # Under the directory lock, so an upsert of the same stem cannot re-create it mid-remove
    # (vault BACKLOG #2782).
    _existing_path(codesets_dir, name)
    with _directory_lock(codesets_dir):
        path = _existing_path(codesets_dir, name)
        # Delete pre-flight (#152): surface the live Router/Handler referents that will now dangle
        # (a code_set("name") that no longer resolves). Computed BEFORE the unlink — while "name"
        # still resolves — because the reverse index only builds a code_set edge for a *registered*
        # table, so a reload after the file is gone would find no referrers. Mirrors the rename path
        # (plan-before-move). Best-effort + additive: the delete is the core op, so an unloadable
        # graph yields no referrers.
        dangling = _code_set_referrers(config_dir, name)
        sidecar = _policy_sidecar_path(path)
        # Decided before the unlink: a second same-stem table (a duplicate the loader refuses)
        # still reads the sidecar as its policy, so it is kept for that table.
        drop_sidecar = atomic_edit.is_file(
            sidecar, refused_error=WiringError
        ) and not _other_table_exists(path)
        try:
            with atomic_edit.refused_as(path, WiringError, "remove it"):
                unlink_generated(path)
            # After the table, so a failure here is loud rather than a table silently stripped of
            # its policy.
            if drop_sidecar:
                _remove_orphan_sidecar(name, sidecar, dangling)
        except WiringError:
            # A refusal says itself: a refused table is still there, and a sidecar that could not
            # be deleted is named in the error.
            raise
        except BaseException:
            # An interrupt after the table's unlink, or in the sidecar's: the sidecar still must
            # not outlive its table.
            if drop_sidecar:
                _drop_sidecar_if_table_gone(path, sidecar, dangling)
            raise
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
    if has_control_char(name):
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


def _reject_toml_collision(target: Path) -> None:
    """For an upsert of ``target``, ``codesets/<name>.csv``: reject if a ``codesets/<name>.toml``
    exists (``target`` is the overwrite target, allowed). Mirrors the loader's duplicate-stem
    fail-loud."""
    codesets_dir, name = target.parent, target.stem
    # A folder of that name has always collided too.
    if _taken(codesets_dir / f"{name}.toml") or _case_variant(codesets_dir, name, besides=target):
        raise WiringError(_collision_message(name, codesets_dir))


def _collision_message(name: str, codesets_dir: Path) -> str:
    # The LITERAL load_code_sets duplicate-name message, so the operator sees the same wording.
    return (
        f"duplicate code set name {name!r} in {codesets_dir} — two files (different "
        "extensions) resolve to the same name; rename one"
    )


def _create_collision_message(name: str, codesets_dir: Path) -> str:
    # A create-flavored save under an existing stem (#240): refuse rather than overwrite (PR #1081's
    # collision-refusal class). Distinct wording from the .toml duplicate-stem message above.
    return (
        f"code set {name!r} already exists in {codesets_dir} — a create must not overwrite it "
        "(edit it, or choose another name)"
    )


# --- path helpers ------------------------------------------------------------


def _codesets_dir(config_dir: str | Path) -> Path:
    return Path(config_dir) / CODESETS_DIR_NAME


def _directory_lock(codesets_dir: Path) -> AbstractContextManager[None]:
    """The cross-process edit lock for every code set in ``codesets_dir`` (vault BACKLOG #2782).

    It is the CONFIG directory's lock, the one ``connections_edit`` takes, so the CLI's edits of
    one directory run one at a time. Keyed on the directory, never on an operator-supplied name,
    so no name can steer the lock file."""
    return atomic_edit.edit_lock(codesets_dir, busy_error=WiringError, refused_error=WiringError)


def _iter_code_set_files(codesets_dir: Path) -> list[Path]:
    """Sorted ``*.csv``/``*.toml`` files in ``codesets_dir`` (deterministic, mirrors the loader)."""
    return [
        p
        for p in sorted(codesets_dir.iterdir())
        # Skip the #162 <name>.policy.toml sidecars — they are policy metadata, not code sets. Only a
        # TRUE sidecar (companion code set present) is skipped; a standalone x.policy.toml still lists
        # as a code set, mirroring the loader (code_sets.is_policy_sidecar).
        if p.suffix.lower() in _SUPPORTED_EXTS
        and not _is_editor_lock_link(p)
        and atomic_edit.is_file(p, refused_error=WiringError)
        and not is_policy_sidecar(p)
    ]


def _is_editor_lock_link(path: Path) -> bool:
    """A dangling ``.#<name>`` link, as Emacs leaves for unsaved edits to a table. The loader skips
    a dangling link, so the listing's gate must not refuse every table over this one."""
    return path.name.startswith(".#") and path.is_symlink() and not path.exists()


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
        if atomic_edit.is_file(candidate, refused_error=WiringError):
            return candidate
    return None


class _SplitPairError(WiringError):
    """A move left the table, and any policy sidecar, off the names it was asked to leave them
    under. ``layout`` says where each file is, by config-relative name only."""

    def __init__(self, message: str, layout: str) -> None:
        super().__init__(message)
        self.layout = layout

    def __reduce__(self) -> tuple[type[_SplitPairError], tuple[str, str]]:
        # Exception pickles as cls(*args), and args holds only the message.
        return (type(self), (str(self), self.layout))


def _move_with_sidecar(
    src: Path, dest: Path, *, roll_back: bool = True, has_sidecar: bool | None = None
) -> bool:
    """Move table ``src`` to ``dest`` and its policy sidecar (#162), if any, beside it (BACKLOG
    #5776), returning whether a sidecar moved. ``has_sidecar`` says whether one moves; ``None``
    reads it from the disk.

    With ``roll_back``, a forward move: the table moves first, so a move cut off half way never
    leaves a table under the name the references read without its policy. A reference then finds
    no table (at load for a module-level capture, else at its first lookup) rather than running
    with the wrong policy. A failure or an interrupt at any point moves back whatever had moved, read
    from the files rather than assumed, since an interrupt can land on either side of a replace.
    A stat that fails is not read as absent: the move back stops there. If the move back fails, a
    failure raises :class:`_SplitPairError` saying where each file is, and an interrupt logs it.

    Without ``roll_back``, a move that is itself the undo of an earlier one, toward the name the
    references read: the sidecar moves first, for the same reason, and nothing is moved back,
    which would carry the files away from that name again. A failure raises
    :class:`_SplitPairError` and an interrupt logs, each saying where each file is."""
    # Here, not at module top, so importing the config layer does not import the auth package.
    from messagefoundry.restricted_file import replace_generated

    src_sidecar = _policy_sidecar_path(src)
    dest_sidecar = _policy_sidecar_path(dest)
    if has_sidecar is None:
        has_sidecar = atomic_edit.is_file(src_sidecar, refused_error=WiringError)
    steps = [(src, dest)] + ([(src_sidecar, dest_sidecar)] if has_sidecar else [])
    if not roll_back:
        steps.reverse()
    try:
        for moving, to in steps:
            with atomic_edit.refused_as(moving, WiringError, f"rename it to {to.name}"):
                replace_generated(moving, to)
    except BaseException as exc:
        back: WiringError | OSError | None = None
        if roll_back:
            try:
                if has_sidecar and _present(dest_sidecar) and not _present(src_sidecar):
                    with atomic_edit.refused_as(
                        dest_sidecar, WiringError, f"rename it back to {src_sidecar.name}"
                    ):
                        replace_generated(dest_sidecar, src_sidecar)
                if _present(dest) and not _present(src):
                    with atomic_edit.refused_as(dest, WiringError, f"rename it back to {src.name}"):
                        replace_generated(dest, src)
            except (WiringError, OSError) as failed:
                back = failed
        if roll_back and back is None:
            raise
        layout = _layout(src, dest, has_sidecar)
        if isinstance(exc, (WiringError, OSError)):
            undo = f"; moving back failed ({back})" if back is not None else ""
            raise _SplitPairError(f"{exc}{undo}, so {layout}", layout) from exc
        # Config-relative names and the error's type only: a log line carries no host path.
        _log.error(
            "code set move cut off by %s%s, so %s; they belong as %s",
            type(exc).__name__,
            f": moving back failed ({_cause_name(back)})" if back is not None else "",
            layout,
            _pair(src if roll_back else dest, has_sidecar),
        )
        raise
    return has_sidecar


def _rel(path: Path) -> str:
    """``path``, a file in the codesets directory, named relative to the config dir, so a log line
    that names it carries no host path."""
    return f"{CODESETS_DIR_NAME}/{path.name}"


def _pair(table: Path, has_sidecar: bool) -> str:
    """``table``, and its policy sidecar when it has one, by config-relative name."""
    return _rel(table) + (f" and {_rel(_policy_sidecar_path(table))}" if has_sidecar else "")


def _reference_split(
    config_dir: str | Path, prepared: PreparedRename, left: list[str]
) -> tuple[str, str]:
    """The referencing files of a rename ``prepared`` that are ``left`` rewritten, and the rest, each
    joined by config-relative name, so a message or log line carries no host path."""
    return (
        ", ".join(_config_rel(config_dir, f) for f in left),
        ", ".join(_config_rel(config_dir, f) for f, _raw, _new in prepared.files if f not in left)
        or "none",
    )


def _config_rel(config_dir: str | Path, file: str) -> str:
    """A referencing module ``file`` named relative to ``config_dir``, else by its bare name, so a
    log line carries no host path."""
    try:
        return Path(file).resolve().relative_to(Path(config_dir).resolve()).as_posix()
    except (ValueError, OSError):
        return Path(file).name


def _present(path: Path) -> bool:
    """Whether anything is at ``path``, a link that leads nowhere included. Only a missing name
    reads as absent (:func:`~messagefoundry.path_reach.is_absent`, which a share Windows cannot
    reach is not); any other failed stat raises, so an unreadable entry is never taken for a free
    name. Unlike ``Path.exists``, which answers ``False`` for every failed stat."""
    try:
        path.lstat()
    except FileNotFoundError as exc:
        if is_absent(exc):
            return False
        raise
    return True


def _taken(path: Path) -> bool:
    """Whether a name is taken in the codesets directory, by a file, a folder or a link: the
    shared gate's refusal for a stat it cannot make, then :func:`_present`."""
    if atomic_edit.is_file(path, refused_error=WiringError):
        return True
    with atomic_edit.refused_as(path, WiringError, atomic_edit.READ_STEP):
        return _present(path)


def _case_variant(codesets_dir: Path, name: str, *, besides: Path | None = None) -> Path | None:
    """A table file of stem ``name`` whose extension differs from ``.csv``/``.toml`` only in case
    (``name.CSV``), which the loader reads too and a case-sensitive file system keeps apart.

    ``besides`` is the table being edited, which is never its own variant. A case-insensitive file
    system opens ``name.CSV`` under the name ``name.csv`` and lists it under its own spelling, so a
    ``besides`` that is a file the listing does not spell exactly is the entry spelled like it in
    another case. Compared by listed name, never by path (``WindowsPath`` equality ignores case)
    or by inode (a link beside the table is a second table to the loader)."""
    with atomic_edit.refused_as(codesets_dir, WiringError, atomic_edit.READ_STEP):
        entries = list(codesets_dir.iterdir())
    itself = (
        besides.name.lower()
        if besides is not None
        and besides.name not in {p.name for p in entries}
        and atomic_edit.is_file(besides, refused_error=WiringError)
        else None
    )
    return next(
        (
            p
            for p in entries
            if p.stem == name
            and p.suffix not in _SUPPORTED_EXTS
            and p.suffix.lower() in _SUPPORTED_EXTS
            and atomic_edit.is_file(p, refused_error=WiringError)
            and p.name.lower() != itself
        ),
        None,
    )


def _cause_name(exc: BaseException) -> str:
    """The type of the OS error under ``exc``, else of ``exc``: a refusal wraps the error that
    says whether a file was held or denied, and a log line gives the type, never the text."""
    cause: BaseException | None = exc
    while cause is not None and not isinstance(cause, OSError):
        cause = cause.__cause__
    return type(cause or exc).__name__


def _where(home: Path, away: Path) -> str:
    """Which of two names a moved file is under, read without assuming: a stat that fails says
    so rather than guessing."""
    try:
        if _present(home):
            return _rel(home)
    except OSError:
        return f"{_rel(home)} or {_rel(away)} ({_rel(home)} could not be read)"
    try:
        if _present(away):
            return _rel(away)
    except OSError:
        return f"{_rel(away)}, if anywhere (it could not be read)"
    return f"under neither {_rel(home)} nor {_rel(away)}"


def _layout(src: Path, dest: Path, has_sidecar: bool) -> str:
    """Where a moved table, and its policy sidecar, are now, by config-relative name."""
    layout = f"the table is {_where(src, dest)}"
    if has_sidecar:
        policy = _where(_policy_sidecar_path(src), _policy_sidecar_path(dest))
        layout += f" and its policy {policy}"
    return layout


def _drop_sidecar_if_table_gone(table: Path, sidecar: Path, dangling: list[dict[str, str]]) -> None:
    """After an interrupt in a remove: delete the policy ``sidecar`` once ``table`` is gone, since
    it would load as a code set of its own. A table whose stat fails keeps its policy. Whatever is
    left is logged at ``ERROR`` by config-relative name, with the error's type only."""
    # Here, not at module top, so importing the config layer does not import the auth package.
    from messagefoundry.restricted_file import unlink_generated

    try:
        if _present(table):
            return
    except OSError as exc:
        _log.error(
            "code set remove interrupted: whether %s was removed could not be read (%s), so its "
            "policy %s was kept; remove that by hand once the table is gone",
            _rel(table),
            type(exc).__name__,
            _rel(sidecar),
        )
        return
    try:
        unlink_generated(sidecar)
    except OSError as exc:
        if isinstance(exc, FileNotFoundError) and is_absent(exc):
            return
        _log.error(
            "code set remove interrupted: %s was removed, but its policy %s was not (%s); it "
            "now loads as a code set of its own, so remove it by hand%s",
            _rel(table),
            _rel(sidecar),
            type(exc).__name__,
            _still_referenced(dangling),
        )


def _other_table_exists(path: Path) -> bool:
    """Whether a second table of ``path``'s stem sits beside it, an extension in another case
    included."""
    return (
        any(
            atomic_edit.is_file(path.with_suffix(ext), refused_error=WiringError)
            for ext in _SUPPORTED_EXTS
            if ext != path.suffix
        )
        or _case_variant(path.parent, path.stem, besides=path) is not None
    )


def _remove_orphan_sidecar(name: str, sidecar: Path, dangling: list[dict[str, str]]) -> None:
    """Delete the policy sidecar of the removed code set ``name``; one that cannot be deleted
    would load as a code set of its own, so that raises :class:`WiringError` naming it."""
    # Here, not at module top, so importing the config layer does not import the auth package.
    from messagefoundry.restricted_file import unlink_generated

    try:
        with atomic_edit.refused_as(sidecar, WiringError, "remove it"):
            unlink_generated(sidecar)
    except (WiringError, OSError) as exc:
        if isinstance(exc, FileNotFoundError) and is_absent(exc):
            return  # already gone, which is the goal
        raise WiringError(
            f"code set {name!r} was removed, but its policy sidecar {sidecar.name} was not "
            f"({exc}); it now loads as a code set of its own, so remove it by hand"
            f"{_still_referenced(dangling)}"
        ) from exc


def _still_referenced(dangling: list[dict[str, str]]) -> str:
    """The referrers a removed code set leaves dangling, by object name, as a message suffix."""
    if not dangling:
        return ""
    return "; these still reference it: " + ", ".join(
        f"{r['referrer_kind']} {r['referrer']!r}" for r in dangling
    )


def _load_all(codesets_dir: Path) -> dict[str, CodeSet]:
    """Run the real loader over the dir (fail-loud on malformed/duplicate/collision).

    Translate the loader's :class:`CodeSetError` to :class:`WiringError` so a read path raises the
    one exception type the CLI catches (the message is preserved verbatim — the loader's wording)."""
    try:
        with atomic_edit.refused_as(codesets_dir, WiringError, atomic_edit.READ_STEP):
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
    this is purely for grid presentation.

    An **over-wide** row (more cells than the header) is **refused** (``WiringError``), NOT sheared
    (#240): the old ``cells[:width]`` truncation let a show → save round-trip persist the shear into the
    file, silently dropping the extra cells and defeating the write-path ``_validate_rows`` guard. An
    over-wide row is malformed data the editor refuses at read time — the same never-accept-and-drop
    rule the blank-key-with-values check already applies (and it mirrors the loader's own tightening)."""
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        all_rows = list(reader)
    if not all_rows:
        return [], []
    headers = [str(h) for h in all_rows[0]]
    width = len(headers)
    rows: list[list[str]] = []
    for i, raw in enumerate(all_rows[1:]):
        cells = [str(c) for c in raw]
        if len(cells) > width:
            raise WiringError(
                f"code set {path.stem!r}: row {i} has more cells than columns "
                f"({len(cells)} > {width})"
            )
        if len(cells) < width:
            cells = [*cells, *([""] * (width - len(cells)))]
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
# A leading "'" forces the cell to be read as literal text on open. This is now the canonical engine
# rule (messagefoundry/spreadsheet.py); this module used to carry its own copy, which omitted LF and
# tested only value[:1], so "   =evil()" rode straight through it.
_CSV_FORMULA_TRIGGERS = SPREADSHEET_FORMULA_TRIGGERS


def _spreadsheet_safe(value: str) -> str:
    """Neutralize a leading formula trigger so a cell can't execute when the CSV is opened in a
    spreadsheet — :func:`~messagefoundry.spreadsheet.spreadsheet_safe` plus this writer's caveat.

    NOTE (round-trip caveat): the codeset CSV is *also* re-parsed by the loader
    (:func:`~messagefoundry.config.code_sets.load_code_set`), which reads cells verbatim. So for a
    cell an operator deliberately begins with one of :data:`_CSV_FORMULA_TRIGGERS`, the loaded value
    carries the defensive ``'`` prefix (e.g. a value ``-5`` round-trips as ``'-5``). Under the
    canonical rule the accepted cost now *also* covers a cell whose trigger sits behind leading
    whitespace or another importer-droppable character (``"  -5"`` becomes ``"'  -5"``), and it
    applies to the KEY column, so such a key is then looked up under its prefixed form. Still
    accepted: codeset cells are operator-authored reference data (never PHI / attacker-influenced),
    and a healthcare code-translation key/value that legitimately starts with ``=+-@``/tab/NUL — or
    with whitespace ahead of one — is pathological. The far more common alphanumeric cell is
    untouched (byte-identical round-trip), and no shipped sample codeset changes under the widening.
    """
    return spreadsheet_safe(value)


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


def _write_validated(path: Path, new_text: str, validate: Validate) -> None:
    """Load ``new_text`` as a candidate via ``validate`` (the real loader), then replace ``path``.

    The candidate carries the live file's name, so the loader reads the same code-set name and format,
    and the ``<name>.policy.toml`` sidecar is copied beside it, so the candidate loads exactly as the
    live file would, policy included. Bytes go out verbatim, so CSV ``\r\n`` terminators survive."""
    atomic_edit.replace_validated(
        path,
        new_text.encode("utf-8"),
        validate,
        companions=(_policy_sidecar_path(path),),
        refused_error=WiringError,
    )


# --- #152 referent pre-flight composition ------------------------------------


def _plan_code_set_referents(config_dir: str | Path, old: str, new: str) -> Any:
    """The :class:`~messagefoundry.config.impact.RenamePlan` rewriting a code set's ``code_set("old")``
    referents to ``new``. Built while ``old`` still resolves (call BEFORE moving the file). The
    tokenize-safe rewriter lives in :mod:`messagefoundry.config.impact` and is never duplicated here.

    Raises :class:`WiringError` when no plan can be built: a config that does not load, or a plan
    the planner refuses. The referents are then unknown, and moving the file would leave every
    ``code_set("old")`` reading a table that is gone while the rename reported success (BACKLOG
    #5980)."""
    from messagefoundry.config import impact

    try:
        registry = _load_referent_registry_or_raise(config_dir)
    except _REGISTRY_LOAD_ERRORS as exc:
        # Scrubbed as validate_config scrubs it: a load error can echo a setting's value.
        reason = scrub_credentials(str(exc))
        raise WiringError(
            f"cannot rename code set {old!r} to {new!r}: its references could not be checked "
            f"({reason}). Nothing was changed; fix the config so it loads, then rename again"
        ) from exc
    # A refusal of the planner's own carries its own reason, and nothing has moved yet.
    return impact.plan_rename(registry, config_dir, "code_set", old, new)


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


#: What load_config raises for a config that does not load.
_REGISTRY_LOAD_ERRORS = (WiringError, OSError, ValueError)


def _load_referent_registry(config_dir: str | Path) -> Any:
    """Load the config graph for the delete pre-flight, or ``None`` if it can't be loaded: a broken
    graph never fails a ``remove``, whose referrers are advisory. A ``rename`` needs the graph to
    rewrite its referents, and refuses without it (:func:`_plan_code_set_referents`)."""
    try:
        return _load_referent_registry_or_raise(config_dir)
    except _REGISTRY_LOAD_ERRORS as exc:
        _log.warning(
            "code set referrer check skipped: the config does not load (%s)", type(exc).__name__
        )
        return None


def _load_referent_registry_or_raise(config_dir: str | Path) -> Any:
    """Load the config graph for a referent pre-flight.

    The code-set edit itself is standalone data (validated by re-loading the one file); the referent
    pre-flight additionally needs the wired graph.

    ``allow_empty``: this is an AUTHORING surface, like ``connection upsert/remove`` (BACKLOG #1648).
    Swallowing the empty-graph refusal here would be SILENT and wrong, not merely conservative — a
    connection-less bundle still has Routers/Handlers that reference code sets, so ``rename`` would
    move the table and leave every ``code_set("old")`` call dangling with no ``referents_rewritten``
    in its result, and ``remove`` would report zero dangling referrers when there are some. Measured
    A/B with a connection declared and without: the only difference was the connection, and only the
    connection-less arm lost the rewrite."""
    from messagefoundry.config.wiring import load_config

    return load_config(config_dir, allow_empty=True)
