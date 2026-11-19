# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read/write the ``[security]`` section of the service-settings TOML — the comment/format-preserving
editor behind the ``security`` CLI (ADR 0118; the VS Code ``[security]`` GUI editor shells it).

The ``[security]`` switches are **pure data** (booleans/ints/strings and string lists such as
``allowed_client_networks`` — no code), so — like
``connections.toml`` (ADR 0007) and ``[[alerts.rules]]`` (ADR 0014) — they are GUI-manageable. A write
touches only the ``[security]`` table and leaves every other section's comments + formatting byte-stable,
hence ``tomlkit`` rather than a plain serializer. Each mutation validates that the whole settings file
still loads (the same ``load_settings`` path the engine uses — which also **rejects the relocated legacy
keys**). The new text is validated as a candidate beside the live file and replaces it only if it loads
(temp + replace, owner-only perms), under a cross-process lock, so a bad edit never touches the live file
and a concurrent edit is never lost (:mod:`messagefoundry.config.atomic_edit`, vault BACKLOG #2782). Validation is injected as a callback so this module stays free of the settings/engine import graph
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

from messagefoundry.config import atomic_edit

Validate = Callable[[Path], None]


class SecurityEditError(ValueError):
    """A ``[security]`` edit was rejected: a malformed update, a file that wouldn't load (e.g. a value
    that fails validation, or a relocated legacy key), or a file system that refused the edit. Raised
    with an operator-facing message."""


def read_security(service_config: str | Path) -> dict[str, Any]:
    """The ``[security]`` table as authored in ``service_config`` (``{}`` if the file or the ``[security]``
    table is absent). These are the EXPLICITLY-set switches — a caller resolves the secure defaults for
    the unset ones. Comment/format trivia is not returned (values only)."""
    text, _crlf = atomic_edit.read_text_if_present(
        Path(service_config), refused_error=SecurityEditError
    )
    if text is None:
        return {}
    doc = tomlkit.parse(text)
    sec = doc.get("security")
    return dict(sec.unwrap()) if sec is not None else {}


def set_security(
    service_config: str | Path, updates: Mapping[str, Any], *, validate: Validate
) -> dict[str, Any]:
    """Merge ``updates`` into the ``[security]`` table (creating the file + table when a key
    changes), validate the whole file still loads, then write comment-preservingly. A value of
    ``None`` **removes** that key (resets it to its secure default). Raises
    :class:`SecurityEditError` if the result wouldn't load, leaving the TOML untouched. Only the
    ``[security]`` table is edited; other sections are byte-stable.

    The result says what changed (BACKLOG #5327): ``keys`` lists the keys written or removed, and
    ``unchanged`` the keys the edit left as they were, a ``None`` reset that found no such key or a
    value the file already holds. When no key changed, ``op`` is ``"unchanged"``. An existing file
    still goes through the same validated replace, so a file the engine would refuse, or a link, is
    refused as it is for any edit, and the file is rewritten by that replace, which restricts it
    as for every set (:func:`atomic_edit.replace_validated`): on POSIX to its owner afterwards,
    the editing account unless root keeps the previous owner; on Windows to the editing account
    or, where another account owned it, to that account and the editing account; logging a
    warning where it cannot. ``rewritten`` says so, and ``detail`` says it in
    words when no key changed. With only resets asked and no file at the path in a folder that
    exists, nothing is created or checked and ``rewritten`` is false. No edit lock is taken when
    the file is absent at the first check; if it is deleted between that check and the lock, the
    lock is taken and its lock file left as any edit leaves it. A missing folder, or a missing
    drive, is refused, so a mistyped path does not read as a successful reset. This
    module cannot tell a known ``[security]`` key from a misspelled one, since it stays outside the
    settings import graph, so refusing a reset of an unknown key is the caller's job; the
    ``security`` CLI does it."""
    if not isinstance(updates, Mapping):
        raise SecurityEditError("security updates must be a JSON object of {key: value}")
    path = Path(service_config)
    if all(value is None for value in updates.values()):
        if not os.path.lexists(path.parent):
            # A mistyped path must not read as a successful reset.
            raise SecurityEditError(
                f"refused, nothing written: the folder {path.parent} does not exist, so there is "
                "no settings file to reset; check the --service-config path"
            )
        if _nothing_at(path):
            # Only resets, and no file to reset them in: nothing can change, so take no lock,
            # whose file would be the edit's only trace. Anything at the path, a directory or a
            # link among them, goes on to the replace, which fails on it.
            return _absent_result(path, list(updates))
    with atomic_edit.edit_lock(path, busy_error=SecurityEditError, refused_error=SecurityEditError):
        original, crlf = atomic_edit.read_text_if_present(path, refused_error=SecurityEditError)
        doc = tomlkit.parse(original) if original is not None else tomlkit.document()

        sec = doc.get("security")
        created = sec is None
        if sec is None:
            sec = tomlkit.table()
            doc["security"] = sec
        changed: list[str] = []
        unchanged: list[str] = []
        current = sec.unwrap()
        for key, value in updates.items():
            if value is None:
                if key in sec:
                    del sec[key]
                    changed.append(key)
                else:
                    # Reporting this as set would claim a reset that did not happen.
                    unchanged.append(key)
            elif key in current and _same(current[key], value):
                unchanged.append(key)
            else:
                sec[key] = value
                changed.append(key)
        if not changed and original is None and _nothing_at(path):
            # The file went between the check above and the lock: still nothing to reset, and a
            # 0-byte file would be the edit's only effect.
            return _absent_result(path, unchanged)
        # Drop a [security] table this edit emptied, the bare one added above, or a bare header,
        # so a full reset-to-defaults leaves no header behind. A table that already held only
        # comments is kept when the edit removed nothing from it.
        if not len(sec) and (changed or created or not sec.as_string().strip()):
            del doc["security"]

        _write_validated(path, atomic_edit.encode_text(tomlkit.dumps(doc), crlf), validate)
    if changed:
        return {"op": "set", "keys": changed, "unchanged": unchanged, "rewritten": True}
    return {
        "op": "unchanged",
        "keys": [],
        "unchanged": unchanged,
        "rewritten": True,
        # The replace does not report whether its restriction took, so this names the step
        # rather than claim its outcome.
        "detail": "no key changed; file rewritten by the validated replace every set uses, which "
        "restricts it, on POSIX to its owner afterwards (the editing account unless root keeps the "
        "previous owner), on Windows to the editing account or, where another account owned it, to "
        "that account and the editing account, and logs a warning where it cannot",
    }


# --- internals ---------------------------------------------------------------


def _nothing_at(path: Path) -> bool:
    """Whether nothing at all is at ``path``, so an edit that changes no key may skip it.

    Only a lstat that says the file is not found counts, and only in a folder that exists: a name
    the system refuses, a missing folder, or a path under a regular file, is a mistyped path an
    edit must fail on rather than report as absent. ``os.path.lexists`` alone reads every failed lstat
    as absent, so the editors' shared stat gate also refuses a file behind an unreachable share."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        return False
    else:
        return False
    if not os.path.isdir(path.parent):
        return False
    return not atomic_edit.is_file(path, refused_error=SecurityEditError)


def _absent_result(path: Path, unchanged: list[str]) -> dict[str, Any]:
    """The result of an edit that changed no key where no file exists: none is created."""
    return {
        "op": "unchanged",
        "keys": [],
        "unchanged": unchanged,
        "rewritten": False,
        "detail": f"no key changed; {path.name} does not exist, so no settings file was created",
    }


def _same(held: Any, value: Any) -> bool:
    """Whether ``value`` is exactly what the file holds, type by type all the way down, since
    ``True == 1`` and ``1.0 == 1`` would otherwise call a different value the same."""
    if type(held) is not type(value):
        return False
    if isinstance(value, list):
        return len(held) == len(value) and all(map(_same, held, value))
    if isinstance(value, dict):
        return held.keys() == value.keys() and all(_same(held[k], value[k]) for k in value)
    return bool(held == value)


def _write_validated(path: Path, data: bytes, validate: Validate) -> None:
    """Validate ``data`` as a candidate and replace ``path`` with it only if it loads.

    ``validate`` receives the CANDIDATE's path, not the live one (vault BACKLOG #2782), so EVERY
    refusal, a :class:`SecurityEditError` from the callback included, leaves the live file
    byte-for-byte and mode-for-mode as it was; a file that did not exist is never created. (A
    callback refusing in this module's own vocabulary once left the refused text on disk, vault
    BACKLOG #2760; with nothing written before validation there is no rollback to skip.)

    The callback owns the wording of its refusal. A whole-file ``load_settings`` failure must reach
    here already rendered, as the ``security`` CLI's callback renders it with
    ``settings_error_detail``: this module stays outside the settings import graph, so it cannot
    render one, and the ``str(exc)`` below is only for an error the callback did not anticipate."""

    def checked(candidate: Path) -> None:
        try:
            validate(candidate)
        except SecurityEditError:
            raise
        except Exception as exc:
            raise SecurityEditError(str(exc)) from exc

    atomic_edit.replace_validated(path, data, checked, refused_error=SecurityEditError)
