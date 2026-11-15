# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read a file's Windows access list, build a folder with an exact one, and check an owner-only file.

A test that checks what a restriction leaves must not take its folder from the test's temp
directory. Python 3.13+ writes SYSTEM, Administrators and OWNER RIGHTS onto a directory made with
mode 0700, as pytest's ``tmp_path`` and ``tempfile.mkdtemp`` both are, and on the hosted runners
those entries have survived ``icacls /inheritance:r`` onto a file as explicit entries (CI runs
36039014999 and 43698326298). :func:`folder_granting` gives the test a folder whose list it chose,
so any extra entry on the file comes from the code under test. Windows only; callers skip
elsewhere."""

from __future__ import annotations

from pathlib import Path


def protected_entries(path: Path) -> tuple[str, str | None, list[tuple[str, str, str, str]]]:
    """The SDDL of ``path``, its owner, and its entries as ``(kind, flags, rights, sid)``, each SID
    in ``S-1-...`` form. Asserts the access list is protected (inheritance blocked)."""
    from messagefoundry.config.atomic_edit import _canonical_sid
    from messagefoundry.store.store import _parse_sddl_dacl, _read_dacl_sddl

    sddl = _read_dacl_sddl(path, owner=True)
    assert sddl is not None
    parsed = _parse_sddl_dacl(sddl)
    assert parsed is not None and parsed.protected, sddl
    owner = _canonical_sid(parsed.owner) if parsed.owner else None
    entries = [
        (kind, flags, rights, _canonical_sid(sid) or sid)
        for kind, flags, rights, sid in parsed.aces
    ]
    return sddl, owner, entries


def folder_granting(path: Path, *sids: str) -> Path:
    """Make the folder ``path`` with a protected access list granting exactly ``sids`` full control,
    inherited by what is created in it, and return it. Asserts the list took."""
    from messagefoundry.store.store import _set_security_from_sddl

    path.mkdir()
    sddl = "D:P" + "".join(f"(A;OICI;FA;;;{sid})" for sid in sids)
    result = _set_security_from_sddl(path, sddl, protected=True)
    assert result.failure is None and result.dacl_status == 0, result
    _, _, entries = protected_entries(path)
    assert [sid for *_, sid in entries] == list(sids), entries
    return path


def assert_owner_only(path: Path, grantee: str) -> None:
    """``path`` carries a protected access list with exactly one entry: ``grantee`` allowed full
    control, explicitly."""
    sddl, _, entries = protected_entries(path)
    assert entries == [("A", "", "FA", grantee)], sddl
