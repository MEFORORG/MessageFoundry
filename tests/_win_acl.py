# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read a file's Windows access list, and check what the rewrite ``store._secure_file`` leaves.

That rewrite is ``icacls /inheritance:r /grant:r *<token SID>:F``. It removes INHERITED entries and
replaces the token account's own; an EXPLICIT entry the file already carried stays. On the hosted
windows-2022 and windows-2025 runners the rewritten file still names SYSTEM, Administrators and
OWNER RIGHTS, as explicit entries beside the token account (CI run 43698326298; earlier, CI run
36039014999, recorded beside the restore staging in ``pipeline/dr_backup.py``). Every one of those
readings was taken AFTER the rewrite. Whether the entries were explicit before it, or were
inherited and came out explicit, is not measured, and this check cannot tell the two apart for
those three: a rewrite that copied exactly those inherited entries would pass. It still fails on
any other entry, an inherited one, a deny, or a missing grant (the control in
``tests/test_atomic_edit.py``). Windows only; callers skip elsewhere."""

from __future__ import annotations

from pathlib import Path

#: SYSTEM, Administrators and OWNER RIGHTS: what the hosted runners leave beside the token account.
REWRITE_RESIDUE_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544", "S-1-3-4"})


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


def assert_rewritten_to_grantee(path: Path, grantee: str) -> None:
    """``path`` carries what the rewrite leaves: a protected list, no inherited entry, no deny,
    ``grantee`` (the token account the rewrite grants) at full control, and nobody else but
    ``REWRITE_RESIDUE_SIDS``. A broad group, an inherited entry or a missing grant fails here."""
    sddl, _, entries = protected_entries(path)
    assert all(kind == "A" and "ID" not in flags for kind, flags, _, _ in entries), sddl
    assert ("A", "", "FA", grantee) in entries, sddl
    assert {sid for *_, sid in entries} - {grantee} <= REWRITE_RESIDUE_SIDS, sddl
