# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read a file's Windows access list, and check what the rewrite ``store._secure_file`` leaves.

That rewrite is ``icacls /inheritance:r /grant:r *<token SID>:F``. It removes INHERITED entries and
replaces the token account's own; an EXPLICIT entry the file already carried stays. The project
records that a hosted runner's temp files can carry SYSTEM, Administrators and OWNER RIGHTS that
way, which then survive the rewrite (CI run 36039014999; ``pipeline/dr_backup.py`` beside the
restore staging, ``tests/test_store_trio_acl.py``, ``tests/test_tee_cli.py``). CI run 43698326298
showed the same three after the rewrite on windows-2022 and windows-2025. So a check of the rewrite
compares against what the file carried explicitly BEFORE it, not against one entry: it still fails
when the rewrite copies inherited entries instead of removing them. Windows only; callers skip
elsewhere."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path


def protected_entries(path: Path) -> tuple[str, str | None, list[tuple[str, str, str, str]]]:
    """The SDDL of ``path``, its owner, and its entries as ``(kind, flags, rights, sid)``, each SID
    in ``S-1-...`` form. Asserts the access list is protected (inheritance blocked)."""
    sddl, owner, entries, protected = _read(path)
    assert protected, sddl
    return sddl, owner, entries


def explicit_sids(path: Path) -> frozenset[str]:
    """The SIDs ``path`` grants or denies in an entry that is not inherited."""
    _, _, entries, _ = _read(path)
    return frozenset(sid for _, flags, _, sid in entries if "ID" not in flags)


def born_explicit_sids(directory: Path) -> frozenset[str]:
    """:func:`explicit_sids` of a file just created in a fresh ``mkdtemp`` directory inside
    ``directory``, which is how the config editors create their candidate."""
    private = Path(tempfile.mkdtemp(dir=directory))
    try:
        probe = private / "probe"
        probe.write_bytes(b"x")
        return explicit_sids(probe)
    finally:
        shutil.rmtree(private)


def assert_rewritten_to_grantee(path: Path, grantee: str, carried: frozenset[str]) -> None:
    """``path`` carries what the rewrite leaves: a protected list, no inherited entry, no deny,
    ``grantee`` (the token account the rewrite grants) at full control, and nobody else but a SID
    in ``carried``, the file's explicit entries before the rewrite. A broad group the file did not
    already name, an inherited entry copied rather than removed, or a missing grant fails here."""
    sddl, _, entries = protected_entries(path)
    assert all(kind == "A" and "ID" not in flags for kind, flags, _, _ in entries), sddl
    assert ("A", "", "FA", grantee) in entries, sddl
    assert {sid for *_, sid in entries} - {grantee} <= carried, (sddl, sorted(carried))


def _read(path: Path) -> tuple[str, str | None, list[tuple[str, str, str, str]], bool]:
    from messagefoundry.config.atomic_edit import _canonical_sid
    from messagefoundry.store.store import _parse_sddl_dacl, _read_dacl_sddl

    sddl = _read_dacl_sddl(path, owner=True)
    assert sddl is not None
    parsed = _parse_sddl_dacl(sddl)
    assert parsed is not None, sddl
    owner = _canonical_sid(parsed.owner) if parsed.owner else None
    entries = [
        (kind, flags, rights, _canonical_sid(sid) or sid)
        for kind, flags, rights, sid in parsed.aces
    ]
    return sddl, owner, entries, parsed.protected
