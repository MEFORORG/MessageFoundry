# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read a file's protected Windows access list, and check what the owner-only rewrite leaves.

The owner-only rewrite is ``store._secure_file``: ``icacls /inheritance:r /grant:r``, which removes
INHERITED entries and replaces the owner's own, and leaves an EXPLICIT entry the file already
carried. A hosted runner's elevated temp files carry SYSTEM, Administrators and OWNER RIGHTS that
way, measured in CI runs 36039014999 and 39087669047 (``tests/test_store_trio_acl.py``,
``tests/test_tee_cli.py``) and again on the first hosted run of the tests that use this module.
Windows only; the callers skip elsewhere."""

from __future__ import annotations

from pathlib import Path

#: The explicit entries a hosted runner's temp file carries into the rewrite: SYSTEM,
#: Administrators and OWNER RIGHTS. A broad group is never one of them.
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


def assert_owner_only_rewrite(path: Path, owner: str) -> None:
    """``path`` carries what the owner-only rewrite leaves: no inherited entry, no deny, ``owner``
    granted full control, and nobody else but ``REWRITE_RESIDUE_SIDS``. A broad group, an inherited
    entry or a missing owner grant fails here."""
    sddl, _, entries = protected_entries(path)
    assert all(kind == "A" and "ID" not in flags for kind, flags, _, _ in entries), sddl
    assert ("A", "", "FA", owner) in entries, sddl
    assert {sid for *_, sid in entries} - {owner} <= REWRITE_RESIDUE_SIDS, sddl
