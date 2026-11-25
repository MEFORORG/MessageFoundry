# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 6.7.1 (BACKLOG #1142, the directory arm): can another principal replace a trust anchor
through its path?

Three layers:

1. Pure tests of the Windows rule over recorded ``(type, flags, mask, sid)`` entries, and of the
   POSIX rule over recorded ``(uid, mode)`` tables. They run on every platform, so the Linux CI leg
   exercises the logic of both arms. The Windows entries were read on a Windows 11 host on
   2026-09-24 with this module's own reader; the machine SID is replaced by ``_M``.
2. Real-file-system tests, gated by platform.
3. The liveness receipt: a real directory grant makes ``run_anchor_preflight`` refuse, and
   removing it makes the same preflight pass.

Where a test names "red under", that is the one edit to the rule that must turn it red.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth import anchor_path as ap
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import (
    DIRECTORY,
    FILE,
    LINK,
    PosixStat,
    WinSecurity,
    WinTrust,
    evaluate_windows_object,
    posix_path_verdict,
    windows_chain,
    windows_path_verdict,
)
from messagefoundry.auth.trust_anchors import AUDIT_ACTION, AnchorSpec, TrustAnchorError
from messagefoundry.service_status import _system_exe
from messagefoundry.store import MessageStore
from tests.test_trust_anchors import _block

_windows_only = pytest.mark.skipif(sys.platform != "win32", reason="reads a real NTFS DACL")
_posix_only = pytest.mark.skipif(sys.platform == "win32", reason="reads real POSIX mode bits")

# --- recorded Windows data ------------------------------------------------------------------------

_M = "S-1-5-21-1000000001-1000000002-1000000003"  # the measured host's machine authority, replaced
USER = f"{_M}-1002"  # the interactive user: a direct member of Administrators
OTHER = f"{_M}-1003"  # a local user who is not
SERVICE = "S-1-5-80-1111111111-2222222222-3333333333-4444444444-5555555555"
TI = ap.TRUSTED_INSTALLER_SID
SYSTEM = "S-1-5-18"
ADMINS = "S-1-5-32-544"
USERS = "S-1-5-32-545"
AUTH_USERS = "S-1-5-11"
INTERACTIVE = "S-1-5-4"

# C:\ as Windows 11 ships it. The Authenticated Users entry with flags 0x0b is inherit-only and
# carries GENERIC_ALL-ish bits plus DELETE; the one with flags 0x00 is add-subdirectory alone.
ROOT = WinSecurity(
    TI,
    (
        (0, 0x03, 0x001F01FF, ADMINS),
        (0, 0x03, 0x001F01FF, SYSTEM),
        (0, 0x03, 0x001200A9, USERS),
        (0, 0x0B, 0xE0010000, AUTH_USERS),
        (0, 0x00, 0x00000004, AUTH_USERS),
        (0, 0x00, 0x001000A1, "S-1-15-3-65536-1888954469-739942743-1668119174-2468466756"),
    ),
)
PROGRAMDATA = WinSecurity(
    SYSTEM,
    (
        (0, 0x03, 0x001F01FF, SYSTEM),
        (0, 0x03, 0x001F01FF, ADMINS),
        (0, 0x0B, 0x10000000, "S-1-3-0"),
        (0, 0x03, 0x001200A9, USERS),
        (0, 0x02, 0x00000116, USERS),
    ),
)
# A directory made under C:\ProgramData by New-Item, as the user, with nothing changed after.
PD_NEW = WinSecurity(
    USER,
    (
        (0, 0x13, 0x001F01FF, SYSTEM),
        (0, 0x13, 0x001F01FF, ADMINS),
        (0, 0x10, 0x001F01FF, USER),
        (0, 0x1B, 0x10000000, "S-1-3-0"),
        (0, 0x13, 0x001200A9, USERS),
        (0, 0x12, 0x00000116, USERS),
    ),
)
PD_ANCHOR = WinSecurity(
    USER,
    (
        (0, 0x10, 0x001F01FF, SYSTEM),
        (0, 0x10, 0x001F01FF, ADMINS),
        (0, 0x10, 0x001F01FF, USER),
        (0, 0x10, 0x001200A9, USERS),
    ),
)
# The profiles root and its Public folder. Public's INTERACTIVE entry on the folder itself is 0x1200af:
# read, traverse, add-file, add-subdirectory. Its inherit-only twin is 0x1301ff, which includes
# DELETE and delete-child, and a new subdirectory inherits that one onto itself.
USERS_DIR = WinSecurity(
    SYSTEM,
    (
        (0, 0x03, 0x001F01FF, SYSTEM),
        (0, 0x03, 0x001F01FF, ADMINS),
        (0, 0x00, 0x001200A9, USERS),
        (0, 0x0B, 0xA0000000, USERS),
        (0, 0x00, 0x001200A9, "S-1-1-0"),
        (0, 0x0B, 0xA0000000, "S-1-1-0"),
    ),
)
PUBLIC = WinSecurity(
    SYSTEM,
    (
        (0, 0x03, 0x001F01FF, ADMINS),
        (0, 0x0B, 0x001F01FF, "S-1-3-0"),
        (0, 0x03, 0x001F01FF, SYSTEM),
        (0, 0x0B, 0x001301FF, INTERACTIVE),
        (0, 0x00, 0x001200AF, INTERACTIVE),
        (0, 0x0B, 0x001301FF, "S-1-5-6"),
        (0, 0x00, 0x001200AF, "S-1-5-6"),
        (0, 0x0B, 0x001301FF, "S-1-5-3"),
        (0, 0x00, 0x001200AF, "S-1-5-3"),
    ),
)
PUBLIC_NEW = WinSecurity(
    USER,
    (
        (0, 0x13, 0x001F01FF, ADMINS),
        (0, 0x10, 0x001F01FF, USER),
        (0, 0x1B, 0x001F01FF, "S-1-3-0"),
        (0, 0x13, 0x001F01FF, SYSTEM),
        (0, 0x13, 0x001301FF, INTERACTIVE),
        (0, 0x13, 0x001301FF, "S-1-5-6"),
        (0, 0x13, 0x001301FF, "S-1-5-3"),
    ),
)
# A file locked the way the installer locks one: SYSTEM F, Administrators F, Users RX, nothing else.
LOCKED_FILE = WinSecurity(
    ADMINS,
    ((0, 0x00, 0x001F01FF, SYSTEM), (0, 0x00, 0x001F01FF, ADMINS), (0, 0x00, 0x001200A9, USERS)),
)
# A clean directory, owned by Administrators: nobody but the trusted can change anything.
CLEAN_DIR = WinSecurity(
    ADMINS,
    ((0, 0x03, 0x001F01FF, SYSTEM), (0, 0x03, 0x001F01FF, ADMINS), (0, 0x03, 0x001200A9, USERS)),
)


def _dir(*extra: tuple[int, int, int, str], owner: str = ADMINS) -> WinSecurity:
    """CLEAN_DIR with extra entries appended."""
    assert CLEAN_DIR.aces is not None
    return WinSecurity(owner, CLEAN_DIR.aces + extra)


def _trust(
    engine: str | None = USER, members: frozenset[str] = frozenset({USER}), complete: bool = True
) -> WinTrust:
    def member(sid: str) -> bool | None:
        if sid in members:
            return True
        return False if complete else None

    return WinTrust(engine, member)


def _findings(
    sec: WinSecurity, kind: str = DIRECTORY, trust: WinTrust | None = None
) -> list[ap.ChainFinding]:
    return evaluate_windows_object("X", kind, sec, trust or _trust())


def _verdict(sec: WinSecurity, kind: str = DIRECTORY, trust: WinTrust | None = None) -> bool | None:
    return ap._combine(_findings(sec, kind, trust))


def _win_chain_verdict(
    objects: dict[str, tuple[str, WinSecurity]],
    anchor: str,
    *,
    links: dict[str, str] | None = None,
    trust: WinTrust | None = None,
    volume: dict[str, str] | None = None,
) -> ap.PathVerdict:
    """Run the whole Windows chain over recorded objects. ``objects`` maps a path to its kind and
    security; ``links`` maps a link path to its target."""
    links = links or {}
    lower = {k.lower(): v for k, v in objects.items()}
    lower_links = {k.lower(): v for k, v in links.items()}

    def probe(path: str) -> tuple[str, str | None]:
        if path.lower() in lower_links:
            return LINK, lower_links[path.lower()]
        if path.lower() not in lower:
            raise FileNotFoundError(2, "not recorded", path)
        return lower[path.lower()][0], None

    def read(path: str, _kind: str) -> WinSecurity:
        return lower[path.lower()][1]

    return windows_path_verdict(
        anchor,
        cwd="C:\\cwd",
        probe=probe,
        read_security=read,
        volume_cause=lambda root: (volume or {}).get(root.lower()),
        trust=trust or _trust(),
    )


# --- the Windows rule, one object -----------------------------------------------------------------


def test_masks_match_the_config_guard_and_leave_out_the_add_rights() -> None:
    from messagefoundry.config.wiring import _WIN_WRITE_MASK

    assert ap.WIN_FILE_MASK == _WIN_WRITE_MASK
    assert ap.WIN_DIR_MASK == 0x100D0040
    assert not ap.WIN_DIR_MASK & (0x2 | 0x4 | 0x40000000)  # add-file, add-subdir, GENERIC_WRITE


def test_volume_root_as_shipped_passes() -> None:
    # Red under: removing the inherit-only skip (Authenticated Users 0xE0010000 carries DELETE).
    assert _findings(ROOT) == []


def test_programdata_and_a_fresh_subdirectory_pass() -> None:
    # Red under: adding 0x2 or 0x4 to the directory mask (Users holds 0x116 on both).
    assert _findings(PROGRAMDATA) == []
    assert _findings(PD_NEW) == []
    assert _findings(PD_ANCHOR, FILE) == []


def test_users_and_public_directories_pass_on_their_own() -> None:
    assert _findings(USERS_DIR) == []
    assert _findings(PUBLIC) == []


def test_delete_child_alone_refuses_the_directory() -> None:
    """THE DEFECT TEST. The file is clean; only its directory grants Users delete-child, and nothing
    else. Red under: removing 0x40 from the directory mask."""
    found = _findings(_dir((0, 0x00, 0x00000040, USERS)))
    assert [f.insecure for f in found] == [True]
    assert "delete or rename entries" in found[0].reason
    assert found[0].sids == (USERS,)
    assert _findings(LOCKED_FILE, FILE) == []


def test_public_subdirectory_refuses_even_with_a_locked_file() -> None:
    # INTERACTIVE 0x1301FF, flags 0x13: both DELETE and delete-child, so this is not the defect test.
    found = _findings(PUBLIC_NEW)
    assert {f.sids for f in found if f.insecure} == {(INTERACTIVE,), ("S-1-5-6",), ("S-1-5-3",)}


def test_new_directory_under_the_root_refuses_through_delete() -> None:
    # Authenticated Users 0x1301BF (M) inherited onto the directory itself. Red under: removing
    # 0x10000 from the directory mask.
    found = _findings(_dir((0, 0x10, 0x001301BF, AUTH_USERS)))
    assert found and found[0].insecure and "rename or delete it" in found[0].reason


def test_foreign_owner_refuses() -> None:
    # Red under: removing the owner test. The ProgramData squatting case.
    found = _findings(_dir(owner=OTHER))
    assert [f.insecure for f in found] == [True]
    assert "owned by" in found[0].reason


def test_incomplete_membership_is_indeterminate() -> None:
    # Red under: mapping an incomplete lookup to False or to True.
    assert _verdict(_dir(owner=OTHER), trust=_trust(complete=False)) is None


def test_incomplete_membership_does_not_hide_a_definite_grant() -> None:
    # Red under: running the owner test before the entry scan and returning there.
    sec = _dir((0, 0, 0x40, INTERACTIVE), owner=OTHER)
    assert _verdict(sec, trust=_trust(complete=False)) is False


def test_a_callback_entry_is_indeterminate() -> None:
    # Red under: skipping allow types the reader does not parse.
    assert _verdict(_dir((0x09, 0, 0x40, ""))) is None


def test_a_callback_entry_first_does_not_hide_a_later_grant() -> None:
    # Red under: returning at the first unknown entry.
    assert _verdict(_dir((0x09, 0, 0x40, ""), (0, 0, 0x40, OTHER))) is False


def test_null_dacl_refuses() -> None:
    # Red under: treating NULL as unreadable.
    assert _verdict(WinSecurity(ADMINS, None)) is False


def test_deny_entries_are_ignored() -> None:
    # Red under: counting deny entries as grants.
    assert _verdict(_dir((1, 0, 0x40, USERS))) is True


def test_named_admin_member_holding_full_control_passes() -> None:
    # Red under: dropping the membership trust. The engine here is a service, not the user.
    trust = _trust(engine=SERVICE)
    assert _verdict(_dir((0, 0, 0x001F01FF, USER)), trust=trust) is True


def test_named_non_member_holding_delete_child_refuses() -> None:
    # Red under: switching to a broad-SID deny-list.
    assert _verdict(_dir((0, 0, 0x40, OTHER))) is False


def test_foreign_domain_admin_rid_is_trusted_as_owner_only() -> None:
    # Red under: applying the admin-RID arm to grantees.
    domain_admins = "S-1-5-21-7-8-9-512"
    assert _verdict(_dir((0, 0, 0x40, domain_admins))) is False
    assert _verdict(_dir(owner=domain_admins)) is True


def test_the_engines_own_account_is_trusted() -> None:
    # Red under: dropping self-trust. The installer grants the run-as account M on the data dir.
    trust = _trust(engine=SERVICE, members=frozenset())
    assert _verdict(_dir((0, 0x03, 0x001301BF, SERVICE)), trust=trust) is True


def test_a_shared_service_account_is_not_self_trusted() -> None:
    # Red under: trusting LocalService because the engine runs as it.
    trust = _trust(engine="S-1-5-19", members=frozenset())
    assert _verdict(_dir((0, 0x03, 0x001301BF, "S-1-5-19")), trust=trust) is False


def test_inherit_only_entries_grant_nothing() -> None:
    assert _verdict(_dir((0, 0x0B, 0x001F01FF, OTHER))) is True


def test_add_rights_and_generic_write_do_not_count_on_a_directory() -> None:
    assert _verdict(_dir((0, 0, 0x116, OTHER), (0, 0, 0x40000000, OTHER))) is True


def test_the_same_add_rights_do_count_on_a_file() -> None:
    assert _verdict(WinSecurity(ADMINS, ((0, 0, 0x2, OTHER),)), FILE) is False


def test_unreadable_engine_sid_still_refuses_a_group() -> None:
    trust = _trust(engine=None)
    assert _verdict(_dir((0, 0, 0x40, INTERACTIVE)), trust=trust) is False
    assert _verdict(_dir((0, 0, 0x40, USERS)), trust=trust) is False
    # A user SID might be the engine itself, so it answers indeterminate rather than refusing.
    assert _verdict(_dir((0, 0, 0x40, OTHER)), trust=trust) is None


def test_a_read_error_is_indeterminate() -> None:
    assert _verdict(WinSecurity(None, (), "Win32 error 5")) is None


# --- the Windows chain ----------------------------------------------------------------------------


def _pd_objects() -> dict[str, tuple[str, WinSecurity]]:
    return {
        "C:\\": (DIRECTORY, ROOT),
        "C:\\ProgramData": (DIRECTORY, PROGRAMDATA),
        "C:\\ProgramData\\mefor": (DIRECTORY, PD_NEW),
        "C:\\ProgramData\\mefor\\ca.pem": (FILE, PD_ANCHOR),
    }


def test_default_programdata_placement_passes_as_the_user_and_as_a_service() -> None:
    anchor = "C:\\ProgramData\\mefor\\ca.pem"
    assert _win_chain_verdict(_pd_objects(), anchor).ok is True
    assert _win_chain_verdict(_pd_objects(), anchor, trust=_trust(engine=SERVICE)).ok is True


def test_public_placements_refuse() -> None:
    objects = {
        "C:\\": (DIRECTORY, ROOT),
        "C:\\Users": (DIRECTORY, USERS_DIR),
        "C:\\Users\\Public": (DIRECTORY, PUBLIC),
        "C:\\Users\\Public\\d": (DIRECTORY, PUBLIC_NEW),
        "C:\\Users\\Public\\d\\ca.pem": (FILE, LOCKED_FILE),
    }
    v = _win_chain_verdict(objects, "C:\\Users\\Public\\d\\ca.pem")
    assert v.ok is False
    # Only the directory fails: the locked file passes the file rule. The file arm alone passes it.
    assert {f.path for f in v.findings} == {"C:\\Users\\Public\\d"}


def test_an_unreadable_ancestor_does_not_stop_the_walk() -> None:
    # Red under: stopping at the first unreadable object.
    objects = _pd_objects()
    objects["C:\\ProgramData"] = (DIRECTORY, WinSecurity(None, (), "Win32 error 5"))
    anchor = "C:\\ProgramData\\mefor\\ca.pem"
    assert _win_chain_verdict(objects, anchor).ok is None
    objects["C:\\ProgramData\\mefor"] = (DIRECTORY, _dir((0, 0, 0x40, USERS)))
    assert _win_chain_verdict(objects, anchor).ok is False


def test_a_junction_object_owned_by_a_non_admin_refuses() -> None:
    # Red under: not reading the link object's own descriptor.
    objects = _pd_objects()
    objects["C:\\ProgramData\\jn"] = (LINK, WinSecurity(OTHER, ((0, 0, 0x001F01FF, OTHER),)))
    links = {"C:\\ProgramData\\jn": "\\\\?\\C:\\ProgramData\\mefor"}
    v = _win_chain_verdict(objects, "C:\\ProgramData\\jn\\ca.pem", links=links)
    assert v.ok is False
    assert {f.path for f in v.findings} == {"C:\\ProgramData\\jn"}
    assert {f.kind for f in v.findings} == {LINK}


def test_a_clean_link_passes_and_its_target_is_walked() -> None:
    objects = _pd_objects()
    objects["C:\\ProgramData\\jn"] = (LINK, LOCKED_FILE)
    links = {"C:\\ProgramData\\jn": "mefor"}  # relative: against the directory holding the link
    chain, cause = windows_chain(
        "C:\\ProgramData\\jn\\ca.pem",
        "C:\\cwd",
        lambda p: (LINK, links[p]) if p in links else (objects[p][0], None),
    )
    assert cause is None
    assert chain == [
        ("C:\\", DIRECTORY),
        ("C:\\ProgramData", DIRECTORY),
        ("C:\\ProgramData\\jn", LINK),
        ("C:\\ProgramData\\mefor", DIRECTORY),
        ("C:\\ProgramData\\mefor\\ca.pem", FILE),
    ]
    assert _win_chain_verdict(objects, "C:\\ProgramData\\jn\\ca.pem", links=links).ok is True


def test_dotdot_is_collapsed_as_text_before_any_link() -> None:
    # Red under: resolving `..` physically on Windows. Win32 collapses it in the string first.
    objects = {
        "C:\\": (DIRECTORY, ROOT),
        "C:\\a": (DIRECTORY, CLEAN_DIR),
        "C:\\a\\ca.pem": (FILE, LOCKED_FILE),
    }
    links = {"C:\\a\\lnk": "D:\\elsewhere"}

    def probe(p: str) -> tuple[str, str | None]:
        return (LINK, links[p]) if p in links else (objects[p][0], None)

    chain, cause = windows_chain("C:\\a\\lnk\\..\\ca.pem", "C:\\cwd", probe)
    assert cause is None
    assert [p for p, _k in chain] == ["C:\\", "C:\\a", "C:\\a\\ca.pem"]


def test_a_link_cycle_ends_indeterminate() -> None:
    links = {"C:\\a": "C:\\b", "C:\\b": "C:\\a"}
    chain, cause = windows_chain("C:\\a\\ca.pem", "C:\\cwd", lambda p: (LINK, links[p]))
    assert cause is not None and "links" in cause


def test_a_relative_anchor_is_made_absolute_against_the_working_directory() -> None:
    objects = {"C:\\": (DIRECTORY, ROOT), "C:\\cwd": (DIRECTORY, CLEAN_DIR)}
    objects["C:\\cwd\\ca.pem"] = (FILE, LOCKED_FILE)
    assert _win_chain_verdict(objects, "ca.pem").ok is True


def test_a_unc_path_or_a_fat_volume_is_indeterminate() -> None:
    # Red under: trusting a volume that keeps no DACL, or a share the host cannot read.
    assert _win_chain_verdict({}, "\\\\server\\share\\ca.pem").ok is None
    assert _win_chain_verdict({}, "\\\\?\\UNC\\server\\share\\ca.pem").ok is None
    objects = {"E:\\": (DIRECTORY, WinSecurity(ADMINS, None)), "E:\\ca.pem": (FILE, CLEAN_DIR)}
    fat = {"e:\\": "it is a FAT32 volume"}
    assert _win_chain_verdict(objects, "E:\\ca.pem", volume=fat).ok is None


def test_a_prefixed_path_reads_as_its_plain_form() -> None:
    assert _win_chain_verdict(_pd_objects(), "\\\\?\\C:\\ProgramData\\mefor\\ca.pem").ok is True
    assert _win_chain_verdict({}, "\\\\.\\PhysicalDrive0").ok is None


def _probe(links: dict[str, str] | None = None) -> ap.WinProbe:
    """A probe where every name is a folder or a ``.pem`` file, except the ``links``."""
    links = {k.lower(): v for k, v in (links or {}).items()}

    def probe(p: str) -> tuple[str, str | None]:
        key = p.lower()
        if key in links:
            return LINK, links[key]
        return (FILE if key.endswith(".pem") else DIRECTORY), None

    return probe


@pytest.mark.parametrize(
    "path",
    [
        # Verbatim: Win32 hands the text to the kernel as written, where normpath collapses it.
        r"\\?\C:\certs\..\other\ca.pem",
        r"\\?\C:\certs\.\ca.pem",
        r"\\?\C:\certs/ca.pem",
        r"\\?\C:\certs\\ca.pem",
        r"\??\C:\certs\..\ca.pem",
        r"\\?\Volume{0000}\certs\..\ca.pem",
        r"\\?\UNC\files.test\share\..\..\C$\ca.pem",
        # A normalized device path: Win32 collapses `..` against the prefix itself, so this opens
        # the share \\files.test\share, where normpath stopped at C: and walked C:\UNC\...
        r"\\.\C:\..\UNC\files.test\share\ca.pem",
        r"\\.\C:\certs\..\..\D:\ca.pem",
        "//?/Volume{0000}/../C:/certs/ca.pem",
        "//./C:/../UNC/files.test/share/ca.pem",
        # A final `.` or `..` that lands on the first name opens the volume device \\.\C:, where
        # normpath walked and cleared the root folder C:\.
        r"\\.\C:\certs\..",
        r"\\.\C:\.",
        r"\\.\Volume{0000}\certs\..",
        # A forward-slash climb from one volume GUID into another: was walked under the first.
        "//?/Volume{0000}/x/../../Volume{1111}/certs/ca.pem",
        # A drive letter or volume GUID with no separator after it opens the volume device.
        r"\\?\C:",
        r"\\.\C:",
        r"\\?\Volume{0000}",
        r"\\.\Volume{0000}",
        "//?/Volume{0000}",
    ],
)
def test_a_device_path_normpath_would_read_as_another_object_is_not_walked(path: str) -> None:
    """Vault BACKLOG #5515. Red under origin/main's strip-then-normpath, though not every case was
    cleared there: most were walked and cleared, but ``\\\\.\\C:\\certs\\..\\..\\D:\\ca.pem`` and
    ``//?/Volume{0000}/../C:/...`` ended as a stream name, ``\\\\?\\C:`` and ``\\\\.\\C:`` as
    drive-relative, the verbatim UNC case as a share, and ``//./C:/../UNC/...`` already as a
    device path. This pins the device-path cause for each."""
    chain, cause = windows_chain(path, "C:\\cwd", _probe())
    assert (chain, cause) == ([], "the path is a device path this check does not read")


@pytest.mark.parametrize("target", [r"\??\C:\real\..\other", r"\\.\C:\real\..\other"])
def test_a_link_to_a_device_path_normpath_would_change_is_not_walked(target: str) -> None:
    """A junction or symlink target is an NT path, read as written, so not even a ``\\\\.\\``
    target is normalized. Red as above."""
    links = {"C:\\certs\\lnk": target}
    _chain, cause = windows_chain("C:\\certs\\lnk\\ca.pem", "C:\\cwd", _probe(links))
    assert cause is not None and cause.kind == "a link points at a path this check does not read"


def test_a_link_in_the_form_readlink_returns_is_judged_by_its_rest() -> None:
    """``os.readlink`` hands back ``\\\\?\\`` where the reparse point stores ``\\??\\``. A plain
    one is walked; one holding ``..`` is not. Red under: stripping it and normalizing the rest."""
    plain = {"C:\\certs\\lnk": r"\\?\C:\real"}
    chain, cause = windows_chain("C:\\certs\\lnk\\ca.pem", "C:\\cwd", _probe(plain))
    assert cause is None and chain[-1][0] == "C:\\real\\ca.pem"
    dotted = {"C:\\certs\\lnk": r"\\?\C:\real\..\other"}
    _chain, cause = windows_chain("C:\\certs\\lnk\\ca.pem", "C:\\cwd", _probe(dotted))
    assert cause is not None and cause.kind == "a link points at a path this check does not read"


def test_a_subst_drive_onto_a_verbatim_path_normpath_would_change_is_not_walked() -> None:
    """A ``subst`` target goes through the same check. Red as above: it walked C:\\other."""
    _chain, cause = windows_chain(
        r"S:\ca.pem",
        r"C:\cwd",
        _probe(),
        drive_target=lambda drive: r"\??\C:\certs\..\other" if drive == "S:" else None,
    )
    assert cause is not None and cause.kind == "a drive stands for a path this check does not read"


def test_a_config_link_to_a_verbatim_path_normpath_would_change_is_refused() -> None:
    """The config-source link walk shares :func:`_strip_win_prefix` with the anchor walk, so a
    verbatim link target holding ``..`` refuses in both. That holds for verbatim targets only: the
    anchor walk reads link targets through the stricter ``_strip_nt_target``, while
    ``config/wiring.py``'s ``_windows_link_target`` still normalizes a ``\\\\.\\`` or mixed-slash
    target. Red as above."""
    from messagefoundry.config.wiring import _windows_link_target

    with pytest.raises(OSError, match="device path"):
        _windows_link_target(r"\??\C:\real\..\other")
    assert _windows_link_target(r"\??\C:\real") == r"C:\real"


@pytest.mark.parametrize("anchor", [r".\certs\ca.pem", "certs/ca.pem", r"..\certs\ca.pem"])
def test_a_relative_anchor_under_a_verbatim_working_directory_is_still_walked(anchor: str) -> None:
    """Win32 normalizes a relative name joined to the working directory, so the join is not read
    as a verbatim path. Red under: running the verbatim check over the joined text."""
    _chain, cause = windows_chain(anchor, r"\\?\C:\svc", _probe())
    assert cause is None


@pytest.mark.parametrize(
    ("cwd", "anchor"),
    [
        # A `..` past the first name may be collapsed against the prefix and reach a share.
        (r"\\.\C:\svc", r"..\..\..\UNC\files.test\share\ca.pem"),
        (r"\\?\C:\svc", r"..\..\..\UNC\files.test\share\ca.pem"),
        # The same under a volume GUID working directory, which the strip leaves as written.
        (r"\\?\Volume{0000}\svc", r"..\..\Volume{1111}\certs\ca.pem"),
        ("//?/Volume{0000}/svc", r"..\..\..\UNC\files.test\share\ca.pem"),
        # A rooted relative name joins to the drive or volume, not to the folder.
        (r"\\.\C:\svc", r"\..\UNC\files.test\share\ca.pem"),
        (r"\\?\C:\svc", r"\certs\ca.pem"),
        (r"\\?\Volume{0000}\svc", r"\certs\ca.pem"),
        # A bare drive or volume GUID working directory names the volume device.
        (r"\\?\C:", r"certs\ca.pem"),
        (r"\\.\C:", r"certs\ca.pem"),
        (r"\\?\Volume{0000}", r"certs\ca.pem"),
        ("//?/Volume{0000}", r"certs\ca.pem"),
    ],
)
def test_a_relative_anchor_under_a_prefixed_working_directory_it_cannot_place_is_not_walked(
    cwd: str, anchor: str
) -> None:
    """Which object Win32 resolves a relative name to there is not emulated, so these refuse.
    Red under: joining by normpath, which clamped each at the drive or volume and cleared it."""
    chain, cause = windows_chain(anchor, cwd, _probe())
    assert (chain, cause) == ([], "the path is a device path this check does not read")


@pytest.mark.parametrize(
    ("cwd", "anchor", "walked"),
    [
        (r"\\.\C:\svc", r"..\certs\ca.pem", "C:\\certs\\ca.pem"),
        (r"\\?\Volume{0000}\svc", r"..\certs\ca.pem", "\\\\?\\Volume{0000}\\certs\\ca.pem"),
        (r"\\?\Volume{0000}\svc", r"certs\ca.pem", "\\\\?\\Volume{0000}\\svc\\certs\\ca.pem"),
        ("\\\\?\\C:\\", r"certs\ca.pem", "C:\\certs\\ca.pem"),  # the root, with its separator
        (r"C:\svc", r"\certs\ca.pem", "C:\\certs\\ca.pem"),  # a plain working directory
        (r"C:\svc", r"..\..\..\certs\ca.pem", "C:\\certs\\ca.pem"),
    ],
)
def test_a_relative_anchor_under_a_working_directory_it_can_place_is_still_walked(
    cwd: str, anchor: str, walked: str
) -> None:
    """The must-not-trip twins: a `..` that stays inside a prefixed working directory, a root
    with its separator, and a plain working directory, which Win32 normalizes as normpath does."""
    chain, cause = windows_chain(anchor, cwd, _probe())
    assert cause is None
    assert chain[-1][0] == walked


@pytest.mark.parametrize(
    ("path", "anchor"),
    [
        (r"\\?\C:\certs\ca.pem", "C:\\certs\\ca.pem"),
        ("\\\\?\\C:\\certs\\", "C:\\certs"),  # one trailing separator
        (r"\\.\C:\certs\..\other\ca.pem", "C:\\other\\ca.pem"),  # `..` that stays under C:
        (r"\\.\C:/certs/ca.pem", "C:\\certs\\ca.pem"),  # Win32 turns `/` into `\` here
        ("//?/Volume{0000}/certs/./ca.pem", "\\\\?\\Volume{0000}\\certs\\ca.pem"),
        (r"\\.\C:\certs\sub\..", "C:\\certs"),  # a final `..` that stays under C:
    ],
)
def test_a_device_path_windows_normalizes_the_same_way_is_still_walked(
    path: str, anchor: str
) -> None:
    """The controls: a plain verbatim path, and a normalized one whose `..` stays inside it."""
    chain, cause = windows_chain(path, "C:\\cwd", _probe())
    assert cause is None
    assert chain[-1][0] == anchor


def test_a_missing_component_is_indeterminate_not_insecure() -> None:
    v = _win_chain_verdict(_pd_objects(), "C:\\ProgramData\\mefor\\gone.pem")
    assert v.ok is None


def test_an_alternate_data_stream_is_indeterminate() -> None:
    assert _win_chain_verdict(_pd_objects(), "C:\\ProgramData\\mefor\\ca.pem:alt").ok is None


# --- the POSIX rule -------------------------------------------------------------------------------

D755 = stat.S_IFDIR | 0o755
D777 = stat.S_IFDIR | 0o777
D1777 = stat.S_IFDIR | 0o1777
F644 = stat.S_IFREG | 0o644
F664 = stat.S_IFREG | 0o664
LNK = stat.S_IFLNK | 0o777

# Read with `stat -c "%a %U(%u) %F %n"` on WSL Ubuntu 24.04.3, 2026-09-24. The ISRG link target
# is as `readlink` printed it there.
_ETC = {
    "/": (0, D755),
    "/etc": (0, D755),
    "/etc/ssl": (0, D755),
    "/etc/ssl/certs": (0, D755),
    "/etc/ssl/certs/ca-certificates.crt": (0, F644),
    "/etc/ssl/certs/ISRG_Root_X1.pem": (0, LNK),
    "/usr": (0, D755),
    "/usr/share": (0, D755),
    "/usr/share/ca-certificates": (0, D755),
    "/usr/share/ca-certificates/mozilla": (0, D755),
    "/usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt": (0, F644),
    "/tmp": (0, D1777),
}
_ETC_LINKS = {
    "/etc/ssl/certs/ISRG_Root_X1.pem": "/usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt"
}


def _posix(
    anchor: str,
    table: dict[str, tuple[int, int]],
    *,
    links: dict[str, str] | None = None,
    euid: int = 10001,
    fstype: dict[str, str] | None = None,
) -> ap.PathVerdict:
    full = {**_ETC, **table}
    all_links = {**_ETC_LINKS, **(links or {})}
    mounts = [("/", "ext4")] + list((fstype or {}).items())

    def lstat_fn(p: str) -> PosixStat:
        if p not in full:
            raise FileNotFoundError(2, "not recorded", p)
        return PosixStat(*full[p])

    def readlink_fn(p: str) -> str:
        return all_links[p]

    return posix_path_verdict(
        anchor,
        cwd="/work",
        euid=euid,
        lstat_fn=lstat_fn,
        readlink_fn=readlink_fn,
        fstype_fn=lambda p: ap.mount_of(p, mounts),
    )


def test_posix_system_bundle_passes() -> None:
    assert _posix("/etc/ssl/certs/ca-certificates.crt", {}).ok is True


def test_posix_link_into_a_root_owned_tree_passes() -> None:
    assert _posix("/etc/ssl/certs/ISRG_Root_X1.pem", {}).ok is True


def test_posix_sticky_tmp_with_the_engines_own_entry_passes() -> None:
    table = {"/tmp/r": (1000, D755), "/tmp/r/anchor.pem": (1000, F644)}
    assert _posix("/tmp/r/anchor.pem", table, euid=1000).ok is True


def test_posix_sticky_tmp_with_another_uids_entry_refuses() -> None:
    table = {"/tmp/r": (1000, D755), "/tmp/r/anchor.pem": (1000, F644)}
    v = _posix("/tmp/r/anchor.pem", table, euid=10001)
    assert v.ok is False
    # The entry is named, never the shared sticky folder: the fix belongs on the entry.
    bad = [f.path for f in v.findings if f.insecure]
    assert "/tmp/r" in bad and "/tmp" not in bad


def test_posix_world_writable_directory_refuses() -> None:
    table = {"/tmp/ww": (1000, D777), "/tmp/ww/anchor.pem": (1000, F644)}
    v = _posix("/tmp/ww/anchor.pem", table, euid=1000)
    assert v.ok is False
    assert [f.path for f in v.findings if f.insecure] == ["/tmp/ww"]


def test_posix_link_to_a_good_target_inside_a_writable_directory_refuses() -> None:
    table = {"/tmp/ww": (1000, D777), "/tmp/ww/link.pem": (1000, LNK)}
    links = {"/tmp/ww/link.pem": "/etc/ssl/certs/ca-certificates.crt"}
    v = _posix("/tmp/ww/link.pem", table, links=links, euid=1000)
    assert v.ok is False
    assert [f.path for f in v.findings if f.insecure] == ["/tmp/ww"]


def test_posix_drvfs_reading_refuses_and_its_mount_is_named() -> None:
    table = {
        "/mnt": (0, D755),
        "/mnt/c": (1000, D777),
        "/mnt/c/ProgramData": (1000, D777),
        "/mnt/c/ProgramData/anchor.pem": (1000, stat.S_IFREG | 0o777),
    }
    v = _posix("/mnt/c/ProgramData/anchor.pem", table, fstype={"/mnt/c": "9p"})
    assert v.ok is False
    assert any(not f.insecure and "9p" in f.reason for f in v.findings)


def test_posix_foreign_owner_refuses() -> None:
    table = {"/srv": (0, D755), "/srv/ca": (2000, D755), "/srv/ca/a.pem": (0, F644)}
    assert _posix("/srv/ca/a.pem", table).ok is False


def test_posix_root_engine_trusts_only_root() -> None:
    table = {"/srv": (0, D755), "/srv/a.pem": (1000, F644)}
    assert _posix("/srv/a.pem", table, euid=0).ok is False
    assert _posix("/srv/a.pem", table, euid=1000).ok is True


def test_posix_clean_chain_on_a_network_mount_is_indeterminate() -> None:
    table = {"/srv": (0, D755), "/srv/a.pem": (0, F644)}
    for fs in ("nfs", "nfs4", "cifs", "fuse.sshfs", "9p"):
        assert _posix("/srv/a.pem", table, fstype={"/srv": fs}).ok is None, fs


def test_posix_unknown_mount_table_is_indeterminate() -> None:
    table = {"/srv": (0, D755), "/srv/a.pem": (0, F644)}
    v = posix_path_verdict(
        "/srv/a.pem",
        cwd="/",
        euid=10001,
        lstat_fn=lambda p: PosixStat(*{**_ETC, **table}[p]),
        readlink_fn=lambda p: "",
        fstype_fn=lambda p: None,
    )
    assert v.ok is None


def test_posix_symlink_cycle_is_indeterminate_and_ends() -> None:
    table = {"/srv": (0, D755), "/srv/a": (0, LNK), "/srv/b": (0, LNK)}
    links = {"/srv/a": "b", "/srv/b": "a"}
    v = _posix("/srv/a", table, links=links)
    assert v.ok is None
    assert any("links" in f.reason for f in v.findings)


def test_posix_relative_link_and_dotdot_after_a_link_are_physical() -> None:
    # /srv/l -> /opt/deep/x (absolute). /srv/l/../ca.pem is /opt/deep/ca.pem, not /srv/ca.pem: the
    # kernel takes `..` from the directory the link led to.
    table = {
        "/srv": (0, D755),
        "/srv/l": (0, LNK),
        "/srv/ca.pem": (0, F644),
        "/opt": (0, D755),
        "/opt/deep": (0, D755),
        "/opt/deep/x": (0, D755),
        "/opt/deep/ca.pem": (2000, F644),  # foreign-owned: reached only if `..` is physical
        "/opt/deep/rel": (0, LNK),
    }
    links = {"/srv/l": "/opt/deep/x", "/opt/deep/rel": "x/../ca.pem"}
    assert _posix("/srv/l/../ca.pem", table, links=links).ok is False
    assert _posix("/srv/ca.pem", table, links=links).ok is True
    assert _posix("/opt/deep/rel", table, links=links).ok is False  # relative target, same file


def test_posix_relative_anchor_uses_the_working_directory() -> None:
    table = {"/work": (0, D755), "/work/a.pem": (0, F644)}
    assert _posix("a.pem", table).ok is True


def test_posix_group_writable_or_irregular_leaf_refuses() -> None:
    table = {"/srv": (0, D755), "/srv/a.pem": (0, F664), "/srv/fifo": (0, stat.S_IFIFO | 0o644)}
    assert _posix("/srv/a.pem", table).ok is False
    assert _posix("/srv/fifo", table).ok is False


def test_posix_missing_file_is_indeterminate() -> None:
    assert _posix("/srv/none.pem", {"/srv": (0, D755)}).ok is None


def test_posix_unreadable_part_does_not_hide_a_writable_ancestor() -> None:
    table = {"/srv": (0, D777)}
    assert _posix("/srv/none.pem", table).ok is False


def test_mountinfo_parses_escapes_and_the_longest_point_wins() -> None:
    text = (
        "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
        "40 22 0:35 / /mnt/my\\040share rw - cifs //s/x rw\n"
        "41 22 0:36 / /mnt rw - tmpfs tmpfs rw\n"
    )
    mounts = ap._parse_mountinfo(text)
    assert ("/mnt/my share", "cifs") in mounts
    assert ap.mount_of("/mnt/my share/a", mounts) == ("/mnt/my share", "cifs")
    assert ap.mount_of("/mnt/other", mounts) == ("/mnt", "tmpfs")
    assert ap.mount_of("/mntx", mounts) == ("/", "ext4")


# --- fixes from the first code-review round -------------------------------------------------------


def test_a_subst_drive_is_walked_from_the_folder_it_stands_for() -> None:
    """`subst X: C:\\ProgramData\\foo\\certs` makes X:\\ look like a volume root, but the folders
    above `certs` can still be renamed. Red under: treating every drive letter as a root."""
    objects = {
        "C:\\": (DIRECTORY, ROOT),
        "C:\\ProgramData": (DIRECTORY, PROGRAMDATA),
        "C:\\ProgramData\\foo": (DIRECTORY, _dir(owner=OTHER)),  # a standard user made it
        "C:\\ProgramData\\foo\\certs": (DIRECTORY, CLEAN_DIR),
        "C:\\ProgramData\\foo\\certs\\ca.pem": (FILE, LOCKED_FILE),
    }
    lower = {k.lower(): v for k, v in objects.items()}
    v = windows_path_verdict(
        "X:\\ca.pem",
        cwd="C:\\cwd",
        probe=lambda p: (lower[p.lower()][0], None),
        read_security=lambda p, _k: lower[p.lower()][1],
        volume_cause=lambda _r: None,
        trust=_trust(),
        drive_target=lambda d: "C:\\ProgramData\\foo\\certs" if d.upper() == "X:" else None,
    )
    assert v.ok is False
    assert [f.path for f in v.findings if f.insecure] == ["C:\\ProgramData\\foo"]


def test_a_volume_that_cannot_be_judged_is_never_walked() -> None:
    """A mapped network drive answers indeterminate before any folder on it is probed, so it costs
    no round trip per folder."""
    probed: list[str] = []

    def probe(p: str) -> tuple[str, str | None]:
        probed.append(p)
        return DIRECTORY, None

    chain, cause = windows_chain(
        "Z:\\certs\\ca.pem", "C:\\cwd", probe, volume_cause=lambda r: "it is a network drive"
    )
    assert chain == [] and probed == []
    assert cause is not None and "network drive" in cause


def test_another_name_surrogate_reparse_point_is_indeterminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A container layer link (0xA0000027) stands for another path, like a junction, but the probe
    cannot read its target. Red under: probing it as a plain folder."""

    class Stat:
        st_reparse_tag = 0xA0000027
        st_mode = stat.S_IFDIR | 0o755

    monkeypatch.setattr(os, "lstat", lambda _p: Stat())
    with pytest.raises(OSError, match="reparse point"):
        ap._win_probe("C:\\layer")
    Stat.st_reparse_tag = 0x9000001A  # a cloud-files placeholder is not a name surrogate
    assert ap._win_probe("C:\\layer") == (DIRECTORY, None)


def test_unreadable_engine_sid_never_softens_a_non_account_sid() -> None:
    """With no engine SID, only an account-shaped SID might be the engine. NetworkService is
    never self-trusted, and an AppContainer SID is never a token's user."""
    trust = _trust(engine=None)
    assert _verdict(_dir((0, 0, 0x40, "S-1-5-20")), trust=trust) is False
    assert _verdict(_dir((0, 0, 0x40, "S-1-15-2-1")), trust=trust) is False
    assert _verdict(_dir((0, 0, 0x40, SERVICE)), trust=trust) is None


def test_posix_sticky_folder_finding_names_the_link_not_the_shared_folder() -> None:
    """Red under: reporting the sticky folder itself, whose printed fix would strip world-write
    from /tmp for every user on the host."""
    table = {"/tmp/ca.pem": (1000, LNK)}
    links = {"/tmp/ca.pem": "/etc/ssl/certs/ca-certificates.crt"}
    v = _posix("/tmp/ca.pem", table, links=links, euid=10001)
    assert v.ok is False
    assert [(f.path, f.kind) for f in v.findings if f.insecure] == [("/tmp/ca.pem", LINK)]


def test_posix_findings_keep_case() -> None:
    table = {
        "/data": (0, D755),
        "/data/Certs": (0, D777),
        "/data/Certs/certs": (0, D777),
        "/data/Certs/certs/ca.pem": (0, F644),
    }
    v = _posix("/data/Certs/certs/ca.pem", table)
    assert [f.path for f in v.findings if f.insecure] == ["/data/Certs", "/data/Certs/certs"]


def test_a_lost_working_directory_is_indeterminate_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def gone() -> str:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(os, "getcwd", gone)
    v = ap.anchor_path_verdict("relative-anchor.pem")
    assert v.ok is None
    assert "could not" in v.findings[0].reason


async def test_a_noisy_anchor_cannot_push_a_quiet_baseline_out_of_reach(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red under: reading only one page of audit rows. One anchor on a mount the check cannot judge
    writes a row on every reload; after a page of them, a quiet anchor's baseline must still count,
    or its next swap reads as a first observation instead of a change."""
    s = await MessageStore.open(tmp_path / "audit.db")
    try:
        monkeypatch.setattr(ta, "_FINGERPRINT_PAGE", 5)
        await s.record_audit(
            AUDIT_ACTION, actor=None, detail=json.dumps({"label": "oidc", "fingerprint": "f1"})
        )
        for i in range(23):
            await s.record_audit(
                AUDIT_ACTION, actor=None, detail=json.dumps({"label": "ad", "n": i})
            )
        assert (await ta._last_fingerprint(s, "oidc")).found == ("sha256", "f1")  # BACKLOG #3425
        assert (await ta._last_fingerprint(s, "api_client")).found is None
    finally:
        await s.close()


# --- the verdict reaches evaluate_anchor and enforcement ------------------------------------------


def _pem(tmp_path: Path) -> Path:
    p = tmp_path / "anchor.pem"
    p.write_bytes(_block(b"anchor"))
    return p


def _bad_path(_p: object) -> ap.PathVerdict:
    finding = ap.ChainFinding("C:\\certs", DIRECTORY, True, "Users can delete entries", (USERS,))
    return ap.PathVerdict(False, (finding,), "windows", SERVICE)


def _unknown_path(_p: object) -> ap.PathVerdict:
    return ap.PathVerdict(None, (ap.ChainFinding("C:\\x", DIRECTORY, False, "access denied"),))


def test_path_false_refuses_at_enforce_and_warns_at_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    p = _pem(tmp_path)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _bad_path)
    spec = AnchorSpec("t", "[api].tls_client_ca_file", str(p), None)
    with pytest.raises(TrustAnchorError) as err:
        ta.enforce_anchor(spec, enforcing=True)
    text = str(err.value)
    assert "can be replaced through its path" in text and "C:\\certs" in text
    assert "icacls 'C:\\certs' /inheritance:d" in text
    assert "icacls 'C:\\certs' /remove:g '*S-1-5-32-545'" in text
    # The fix removes only what the check named. A blanket reset would strip the engine's own
    # modify grant from its data folder; no grant finding here is about the owner, so no setowner.
    assert "/inheritance:r" not in text and "/grant" not in text and "/setowner" not in text
    assert f"account it ran as ({SERVICE})" in text
    assert "enforce refuses it" in text
    assert text.isascii()
    ta.enforce_anchor(spec, enforcing=False)
    assert "using it anyway" in caplog.text


def test_path_none_refuses_at_enforce_unless_a_pin_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #1142, slice 3 inverts this arm's degrade: a chain that could not be read refuses at
    enforce, names what could not be read and both fixes, and a matching pin lets it load."""
    p = _pem(tmp_path)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _unknown_path)
    spec = AnchorSpec("t", "[x]", str(p), None, "[x].pin")
    with pytest.raises(TrustAnchorError) as err:
        ta.enforce_anchor(spec, enforcing=True)
    text = str(err.value)
    # The finding's path is quoted with repr (BACKLOG #2358), so its backslash is escaped.
    assert "could not settle" in text and "directory 'C:\\\\x': access denied" in text
    assert "move the anchor" in text and "set [x].pin to" in text
    assert hashlib.sha256(p.read_bytes()).hexdigest() in text
    assert "enforce refuses it" in text and text.isascii()
    ta.enforce_anchor(spec, enforcing=False)
    assert "using it anyway" in caplog.text
    caplog.clear()
    pinned = AnchorSpec("t", "[x]", str(p), hashlib.sha256(p.read_bytes()).hexdigest(), "[x].pin")
    assert ta.enforce_anchor(pinned, enforcing=True)
    assert "[x].pin matches the bytes read" in caplog.text


def test_path_arm_runs_beside_the_file_arm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Either arm refuses alone. Neither one's pass can clear the other's refusal."""
    p = _pem(tmp_path)
    spec = AnchorSpec("t", "[x]", str(p), None)
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: ap.PathVerdict(True))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    with pytest.raises(TrustAnchorError, match="writable by a non-owner"):
        ta.enforce_anchor(spec, enforcing=True)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _bad_path)
    with pytest.raises(TrustAnchorError, match="through its path"):
        ta.enforce_anchor(spec, enforcing=True)


def _refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verdict: ap.PathVerdict) -> str:
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: verdict)
    with pytest.raises(TrustAnchorError) as err:
        ta.enforce_anchor(AnchorSpec("t", "[x]", str(_pem(tmp_path)), None), enforcing=True)
    return str(err.value)


def test_posix_fix_text_names_each_object(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = ap.ChainFinding(
        "/srv/it's", DIRECTORY, True, "group or others can write to it", writable=True
    )
    link = ap.ChainFinding("/tmp/ca.pem", LINK, True, "it is owned by uid 1000", owner=True)
    text = _refusal(tmp_path, monkeypatch, ap.PathVerdict(False, (folder, link), "posix", "uid 7"))
    q = shlex.quote("/srv/it's")
    # Each finding gets its own command: the folder's is about write bits, so no chown.
    assert f"  chmod go-w {q}" in text
    assert not [line for line in text.splitlines() if "chown" in line and q in line]
    # A link is re-owned with -h, so the command acts on the link and not on what it points at.
    assert "  chown -h root /tmp/ca.pem" in text and "chmod go-w /tmp/ca.pem" not in text
    assert "account it ran as (uid 7)" in text


def test_posix_mode_only_finding_on_the_engines_folder_suggests_no_chown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The container's ``/config`` belongs to the engine. Made group-writable, it earns a mode
    finding and nothing else, so the fix is the chmod alone. A chown to root would take the
    engine's own data folder away from it. Red under: printing a chown for every object."""
    table = {"/config": (10001, stat.S_IFDIR | 0o775), "/config/ca.pem": (10001, F644)}
    v = _posix("/config/ca.pem", table, euid=10001)
    assert [(f.path, f.owner) for f in v.findings if f.insecure] == [("/config", False)]
    text = _refusal(tmp_path, monkeypatch, v)
    assert "  chmod go-w /config" in text
    assert "chown" not in text


def test_posix_owner_finding_suggests_a_chown_that_keeps_the_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An owner finding hands the object to root and changes nothing else. ``root:root`` would
    also take the group, and with it any access the engine held through that group."""
    table = {"/srv": (0, D755), "/srv/ca": (2000, D755), "/srv/ca/a.pem": (0, F644)}
    v = _posix("/srv/ca/a.pem", table)
    assert [(f.path, f.owner) for f in v.findings if f.insecure] == [("/srv/ca", True)]
    text = _refusal(tmp_path, monkeypatch, v)
    assert "  chown -h root /srv/ca" in text
    assert "root:root" not in text and "chmod" not in text


def test_windows_fix_text_for_an_owner_and_a_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned = ap.ChainFinding("C:\\d", DIRECTORY, True, "it is owned by X", (OTHER,), owner=True)
    link = ap.ChainFinding("C:\\d\\jn", LINK, True, "X can write to it", (OTHER,))
    text = _refusal(tmp_path, monkeypatch, ap.PathVerdict(False, (owned, link), "windows"))
    assert "icacls 'C:\\d' /setowner '*S-1-5-32-544'" in text
    assert "icacls 'C:\\d' /remove:g" not in text  # the owner finding names no grant to remove
    assert f"icacls 'C:\\d\\jn' /L /remove:g '*{OTHER}'" in text


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


async def _events(store: MessageStore) -> list[dict[str, Any]]:
    rows = await store.list_audit(action=AUDIT_ACTION, limit=200)
    return [json.loads(r["detail"]) for r in rows]


async def test_preflight_audits_path_indeterminate_and_refuses_at_enforce(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second receipt, inverted by BACKLOG #1142 slice 3 as the design memo planned:
    path_indeterminate is written, and then the preflight refuses at enforce."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _unknown_path)
    spec = AnchorSpec("ad", "[auth].ad_tls_ca_cert_file", str(_pem(tmp_path)), None)
    with pytest.raises(TrustAnchorError, match="could not settle"):
        await ta.run_anchor_preflight([spec], store, enforcing=True)
    row = next(r for r in await _events(store) if r["event"] == "path_indeterminate")
    assert row["components"] == [{"path": "C:\\x", "kind": DIRECTORY, "reason": "access denied"}]
    assert row["enforcing"] is True and row["pinned"] is False


async def test_preflight_path_indeterminate_with_a_matching_pin_loads_and_says_so(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _unknown_path)
    p = _pem(tmp_path)
    pin = hashlib.sha256(p.read_bytes()).hexdigest()
    spec = AnchorSpec(
        "api_client", "[api].tls_client_ca_file", str(p), pin, "[api].tls_client_ca_pin"
    )
    await ta.run_anchor_preflight([spec], store, enforcing=True)
    row = next(r for r in await _events(store) if r["event"] == "path_indeterminate")
    assert row["pinned"] is True


# --- real file systems ----------------------------------------------------------------------------


def _icacls(*args: str, check: bool = True) -> str:
    done = subprocess.run(  # noqa: S603
        [_system_exe("icacls.exe"), *args], check=check, capture_output=True, text=True
    )
    return done.stdout


@pytest.fixture
def programdata_dir() -> Iterator[Path]:
    """A new directory under %ProgramData%, made the ordinary way. Not ``tmp_path``: its ancestors
    are the host's temp directory, which refuses on some hosts (see tests/conftest.py)."""
    root = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData"))
    d = root / f"mefor-test-{uuid.uuid4().hex[:12]}"
    d.mkdir()
    try:
        yield d
    finally:
        _icacls(str(d), "/reset", "/T", "/C", "/Q", check=False)
        shutil.rmtree(d, ignore_errors=True)


@_windows_only
def test_windows_default_programdata_placement_passes(programdata_dir: Path) -> None:
    """The default-install receipt. This is also the Windows Server measurement on the CI legs."""
    anchor = programdata_dir / "anchor.pem"
    anchor.write_bytes(b"x")
    v = ap.anchor_path_verdict(anchor)
    assert v.ok is True, v.findings


@_windows_only
def test_windows_public_placement_refuses() -> None:
    public = Path(os.environ.get("PUBLIC", "C:\\Users\\Public"))
    d = public / f"mefor-test-{uuid.uuid4().hex[:12]}"
    d.mkdir()
    try:
        (d / "anchor.pem").write_bytes(b"x")
        v = ap.anchor_path_verdict(d / "anchor.pem")
        assert v.ok is False, v.findings
        assert any(f.path.lower() == str(d).lower() and f.insecure for f in v.findings)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@_windows_only
def test_windows_delete_child_on_the_directory_is_the_hole_the_file_arm_misses(
    programdata_dir: Path,
) -> None:
    """Section 4c of the design, pinned. The anchor's own DACL is locked, so the file arm reads it
    owner-only. Its directory grants Users delete-child alone, so Users can delete it and plant a
    substitute. Only the path arm sees that."""
    anchor = programdata_dir / "anchor.pem"
    anchor.write_bytes(b"x")
    _icacls(
        str(anchor),
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:F",
        "*S-1-5-32-544:F",
        "*S-1-5-32-545:RX",
    )
    _icacls(str(programdata_dir), "/grant", "*S-1-5-32-545:(DC)")
    assert ta.dacl_is_owner_only(anchor) is True
    v = ap.anchor_path_verdict(anchor)
    assert v.ok is False
    bad = [f for f in v.findings if f.insecure]
    assert [(f.path.lower(), f.sids) for f in bad] == [(str(programdata_dir).lower(), (USERS,))]


@_windows_only
async def test_windows_liveness_receipt(
    programdata_dir: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The liveness receipt, through the real reader: a delete-child grant to Users on the anchor's
    directory makes the enforcing preflight refuse and audit the directory; removing the grant makes
    the same preflight pass."""
    monkeypatch.setattr(ta, "anchor_path_verdict", ap.anchor_path_verdict)  # undo the conftest stub
    anchor = programdata_dir / "anchor.pem"
    anchor.write_bytes(_block(b"anchor"))
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(anchor), None)
    await ta.run_anchor_preflight([spec], store, enforcing=True)  # baseline: passes

    _icacls(str(programdata_dir), "/grant", "*S-1-5-32-545:(DC)")
    with pytest.raises(TrustAnchorError, match="delete or rename entries"):
        await ta.run_anchor_preflight([spec], store, enforcing=True)
    row = next(r for r in await _events(store) if r["event"] == "path_insecure")
    assert [c["path"].lower() for c in row["components"]] == [str(programdata_dir).lower()]
    assert "BUILTIN\\Users (S-1-5-32-545)" in row["components"][0]["reason"]

    _icacls(str(programdata_dir), "/remove:g", "*S-1-5-32-545")
    await ta.run_anchor_preflight([spec], store, enforcing=True)  # the grant is gone: passes again


@_posix_only
def test_posix_tmp_path_modes(tmp_path: Path) -> None:
    d = tmp_path / "ca"
    d.mkdir()
    anchor = d / "anchor.pem"
    anchor.write_bytes(b"x")
    os.chmod(anchor, 0o644)
    os.chmod(d, 0o755)
    assert ap.anchor_path_verdict(anchor).ok is True
    os.chmod(d, 0o777)
    assert ap.anchor_path_verdict(anchor).ok is False
    os.chmod(d, 0o1777)  # sticky, and the anchor is the engine's own
    assert ap.anchor_path_verdict(anchor).ok is True
    os.chmod(d, 0o755)


@_posix_only
async def test_posix_liveness_receipt(tmp_path: Path, store: MessageStore) -> None:
    """The POSIX liveness receipt, through the real reader: an o+w directory refuses the enforcing
    preflight and is audited; putting the mode back makes the same preflight pass."""
    d = tmp_path / "ca"
    d.mkdir(mode=0o755)
    anchor = d / "anchor.pem"
    anchor.write_bytes(_block(b"anchor"))
    os.chmod(anchor, 0o644)
    os.chmod(d, 0o755)
    spec = AnchorSpec("ad", "[auth].ad_tls_ca_cert_file", str(anchor), None)
    await ta.run_anchor_preflight([spec], store, enforcing=True)

    os.chmod(d, 0o757)
    with pytest.raises(TrustAnchorError, match="group or others can write to it"):
        await ta.run_anchor_preflight([spec], store, enforcing=True)
    row = next(r for r in await _events(store) if r["event"] == "path_insecure")
    assert [c["path"] for c in row["components"]] == [str(d)]

    os.chmod(d, 0o755)
    await ta.run_anchor_preflight([spec], store, enforcing=True)


# --- default-install placements under slice 3 (BACKLOG #1142) ------------------------------------
#
# Slice 3 refuses an ACL or path the engine could not read, at enforce, unless a pin matches. So the
# realistic secure placements must read DETERMINATE on both arms, or a default install stops starting.

_PEM_BLOCK = _block(b"anchor")  # a real certificate: the preflight loads it


@_windows_only
def test_windows_default_programdata_placement_loads_at_enforce_with_no_pin(
    programdata_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both arms read for real: the conftest path stub is put back. Measured on this CI leg, and on
    a Windows 11 dev host as the interactive user, 2026-09-25."""
    monkeypatch.setattr(ta, "anchor_path_verdict", ap.anchor_path_verdict)
    anchor = programdata_dir / "anchor.pem"
    anchor.write_bytes(_PEM_BLOCK)
    spec = AnchorSpec("t", "[api].tls_client_ca_file", str(anchor), None)
    v = ta.evaluate_anchor(spec)
    assert (v.acl_ok, v.path_ok) == (True, True), v.path_check
    assert ta.verified_anchor_cadata(spec, enforcing=True)


@_windows_only
def test_windows_temp_placement_refuses_at_enforce_where_it_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The placement slice 3 newly refuses. Measured on a Windows 11 dev host, not elevated,
    2026-09-25: reading C:\\Windows\\Temp's DACL fails with Win32 error 5, so the path check answers
    indeterminate. An account that can read it, such as an elevated CI runner, skips here."""
    monkeypatch.setattr(ta, "anchor_path_verdict", ap.anchor_path_verdict)
    temp = Path(os.environ.get("SYSTEMROOT", "C:\\Windows")) / "Temp"
    anchor = temp / f"mefor-test-{uuid.uuid4().hex[:12]}.pem"
    try:
        anchor.write_bytes(_PEM_BLOCK)
    except OSError as exc:
        pytest.skip(f"cannot write under {temp}: {exc}")
    try:
        spec = AnchorSpec(
            "t", "[api].tls_client_ca_file", str(anchor), None, "[api].tls_client_ca_pin"
        )
        v = ta.evaluate_anchor(spec)
        if v.path_ok is not None:
            pytest.skip(f"this account can read {temp} (path_ok={v.path_ok})")
        with pytest.raises(TrustAnchorError) as err:
            ta.enforce_anchor(spec, enforcing=True)
        text = str(err.value)
        assert "Win32 error 5" in text
        assert "move the anchor" in text and "set [api].tls_client_ca_pin to" in text
        pinned = AnchorSpec("t", "[x]", str(anchor), hashlib.sha256(_PEM_BLOCK).hexdigest())
        assert ta.verified_anchor_cadata(pinned, enforcing=True)  # the escape
    finally:
        anchor.unlink(missing_ok=True)


def test_posix_root_owned_755_placement_loads_at_enforce_with_no_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The POSIX default: a root-owned 755 folder such as /etc/messagefoundry/, a 644 file, and the
    engine running as its own non-root account. Recorded modes, so both CI legs run it."""
    table = {"/etc/messagefoundry": (0, D755), "/etc/messagefoundry/ca.pem": (0, F644)}
    v = _posix("/etc/messagefoundry/ca.pem", table, euid=999)
    assert v.ok is True, v.findings
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: v)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)  # 644: no group or other write
    ta.enforce_anchor(AnchorSpec("t", "[x]", str(_pem(tmp_path)), None), enforcing=True)


# --- vault BACKLOG #5337: a drive-relative spelling reached through the working directory --------


def _plain_probe(p: str) -> tuple[str, str | None]:
    """Every name is a folder, or a file when it ends in ``.pem``; nothing is a link."""
    return (FILE if p.lower().endswith(".pem") else DIRECTORY), None


def _subst_s(drive: str) -> str | None:
    return "\\??\\C:\\real" if drive == "S:" else None


@pytest.mark.parametrize(
    ("anchor", "cwd", "drive_target"),
    [
        # ``C:`` joined to ``ca.pem`` reads ``C:ca.pem``. Red: walked as C:\ca.pem, from the root.
        ("ca.pem", "C:", ap._no_drive_target),
        # A subst drive as that working directory. Red: spliced as C:\realcerts\ca.pem.
        ("certs\\ca.pem", "S:", _subst_s),
    ],
)
def test_a_relative_anchor_under_a_drive_relative_working_directory_is_not_walked(
    anchor: str, cwd: str, drive_target: Any
) -> None:
    """Windows reads ``C:x`` from that drive's own working directory, which the walk does not know,
    so it refuses on every pass, not only on the text it was given (vault BACKLOG #5337)."""
    chain, cause = windows_chain(anchor, cwd, _plain_probe, drive_target=drive_target)
    assert chain == []
    assert cause is not None and "no separator after it" in cause


def test_a_subst_drive_splices_its_target_with_a_separator() -> None:
    """The control: a subst working directory with a separator is walked under its target."""
    chain, cause = windows_chain("certs\\ca.pem", "S:\\w", _plain_probe, drive_target=_subst_s)
    assert cause is None
    assert chain[-1] == ("C:\\real\\w\\certs\\ca.pem", FILE)


# --- BACKLOG #6281 member S12-15: the real reader reads a mask only where an entry holds one -------

#: ``S-1-1-0`` (Everyone) as a binary SID: revision 1, one sub-authority, authority 1, value 0.
_EVERYONE_SID_BYTES = bytes([1, 1, 0, 0, 0, 0, 0, 1]) + (0).to_bytes(4, "little")


def _ace(ace_type: int, body: bytes) -> bytes:
    """One access entry: type, flags, the entry's size counting its own 4-byte header, then body."""
    return bytes([ace_type, 0]) + (4 + len(body)).to_bytes(2, "little") + body


def _allow_everyone() -> bytes:
    return _ace(0x00, (0x001F01FF).to_bytes(4, "little") + _EVERYONE_SID_BYTES)


def _set_protected_dacl(path: Path, aces: list[bytes]) -> int:
    """Write ``aces`` as the protected DACL of ``path``, byte for byte, and return the Win32 status.
    The kernel validates the list, so a status other than 0 means it refused that shape."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise OSError("writes a real NTFS DACL")
    import ctypes
    from ctypes import wintypes

    body = b"".join(aces)
    # ACL header: revision 2, sbz1, AclSize, AceCount, sbz2.
    acl = (
        bytes([2, 0])
        + (8 + len(body)).to_bytes(2, "little")
        + len(aces).to_bytes(2, "little")
        + bytes(2)
        + body
    )
    buffer = ctypes.create_string_buffer(acl, len(acl))
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    # SE_FILE_OBJECT; DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
    return int(advapi32.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, buffer, None))


@_windows_only
def test_s12_15_an_entry_of_an_undefined_type_has_no_mask_read_past_its_end(
    tmp_path: Path,
) -> None:
    """An entry of a type Windows does not define may be its 4-byte header alone, and the kernel
    accepts it in a DACL. The reader records no rights for it. Red: it read the four bytes after
    the header as a mask, here the next entry's header, ``0x00140000``. No caller reads a mask for
    a type that grants nothing, so no verdict changes; after the DACL's last entry the same read
    ran off the descriptor."""
    target = tmp_path / "short-entry.txt"
    target.write_bytes(b"synthetic")
    assert _set_protected_dacl(target, [_ace(0x20, b""), _allow_everyone()]) == 0
    sec = ap.windows_host_readers().read_security(str(target), FILE)
    assert sec.error is None
    assert sec.aces == ((0x20, 0, 0, ""), (0x00, 0, 0x001F01FF, "S-1-1-0"))


@_windows_only
def test_s12_15_the_reader_still_reads_a_well_formed_allow_entry(tmp_path: Path) -> None:
    """The control: a well-formed allow entry reads with its mask and SID as before. The deny entry
    beside it now records no rights. It recorded ``0x2`` before, and no caller reads the rights of
    an entry that grants nothing."""
    target = tmp_path / "well-formed.txt"
    target.write_bytes(b"synthetic")
    deny_write = _ace(0x01, (0x00000002).to_bytes(4, "little") + _EVERYONE_SID_BYTES)
    assert _set_protected_dacl(target, [deny_write, _allow_everyone()]) == 0
    sec = ap.windows_host_readers().read_security(str(target), FILE)
    assert sec.error is None
    assert sec.aces == ((0x01, 0, 0, ""), (0x00, 0, 0x001F01FF, "S-1-1-0"))
