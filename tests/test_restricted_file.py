# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Key files are created restricted, and checked before use (vault BACKLOG #2601).

Three layers, each with a control that must give the opposite answer:

* the pure policy in :mod:`messagefoundry.restricted_file`, which runs on every platform;
* the real create and the real read check, one arm per platform. The Windows arm runs on the
  ``test (windows-2022, py3.14)`` and ``test (windows-2025, py3.14)`` legs and is skipped
  elsewhere; the POSIX arm runs on ``test (ubuntu-latest, py3.14)`` and is skipped on Windows;
* the writers and the ``serve`` gate, driven through one seam so they run on every platform.
"""

from __future__ import annotations

import dataclasses
import errno
import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.restricted_file as restricted_file
import messagefoundry.secrets_dpapi as dpapi_mod
import messagefoundry.store.store as store_mod
from messagefoundry.__main__ import _write_private_key, main
from messagefoundry.auth.anchor_path import (
    DIRECTORY,
    FILE,
    LINK,
    SHARE_CAUSE,
    PosixStat,
    WalkCause,
    WinSecurity,
    WinTrust,
    windows_chain,
)
from messagefoundry.config.wiring import _WinPathSecurity
from messagefoundry.restricted_file import (
    RestrictedFileError,
    broad_access_problem,
    write_restricted_file,
)
from messagefoundry.store.crypto import generate_key
from tests._phi_gate_provisions import PHI_GATE_PROVISIONS_TOML

# The two serve gates every enforcing start meets (tests/_phi_gate_provisions.py says why a module
# names them). They do nothing for the tests here that never call serve.
pytestmark = pytest.mark.usefixtures("bounded_warn_only_retention", "verified_log_forwarding")

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

windows_only = pytest.mark.skipif(
    sys.platform != "win32", reason="the Windows arm; the windows-2022 and windows-2025 legs run it"
)
posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="the POSIX arm; the ubuntu-latest leg runs it"
)

_SYSTEM = "S-1-5-18"
_ADMINS = "S-1-5-32-544"
_USERS = "S-1-5-32-545"
_SERVICE = "S-1-5-80-1-2-3-4-5"
_CREATOR = "S-1-5-21-1-2-3-1001"
_FULL = 0x1F01FF
_READ = 0x120089
_ALLOW = 0
_DENY = 1


def _security(*aces: tuple[int, int, str], **fields: Any) -> _WinPathSecurity:
    return _WinPathSecurity(owner_sid=_CREATOR, aces=tuple(aces), **fields)


# --- pure policy: what a new file carries ---------------------------------------------------------


def test_a_new_file_names_system_administrators_the_creator_and_each_read_grant() -> None:
    access = restricted_file._expected_access(_CREATOR, [_SERVICE])
    assert access == {_SYSTEM: _FULL, _ADMINS: _FULL, _CREATOR: _FULL, _SERVICE: _READ}
    assert restricted_file._protected_sddl(access) == (
        f"D:P(A;;FA;;;{_SYSTEM})(A;;FA;;;{_ADMINS})(A;;FA;;;{_CREATOR})(A;;FR;;;{_SERVICE})"
    )


def test_an_account_already_holding_full_control_gets_no_second_entry() -> None:
    # SYSTEM creating the file, and SYSTEM named as a read grant: one entry, full control.
    assert restricted_file._expected_access(_SYSTEM, [_SYSTEM, _ADMINS]) == {
        _SYSTEM: _FULL,
        _ADMINS: _FULL,
    }


def test_a_new_file_without_its_creators_access_is_the_drafts_descriptor() -> None:
    access = restricted_file._expected_access(_CREATOR, [_SERVICE], creator_access=False)
    assert access == {_SYSTEM: _FULL, _ADMINS: _FULL, _SERVICE: _READ}
    assert restricted_file._protected_sddl(access) == (
        f"D:P(A;;FA;;;{_SYSTEM})(A;;FA;;;{_ADMINS})(A;;FR;;;{_SERVICE})"
    )


_READ_DELETE = 0x00130089


def test_the_handoffs_grant_is_read_and_delete() -> None:
    # Vault BACKLOG #3411: the service deletes the handoff through the handle it read it with.
    access = restricted_file._expected_access(
        _CREATOR, [_SERVICE], creator_access=False, read_delete=True
    )
    assert access == {_SYSTEM: _FULL, _ADMINS: _FULL, _SERVICE: _READ_DELETE}
    assert restricted_file._protected_sddl(access) == (
        f"D:P(A;;FA;;;{_SYSTEM})(A;;FA;;;{_ADMINS})(A;;FRSD;;;{_SERVICE})"
    )
    # The control: without it, read alone.
    assert restricted_file._expected_access(_CREATOR, [_SERVICE])[_SERVICE] == _READ


@pytest.mark.parametrize("sid", [_SYSTEM, "S-1-5-19", "S-1-5-20", None])
def test_a_key_custody_file_is_never_kept_for_a_shared_account(sid: str | None) -> None:
    # SYSTEM is named outright: a grant to it would collapse into SYSTEM's own full-control entry.
    assert restricted_file.custody_account_problem(sid) is not None
    assert restricted_file.custody_account_problem(_SERVICE) is None  # the control
    assert restricted_file.custody_account_problem(_CREATOR) is None


def test_the_create_and_the_read_judge_one_exact_standard() -> None:
    # The create reads back through the creating handle and calls the read side's own check,
    # which judges each entry's flags too.
    expected = restricted_file._expected_access(_CREATOR, [_SERVICE])
    exact = (
        (_ALLOW, 0, _FULL, _SYSTEM),
        (_ALLOW, 0, _FULL, _ADMINS),
        (_ALLOW, 0, _FULL, _CREATOR),
        (_ALLOW, 0, _READ, _SERVICE),
    )
    held = restricted_file._HandleSecurity(owner_sid=_CREATOR, protected=True, aces=exact)
    assert restricted_file._exact_descriptor_problem(held, expected, engine_sid=_CREATOR) is None
    flagged = restricted_file._HandleSecurity(
        owner_sid=_CREATOR, protected=True, aces=(*exact[:3], (_ALLOW, 0x10, _READ, _SERVICE))
    )
    assert "flags 0x10" in str(
        restricted_file._exact_descriptor_problem(flagged, expected, engine_sid=_CREATOR)
    )


# --- pure policy: the exact check through a handle ------------------------------------------------

_HandleSecurity = restricted_file._HandleSecurity


def _held(*aces: tuple[int, int, int, str], **fields: Any) -> Any:
    fields.setdefault("owner_sid", _ADMINS)
    fields.setdefault("protected", True)
    return _HandleSecurity(aces=aces, **fields)


_EXACT_READ = (
    (_ALLOW, 0, _FULL, _SYSTEM),
    (_ALLOW, 0, _FULL, _ADMINS),
    (_ALLOW, 0, _READ, _SERVICE),
)


def _exact(security: Any, *, engine_access: int = _READ) -> str | None:
    if engine_access == _READ:  # the handoff's list
        expected = restricted_file._expected_access(_CREATOR, [_SERVICE], creator_access=False)
    else:  # the host file's list
        expected = restricted_file._expected_access(_SERVICE, ())
    return restricted_file._exact_descriptor_problem(security, expected, engine_sid=_SERVICE)


def test_the_exact_check_accepts_the_drafts_descriptor_and_each_allowed_owner() -> None:
    for owner in (_SYSTEM, _ADMINS, _SERVICE):  # the controls for every refusal below
        assert _exact(_held(*_EXACT_READ, owner_sid=owner)) is None
    assert _exact(_held(*reversed(_EXACT_READ))) is None  # order does not matter
    full = ((_ALLOW, 0, _FULL, _SYSTEM), (_ALLOW, 0, _FULL, _ADMINS), (_ALLOW, 0, _FULL, _SERVICE))
    assert _exact(_held(*full), engine_access=_FULL) is None


def test_the_exact_check_refuses_another_owner() -> None:
    # A handoff another local account wrote with a narrow list: that account owns its file.
    problem = _exact(_held(*_EXACT_READ, owner_sid=_CREATOR))
    assert f"owned by {_CREATOR}" in str(problem)
    assert "owner could not be read" in str(_exact(_held(*_EXACT_READ, owner_sid=None)))


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ((_ALLOW, 0, _READ, _CREATOR), f"grants {_CREATOR} access 0x00120089"),
        ((_ALLOW, 0, _READ, "S-1-15-2-1"), "the application package S-1-15-2-1"),
        ((_ALLOW, 0, _READ, _USERS), "Users"),
        ((_DENY, 0, _FULL, _CREATOR), "type 0x01"),
        ((0x05, 0, _READ, ""), "type 0x05"),
    ],
)
def test_the_exact_check_refuses_any_extra_entry(
    extra: tuple[int, int, int, str], expected: str
) -> None:
    problem = _exact(_held(*_EXACT_READ, extra))
    assert expected in str(problem) and "beyond the key file's own" in str(problem)


def test_the_exact_check_refuses_a_changed_missing_or_repeated_entry() -> None:
    widened = (
        (_ALLOW, 0, _FULL, _SYSTEM),
        (_ALLOW, 0, _FULL, _ADMINS),
        (_ALLOW, 0, _FULL, _SERVICE),
    )
    assert "access 0x001f01ff" in str(_exact(_held(*widened)))
    inherit = (*_EXACT_READ[:2], (_ALLOW, 0x10, _READ, _SERVICE))
    assert "flags 0x10" in str(_exact(_held(*inherit)))
    assert "lacks or repeats" in str(_exact(_held(*_EXACT_READ[:2])))
    assert "lacks or repeats" in str(_exact(_held(*_EXACT_READ, _EXACT_READ[2])))


def test_the_exact_check_refuses_what_it_could_not_read_or_an_open_list() -> None:
    assert "could not be read (Win32 error 5" in str(
        _exact(_HandleSecurity(error="Win32 error 5: Access is denied."))
    )
    assert "no access list at all" in str(_exact(_held(dacl_present=False)))
    assert "does not block inheritance" in str(_exact(_held(*_EXACT_READ, protected=False)))


_HandleVolume = restricted_file._HandleVolume


def _volume(file_system: str = "NTFS", device_type: int = 0x07, **fields: Any) -> str | None:
    return restricted_file._volume_problem(
        _HandleVolume(file_system=file_system, device_type=device_type, **fields)
    )


def test_a_key_file_volume_must_be_a_local_ntfs_or_refs_disk() -> None:
    assert _volume("NTFS") is None  # the controls: what a local disk answered, measured
    assert _volume("ReFS") is None
    # A server or a user-mode file system reports the owner and list; this host keeps neither.
    assert "network volume" in str(_volume(characteristics=0x10))
    for device_type in (0x14, 0x12, 0x06, 0x28, 0x35, 0x36):  # network and DFS redirectors
        assert f"device type {device_type:#04x}" in str(_volume(device_type=device_type))
    assert "FAT32 volume" in str(_volume("FAT32"))
    assert "nameless volume" in str(_volume(""))
    failed = _HandleVolume(error="Win32 error 1")
    assert "could not be read (Win32 error 1)" in str(restricted_file._volume_problem(failed))


def test_the_file_system_allowlists_cannot_be_changed_at_run_time() -> None:
    with pytest.raises(TypeError):
        restricted_file.LINUX_HOST_FILE_SYSTEMS[0x6969] = "x"  # type: ignore[index]
    with pytest.raises(TypeError):
        restricted_file.LINUX_CREDENTIAL_FILE_SYSTEMS[0x6969] = "x"  # type: ignore[index]


_EXT4, _XFS, _BTRFS, _ZFS, _F2FS, _BCACHEFS = (
    0xEF53,
    0x58465342,
    0x9123683E,
    0x2FC12FC1,
    0xF2F52010,
    0xCA451A4E,
)
_RAMFS, _TMPFS = 0x858458F6, 0x01021994


def test_the_file_system_allowlists_name_exactly_the_local_kinds() -> None:
    assert set(restricted_file.LINUX_HOST_FILE_SYSTEMS) == {
        _EXT4,
        _XFS,
        _BTRFS,
        _ZFS,
        _F2FS,
        _BCACHEFS,
    }
    assert set(restricted_file.LINUX_CREDENTIAL_FILE_SYSTEMS) == {_RAMFS, _TMPFS}


@pytest.mark.parametrize(
    "magic",
    [
        0x6969,  # NFS
        0xFF534D42,  # CIFS
        0xFE534D42,  # SMB2
        0x65735546,  # FUSE
        0x794C7630,  # overlayfs
        0xF15F,  # ecryptfs, which may be stacked over NFS
        # On no deny list slice B1.5 had, and refused here without being named.
        0x20030528,  # OrangeFS
        0x19830326,  # BeeGFS
        _TMPFS,  # in memory: a host file would not outlive a reboot
        0,
    ],
)
def test_a_host_file_system_the_allowlist_does_not_name_is_refused_by_its_magic(
    magic: int,
) -> None:
    allowed = restricted_file.LINUX_HOST_FILE_SYSTEMS
    problem = restricted_file.linux_file_system_problem(magic, allowed, "host file")
    assert f"type {magic:#010x}" in str(problem)
    assert "xfs" in str(problem) and "bcachefs only" in str(problem)
    for local in allowed:  # the controls
        assert restricted_file.linux_file_system_problem(local, allowed, "host file") is None


def test_an_empty_allowlist_refuses_every_file_system() -> None:
    from types import MappingProxyType

    assert "no file system holds" in str(
        restricted_file.linux_file_system_problem(_EXT4, MappingProxyType({}), "host file")
    )


@pytest.mark.parametrize(
    ("sid", "kind", "allowed"),
    [
        (_CREATOR, 1, True),  # a user account
        (_SERVICE, 5, True),  # a virtual service account, as Windows reports one
        (_SERVICE, None, True),  # the same, for a service not yet installed
        (_ADMINS, 4, False),  # an alias
        ("S-1-5-32-551", 4, False),  # Backup Operators
        ("S-1-5-21-1-2-3-512", 2, False),  # a domain group
        ("S-1-5-21-1-2-3-512", None, False),  # one whose domain did not answer
        ("S-1-5-80-0", 5, False),  # ALL SERVICES
        ("S-1-1-0", 5, False),  # Everyone
        ("S-1-15-2-1", 5, False),  # ALL APPLICATION PACKAGES
        (_SYSTEM, 5, False),
        ("S-1-5-19", 5, False),
        ("S-1-5-80-1-2-3-4-5-6", 5, False),  # not the shape of one service's own SID
        ("S-1-5-21-1-2-3-1105", 9, True),  # a computer account, as a gMSA may answer
    ],
)
def test_a_handoff_is_granted_to_one_account_only(
    sid: str, kind: int | None, allowed: bool
) -> None:
    asked: list[str] = []

    def _kind_of(asked_sid: str) -> int | None:
        asked.append(asked_sid)
        return kind

    problem = restricted_file.handoff_grantee_problem(sid, _kind_of)
    assert (problem is None) is allowed, problem
    # Windows is asked only past the checks that need no lookup: the shared accounts, a package
    # and one service's own SID are judged on the SID alone.
    no_lookup = sid in {_SYSTEM, "S-1-5-19", "S-1-15-2-1", _SERVICE}
    assert asked == ([] if no_lookup else [sid])


@windows_only
def test_windows_an_account_kind_is_read_from_windows() -> None:
    from messagefoundry.config.wiring import _win32_config_source_probes

    me = _win32_config_source_probes().self_sid
    assert me is not None
    assert restricted_file.lookup_sid_kind(me) == 1  # a user account
    assert restricted_file.lookup_sid_kind(_ADMINS) == 4  # an alias
    assert restricted_file.lookup_sid_kind("S-1-5-21-1-2-3-512") is None  # mapped to nothing


def test_a_credential_is_read_from_an_in_memory_file_system_only() -> None:
    allowed = restricted_file.LINUX_CREDENTIAL_FILE_SYSTEMS
    assert restricted_file.linux_file_system_problem(_TMPFS, allowed, "credential") is None
    assert restricted_file.linux_file_system_problem(_RAMFS, allowed, "credential") is None
    assert "ramfs or tmpfs only" in str(
        restricted_file.linux_file_system_problem(_EXT4, allowed, "credential")
    )


def test_a_c_library_without_fstatfs_is_an_error_chained_from_its_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ctypes

    class _NoSymbols:
        def __init__(self, *_a: object, **_k: object) -> None:
            pass

        def __getattr__(self, name: str) -> object:
            raise AttributeError(name)

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(ctypes, "CDLL", _NoSymbols)
    with pytest.raises(OSError, match="offers no fstatfs") as excinfo:
        restricted_file.linux_file_system_type(0)
    assert excinfo.value.errno == errno.ENOSYS
    assert isinstance(excinfo.value.__cause__, AttributeError)  # not dropped


def test_a_volume_check_off_linux_and_windows_is_refused_before_a_file_is_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    path = tmp_path / "host.blob"
    with pytest.raises(RestrictedFileError, match="Linux and Windows only"):
        restricted_file._create_restricted(
            path, (), creator_access=True, owner=None, local_volume_only=True
        )
    assert not path.exists()


def test_a_file_that_cannot_be_removed_after_a_failure_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _refuse(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(errno.EACCES, "Access is denied")

    monkeypatch.setattr(Path, "unlink", _refuse)
    original = RestrictedFileError("the original failure")
    with pytest.raises(RestrictedFileError, match="left behind") as excinfo:
        restricted_file._remove_failed(tmp_path / "store.key", original)
    # The original failure is named, and chained, not replaced by the unlink error.
    assert "the original failure" in str(excinfo.value)
    assert excinfo.value.__cause__ is original
    # A BaseException that is not an Exception keeps its type and gains a note.
    interrupt = KeyboardInterrupt()
    restricted_file._remove_failed(tmp_path / "store.key", interrupt)
    assert "left behind" in " ".join(getattr(interrupt, "__notes__", []))


def test_a_file_already_gone_after_a_failure_is_no_second_error(tmp_path: Path) -> None:
    restricted_file._remove_failed(tmp_path / "absent.key", RestrictedFileError("x"))


# --- pure policy: the read check ------------------------------------------------------------------


def test_an_access_list_naming_only_the_intended_accounts_has_no_read_problem() -> None:
    # The control for every refusal below: the list the helper itself writes.
    restricted = _security(
        (_ALLOW, _FULL, _SYSTEM),
        (_ALLOW, _FULL, _ADMINS),
        (_ALLOW, _FULL, _CREATOR),
        (_ALLOW, _READ, _SERVICE),
    )
    assert restricted_file._windows_access_problem(restricted) is None


@pytest.mark.parametrize(
    ("ace", "named"),
    [
        ((_ALLOW, _READ, _USERS), f"Users ({_USERS})"),
        ((_ALLOW, _FULL, "S-1-1-0"), "Everyone"),
        ((_ALLOW, 0x80000000, "S-1-5-11"), "Authenticated users (S-1-5-11)"),  # GENERIC_READ
        ((_ALLOW, 0x00040000, "S-1-5-4"), "S-1-5-4"),  # WRITE_DAC alone: it can grant itself read
        ((_ALLOW, _READ, "S-1-5-21-9-9-9-513"), "S-1-5-21-9-9-9-513"),  # Domain Users
        # Broad groups and logon classes beyond the trust-anchor list.
        ((_ALLOW, _READ, "S-1-2-0"), "S-1-2-0"),  # LOCAL
        ((_ALLOW, _READ, "S-1-5-14"), "S-1-5-14"),  # REMOTE INTERACTIVE LOGON
        ((_ALLOW, _READ, "S-1-5-15"), "S-1-5-15"),  # THIS ORGANIZATION
        ((_ALLOW, _READ, "S-1-5-32-555"), "S-1-5-32-555"),  # Remote Desktop Users
        ((_ALLOW, _READ, "S-1-5-80-0"), "S-1-5-80-0"),  # ALL SERVICES
        ((_ALLOW, _READ, "S-1-5-32-568"), "S-1-5-32-568"),  # IIS_IUSRS
        ((_ALLOW, _READ, "S-1-18-1"), "S-1-18-1"),  # asserted identity, on every domain logon
        ((_ALLOW, _READ, "S-1-5-21-9-9-9-515"), "S-1-5-21-9-9-9-515"),  # Domain Computers
        # Changing the file counts as much as reading it: the key could be substituted.
        ((_ALLOW, 0x00000002, _USERS), f"Users ({_USERS})"),  # FILE_WRITE_DATA
        ((_ALLOW, 0x00010000, _USERS), f"Users ({_USERS})"),  # DELETE
    ],
)
def test_a_broad_account_that_can_read_is_a_problem(ace: tuple[int, int, str], named: str) -> None:
    listed = _security((_ALLOW, _FULL, _SYSTEM), ace)
    problem = restricted_file._windows_access_problem(listed)
    assert problem is not None and named in problem and "can read or change it" in problem


@pytest.mark.parametrize(
    "sid",
    [
        "S-1-18-3",  # Fresh public key identity
        "S-1-18-4",  # Key trust identity
        "S-1-18-5",  # Key property MFA
        "S-1-18-6",  # Key property attestation
        "S-1-5-1000",  # Other Organization
        "S-1-5-65-1",  # This Organization Certificate
        "S-1-5-90-0",  # Window Manager Group
        "S-1-5-9",  # Enterprise Domain Controllers
        "S-1-5-83-0",  # Virtual Machines
        "S-1-5-84-0-0-0-0-0",  # USER MODE DRIVERS
        "S-1-5-22",  # Legacy Enterprise Read-only Domain Controllers Beta
        "S-1-5-32-554",  # Pre-Windows 2000 Compatible Access
        "S-1-5-64-36",  # Cloud Account Authentication
        "S-1-5-21-9-9-9-516",  # Domain Controllers
        "S-1-5-21-9-9-9-521",  # Read-only Domain Controllers
        "S-1-5-21-9-9-9-498",  # Enterprise Read-only Domain Controllers
    ],
)
def test_more_well_known_groups_are_broad(sid: str) -> None:
    # Vault BACKLOG #5929 item 3: each of these well-known groups passed the broad-group screen, so
    # a read grant naming one would have widened read access to a key file.
    assert "a group many accounts hold" in str(restricted_file._screened_principal(sid))
    listed = _security((_ALLOW, _FULL, _SYSTEM), (_ALLOW, _READ, sid))
    assert sid in str(restricted_file._windows_access_problem(listed))


def test_a_domain_account_sid_is_not_a_broad_group() -> None:
    # Vault BACKLOG #5929 item 4: an account of a domain (S-1-5-21-..., the shape a group managed
    # service account's SID takes) is one account, so a read grant to it is not reported. Domain
    # Computers in the same domain is the control.
    account = "S-1-5-21-9-9-9-1105"
    assert restricted_file._screened_principal(account) is None
    listed = _security((_ALLOW, _FULL, _SYSTEM), (_ALLOW, _READ, account))
    assert restricted_file._windows_access_problem(listed) is None
    computers = _security((_ALLOW, _FULL, _SYSTEM), (_ALLOW, _READ, "S-1-5-21-9-9-9-515"))
    assert restricted_file._windows_access_problem(computers) is not None


def test_a_shared_service_account_is_an_account_not_a_broad_group() -> None:
    # An engine may run as NETWORK SERVICE, and an operator may grant it. The create accepts that
    # grant, so the check must not then report the file: one predicate serves both sides.
    listed = _security((_ALLOW, _FULL, _SYSTEM), (_ALLOW, _READ, "S-1-5-20"))
    assert restricted_file._windows_access_problem(listed) is None
    assert not restricted_file._is_broad_group("S-1-5-20")
    assert restricted_file._is_broad_group(_USERS)  # the control


def test_an_entry_the_check_cannot_interpret_is_a_problem() -> None:
    # A conditional allow entry (type 9) is recorded with no rights and no account, so who it lets
    # in is unknown. That is not a pass. A deny entry (type 1) grants nothing and is the control.
    conditional = _security((_ALLOW, _FULL, _SYSTEM), (9, 0, ""))
    assert "cannot interpret" in str(restricted_file._windows_access_problem(conditional))
    denied = _security((_ALLOW, _FULL, _SYSTEM), (_DENY, 0, ""))
    assert restricted_file._windows_access_problem(denied) is None


def test_a_broad_group_that_can_neither_read_nor_change_the_file_is_not_a_problem() -> None:
    # Reading attributes, or being denied, gives nobody the key and lets nobody replace it.
    attributes_only = _security((_ALLOW, 0x00000080, _USERS))  # FILE_READ_ATTRIBUTES
    assert restricted_file._windows_access_problem(attributes_only) is None
    denied = _security((_DENY, 0, ""), (_ALLOW, _FULL, _CREATOR))
    assert restricted_file._windows_access_problem(denied) is None


def test_an_access_list_that_could_not_be_read_is_a_problem() -> None:
    assert "could not be read" in str(
        restricted_file._windows_access_problem(_WinPathSecurity(status=5, status_text="denied"))
    )
    assert "no access list" in str(
        restricted_file._windows_access_problem(_WinPathSecurity(dacl_present=False))
    )
    assert "in full" in str(
        restricted_file._windows_access_problem(_WinPathSecurity(owner_sid=_CREATOR))
    )


def test_a_package_sid_is_told_apart_from_an_account() -> None:
    # Vault BACKLOG #3411: a key file is never granted to an AppContainer package or capability.
    assert restricted_file._is_package_sid("S-1-15-2-1")
    assert restricted_file._is_package_sid("s-1-15-3-1024-1")
    assert not restricted_file._is_package_sid("S-1-5-19")  # the control: LOCAL SERVICE
    assert not restricted_file._is_package_sid("S-1-5-80-1234")  # a service SID


def test_the_posix_check_is_the_group_and_other_read_and_write_bits() -> None:
    assert restricted_file._posix_access_problem(stat.S_IFREG | 0o600) is None  # the control
    assert restricted_file._posix_access_problem(stat.S_IFREG | 0o400) is None
    assert "0640" in str(restricted_file._posix_access_problem(stat.S_IFREG | 0o640))
    assert "0604" in str(restricted_file._posix_access_problem(stat.S_IFREG | 0o604))
    assert "0620" in str(restricted_file._posix_access_problem(stat.S_IFREG | 0o620))
    assert "0602" in str(restricted_file._posix_access_problem(stat.S_IFREG | 0o602))
    # An execute bit alone gives nobody the key and lets nobody replace it.
    assert restricted_file._posix_access_problem(stat.S_IFREG | 0o711) is None


_ENGINE_UID = 10001
_OTHER_UID = 10002
_KEY = stat.S_IFREG | 0o600
_HOLDER = stat.S_IFDIR | 0o700


def _posix_key(
    mode: int = _KEY,
    uid: int = _ENGINE_UID,
    parent_mode: int = _HOLDER,
    parent_uid: int = _ENGINE_UID,
) -> str | None:
    return restricted_file._posix_key_file_problem(
        mode=mode, uid=uid, parent_mode=parent_mode, parent_uid=parent_uid, euid=_ENGINE_UID
    )


def test_the_posix_key_file_decision_passes_an_owner_only_file_in_an_owner_only_directory() -> None:
    """The control for the refusals below (vault BACKLOG #5636)."""
    assert _posix_key() is None
    assert _posix_key(uid=0, parent_uid=0) is None  # root owns what it can reach anyway
    assert _posix_key(parent_mode=stat.S_IFDIR | 0o755) is None  # read and search change nothing
    # A sticky directory that others may write still lets nobody else delete or rename the file.
    assert _posix_key(parent_mode=stat.S_IFDIR | 0o1777, parent_uid=0) is None


def test_the_posix_key_file_decision_refuses_a_link() -> None:
    assert "it is a link" in str(_posix_key(mode=stat.S_IFLNK | 0o777))
    # The link is refused whoever owns it and wherever it is.
    assert "it is a link" in str(_posix_key(mode=stat.S_IFLNK | 0o600, uid=0))


def test_the_posix_key_file_decision_refuses_a_file_another_account_owns() -> None:
    problem = str(_posix_key(uid=_OTHER_UID))
    assert f"owned by uid {_OTHER_UID}" in problem and f"(uid {_ENGINE_UID})" in problem


def test_the_posix_key_file_decision_still_refuses_a_group_or_other_bit() -> None:
    assert "0640" in str(_posix_key(mode=stat.S_IFREG | 0o640))
    assert "0604" in str(_posix_key(mode=stat.S_IFREG | 0o604))


def test_the_posix_key_file_decision_refuses_a_directory_another_account_owns() -> None:
    problem = str(_posix_key(parent_uid=_OTHER_UID))
    assert "the directory that holds it" in problem and f"uid {_OTHER_UID}" in problem


@pytest.mark.parametrize("mode", [0o770, 0o730, 0o707, 0o703, 0o777, 0o2775])
def test_the_posix_key_file_decision_refuses_a_directory_a_group_or_other_may_write(
    mode: int,
) -> None:
    problem = str(_posix_key(parent_mode=stat.S_IFDIR | mode))
    assert f"has mode {mode:04o} with no sticky bit" in problem


def test_the_directory_that_holds_a_path_is_read_through_the_kernel_for_dot_names() -> None:
    assert restricted_file._posix_parent(Path("a") / "b.key") == Path("a")
    assert restricted_file._posix_parent(Path("b.key")) == Path(".")
    assert restricted_file._posix_parent(Path(".")) == Path("..")
    assert restricted_file._posix_parent(Path("a") / "..") == Path("a") / ".." / ".."


# --- the Windows owner, the holding directory and the path above (vault BACKLOG #5657) -----------

#: ``C:\ProgramData``'s own list, as ``icacls`` shows it on a stock host: Users may list and
#: traverse it and add a file or a folder to it, which replaces nothing. A key under it must pass.
_PROGRAMDATA_ACES: tuple[tuple[int, int, str], ...] = (
    (_ALLOW, _FULL, _SYSTEM),
    (_ALLOW, _FULL, _ADMINS),
    (_ALLOW, 0x10000000, "S-1-3-0"),  # CREATOR OWNER, GENERIC_ALL, inherit-only
    (_ALLOW, 0x001200A9, _USERS),  # read and execute
    (_ALLOW, 0x00000116, _USERS),  # WD, AD, WEA, WA
)


@pytest.mark.parametrize("owner", [_CREATOR, _SYSTEM, _ADMINS, "S-1-5-20"])
def test_a_key_file_any_one_account_owns_has_no_owner_problem(owner: str) -> None:
    """The control: an operator's own TLS key is often owned by the administrator who copied it in,
    so the owner rule names no allowed accounts, only refused ones."""
    listed = _WinPathSecurity(owner_sid=owner, aces=((_ALLOW, _FULL, _SYSTEM),))
    assert restricted_file._windows_access_problem(listed) is None


@pytest.mark.parametrize(
    ("owner", "named"),
    [
        (_USERS, f"Users ({_USERS})"),
        ("S-1-1-0", "Everyone"),
        ("S-1-5-11", "(S-1-5-11)"),
        ("S-1-15-2-1", "an application package"),
    ],
)
def test_a_key_file_a_broad_group_or_a_package_owns_is_refused(owner: str, named: str) -> None:
    """An owner may rewrite the list, so a broad owner is as open as a broad grant of full
    control. The old check read the entries only and passed this list."""
    listed = _WinPathSecurity(owner_sid=owner, aces=((_ALLOW, _FULL, _SYSTEM),))
    problem = str(restricted_file._windows_access_problem(listed))
    assert (
        "its owner is " in problem and named in problem and "can change its access list" in problem
    )


def test_a_key_file_whose_owner_could_not_be_read_is_refused() -> None:
    listed = _WinPathSecurity(owner_sid=None, aces=((_ALLOW, _FULL, _SYSTEM),))
    assert "its owner could not be read" in str(restricted_file._windows_access_problem(listed))


_INHERIT_ONLY = 0x08


def _holder(*aces: tuple[int, int, str], owner: str = _CREATOR, flags: int = 0) -> WinSecurity:
    """A holder's owner and entries as the flag-aware reader records them, each with ``flags``."""
    return WinSecurity(owner, tuple((t, flags, m, s) for t, m, s in aces))


#: Modify, as a data drive's root hands it to Authenticated Users: it carries DELETE.
_MODIFY = 0x001301BF


def test_a_holder_like_programdata_or_a_data_drive_holds_no_right_the_holder_rule_refuses() -> None:
    """ProgramData's list is the control for the holder refusals below: listing, traversing and
    adding a file delete no file already in the directory. The Modify a data drive's root hands
    Authenticated Users passing here pins an OPEN gap, not a guarantee: Modify carries DELETE,
    which lets its holder rename the directory away, and the rule does not count it yet (vault
    BACKLOG #5657 item 11 (a)). Fixing that gap changes this assertion."""
    assert restricted_file._windows_holder_problem(_holder(*_PROGRAMDATA_ACES)) is None
    modify = _holder((_ALLOW, _FULL, _SYSTEM), (_ALLOW, _MODIFY, "S-1-5-11"))
    assert restricted_file._windows_holder_problem(modify) is None


@pytest.mark.parametrize(
    "right",
    [
        0x00000040,  # FILE_DELETE_CHILD
        0x00040000,  # WRITE_DAC: it can give itself FILE_DELETE_CHILD
        0x00080000,  # WRITE_OWNER: likewise, by taking the directory over
        0x10000000,  # GENERIC_ALL
    ],
)
def test_a_holder_that_lets_a_broad_group_replace_a_key_is_refused(right: int) -> None:
    holder = _holder(*_PROGRAMDATA_ACES, (_ALLOW, right, _USERS))
    problem = str(restricted_file._windows_holder_problem(holder))
    assert f"Users ({_USERS}) can delete or replace a file in it" in problem


def test_a_holder_entry_that_applies_only_to_its_children_is_still_counted() -> None:
    """The holder rule refused an inherit-only entry before it read the entry flags, as
    origin/main's reader, which drops them, still does; skipping one passed a holder origin/main
    refused, so it is counted again."""
    template = _holder((_ALLOW, _FULL, _USERS), owner=_ADMINS, flags=_INHERIT_ONLY)
    assert f"Users ({_USERS})" in str(restricted_file._windows_holder_problem(template))
    as_main_reads_it = _WinPathSecurity(owner_sid=_ADMINS, aces=((_ALLOW, _FULL, _USERS),))
    assert restricted_file._windows_access_problem(as_main_reads_it, 0x40) is not None


def test_a_holder_a_broad_group_owns_is_refused() -> None:
    holder = _holder(*_PROGRAMDATA_ACES, owner=_USERS)
    problem = str(restricted_file._windows_holder_problem(holder))
    assert "its owner is " in problem and f"Users ({_USERS})" in problem


def test_a_holder_with_no_access_list_or_no_readable_owner_is_refused() -> None:
    assert "no access list" in str(
        restricted_file._windows_holder_problem(WinSecurity(_ADMINS, None))
    )
    unowned = WinSecurity(None, ((_ALLOW, 0, _FULL, _SYSTEM),))
    assert "owner could not be read" in str(restricted_file._windows_holder_problem(unowned))


def _walk(path: str) -> list[tuple[str, str]]:
    """The walk of a Windows ``path`` over a stand-in file system with one junction, at
    ``C:\\data\\linked``, onto ``D:\\elsewhere``."""

    def probe(part: str) -> tuple[str, str | None]:
        if part.lower() == "c:\\data\\linked":
            return LINK, "D:\\elsewhere"
        return (FILE if part.endswith(".key") else DIRECTORY), None

    chain, cause = windows_chain(path, "C:\\", probe)
    assert cause is None
    return chain


#: The engine's own account in the stand-in readers below.
_ENGINE_SID = "S-1-5-80-9-9-9"


def _link_problem(
    *,
    link: WinSecurity,
    holder: WinSecurity,
    path: str,
    others: dict[str, WinSecurity] | None = None,
) -> str | None:
    """:func:`_windows_link_problem` over :func:`_walk`, with ``link`` read for the junction and
    ``holder`` for the folder that holds it, ``others`` by lower-cased path; every other object
    reads as SYSTEM's alone."""
    clean = WinSecurity(_SYSTEM, ((_ALLOW, 0, _FULL, _SYSTEM),))

    def read_security(obj: str, _kind: str) -> WinSecurity:
        named = {"c:\\data\\linked": link, "c:\\data": holder, **(others or {})}
        return named.get(obj.lower(), clean)

    trust = WinTrust(_ENGINE_SID, admin_member=lambda _sid: False)
    return restricted_file._windows_link_problem(_walk(path), read_security, trust)


#: A junction or folder only SYSTEM and Administrators may change, as ``C:\Users\All Users``.
_SYSTEMS = WinSecurity(_SYSTEM, ((_ALLOW, 0, _FULL, _SYSTEM), (_ALLOW, 0, _FULL, _ADMINS)))


def test_a_junction_only_system_administrators_or_the_engine_can_change_passes() -> None:
    """Vault BACKLOG #5657, the owner's ruling of the Manager's question 2: a link above the key is
    judged by who can change it, so a SYSTEM junction or a volume an administrator mounted passes."""
    assert _link_problem(link=_SYSTEMS, holder=_SYSTEMS, path="C:\\data\\linked\\k.key") is None
    engines = WinSecurity(_ENGINE_SID, ((_ALLOW, 0, _FULL, _ENGINE_SID),))
    assert _link_problem(link=engines, holder=_SYSTEMS, path="C:\\data\\linked\\k.key") is None
    # A path with no junction on it reads no security at all.
    assert _link_problem(link=_SYSTEMS, holder=_SYSTEMS, path="C:\\data\\real\\k.key") is None


def test_a_junction_a_broad_group_can_change_is_refused() -> None:
    writable_link = WinSecurity(_SYSTEM, ((_ALLOW, 0, 0x00000002, _USERS),))  # FILE_WRITE_DATA
    problem = str(_link_problem(link=writable_link, holder=_SYSTEMS, path="C:\\data\\linked\\k"))
    assert (
        "a junction or link on its path can be changed by an account this check does not trust"
        in problem
    )
    assert f"({_USERS})" in problem
    deletable = WinSecurity(_SYSTEM, ((_ALLOW, 0, 0x00000040, _USERS),))  # FILE_DELETE_CHILD
    problem = str(_link_problem(link=_SYSTEMS, holder=deletable, path="C:\\data\\linked\\k"))
    assert "a folder holding or above a junction or link on its path can be changed" in problem
    owned = WinSecurity(_USERS, ((_ALLOW, 0, _FULL, _SYSTEM),))
    assert "owned by" in str(_link_problem(link=owned, holder=_SYSTEMS, path="C:\\data\\linked\\k"))
    unread = WinSecurity(None, (), "error 5")
    assert "could not be judged" in str(
        _link_problem(link=unread, holder=_SYSTEMS, path="C:\\data\\linked\\k")
    )


def test_a_walk_that_did_not_finish_is_refused_except_at_a_share() -> None:
    assert restricted_file._windows_cause_problem(None) is None
    assert restricted_file._windows_cause_problem(WalkCause.plain(SHARE_CAUSE)) is None
    stopped = WalkCause("C:\\a secret path could not be read", "a name could not be read")
    problem = str(restricted_file._windows_cause_problem(stopped))
    assert "could not be walked (a name could not be read)" in problem
    assert "secret path" not in problem  # a cause's kind names no path; its text may


def _posix_link(
    path: str, objects: dict[str, tuple[int, int]], links: dict[str, str]
) -> str | None:
    """:func:`_posix_link_problem` over a stand-in file system: ``objects`` maps a path to its
    ``(uid, mode)``, ``links`` a link to its target. The engine is :data:`_ENGINE_UID`."""

    def lstat_fn(part: str) -> PosixStat:
        if part not in objects:
            raise OSError(errno.ENOENT, "No such file or directory")
        uid, mode = objects[part]
        return PosixStat(uid, mode)

    return restricted_file._posix_link_problem(
        path, cwd="/", euid=_ENGINE_UID, lstat_fn=lstat_fn, readlink_fn=links.__getitem__
    )


_ROOT_DIR = (0, stat.S_IFDIR | 0o755)
_KEY_TREE: dict[str, tuple[int, int]] = {
    "/": _ROOT_DIR,
    "/private": _ROOT_DIR,
    "/private/tmp": (0, stat.S_IFDIR | 0o1777),
    "/private/tmp/keys": (_ENGINE_UID, stat.S_IFDIR | 0o700),
    "/private/tmp/keys/k.key": (_ENGINE_UID, _KEY),
}


def test_a_posix_link_only_root_or_the_engine_can_change_passes() -> None:
    """Vault BACKLOG #5656: macOS ``/tmp`` is root's link to ``/private/tmp`` in a folder only root
    may write, so a key under it passes; the old walk refused every link above the key."""
    tree = {**_KEY_TREE, "/tmp": (0, stat.S_IFLNK | 0o755)}
    assert _posix_link("/tmp/keys/k.key", tree, {"/tmp": "private/tmp"}) is None
    # The engine's own link, in a sticky folder others may write, passes too.
    mine = {**tree, "/private/tmp/mine": (_ENGINE_UID, stat.S_IFLNK | 0o777)}
    assert _posix_link("/private/tmp/mine/k.key", mine, {"/private/tmp/mine": "keys"}) is None


def test_a_folder_above_a_junction_a_broad_group_can_change_is_refused() -> None:
    """A broad delete right on any folder above the junction's holder lets that group rename the
    holder away and put its own junction in its place (the Manager's ruling on round 3 item 1)."""
    above = {"c:\\": WinSecurity(_SYSTEM, ((_ALLOW, 0, 0x00000040, _USERS),))}  # FILE_DELETE_CHILD
    problem = str(
        _link_problem(link=_SYSTEMS, holder=_SYSTEMS, path="C:\\data\\linked\\k", others=above)
    )
    assert "a folder holding or above a junction or link on its path can be changed" in problem
    # DELETE on a volume root renames nothing, so it is not counted there.
    root_delete = {"c:\\": WinSecurity(_SYSTEM, ((_ALLOW, 0, 0x00010000, "S-1-5-11"),))}
    assert (
        _link_problem(
            link=_SYSTEMS, holder=_SYSTEMS, path="C:\\data\\linked\\k", others=root_delete
        )
        is None
    )


def test_a_posix_folder_above_a_links_holder_others_may_write_is_refused() -> None:
    """``/shared`` is 0777 with no sticky bit, above a root-owned ``/shared/sub`` that holds a
    root-owned link: any account may rename ``sub`` away and plant its own link."""
    tree = {
        **_KEY_TREE,
        "/shared": (0, stat.S_IFDIR | 0o777),
        "/shared/sub": _ROOT_DIR,
        "/shared/sub/keys": (0, stat.S_IFLNK | 0o777),
    }
    problem = str(
        _posix_link("/shared/sub/keys/k.key", tree, {"/shared/sub/keys": "/private/tmp/keys"})
    )
    assert "a folder holding or above a junction or link on its path can be changed" in problem
    # The control: the same tree with /shared sticky passes.
    sticky = {**tree, "/shared": (0, stat.S_IFDIR | 0o1777)}
    assert (
        _posix_link("/shared/sub/keys/k.key", sticky, {"/shared/sub/keys": "/private/tmp/keys"})
        is None
    )


@pytest.mark.parametrize("owner", [_ENGINE_SID, _SYSTEM, _ADMINS])
def test_a_file_only_the_engine_writes_may_be_owned_by_the_engine_system_or_administrators(
    owner: str,
) -> None:
    assert restricted_file._windows_engine_owner_problem(owner, _ENGINE_SID) is None


def test_a_file_only_the_engine_writes_owned_by_another_account_is_refused() -> None:
    """The minted TLS pair: one planted through the right to add a file to the store directory,
    owned by the account that planted it, is refused (the Manager's ruling on round 3 item 2)."""
    problem = str(restricted_file._windows_engine_owner_problem(_CREATOR, _ENGINE_SID))
    assert f"it is owned by {_CREATOR}" in problem and "the engine did not make it" in problem
    assert "could not be read" in str(
        restricted_file._windows_engine_owner_problem(None, _ENGINE_SID)
    )
    assert "could not be read" in str(restricted_file._windows_engine_owner_problem(_CREATOR, None))


@pytest.mark.parametrize(
    "path",
    [
        "\\\\localhost\\c$\\keys\\k.key",
        "\\\\LOCALHOST\\c$\\keys\\k.key",
        "\\\\127.0.0.1\\c$\\keys\\k.key",
        "\\\\127.1.2.3\\c$\\keys\\k.key",
        "\\\\[::1]\\c$\\keys\\k.key",
        "\\\\0--1.ipv6-literal.net\\c$\\keys\\k.key",
        "\\\\?\\UNC\\localhost\\c$\\keys\\k.key",
        "\\\\.\\UNC\\localhost\\c$\\keys\\k.key",
        "\\\\localhost.\\c$\\keys\\k.key",
        "\\\\0-0-0-0-0-0-0-1.ipv6-literal.net\\c$\\keys\\k.key",
        "\\\\MyHost\\keys\\k.key",
        "//localhost/c$/keys/k.key",
        "\\\\127.1\\c$\\keys\\k.key",  # IPv4 shorthand
        "\\\\2130706433\\c$\\keys\\k.key",  # 127.0.0.1 as one decimal number
        "\\\\0.0.0.0\\c$\\keys\\k.key",
        "\\\\192.0.2.10\\c$\\keys\\k.key",  # this host's own address, by the route below
        "\\\\0--1.ipv6-literal.net.\\c$\\keys\\k.key",  # the fully qualified spelling
        "\\\\localhost@SSL\\DavWWWRoot\\keys\\k.key",  # WebDAV over TLS
        "\\\\localhost@8080\\keys\\k.key",  # WebDAV on a port
        "\\\\localhost@SSL@8443\\DavWWWRoot\\keys\\k.key",
        "\\\\localhost$NOCSC$\\c$\\keys\\k.key",  # the offline-files bypass
        "\\\\MYHOST$NOCSC$\\keys\\k.key",
    ],
)
def test_a_share_that_is_this_host_itself_is_refused(path: str) -> None:
    """Vault BACKLOG #5657: a share spelled with one of this host's own names or addresses
    is refused."""
    problem = str(restricted_file._loopback_share_problem(path, "myhost", _routes_to_itself))
    assert "a network share that may be on this host itself" in problem
    assert "keys" not in problem  # names no path


def _routes_to_itself(addr: Any) -> Any:
    """A stand-in route: ``192.0.2.10`` is this host's own address; any other is reached from it."""
    import ipaddress

    own = ipaddress.ip_address("192.0.2.10")
    return addr if addr == own else own


@pytest.mark.parametrize(
    "path",
    [
        "\\\\fileserver\\keys\\k.key",
        "\\\\myhost2\\keys\\k.key",
        "C:\\keys\\k.key",
        "\\\\127.example.com\\keys\\k.key",  # a name, not the 127 range
        "\\\\192.0.2.99\\keys\\k.key",  # another host's address: the negative control
    ],
)
def test_a_share_on_another_host_or_a_local_path_is_not_a_loopback(path: str) -> None:
    problem = restricted_file._loopback_share_problem(
        path, "myhost.corp.example", _routes_to_itself
    )
    assert problem is None


def test_a_share_address_whose_route_cannot_be_read_is_refused() -> None:
    """Fail closed: an address this host cannot place may be its own."""
    problem = restricted_file._loopback_share_problem(
        "\\\\192.0.2.99\\keys\\k.key", "myhost", lambda _addr: None
    )
    assert problem is not None and "route this host could not read" in problem


def test_the_route_probe_answers_a_loopback_address_with_itself() -> None:
    import ipaddress

    loopback = ipaddress.ip_address("127.0.0.1")
    assert restricted_file._route_source(loopback) == loopback


@pytest.mark.parametrize(
    ("path", "host_name"),
    [
        ("\\\\myhost.other.example\\keys\\k.key", "myhost.corp.example"),  # same first label
        ("\\\\myhost\\keys\\k.key", "myhost.corp.example"),  # the first label alone
        ("\\\\myhost.corp.example\\keys\\k.key", "myhost"),  # a longer name
        ("\\\\LAB-SERVER-NAME\\c$\\k.key", "lab-server-name-01"),  # the NetBIOS form
    ],
)
def test_a_share_matching_only_part_of_this_hosts_name_is_not_a_loopback(
    path: str, host_name: str
) -> None:
    """origin/main read no share as this host, so a share on another host that shares this host's
    first label passed there; the name is now matched whole."""
    assert restricted_file._loopback_share_problem(path, host_name, _routes_to_itself) is None


@pytest.mark.parametrize("ace_type", [0x05, 0x09, 0x0B])  # object, callback, callback object
def test_a_conditional_holder_entry_is_refused_whatever_its_mask(ace_type: int) -> None:
    """origin/main refused any conditional, object or callback allow entry on the holder, whom it
    applies to being unknown; the branch passed one whose mask held no replace right."""
    read_only = WinSecurity(_ADMINS, ((ace_type, 0, 0x00000001, ""),))
    assert "conditional entry" in str(restricted_file._windows_holder_problem(read_only))
    as_main_reads_it = _WinPathSecurity(owner_sid=_ADMINS, aces=((ace_type, 0x00000001, ""),))
    assert "conditional entry" in str(
        restricted_file._windows_access_problem(as_main_reads_it, 0x40)
    )


def test_a_posix_root_that_could_not_be_read_is_refused() -> None:
    """Vault BACKLOG #5636, #5657: when ``lstat('/')`` failed, the walk returned one unread finding
    about ``/``, which the link filter dropped, so no link on the path was judged."""

    def lstat_fn(part: str) -> PosixStat:
        raise OSError(errno.EACCES, "Permission denied")

    problem = restricted_file._posix_link_problem(
        "/srv/keys/k.key",
        cwd="/",
        euid=_ENGINE_UID,
        lstat_fn=lstat_fn,
        readlink_fn=lambda _part: "",
    )
    assert problem is not None and "could not be read, so no link on it was judged" in problem


def _typed_link_problem(path: str, mounts: list[tuple[str, str]]) -> str | None:
    """:func:`_posix_link_problem` over :data:`_KEY_TREE`, every object root's or the engine's and
    no folder others may write without the sticky bit, so only the mount type can refuse."""

    def lstat_fn(part: str) -> PosixStat:
        if part not in _KEY_TREE:
            raise OSError(errno.ENOENT, "No such file or directory")
        uid, mode = _KEY_TREE[part]
        return PosixStat(uid, mode)

    from messagefoundry.auth.anchor_path import mount_of

    return restricted_file._posix_link_problem(
        path,
        cwd="/",
        euid=_ENGINE_UID,
        lstat_fn=lstat_fn,
        readlink_fn=lambda _part: "",
        fstype_fn=lambda part: mount_of(part, mounts),
    )


@pytest.mark.parametrize(
    "fstype",
    [
        *sorted(restricted_file._POSIX_DELEGATED_FILE_SYSTEMS),
        "fuse.sshfs",
        "fuseblk.ntfs-3g",
    ],
)
def test_a_posix_key_on_a_delegated_file_system_is_refused(fstype: str) -> None:
    """Vault BACKLOG #5657 step 6 (f), #5636: the owner and mode bits of an NFS, CIFS, 9p or FUSE
    mount are not what decides who may reach the file, so a clean 0600 key under clean folders on
    one was passed. The refusal names the type and no path."""
    mounts = [("/", "ext4"), ("/private/tmp", fstype)]
    problem = _typed_link_problem("/private/tmp/keys/k.key", mounts)
    assert problem is not None and f"its path is on a mount of type {fstype}," in problem
    assert "/private" not in problem


def test_a_posix_mount_refusal_names_no_role_its_caller_does_not_hold() -> None:
    """The reason is spliced after whatever the caller names, a key file, the secrets directory or
    the custody directory, so its remedy must work for each: it once told a secrets-directory
    refusal to move "its store directory", which that directory has none of (vault BACKLOG #5657)."""
    mounts = [("/", "ext4"), ("/private/tmp", "nfs")]
    problem = _typed_link_problem("/private/tmp/keys", mounts)
    assert problem is not None
    assert "store directory" not in problem and "the engine mints" not in problem
    assert problem.endswith(
        "keep it, and the folders its path runs through, on a local file system"
    )


@pytest.mark.parametrize("fstype", ["9p", "virtiofs", "nfs4"])
def test_a_posix_root_mount_is_not_judged_by_its_type(fstype: str) -> None:
    """A sandbox whose ``/`` is a 9p or virtiofs share would otherwise refuse every key file; a
    delegated mount below ``/`` on the same path is still refused."""
    assert _typed_link_problem("/private/tmp/keys/k.key", [("/", fstype)]) is None
    below = [("/", fstype), ("/private", "nfs")]
    assert "mount of type nfs," in str(_typed_link_problem("/private/tmp/keys/k.key", below))


@pytest.mark.parametrize("fstype", ["ext4", "xfs", "tmpfs", "overlay", "zfs", "vfat"])
def test_a_posix_key_on_a_type_not_named_is_not_judged_by_its_type(fstype: str) -> None:
    """A local type, and any type the rule does not name, is left as before: the negative
    control for the test above."""
    mounts = [("/", "ext4"), ("/private/tmp", fstype)]
    assert _typed_link_problem("/private/tmp/keys/k.key", mounts) is None


def test_a_posix_mount_type_the_refusal_cannot_print_is_not_quoted() -> None:
    """A FUSE subtype is chosen by whoever mounts it, so one with characters outside a type name's
    is replaced in the refusal rather than copied into the start error and the log."""
    mounts = [("/", "ext4"), ("/private/tmp", "fuse.\x1b[2Jodd")]
    problem = _typed_link_problem("/private/tmp/keys/k.key", mounts)
    assert problem is not None and "on a mount of type network or FUSE," in problem
    assert "\x1b" not in problem


def test_a_posix_mount_table_that_could_not_be_read_judges_no_type() -> None:
    """With no mount read (``fstype_fn`` answers ``None``, as off Linux) nothing is refused for
    its type, and the walk is otherwise unchanged."""
    assert _typed_link_problem("/private/tmp/keys/k.key", []) is None


@pytest.mark.skipif(sys.platform == "win32", reason="the POSIX key-file check runs off Windows")
def test_broad_access_problem_refuses_a_key_the_mount_table_puts_on_nfs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end on this host: a 0600 key in a 0700 folder passes, until the mount table says
    the folder is an NFS mount (vault BACKLOG #5657 step 6 (f))."""
    os.chmod(tmp_path, 0o700)
    key = tmp_path / "k.key"
    key.write_bytes(b"synthetic")
    os.chmod(key, 0o600)
    # The control: a CI runner's temporary folder is on a local file system.
    assert restricted_file.broad_access_problem(key) is None
    monkeypatch.setattr(
        restricted_file,
        "read_mounts",
        lambda: [("/", "ext4"), (os.path.realpath(tmp_path), "nfs4")],
        raising=False,
    )
    problem = restricted_file.broad_access_problem(key)
    assert problem is not None and "its path is on a mount of type nfs4," in problem


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux has a mount table to read")
def test_broad_access_problem_refuses_where_the_linux_mount_table_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Linux an unreadable ``/proc/self/mountinfo`` means no type on the path was judged, so it
    is refused rather than passed as if it had been."""
    os.chmod(tmp_path, 0o700)
    key = tmp_path / "k.key"
    key.write_bytes(b"synthetic")
    os.chmod(key, 0o600)
    monkeypatch.setattr(restricted_file, "read_mounts", lambda: None, raising=False)
    problem = restricted_file.broad_access_problem(key)
    assert problem is not None and "/proc/self/mountinfo could not be read" in problem


def test_a_posix_link_another_account_can_change_is_refused() -> None:
    # A link in a folder a group may write, with no sticky bit: any member may re-point it.
    shared = {
        **_KEY_TREE,
        "/srv": (0, stat.S_IFDIR | 0o775),
        "/srv/keys": (0, stat.S_IFLNK | 0o777),
    }
    problem = str(_posix_link("/srv/keys/k.key", shared, {"/srv/keys": "/private/tmp/keys"}))
    assert "a folder holding or above a junction or link on its path can be changed" in problem
    assert "group or others can write to it" in problem
    # A link another account owns, in a sticky folder others may write: its owner may re-point it.
    theirs = {**_KEY_TREE, "/private/tmp/theirs": (_OTHER_UID, stat.S_IFLNK | 0o777)}
    problem = str(_posix_link("/private/tmp/theirs/k.key", theirs, {"/private/tmp/theirs": "keys"}))
    assert "a link on its path is owned by another account" in problem
    assert "/private" not in problem  # a refusal names no path
    # A folder holding a link that another account owns.
    owned = {
        **_KEY_TREE,
        "/srv": (_OTHER_UID, stat.S_IFDIR | 0o755),
        "/srv/keys": (0, stat.S_IFLNK),
    }
    problem = str(_posix_link("/srv/keys/k.key", owned, {"/srv/keys": "/private/tmp/keys"}))
    assert f"uid {_OTHER_UID}" in problem


# --- the Windows arm, for real --------------------------------------------------------------------


def _grant_users_read(path: Path) -> None:
    store_mod._grant_read(path, f"*{_USERS}")


def _windows_access(path: Path) -> tuple[bool, set[tuple[int, int, str]], str | None]:
    """(protected, entries, creator SID) of ``path``, read through the engine's own ctypes readers."""
    from messagefoundry.config.wiring import _win32_config_source_probes

    probes = _win32_config_source_probes()
    security = probes.read_path(path)
    parsed = store_mod._parse_sddl_dacl(store_mod._read_dacl_sddl(path) or "")
    assert parsed is not None and security.aces is not None
    return parsed.protected, set(security.aces), probes.self_sid


@windows_only
def test_windows_creates_the_file_with_exactly_the_intended_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No icacls call is made for the file: the list is attached by the creating call itself.
    def _no_icacls(*_a: object, **_k: object) -> str:
        raise AssertionError("the restricted create must not shell out")

    monkeypatch.setattr(store_mod, "_system_exe", _no_icacls)
    path = tmp_path / "store.key"
    write_restricted_file(path, b"KEY-MATERIAL-STAND-IN", read_grants=[f"*{_SERVICE}"])

    assert path.read_bytes() == b"KEY-MATERIAL-STAND-IN"
    protected, entries, creator = _windows_access(path)
    assert protected
    assert creator is not None
    assert entries == {
        (_ALLOW, _FULL, _SYSTEM),
        (_ALLOW, _FULL, _ADMINS),
        (_ALLOW, _FULL, creator),
        (_ALLOW, _READ, _SERVICE),
    }
    assert broad_access_problem(path) is None


@windows_only
def test_windows_creates_the_drafts_descriptor_without_the_creators_entry(tmp_path: Path) -> None:
    # Off-admin, as here, the creator owns the file and is in no entry; it still writes the file
    # through the handle that made it.
    path = tmp_path / "handoff.key"
    write_restricted_file(
        path, b"KEY-MATERIAL-STAND-IN", read_grants=[f"*{_SERVICE}"], creator_access=False
    )
    protected, entries, creator = _windows_access(path)
    assert protected
    assert entries == {
        (_ALLOW, _FULL, _SYSTEM),
        (_ALLOW, _FULL, _ADMINS),
        (_ALLOW, _READ, _SERVICE),
    }
    assert creator not in {sid for _t, _m, sid in entries}
    # The default is unchanged: the creator keeps its full-control entry.
    default = tmp_path / "default.key"
    write_restricted_file(default, b"k", read_grants=[f"*{_SERVICE}"])
    assert (_ALLOW, _FULL, creator) in _windows_access(default)[1]


def _is_elevated() -> bool:
    # The production pre-check, not a second API (vault BACKLOG #6674 item 5).
    if sys.platform != "win32":
        return False
    try:
        return restricted_file.administrators_enabled()
    except RestrictedFileError:
        return False  # a token that cannot be read is not elevated; never fail collection


@windows_only
def test_windows_creates_the_file_owned_as_asked_or_not_at_all(tmp_path: Path) -> None:
    path = tmp_path / "handoff.key"
    grants = [f"*{_SERVICE}"]
    if not _is_elevated():
        # A filtered token holds Administrators deny-only, so the create itself is refused.
        with pytest.raises(RestrictedFileError, match="may not make"):
            write_restricted_file(
                path, b"k", read_grants=grants, creator_access=False, owner=_ADMINS
            )
        assert not path.exists()
        return
    write_restricted_file(path, b"k", read_grants=grants, creator_access=False, owner=_ADMINS)
    parsed = store_mod._parse_sddl_dacl(store_mod._read_dacl_sddl(path, owner=True) or "")
    assert parsed is not None and parsed.owner == _ADMINS


@windows_only
def test_windows_an_owner_no_token_may_assign_is_refused_on_every_leg(tmp_path: Path) -> None:
    # Vault BACKLOG #6674 item 2: the Administrators owner reaches ERROR_INVALID_OWNER only off-admin,
    # and the hosted legs run elevated. One service's SID is an owner neither an elevated nor a
    # filtered token may assign without the restore privilege enabled, so this reaches the 1307
    # branch on every leg. The CI leg runs under Git Bash, whose runtime is believed to enable that
    # privilege on an elevated token, so it is turned off for the create.
    from tests.test_worktree_remove_in_use import _privileges_disabled

    path = tmp_path / "handoff.key"
    with (
        _privileges_disabled(("SeRestorePrivilege",)),
        pytest.raises(RestrictedFileError, match="may not make") as caught,
    ):
        write_restricted_file(path, b"k", owner=f"*{_SERVICE}")
    assert isinstance(caught.value, restricted_file.OwnerRefused)
    assert not path.exists()


@windows_only
@pytest.mark.parametrize(
    ("owner", "refusal"),
    [
        pytest.param("*S-1-1-0", "a group many accounts hold", id="everyone"),
        pytest.param(f"*{_USERS}", "a group many accounts hold", id="users"),
        pytest.param("*S-1-15-2-1", "an application package", id="all-app-packages"),
        pytest.param("*S-1-15-3-1024-1", "an application package", id="capability"),
    ],
)
def test_windows_an_owner_is_screened_as_a_read_grant_is(
    tmp_path: Path, owner: str, refusal: str
) -> None:
    # Vault BACKLOG #6674 item 1: an owner holds READ_CONTROL and WRITE_DAC, so it gets the package
    # and broad-group screens a read grant gets, before any file is made. The control, an owner of
    # this process's own account, is test_windows_a_file_that_reads_back_owned_by_another_is_removed.
    path = tmp_path / "store.key"
    with pytest.raises(RestrictedFileError, match=refusal) as caught:
        write_restricted_file(path, b"k", owner=owner)
    assert "cannot be owned by it" in str(caught.value)
    assert not isinstance(caught.value, restricted_file.OwnerRefused)  # refused before the create
    assert not path.exists()


@windows_only
def test_windows_an_owner_named_by_a_group_name_is_refused(tmp_path: Path) -> None:
    # Vault BACKLOG #6674 item 3, as documented: an alias such as Administrators is refused by
    # name, with owner advice, and is named as an owner by its SID.
    import getpass

    path = tmp_path / "store.key"
    with pytest.raises(RestrictedFileError, match="name an owner .* by its SID"):
        write_restricted_file(path, b"k", owner="BUILTIN\\Administrators")
    assert not path.exists()
    # The control: an owner named by this process's own account name resolves and is accepted.
    mine = tmp_path / "mine.key"
    write_restricted_file(mine, b"k", owner=f"{os.environ['USERDOMAIN']}\\{getpass.getuser()}")
    assert mine.read_bytes() == b"k"


@windows_only
def test_windows_a_file_that_reads_back_owned_by_another_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.config.wiring import _win32_config_source_probes

    # Any token may make its own account the owner, so this runs off-admin too.
    me = _win32_config_source_probes().self_sid
    assert me is not None
    control = tmp_path / "control.key"
    # The control: read back as asked, so kept. Named as a grant is, so the leading `*` resolves.
    write_restricted_file(control, b"k", owner=f"*{me}")
    assert control.read_bytes() == b"k"
    real = restricted_file._read_handle_security

    def _foreign(handle: int) -> Any:
        read = real(handle)
        assert read.owner_sid == me  # the real read, through the creating handle, saw the owner
        return type(read)(owner_sid=_SERVICE)

    monkeypatch.setattr(restricted_file, "_read_handle_security", _foreign)
    path = tmp_path / "store.key"
    with pytest.raises(RestrictedFileError, match="reads back owned by"):
        write_restricted_file(path, b"k", owner=me)
    assert not path.exists()


@windows_only
def test_windows_the_exact_check_reads_a_real_handle(tmp_path: Path) -> None:
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        return
    import msvcrt

    path = tmp_path / "store.key"
    write_restricted_file(path, b"k")  # SYSTEM, Administrators and this account, full control
    with path.open("rb") as handle:
        os_handle = msvcrt.get_osfhandle(handle.fileno())
        assert restricted_file.key_file_handle_problem(os_handle, engine_read_only=False) is None
        assert "beyond the key file's own" in str(
            restricted_file.key_file_handle_problem(os_handle, engine_read_only=True)
        )
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"x")
    with plain.open("rb") as handle:
        os_handle = msvcrt.get_osfhandle(handle.fileno())
        assert restricted_file.key_file_handle_problem(os_handle, engine_read_only=False)


@windows_only
def test_windows_restricts_the_file_before_any_byte_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The defect this closes was a file that held the key while it still carried the directory's
    inherited access. Read the access at the moment the write starts: it is already final."""
    path = tmp_path / "store.key"
    seen: dict[str, Any] = {}
    real_fdopen = os.fdopen

    def _observing_fdopen(fd: int, *a: Any, **k: Any) -> Any:
        seen["size"] = path.stat().st_size
        seen["protected"], seen["entries"], _creator = _windows_access(path)
        return real_fdopen(fd, *a, **k)

    # A scoped patch: undoing the shared monkeypatch would also undo the module's serve fixtures.
    with monkeypatch.context() as scoped:
        scoped.setattr(os, "fdopen", _observing_fdopen)
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN")

    assert seen["size"] == 0
    assert seen["protected"] is True
    assert seen["entries"] == _windows_access(path)[1]
    # The control: a file created the ordinary way in the same directory inherits, unprotected.
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"x")
    assert _windows_access(plain)[0] is False


@windows_only
def test_windows_resolves_an_account_name_and_refuses_one_it_cannot(tmp_path: Path) -> None:
    named = tmp_path / "named.key"
    write_restricted_file(named, b"k", read_grants=["NT AUTHORITY\\NETWORK SERVICE"])
    assert (_ALLOW, _READ, "S-1-5-20") in _windows_access(named)[1]
    # What the create accepts as a grant, the check does not then report.
    assert broad_access_problem(named) is None

    refused = tmp_path / "refused.key"
    with pytest.raises(RestrictedFileError, match="could not be resolved"):
        write_restricted_file(refused, b"k", read_grants=["NO-SUCH-DOMAIN\\no-such-account"])
    assert not refused.exists()


@windows_only
@pytest.mark.parametrize("name", ["NT SERVICE", "BUILTIN"])
def test_windows_refuses_a_name_that_is_not_one_account(tmp_path: Path, name: str) -> None:
    # A bare domain resolves to a SID no token carries, so the grant would reach nobody and the
    # service would fail at its first start. A group is not one account either. The control is the
    # account name in the test above, which is granted.
    with pytest.raises(RestrictedFileError, match="to a domain, and a key file is granted"):
        write_restricted_file(tmp_path / "store.key", b"k", read_grants=[name])
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("kind", "admitted_as_grant", "admitted_as_owner", "named"),
    [
        (1, True, True, None),
        (5, True, True, None),
        # A group managed service account may resolve as a computer account, so the grant takes
        # one, and a plain computer account with it. An owner of that kind is named by its SID.
        (9, True, False, "a computer account"),
        (2, False, False, "a group"),
        (3, False, False, "a domain"),
        (4, False, False, "an alias"),
        (6, False, False, "a deleted account"),
        (7, False, False, "an invalid account"),
        (8, False, False, "an unknown account"),
        (10, False, False, "a label"),
        (11, False, False, "a logon session"),
        (12, False, False, "an account of kind 12"),
    ],
)
def test_a_grant_name_may_resolve_to_a_computer_account(
    kind: int, admitted_as_grant: bool, admitted_as_owner: bool, named: str | None
) -> None:
    for as_owner, admitted in ((False, admitted_as_grant), (True, admitted_as_owner)):
        problem = restricted_file._name_kind_problem("CORP\\svc-mefor$", kind, as_owner=as_owner)
        if admitted:
            assert problem is None
        else:
            # The refusal names the kind the name resolved to.
            assert problem is not None and f"to {named}," in problem
            # Only an owner that can hold a file, a group, an alias or a computer account, is sent
            # on to its SID literal: not a dead account, nor a domain, a label or a logon session.
            assert ("by its SID" in problem) == (as_owner and kind in (2, 4, 9))
            if not as_owner and kind not in (6, 7, 8):
                # A grant refusal says the broad groups among well-known names are refused.
                assert "less at least the known broad groups" in problem


@windows_only
def test_windows_a_computer_account_grant_name_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The whole create, for a name Windows resolves as a computer account: the grant is written
    # and reads back. NETWORK SERVICE's SID stands in for the gMSA, an account apart from the
    # creator so its read entry is its own; the kind is what is under test.
    monkeypatch.setattr(restricted_file, "lookup_account_name", lambda _name: ("S-1-5-20", 9))
    path = tmp_path / "store.key"
    write_restricted_file(path, b"k", read_grants=["CORP\\gmsa-mefor$"])
    assert (_ALLOW, _READ, "S-1-5-20") in _windows_access(path)[1]
    assert path.read_bytes() == b"k"
    # The control: the same name as an owner is refused, and leaves no file.
    refused = tmp_path / "owned.key"
    with pytest.raises(RestrictedFileError, match="to a computer account, not a user"):
        write_restricted_file(refused, b"k", owner="CORP\\gmsa-mefor$")
    assert not refused.exists()


@windows_only
@pytest.mark.parametrize(
    "grant", [f"*{_USERS}", "*S-1-1-0", "*S-1-5-11", "*S-1-5-15", "*S-1-5-1000", "*S-1-18-3"]
)
def test_windows_refuses_a_read_grant_to_a_broad_group(tmp_path: Path, grant: str) -> None:
    # A grant that would make the key file broadly readable is not a restricted create. The control
    # is the per-service grant in the test above, which is created.
    path = tmp_path / "store.key"
    with pytest.raises(RestrictedFileError, match="cannot be granted"):
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN", read_grants=[grant])
    assert list(tmp_path.iterdir()) == []


@windows_only
def test_windows_removes_a_file_whose_access_does_not_read_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The file really is created, then judged. A read-back that disagrees must leave nothing.
    path = tmp_path / "store.key"
    seen: dict[str, bool] = {}

    def _disagree(*_a: object, **_k: object) -> str:
        seen["existed"] = path.exists()
        return "stand-in mismatch"

    monkeypatch.setattr(restricted_file, "_exact_descriptor_problem", _disagree)
    with pytest.raises(RestrictedFileError, match="stand-in mismatch"):
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN")
    assert seen == {"existed": True}
    assert list(tmp_path.iterdir()) == []


@windows_only
def test_windows_the_create_reads_back_through_its_own_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _by_name(*_a: object, **_k: object) -> str | None:
        raise AssertionError("the create must not read the new file back by its name")

    handles: list[int] = []
    real = restricted_file._read_handle_security

    def _spy(handle: int) -> Any:
        handles.append(handle)
        return real(handle)

    monkeypatch.setattr(store_mod, "_read_dacl_sddl", _by_name)
    monkeypatch.setattr(restricted_file, "_read_handle_security", _spy)
    path = tmp_path / "store.key"
    write_restricted_file(path, b"k")
    assert path.read_bytes() == b"k"
    assert len(handles) == 1  # the creating handle, read once


@windows_only
def test_windows_a_created_entry_with_an_inheritance_flag_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The read side's standard: the earlier create-side check compared entries without their flags.
    real = restricted_file._read_handle_security

    def _flagged(handle: int) -> Any:
        read = real(handle)
        ace_type, _flags, mask, sid = read.aces[-1]
        return type(read)(
            owner_sid=read.owner_sid,
            protected=read.protected,
            aces=(*read.aces[:-1], (ace_type, 0x10, mask, sid)),
        )

    monkeypatch.setattr(restricted_file, "_read_handle_security", _flagged)
    path = tmp_path / "store.key"
    with pytest.raises(RestrictedFileError, match="flags 0x10"):
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN")
    assert list(tmp_path.iterdir()) == []


@windows_only
def test_windows_creates_a_read_and_delete_grant(tmp_path: Path) -> None:
    path = tmp_path / "handoff.key"
    write_restricted_file(
        path, b"k", read_grants=[f"*{_SERVICE}"], creator_access=False, read_delete=True
    )
    assert _windows_access(path)[1] == {
        (_ALLOW, _FULL, _SYSTEM),
        (_ALLOW, _FULL, _ADMINS),
        (_ALLOW, _READ_DELETE, _SERVICE),
    }


@windows_only
@pytest.mark.parametrize(
    ("volume", "expected"),
    [
        (restricted_file._HandleVolume(file_system="FAT32", device_type=0x07), "FAT32 volume"),
        (
            restricted_file._HandleVolume(
                file_system="NTFS", device_type=0x07, characteristics=0x10
            ),
            "network volume",
        ),
        (restricted_file._HandleVolume(file_system="NTFS", device_type=0x14), "device type 0x14"),
    ],
)
def test_windows_a_key_custody_file_off_a_local_disk_is_refused_before_a_byte_is_written(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    volume: Any,
    expected: str,
) -> None:
    control = tmp_path / "control.key"
    write_restricted_file(control, b"k", local_volume_only=True)  # the control: a real local disk
    assert control.read_bytes() == b"k"
    seen: list[int] = []

    def _read(handle: int) -> Any:
        seen.append(handle)
        return volume

    monkeypatch.setattr(restricted_file, "_read_handle_volume", _read)
    path = tmp_path / "store.key"
    with pytest.raises(RestrictedFileError, match=expected):
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN", local_volume_only=True)
    assert not path.exists() and len(seen) == 1
    # Off by default: the other key writers, the TLS key's included, are not checked.
    write_restricted_file(tmp_path / "tls.key", b"k")
    assert len(seen) == 1


@windows_only
def test_windows_a_file_is_deleted_through_its_handle(tmp_path: Path) -> None:
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        return
    import msvcrt

    path = tmp_path / "handoff.key"
    write_restricted_file(path, b"k")
    # The control: a handle without DELETE is refused.
    with path.open("rb") as handle, pytest.raises(PermissionError):
        restricted_file.delete_through_handle(msvcrt.get_osfhandle(handle.fileno()))
    assert path.exists()
    from messagefoundry.store.custody import _open_windows_held

    fd = _open_windows_held(path, delete=True)
    try:
        restricted_file.delete_through_handle(msvcrt.get_osfhandle(fd))
    finally:
        os.close(fd)
    assert not path.exists()


@windows_only
def test_windows_a_read_only_file_is_deleted_through_its_handle(tmp_path: Path) -> None:
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        return
    import msvcrt

    from messagefoundry.store.custody import _open_windows_held

    path = tmp_path / "handoff.key"
    write_restricted_file(path, b"k")
    os.chmod(path, stat.S_IREAD)  # FILE_ATTRIBUTE_READONLY, as a copy or a restore may leave it
    assert os.stat(path).st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
    fd = _open_windows_held(path, delete=True)
    try:
        restricted_file.delete_through_handle(msvcrt.get_osfhandle(fd))
    finally:
        os.close(fd)
    assert not path.exists()


def test_a_file_is_deleted_through_its_handle_on_windows_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(RestrictedFileError, match="Windows only"):
        restricted_file.delete_through_handle(0)


@windows_only
def test_windows_read_check_on_real_files(tmp_path: Path) -> None:
    restricted = tmp_path / "restricted.key"
    write_restricted_file(restricted, b"k")
    assert broad_access_problem(restricted) is None  # the control

    broad = tmp_path / "broad.key"
    broad.write_bytes(b"k")
    _grant_users_read(broad)
    assert f"Users ({_USERS})" in str(broad_access_problem(broad))

    link = tmp_path / "link.key"
    try:
        os.symlink(restricted, link)
    except OSError:
        return  # this account may not create a symbolic link; the two arms above still ran
    assert "it is a link" in str(broad_access_problem(link))


def _icacls(path: Path, *args: str) -> None:
    import subprocess

    subprocess.run(["icacls", str(path), *args], check=True, capture_output=True)


@windows_only
def test_windows_refuses_a_restricted_key_beneath_a_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #5657: the check read the key file alone, never the folders on its path. A
    junction is judged by who can change it: the engine's own junction in its own folder passes,
    and one in a folder Users may delete entries in is refused. A junction needs no privilege to
    make, so this arm never skips."""
    judge_links_only_under(monkeypatch, tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    key = real / "store.key"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    assert broad_access_problem(key) is None  # the control: the same file by its own path
    _junction(tmp_path / "mine", real)
    assert broad_access_problem(tmp_path / "mine" / "store.key") is None
    shared = tmp_path / "shared"
    shared.mkdir()
    _icacls(shared, "/grant", f"*{_USERS}:(DC)")
    _junction(shared / "theirs", real)
    problem = str(broad_access_problem(shared / "theirs" / "store.key"))
    assert "a folder holding or above a junction or link on its path can be changed" in problem
    assert str(tmp_path) not in problem  # a refusal names no path
    # The same delete right one folder further up is refused too: it could rename the holder.
    (shared / "sub").mkdir()
    _junction(shared / "sub" / "deeper", real)
    problem = str(broad_access_problem(shared / "sub" / "deeper" / "store.key"))
    assert "a folder holding or above a junction or link on its path can be changed" in problem


def judge_links_only_under(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    """Make the Windows host readers, which the link rule and the holder read both use, read the
    real access lists of ``root`` and what is under it, and read every folder above ``root`` as
    SYSTEM's alone, so a holder outside ``root`` always passes. A test host's own profile folders are not
    the test's to judge: one measured host grants an AppContainer capability full control of
    ``AppData``, which refuses every junction under the temporary directory. A no-op elsewhere."""
    if sys.platform != "win32":
        return
    monkeypatch.setattr(
        restricted_file, "windows_host_readers", lambda: _host_judging_only_under(root)
    )


def _junction(link: Path, target: Path) -> None:
    import subprocess

    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True
    )


@windows_only
def test_windows_a_key_through_a_junction_only_system_can_change_passes() -> None:
    """``C:\\Users\\All Users`` is a junction SYSTEM owns onto ``C:\\ProgramData``, which only
    SYSTEM and Administrators may change, so the folders above a key reached through it pass."""
    all_users = Path("C:/Users/All Users")
    if not os.path.lexists(all_users / "Microsoft"):
        pytest.skip("this host has no All Users junction onto a Microsoft folder")
    import messagefoundry.auth.anchor_path as anchor_path

    host = anchor_path.windows_host_readers()
    # A folder stands in for the key: the walk reads the folders above it, and the holder.
    assert restricted_file._windows_surroundings_problem(all_users / "Microsoft", host) is None


def _host_judging_only_under(root: Path, **changes: Any) -> Any:
    """This host's readers, reading every folder above ``root`` as SYSTEM's alone, as
    :func:`judge_links_only_under` does, with ``changes`` replacing fields."""
    import messagefoundry.auth.anchor_path as anchor_path

    host = anchor_path.windows_host_readers()
    inside = str(root).lower()
    clean = WinSecurity(_SYSTEM, ((_ALLOW, 0, _FULL, _SYSTEM),))

    def read_security(obj: str, kind: str) -> WinSecurity:
        if obj.lower() == inside or obj.lower().startswith(inside + "\\"):
            return host.read_security(obj, kind)
        return clean

    return dataclasses.replace(host, read_security=read_security, **changes)


@windows_only
def test_windows_a_junction_at_the_holder_is_judged_where_it_points(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #5657 step 1 (a): the holder rule read a junction standing in for the holder
    by its own access list, so a trusted junction onto a folder Users may delete files in passed.
    The holder is now read where the path resolves to."""
    judge_links_only_under(monkeypatch, tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    key = real / "store.key"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    _junction(tmp_path / "mine", real)
    assert broad_access_problem(tmp_path / "mine" / "store.key") is None  # the control
    _icacls(real, "/grant", f"*{_USERS}:(DC)")
    problem = str(broad_access_problem(tmp_path / "mine" / "store.key"))
    assert f"Users ({_USERS}) can delete or replace a file in it" in problem


@windows_only
@pytest.mark.parametrize("grant", ["(DC)", "(OI)(IO)(F)"])
def test_windows_a_junction_at_the_holder_is_also_judged_by_its_own_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grant: str
) -> None:
    """Before the holder was read where the path resolves to, a junction standing in for the holder
    was read by its own access list, with the holder rule, and one granting Users a replace right
    there was refused. Reading where the junction leads must not drop that read."""
    judge_links_only_under(monkeypatch, tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    write_restricted_file(real / "store.key", b"KEY-MATERIAL-STAND-IN")
    _junction(tmp_path / "mine", real)
    assert broad_access_problem(tmp_path / "mine" / "store.key") is None  # the control
    _icacls(tmp_path / "mine", "/L", "/grant", f"*{_USERS}:{grant}")  # the junction's own list
    assert broad_access_problem(real / "store.key") is None  # the target is unchanged
    from messagefoundry.config.wiring import _win32_config_source_probes

    holder = _win32_config_source_probes().read_path(tmp_path / "mine")
    problem = restricted_file._windows_access_problem(
        holder, restricted_file._HOLDER_REPLACE_MASK, reach=restricted_file._HOLDER_REACH
    )
    assert problem is not None  # the as-written reader and rule refuse the junction's list
    problem = str(broad_access_problem(tmp_path / "mine" / "store.key"))
    assert f"Users ({_USERS}) can delete or replace a file in it" in problem


@windows_only
@pytest.mark.parametrize("spelling", ["Q:\\store.key", "\\\\?\\Q:\\store.key"])
def test_windows_a_subst_root_onto_a_junction_is_also_judged_by_its_own_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str
) -> None:
    """The same junction's own list, reached as a ``subst`` drive root holding the key, however the
    path is spelled. The letter is a stand-in: the readers answer it as ``subst`` would, so no
    drive is defined on the host."""
    real = tmp_path / "real"
    real.mkdir()
    write_restricted_file(real / "store.key", b"KEY-MATERIAL-STAND-IN")
    _junction(tmp_path / "mine", real)
    target = "\\??\\" + str(tmp_path / "mine")
    host = _host_judging_only_under(
        tmp_path, drive_target=lambda d: target if d.upper() == "Q:" else None
    )
    _read_stand_in_letter_as_written(monkeypatch, tmp_path / "mine")
    surroundings = restricted_file._windows_surroundings_problem
    assert surroundings(Path(spelling), host) is None  # the control
    _icacls(tmp_path / "mine", "/L", "/grant", f"*{_USERS}:(DC)")  # the junction's own list
    problem = str(surroundings(Path(spelling), host))
    assert f"Users ({_USERS}) can delete or replace a file in it" in problem


def _read_stand_in_letter_as_written(monkeypatch: pytest.MonkeyPatch, folder: Path) -> None:
    """Make the as-written holder read answer the stand-in letter ``Q:`` as the folder it stands
    for, in any spelling of it, as Windows would for a real ``subst`` drive."""
    as_written = restricted_file._windows_holder_as_written_problem

    def read(holder_path: Path) -> str | None:
        text = str(holder_path)
        for head in ("\\\\?\\Q:", "\\\\.\\Q:", "Q:"):
            if text.upper().startswith(head):
                return as_written(Path(str(folder) + text[len(head) :]))
        return as_written(holder_path)

    monkeypatch.setattr(restricted_file, "_windows_holder_as_written_problem", read)


@windows_only
def test_windows_a_share_is_refused_when_this_hosts_name_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: a share this host cannot rule out may be itself. The walk stops at the share
    before any read, so no network is touched."""

    def unreadable() -> str:
        raise OSError(errno.EIO, "name lookup failed")

    monkeypatch.setattr(restricted_file, "_host_name", unreadable)
    host = _host_judging_only_under(tmp_path)
    problem = restricted_file._windows_surroundings_problem(
        Path("\\\\fileserver\\keys\\store.key"), host
    )
    assert problem is not None and "own name could not be read" in problem


@windows_only
def test_windows_a_path_resolving_to_a_volume_root_still_has_its_links_judged(
    tmp_path: Path,
) -> None:
    """A secrets directory named as a ``subst`` root that reaches a volume root through a junction:
    the walk returned before the link rule, so a junction Users could re-point passed. The letter
    is a stand-in, as in the test below. The junction onto the root is removed by ``os.rmdir``,
    which removes the link only, before anything else can walk it. The root is another drive's:
    one already on the path is refused for that instead (a folder already on the path)."""
    import string

    others = [
        f"{letter}:\\"
        for letter in string.ascii_uppercase
        if f"{letter}:" != tmp_path.drive.upper() and os.path.isdir(f"{letter}:\\")
    ]
    if not others:
        pytest.skip("this host has no second drive to point a junction at")
    shared = tmp_path / "shared"
    shared.mkdir()
    junction = shared / "j"
    _junction(junction, Path(others[0]))
    try:
        target = "\\??\\" + str(junction)
        host = _host_judging_only_under(
            tmp_path, drive_target=lambda d: target if d.upper() == "Q:" else None
        )
        assert restricted_file._windows_surroundings_problem(Path("Q:\\"), host) is None
        _icacls(shared, "/grant", f"*{_USERS}:(DC)")  # Users may delete and replace the junction
        problem = str(restricted_file._windows_surroundings_problem(Path("Q:\\"), host))
        assert "a folder holding or above a junction or link on its path can be changed" in problem
    finally:
        os.rmdir(junction)


@windows_only
def test_windows_a_junction_holding_a_key_on_a_share_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Read through a share, a junction holding the key was judged by its own access list, not by
    the folder it points at. The share is this host's administrative share, with the loopback
    refusal stood down so the share reads as another server's."""
    drive = tmp_path.drive.rstrip(":")
    root = f"\\\\localhost\\{drive}$"
    if not os.path.isdir(root):
        pytest.skip("this account cannot reach the host's administrative share")
    monkeypatch.setattr(restricted_file, "_loopback_share_problem", lambda *_args: None)
    real = tmp_path / "real"
    real.mkdir()
    write_restricted_file(real / "store.key", b"KEY-MATERIAL-STAND-IN")
    _junction(tmp_path / "j", real)
    host = _host_judging_only_under(tmp_path)
    via_share = Path(root + str(tmp_path)[2:])
    surroundings = restricted_file._windows_surroundings_problem
    assert surroundings(via_share / "real" / "store.key", host) is None  # the control
    problem = str(surroundings(via_share / "j" / "store.key", host))
    assert "the folder that holds it is a reparse point" in problem


@windows_only
def test_windows_a_subst_drive_on_the_path_gives_the_folders_above_no_link_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """origin/main judged no folder above a ``subst`` drive's target by the link rule, so a key
    through ``subst`` with a broad group's delete right above the holder passed there. The branch
    refused it; it passes again. The holder itself is still read where the drive leads. The letter
    is a stand-in: the readers answer it as ``subst`` would, so no drive is defined on the host."""
    top = tmp_path / "top"
    mid = top / "mid"
    secrets = mid / "secrets"
    secrets.mkdir(parents=True)
    write_restricted_file(secrets / "store.key", b"KEY-MATERIAL-STAND-IN")
    target = "\\??\\" + str(secrets)

    def drive_target(drive: str) -> str | None:
        return target if drive.upper() == "Q:" else None

    host = _host_judging_only_under(tmp_path, drive_target=drive_target)
    _read_stand_in_letter_as_written(monkeypatch, secrets)
    surroundings = restricted_file._windows_surroundings_problem
    assert surroundings(Path("Q:\\store.key"), host) is None  # the control
    _icacls(top, "/grant", f"*{_USERS}:(DC)")  # Users may rename mid away, from above the holder
    assert surroundings(Path("Q:\\store.key"), host) is None
    _icacls(mid, "/grant", f"*{_USERS}:(DC)")  # above the holder too
    assert surroundings(Path("Q:\\store.key"), host) is None
    _icacls(secrets, "/grant", f"*{_USERS}:(DC)")  # the holder, read where the drive leads
    problem = str(surroundings(Path("Q:\\store.key"), host))
    assert f"Users ({_USERS}) can delete or replace a file in it" in problem
    # A letter onto a share: neither the loopback test nor the holder read sees that share.
    onto_share = dataclasses.replace(
        host, drive_target=lambda d: "\\??\\UNC\\localhost\\c$" if d.upper() == "Q:" else None
    )
    problem = str(surroundings(Path("Q:\\keys\\store.key"), onto_share))
    assert "onto a network share" in problem


@windows_only
def test_windows_a_subst_root_secrets_directory_gets_no_link_rule_on_its_holder(
    tmp_path: Path,
) -> None:
    """A ``subst`` drive root named as the secrets directory: origin/main walked nothing for a
    drive root, so a single account that is not an administrator owning the folder that holds the
    target passed there. The branch judged that folder by the link rule and refused it; it passes
    again, by the holder rule alone."""
    mid = tmp_path / "mid"
    secrets = mid / "secrets"
    secrets.mkdir(parents=True)
    target = "\\??\\" + str(secrets)
    base = _host_judging_only_under(
        tmp_path, drive_target=lambda d: target if d.upper() == "Q:" else None
    )
    stranger = "S-1-5-21-1111111111-2222222222-3333333333-1001"

    def read_security(obj: str, kind: str) -> WinSecurity:
        if obj.lower() == str(mid).lower():
            return WinSecurity(stranger, ((_ALLOW, 0, _FULL, _SYSTEM),))
        return base.read_security(obj, kind)

    surroundings = restricted_file._windows_surroundings_problem
    assert surroundings(Path("Q:\\"), base) is None  # the control
    host = dataclasses.replace(base, read_security=read_security)
    assert surroundings(Path("Q:\\"), host) is None
    # The holder rule still reads that folder: a broad group's delete right there is refused.
    users = WinSecurity(stranger, ((_ALLOW, 0, 0x00000040, _USERS),))
    refusing = dataclasses.replace(
        base,
        read_security=lambda obj, kind: (
            users if obj.lower() == str(mid).lower() else base.read_security(obj, kind)
        ),
    )
    assert f"Users ({_USERS})" in str(surroundings(Path("Q:\\"), refusing))


def _real_win_probe() -> Any:
    """The real Windows probe, which ``restricted_file`` does not re-export."""
    import messagefoundry.auth.anchor_path as anchor_path

    return anchor_path._win_probe


def _probe_with_links(links: Mapping[str, str]) -> Any:
    """The real probe, answering each path in ``links`` (lower-cased) as a link to its value."""
    real = _real_win_probe()

    def probe(path: str) -> tuple[str, str | None]:
        if path.lower() in links:
            return LINK, links[path.lower()]
        return real(path)

    return probe


@windows_only
def test_windows_a_mapped_network_drive_is_read_as_a_share(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mapped drive was walked as a local volume, so a junction on the file server was spliced in
    as a path on this host and the holder read here: a locked-down local folder of the same name
    passed. The drive letter and the server's junction are stand-ins, so no drive is mapped."""
    secure = tmp_path / "secure"
    secure.mkdir()
    write_restricted_file(secure / "client.key", b"KEY-MATERIAL-STAND-IN")
    monkeypatch.setattr(
        restricted_file, "_is_remote_drive", lambda root: root.upper() == "Y:\\", raising=False
    )
    monkeypatch.setattr(restricted_file, "_win_probe", _probe_with_links({"y:\\keys": str(secure)}))
    monkeypatch.setattr(
        restricted_file, "_is_reparse_point", lambda path: path.lower() == "y:\\keys"
    )
    monkeypatch.setattr(restricted_file, "_mapped_drive_share", lambda _d: "\\\\fileserver\\keys")
    host = _host_judging_only_under(tmp_path, drive_target=lambda _d: None)
    surroundings = restricted_file._windows_surroundings_problem
    # The control: the local folder the server's junction names passes when named directly.
    assert surroundings(secure / "client.key", host) is None
    problem = str(surroundings(Path("Y:\\keys\\client.key"), host))
    assert "the folder that holds it is a reparse point" in problem


@windows_only
def test_windows_a_link_or_subst_drive_onto_a_mapped_drive_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A link or ``subst`` drive onto a mapped drive letter reaches a share, as one onto a UNC
    share does, and is refused the same way. The letters and the link are stand-ins."""
    secure = tmp_path / "secure"
    secure.mkdir()
    write_restricted_file(secure / "client.key", b"KEY-MATERIAL-STAND-IN")
    monkeypatch.setattr(
        restricted_file, "_is_remote_drive", lambda root: root.upper() == "Y:\\", raising=False
    )
    link = str(tmp_path / "lnk")
    monkeypatch.setattr(
        restricted_file, "_win_probe", _probe_with_links({link.lower(): "Y:\\real"})
    )
    host = _host_judging_only_under(
        tmp_path, drive_target=lambda d: "\\??\\Y:\\real" if d.upper() == "Q:" else None
    )
    surroundings = restricted_file._windows_surroundings_problem
    assert surroundings(secure / "client.key", host) is None  # the control
    for path in (Path(link) / "client.key", Path("Q:\\client.key")):
        problem = str(surroundings(path, host))
        assert "onto a network share or a mapped network drive" in problem, path


@windows_only
def test_windows_a_mapped_drive_onto_this_host_is_refused_as_a_loopback_share(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mapped drive letter names no server, so the loopback test passed one mapped onto this
    host. It is now judged through the share the drive is mapped to, and refused when that share
    cannot be read. The letter and its share are stand-ins, so no drive is mapped."""
    import messagefoundry.auth.anchor_path as anchor_path

    monkeypatch.setattr(
        restricted_file, "_is_remote_drive", lambda root: root.upper() == "Y:\\", raising=False
    )
    monkeypatch.setattr(restricted_file, "_host_name", lambda: "engine-host")
    real = _real_win_probe()
    monkeypatch.setattr(  # the mapped folders, as the local walk of the drive reads them
        restricted_file,
        "_win_probe",
        lambda path: (DIRECTORY, None) if path.lower().startswith("y:") else real(path),
    )
    host = anchor_path.windows_host_readers()
    surroundings = restricted_file._windows_surroundings_problem
    for share in ("\\\\localhost\\c$", "\\\\ENGINE-HOST\\keys"):
        monkeypatch.setattr(
            restricted_file, "_mapped_drive_share", lambda _d, s=share: s, raising=False
        )
        problem = str(surroundings(Path("Y:\\keys\\client.key"), host))
        assert "a network share that may be on this host itself" in problem, share

    def unreadable(_drive: str) -> str:
        raise OSError(errno.EIO, "no connection")

    monkeypatch.setattr(restricted_file, "_mapped_drive_share", unreadable, raising=False)
    problem = str(surroundings(Path("Y:\\keys\\client.key"), host))
    assert "mapped network drive whose share could not be read" in problem


@windows_only
def test_windows_a_drive_type_that_cannot_be_read_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ``OSError`` from the drive-type read escaped the walk, and with it
    ``broad_access_problem``. It now ends the walk with a cause, which is refused."""
    secure = tmp_path / "secure"
    secure.mkdir()
    key = secure / "store.key"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    host = _host_judging_only_under(tmp_path)
    surroundings = restricted_file._windows_surroundings_problem
    assert surroundings(key, host) is None  # the control

    def unreadable(_root: str) -> bool:
        raise OSError(errno.EIO, "drive type unreadable")

    monkeypatch.setattr(restricted_file, "_is_remote_drive", unreadable)
    problem = str(surroundings(key, host))
    assert "its drive type could not be read" in problem
    assert str(tmp_path) not in problem


@windows_only
def test_windows_an_unknown_drive_type_is_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    """``DRIVE_UNKNOWN`` and ``DRIVE_NO_ROOT_DIR`` are read as a drive type that cannot be read,
    so the walk refuses them as it refuses an ``OSError``. ``GetDriveTypeW`` is a stand-in."""
    import ctypes

    class _Kernel32:
        def __init__(self, answer: int) -> None:
            self.answer = answer

        def GetDriveTypeW(self, _root: str) -> int:  # noqa: N802 - the Win32 name
            return self.answer

    for answer in (0, 1):
        monkeypatch.setattr(ctypes, "WinDLL", lambda _name, a=answer: _Kernel32(a))
        with pytest.raises(OSError):
            restricted_file._is_remote_drive("Q:\\")
    monkeypatch.setattr(ctypes, "WinDLL", lambda _name: _Kernel32(4))
    assert restricted_file._is_remote_drive("Q:\\") is True
    monkeypatch.setattr(ctypes, "WinDLL", lambda _name: _Kernel32(3))
    assert restricted_file._is_remote_drive("Q:\\") is False


@windows_only
def test_windows_a_volume_the_host_cannot_judge_is_judged_as_before(tmp_path: Path) -> None:
    """The walk asked ``host.volume_cause``, which refuses a volume whose file system is neither
    NTFS nor ReFS, such as CSVFS or FAT, or cannot be read, so a key file on such a volume that the
    check passed before the walk was refused.
    Only the drive type is now read on the walk. The CSVFS volume is a stand-in."""
    secure = tmp_path / "secure"
    secure.mkdir()
    key = secure / "store.key"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    host = _host_judging_only_under(
        tmp_path,
        volume_cause=lambda _root: (
            "it is a CSVFS volume, whose permissions this check does not read"
        ),
    )
    assert restricted_file._windows_surroundings_problem(key, host) is None


@windows_only
def test_windows_a_junction_above_the_holder_on_a_mapped_drive_is_judged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """origin/main walked a mapped drive as a local volume, so a junction on it above the holder
    that another account can change was refused; the branch stopped at the share and passed it.
    The drive, the server's junction and its owner are stand-ins, so no drive is mapped."""
    secure = tmp_path / "secure"
    (secure / "inner").mkdir(parents=True)
    monkeypatch.setattr(restricted_file, "_is_remote_drive", lambda root: root.upper() == "Y:\\")
    monkeypatch.setattr(restricted_file, "_win_probe", _probe_with_links({"y:\\keys": str(secure)}))
    monkeypatch.setattr(restricted_file, "_is_reparse_point", lambda _path: False)
    monkeypatch.setattr(restricted_file, "_mapped_drive_share", lambda _d: "\\\\fileserver\\keys")
    monkeypatch.setattr(restricted_file, "_host_name", lambda: "engine-host")
    base = _host_judging_only_under(tmp_path, drive_target=lambda _d: None)
    stranger = "S-1-5-21-1111111111-2222222222-3333333333-1001"

    def read_security(obj: str, kind: str) -> WinSecurity:
        if obj.lower() == "y:\\keys":
            return WinSecurity(stranger, ((_ALLOW, 0, _FULL, _SYSTEM),))
        return base.read_security(obj, kind)

    surroundings = restricted_file._windows_surroundings_problem
    key = Path("Y:\\keys\\inner\\client.key")
    assert surroundings(key, base) is None  # the control
    problem = str(surroundings(key, dataclasses.replace(base, read_security=read_security)))
    assert "a junction or link on its path can be changed" in problem


@windows_only
def test_windows_the_key_files_own_name_is_not_walked(tmp_path: Path) -> None:
    """origin/main walked the folder holding the key file, not the file's own name, so a stream
    name passed there; the branch walked the name too and refused it as a path it could not
    walk."""
    holder = tmp_path / "holder"
    holder.mkdir()
    write_restricted_file(holder / "store.key", b"KEY-MATERIAL-STAND-IN")
    host = _host_judging_only_under(tmp_path)
    surroundings = restricted_file._windows_surroundings_problem
    for name in ("store.key", "store.key:alt", "store.key::$DATA", "store.key.", "store.key "):
        assert surroundings(holder / name, host) is None, name


@windows_only
def test_windows_a_link_back_to_a_folder_already_on_the_path_is_judged_as_before(
    tmp_path: Path,
) -> None:
    """origin/main read the holder of a path that resolves, through a junction, to a folder
    already on it, by its path as written; the branch refused every such path. A junction here
    needs no privilege, so this never skips."""
    folder = tmp_path / "a"
    inner = folder / "b"
    inner.mkdir(parents=True)
    write_restricted_file(folder / "store.key", b"KEY-MATERIAL-STAND-IN")
    loop = inner / "up"
    _junction(loop, folder)
    try:
        host = _host_judging_only_under(tmp_path)
        surroundings = restricted_file._windows_surroundings_problem
        assert surroundings(loop / "store.key", host) is None  # a key file
        assert surroundings(loop / "b", host) is None  # a directory, as a secrets directory is
    finally:
        os.rmdir(loop)


@windows_only
def test_windows_refuses_a_key_in_a_directory_users_may_delete_files_in(tmp_path: Path) -> None:
    holder = tmp_path / "holder"
    holder.mkdir()
    key = holder / "store.key"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    assert broad_access_problem(key) is None  # the control
    _icacls(holder, "/grant", f"*{_USERS}:(DC)")
    problem = str(broad_access_problem(key))
    assert "the directory that holds it is not restricted" in problem
    assert f"Users ({_USERS}) can delete or replace a file in it" in problem


@windows_only
def test_windows_a_key_in_a_directory_the_engine_makes_under_programdata_passes(
    tmp_path: Path,
) -> None:
    """A default install keeps its data under ``C:\\ProgramData``, and the engine makes its store
    directory there with no access list of its own, so it inherits the folder's. A key the engine
    mints in it must pass. The folder stands in for ``C:\\ProgramData``, with its list, plus this
    account, which an unelevated test run needs to reach it."""
    from messagefoundry.config.wiring import _win32_config_source_probes

    me = _win32_config_source_probes().self_sid
    assert me is not None
    data = tmp_path / "ProgramData"
    data.mkdir()
    _icacls(
        data,
        "/inheritance:r",
        "/grant:r",
        f"*{_SYSTEM}:(OI)(CI)F",
        f"*{_ADMINS}:(OI)(CI)F",
        "*S-1-3-0:(OI)(CI)(IO)F",
        f"*{_USERS}:(OI)(CI)RX",
        f"*{me}:(OI)(CI)F",
    )
    _icacls(data, "/grant", f"*{_USERS}:(CI)(WD,AD,WEA,WA)")
    state = data / "MessageFoundry"
    state.mkdir()  # as the engine makes its store directory on Windows: no mode, so it inherits
    key = state / "api.key"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    assert broad_access_problem(key) is None
    # The control: a folder that hands its new folders a broad delete right is refused.
    _icacls(data, "/grant", f"*{_USERS}:(CI)(DC)")
    widened = data / "Widened"
    widened.mkdir()
    write_restricted_file(widened / "api.key", b"KEY-MATERIAL-STAND-IN")
    assert "can delete or replace a file in it" in str(broad_access_problem(widened / "api.key"))


# --- the POSIX arm, for real ----------------------------------------------------------------------


@posix_only
def test_posix_creates_the_file_owner_only_whatever_the_umask(tmp_path: Path) -> None:
    path = tmp_path / "store.key"
    previous = os.umask(0)  # the most permissive umask: the mode must come from the create
    try:
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN")
        plain = tmp_path / "plain.bin"
        plain.write_bytes(b"x")
    finally:
        os.umask(previous)
    assert path.read_bytes() == b"KEY-MATERIAL-STAND-IN"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert broad_access_problem(path) is None
    # The control: the ordinary create under the same umask is readable by everyone.
    assert stat.S_IMODE(plain.stat().st_mode) & 0o044
    assert broad_access_problem(plain) is not None


@posix_only
def test_posix_raises_and_leaves_nothing_when_the_mode_does_not_read_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A filesystem that ignores modes reports something broader than was asked for.
    path = tmp_path / "store.key"
    real_open, real_fstat, real_close = os.open, os.fstat, os.close
    created: set[int] = set()
    forged: list[int] = []

    # Forward the call untouched rather than re-declare os.open's signature: a copied default
    # mode can drift from os.open's own, and CodeQL flags a hand-written 0o777.
    def opening(*args: Any, **kwargs: Any) -> int:
        fd = real_open(*args, **kwargs)
        if os.fspath(kwargs["path"] if "path" in kwargs else args[0]) == os.fspath(path):
            created.add(fd)
        return fd

    def closing(fd: int) -> None:
        created.discard(fd)  # a later descriptor that reuses the number reads back as it is
        real_close(fd)

    # Only the descriptor of the file under test reads back broad. Every other one is the real
    # status, because other code calls os.fstat while the patch is in place: pytest 9.2's capture
    # reads st_size from it.
    def broad(fd: int) -> os.stat_result:
        result = real_fstat(fd)
        if fd not in created:
            return result
        forged.append(fd)
        # __reduce__ carries the fields the sequence leaves out (st_mtime_ns and the rest).
        reduced: Any = result.__reduce__()
        fields, extras = reduced[1]
        return os.stat_result((stat.S_IFREG | 0o644, *fields[1:]), extras)

    monkeypatch.setattr(os, "open", opening)
    monkeypatch.setattr(os, "fstat", broad)
    monkeypatch.setattr(os, "close", closing)
    with pytest.raises(RestrictedFileError, match="mode 0644"):
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN")
    assert forged  # control: the refusal read the forged status
    assert not path.exists()


@posix_only
def test_posix_raises_restricted_and_leaves_nothing_when_the_mode_cannot_be_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # vfat and exFAT keep no modes and refuse the chmod with a plain OSError.
    def refusing(fd: int, mode: int) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "fchmod", refusing)
    path = tmp_path / "store.key"
    with pytest.raises(RestrictedFileError, match="mode could not be set"):
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN")
    assert not path.exists()


@posix_only
def test_posix_refuses_a_read_grant_it_cannot_honour(tmp_path: Path) -> None:
    path = tmp_path / "store.key"
    with pytest.raises(RestrictedFileError, match="Windows only"):
        write_restricted_file(path, b"k", read_grants=["someone"])
    assert not path.exists()
    with pytest.raises(RestrictedFileError, match="Windows only"):
        write_restricted_file(path, b"k", creator_access=False)
    assert not path.exists()
    with pytest.raises(RestrictedFileError, match="Windows only"):
        write_restricted_file(path, b"k", owner=_ADMINS)
    assert not path.exists()
    with pytest.raises(RestrictedFileError, match="Windows only"):
        write_restricted_file(path, b"k", read_delete=True)
    assert not path.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="the file system is checked on Linux only")
@pytest.mark.parametrize("magic", [0x6969, 0x794C7630, _TMPFS])
def test_linux_a_key_custody_file_off_a_local_disk_is_refused_before_a_byte_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, magic: int
) -> None:
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        here = restricted_file.linux_file_system_type(fd)
    finally:
        os.close(fd)
    if here not in restricted_file.LINUX_HOST_FILE_SYSTEMS:  # a /tmp on tmpfs, at least
        pytest.skip(f"the temporary directory is on file system type {here:#010x}")
    control = tmp_path / "control.key"
    write_restricted_file(control, b"k", local_volume_only=True)  # the control: the real disk
    assert control.read_bytes() == b"k"
    sizes: list[int] = []

    def _fstatfs(fd: int) -> int:
        sizes.append(os.fstat(fd).st_size)  # what the file held when its file system was judged
        return magic

    monkeypatch.setattr(restricted_file, "linux_file_system_type", _fstatfs)
    path = tmp_path / "store.key"
    with pytest.raises(RestrictedFileError, match=f"type {magic:#010x}"):
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN", local_volume_only=True)
    assert sizes == [0] and not path.exists()
    # Off by default: the other key writers, the TLS key's included, are not checked.
    write_restricted_file(tmp_path / "tls.key", b"k")
    assert sizes == [0]


# --- both platforms, for real ---------------------------------------------------------------------


def test_an_existing_file_is_not_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "store.key"
    path.write_bytes(b"THE-OPERATORS-FILE")
    with pytest.raises(FileExistsError):
        write_restricted_file(path, b"REPLACEMENT")
    assert path.read_bytes() == b"THE-OPERATORS-FILE"


def test_a_name_that_is_a_link_is_refused_and_nothing_is_created_behind_it(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    link = tmp_path / "store.key"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("this account may not create a symbolic link")
    with pytest.raises(FileExistsError):
        write_restricted_file(link, b"KEY-MATERIAL-STAND-IN")
    assert not target.exists()


@posix_only
def test_posix_refuses_a_restricted_key_reached_through_a_link(tmp_path: Path) -> None:
    """Vault BACKLOG #5636: the check followed the link and judged the file behind it."""
    key = tmp_path / "real.key"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    assert broad_access_problem(key) is None  # the control: the file itself passes
    link = tmp_path / "linked.key"
    os.symlink(key, link)
    assert "it is a link" in str(broad_access_problem(link))


@posix_only
def test_posix_refuses_a_restricted_key_in_a_directory_others_may_write(tmp_path: Path) -> None:
    holder = tmp_path / "holder"
    holder.mkdir(mode=0o700)
    key = holder / "store.key"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    assert broad_access_problem(key) is None  # the control
    holder.chmod(0o777)
    assert "with no sticky bit" in str(broad_access_problem(key))
    holder.chmod(0o1777)  # the sticky bit keeps others from deleting or renaming the file
    assert broad_access_problem(key) is None
    holder.chmod(0o770)
    assert "has mode 0770" in str(broad_access_problem(key))


@posix_only
def test_posix_refuses_a_restricted_key_another_account_owns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another account is stood in for by the engine's: no test may chown a file away."""
    real = os.geteuid()
    if real == 0:
        pytest.skip("root is an allowed owner, so a root-owned stand-in proves nothing")
    key = tmp_path / "store.key"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    assert broad_access_problem(key) is None  # the control: the engine's own account owns it
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    assert f"owned by uid {real}" in str(broad_access_problem(key))


@posix_only
def test_posix_refuses_a_key_whose_directory_cannot_be_examined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "store.key"
    write_restricted_file(key, b"KEY-MATERIAL-STAND-IN")
    assert broad_access_problem(key) is None  # the control
    real_stat = os.stat

    def refuse_the_holder(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if Path(path) == tmp_path:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", refuse_the_holder)
    assert "the directory that holds it could not be examined" in str(broad_access_problem(key))


@posix_only
def test_posix_refuses_a_restricted_key_beneath_a_linked_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #5656: only the last part of the path was read without following a link, so a
    linked folder above it was followed whoever could re-point it. A link in a folder a group or
    other may write is refused now; the engine's own link in its own folder passes."""
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    write_restricted_file(real / "store.key", b"KEY-MATERIAL-STAND-IN")
    assert broad_access_problem(real / "store.key") is None  # the control
    (tmp_path / "mine").symlink_to(real, target_is_directory=True)
    assert broad_access_problem(tmp_path / "mine" / "store.key") is None
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)  # whatever the umask: any account may re-point a link in it
    (shared / "theirs").symlink_to(real, target_is_directory=True)
    link = "a folder holding or above a junction or link on its path can be changed"
    assert link in str(broad_access_problem(shared / "theirs" / "store.key"))
    # ``..`` after a link leads where the link's target says, so it is not collapsed away.
    assert link in str(broad_access_problem(shared / "theirs" / ".." / "real" / "store.key"))
    # A relative path is walked from the working directory.
    monkeypatch.chdir(tmp_path)
    assert link in str(broad_access_problem(Path("shared") / "theirs" / "store.key"))
    assert broad_access_problem(Path("mine") / "store.key") is None
    # A folder others may write one level further up is refused too: it could rename the holder.
    (shared / "sub").mkdir(mode=0o700)
    (shared / "sub" / "deeper").symlink_to(real, target_is_directory=True)
    assert link in str(broad_access_problem(shared / "sub" / "deeper" / "store.key"))


def test_a_missing_file_is_a_read_problem_not_a_pass(tmp_path: Path) -> None:
    assert "could not be examined" in str(broad_access_problem(tmp_path / "absent.key"))


# --- the seam the writers share -------------------------------------------------------------------


def _refuse_the_create(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the restricted create fail the way a host that cannot apply the access list would."""

    def _refuse(path: Path, _grants: object, **_k: object) -> int:
        raise RestrictedFileError(f"{path} could not be created restricted: stand-in refusal")

    monkeypatch.setattr(restricted_file, "_create_restricted", _refuse)


def _allow_the_create(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The control for :func:`_refuse_the_create`: the same seam, succeeding, on any platform."""
    seen: dict[str, Any] = {}

    def _create(path: Path, grants: object, **_k: object) -> int:
        seen["grants"] = list(grants)  # type: ignore[call-overload]
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0))

    monkeypatch.setattr(restricted_file, "_create_restricted", _create)
    return seen


def _stub_dpapi(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for CryptProtectData, so the writers can be driven on every platform."""
    monkeypatch.setattr(dpapi_mod, "dpapi_protect", lambda secret, **_k: b"BLOB:" + secret)


def _secure_file_must_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def _never(path: Path, **_kw: object) -> None:
        raise AssertionError(f"a key file reached the best-effort _secure_file: {path}")

    monkeypatch.setattr(store_mod, "_secure_file", _never)


def test_the_tls_private_key_is_written_through_the_restricted_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _secure_file_must_not_run(monkeypatch)
    key_path = tmp_path / "key.pem"
    _write_private_key(key_path, b"KEY-MATERIAL-STAND-IN\n")  # the control: the real create works
    assert key_path.read_bytes() == b"KEY-MATERIAL-STAND-IN\n"
    assert broad_access_problem(key_path) is None

    # A refused create reaches the caller as it is: nothing downgrades it to a logged warning.
    _refuse_the_create(monkeypatch)
    with pytest.raises(RestrictedFileError):
        _write_private_key(tmp_path / "refused.pem", b"KEY-MATERIAL-STAND-IN\n")


def test_the_protected_store_key_is_written_through_the_restricted_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_dpapi(monkeypatch)
    _secure_file_must_not_run(monkeypatch)
    seen = _allow_the_create(monkeypatch)
    out = tmp_path / "store.key.dpapi"
    dpapi_mod.protect_key_to_file("QUJD", out, machine_scope=True, read_grants=["*S-1-5-18"])
    assert out.read_bytes() == b"BLOB:QUJD"
    assert seen["grants"] == ["*S-1-5-18"]

    # An existing file is refused and left as it was, where the old write replaced it.
    with pytest.raises(FileExistsError):
        dpapi_mod.protect_key_to_file("WFla", out, machine_scope=True)
    assert out.read_bytes() == b"BLOB:QUJD"

    _refuse_the_create(monkeypatch)
    with pytest.raises(RestrictedFileError):
        dpapi_mod.protect_key_to_file("QUJD", tmp_path / "refused.dpapi", machine_scope=True)


# --- protect-key ----------------------------------------------------------------------------------


def _protect_key(tmp_path: Path, *extra: str) -> tuple[int, Path]:
    out = tmp_path / "store.key.dpapi"
    return main(["protect-key", "--out", str(out), "--generate", *extra]), out


def test_protect_key_succeeds_when_the_file_is_created_restricted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The control for the two failures below, through the same seam.
    _stub_dpapi(monkeypatch)
    _secure_file_must_not_run(monkeypatch)
    seen = _allow_the_create(monkeypatch)
    rc, out = _protect_key(tmp_path, "--grant-account", "NT SERVICE\\MessageFoundry")
    captured = capsys.readouterr()
    assert rc == 0
    assert "Wrote" in captured.out
    assert "Generated a new store key" in captured.err
    assert out.read_bytes().startswith(b"BLOB:")
    assert seen["grants"] == ["NT SERVICE\\MessageFoundry"]


def test_protect_key_fails_and_says_so_when_the_file_cannot_be_created_restricted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_dpapi(monkeypatch)
    _refuse_the_create(monkeypatch)
    rc, out = _protect_key(tmp_path)
    captured = capsys.readouterr()
    assert rc != 0
    assert "Wrote" not in captured.out and "Wrote" not in captured.err
    assert "could not be created restricted" in captured.err
    assert "No key file was written" in captured.err
    # A key that protects nothing is not printed either: there is no file for it to open.
    assert "Generated a new store key" not in captured.err
    assert not out.exists()


def test_protect_key_refuses_to_replace_an_existing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_dpapi(monkeypatch)
    _allow_the_create(monkeypatch)
    out = tmp_path / "store.key.dpapi"
    out.write_bytes(b"THE-KEY-IN-USE")
    rc, _out = _protect_key(tmp_path)
    captured = capsys.readouterr()
    assert rc != 0
    assert "refusing to overwrite" in captured.err
    assert "Wrote" not in captured.out
    assert out.read_bytes() == b"THE-KEY-IN-USE"


@windows_only
def test_protect_key_for_real_writes_a_restricted_file_that_unprotects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _secure_file_must_not_run(monkeypatch)
    rc, out = _protect_key(tmp_path)
    captured = capsys.readouterr()
    assert rc == 0 and "Wrote" in captured.out
    key = dpapi_mod.load_protected_key(out)
    assert key in captured.err  # the one-time offline copy is the key the file holds
    protected, entries, creator = _windows_access(out)
    assert protected and creator is not None
    assert entries == {(_ALLOW, _FULL, _SYSTEM), (_ALLOW, _FULL, _ADMINS), (_ALLOW, _FULL, creator)}


# --- the check when `serve` is about to use a key file --------------------------------------------


def _broaden(path: Path) -> None:
    """Let accounts beyond the owner read ``path``, the way a broad directory would."""
    if sys.platform == "win32":
        _grant_users_read(path)
    else:
        path.chmod(0o644)


def _serve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str) -> int:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"])


@pytest.mark.parametrize(("platform", "mode"), [("linux", 0o755), ("win32", None)])
def test_the_engine_asks_for_a_state_dir_no_one_else_may_write_on_posix_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, mode: int | None
) -> None:
    """The seam, on every platform (vault BACKLOG #5636). POSIX asks for 0755: no group or other
    write bit, and still readable, so a client running as another account can read the pinned
    certificate. Windows passes no mode, so the directory inherits its parent's access list. The
    real create runs without a mode."""
    from messagefoundry.api import tls as tls_mod

    seen: list[object] = []
    real_mkdir = Path.mkdir

    def record(self: Path, *args: Any, **kwargs: Any) -> None:
        seen.append(kwargs.pop("mode", args[0] if args else None))
        real_mkdir(self, **kwargs)

    monkeypatch.setattr(Path, "mkdir", record)
    monkeypatch.setattr(sys, "platform", platform)
    tls_mod._make_state_dir(tmp_path / "store")
    monkeypatch.undo()
    assert seen == [mode] and (tmp_path / "store").is_dir()


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_the_generated_key_remedy_names_the_store_dir_with_commands_on_posix_only(
    monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    """The store directory is judged on every platform (vault BACKLOG #5636, #5657), so each remedy
    names it. The chmod and chown are POSIX commands, so they are printed there alone, with the
    paths shell-quoted so they can be pasted as printed.
    A mode cause gets chmod go-w, an owner cause gets chown to the engine's account, and moving the
    store, which would start a new, empty one, is not offered."""
    import messagefoundry.__main__ as cli

    monkeypatch.setattr(cli, "_engine_account_name", lambda: "mefor svc")
    monkeypatch.setattr(sys, "platform", platform)
    remedy = cli._generated_tls_key_remedy(Path("/srv/mefor data"))
    assert "[store].path" not in remedy
    # An owner refusal (vault BACKLOG #5657) is fixed by a new pair, not by a narrower access list.
    assert "who owns the key itself, rather than the directory that holds it, delete it" in remedy
    if platform == "win32":
        assert "chmod" not in remedy and "chown" not in remedy
        # The Windows check judges the store directory too (vault BACKLOG #5657).
        assert "the store's directory" in remedy and "junction" in remedy
    else:
        # The space makes shlex quote the whole path; Path spells the separators per host.
        quoted = f"'{Path('/srv/mefor data')}'"
        assert f"names the directory's mode, remove the write bits: chmod go-w {quoted}" in remedy
        assert "names the directory's owner" in remedy
        assert f"chown 'mefor svc' {quoted}" in remedy
        assert "names a link on its path" in remedy  # vault BACKLOG #5656


def _write_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str) -> None:
    """The settings file in ``tmp_path``, whose folder the start-path guard requires owner-only,
    and the stubs ``serve`` needs. Written before any umask a test sets, so the file is not
    group-writable."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)


def _serve_store(store_dir: Path) -> int:
    """``serve`` with its store in ``store_dir``, after :func:`_write_settings`."""
    argv = ["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]
    return main([*argv, "--db", str(store_dir / "messagefoundry.db")])


@posix_only
def test_serve_under_umask_002_makes_a_store_dir_no_group_may_write_and_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Vault BACKLOG #5636. A store directory the engine creates itself has no group or other
    write bit, so the key-file check passes the key it mints there, under umask 002 as under any
    other."""
    from messagefoundry.api.tls import _generated_pair

    store_dir = tmp_path / "store"
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    _write_settings(tmp_path, monkeypatch, PHI_GATE_PROVISIONS_TOML)
    old = os.umask(0o002)
    try:
        assert _serve_store(store_dir) == 0
    finally:
        os.umask(old)
    assert stat.S_IMODE(store_dir.stat().st_mode) == 0o755
    _cert, key = _generated_pair(store_dir)
    assert broad_access_problem(key) is None
    assert "is not restricted" not in capsys.readouterr().err


@posix_only
def test_serve_reports_an_existing_store_dir_a_group_may_write_by_enforcement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Vault BACKLOG #5636. A store directory that existed already keeps its mode, and the
    generated-key gate reports it: enforce refuses with exit 2, warn warns and starts. The remedy
    names the directory and the command."""
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    store_dir.chmod(0o775)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    _write_settings(tmp_path, monkeypatch, PHI_GATE_PROVISIONS_TOML)
    assert _serve_store(store_dir) == 2
    err = capsys.readouterr().err
    assert "the directory that holds it has mode 0775 with no sticky bit" in err
    assert f"chmod go-w {store_dir}" in err and "refusing to start" in err
    assert stat.S_IMODE(store_dir.stat().st_mode) == 0o775  # never changed by the engine

    warn = 'security.enforcement = "warn"\n' + PHI_GATE_PROVISIONS_TOML
    _write_settings(tmp_path, monkeypatch, warn)
    assert _serve_store(store_dir) == 0
    err = capsys.readouterr().err
    assert "warning: the generated TLS private key" in err and "mode 0775" in err


@pytest.mark.parametrize(("platform", "mode"), [("linux", 0o700), ("win32", None)])
def test_cert_commands_ask_for_an_owner_only_out_dir_on_posix_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, mode: int | None
) -> None:
    """The seam, on every platform: POSIX asks for 0700, Windows for no mode so the directory
    inherits its parent's access list. The real create runs without a mode, so no protected list
    is attached to this test's directory."""
    import messagefoundry.__main__ as cli

    seen: list[object] = []
    real_mkdir = Path.mkdir

    def record(self: Path, **kwargs: Any) -> None:
        seen.append(kwargs.pop("mode", None))
        real_mkdir(self, **kwargs)

    monkeypatch.setattr(Path, "mkdir", record)
    # The key write has its own per-platform arms, which the faked platform must not reach.
    monkeypatch.setattr(cli, "_write_private_key", lambda path, pem: path.write_bytes(pem))
    monkeypatch.setattr(sys, "platform", platform)
    out = tmp_path / "tls"
    assert cli._write_cert_files(out, out / "k.pem", b"KEY-STAND-IN\n", [], as_json=False) is None
    monkeypatch.undo()
    assert seen == [mode]


@posix_only
def test_cert_self_signed_makes_its_out_dir_owner_only_whatever_the_umask(tmp_path: Path) -> None:
    """Under umask 002 a plain mkdir gives 0775, and the key-file gate refuses the key the
    engine's own tool wrote there (vault BACKLOG #5636)."""
    out = tmp_path / "tls"
    old = os.umask(0o002)
    try:
        assert main(["cert", "self-signed", "--cn", "dev.local", "--out-dir", str(out)]) == 0
    finally:
        os.umask(old)
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    [key] = [p for p in out.iterdir() if "key" in p.name]
    assert broad_access_problem(key) is None


def test_serve_refuses_a_generated_tls_key_a_broad_account_can_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry.api.tls import _generated_pair

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    # The control: the pair the engine mints is restricted, so the same start succeeds.
    assert _serve(tmp_path, monkeypatch, PHI_GATE_PROVISIONS_TOML) == 0
    _cert, key = _generated_pair(tmp_path)
    assert key.exists()
    assert "is not restricted" not in capsys.readouterr().err

    _broaden(key)
    assert _serve(tmp_path, monkeypatch, PHI_GATE_PROVISIONS_TOML) == 2
    err = capsys.readouterr().err
    assert "error: the generated TLS private key" in err
    assert "is not restricted" in err and "refusing to start" in err

    # Under enforcement = warn the same finding is a warning and the engine starts.
    assert (
        _serve(tmp_path, monkeypatch, 'security.enforcement = "warn"\n' + PHI_GATE_PROVISIONS_TOML)
        == 0
    )
    err = capsys.readouterr().err
    assert "warning: the generated TLS private key" in err and "is not restricted" in err


@windows_only
def test_serve_refuses_a_generated_tls_pair_another_account_owns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pair planted in the store directory through a right to add a file to it is owned by the
    account that planted it, and the engine reuses a pair it finds, so ``serve`` refuses a generated
    pair the engine's own account, SYSTEM or Administrators does not own (vault BACKLOG #5657). The
    other account is stood in for by giving the engine another SID: no test may chown a file away."""
    from messagefoundry.api.tls import _generated_pair
    from messagefoundry.config.wiring import _win32_config_source_probes

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    assert _serve(tmp_path, monkeypatch, PHI_GATE_PROVISIONS_TOML) == 0  # the control
    _cert, key = _generated_pair(tmp_path)
    owner = _win32_config_source_probes().read_path(key).owner_sid
    if owner in (_SYSTEM, _ADMINS):
        pytest.skip("an elevated run mints the pair owned by Administrators, an allowed owner")
    capsys.readouterr()
    import messagefoundry.auth.anchor_path as anchor_path

    real_readers = anchor_path.windows_host_readers
    monkeypatch.setattr(
        restricted_file,
        "windows_host_readers",
        lambda: dataclasses.replace(real_readers(), engine_sid=_SERVICE),
    )
    assert _serve(tmp_path, monkeypatch, PHI_GATE_PROVISIONS_TOML) == 2
    err = capsys.readouterr().err
    assert "error: the generated TLS private key" in err and "the engine did not make it" in err


def test_serve_refuses_a_store_key_file_a_broad_account_can_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(dpapi_mod, "dpapi_available", lambda: True)
    key_file = tmp_path / "store.key.dpapi"
    toml = PHI_GATE_PROVISIONS_TOML + f'[store]\nencryption_key_file = "{key_file.as_posix()}"\n'

    # The control: a key file created restricted passes the check.
    write_restricted_file(key_file, b"BLOB-STAND-IN")
    assert _serve(tmp_path, monkeypatch, toml) == 0
    assert "is not restricted" not in capsys.readouterr().err

    _broaden(key_file)
    assert _serve(tmp_path, monkeypatch, toml) == 2
    err = capsys.readouterr().err
    assert "error: the store key file named by [store].encryption_key_file" in err
    assert "is not restricted" in err and "refusing to start" in err

    assert _serve(tmp_path, monkeypatch, 'security.enforcement = "warn"\n' + toml) == 0
    err = capsys.readouterr().err
    assert "warning: the store key file named by [store].encryption_key_file" in err


def test_serve_does_not_check_a_store_key_file_the_provider_will_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The environment key wins under the default provider, so the file is not this start's key.
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    key_file = tmp_path / "store.key.dpapi"
    key_file.write_bytes(b"BLOB-STAND-IN")
    _broaden(key_file)
    toml = PHI_GATE_PROVISIONS_TOML + f'[store]\nencryption_key_file = "{key_file.as_posix()}"\n'
    assert _serve(tmp_path, monkeypatch, toml) == 0
    assert "encryption_key_file is not restricted" not in capsys.readouterr().err


# --- which key file the provider loads, and the warning at the read -------------------------------


@pytest.mark.parametrize(
    ("provider", "env_key", "loads_the_file"),
    [
        ("auto", None, True),
        ("auto", "QUJD", False),  # the environment key wins, so the file is not loaded
        ("dpapi", "QUJD", True),  # pinned to the file whatever the environment holds
        ("env", None, False),
        ("vault", None, False),
    ],
)
def test_provider_key_file_is_the_file_the_provider_loads(
    provider: str, env_key: str | None, loads_the_file: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store.keyprovider import provider_key_file, resolve_key_provider

    settings = StoreSettings(
        key_provider=provider, encryption_key=env_key, encryption_key_file="k.dpapi"
    )
    assert provider_key_file(settings) == ("k.dpapi" if loads_the_file else None)
    assert provider_key_file(settings.model_copy(update={"encryption_key_file": None})) is None
    if provider == "vault":
        return  # an external provider needs its backend to resolve; it loads no local file
    # The same answer from the read side: the file is loaded exactly when it was named.
    loaded: list[object] = []

    def _load(path: object) -> str:
        loaded.append(path)
        return "KEY"

    monkeypatch.setattr(dpapi_mod, "load_protected_key", _load)
    resolve_key_provider(settings).active_key()
    assert loaded == (["k.dpapi"] if loads_the_file else [])


def test_reading_a_key_file_a_broad_account_can_read_is_warned_about(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    monkeypatch.setattr(dpapi_mod, "dpapi_unprotect", lambda blob: b"QUJD")
    monkeypatch.setattr(dpapi_mod, "_checked_key_files", set())
    restricted = tmp_path / "restricted.dpapi"
    write_restricted_file(restricted, b"BLOB")
    with caplog.at_level(logging.WARNING, logger=dpapi_mod.__name__):
        assert dpapi_mod.load_protected_key(restricted) == "QUJD"
    assert "is not restricted" not in caplog.text  # the control

    broad = tmp_path / "broad.dpapi"
    broad.write_bytes(b"BLOB")
    _broaden(broad)
    with caplog.at_level(logging.WARNING, logger=dpapi_mod.__name__):
        assert dpapi_mod.load_protected_key(broad) == "QUJD"  # warned, and still read
        assert dpapi_mod.load_protected_key(broad) == "QUJD"  # a DR backup pass reads it again
    assert caplog.text.count("[store].encryption_key_file is not restricted") == 1


# --- supervise makes the same checks once, before it spawns a shard -------------------------------


def _supervise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[int, list[str]]:
    """``supervise`` with the fleet stubbed out: its return code and the configs it would spawn."""
    import argparse

    from messagefoundry import __main__ as cli

    spawned: list[str] = []

    async def fake_supervise(config: str, **_kwargs: object) -> int:
        spawned.append(config)
        return 0

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", fake_supervise)
    monkeypatch.setattr(cli, "configure_logging", lambda *args, **kwargs: None)
    args = argparse.Namespace(
        config=str(SAMPLES_CONFIG),
        db=str(tmp_path / "mefor.db"),
        base_port=8765,
        env="dev",
        service_config=None,
        project_root=str(tmp_path),
    )
    # The supervisor runs serve's open-egress gate before it forwards (BACKLOG #2356).
    from tests._phi_gate_provisions import setenv_declared_egress

    setenv_declared_egress(monkeypatch)
    return cli._supervise(args), spawned


def test_supervise_refuses_a_broadly_readable_key_file_before_it_spawns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Each shard's ``serve`` would refuse, and the supervisor would only restart it. So the
    refusal belongs in ``supervise``, once, with nothing spawned."""
    from messagefoundry.api.tls import _generated_pair

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    # The control: a first run mints a restricted pair and the fleet starts.
    rc, spawned = _supervise(tmp_path, monkeypatch)
    assert (rc, len(spawned)) == (0, 1), capsys.readouterr().err
    _cert, key = _generated_pair(tmp_path)
    assert key.exists()

    _broaden(key)
    rc, spawned = _supervise(tmp_path, monkeypatch)
    err = capsys.readouterr().err
    assert rc == 2 and spawned == []
    assert "error: the generated TLS private key" in err and "is not restricted" in err

    monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    rc, spawned = _supervise(tmp_path, monkeypatch)
    assert (rc, len(spawned)) == (0, 1)
    assert "warning: the generated TLS private key" in capsys.readouterr().err


def test_supervise_refuses_a_broadly_readable_store_key_file_before_it_opens_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(dpapi_mod, "dpapi_available", lambda: True)
    key_file = tmp_path / "store.key.dpapi"
    key_file.write_bytes(b"BLOB-STAND-IN")
    _broaden(key_file)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY_FILE", str(key_file))
    rc, spawned = _supervise(tmp_path, monkeypatch)
    err = capsys.readouterr().err
    assert rc == 2 and spawned == []
    assert "error: the store key file named by [store].encryption_key_file" in err
    assert not (tmp_path / "mefor.db").exists(), "the store was opened before the refusal"


def test_serve_exits_cleanly_when_the_tls_key_cannot_be_created_restricted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A host that cannot apply the restriction has no pair to fall back on at a first run. That is
    # a refusal with a reason and exit 2, as protect-key gives, not a traceback.
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    _refuse_the_create(monkeypatch)
    assert _serve(tmp_path, monkeypatch, PHI_GATE_PROVISIONS_TOML) == 2
    err = capsys.readouterr().err
    assert "could not be created restricted" in err and "refusing to start" in err


def test_the_store_key_file_check_is_left_to_the_provider_where_dpapi_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Off Windows the file cannot be used at all, and the key provider says so at store open. A
    # refusal about its access, with a Windows remedy, would hide that fault.
    from messagefoundry import __main__ as cli
    from messagefoundry.config.settings import load_settings

    key_file = tmp_path / "store.key.dpapi"
    key_file.write_bytes(b"BLOB-STAND-IN")
    _broaden(key_file)
    settings = load_settings(environ={"MEFOR_STORE_ENCRYPTION_KEY_FILE": str(key_file)})
    monkeypatch.setattr(dpapi_mod, "dpapi_available", lambda: False)
    assert cli._store_key_file_gate(settings, enforcing=True) is True
    assert capsys.readouterr().err == ""
    monkeypatch.setattr(dpapi_mod, "dpapi_available", lambda: True)  # the control
    assert cli._store_key_file_gate(settings, enforcing=True) is False


def test_the_store_key_file_gate_judges_a_dangling_link_rather_than_skipping_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Vault BACKLOG #5657 step 10 (g): the gate skipped a path ``Path.exists()`` denied, and that
    follows a link, so a link to a missing file was never judged. It is refused as a link now."""
    from messagefoundry import __main__ as cli
    from messagefoundry.config.settings import load_settings

    link = tmp_path / "store.key.dpapi"
    try:
        os.symlink(tmp_path / "missing.dpapi", link)
    except OSError as exc:  # Windows without the symbolic-link privilege
        pytest.skip(f"no symbolic link could be made here ({exc.strerror})")
    settings = load_settings(environ={"MEFOR_STORE_ENCRYPTION_KEY_FILE": str(link)})
    monkeypatch.setattr(dpapi_mod, "dpapi_available", lambda: True)
    assert cli._store_key_file_gate(settings, enforcing=True) is False
    assert "is a link" in capsys.readouterr().err
    link.unlink()  # the control: a name nothing is at is still left to the key provider
    assert cli._store_key_file_gate(settings, enforcing=True) is True


def test_supervise_exits_cleanly_when_the_tls_key_cannot_be_created_restricted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    _refuse_the_create(monkeypatch)
    rc, spawned = _supervise(tmp_path, monkeypatch)
    err = capsys.readouterr().err
    assert rc == 2 and spawned == []
    assert "could not be created restricted" in err and "refusing to start the fleet" in err
