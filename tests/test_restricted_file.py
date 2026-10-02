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

import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.restricted_file as restricted_file
import messagefoundry.secrets_dpapi as dpapi_mod
import messagefoundry.store.store as store_mod
from messagefoundry.__main__ import _write_private_key, main
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


def test_a_created_file_must_read_back_exactly_as_asked() -> None:
    expected = restricted_file._expected_access(_CREATOR, [_SERVICE])
    exact = _security(
        (_ALLOW, _FULL, _SYSTEM),
        (_ALLOW, _FULL, _ADMINS),
        (_ALLOW, _FULL, _CREATOR),
        (_ALLOW, _READ, _SERVICE),
    )
    assert restricted_file._created_mismatch(exact, True, expected) is None  # the control

    one_more = _security(*(exact.aces or ()), (_ALLOW, _READ, _USERS))
    assert "not the one that was asked for" in str(
        restricted_file._created_mismatch(one_more, True, expected)
    )
    widened = _security(
        (_ALLOW, _FULL, _SYSTEM),
        (_ALLOW, _FULL, _ADMINS),
        (_ALLOW, _FULL, _CREATOR),
        (_ALLOW, _FULL, _SERVICE),
    )
    assert restricted_file._created_mismatch(widened, True, expected) is not None
    assert "does not block inheritance" in str(
        restricted_file._created_mismatch(exact, False, expected)
    )
    # A read-back that did not finish is a mismatch, never a pass.
    assert restricted_file._created_mismatch(exact, None, expected) is not None
    assert restricted_file._created_mismatch(_WinPathSecurity(status=5), True, expected) is not None
    assert (
        restricted_file._created_mismatch(_WinPathSecurity(dacl_present=False), True, expected)
        is not None
    )
    assert (
        restricted_file._created_mismatch(_WinPathSecurity(owner_sid=_CREATOR), True, expected)
        is not None
    )


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


def test_the_posix_check_is_the_group_and_other_read_and_write_bits() -> None:
    assert restricted_file._posix_access_problem(stat.S_IFREG | 0o600) is None  # the control
    assert restricted_file._posix_access_problem(stat.S_IFREG | 0o400) is None
    assert "0640" in str(restricted_file._posix_access_problem(stat.S_IFREG | 0o640))
    assert "0604" in str(restricted_file._posix_access_problem(stat.S_IFREG | 0o604))
    assert "0620" in str(restricted_file._posix_access_problem(stat.S_IFREG | 0o620))
    assert "0602" in str(restricted_file._posix_access_problem(stat.S_IFREG | 0o602))
    # An execute bit alone gives nobody the key and lets nobody replace it.
    assert restricted_file._posix_access_problem(stat.S_IFREG | 0o711) is None


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
    with pytest.raises(RestrictedFileError, match="not one account"):
        write_restricted_file(tmp_path / "store.key", b"k", read_grants=[name])
    assert list(tmp_path.iterdir()) == []


@windows_only
@pytest.mark.parametrize("grant", [f"*{_USERS}", "*S-1-1-0", "*S-1-5-11", "*S-1-5-15"])
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

    def _disagree(*_a: object) -> str:
        seen["existed"] = path.exists()
        return "stand-in mismatch"

    monkeypatch.setattr(restricted_file, "_created_mismatch", _disagree)
    with pytest.raises(RestrictedFileError, match="stand-in mismatch"):
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN")
    assert seen == {"existed": True}
    assert list(tmp_path.iterdir()) == []


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
    real_fstat = os.fstat

    class _Broad:
        def __init__(self, real: os.stat_result) -> None:
            self.st_mode = stat.S_IFREG | 0o644
            self.st_uid = real.st_uid

    monkeypatch.setattr(os, "fstat", lambda fd: _Broad(real_fstat(fd)))
    with pytest.raises(RestrictedFileError, match="owner alone"):
        write_restricted_file(path, b"KEY-MATERIAL-STAND-IN")
    assert not path.exists()


@posix_only
def test_posix_refuses_a_read_grant_it_cannot_honour(tmp_path: Path) -> None:
    path = tmp_path / "store.key"
    with pytest.raises(RestrictedFileError, match="Windows only"):
        write_restricted_file(path, b"k", read_grants=["someone"])
    assert not path.exists()


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


def test_a_missing_file_is_a_read_problem_not_a_pass(tmp_path: Path) -> None:
    assert "could not be examined" in str(broad_access_problem(tmp_path / "absent.key"))


# --- the seam the writers share -------------------------------------------------------------------


def _refuse_the_create(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the restricted create fail the way a host that cannot apply the access list would."""

    def _refuse(path: Path, _grants: object) -> int:
        raise RestrictedFileError(f"{path} could not be created restricted: stand-in refusal")

    monkeypatch.setattr(restricted_file, "_create_restricted", _refuse)


def _allow_the_create(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The control for :func:`_refuse_the_create`: the same seam, succeeding, on any platform."""
    seen: dict[str, Any] = {}

    def _create(path: Path, grants: object) -> int:
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
    dpapi_mod.protect_key_to_file("QUJD", out, read_grants=["*S-1-5-18"])
    assert out.read_bytes() == b"BLOB:QUJD"
    assert seen["grants"] == ["*S-1-5-18"]

    # An existing file is refused and left as it was, where the old write replaced it.
    with pytest.raises(FileExistsError):
        dpapi_mod.protect_key_to_file("WFla", out)
    assert out.read_bytes() == b"BLOB:QUJD"

    _refuse_the_create(monkeypatch)
    with pytest.raises(RestrictedFileError):
        dpapi_mod.protect_key_to_file("QUJD", tmp_path / "refused.dpapi")


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


def test_supervise_exits_cleanly_when_the_tls_key_cannot_be_created_restricted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    _refuse_the_create(monkeypatch)
    rc, spawned = _supervise(tmp_path, monkeypatch)
    err = capsys.readouterr().err
    assert rc == 2 and spawned == []
    assert "could not be created restricted" in err and "refusing to start the fleet" in err
