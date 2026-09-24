# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SQLite store trio's DACL when the data directory is hardened (ADR 0183 Wave 0b, ADR 0163).

ADR 0183 Wave 0 measured, on hosted windows-2022 and windows-2025 (CI run 36026471545), that the
old re-secure made whichever identity opened a fresh store first its ONLY principal: the operator
running ``provision-admin`` locked the NSSM service account out, and the service locked the operator
out. The fix: when the store's directory is HARDENED (inheritance removed, and every entry names
SYSTEM, BUILTIN\\Administrators or one per-service virtual account), the trio inherits exactly what
that directory grants instead of being rewritten to the opener alone. Anywhere else the old
owner-only restriction is unchanged.

Three tiers, each saying what it can and cannot show:

* The SDDL decision is pure and runs on every platform.
* The Windows tests run the real ``icacls`` against a real directory and skip off Windows, because
  the mechanism is a Windows DACL. They read the result back as SDDL, so the reading does not depend
  on the display language. Once a file inherits a hardened directory, its non-elevated owner holds
  only the implicit READ_CONTROL and WRITE_DAC, and ``icacls`` asks for more than that (measured:
  exit 5, "Access is denied"). So those reads use ``_read_dacl_sddl``, which asks for the DACL alone,
  and a separate test checks that reader against ``icacls /save`` where both can read.
* One test needs an ELEVATED token, because it drives ``MessageStore.open`` inside a directory only
  SYSTEM, Administrators and a service account may write. It skips when not elevated; the hosted
  ``windows-service-smoke`` store-access arms cover the same ground as the real service account.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import messagefoundry.store.store as store_mod

_windows_only = pytest.mark.skipif(
    sys.platform != "win32", reason="the store trio's DACL is a Windows mechanism (icacls)"
)

#: NT SERVICE\TrustedInstaller: a per-service virtual-account SID present on every Windows host, used
#: here as the stand-in for NT SERVICE\MessageFoundry, which exists only once the service is installed.
_TI = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

#: The data directory install-service.ps1 writes: protected, SYSTEM and Administrators full control,
#: the run-as virtual account Modify, all inherited by files (OI) and folders (CI).
_INSTALLER_DIR = f"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;{_TI})"


# --- the decision, on every platform ------------------------------------------------------------


def test_the_installers_data_directory_confines_the_store() -> None:
    dacl = store_mod._parse_sddl_dacl(_INSTALLER_DIR)
    assert dacl is not None
    assert store_mod._dacl_confines_store(dacl)


@pytest.mark.parametrize(
    ("label", "sddl"),
    [
        ("inheritance still on", f"D:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{_TI})"),
        ("BUILTIN\\Users by alias", "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"),
        ("BUILTIN\\Users by SID", "D:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;S-1-5-32-545)"),
        ("Everyone", "D:P(A;OICI;FA;;;SY)(A;OICI;FR;;;WD)"),
        ("Authenticated Users", "D:P(A;OICI;FA;;;BA)(A;OICI;FR;;;AU)"),
        ("NT SERVICE\\ALL SERVICES", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-80-0)"),
        ("a named user or group", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"),
        ("CREATOR OWNER", "D:P(A;OICI;FA;;;SY)(A;OICIIO;FA;;;CO)"),
        ("a callback ACE", "D:P(A;OICI;FA;;;SY)(XA;OICI;FA;;;WD;(@User.x == 1))"),
        ("a null DACL", "D:NO_ACCESS_CONTROL"),
        ("an empty DACL", "D:P"),
        ("no DACL section", "O:BAG:SY"),
        ("garbage", "not an sddl string"),
    ],
)
def test_a_directory_that_admits_anyone_else_does_not_confine_the_store(
    label: str, sddl: str
) -> None:
    # Each row admits (or may admit) a principal beyond SYSTEM, Administrators and one service
    # account, or cannot be read with confidence. Every one must fall back to the owner-only rewrite.
    dacl = store_mod._parse_sddl_dacl(sddl)
    assert dacl is None or not store_mod._dacl_confines_store(dacl), label


def test_a_deny_entry_does_not_disqualify_a_hardened_directory() -> None:
    # A deny only narrows access, so it cannot let anybody else in.
    dacl = store_mod._parse_sddl_dacl(_INSTALLER_DIR + "(D;OICI;FA;;;BG)")
    assert dacl is not None and store_mod._dacl_confines_store(dacl)


def test_inherited_only_is_recognised() -> None:
    inheriting = store_mod._parse_sddl_dacl(
        f"D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1301bf;;;{_TI})"
    )
    owner_only = store_mod._parse_sddl_dacl("D:PAI(A;;FA;;;S-1-5-21-1-2-3-1001)")
    mixed = store_mod._parse_sddl_dacl("D:AI(A;;FA;;;S-1-5-21-1-2-3-1001)(A;ID;FA;;;SY)")
    assert inheriting is not None and store_mod._dacl_inherits_only(inheriting)
    assert owner_only is not None and not store_mod._dacl_inherits_only(owner_only)
    assert mixed is not None and not store_mod._dacl_inherits_only(mixed)


def test_off_windows_the_store_file_still_gets_the_owner_only_restriction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The new path is Windows-only; everywhere else it must hand straight to _secure_file.
    seen: list[Path] = []
    monkeypatch.setattr(store_mod, "_secure_file", lambda path, **_kw: seen.append(path))
    monkeypatch.setattr(store_mod.os, "name", "posix")
    target = tmp_path / "s.db"
    store_mod._secure_store_file(target, dir_confines=True)
    assert seen == [target]


# --- the real mechanism, on Windows ------------------------------------------------------------


def _run(argv: list[str]) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)  # noqa: S603
    assert result.returncode == 0, (
        f"{argv} exited {result.returncode}: {result.stderr or result.stdout}"
    )
    return result.stdout


def _icacls() -> str:
    from messagefoundry.service_status import _system_exe

    return _system_exe("icacls.exe")


def _my_sid() -> str:
    from messagefoundry.service_status import _system_exe

    line = _run([_system_exe("whoami.exe"), "/user", "/fo", "csv", "/nh"]).strip()
    return line.rsplit(",", 1)[1].strip().strip('"')


def _sddl_of(path: Path, scratch: Path) -> str:
    """The DACL of ``path`` as SDDL, read by ``icacls /save`` -- independent of the ctypes reader, and
    language-independent. It needs more than READ_CONTROL, so it works only where the caller has an
    explicit or group grant on the file."""
    out = scratch / f"acl-{path.name}.txt"
    _run([_icacls(), str(path), "/save", str(out)])
    text = out.read_bytes().decode("utf-16-le").lstrip("\ufeff")
    return [line for line in text.splitlines() if line.strip()][1]


def _harden(directory: Path) -> None:
    """Lock ``directory`` the way install-service.ps1 locks the data directory."""
    _run(
        [
            _icacls(),
            str(directory),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            f"*{_TI}:(OI)(CI)M",
        ]
    )


def _release(directory: Path, sid: str) -> None:
    # Hand the directory back to the test user so pytest can clean it up. The owner keeps WRITE_DAC.
    subprocess.run(  # noqa: S603
        [_icacls(), str(directory), "/grant", f"*{sid}:(OI)(CI)F", "/T", "/C"],
        check=False,
        capture_output=True,
    )


@_windows_only
def test_a_store_file_in_a_hardened_directory_inherits_the_directory(tmp_path: Path) -> None:
    """The fix itself, runnable without elevation. The file is made owner-only first, the way the old
    re-secure left it, and the directory is then hardened. Its owner keeps READ_CONTROL and WRITE_DAC,
    so it can still be re-secured and read back although the owner cannot create files there.

    RED before the fix: the open path's restriction rewrote the file to its opener alone, so the
    service account (here TrustedInstaller's SID) and Administrators had no entry."""
    me = _my_sid()
    data = tmp_path / "data"
    data.mkdir()
    db = data / "messagefoundry.db"
    db.write_bytes(b"")
    _run([_icacls(), str(db), "/inheritance:r", "/grant:r", f"*{me}:F"])
    _harden(data)
    try:
        confines = store_mod._store_dir_confines(data)
        assert confines, (
            f"a directory hardened like the installer's did not confine: {_sddl_of(data, tmp_path)}"
        )
        store_mod._secure_store_file(db, dir_confines=confines)
        sddl = store_mod._read_dacl_sddl(db)
        assert sddl is not None, "the owner could not read the DACL back"
        dacl = store_mod._parse_sddl_dacl(sddl)
        assert dacl is not None
        assert not dacl.protected, "the store file still blocks inheritance"
        sids = {sid for _type, _flags, sid in dacl.aces}
        assert sids == {"SY", "BA", _TI}, (
            f"expected exactly SYSTEM, Administrators and the service: {dacl}"
        )
        assert store_mod._dacl_inherits_only(dacl), dacl
    finally:
        _release(data, me)


@_windows_only
def test_a_store_file_outside_a_hardened_directory_stays_owner_only(tmp_path: Path) -> None:
    # A developer checkout or a temp directory inherits a broad parent, so the old owner-only
    # restriction must still apply there: this is the half of ADR 0163's property the fix keeps.
    me = _my_sid()
    db = tmp_path / "messagefoundry.db"
    db.write_bytes(b"")
    confines = store_mod._store_dir_confines(tmp_path)
    assert not confines
    store_mod._secure_store_file(db, dir_confines=confines)
    dacl = store_mod._parse_sddl_dacl(_sddl_of(db, tmp_path))
    assert dacl is not None and dacl.protected
    assert {sid for _t, _f, sid in dacl.aces} == {me}, dacl


@_windows_only
def test_the_dacl_reader_agrees_with_icacls(tmp_path: Path) -> None:
    # The hardened-directory tests read back through _read_dacl_sddl, so check it against icacls
    # /save on a file both can read. Without this, a reader returning the wrong file's DACL, or a
    # stale one, would pass those tests.
    db = tmp_path / "agree.db"
    db.write_bytes(b"")
    _run([_icacls(), str(db), "/inheritance:r", "/grant:r", f"*{_my_sid()}:F", "*S-1-5-18:R"])
    ours = store_mod._parse_sddl_dacl(store_mod._read_dacl_sddl(db) or "")
    theirs = store_mod._parse_sddl_dacl(_sddl_of(db, tmp_path))
    assert ours is not None and ours == theirs, (ours, theirs)


@_windows_only
def test_a_file_already_inheriting_a_hardened_directory_is_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The service account holds Modify, not WRITE_DAC, so a second opener that rewrote an already
    # correct DACL would fail and log a warning on every start. It must not try.
    me = _my_sid()
    data = tmp_path / "data"
    data.mkdir()
    db = data / "messagefoundry.db"
    db.write_bytes(b"")
    _harden(data)
    try:
        calls: list[list[str]] = []
        real = store_mod.subprocess.run

        def _spy(argv: list[str], *args: object, **kwargs: object) -> object:
            calls.append(list(argv))
            return real(argv, *args, **kwargs)  # type: ignore[call-overload]

        monkeypatch.setattr(store_mod.subprocess, "run", _spy)
        store_mod._secure_store_file(db, dir_confines=True)
        assert calls == [], f"an already-inheriting store file was rewritten: {calls}"
    finally:
        _release(data, me)


def _elevated() -> bool:
    if sys.platform != "win32":
        return False
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


@pytest.mark.skipif(
    not _elevated(),
    reason="needs an elevated token: it opens a store inside a directory only SYSTEM, "
    "Administrators and a service account may write (the hosted Windows legs are elevated)",
)
async def test_open_in_a_hardened_directory_leaves_the_trio_to_the_directory(
    tmp_path: Path,
) -> None:
    """End to end through MessageStore.open, as an elevated operator in an installer-shaped directory.
    RED before the fix: the .db came back protected, granting the operator alone."""
    me = _my_sid()
    data = tmp_path / "data"
    data.mkdir()
    _harden(data)
    try:
        store = await store_mod.MessageStore.open(data / "messagefoundry.db")
        await store.close()
        dacl = store_mod._parse_sddl_dacl(_sddl_of(data / "messagefoundry.db", tmp_path))
        assert dacl is not None and not dacl.protected, dacl
        assert {sid for _t, _f, sid in dacl.aces} == {"SY", "BA", _TI}, dacl
    finally:
        _release(data, me)
