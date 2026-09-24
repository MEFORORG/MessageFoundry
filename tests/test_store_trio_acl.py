# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SQLite store trio's DACL in a hardened data directory (ADR 0183 Wave 0b, ADR 0163).

ADR 0183 Wave 0 measured, on hosted windows-2022 and windows-2025 (CI run 36026471545), that the old
re-secure made whichever identity opened a fresh store first its ONLY principal: the operator running
``provision-admin`` locked the NSSM service account out, and the service locked the operator out. The
fix: when the store's directory is HARDENED the way install-service.ps1 leaves it, every open writes
the same explicit, protected DACL -- SYSTEM, Administrators, and the directory's one service account --
whoever opens. Anywhere else the owner-only rewrite is unchanged.

Three tiers, each saying what it can and cannot show:

* The SDDL decisions are pure and run on every platform, as does the wiring into ``open``.
* The Windows tests drive the real ``icacls`` on real files and skip off Windows, because the
  mechanism is a Windows DACL. A non-elevated user cannot make BUILTIN\\Administrators a directory's
  owner, so those tests pass the grant set directly to the file step and test directory DETECTION on
  the refusing side (a user-owned directory, a junction). They read results back as SDDL through
  ``_read_dacl_sddl``, which needs only READ_CONTROL: once a file carries no entry for its
  non-elevated owner, ``icacls`` itself is refused (measured: exit 5). A separate test checks that
  reader against ``icacls /save`` where both can read.
* One test needs an ELEVATED token: it opens a store end to end in an installer-shaped directory. It
  skips when not elevated. The hosted ``windows-service-smoke`` store-access arms run the same flow
  under the real NSSM service account.
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
#: as the stand-in for NT SERVICE\MessageFoundry, which exists only once the service is installed.
_TI = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_OTHER_SERVICE = "S-1-5-80-1-2-3-4-5"
_SY, _BA = "S-1-5-18", "S-1-5-32-544"

#: The data directory install-service.ps1 writes: owned by Administrators, protected, SYSTEM and
#: Administrators full control, the run-as virtual account Modify, inherited by files and folders.
_INSTALLER_DIR = f"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;{_TI})"


# --- the decisions, on every platform -------------------------------------------------------------


def _grants(sddl: str) -> tuple[str, ...] | None:
    dacl = store_mod._parse_sddl_dacl(sddl)
    return None if dacl is None else store_mod._hardened_trio_grants(dacl)


def test_the_installers_data_directory_is_hardened() -> None:
    assert _grants(_INSTALLER_DIR) == (_SY, _BA, _TI)


def test_a_localsystem_install_grants_system_and_administrators_only() -> None:
    # -AllowLocalSystem: the directory names no service account, so the trio names none either.
    assert _grants("O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)") == (_SY, _BA)


@pytest.mark.parametrize(
    ("label", "sddl"),
    [
        ("inheritance still on", f"O:BAD:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{_TI})"),
        ("BUILTIN\\Users by alias", "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)"),
        ("BUILTIN\\Users by SID", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;S-1-5-32-545)"),
        ("Everyone", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FR;;;WD)"),
        ("Authenticated Users", "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FR;;;AU)"),
        ("NT SERVICE\\ALL SERVICES", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-80-0)"),
        (
            "a second service account",
            f"O:BAD:P(A;;FA;;;SY)(A;;FA;;;{_TI})(A;;FA;;;{_OTHER_SERVICE})",
        ),
        ("a named user or group", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"),
        ("CREATOR OWNER", "O:BAD:P(A;OICI;FA;;;SY)(A;OICIIO;FA;;;CO)"),
        ("OWNER RIGHTS", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)"),
        ("owned by a standard user", "O:S-1-5-21-1-2-3-1001D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
        (
            "owned by an unnamed service",
            f"O:{_OTHER_SERVICE}D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;{_TI})",
        ),
        ("no owner read", "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
        ("deny entries only", "O:BAD:P(D;OICI;FA;;;WD)"),
        ("a callback ACE", "O:BAD:P(A;OICI;FA;;;SY)(XA;OICI;FA;;;WD;(@User.x == 1))"),
        ("a null DACL", "O:BAD:NO_ACCESS_CONTROL"),
        ("an empty DACL", "O:BAD:P"),
        ("no DACL section", "O:BAG:SY"),
        ("garbage", "not an sddl string"),
    ],
)
def test_a_directory_that_admits_anyone_else_is_not_hardened(label: str, sddl: str) -> None:
    # Each row admits (or may admit) a principal beyond SYSTEM, Administrators and one service
    # account, lets an outsider rewrite the directory, or cannot be read with confidence. Every one
    # must fall back to the owner-only rewrite.
    assert _grants(sddl) is None, label


def test_a_directory_with_a_deny_entry_is_not_hardened() -> None:
    # The trio's DACL does not carry the directory's denies over, so a store derived from a directory
    # that denies somebody would be WIDER than the directory. Refusing is the only honest option.
    assert _grants(_INSTALLER_DIR + "(D;OICI;FA;;;BG)") is None


def test_the_grants_name_only_what_the_directory_allows() -> None:
    # A directory that leaves Administrators out must not get them added on the store.
    assert _grants(f"O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;{_TI})") == (_SY, _TI)


def test_an_exact_trio_dacl_is_recognised_and_nothing_else_is() -> None:
    grants = (_SY, _BA, _TI)
    exact = store_mod._parse_sddl_dacl(f"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;{_TI})")
    inheriting = store_mod._parse_sddl_dacl(f"D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{_TI})")
    extra = store_mod._parse_sddl_dacl(f"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{_TI})(A;;FR;;;BU)")
    missing = store_mod._parse_sddl_dacl("D:PAI(A;;FA;;;SY)(A;;FA;;;BA)")
    # A stale entry marked inherited, as a file moved in from a broad directory keeps (measured).
    stale = store_mod._parse_sddl_dacl(f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;ID;FR;;;{_TI})")
    assert exact is not None and not store_mod._trio_dacl_is_exact(exact, grants), "owner unread"
    owned = store_mod._parse_sddl_dacl(f"O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;{_TI})")
    assert owned is not None and store_mod._trio_dacl_is_exact(owned, grants)
    # An owner outside the set keeps WRITE_DAC and could re-grant itself read (measured).
    user_owned = store_mod._parse_sddl_dacl(
        f"O:S-1-5-21-1-2-3-1001D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;{_TI})"
    )
    assert user_owned is not None and not store_mod._trio_dacl_is_exact(user_owned, grants)
    for label, dacl in (
        ("inheriting", inheriting),
        ("extra", extra),
        ("missing", missing),
        ("stale", stale),
    ):
        assert dacl is not None and not store_mod._trio_dacl_is_exact(dacl, grants), label


def test_without_hardened_grants_the_store_file_gets_the_owner_only_restriction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Path] = []
    monkeypatch.setattr(store_mod, "_secure_file", lambda path, **_kw: seen.append(path))
    target = tmp_path / "s.db"
    store_mod._secure_store_file(target, dir_grants=None)
    monkeypatch.setattr(store_mod, "_is_windows", lambda: False)
    store_mod._secure_store_file(target, dir_grants=(_SY,))
    assert seen == [target, target]


def test_an_exact_store_file_is_left_alone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The service account holds Modify, not WRITE_DAC, so a second opener that rewrote an already
    # exact DACL would fail and warn on every start. It must not try. Seams only, so it runs anywhere.
    exact = f"O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;{_TI})"
    writes: list[object] = []
    monkeypatch.setattr(store_mod, "_is_windows", lambda: True)
    monkeypatch.setattr(store_mod, "_reaches_through_a_link", lambda _p: False)
    monkeypatch.setattr(store_mod, "_read_dacl_sddl", lambda _p, **_kw: exact)
    monkeypatch.setattr(store_mod, "_write_trio_dacl", lambda *a, **kw: writes.append((a, kw)))
    store_mod._secure_store_file(tmp_path / "s.db", dir_grants=(_SY, _BA, _TI))
    assert writes == [], writes
    # CONTROL: the same file owned by a user is rewritten, with Administrators named as the owner.
    monkeypatch.setattr(
        store_mod,
        "_read_dacl_sddl",
        lambda _p, **_kw: exact.replace("O:BA", "O:S-1-5-21-1-2-3-1001"),
    )
    store_mod._secure_store_file(tmp_path / "s.db", dir_grants=(_SY, _BA, _TI))
    assert len(writes) == 1 and writes[0][1] == {"owner": "BA"}, writes


def test_restore_applies_the_hardened_rule_to_the_restored_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A restored store published owner-only would lock the service out of the store it is about to
    # open. RED before the fix: _place_restored_store called _secure_file directly.
    from messagefoundry.pipeline import dr_backup

    src = tmp_path / "staged.db"
    src.write_bytes(b"x")
    dest = tmp_path / "restored" / "msg.db"
    dest.parent.mkdir()
    secured: list[tuple[Path, object]] = []
    monkeypatch.setattr(store_mod, "_store_dir_grants", lambda directory: (_SY, str(directory)))
    monkeypatch.setattr(
        store_mod,
        "_secure_store_file",
        lambda path, *, dir_grants: secured.append((path, dir_grants)),
    )
    dr_backup._place_restored_store(src, dest)
    assert secured == [(dest, (_SY, str(dest.parent)))], secured


async def test_open_applies_the_hardened_rule_to_the_store_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The wiring, on every platform and without elevation: open must ask about the store's OWN
    # directory and pass that answer to every trio file it secures. RED before the fix: open called
    # _secure_file_async directly, so neither seam was consulted.
    asked: list[Path] = []
    secured: list[tuple[str, object]] = []

    def _grants_for(directory: Path) -> tuple[str, ...]:
        asked.append(directory)
        return (_SY,)

    monkeypatch.setattr(store_mod, "_store_dir_grants", _grants_for)
    monkeypatch.setattr(
        store_mod,
        "_secure_store_file",
        lambda path, *, dir_grants: secured.append((path.name, dir_grants)),
    )
    store = await store_mod.MessageStore.open(tmp_path / "wired.db")
    await store.close()
    assert asked == [tmp_path]
    assert ("wired.db", (_SY,)) in secured, secured


# --- the real mechanism, on Windows ---------------------------------------------------------------


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
    """The DACL of ``path`` as SDDL, read by ``icacls /save``: independent of the ctypes reader, and
    language-independent. It needs more than READ_CONTROL, so it works only where the caller has an
    explicit or group grant on the file."""
    out = scratch / f"acl-{path.name}.txt"
    _run([_icacls(), str(path), "/save", str(out)])
    text = out.read_bytes().decode("utf-16-le").lstrip("\ufeff")
    return [line for line in text.splitlines() if line.strip()][1]


def _read_back(path: Path) -> store_mod._SddlDacl:
    sddl = store_mod._read_dacl_sddl(path, owner=True)
    assert sddl is not None, f"the owner could not read the DACL of {path} back"
    dacl = store_mod._parse_sddl_dacl(sddl)
    assert dacl is not None, sddl
    return dacl


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
    # Hand the tree back to the test user so pytest can clean it up; the owner keeps WRITE_DAC.
    result = subprocess.run(  # noqa: S603
        [_icacls(), str(directory), "/grant", f"*{sid}:(OI)(CI)F", "/T", "/C"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"cleanup could not restore access to {directory}: {result.stdout}"
    )


@_windows_only
def test_a_store_file_gets_exactly_the_hardened_principals(tmp_path: Path) -> None:
    """The file step, without elevation. The file starts the way the old re-secure left it (its opener
    alone) plus a stale explicit BUILTIN\\Users read, as a moved-in or restored file can carry. It must
    end protected, naming exactly SYSTEM, Administrators and the service account, and nobody else.

    RED before the fix: the restriction rewrote it to the opener alone, so the service account and
    Administrators had no entry (and Wave 0 saw exactly that under NSSM)."""
    me = _my_sid()
    data = tmp_path / "data"
    data.mkdir()
    db = data / "messagefoundry.db"
    db.write_bytes(b"")
    _run([_icacls(), str(db), "/inheritance:r", "/grant:r", f"*{me}:F", "*S-1-5-32-545:R"])
    _harden(data)
    try:
        store_mod._secure_store_file(db, dir_grants=(_SY, _BA, _TI))
        dacl = _read_back(db)
        assert dacl.protected, dacl
        assert all(t == "A" and "ID" not in f for t, f, _s in dacl.aces), dacl
        assert {sid for _t, _f, sid in dacl.aces} == {_SY, _BA, _TI}, dacl
        # The owner: an elevated token moves it to Administrators; a non-elevated one cannot, so the
        # file keeps its user owner and the step logs the refusal instead of passing as exact.
        if _elevated():
            assert dacl.owner == _BA, dacl
        else:
            assert dacl.owner == me, dacl
            assert not store_mod._trio_dacl_is_exact(dacl, (_SY, _BA, _TI))
    finally:
        _release(data, me)


@_windows_only
def test_a_directory_owned_by_a_standard_user_is_not_hardened(tmp_path: Path) -> None:
    # Its owner keeps WRITE_DAC over it, so its entries do not bind the owner; the rule must refuse it
    # even with the installer's exact entries. Runs only where the test user is NOT an elevated
    # administrator, since an elevated user's new directory is owned by Administrators.
    if _elevated():
        pytest.skip("an elevated user's directory is owned by Administrators, not by the user")
    me = _my_sid()
    data = tmp_path / "data"
    data.mkdir()
    _harden(data)
    try:
        assert store_mod._store_dir_grants(data) is None
    finally:
        _release(data, me)


@_windows_only
def test_a_store_directory_reached_through_a_junction_is_not_hardened(tmp_path: Path) -> None:
    # A junction has its own DACL, while files created through it inherit the TARGET's (measured).
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    _run(["cmd.exe", "/c", "mklink", "/J", str(link), str(target)])
    try:
        assert store_mod._reaches_through_a_link(link)
        assert store_mod._reaches_through_a_link(link / "messagefoundry.db"), "an ancestor link"
        assert not store_mod._reaches_through_a_link(target)
        # Isolate the link check: give both paths the installer's DACL, so the junction is refused
        # for being a link and for nothing else. Without the check both would be hardened.
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(store_mod, "_read_dacl_sddl", lambda _p, **_kw: _INSTALLER_DIR)
            assert store_mod._store_dir_grants(target) == (_SY, _BA, _TI)
            assert store_mod._store_dir_grants(link) is None
    finally:
        subprocess.run(["cmd.exe", "/c", "rmdir", str(link)], check=False, capture_output=True)  # noqa: S603


@_windows_only
def test_a_store_outside_a_hardened_directory_stays_owner_only(tmp_path: Path) -> None:
    # A developer checkout or a temp directory: the half of ADR 0163's property the fix keeps.
    me = _my_sid()
    db = tmp_path / "messagefoundry.db"
    db.write_bytes(b"")
    grants = store_mod._store_dir_grants(tmp_path)
    assert grants is None
    store_mod._secure_store_file(db, dir_grants=grants)
    dacl = _read_back(db)
    assert dacl.protected and {sid for _t, _f, sid in dacl.aces} == {me}, dacl


@_windows_only
def test_the_dacl_reader_agrees_with_icacls(tmp_path: Path) -> None:
    # The Windows tests read back through _read_dacl_sddl, so check it against icacls /save on a file
    # both can read. Without this, a reader returning the wrong file's DACL would pass them.
    db = tmp_path / "agree.db"
    db.write_bytes(b"")
    _run([_icacls(), str(db), "/inheritance:r", "/grant:r", f"*{_my_sid()}:F", "*S-1-5-18:R"])
    ours = store_mod._parse_sddl_dacl(store_mod._read_dacl_sddl(db) or "")
    theirs = store_mod._parse_sddl_dacl(_sddl_of(db, tmp_path))
    assert ours is not None and ours == theirs, (ours, theirs)


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
async def test_open_in_a_hardened_directory_grants_the_directorys_principals(
    tmp_path: Path,
) -> None:
    """End to end through MessageStore.open, as an elevated operator in an installer-shaped directory
    (an elevated user's new directory is owned by Administrators). RED before the fix: the .db came
    back protected, granting the operator alone."""
    me = _my_sid()
    data = tmp_path / "data"
    data.mkdir()
    _harden(data)
    try:
        assert store_mod._store_dir_grants(data) == (_SY, _BA, _TI)
        store = await store_mod.MessageStore.open(data / "messagefoundry.db")
        await store.close()
        dacl = _read_back(data / "messagefoundry.db")
        assert store_mod._trio_dacl_is_exact(dacl, (_SY, _BA, _TI)), dacl  # owner included
    finally:
        _release(data, me)
