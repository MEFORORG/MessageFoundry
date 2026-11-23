# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Outside a hardened data directory, in a folder whose entries its files inherit, opening a store
leaves each file's access list granting the process token's account alone, for each USERNAME
value sampled below (vault BACKLOG #5612). A folder that hands its entries down as explicit ones is
not built here, and there the restriction is not owner-only: the icacls call it runs is recorded
leaving such entries on a file (``tests/_win_acl.py``).

These cover the owner-only restriction only: a hardened directory's grants, and the file owner,
are not read here. They drive ``MessageStore.open`` with a real icacls, then read each file's
access list with ``Get-Acl`` and the account with ``whoami``, so no instrument goes through the code
under test. The restriction used to grant ``%USERNAME%``: an inherited value naming another
principal was granted Full Control, and an empty one, with getpass finding nothing either, skipped
the restriction and left the file its inherited access list. Windows only.

The folder is made here granting only the token's account, for the reason ``tests/_win_acl.py``
gives, so any other entry on a store file comes from the code under test.
"""

from __future__ import annotations

import asyncio
import functools
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from messagefoundry.store import MessageStore

# Each case starts several cold Windows PowerShell processes, so the default per-test budget is
# raised; each subprocess still has its own timeout below it.
pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="icacls DACL is Windows-only"),
    pytest.mark.timeout(240),
]


def _system_directory() -> Path:
    """System32 as the OS reports it, never from an inheritable environment variable."""
    import ctypes

    buffer = ctypes.create_unicode_buffer(260)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))  # type: ignore[attr-defined,unused-ignore]
    assert 0 < length < len(buffer)
    return Path(buffer.value)


_SYSTEM32 = _system_directory() if sys.platform == "win32" else Path()
_POWERSHELL = _SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
_EVERYONE = "S-1-1-0"
_FULL_CONTROL = 0x1F01FF


def _run(argv: list[str], *, extra_env: dict[str, str] | None = None) -> str:
    """Run a system tool and return its stdout; raise on a non-zero exit or any stderr.

    ``PSModulePath`` is dropped: one inherited from PowerShell 7 makes Windows PowerShell load the
    wrong ``Microsoft.PowerShell.Security``, and Get-Acl then fails. Console tools write the OEM code
    page, so that is the decoding."""
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    env.update(extra_env or {})
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        encoding="oem",
        errors="replace",
        env=env,
        timeout=40,
    )
    assert result.returncode == 0 and not result.stderr.strip(), (
        f"{argv[0]} failed ({result.returncode}): {result.stderr}"
    )
    return result.stdout


@functools.cache
def _token_sid() -> str:
    """The SID of the account running the tests, as whoami reads it from the token."""
    out = _run([str(_SYSTEM32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"])
    match = re.search(r'"(S-1-[0-9-]+)"', out)
    assert match is not None, out
    return match.group(1)


@dataclass(frozen=True)
class _Entry:
    kind: str
    inherited: bool
    mask: int
    sid: str


@dataclass(frozen=True)
class _Acl:
    protected: bool
    entries: tuple[_Entry, ...]
    raw: str


# Windows PowerShell's own reader. Each trustee is printed as a SID, never an SDDL alias such as
# LA or WD, so the comparisons below hold whichever account runs the tests. Stop makes a failed
# read exit non-zero rather than print an empty list.
_READ_ACL = (
    "$ErrorActionPreference = 'Stop';"
    "$d = New-Object System.Security.AccessControl.RawSecurityDescriptor("
    "(Get-Acl -LiteralPath $env:MF_ACL_PATH).Sddl);"
    "$p = $d.ControlFlags.HasFlag("
    "[System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected);"
    "if ($p) { 'protected=1' } else { 'protected=0' };"
    "foreach ($a in $d.DiscretionaryAcl) {"
    " $i = if ($a.IsInherited) { '1' } else { '0' };"
    " [string]$a.AceType + '|' + $i + '|' + [string]$a.AccessMask + '|'"
    " + $a.SecurityIdentifier.Value }"
)


def _acl(path: Path) -> _Acl:
    out = _run(
        [str(_POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", _READ_ACL],
        extra_env={"MF_ACL_PATH": str(path)},
    )
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    assert lines and lines[0] in ("protected=0", "protected=1"), out
    entries = []
    for line in lines[1:]:
        kind, inherited, mask, sid = line.split("|")
        entries.append(_Entry(kind, inherited == "1", int(mask), sid))
    assert entries, f"no entry was read for {path}, so nothing below would be checked:\n{out}"
    return _Acl(lines[0] == "protected=1", tuple(entries), out)


# Replaces the whole access list with the SDDL given, writing only the access section.
# ``icacls /inheritance:r /grant:r`` is not enough: the first removes only entries marked inherited
# and the second replaces only the named SID's entries, so other explicit entries survive. On the
# hosted runners the child folder made under pytest's mode-0700 temp folder held SYSTEM,
# Administrators and OWNER RIGHTS as explicit entries after that call (CI run 45151393786); why
# they arrive explicit there and inherited on a developer machine is not established.
# SetAccessControl is used rather than Set-Acl: Windows PowerShell's Set-Acl also writes the audit
# list when the item is already protected, which needs a privilege an unelevated account lacks.
_SET_ACL = (
    "$ErrorActionPreference = 'Stop';"
    "$i = Get-Item -LiteralPath $env:MF_ACL_PATH;"
    "$a = $i.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access);"
    "$a.SetSecurityDescriptorSddlForm($env:MF_ACL_SDDL,"
    " [System.Security.AccessControl.AccessControlSections]::Access);"
    "$i.SetAccessControl($a)"
)


def _grant_only(path: Path, sid: str) -> Path:
    """Replace the folder ``path``'s list with a protected one granting ``sid`` alone, inherited by
    what is made in it, and check that it took."""
    _run(
        [str(_POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", _SET_ACL],
        extra_env={"MF_ACL_PATH": str(path), "MF_ACL_SDDL": f"D:PAI(A;OICI;FA;;;{sid})"},
    )
    acl = _acl(path)
    assert acl.protected, acl.raw
    assert acl.entries == (_Entry("AccessAllowed", False, _FULL_CONTROL, sid),), acl.raw
    return path


def _folder_granting_only(path: Path, sid: str) -> Path:
    """Make the folder ``path`` and give it, by :func:`_grant_only`, a protected list granting
    ``sid`` alone."""
    path.mkdir()
    return _grant_only(path, sid)


def _clear_user_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    # getpass.getuser reads these, in this order; with none set it has nothing to fall back on.
    for name in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    "username",
    [None, "", "mf-no-such-account-5612", "Everyone"],
    ids=["unset", "empty", "unknown-name", "another-principal"],
)
async def test_open_grants_only_the_token_account_on_the_store_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, username: str | None
) -> None:
    sid = _token_sid()
    db = _folder_granting_only(tmp_path / "store", sid) / "secured.db"
    _clear_user_variables(monkeypatch)
    if username is not None:
        monkeypatch.setenv("USERNAME", username)
    store = await MessageStore.open(db)
    try:
        # Read while open, so the WAL and shared-memory files exist beside the database.
        trio = [db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")]
        assert all(p.exists() for p in trio), [p.name for p in trio if not p.exists()]
        acls = {p.name: await asyncio.to_thread(_acl, p) for p in trio}
    finally:
        await store.close()

    only_the_token = (_Entry("AccessAllowed", False, _FULL_CONTROL, sid),)
    for name, acl in acls.items():
        # Protected, so the restriction ran, and exactly one entry: the token's account. Neither
        # Everyone nor any other principal USERNAME could name holds anything.
        assert acl.protected, f"{name} kept its inherited access list:\n{acl.raw}"
        assert acl.entries == only_the_token, f"{name}:\n{acl.raw}"


def test_control_the_instrument_sees_an_unrestricted_file(tmp_path: Path) -> None:
    """A file made in the same kind of folder without the restriction reads as unprotected with an
    inherited entry, and a grant to Everyone reads back as its SID, so each assertion above can
    fail."""
    folder = _folder_granting_only(tmp_path / "store", _token_sid())
    plain = folder / "plain.db"
    plain.write_bytes(b"x")
    acl = _acl(plain)
    assert not acl.protected, acl.raw
    assert acl.entries == (_Entry("AccessAllowed", True, _FULL_CONTROL, _token_sid()),), acl.raw
    granted = folder / "granted.db"
    granted.write_bytes(b"x")
    _run([str(_SYSTEM32 / "icacls.exe"), str(granted), "/grant", f"*{_EVERYONE}:F"])
    assert _EVERYONE in {e.sid for e in _acl(granted).entries}


def test_control_the_folder_setup_clears_explicit_entries(tmp_path: Path) -> None:
    """A folder already holding explicit SYSTEM, Administrators and OWNER RIGHTS entries, the
    entries CI run 45151393786 found on the runner's folder, ends with the token's entry alone, and
    so does a folder already protected, so a return to ``icacls /inheritance:r`` for the setup
    fails here too. Whether the runner's files also receive entries as explicit ones is not tested
    here."""
    folder = tmp_path / "seeded"
    folder.mkdir()
    seeded = ("S-1-5-18", "S-1-5-32-544", "S-1-3-4")
    _run(
        [str(_SYSTEM32 / "icacls.exe"), str(folder), "/grant"]
        + [f"*{sid}:(OI)(CI)F" for sid in seeded]
    )
    assert set(seeded) <= {e.sid for e in _acl(folder).entries if not e.inherited}
    _grant_only(folder, _token_sid())
    # Now protected, which is what made Set-Acl need the audit privilege.
    _grant_only(folder, _token_sid())
