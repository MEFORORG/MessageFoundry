# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Opening a store restricts its file to the process token's account, whatever USERNAME says
(vault BACKLOG #5612).

These drive ``MessageStore.open`` with a real icacls, then read the file's access list with
``Get-Acl`` and the account with ``whoami``, so no instrument goes through the code under test. The
restriction used to grant ``%USERNAME%``: an inherited value naming another principal was granted
Full Control, and an empty one, with getpass finding nothing either, skipped the restriction and
left the file its inherited access list. Windows only.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from messagefoundry.store import MessageStore

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="icacls DACL is Windows-only")

_SYSTEM32 = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
_EVERYONE = "S-1-1-0"
_FULL_CONTROL = 0x1F01FF


def _token_sid() -> str:
    """The SID of the account running the tests, as whoami reads it from the token."""
    out = subprocess.run(
        [str(_SYSTEM32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
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
# LA or WD, so the comparisons below hold whichever account runs the tests.
_READ_ACL = (
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
    out = subprocess.run(
        [
            str(_SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _READ_ACL,
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "MF_ACL_PATH": str(path)},
    ).stdout
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    assert lines and lines[0] in ("protected=0", "protected=1"), out
    entries = []
    for line in lines[1:]:
        kind, inherited, mask, sid = line.split("|")
        entries.append(_Entry(kind, inherited == "1", int(mask), sid))
    return _Acl(lines[0] == "protected=1", tuple(entries), out)


def _clear_user_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    # getpass.getuser reads these, in this order; with none set it has nothing to fall back on.
    for name in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    "username",
    [None, "", "mf-no-such-account-5612", "Everyone"],
    ids=["unset", "empty", "unknown-name", "another-principal"],
)
async def test_open_restricts_the_store_file_to_the_token_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, username: str | None
) -> None:
    sid = _token_sid()
    db = tmp_path / "secured.db"
    _clear_user_variables(monkeypatch)
    if username is not None:
        monkeypatch.setenv("USERNAME", username)
    store = await MessageStore.open(db)
    await store.close()

    acl = _acl(db)
    # Protected, and no entry inherited from the folder: the restriction ran.
    assert acl.protected, f"the store file kept its inherited access list:\n{acl.raw}"
    assert not [e for e in acl.entries if e.inherited], acl.raw
    # The token's account holds full control explicitly, and USERNAME's principal holds nothing.
    assert _Entry("AccessAllowed", False, _FULL_CONTROL, sid) in acl.entries, acl.raw
    assert _EVERYONE not in {e.sid for e in acl.entries}, acl.raw


async def test_control_the_instrument_sees_an_unrestricted_file(tmp_path: Path) -> None:
    """A file made in the same folder without the restriction reads as unprotected with inherited
    entries, and Everyone reads back as its SID, so each assertion above can fail."""
    plain = tmp_path / "plain.db"
    plain.write_bytes(b"x")
    acl = _acl(plain)
    assert not acl.protected, acl.raw
    assert [e for e in acl.entries if e.inherited], acl.raw
    granted = tmp_path / "granted.db"
    granted.write_bytes(b"x")
    subprocess.run(
        [str(_SYSTEM32 / "icacls.exe"), str(granted), "/grant", "*S-1-1-0:F"],
        check=True,
        capture_output=True,
    )
    assert _EVERYONE in {e.sid for e in _acl(granted).entries}
