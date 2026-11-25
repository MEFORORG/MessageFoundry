# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""install-service.ps1 under ``[store].key_provider = 'host'`` (vault BACKLOG #3411, key custody S3
slice B3c).

The installer refuses SYSTEM, LOCAL SERVICE and NETWORK SERVICE, which the host provider refuses as
the engine account, before anything acts. It does not check the provider's refusal of a non-local
account under enforce. Behaviour runs the script's own functions, extracted by AST, through ``pwsh``; the
call sites are read by AST, since no test runs the script body.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

import pytest

import messagefoundry.service as svc
from tests.test_service_install_manifest import (
    _extract,
    _ok,
    _preflight_facts,
    _psq,
    _run,
    _script_text,
    _sole_call,
    _sole_call_on,
    _windows_only,
)

_SCRIPT = svc.install_script_path()

pytestmark = pytest.mark.skipif(
    _SCRIPT is None,
    reason="install-service.ps1 not locatable (off-repo / non-editable install)",
)

_BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"

# (settings file text, what the installer must read as [store].key_provider)
_SETTINGS: list[tuple[str, str | None]] = [
    ('[store]\nkey_provider = "host"\n', "host"),
    ("[store]\nkey_provider = 'host'   # the custody provider\n", "host"),
    ('[api]\nport = 1\n\n[ store ]\nbackend = "sqlite"\n  key_provider="host"\n', "host"),
    ('[store]\n"key_provider" = "host"\n', "host"),
    ('store.key_provider = "host"\n[api]\nport = 1\n', "host"),
    ('store = { backend = "sqlite", key_provider = "host" }\n', "host"),
    (_BOM + '[store]\nkey_provider = "host"\n', "host"),
    ('[store]\nkey_provider = "auto"\n', "auto"),
    ('[store]\nbackend = "sqlite"\n', None),
    ('[store.tls]\nkey_provider = "host"\n', None),
    ('[api]\nkey_provider = "host"\n', None),
    ('[store]\n[[alerts.sinks]]\nkey_provider = "host"\n', None),
    ('[store]\n# key_provider = "host"\n', None),
    ('[store]\nother_key_provider = "host"\n', None),
    # TOML names are case-sensitive, and a key in a nested inline table is not [store]'s.
    ('[STORE]\nkey_provider = "host"\n', None),
    ('[store]\nKEY_PROVIDER = "host"\n', None),
    ('store = { tls = { key_provider = "host" } }\n', None),
    # Text that only looks like the key: a comment, a string value, a multi-line string.
    ('store = { backend = "sqlite" }  # was key_provider = "host"\n', None),
    ('store = { backend = "sqlite", note = "x key_provider = \'host\'" }\n', None),
    ('[api]\nnote = """\n[store]\nkey_provider = "host"\n"""\n', None),
    # Lines that only look like a table header do not move the reader out of [store].
    ('[store]\npairs = [\n  ["a", "b"]\n]\nkey_provider = "host"\n', "host"),
    # A one-element nested array line has a header's shape, inside [store] and outside it.
    ('[store]\nretired = [\n  ["k1"]\n]\nkey_provider = "host"\n', "host"),
    ('[store]\nn = [\n  [1],\n  [2]\n]\nkey_provider = "host"\n', "host"),
    ('[api]\nhosts = [\n  ["store"]\n]\nkey_provider = "host"\n', None),
    ('[api]\nhosts = [ # "]"\n  ["store"]\n]\nkey_provider = "host"\n', None),
    ('[store]\nnote = """\n[api]\n"""\nkey_provider = "host"\n', "host"),
    # The array is open after a multi-line string ends, so its element lines are not headers.
    ('[store]\nx = [ """\na""",\n  [1]\n]\nkey_provider = "host"\n', "host"),
    ('[api]\nx = [ """\nq""",\n  ["store"]\n]\nkey_provider = "host"\n', None),
    ("[store]\nx = [ '''\nq''', [\n  [[1]]\n]]\nkey_provider = \"host\"\n", "host"),
    ('[store]\nx = [\n"""a\n""", [\n[[1]]]]\nkey_provider = "host"\n', "host"),
    # A triple quote that opens no multi-line string: in a one-line string, in a comment.
    ('[api]\nnote = \'say """\'\n[store]\nkey_provider = "host"\n', "host"),
    ("# don't '''\n[store]\nkey_provider = \"host\"\n", "host"),
    ('[store]\nn = """a""""\nkey_provider = "host"\n', "host"),
    ('[store]\nn = """a\\"""\n[api]\n"""\nkey_provider = "host"\n', "host"),
    # Headers: tabs, quoted keys, arrays of tables. One the reader cannot classify, such as a
    # quoted key with an escape, ends [store].
    ('[\tstore\t]\nkey_provider = "host"\n', "host"),
    ('[store]\n[\tapi\t]\nkey_provider = "host"\n', None),
    ('[store]\n["a:b"]\nkey_provider = "host"\n', None),
    ('["sto re"]\nkey_provider = "host"\n', None),
    ('[ "store" ]\nkey_provider = "host"\n', "host"),
    ('[store]\n["\\u0061pi"]\nkey_provider = "host"\n', None),
    ('[store]\n[[array.of.tables]]\nkey_provider = "host"\n', None),
    ('[[array.of.tables]]\nx = 1\n[store]\nkey_provider = "host"\n', "host"),
    # The table named "" is not the root, so a dotted or inline store under it is not [store].
    ('[""]\nstore.key_provider = "host"\n', None),
    ("[ '' ]\nstore = { key_provider = \"host\" }\n", None),
    # Text inside a triple-quoted inline-table value is not a key.
    ("store = { a = '''x', key_provider = 'host''' }\n", None),
    ('store = { a = """x", key_provider = "host"""" }\n', None),
    ("", None),
]


@pytest.mark.parametrize(
    "host",
    [
        "pwsh",
        pytest.param(
            "powershell",
            marks=pytest.mark.skipif(
                not sys.platform.startswith("win"), reason="Windows PowerShell 5.1"
            ),
        ),
    ],
)
def test_the_settings_reader_finds_the_key_provider(tmp_path: Path, host: str) -> None:
    """Every case is a real settings file whose [store].key_provider, under Python's own TOML
    reader, is the value the installer must read, on both hosts the installer runs under."""
    assert _SCRIPT is not None
    for text, expected in _SETTINGS:
        store = tomllib.loads(text.removeprefix(_BOM)).get("store", {})
        assert store.get("key_provider") == expected, text
    paths = []
    for i, (text, _) in enumerate(_SETTINGS):
        p = tmp_path / f"settings-{i}.toml"
        p.write_bytes(text.encode("utf-8"))
        paths.append(str(p))
    body = (
        "  $out = @(foreach ($p in @("
        + ", ".join(_psq(p) for p in paths)
        + ")) { $v = Get-SettingsKeyProvider -Path $p; if ($null -eq $v) { '<none>' } else { $v } })\n"
        "  ConvertTo-Json -InputObject $out -Compress\n"
    )
    got = json.loads(_ok(_extract(_SCRIPT, ["Get-SettingsKeyProvider"], body), tmp_path, host))
    want = ["<none>" if e is None else e for _, e in _SETTINGS]
    assert got == want, list(zip([t for t, _ in _SETTINGS], got, want, strict=True))


# (-ServiceAccount, -AllowLocalSystem, refused)
_ACCOUNTS: list[tuple[str, bool, bool]] = [
    ("", True, True),
    ("", False, False),
    (r"NT SERVICE\MessageFoundry", False, False),
    (r"NT SERVICE\MessageFoundry", True, False),  # an explicit -ServiceAccount wins
    (r"CONTOSO\svc-mefor$", False, False),
    ("LocalSystem", False, True),
    (r".\LocalSystem", False, True),
    (r"NT AUTHORITY\SYSTEM", False, True),
    ("SYSTEM", False, True),
    (r"nt authority\localservice", False, True),
    (r"NT AUTHORITY\LOCAL SERVICE", False, True),
    (r"NT AUTHORITY\NetworkService", False, True),
    (r"NT AUTHORITY\NETWORK SERVICE", False, True),
    ("*S-1-5-18", False, True),
    ("S-1-5-20", False, True),
]


def test_the_host_provider_refuses_the_shared_accounts(tmp_path: Path) -> None:
    """One pwsh run for every case: the function is pure."""
    assert _SCRIPT is not None
    calls = "\n".join(
        f"  $out += [string](Get-HostCustodyAccountProblem -ServiceAccount {_psq(account)} "
        f"-AllowLocalSystem:{'$true' if allow else '$false'})"
        for account, allow, _ in _ACCOUNTS
    )
    body = f"  $out = @()\n{calls}\n  ConvertTo-Json -InputObject $out -Compress\n"
    got = json.loads(_ok(_extract(_SCRIPT, ["Get-HostCustodyAccountProblem"], body), tmp_path))
    assert [bool(p) for p in got] == [r for _, _, r in _ACCOUNTS], list(
        zip(_ACCOUNTS, got, strict=False)
    )


def test_the_installer_refuses_before_anything_acts(tmp_path: Path) -> None:
    """CALL-SITE guard: the refusal reads the service's own environment first, then the settings
    file the service is registered with, and throws before NSSM is resolved or the install is
    built."""
    facts = _preflight_facts(tmp_path)
    text = _script_text().replace("\r\n", "\n")
    reader = _sole_call(facts, "Get-SettingsKeyProvider")
    assert "-Path $ServiceConfig" in reader["text"], reader["text"]
    problem = _sole_call(facts, "Get-HostCustodyAccountProblem")
    assert "-ServiceAccount $ServiceAccount" in problem["text"], problem["text"]
    assert "-AllowLocalSystem:$AllowLocalSystem" in problem["text"], problem["text"]
    registered = next(
        c
        for c in facts["commands"]
        if c["name"] == "Get-RegisteredEnvironmentValue" and "MEFOR_STORE_KEY_PROVIDER" in c["text"]
    )
    assert registered["start"] < reader["start"]
    refusal = text.index('throw ("$custodyAccountProblem, and $namedBy')
    for later in (
        "if ($BuildsInstall) {\n    # AFTER the normalization",
        "if (-not $BuildsInstall) { $NssmPath = Resolve-Nssm",
        "New-Item -ItemType Directory -Force -Path $DataDir",
    ):
        assert refusal < text.index(later), later
    # The settings file is known to exist before it is read.
    assert text.index("Service settings file not found at: $ServiceConfig") < refusal


# --- the custody directory (ADR 0214's 2026-11-22 amendment) --------------------------------------

#: (the service account's grant, as icacls spells it, whether Get-CustodyGrantProblem passes it)
_GRANTS: list[tuple[str, bool]] = [
    ("(RX,WD)", True),
    ("(RX)", False),  # no add-file: the first start could not write master.key
    ("(WD)", False),  # no read
    ("(OI)(RX,WD)", False),  # inherited by the files in it
    ("(RX,WD,DC)", False),  # may delete any file in it
    ("(RX,WD,WDAC)", False),  # may change its list
    ("M", False),
    ("F", False),
    ("(GR,WD)", False),  # a generic right is not read as the rights it maps to
    ("(RX,WD)+deny${me}:(WD)", False),  # a deny for the account itself takes add-file away
    # One for a group it is in binds it too, and the groups are not read, so any deny is refused.
    ("(RX,WD)+deny*S-1-5-32-545:(WD)", False),
    ("(RX,WD)+deny*S-1-5-32-545:(OI)(IO)(WD)", True),  # inherit-only: not on the directory
]


@_windows_only
def test_the_custody_grant_rule(tmp_path: Path) -> None:
    """Get-CustodyGrantProblem on a real directory's list, one per grant and deny."""
    assert _SCRIPT is not None
    dirs = []
    for i, (spelled, _) in enumerate(_GRANTS):
        d = tmp_path / f"g{i}"
        d.mkdir()
        grant, _, deny = spelled.partition("+deny")
        dirs.append((str(d), grant, deny))
    cases = "\n".join(
        f'  & icacls {_psq(d)} /inheritance:r /grant:r "*${{mySid}}:{grant}" '
        f"'*S-1-5-32-544:(OI)F' | Out-Null\n"
        + (f'  & icacls {_psq(d)} /deny "{deny}" | Out-Null\n' if deny else "")
        + f"  $out += [string](Get-CustodyGrantProblem -Acl (Get-Acl -LiteralPath {_psq(d)}) "
        "-AccountSid $mySid)"
        for d, grant, deny in dirs
    )
    body = (
        "  $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
        '  $me = "*$mySid"\n'
        f"  $out = @()\n{cases}\n  ConvertTo-Json -InputObject $out -Compress\n"
    )
    try:
        got = json.loads(_ok(_extract(_SCRIPT, ["Get-CustodyGrantProblem"], body), tmp_path))
    finally:
        restore = "\n".join(
            "  $s = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
            f'  & icacls {_psq(d)} /remove:d "*$s" "*S-1-5-32-545" | Out-Null\n'
            f'  & icacls {_psq(d)} /inheritance:e /grant "*${{s}}:(OI)(CI)F" | Out-Null'
            for d, _, _ in dirs
        )
        _run(_extract(_SCRIPT, [], restore), tmp_path)
    assert [not p for p in got] == [ok for _, ok in _GRANTS], list(zip(_GRANTS, got, strict=True))


@_windows_only
def test_the_custody_directory_lockdown_grants_exactly_read_and_add_file(tmp_path: Path) -> None:
    """Set-CustodyDirAcl on a directory that inherits Users read and the account's Modify, and
    denies the account and Users add-file, and grants the account Modify itself. The account ends with read and add-file on the directory alone,
    nothing inherited and no deny, and the engine's own check of a custody directory passes it,
    where it refused the directory before. Unelevated, the owner change is refused, and the
    function refuses for that alone."""
    from messagefoundry.store import custody_host

    assert _SCRIPT is not None
    parent = tmp_path / "cd"
    custody = parent / "custody"
    custody.mkdir(parents=True)
    pre = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  & icacls {_psq(str(parent))} /grant '*S-1-5-32-545:(OI)(CI)RX' "${{me}}:(OI)(CI)M" | Out-Null
  & icacls {_psq(str(custody))} /deny "${{me}}:(WD)" '*S-1-5-32-545:(WD)' | Out-Null
  # An explicit wider grant, with other inheritance flags than the one the lockdown writes.
  & icacls {_psq(str(custody))} /grant "${{me}}:(OI)(CI)M" | Out-Null
"""
    _ok(_extract(_SCRIPT, [], pre), tmp_path)
    environ = {"MEFOR_CUSTODY_DIRECTORY": str(custody)}
    assert custody_host._own_directory_refusal(environ) is not None, (
        "CONTROL FAILED: the engine accepted the directory before the lockdown"
    )
    lock = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $dir = {_psq(str(custody))}
  $refusal = ''
  try {{ Set-CustodyDirAcl -Path $dir -Account $me }} catch {{ $refusal = $_.Exception.Message }}
  $acl = Get-Acl -LiteralPath $dir
  $mine = @($acl.Access | Where-Object {{
    try {{ $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $mySid }}
    catch {{ $false }} }})
  [pscustomobject]@{{
    refusal = $refusal
    inherited = @($acl.Access | Where-Object {{ $_.IsInherited }}).Count
    denies = @($acl.Access | Where-Object {{ "$($_.AccessControlType)" -eq 'Deny' }}).Count
    protected = $acl.AreAccessRulesProtected
    mine = @($mine | ForEach-Object {{ [pscustomobject]@{{
      type = "$($_.AccessControlType)"; rights = [int64]$_.FileSystemRights;
      inherit = "$($_.InheritanceFlags)" }} }})
    grant = (Get-CustodyGrantProblem -Acl $acl -AccountSid $mySid)
    text = (& icacls $dir | Out-String)
  }} | ConvertTo-Json -Depth 4 -Compress
"""
    names = [
        "Set-CustodyDirAcl",
        "Get-CustodyGrantProblem",
        "Get-WellKnownBroadSids",
        "Get-BroadAclResidue",
        "Get-ReparsePointAncestor",
    ]
    try:
        got = json.loads(_ok(_extract(_SCRIPT, names, lock), tmp_path).strip().splitlines()[-1])
        after = custody_host._own_directory_refusal(environ)
    finally:
        restore = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  & icacls {_psq(str(custody))} /inheritance:e /grant "${{me}}:(OI)(CI)F" | Out-Null
"""
        _run(_extract(_SCRIPT, [], restore), tmp_path)
    assert after is None, f"the engine refuses the locked directory: {after}\n{got['text']}"
    assert got["protected"] and got["inherited"] == 0, got["text"]
    assert got["denies"] == 0, f"a deny survived the lockdown:\n{got['text']}"
    mine = got["mine"] if isinstance(got["mine"], list) else [got["mine"]]
    # ReadAndExecute | CreateFiles | Synchronize, in one allow entry inherited by nothing.
    assert mine == [{"type": "Allow", "rights": 0x1200AB, "inherit": "None"}], got["text"]
    assert not got["grant"], got["grant"]
    refusal = got["refusal"]
    assert not refusal or (
        "owner" in refusal
        and "grants access" not in refusal
        and "inherits" not in refusal
        and "more than" not in refusal
    ), f"a clean lockdown must find nothing but the owner; got {refusal}"


def test_the_installer_makes_and_names_the_custody_directory_under_the_host_provider(
    tmp_path: Path,
) -> None:
    """CALL-SITE guard: the custody directory is judged with the secrets directory's rules before
    NSSM is resolved, and made restricted, restricted for the account and named to the service
    after the secrets directory, once the service is registered. Each step sits under
    the host provider's branch, and -CustodyDir is refused without it."""
    facts = _preflight_facts(tmp_path)
    # Read by line: the call offsets count the file's own line endings, which read_text folds.
    text = _script_text()
    check = _sole_call_on(facts, "Get-CustodyDirProblem", "-Path $CustodyDir")
    assert "$SecretsDir" in check["text"] and "-Named:$CustodyDirNamed" in check["text"], check
    creates = _sole_call_on(facts, "New-RestrictedDirectory", "-Path $CustodyDir")
    assert not [
        c
        for c in facts["commands"]
        if c["name"] in ("New-AdminOnlyFolder", "New-Item") and "-Path $CustodyDir" in c["text"]
    ], "the custody directory itself must not be made by New-Item"
    lock = _sole_call(facts, "Set-CustodyDirAcl")
    assert "-Path $CustodyDir" in lock["text"] and "-Account $ServiceAccount" in lock["text"]
    secrets_lock = _sole_call(facts, "Set-SecretsDirAcl")
    named = _sole_call_on(facts, "Set-ServiceEnvironmentValue", "$CustodyDir")
    assert "MEFOR_CUSTODY_DIRECTORY" in named["text"], named["text"]
    nssm = min(c["start"] for c in facts["commands"] if c["name"] == "Resolve-Nssm")
    registered = min(
        c["start"]
        for c in facts["commands"]
        if c["name"] == "Invoke-Nssm" and "install" in c["text"]
    )
    host = _sole_call(facts, "Get-HostCustodyAccountProblem")
    assert host["start"] < check["start"] < nssm
    # Made just before it is restricted and named (review round-001caa04b0 item 5), so a refusal
    # earlier in the run leaves no folder the service does not name for the next run to refuse.
    assert registered < secrets_lock["start"] < creates["start"] < lock["start"] < named["start"]
    # Each act is inside an `if ($HostCustody)` block.
    lines = text.splitlines()
    for call in (creates, lock, named):
        at = call["line"] - 1  # 1-based in the parser's extent
        head = max(i for i in range(at) if lines[i].startswith("if ($HostCustody) {"))
        end = next(i for i in range(head, len(lines)) if lines[i] == "}")
        assert head < at < end, call["text"]
    assert "-CustodyDir is used only under [store].key_provider = 'host'" in text
    # A custody variable the installer could not write refuses and disables the service, as a
    # lockdown failure does: without it the service reads its key file elsewhere.
    flat = " ".join(text.split())
    refusal = flat.index('throw ("Could not name the custody directory')
    assert "Disable-RefusedService" in flat[refusal : refusal + 600], flat[refusal : refusal + 600]
    # A refusal while it is made disables the service too. Whether it was there is read before the
    # create, which succeeds on a folder already there, and "made here" is set only after the
    # create's read-back, so a folder someone made in between is never removed as this run's.
    made = flat.index("$custodyExisted = Test-Path -LiteralPath $CustodyDir")
    create = flat.index('New-RestrictedDirectory -Path $CustodyDir -What "the custody directory"')
    marked = flat.index("$CustodyDirMadeHere = -not $custodyExisted")
    assert made < create < marked, (made, create, marked)
    window = flat[create : flat.index("Set-CustodyDirAcl -Path $CustodyDir", create)]
    assert "Disable-RefusedService" in window and "Remove-CustodyDirMadeHere" in window, window
    # Each custody refusal after registration removes only a directory this run made; none
    # tells anyone to add the variable by hand or to remove a directory.
    removals = [
        c
        for c in facts["commands"]
        if c["name"] == "Remove-CustodyDirMadeHere" and c["start"] > registered
    ]
    assert len(removals) == 3, removals
    assert all("-MadeHere:$CustodyDirMadeHere" in c["text"] for c in removals), removals
    naming = flat[refusal : refusal + 800]
    assert "Re-run the installer" in naming, naming
    for gone in ("by hand", "re-enable the service", "remove the empty directory"):
        assert gone not in naming, gone
    assert "remove the empty directory" not in flat
    assert 'Write-Warning ("Could not name the custody directory' not in flat


def test_the_uninstaller_names_the_custody_directory_and_removes_its_grant(
    tmp_path: Path,
) -> None:
    """CALL-SITE guard: the uninstaller reads MEFOR_CUSTODY_DIRECTORY off the registration,
    removes the account's entry there under -RemoveAccountAces, and hands both to the notice,
    whose lines tests/test_service_install_manifest.py checks."""
    from tests.test_service_install_manifest import _UNINSTALL

    assert _UNINSTALL is not None
    facts = _preflight_facts(tmp_path, _UNINSTALL)
    remove = _sole_call_on(facts, "Remove-AccountAce", "-Path $custodyDir")
    assert "-Principal $acePrincipal" in remove["text"], remove["text"]
    notice = _sole_call(facts, "Get-UninstallResidueNotice")
    assert "-CustodyDir $custodyDir" in notice["text"], notice["text"]
    assert "-CustodyAceRemoved:$custodyAceRemoved" in notice["text"], notice["text"]
    uninstall = _UNINSTALL.read_text(encoding="utf-8")
    assert 'StartsWith("MEFOR_CUSTODY_DIRECTORY="' in uninstall
    # The key-file probe cannot stop the uninstall before its notice: Join-Path throws on a drive
    # that is gone, so the probe joins without it, inside a try that names what it could not read.
    probe = uninstall.index('foreach ($name in @("master.key", "handoff.key"))')
    window = uninstall[uninstall.rindex("try {", 0, probe) : probe + 400]
    assert "[IO.Path]::Combine($custodyDir, $name)" in window and "$unreadable +=" in window, window
    assert "Join-Path $custodyDir" not in uninstall
    # The warning stays unless the directory itself reads as there (review round-001caa04b0 item 6).
    assert "-CustodyUnconfirmed:$custodyUnconfirmed" in notice["text"], notice["text"]
    assert (
        "$custodyUnconfirmed = -not (Test-Path -LiteralPath $custodyDir -PathType Container)"
        in uninstall
    )


def test_the_uninstall_notice_says_what_the_custody_directory_keeps(tmp_path: Path) -> None:
    """The notice names each key file the directory holds, and only those, says each keeps its own
    entry for the account, and warns that a reinstall refuses the kept directory. With no account
    read it does not print an empty name. With no custody directory, none of it is printed."""
    from tests.test_service_install_manifest import _FULL_FACTS, _notice

    both = {**_FULL_FACTS, "CustodyFiles": ["master.key", "handoff.key"]}
    flat = " ".join(_notice(tmp_path, both).split())
    for needed in (
        "master.key holds the store's key",
        "handoff.key holds the store's key",
        "It keeps its own entry for 'NT SERVICE\\MessageFoundry'",
        "A reinstall refuses this directory",
        "When a refusal names master.key or handoff.key",
    ):
        assert needed in flat, (needed, flat)
    handoff_only = " ".join(
        _notice(tmp_path, {**_FULL_FACTS, "CustodyFiles": ["handoff.key"]}).split()
    )
    assert "handoff.key holds" in handoff_only, handoff_only
    assert "master.key holds" not in handoff_only, handoff_only
    # Review round-001caa04b0 item 6: an offline drive reads as absent without an error, so a
    # directory not read as there keeps the never-delete warning with no file named. The control:
    # a directory read as there, holding neither file, carries no such warning.
    warning = "It may still hold master.key or handoff.key"
    unread = {**_FULL_FACTS, "CustodyFiles": [], "CustodyUnconfirmed": True}
    unconfirmed = " ".join(_notice(tmp_path, unread).split())
    assert warning in unconfirmed and "never delete either" in unconfirmed, unconfirmed
    read = " ".join(_notice(tmp_path, {**unread, "CustodyUnconfirmed": False}).split())
    assert warning not in read, read
    nobody = " ".join(
        _notice(tmp_path, {**both, "ServiceAccount": "", "ServiceAccountSid": ""}).split()
    )
    assert "entry for ''" not in nobody and "the account the service ran as" in nobody, nobody
    without = " ".join(_notice(tmp_path, {**_FULL_FACTS, "CustodyDir": ""}).split())
    assert "handoff.key holds" not in without and "Custody" not in without, without


@_windows_only
def test_the_custody_directory_check_accepts_a_named_one_and_never_says_remove(
    tmp_path: Path,
) -> None:
    """Get-CustodyDirProblem: a re-run over a service whose environment names the directory, with
    an owner each install sets (here this account, which an unelevated test can own), accepts it;
    the same directory the service does not name is refused without telling anyone to remove it.
    An empty one is refused without being said to hold a key (review round-001caa04b0 item 5).
    Remove-CustodyDirMadeHere removes only a directory this run made that holds nothing."""
    assert _SCRIPT is not None
    kept = tmp_path / "kept"
    kept.mkdir()
    (kept / "master.key").write_bytes(b"k")
    empty = tmp_path / "empty"
    empty.mkdir()
    made = tmp_path / "made"
    made.mkdir()
    full = tmp_path / "full"
    full.mkdir()
    (full / "master.key").write_bytes(b"k")
    other = tmp_path / "other"
    other.mkdir()
    body = rf"""
  $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  [pscustomobject]@{{
    named = [string](Get-CustodyDirProblem -Path {_psq(str(kept))} -ServiceName 'NoSuchSvc-w7' -Named -AcceptedOwners @($mySid))
    unnamed = [string](Get-CustodyDirProblem -Path {_psq(str(kept))} -ServiceName 'NoSuchSvc-w7' -AcceptedOwners @($mySid))
    empty = [string](Get-CustodyDirProblem -Path {_psq(str(empty))} -ServiceName 'NoSuchSvc-w7' -AcceptedOwners @($mySid))
    owner = [string](Get-CustodyDirProblem -Path {_psq(str(kept))} -ServiceName 'NoSuchSvc-w7' -Named)
    made = [string](Remove-CustodyDirMadeHere -Path {_psq(str(made))} -MadeHere)
    full = [string](Remove-CustodyDirMadeHere -Path {_psq(str(full))} -MadeHere)
    other = [string](Remove-CustodyDirMadeHere -Path {_psq(str(other))})
  }} | ConvertTo-Json -Compress
"""
    names = [
        "Get-CustodyDirProblem",
        "Remove-CustodyDirMadeHere",
        "Get-LockPathProblem",
        "Get-ReparsePointAncestor",
        "Get-OtherServiceNamingPath",
        "ConvertTo-NormalPath",
        "ConvertTo-EngineStripped",
        "Get-EnvironmentListValue",
        "Test-EnvironmentEntryNames",
    ]
    got = json.loads(_ok(_extract(_SCRIPT, names, body), tmp_path).strip().splitlines()[-1])
    assert got["named"] == "", got
    assert "does not name it" in got["unnamed"] and "delete nothing" in got["unnamed"], got
    assert "When a refusal names master.key or handoff.key" in got["unnamed"], got
    assert "holds 1 item(s), such as 'master.key'" in got["unnamed"], got
    assert "holds nothing" in got["empty"] and "may hold" not in got["empty"], got
    assert "may be the only copy" not in got["empty"], got
    for text in (got["unnamed"], got["empty"]):
        assert not re.search(r"\bremov", text, re.IGNORECASE), text
    assert "owner" in got["owner"], got  # the control: this account is not an install's owner
    assert not made.exists() and "was removed" in got["made"], got
    assert (full / "master.key").exists() and got["full"] == "", got
    assert other.exists() and got["other"] == "", got


def test_the_secrets_directory_texts_never_send_a_key_file_to_be_deleted(tmp_path: Path) -> None:
    """Review round-0c8608ba47 item 1: docs/SERVICE.md's key-file procedure sends an operator to a
    new -SecretsDir, and the custody files may sit in the secrets directory, so each installer and
    uninstaller text that says to delete or remove the secrets directory or its files carves out
    master.key and handoff.key and points at that procedure."""
    from tests.test_service_install_manifest import _FULL_FACTS, _notice

    # The script's string pieces joined, so a sentence split over `" +` lines reads whole.
    joined = re.sub(r'"\s*\+\s*"', "", " ".join(_script_text().split()))
    title = "When a refusal names master.key or handoff.key"
    # The -SecretsDir change warning carves the key files out before it says to copy and delete.
    keep = joined.index("Leave a master.key or handoff.key in the old directory where it is")
    assert keep < joined.index("Then delete the old files you copied"), keep
    assert title in joined[keep : keep + 400], joined[keep : keep + 400]
    # The existing-directory refusal and the squatter refusal say remove only when no key file
    # is listed there, and a listing that fails counts as one.
    held = joined.index("$secretsProblem = if ($secretsKeyHeld) {")
    assert title in joined[held : held + 500] and "} catch { $true }" in joined[held - 300 : held]
    assert '$remedy = if ($What -eq "the custody directory" -or $keyHeld) {' in joined
    assert "} catch { $true }" in joined[joined.index("$keyHeld = try {") :][:300]
    # Get-SecretsDirHeldProblem says no remove over a key file; the control is another file.
    assert _SCRIPT is not None
    with_key = tmp_path / "with-key"
    with_key.mkdir()
    (with_key / "handoff.key").write_bytes(b"k")
    other = tmp_path / "other-file"
    other.mkdir()
    (other / "MEFOR_X").write_bytes(b"v")
    body = (
        "  [pscustomobject]@{ key = [string](Get-SecretsDirHeldProblem -Path "
        f"{_psq(str(with_key))}); other = [string](Get-SecretsDirHeldProblem -Path "
        f"{_psq(str(other))}) }} | ConvertTo-Json -Compress\n"
    )
    out = _ok(_extract(_SCRIPT, ["Get-SecretsDirHeldProblem"], body), tmp_path)
    got = json.loads(out.strip().splitlines()[-1])
    assert "handoff.key" in got["key"] and title in got["key"], got
    assert not re.search(r"\bremov", got["key"], re.IGNORECASE), got
    assert "Remove the directory" in got["other"], got
    notice = " ".join(_notice(tmp_path, {**_FULL_FACTS, "CustodyDir": ""}).split())
    assert "except master.key and handoff.key" in notice, notice
    assert "never delete either" in notice, notice
