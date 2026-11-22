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
    ("", None),
]


def test_the_settings_reader_finds_the_key_provider(tmp_path: Path) -> None:
    """Every case is a real settings file whose [store].key_provider, under Python's own TOML
    reader, is the value the installer must read."""
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
    got = json.loads(_ok(_extract(_SCRIPT, ["Get-SettingsKeyProvider"], body), tmp_path))
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
    denies the account and Users add-file. The account ends with read and add-file on the directory alone,
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
    NSSM is resolved, made restricted before the service is registered, restricted after the
    secrets directory once the account resolves, and named to the service. Each step sits under
    the host provider's branch, and -CustodyDir is refused without it."""
    facts = _preflight_facts(tmp_path)
    # Read by line: the call offsets count the file's own line endings, which read_text folds.
    text = _script_text()
    check = _sole_call_on(facts, "Get-LockPathProblem", "-Path $CustodyDir")
    assert "-AllowMissing" in check["text"] and "$SecretsDir" in check["text"], check["text"]
    sharers = _sole_call_on(facts, "Get-OtherServiceNamingPath", "-Path $CustodyDir")
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
    assert host["start"] < check["start"] < sharers["start"] < nssm
    assert creates["start"] < registered < secrets_lock["start"] < lock["start"] < named["start"]
    # Each act is inside an `if ($HostCustody)` block.
    lines = text.splitlines()
    for call in (creates, lock, named):
        at = call["line"] - 1  # 1-based in the parser's extent
        head = max(i for i in range(at) if lines[i].startswith("if ($HostCustody) {"))
        end = next(i for i in range(head, len(lines)) if lines[i] == "}")
        assert head < at < end, call["text"]
    assert "-CustodyDir is used only under [store].key_provider = 'host'" in text
