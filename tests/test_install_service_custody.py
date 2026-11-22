# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""install-service.ps1 under ``[store].key_provider = 'host'`` (vault BACKLOG #3411, key custody S3
slice B3c).

The installer refuses the accounts the host provider refuses as the engine account, before
anything acts; lets the service account add a file to the secrets directory, where the service's
first start writes its key file from the handoff; and prints the ``provision-admin
--service-account`` step. Behaviour runs the script's own functions, extracted by AST, through
``pwsh``; the call sites are read by AST, since no test runs the script body.
"""

from __future__ import annotations

import json
import tomllib
import uuid
from pathlib import Path

import pytest

from tests.test_service_install_manifest import (
    _SCRIPT,
    _extract,
    _ok,
    _preflight_facts,
    _psq,
    _run,
    _script_text,
    _sole_call,
    _windows_only,
)

pytestmark = pytest.mark.skipif(
    _SCRIPT is None,
    reason="install-service.ps1 not locatable (off-repo / non-editable install)",
)

# (settings file text, what the installer must read as [store].key_provider)
_SETTINGS: list[tuple[str, str | None]] = [
    ('[store]\nkey_provider = "host"\n', "host"),
    ("[store]\nkey_provider = 'host'   # the custody provider\n", "host"),
    ('[api]\nport = 1\n\n[ store ]\nbackend = "sqlite"\n  key_provider="host"\n', "host"),
    ('[store]\n"key_provider" = "host"\n', "host"),
    ('store.key_provider = "host"\n[api]\nport = 1\n', "host"),
    ('store = { backend = "sqlite", key_provider = "host" }\n', "host"),
    ('﻿[store]\nkey_provider = "host"\n', "host"),
    ('[store]\nkey_provider = "auto"\n', "auto"),
    ('[store]\nbackend = "sqlite"\n', None),
    ('[store.tls]\nkey_provider = "host"\n', None),
    ('[api]\nkey_provider = "host"\n', None),
    ('[store]\n[[alerts.sinks]]\nkey_provider = "host"\n', None),
    ('[store]\n# key_provider = "host"\n', None),
    ('[store]\nother_key_provider = "host"\n', None),
    ("", None),
]


def test_the_settings_reader_finds_the_key_provider(tmp_path: Path) -> None:
    """Every positive case parses to the same value under Python's own TOML reader, so the cases
    are real settings files and not text the reader merely happens to match."""
    assert _SCRIPT is not None
    for text, expected in _SETTINGS:
        parsed = tomllib.loads(text.lstrip("﻿"))
        store = parsed.get("store", {})
        assert store.get("key_provider") == expected or expected is None, text
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


def test_the_installer_refuses_before_anything_acts_and_wires_the_custody_steps(
    tmp_path: Path,
) -> None:
    """CALL-SITE guard: the refusal reads the settings file the service is registered with, the
    service's own environment first, and throws before NSSM is resolved or the install is built;
    the secrets directory's grant follows the same reading; and the printed step names
    --service-account."""
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
    refusal = text.index("$custodyAccountProblem, and the service's settings name")
    for later in (
        "if ($BuildsInstall) {\n    # AFTER the normalization",
        "if (-not $BuildsInstall) { $NssmPath = Resolve-Nssm",
        "New-Item -ItemType Directory -Force -Path $DataDir",
    ):
        assert refusal < text.index(later), later
    # The settings file is known to exist before it is read.
    assert text.index("Service settings file not found at: $ServiceConfig") < refusal
    lock = _sole_call(facts, "Set-SecretsDirAcl")
    assert "-AddFile:$HostCustody" in lock["text"], lock["text"]
    assert "--service-account $(& $q $RunAsObjectName)" in text
    assert "$env:MEFOR_SECRETS_DIRECTORY = $(& $q $SecretsDir)" in text


@_windows_only
def test_add_file_lets_the_account_add_a_file_to_the_directory_alone(tmp_path: Path) -> None:
    """Set-SecretsDirAcl -AddFile gives the account CreateFiles on the directory, not inherited by
    its files, and the engine's own check still accepts the directory. Without the switch the
    account gets no such right (the control). Unelevated, the owner change is refused, and the
    function refuses for that alone, as in the lockdown test beside it."""
    from messagefoundry.restricted_file import broad_access_problem

    assert _SCRIPT is not None
    results = {}
    for add in (True, False):
        secrets = tmp_path / f"sd-{uuid.uuid4().hex[:8]}" / "secrets"
        secrets.mkdir(parents=True)
        switch = "$true" if add else "$false"
        body = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $dir = {_psq(str(secrets))}
  $refusal = ''
  try {{ Set-SecretsDirAcl -Path $dir -Account $me -AddFile:{switch} }} catch {{ $refusal = $_.Exception.Message }}
  $acl = Get-Acl $dir
  $add = [System.Security.AccessControl.FileSystemRights]::CreateFiles
  $mine = @($acl.Access | Where-Object {{
    try {{ $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $mySid }}
    catch {{ $false }} }})
  [pscustomobject]@{{
    refusal = $refusal
    dirAdd = @($mine | Where-Object {{ ($_.FileSystemRights -band $add) -eq $add -and
      -not ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) }}).Count
    inheritedAdd = @($mine | Where-Object {{ ($_.FileSystemRights -band $add) -eq $add -and
      ($_.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None) }}).Count
    text = (& icacls $dir | Out-String)
  }} | ConvertTo-Json -Depth 4 -Compress
"""
        try:
            got = json.loads(
                _ok(
                    _extract(
                        _SCRIPT,
                        [
                            "Set-SecretsDirAcl",
                            "Get-WellKnownBroadSids",
                            "Get-BroadAclResidue",
                            "Get-ReparsePointAncestor",
                        ],
                        body,
                    ),
                    tmp_path,
                )
                .strip()
                .splitlines()[-1]
            )
            got["engine"] = broad_access_problem(secrets, directory=True)
        finally:
            restore = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  & icacls {_psq(str(secrets))} /inheritance:e /grant "${{me}}:(OI)(CI)F" | Out-Null
"""
            _run(_extract(_SCRIPT, [], restore), tmp_path)
        results[add] = got
    on, off = results[True], results[False]
    assert on["engine"] is None, on
    assert on["dirAdd"] >= 1 and on["inheritedAdd"] == 0, on["text"]
    assert off["dirAdd"] == 0, (
        f"CONTROL FAILED: the account could add a file without -AddFile\n{off['text']}"
    )
    for got in (on, off):
        refusal = got["refusal"]
        assert not refusal or (
            "owner" in refusal and "add a file" not in refusal and "grants access" not in refusal
        ), refusal
