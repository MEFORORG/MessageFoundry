# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The service installer restricts the engine's token (vault BACKLOG #2702).

``install-service.ps1`` used to set neither a service SID type nor a ``RequiredPrivileges`` list. The
service would then have run with every privilege its account holds, and with a token that can write
wherever that account or any group it belongs to can. It now sets a short privilege list for every
account, and a ``restricted`` SID type when the service runs as its own virtual account.

What this file pins, and how:

1. **Which accounts get the restricted SID.** ``Get-ServiceSidTypeChoice`` is lifted out of the
   script by PowerShell AST and run for each account shape.
2. **Both settings are written through the Service Control Manager and read back.**
   ``Set-ServiceTokenHardening`` runs against a stand-in ``sc.exe`` and a stand-in registry. Every
   refusal has an accepting arm beside it, because a function that always throws would pass a
   refusal-only test.
3. **The script still calls them, in order.** Read from the AST, and the same guard is run over a
   copy of the script with the call deleted, where it must fail.
4. **The grant a restricted token depends on is read from the DACL**, on a real directory.
5. **The instrument the smoke leg uses can tell a hardened token from any other.**
   ``scripts/ci/service_token_probe.py`` is run against child processes started under stand-in
   tokens (``tests/_restricted_token.py``): hardened, write-restricted only, privilege-stripped
   only, and ordinary. Only the first may pass.
6. **The uninstaller reports a registration that is only marked for deletion**, which is the one
   case where the two settings outlive the uninstall.

WHAT THIS DOES NOT TEST: that the Service Control Manager builds the token the settings ask for,
and that the engine starts under it as a real service. No test here installs a service. The
``windows-service-smoke`` leg does both, and reads the running engine's token with the same probe.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import messagefoundry.service as svc
from tests._restricted_token import (
    DISABLE_MAX_PRIVILEGE,
    EVERYONE,
    WRITE_RESTRICTED,
    WRITE_RESTRICTED_SID,
    spawn_restricted,
)
from tests.test_service_install_manifest import _extract, _notice, _ok, _preflight_facts, _psq

_SCRIPT = svc.install_script_path()
_UNINSTALL = svc.uninstall_script_path()
_ROOT = Path(__file__).resolve().parents[1]
_PROBE = _ROOT / "scripts" / "ci" / "service_token_probe.py"

pytestmark = pytest.mark.skipif(
    _SCRIPT is None,
    reason="install-service.ps1 not locatable (off-repo / non-editable install)",
)

_windows_only = pytest.mark.skipif(
    not sys.platform.startswith("win"), reason="Windows tokens and DACLs"
)

_PRIVILEGE = "SeChangeNotifyPrivilege"


def _last_json(stdout: str) -> Any:
    return json.loads(stdout.strip().splitlines()[-1])


# --- 1. which accounts get the restricted SID ------------------------------------------------------
# The cases run in the `token_report` fixture below, in the one pwsh process section 2 uses.


def test_only_the_services_own_virtual_account_gets_the_restricted_sid(
    token_report: dict[str, Any],
) -> None:
    """The default account is restricted. LocalSystem, a gMSA, a named user and some OTHER service's
    virtual account are not, and each says why: their grants name a SID the restricted token does
    not count. The opt-out switch is the only way the default account is left unrestricted."""
    got = token_report["choices"]
    assert got["default"] == {"SidType": "restricted", "Reason": ""}
    assert got["default-case"]["SidType"] == "restricted", (
        "an account name is not case-sensitive; a lower-case spelling of the service's own virtual "
        "account must not fall through to the unrestricted branch"
    )
    assert got["skip"] == {"SidType": "none", "Reason": "switch"}
    for name in ("localsystem", "gmsa", "user", "other-virtual", "other-skip"):
        assert got[name] == {"SidType": "none", "Reason": "account"}, name


# --- 2. set through the SCM, and read back ---------------------------------------------------------

_TOKEN_FNS = ["Get-ServiceSidTypeChoice", "Get-ServiceTokenProblem", "Set-ServiceTokenHardening"]

# Defined AFTER the lifted functions, so they win. `sc.exe` is a function here: PowerShell resolves a
# function before an application, on every host, so no real sc.exe runs and nothing is registered.
# The stand-in applies a change to $registry only when it "succeeds", the way the SCM does.
_TOKEN_STUBS = r"""
  $registry = @{}
  $scExit = 0
  $scApplies = $true
  $scSetsExit = $true
  $scCalls = [Collections.Generic.List[string]]::new()
  $disabled = [Collections.Generic.List[string]]::new()
  function Set-Service { param($Name, $StartupType, $ErrorAction) $disabled.Add("$Name=$StartupType") }
  function Get-ItemProperty {
    param($LiteralPath, $ErrorAction)
    $name = Split-Path -Leaf $LiteralPath
    if (-not $registry.ContainsKey($name)) { throw "no such key: $LiteralPath" }
    [pscustomobject]$registry[$name]
  }
  function sc.exe {
    $scCalls.Add(($args -join ' '))
    if ($scSetsExit) { $global:LASTEXITCODE = $scExit }
    if ($scExit -ne 0) { '[SC] ChangeServiceConfig2 FAILED'; return }
    if (-not $scApplies) { return }
    $verb, $name, $value = $args
    if ($verb -eq 'sidtype') {
      if ($value -eq 'restricted') { $registry[$name].ServiceSidType = 3 }
      else { $registry[$name].Remove('ServiceSidType') }
    }
    if ($verb -eq 'privs') { $registry[$name].RequiredPrivileges = @($value -split '/') }
  }
  function Invoke-Arm([string]$Key, [hashtable]$Start, [scriptblock]$Action) {
    # A local, on purpose. The stand-ins above read it through PowerShell's dynamic scope, and
    # they change the table in place, so this function reads back what they did.
    $registry = @{ MessageFoundry = $Start }
    $scCalls.Clear(); $disabled.Clear()
    # A REAL zero is left behind on purpose: it is the one stale value that would let a check that
    # forgot to clear the variable read a launch that never happened as a success.
    $global:LASTEXITCODE = 0
    $threw = ''
    try { & $Action } catch { $threw = $_.Exception.Message }
    $res[$Key] = [pscustomobject]@{
      threw = $threw; calls = @($scCalls); disabled = @($disabled)
      sid = $registry.MessageFoundry.ServiceSidType
      privs = @($registry.MessageFoundry.RequiredPrivileges)
    }
  }
"""

_TOKEN_CASES = r"""
  $res = [ordered]@{}
  $ask = @{ ServiceName = 'MessageFoundry'; SidType = 'restricted'; Privileges = 'SeChangeNotifyPrivilege' }
  $askNone = @{ ServiceName = 'MessageFoundry'; SidType = 'none'; Privileges = 'SeChangeNotifyPrivilege' }
  $harden = { Set-ServiceTokenHardening @ask }
  $relax = { Set-ServiceTokenHardening @askNone }
  Invoke-Arm 'fresh' @{} $harden
  # A rerun that moves the service off its own virtual account: restricted must not be left behind.
  Invoke-Arm 'relax' @{ ServiceSidType = 3; RequiredPrivileges = @('SeChangeNotifyPrivilege') } $relax
  $scExit = 5
  Invoke-Arm 'refused' @{} $harden
  $scExit = 0; $scApplies = $false
  Invoke-Arm 'not-applied' @{} $harden
  $scApplies = $true; $scSetsExit = $false
  Invoke-Arm 'never-ran' @{} $harden
  $scSetsExit = $true
  # --- the read-back by itself
  $registry = @{ MessageFoundry = @{ ServiceSidType = 3; RequiredPrivileges = @('SeChangeNotifyPrivilege') } }
  $res['read-good'] = Get-ServiceTokenProblem @ask
  $registry.MessageFoundry.RequiredPrivileges = @('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege')
  $res['read-extra'] = Get-ServiceTokenProblem @ask
  $registry.MessageFoundry = @{ ServiceSidType = 1; RequiredPrivileges = @('SeChangeNotifyPrivilege') }
  $res['read-unrestricted'] = Get-ServiceTokenProblem @ask
  $registry.MessageFoundry = @{ ServiceSidType = 0; RequiredPrivileges = @('SeChangeNotifyPrivilege') }
  $res['read-none-zero'] = Get-ServiceTokenProblem @askNone
  $registry.MessageFoundry = @{ ServiceSidType = 3 }
  $res['read-no-list'] = Get-ServiceTokenProblem @ask
  $registry = @{}
  $res['read-missing'] = Get-ServiceTokenProblem @ask
  # --- which accounts get the restricted SID (section 1)
  $choices = [ordered]@{}
  $accounts = [ordered]@{
    'default'       = @{ ServiceAccount = 'NT SERVICE\MessageFoundry' }
    'default-case'  = @{ ServiceAccount = 'nt service\messagefoundry' }
    'skip'          = @{ ServiceAccount = 'NT SERVICE\MessageFoundry'; Skip = $true }
    'localsystem'   = @{ ServiceAccount = '' }
    'gmsa'          = @{ ServiceAccount = 'CORP\mefor-svc$' }
    'user'          = @{ ServiceAccount = '.\mefor' }
    'other-virtual' = @{ ServiceAccount = 'NT SERVICE\SomethingElse' }
    'other-skip'    = @{ ServiceAccount = 'CORP\mefor-svc$'; Skip = $true }
  }
  foreach ($case in $accounts.Keys) {
    $params = $accounts[$case]
    $choices[$case] = Get-ServiceSidTypeChoice -ServiceName 'MessageFoundry' @params
  }
  $res['choices'] = $choices
  $res | ConvertTo-Json -Depth 6 -Compress
"""


@pytest.fixture(scope="module")
def token_report(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Every arm of sections 1 and 2, in ONE pwsh process (each spawn costs about a second)."""
    assert _SCRIPT is not None
    tmp_path = tmp_path_factory.mktemp("token")
    got: dict[str, Any] = _last_json(
        _ok(_extract(_SCRIPT, _TOKEN_FNS, _TOKEN_STUBS + _TOKEN_CASES), tmp_path)
    )
    return got


def test_a_fresh_install_sets_the_sid_type_and_the_privilege_list(
    token_report: dict[str, Any],
) -> None:
    """THE ACCEPTING ARM. Both settings go through sc.exe, both are read back, and nothing throws."""
    fresh = token_report["fresh"]
    assert fresh["threw"] == "", fresh
    assert fresh["calls"] == [
        "sidtype MessageFoundry restricted",
        f"privs MessageFoundry {_PRIVILEGE}",
    ]
    assert fresh["sid"] == 3 and fresh["privs"] == [_PRIVILEGE]
    assert fresh["disabled"] == [], "a successful install must not disable the service"


def test_a_rerun_takes_the_restricted_sid_back_off(token_report: dict[str, Any]) -> None:
    """A rerun that moves the service to another account writes ``none`` over ``restricted``, and
    keeps the privilege list. Leaving the SID type alone would keep a restricted token on an account
    whose grants do not name the service."""
    relax = token_report["relax"]
    assert relax["threw"] == "", relax
    assert relax["calls"][0] == "sidtype MessageFoundry none"
    assert relax["sid"] is None and relax["privs"] == [_PRIVILEGE]


def test_a_refused_change_stops_the_install_and_disables_the_service(
    token_report: dict[str, Any],
) -> None:
    """sc.exe exiting non-zero is a throw that names the call and the exit code, and the service is
    set to Disabled first so it cannot start at the next boot with a token nobody chose."""
    refused = token_report["refused"]
    assert "sc.exe sidtype MessageFoundry restricted failed (exit 5)" in refused["threw"], refused
    assert "ChangeServiceConfig2 FAILED" in refused["threw"], "sc.exe's own words were dropped"
    assert refused["disabled"] == ["MessageFoundry=Disabled"]
    assert len(refused["calls"]) == 1, "the privilege list was still set after the SID type failed"


def test_a_change_that_did_not_take_is_caught_by_the_read_back(
    token_report: dict[str, Any],
) -> None:
    """sc.exe exits 0 and the registration is unchanged. Only the read-back can see that."""
    arm = token_report["not-applied"]
    assert "although sc.exe reported success" in arm["threw"], arm
    assert "its SID type reads 0, not 3 (restricted)" in arm["threw"]
    assert "its privilege list reads nothing" in arm["threw"]
    assert arm["disabled"] == ["MessageFoundry=Disabled"]


def test_an_sc_that_never_ran_is_not_read_as_success(token_report: dict[str, Any]) -> None:
    """A launch that fails writes no exit code. The variable held a real 0 from an earlier command,
    so a check that did not clear it first would pass here."""
    arm = token_report["never-ran"]
    assert "did not run (it left no exit code)" in arm["threw"], arm
    assert arm["disabled"] == ["MessageFoundry=Disabled"]


def test_the_read_back_names_what_it_found(token_report: dict[str, Any]) -> None:
    assert token_report["read-good"] == "", "CONTROL: a registration as asked must read clean"
    assert token_report["read-none-zero"] == "", "a SID type stored as 0 is 'none'"
    assert "SeImpersonatePrivilege" in token_report["read-extra"], (
        "a privilege beyond the list was not reported: the list would not be the one this script set"
    )
    assert "its SID type reads 1, not 3" in token_report["read-unrestricted"], (
        "an UNRESTRICTED SID type passed as restricted; it adds the service SID and restricts nothing"
    )
    assert "its privilege list reads nothing" in token_report["read-no-list"]
    assert "could not be read" in token_report["read-missing"]


# --- 3. the script still calls them, in order ------------------------------------------------------


def _wiring_problems(facts: dict[str, Any]) -> list[str]:
    """Why the top level of install-service.ps1 does not harden the token, from its AST facts."""
    commands = facts["commands"]

    def calls(name: str) -> list[dict[str, Any]]:
        return [c for c in commands if c["name"] == name]

    problems = []
    setters = calls("Set-ServiceTokenHardening")
    if len(setters) != 1:
        return [f"expected one Set-ServiceTokenHardening call, found {len(setters)}"]
    setter = setters[0]
    for needle in ("$SidChoice.SidType", "-Privileges $ServicePrivileges"):
        if needle not in setter["text"]:
            problems.append(f"the call does not pass {needle}: {setter['text']}")
    accounts = calls("Set-ServiceAccount")
    if not accounts or setter["start"] < max(c["start"] for c in accounts):
        problems.append("the token is set before the run-as account it depends on")
    choices = calls("Get-ServiceSidTypeChoice")
    if len(choices) != 1 or "-Skip:$SkipRestrictedServiceSid" not in choices[0]["text"]:
        problems.append("the SID type is not chosen from the account and the opt-out switch")
    elif "-ServiceAccount $ServiceAccount" not in choices[0]["text"]:
        problems.append("the SID type choice is not handed the account that carries the grants")
    lists = [a for a in facts["assignments"] if a["lhs"] == "ServicePrivileges"]
    if len(lists) != 1 or lists[0]["rhsText"] != f'@("{_PRIVILEGE}")':
        problems.append(
            f"$ServicePrivileges is not exactly {_PRIVILEGE}: {[a['rhsText'] for a in lists]}"
        )
    grants = calls("Get-WriteGrantProblem")
    lockdown = calls("Set-SecureDataDirAcl")
    if not grants or not lockdown or grants[0]["start"] < lockdown[0]["start"]:
        problems.append("the service's grant is not read back after the data-directory lockdown")
    rhs = {
        a["lhs"]: a["rhsText"]
        for a in facts["assignments"]
        if a["lhs"] in ("storeDir", "writeDirs")
    }
    if "$DbPath" not in rhs.get("storeDir", "") or rhs.get("writeDirs") != "$storeDir":
        problems.append(
            "the store's own directory is not read back, so a -DbPath elsewhere is missed"
        )
    return problems


def test_the_installer_hardens_the_token_after_it_sets_the_account(tmp_path: Path) -> None:
    assert _wiring_problems(_preflight_facts(tmp_path)) == []


@pytest.mark.parametrize(
    ("old", "new", "expect"),
    [
        (
            "\nSet-ServiceTokenHardening -ServiceName",
            "\n# Set-ServiceTokenHardening",
            "expected one",
        ),
        (" `\n    -Skip:$SkipRestrictedServiceSid", "", "opt-out switch"),
        (
            '$ServicePrivileges = @("SeChangeNotifyPrivilege")',
            '$ServicePrivileges = @("SeChangeNotifyPrivilege", "SeImpersonatePrivilege")',
            "is not exactly",
        ),
        ("$problem = Get-WriteGrantProblem -Path $dir", "$problem = '' # -Path $dir", "read back"),
        ("$writeDirs += $storeDir", "", "store's own directory"),
    ],
    ids=["call-removed", "switch-unwired", "privilege-added", "grant-not-read", "store-not-read"],
)
def test_the_wiring_guard_fails_when_a_piece_is_changed(
    tmp_path: Path, old: str, new: str, expect: str
) -> None:
    """THE CONTROL. Each piece the guard above depends on is changed in a copy of the script, and
    the guard must then name it. A guard that cannot fail would pass on a script that sets nothing."""
    assert _SCRIPT is not None
    source = _SCRIPT.read_text(encoding="utf-8")
    assert source.count(old) == 1, f"CONTROL FAILED: {old!r} is not in the script exactly once"
    mutated = tmp_path / "install-service.ps1"
    mutated.write_text(source.replace(old, new), encoding="utf-8")
    problems = _wiring_problems(_preflight_facts(tmp_path, script=mutated))
    assert any(expect in p for p in problems), problems


def test_the_opt_out_is_a_switch_and_so_defaults_to_the_hardened_token() -> None:
    """A [switch] is off unless it is passed, which is what makes the restricted SID the default.
    The same name must be in both documents that list the installer's loosening switches."""
    assert _SCRIPT is not None
    assert "[switch]$SkipRestrictedServiceSid" in _SCRIPT.read_text(encoding="utf-8")
    for doc in ("SERVICE.md", "DANGEROUS-FUNCTIONALITY.md"):
        text = (_ROOT / "docs" / doc).read_text(encoding="utf-8")
        assert "-SkipRestrictedServiceSid" in text, f"docs/{doc} does not name the opt-out switch"
        assert "-AllowLocalSystem" in text, f"CONTROL FAILED: docs/{doc} lists no installer switch"


# --- 4. the grant a restricted token depends on is read from the DACL ------------------------------


@_windows_only
def test_the_services_own_grant_is_read_from_the_dacl(tmp_path: Path) -> None:
    """Modify granted by name reads clean. Read-only, and no entry at all, are both named. Run on a
    real directory, with the test's own account standing in for the service's."""
    assert _SCRIPT is not None
    names = ("modify", "read", "none", "only", "generic")
    dirs = {name: tmp_path / f"{name}-{uuid.uuid4().hex[:8]}" for name in names}
    table = "; ".join(f"{name} = {_psq(str(path))}" for name, path in dirs.items())
    for d in dirs.values():
        d.mkdir()
    # THE RESTORE IS IN A `finally`. Each directory has inheritance stripped, and one drops this
    # account altogether; left like that, pytest's tmp_path cleanup fails on some LATER run.
    body = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $dirs = @{{ {table} }}
  $out = [ordered]@{{}}
  try {{
    & icacls $dirs.modify /inheritance:r /grant:r "${{me}}:(OI)(CI)M" '*S-1-5-18:(OI)(CI)F' | Out-Null
    & icacls $dirs.read /inheritance:r /grant:r "${{me}}:(OI)(CI)RX" '*S-1-5-18:(OI)(CI)F' | Out-Null
    & icacls $dirs.none /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)M' | Out-Null
    & icacls $dirs.only /inheritance:r /grant:r "${{me}}:M" '*S-1-5-18:(OI)(CI)F' | Out-Null
    & icacls $dirs.generic /inheritance:r /grant:r "${{me}}:(OI)(CI)(GA)" '*S-1-5-18:(OI)(CI)F' | Out-Null
    foreach ($name in $dirs.Keys) {{
      $out[$name] = Get-WriteGrantProblem -Path $dirs[$name] -Principal $me
    }}
    $out | ConvertTo-Json -Compress
  }} finally {{
    foreach ($d in $dirs.Values) {{ & icacls $d /inheritance:e /grant "${{me}}:(OI)(CI)F" | Out-Null }}
  }}
"""
    got = _last_json(_ok(_extract(_SCRIPT, ["Get-WriteGrantProblem"], body), tmp_path))
    assert got["modify"] == "", f"CONTROL: a Modify grant by name must read clean: {got['modify']}"
    assert "Modify by name" in got["read"], "a read-only grant passed as a write grant"
    assert "Modify by name" in got["none"], (
        "a directory that grants only Users passed. A restricted token does not count that group."
    )
    assert "Modify by name" in got["only"], (
        "a grant on the folder alone passed. What the service creates there would not inherit it, "
        "so it could create its store and be refused on it at the next start."
    )
    # Windows stores a generic-rights grant as a PAIR: a folder-only entry and an inherit-only one.
    # Neither half is a whole grant, and together they are. A reader that wants one entry to carry
    # both would warn about a directory the service can write.
    assert got["generic"] == "", (
        f"a grant stored as a split pair read as no grant: {got['generic']}"
    )


# --- 5. the smoke leg's instrument can tell a hardened token from any other ------------------------


def _probe() -> ModuleType:
    spec = importlib.util.spec_from_file_location("service_token_probe", _PROBE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stand_in_sids(probe: ModuleType) -> tuple[str, list[str]]:
    """This account's SID, standing in for the service SID, and the restricting list the Service
    Control Manager is documented to build around it."""
    me = probe.read_token(None)
    logon = [g["sid"] for g in me["groups"] if g["logon_id"]]
    return me["user"], [me["user"], EVERYONE, WRITE_RESTRICTED_SID, *logon]


_SLEEP = [sys.executable, "-c", "import time; time.sleep(60)"]


@_windows_only
@pytest.mark.parametrize(
    ("flags", "restrict", "expect"),
    [
        (WRITE_RESTRICTED | DISABLE_MAX_PRIVILEGE, True, []),
        (WRITE_RESTRICTED, True, ["not exactly"]),
        (DISABLE_MAX_PRIVILEGE, False, ["not write-restricted", "restricting list"]),
        # Restricting SIDs without the write-restricted flag: a FULLY restricted token, which is a
        # different thing. It must not pass as the write-restricted one a service gets.
        (DISABLE_MAX_PRIVILEGE, True, ["not write-restricted"]),
    ],
    ids=["hardened", "privileges-kept", "not-restricted", "fully-restricted"],
)
def test_the_reader_tells_a_hardened_token_from_the_others(
    flags: int, restrict: bool, expect: list[str]
) -> None:
    """Four real child processes, four tokens, and only the hardened one passes. The other three
    are the controls: each fails for its own reason, so a reader that reported every token as
    hardened, or a rule that accepted anything, is caught here and not on a hosted runner."""
    probe = _probe()
    service_sid, restricting = _stand_in_sids(probe)
    child = spawn_restricted(_SLEEP, restricting_sids=restricting if restrict else [], flags=flags)
    try:
        token = probe.read_token(child.pid)
    finally:
        child.kill()
    problems = probe.token_problems(token, service_sid=service_sid, privileges=[_PRIVILEGE])
    assert len(problems) == len(expect), problems
    for needle in expect:
        assert any(needle in p for p in problems), (needle, problems)


@_windows_only
def test_an_ordinary_process_does_not_pass_as_hardened() -> None:
    """The control the leg itself relies on: its own shell must read as NOT hardened."""
    probe = _probe()
    service_sid, _ = _stand_in_sids(probe)
    token = probe.read_token(None)
    problems = probe.token_problems(token, service_sid=service_sid, privileges=[_PRIVILEGE])
    assert any("not write-restricted" in p for p in problems), problems


@_windows_only
def test_a_restricted_token_is_refused_where_only_a_group_grants_it(tmp_path: Path) -> None:
    """The ``inside`` mode, run under a stand-in for the hardened token, and then under an ordinary
    one. One directory grants this account by name. The other grants Users and Authenticated Users
    only, the way a File connection's directory often does.

    The hardened run writes the first and is refused on the second, and the rule passes it. The
    ordinary run writes BOTH, and the rule must fail it: that is what shows the refusal comes from
    the restriction and not from the directory.
    """
    # Imported here: that module is a test file too, and only this Windows-only test needs it. Its
    # helper also removes an explicit OWNER RIGHTS entry, which a hosted runner's temp directory can
    # carry and which would let the child write as the owner of the directory.
    from tests.test_store_trio_acl import _build_dir_dacl

    probe = _probe()
    service_sid, restricting = _stand_in_sids(probe)
    granted, denied = tmp_path / "granted", tmp_path / "denied"
    granted.mkdir()
    denied.mkdir()
    rule = {"service_sid": service_sid, "privileges": [_PRIVILEGE]}
    try:
        _build_dir_dacl(
            granted, f"*{service_sid}:(OI)(CI)M", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"
        )
        _build_dir_dacl(
            denied, *(f"*{sid}:(OI)(CI)M" for sid in probe.BROAD_GROUPS), "*S-1-5-18:(OI)(CI)F"
        )
        argv = [sys.executable, str(_PROBE), "inside", "--granted-dir", str(granted)]
        argv += ["--denied-dir", str(denied), "--report"]

        # The two runs write different files, so the ordinary one runs while the hardened one does.
        hardened_report, ordinary_report = granted / "hardened.json", granted / "ordinary.json"
        child = spawn_restricted([*argv, str(hardened_report)], restricting_sids=restricting)
        try:
            subprocess.run([*argv, str(ordinary_report)], check=True, timeout=120)
        finally:
            exit_code = child.wait(120)
        assert exit_code == 0
        hardened = json.loads(hardened_report.read_text(encoding="utf-8"))
        ordinary = json.loads(ordinary_report.read_text(encoding="utf-8"))
    finally:
        for d in (granted, denied):
            subprocess.run(
                ["icacls", str(d), "/inheritance:e", "/grant", f"*{service_sid}:(OI)(CI)F"],
                capture_output=True,
            )

    assert probe.inside_problems(hardened, **rule) == [], json.dumps(hardened, indent=2)
    assert hardened["granted"]["wrote"] and not hardened["denied"]["wrote"]
    # The engine's alternate-credential path (transports/wincred.py) under the stand-in token: the
    # logon and the impersonation both work with no privilege but SeChangeNotifyPrivilege.
    assert hardened["wincred"]["ok"], hardened["wincred"]
    assert hardened["wincred"]["thread_token"]["impersonation_level"] == 2

    assert ordinary["denied"]["wrote"], (
        "CONTROL FAILED: an ordinary token could not write the group-granted directory either, so "
        "the hardened run's refusal there says nothing about the restriction"
    )
    problems = probe.inside_problems(ordinary, **rule)
    assert any("grants only Users" in p for p in problems), problems
    assert any("not write-restricted" in p for p in problems), problems


def _passing_report() -> dict[str, Any]:
    """A report shaped like the one a hardened service writes. No Windows call is made."""
    wrote = {"directory": "d", "wrote": True, "errno": None, "error": None}
    token = {
        "write_restricted": True,
        "restricting_sids": ["S-1-5-80-1", "S-1-1-0"],
        "privileges": [_PRIVILEGE],
        "groups": [{"sid": "S-1-5-11", "enabled": True, "deny_only": False, "logon_id": False}],
    }
    thread = {"impersonation_level": 2, "write_restricted": False}
    return {
        "token": token,
        "granted": dict(wrote),
        "denied": {**wrote, "wrote": False, "errno": 13, "error": "PermissionError"},
        "temp": dict(wrote),
        "wincred": {
            "ran": True,
            "ok": True,
            "error": None,
            "thread_token": thread,
            "granted": dict(wrote),
            "denied": dict(wrote),
        },
    }


def _broken(path: list[str], value: Any) -> dict[str, Any]:
    report = _passing_report()
    node: Any = report
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return report


@pytest.mark.parametrize(
    ("path", "value", "expect"),
    [
        (["denied", "wrote"], True, "grants only Users"),
        # errno 2: the directory was not there. That is a failed write and not a refused one.
        (["denied", "errno"], 2, "not as a refusal"),
        (["granted", "wrote"], False, "could not write d"),
        (["token", "privileges"], [_PRIVILEGE, "SeImpersonatePrivilege"], "not exactly"),
        (["token", "groups"], [], "CONTROL FAILED"),
        (["wincred", "ok"], False, "failed at the logon stage"),
        # The stage is part of the reading: a failure after the logon must not blame the logon.
        (
            ["wincred"],
            {"ran": True, "ok": False, "stage": "under the credential", "error": "x"},
            "failed at the under the credential stage",
        ),
        # Windows answers a refused impersonation with an identification-level token and a success.
        (["wincred", "thread_token", "impersonation_level"], 1, "refused the impersonation"),
        (["wincred", "granted", "wrote"], False, "under the alternate credential"),
        (["probe_errors"], {"token": "OSError: 5"}, "the token step failed"),
    ],
)
def test_the_rule_fails_each_way_a_report_can_be_wrong(
    path: list[str], value: Any, expect: str
) -> None:
    """Runs on every host: the rule is a plain function over a report. The passing report is the
    control, and each case changes ONE reading in it."""
    probe = _probe()
    rule = {"service_sid": "S-1-5-80-1", "privileges": [_PRIVILEGE]}
    assert probe.inside_problems(_passing_report(), **rule) == [], "CONTROL: the base report passes"
    problems = probe.inside_problems(_broken(path, value), **rule)
    assert any(expect in p for p in problems), problems


def test_an_unwritable_temp_directory_is_a_note_and_not_a_failure() -> None:
    """The temporary directory says what the engine can still do, not whether the token is
    restricted. Its first hosted run never reached it, so it must not be able to fail the leg on a
    guess. It is still reported: a failure is a note, and a success is no note at all."""
    probe = _probe()
    rule = {"service_sid": "S-1-5-80-1", "privileges": [_PRIVILEGE]}
    failed = _broken(["temp"], {"directory": "t", "wrote": False, "errno": 13, "error": "denied"})
    assert probe.inside_problems(failed, **rule) == []
    assert any("temporary directory (t)" in note for note in probe.inside_notes(failed))
    assert probe.inside_notes(_passing_report()) == [], "CONTROL: a writable one leaves no note"


def test_a_report_with_a_step_missing_is_not_a_pass() -> None:
    """A step that never ran left nothing to judge. Each one is named, and an empty report fails on
    all of them, so a probe that died at once cannot read as a service that passed."""
    probe = _probe()
    rule = {"service_sid": "S-1-5-80-1", "privileges": [_PRIVILEGE]}
    assert len(probe.inside_problems({}, **rule)) == len(probe.INSIDE_STEPS)
    for step in probe.INSIDE_STEPS:
        report = _passing_report()
        del report[step]
        assert probe.inside_problems(report, **rule) == [f"the report has no {step} reading"]


def _smoke_step_script(name_starts: str) -> str:
    """The run script of one windows-service-smoke step, without its comment lines.

    Read from the parsed workflow, so a needle cannot be satisfied by a YAML comment above the step
    or by a comment inside it. Imported here: without PyYAML that module skips whoever imports it.
    """
    from tests._workflow_contexts import jobs_of

    steps = jobs_of("ci.yml")["windows-service-smoke"]["steps"]
    found = [s for s in steps if str(s.get("name", "")).startswith(name_starts)]
    assert len(found) == 1, f"expected one step named {name_starts!r}, found {len(found)}"
    name = str(found[0]["name"])
    assert name.count("(") == name.count(")"), (
        f"the step name is cut short; an unquoted ' #' starts a YAML comment: {name!r}"
    )
    lines = str(found[0]["run"]).splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith("#"))


def _sample_file_directories() -> set[str]:
    """The top-level directory of every File connection in samples/config, read from the syntax
    tree so a call split over lines is still found. A directory that is not a literal fails here,
    by name, and not later as a write refusal on a hosted runner."""
    found = set()
    for module in sorted((_ROOT / "samples" / "config").glob("*.py")):
        for node in ast.walk(ast.parse(module.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "File"):
                continue
            for keyword in node.keywords:
                if keyword.arg != "directory":
                    continue
                assert isinstance(keyword.value, ast.Constant), (
                    f"{module.name}: a File directory that is not a literal; add its directory to "
                    "the smoke leg's grant list by hand and teach this test to read it"
                )
                found.add(str(keyword.value.value).removeprefix("./").split("/")[0])
    return found


def test_the_smoke_leg_grants_every_directory_the_samples_graph_writes() -> None:
    """The leg grants the service by name on the directories the samples graph's File connections
    use, because a restricted token does not count a grant to Users. The list in ci.yml is a hand
    copy of those connections, so a new one would fail far from its cause. This ties the two."""
    found = _sample_file_directories()
    assert found, "CONTROL FAILED: no File connection was found in samples/config"
    toml = (_ROOT / "samples" / "config" / "connections.toml").read_text(encoding="utf-8")
    assert not [line for line in toml.splitlines() if line.lstrip().startswith("directory")], (
        "samples/config/connections.toml now declares a directory; this test reads the .py modules "
        "only, so add that directory to the smoke leg's grant list and to this test"
    )
    script = _smoke_step_script("Install the service")
    listed = script.split("foreach ($d in ", 1)[1].split(")", 1)[0]
    assert {d.strip().strip('"') for d in listed.split(",")} == found, (
        f"the smoke leg grants [{listed}], and the samples graph's File connections use {sorted(found)}"
    )


def test_the_smoke_leg_reads_the_token_it_asked_for() -> None:
    """The leg must read the registration back, read the running engine's token, and run the probe
    as the service. This checks the commands are in the step's run script; the leg's own result is
    the reading.

    THIS CANNOT BE DEMONSTRATED FROM A PULL REQUEST: the job runs on a schedule, on dispatch and in
    the merge queue, and a pull_request event skips it.
    """
    script = _smoke_step_script("Verify the service token is restricted")
    for needle in (
        "& sc.exe qsidtype MessageFoundry",
        "& sc.exe qprivs MessageFoundry",
        # The leg names the privilege itself and does not read it from the installer: a list the
        # installer widened would otherwise pass its own check.
        f'$privilege = "{_PRIVILEGE}"',
        '$probe = Join-Path $PWD "scripts\\ci\\service_token_probe.py"',
        "& python $probe check-read --service-sid $serviceSid --privilege $privilege --control-pid $PID",
        '$_.Name -eq "python.exe"',
        "& python $probe check-inside --report $report --service-sid $serviceSid --privilege $privilege",
    ):
        assert needle in script, f"the step no longer runs {needle!r}"
    # CONTROL: the comment lines are really gone, so a needle cannot be met by one.
    assert "# ---" not in script and "CONTROL" in script


def test_the_smoke_leg_judges_the_probe_start_by_its_report() -> None:
    """The first hosted run of this step failed on the exit code of the start command, on both
    runners (merge-group run 36981542600). The service holds START_PENDING for its AppThrottle and
    the command gives up first, so it exits 1 on a start that works: the same run printed the same
    line for the engine's own start. The start is judged by the report the probe writes.

    So no line may read the exit code of a start, and the step must still fail without a report.
    The set lines are the control: their exit code is real, and each one is still read.
    """
    lines = _smoke_step_script("Verify the service token is restricted").splitlines()
    follows = {
        verb: [
            lines[i + 1].strip()
            for i, line in enumerate(lines[:-1])
            if f'nssm.exe" {verb} MessageFoundry' in line
        ]
        for verb in ("start", "set")
    }
    assert len(follows["start"]) == 1 and len(follows["set"]) == 2, follows
    assert not follows["start"][0].startswith("Assert-Native"), (
        f"the step reads the exit code of the start again: {follows['start'][0]}"
    )
    assert all(line.startswith("Assert-Native") for line in follows["set"]), (
        f"CONTROL FAILED: a set command's exit code is no longer read: {follows['set']}"
    )
    script = "\n".join(lines)
    assert "if (-not (Test-Path -LiteralPath $report))" in script and "wrote no report" in script, (
        "the step no longer fails when the probe wrote no report, so nothing judges the start"
    )


# --- 6. the uninstaller and a registration that is only marked for deletion ------------------------


def test_the_uninstaller_reports_a_registration_that_outlived_the_removal(tmp_path: Path) -> None:
    """The SID type and the privilege list live on the registration. When Windows has only marked
    the service for deletion they are still there, and the inventory says so. When the key is gone
    there is nothing to report, and the line must be absent."""
    facts: dict[str, object] = {"ServiceName": "MessageFoundry", "DataDir": "C:\\mefor-data"}
    pending = _notice(tmp_path, {**facts, "RegistrationPending": True})
    gone = _notice(tmp_path, facts)
    assert "marked for deletion" in pending and "privilege list" in pending, pending
    assert "marked for deletion" not in gone
    assert "Data directory" in gone, "CONTROL FAILED: the notice printed nothing"


def test_the_uninstaller_looks_for_the_key_after_it_removes_the_service(tmp_path: Path) -> None:
    """Read from the AST: the key is tested AFTER sc.exe delete, and that reading is what the
    inventory is given. Tested before the removal, the key is always there."""
    assert _UNINSTALL is not None
    cmds = _preflight_facts(tmp_path, script=_UNINSTALL)["commands"]
    delete = [c for c in cmds if c["name"] == "sc.exe" and "delete" in c["text"]]
    probe = [c for c in cmds if c["name"] == "Test-Path" and "$svcKey" in c["text"]]
    notice = [c for c in cmds if c["name"] == "Get-UninstallResidueNotice"]
    assert len(delete) == 1 and probe and len(notice) == 1, (delete, probe, notice)
    # More than one read: the key is given a few seconds to go. Every one of them is after the
    # removal and before the inventory.
    assert all(delete[0]["start"] < c["start"] < notice[0]["start"] for c in probe), probe
    assert "-RegistrationPending:$registrationPending" in notice[0]["text"]
