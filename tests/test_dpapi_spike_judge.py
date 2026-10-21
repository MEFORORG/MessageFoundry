# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DPAPI spike's judge may not turn a broken instrument into an answer (vault BACKLOG #3411).

``scripts/ci/dpapi_spike_worker.py`` runs as two Windows services on a hosted runner and reports
what DPAPI did. :func:`judge_reports` turns those reports into the three answers the key-custody
draft asks for. The danger in a spike is an answer the instrument never earned: a garbage blob
"refused" to the second account, a service that ran as the runner's administrator or without the
installer's token, a restart that was the same process. So every case below hands the judge
reports where one control fails and checks the answer becomes INCONCLUSIVE, and the all-good case
is the positive control that the judge can say YES at all.

These run anywhere: the judge reads dictionaries and files, and no case calls DPAPI.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[1]
_WORKER = _REPO / "scripts" / "ci" / "dpapi_spike_worker.py"
_RIG = _REPO / "scripts" / "ci" / "dpapi_spike.ps1"
_INSTALLER = _REPO / "scripts" / "service" / "install-service.ps1"
OWNER_SID = "S-1-5-80-1111111111-2222222222-3333333333-4444444444-555555555"
OTHER_SID = "S-1-5-21-1000000001-1000000002-1000000003-1001"
SYSTEM_SID = "S-1-5-18"
ADMINS = "S-1-5-32-544"
PRIVILEGES = ["SeChangeNotifyPrivilege"]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dpapi_spike_worker", _WORKER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["dpapi_spike_worker"] = module
    spec.loader.exec_module(module)
    return module


W = _load()


def _ok(**extra: Any) -> dict[str, Any]:
    return {"ok": True, "error": None, "win32": None, **extra}


def _opened() -> dict[str, Any]:
    return _ok(read=True, blob_len=294, matches=True)


def _refused() -> dict[str, Any]:
    return {
        "ok": False,
        "read": True,
        "blob_len": 294,
        "matches": False,
        "error": "DpapiError: CryptUnprotectData failed (Win32 error -2146893813)",
        "win32": 2148073483,
    }


def _dpapi_failed() -> dict[str, Any]:
    return {"ok": False, "error": "DpapiError: CryptProtectData failed (Win32 error 5)", "win32": 5}


def _unread() -> dict[str, Any]:
    return {"ok": False, "read": False, "error": "could not read user.blob: [Errno 13]"}


def _group(
    sid: str, *, enabled: bool = True, deny_only: bool = False, logon: bool = False
) -> dict[str, Any]:
    return {"sid": sid, "enabled": enabled, "deny_only": deny_only, "logon_id": logon}


def _token(user: str, *, restricted: bool, logon: str = "S-1-5-5-0-1") -> dict[str, Any]:
    """The shape service_token_probe.read_token returns."""
    return {
        "user": user,
        # Users, and a deny-only Administrators as a filtered admin token holds it: not elevated.
        "groups": [
            _group("S-1-5-32-545"),
            _group(ADMINS, enabled=False, deny_only=True),
            _group(logon, logon=True),
        ],
        "privileges": list(PRIVILEGES),
        "restricting_sids": [user, "S-1-1-0"] if restricted else [],
        "flags": 8 if restricted else 0,
        "write_restricted": restricted,
    }


def _good() -> dict[str, Any]:
    start1 = {
        "role": "owner",
        "start": 1,
        "pid": 100,
        "token": _token(OWNER_SID, restricted=True, logon="S-1-5-5-0-1"),
        "user_protect": _ok(blob_len=294),
        "machine_protect": _ok(blob_len=294),
        "user_unprotect": _opened(),
    }
    start2 = {
        "role": "owner",
        "start": 2,
        "pid": 200,
        "token": _token(OWNER_SID, restricted=True, logon="S-1-5-5-0-2"),
        "user_unprotect": _opened(),
    }
    other = {
        "role": "other",
        "pid": 300,
        "token": _token(OTHER_SID, restricted=False, logon="S-1-5-5-0-3"),
        "foreign_user_blob": _refused(),
        "foreign_machine_blob": _opened(),
        "own_protect": _ok(blob_len=294),
        "own_unprotect": _opened(),
    }
    return {
        "start1": start1,
        "start2": start2,
        "other": other,
        "owner_sid": OWNER_SID,
        "other_sid": OTHER_SID,
        "privileges": list(PRIVILEGES),
        "user_copy_identical": True,
        "machine_copy_identical": True,
    }


def _answers(case: dict[str, Any]) -> dict[str, str]:
    return {a.key: a.answer for a in W.judge_reports(**case)}


def test_the_all_good_reports_answer_yes_three_times() -> None:
    # The positive control: a judge that can only say INCONCLUSIVE would pass every case below.
    assert _answers(_good()) == {"Q1": "YES", "Q2": "YES", "Q3": "YES"}


def test_an_other_account_that_opens_the_blob_is_a_no_not_a_failure() -> None:
    case = _good()
    case["other"]["foreign_user_blob"] = _opened()
    assert _answers(case) == {"Q1": "YES", "Q2": "NO", "Q3": "YES"}


def _mutate(path: str, value: Any) -> dict[str, Any]:
    case = _good()
    *parents, leaf = path.split(".")
    node = case
    for key in parents:
        node = node[key]
    node[leaf] = value
    return case


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        # Q1: the owner must hold the installer's hardened token, by the smoke leg's own rule.
        ("start1.token.user", SYSTEM_SID, {"Q1": "INCONCLUSIVE"}),
        ("start1.token.write_restricted", False, {"Q1": "INCONCLUSIVE"}),
        ("start1.token.restricting_sids", ["S-1-1-0"], {"Q1": "INCONCLUSIVE"}),
        (
            "start1.token.privileges",
            [*PRIVILEGES, "SeImpersonatePrivilege"],
            {"Q1": "INCONCLUSIVE"},
        ),
        ("start1.token", {"error": "OSError: access denied"}, {"Q1": "INCONCLUSIVE"}),
        ("start1.token", None, {"Q1": "INCONCLUSIVE"}),
        ("start1.token.groups", [_group(ADMINS)], {"Q1": "INCONCLUSIVE"}),
        ("start1", None, {"Q1": "INCONCLUSIVE", "Q2": "INCONCLUSIVE", "Q3": "INCONCLUSIVE"}),
        # Q1 measured NO: then there is no valid blob, so Q2 and Q3 are NOT RUN.
        ("start1.user_protect", _dpapi_failed(), {"Q1": "NO"}),
        ("start1.user_unprotect", _refused(), {"Q1": "NO"}),
        ("start1.user_unprotect", {**_opened(), "matches": False}, {"Q1": "NO"}),
        # A failure that is not DPAPI's is not a NO.
        (
            "start1.user_protect",
            {"ok": False, "error": "MemoryError: ", "win32": None},
            {"Q1": "INCONCLUSIVE"},
        ),
        ("start1.user_unprotect", _unread(), {"Q1": "INCONCLUSIVE"}),
        # A report numbered 1 that did not protect: an earlier start wrote the blob unreported.
        ("start1.user_protect", None, {"Q1": "INCONCLUSIVE"}),
        # Q2: a refusal counts only beside every control.
        ("user_copy_identical", False, {"Q2": "INCONCLUSIVE"}),
        ("machine_copy_identical", False, {"Q2": "INCONCLUSIVE"}),
        ("other.token.user", OWNER_SID, {"Q2": "INCONCLUSIVE"}),
        ("other.token.user", "S-1-5-21-9-9-9-1002", {"Q2": "INCONCLUSIVE"}),
        ("other_sid", OWNER_SID, {"Q2": "INCONCLUSIVE"}),
        (
            "other.foreign_user_blob",
            {**_refused(), "error": "MemoryError: "},
            {"Q2": "INCONCLUSIVE"},
        ),
        ("other.token", None, {"Q2": "INCONCLUSIVE"}),
        ("other.token.groups", [_group(ADMINS)], {"Q2": "INCONCLUSIVE"}),
        ("other.token.groups", "not a list", {"Q2": "INCONCLUSIVE"}),
        ("other.token.privileges", [*PRIVILEGES, "SeDebugPrivilege"], {"Q2": "INCONCLUSIVE"}),
        ("other.token.write_restricted", True, {"Q2": "INCONCLUSIVE"}),
        ("other.foreign_machine_blob", _refused(), {"Q2": "INCONCLUSIVE"}),
        ("other.own_protect", {"ok": False, "error": "x", "win32": 5}, {"Q2": "INCONCLUSIVE"}),
        ("other.own_unprotect", _refused(), {"Q2": "INCONCLUSIVE"}),
        (
            "other.foreign_user_blob",
            {"ok": False, "read": False, "error": "no file"},
            {"Q2": "INCONCLUSIVE"},
        ),
        ("other", None, {"Q2": "INCONCLUSIVE"}),
        # Q3: the restart must be a second start, a new process, on the same hardened token.
        ("start2", None, {"Q3": "INCONCLUSIVE"}),
        # The same logon session is not a restart, whatever the process id says.
        ("start2.token.groups", [_group("S-1-5-5-0-1", logon=True)], {"Q3": "INCONCLUSIVE"}),
        ("start2.token.groups", [], {"Q3": "INCONCLUSIVE"}),
        ("start2.start", 3, {"Q3": "INCONCLUSIVE"}),
        ("start2.token.user", SYSTEM_SID, {"Q3": "INCONCLUSIVE"}),
        ("start2.token.write_restricted", False, {"Q3": "INCONCLUSIVE"}),
        ("start2.user_protect", _ok(blob_len=294), {"Q3": "INCONCLUSIVE"}),
        ("start2.user_unprotect", {**_opened(), "blob_len": 300}, {"Q3": "INCONCLUSIVE"}),
        ("start2.user_unprotect", _unread(), {"Q3": "INCONCLUSIVE"}),
        ("start2.user_unprotect", _refused(), {"Q3": "NO"}),
    ],
)
def test_one_broken_input_moves_only_the_answers_it_should(
    path: str, value: Any, expected: dict[str, str]
) -> None:
    answers = _answers(_mutate(path, value))
    # An answer the case does not name stays YES, except where Q1 is not YES: Q2 and Q3 rest on it.
    q1 = expected.get("Q1", "YES")
    rest = {"YES": "YES", "NO": "NOT RUN"}.get(q1, "INCONCLUSIVE")
    want = {"Q1": q1, "Q2": rest, "Q3": rest, **expected}
    assert answers == want, path


def test_an_other_report_that_is_the_owner_itself_is_not_a_second_account() -> None:
    # The rig handed the owner's SID as --other-sid, and the other report did run as the owner.
    case = _mutate("other_sid", OWNER_SID)
    case["other"]["token"]["user"] = OWNER_SID
    assert _answers(case)["Q2"] == "INCONCLUSIVE"


def test_a_pid_reused_across_the_restart_is_still_a_restart() -> None:
    # Windows reuses process ids; the new logon session is what shows the restart.
    assert _answers(_mutate("start2.pid", 100))["Q3"] == "YES"


def test_the_code_reader_turns_a_signed_hresult_back_into_its_unsigned_code() -> None:
    # ctypes.get_last_error() is signed, so secrets_dpapi prints NTE_BAD_KEY_STATE negative.
    found = W._WIN32_CODE.search("CryptUnprotectData failed (Win32 error -2146893813); the key")
    assert found is not None
    assert int(found.group(1)) & 0xFFFFFFFF == 0x8009000B


def test_the_render_prints_every_answer_control_and_the_reboot_arm() -> None:
    text = W.render(
        W.judge_reports(**_good()), image="windows-2022", os_build="20348", accounts="a, b"
    )
    lines = [line for line in text.splitlines() if line.startswith("DPAPI-SPIKE windows-2022 ")]
    for key in ("Q1", "Q2", "Q3"):
        assert any(
            line.startswith(f"DPAPI-SPIKE windows-2022 {key} ") and line.endswith(": YES")
            for line in lines
        ), key
    assert sum(" control HELD: " in line for line in lines) == 13
    assert not any(" control FAILED: " in line for line in lines)
    assert any("REBOOT arm: NOT RUN" in line and "hosted runners" in line for line in lines)
    # cp1252-safe: the summary is read on Windows consoles too.
    text.encode("cp1252")


def _write_tree(tmp_path: Path, case: dict[str, Any]) -> tuple[Path, Path]:
    owner, other = tmp_path / "owner", tmp_path / "other"
    owner.mkdir()
    other.mkdir()
    for n, key in ((1, "start1"), (2, "start2")):
        (owner / W.owner_report(n)).write_text(json.dumps(case[key]), encoding="utf-8")
    (other / W.OTHER_REPORT).write_text(json.dumps(case["other"]), encoding="utf-8")
    for blob, copy_name in (
        (W.USER_BLOB, W.FOREIGN_USER_BLOB),
        (W.MACHINE_BLOB, W.FOREIGN_MACHINE_BLOB),
    ):
        (owner / blob).write_bytes(b"synthetic " + blob.encode())
        (other / copy_name).write_bytes(b"synthetic " + blob.encode())
    return owner, other


def _judge(owner: Path, other: Path, summary: Path) -> int:
    argv = ["judge", "--owner-dir", str(owner), "--other-dir", str(other)]
    argv += ["--owner-sid", OWNER_SID, "--other-sid", OTHER_SID]
    argv += ["--owner-account", "NT SERVICE\\MeforDpapiSpikeA", "--other-account", "VM\\b"]
    argv += ["--privilege", PRIVILEGES[0], "--image", "windows-2025", "--summary", str(summary)]
    return int(W.main(argv))


def test_the_judge_reads_the_files_and_a_no_is_still_a_green_run(tmp_path: Path) -> None:
    case = _good()
    case["other"]["foreign_user_blob"] = _opened()
    owner, other = _write_tree(tmp_path, case)
    summary = tmp_path / "summary.md"
    summary.write_text("earlier step\n", encoding="utf-8")
    assert _judge(owner, other, summary) == 0
    text = summary.read_text(encoding="utf-8")
    assert text.startswith("earlier step\n"), "the summary must be appended to, not replaced"
    assert "DPAPI-SPIKE windows-2025 Q2 " in text and "blob: NO" in text


def test_a_q1_no_is_a_finding_and_leaves_the_run_green(tmp_path: Path) -> None:
    case = _good()
    case["start1"]["user_protect"] = _dpapi_failed()
    owner, other = _write_tree(tmp_path, case)
    summary = tmp_path / "summary.md"
    assert _judge(owner, other, summary) == 0
    text = summary.read_text(encoding="utf-8")
    assert "Q1 " in text and "as the service" in text
    assert sum(line.endswith(": NOT RUN") for line in text.splitlines()) == 2, text
    # A NOT RUN answer prints no control lines: they would read as instrument failures.
    assert not any(
        line.startswith(
            ("DPAPI-SPIKE windows-2025 Q2 control", "DPAPI-SPIKE windows-2025 Q3 control")
        )
        for line in text.splitlines()
    ), text


def test_a_copy_that_differs_on_disk_makes_the_run_red(tmp_path: Path) -> None:
    owner, other = _write_tree(tmp_path, _good())
    (other / W.FOREIGN_USER_BLOB).write_bytes(b"not the owner's bytes")
    assert _judge(owner, other, tmp_path / "summary.md") == 1
    assert "Q2 a second" in (tmp_path / "summary.md").read_text(encoding="utf-8")


# ------------------------------------------------------------------- the rig's lift of the installer

# Read by the PowerShell AST, never run: the rig's $lifted list, the installer's top-level functions
# and assignments, and every command and variable each lifted function uses. $drop removes one name
# from the list first, which is the control arm: a check that never reports a gap proves nothing.
_LIFT_CHECK = r"""
param([string]$RigPath, [string]$InstallerPath, [string]$Drop)
$ErrorActionPreference = 'Stop'
$L = [System.Management.Automation.Language.Parser]
# Its own names: a [string] parameter would turn an AST assigned to it back into text.
$rig = $L::ParseFile($RigPath, [ref]$null, [ref]$null)
$at = { param($tree, $type) $tree.FindAll({ $args[0] -is $type }, $true) }
$assign = [System.Management.Automation.Language.AssignmentStatementAst]
$fnType = [System.Management.Automation.Language.FunctionDefinitionAst]
$named = { param($name) @(& $at $rig $assign | Where-Object { $_.Left.Extent.Text -eq $name }) }
$lifted = @((& $named '$lifted')[0].Right.Expression.SafeGetValue() | Where-Object { $_ -ne $Drop })
$values = @((& $named '$liftedValues')[0].Right.Expression.SafeGetValue() | Where-Object { $_ -ne $Drop })
$rigDefs = @(& $at $rig $fnType | ForEach-Object { $_.Name })
$tree = $L::ParseFile($InstallerPath, [ref]$null, [ref]$null)
$top = @($tree.EndBlock.Statements)
$defs = @{}
foreach ($f in @($top | Where-Object { $_ -is $fnType })) { $defs[$f.Name] = $f }
# The installer's script parameters count too: in the rig a read of one is $null, or the rig's own
# parameter of the same name.
$topVars = @($tree.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) + @($top | Where-Object { $_ -is $assign -and $_.Left -is
  [System.Management.Automation.Language.VariableExpressionAst] } |
  ForEach-Object { $_.Left.VariablePath.UserPath })
$gaps = @()
foreach ($name in $lifted) {
  if (-not $defs.ContainsKey($name)) { $gaps += "$name is not a top-level installer function"; continue }
  $body = $defs[$name].Body
  $calls = @(& $at $body ([System.Management.Automation.Language.CommandAst]) |
    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
  foreach ($c in $calls) {
    if ($defs.ContainsKey($c) -and $lifted -notcontains $c -and $rigDefs -notcontains $c) {
      $gaps += "$name calls $c, which is not lifted" }
  }
  $params = @($body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
  $used = @(& $at $body ([System.Management.Automation.Language.VariableExpressionAst]) |
    ForEach-Object { $_.VariablePath.UserPath } | Sort-Object -Unique)
  foreach ($v in $used) {
    # NssmPath is the rig's own: it is the checked copy Resolve-Nssm returned.
    if ($topVars -contains $v -and $params -notcontains $v -and $values -notcontains $v -and
        $v -ne 'NssmPath') { $gaps += "$name reads top-level `$$v, which is not lifted" }
  }
}
foreach ($v in $values) {
  $a = @($top | Where-Object { $_ -is $assign -and $_.Left.Extent.Text -eq "`$$v" })
  if ($a.Count -ne 1) { $gaps += "`$$v is assigned $($a.Count) times at top level"; continue }
  try { $null = $a[0].Right.Expression.SafeGetValue() } catch { $gaps += "`$$v is not a constant" }
}
@{ lifted = $lifted.Count; gaps = $gaps } | ConvertTo-Json -Compress
"""


def _lift_gaps(tmp_path: Path, drop: str = "") -> dict[str, Any]:
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    script = tmp_path / "lift_check.ps1"
    script.write_text(_LIFT_CHECK, encoding="utf-8")
    argv = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)]
    argv += ["-RigPath", str(_RIG), "-InstallerPath", str(_INSTALLER), "-Drop", drop]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
    assert done.returncode == 0, done.stderr
    result: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    result["gaps"] = list(result["gaps"] or [])
    return result


def test_every_installer_helper_the_rig_lifts_is_lifted_with_it(tmp_path: Path) -> None:
    # The rig lifts install-service.ps1's definitions by name, and runs only when its own files
    # change. A new helper call inside a lifted function would otherwise break the spike silently,
    # at its next run, with "not recognized".
    result = _lift_gaps(tmp_path)
    assert result["lifted"] >= 18, "CONTROL FAILED: the rig's $lifted list was not read"
    assert result["gaps"] == []


def test_the_lift_check_reports_a_value_left_out(tmp_path: Path) -> None:
    # The control arm for the variable branch: Resolve-Nssm reads $NssmExeSha256.
    gaps = _lift_gaps(tmp_path, drop="NssmExeSha256")["gaps"]
    assert any("reads top-level $NssmExeSha256" in gap for gap in gaps), gaps


def test_the_lift_check_reports_a_helper_left_out(tmp_path: Path) -> None:
    # The control arm: Resolve-Nssm calls Get-FilePinProblem, so dropping it must be named.
    gaps = _lift_gaps(tmp_path, drop="Get-FilePinProblem")["gaps"]
    assert any("calls Get-FilePinProblem" in gap for gap in gaps), gaps


def test_the_rig_waits_on_and_copies_the_names_the_worker_writes() -> None:
    # The rig is PowerShell and cannot import the worker's constants, so they are pinned here.
    rig = _RIG.read_text(encoding="utf-8")
    names = [W.owner_report(1), W.owner_report(2), W.OTHER_REPORT, W.USER_BLOB, W.MACHINE_BLOB]
    names += [W.FOREIGN_USER_BLOB, W.FOREIGN_MACHINE_BLOB]
    assert len(names) >= 7, "CONTROL FAILED: the worker's file names were not collected"
    missing = [name for name in names if f'"{name}"' not in rig]
    assert not missing, f"scripts/ci/dpapi_spike.ps1 no longer names {missing}"
