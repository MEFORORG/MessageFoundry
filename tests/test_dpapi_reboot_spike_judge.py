# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DPAPI reboot spike's judge may not turn a broken instrument into an answer (vault BACKLOG
#3411, the reboot arm).

``scripts/research/dpapi-reboot-spike/dpapi_reboot_spike.ps1`` runs once, by hand, on a lab VM,
and its judge (``Invoke-Judge``) turns the service's reports into the five arm verdicts and the
SURVIVES / DOES NOT SURVIVE line. A defect there would show only on that one run. So these cases
hand the judge, lifted out of the script by the PowerShell AST and run as written, reports where
one control or one precondition fails, and check the answer is INCONCLUSIVE rather than YES or NO.
The all-good rebooted case is the positive control that it can say SURVIVES at all.

They need pwsh, and nothing of Windows: the judge reads files.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_RIG = _REPO / "scripts" / "research" / "dpapi-reboot-spike" / "dpapi_reboot_spike.ps1"
_PWSH = shutil.which("pwsh")

pytestmark = pytest.mark.skipif(_PWSH is None, reason="pwsh not on PATH")

SID = "S-1-5-80-4122042409-3321711707-2963677527-2474584594-1716172443"
BAD_KEY = "FAIL win32=-2146893813"

# Lifts the judge and the three assignments it reads out of the rig, and runs nothing else of it:
# the rig's top level is a circuit breaker and a mode switch.
_DRIVER = r"""
param([string]$Rig, [string]$Dir, [string]$Rebooted)
$ErrorActionPreference = 'Stop'
$top = @([System.Management.Automation.Language.Parser]::ParseFile($Rig, [ref]$null, [ref]$null).EndBlock.Statements)
foreach ($n in 'ServiceName', 'Account', 'NteBadKeyState') {
    $a = @($top | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq "`$$n" })
    if ($a.Count -ne 1) { throw "the rig assigns `$$n $($a.Count) times at top level" }
    . ([scriptblock]::Create($a[0].Extent.Text))
}
foreach ($n in 'Read-Report', 'Get-Verdict', 'Get-RebootProblem', 'Invoke-Judge') {
    $f = @($top | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $n })
    if ($f.Count -ne 1) { throw "the rig defines $n $($f.Count) times at top level" }
    . ([scriptblock]::Create($f[0].Extent.Text))
}
(Invoke-Judge $Dir ($Rebooted -eq '1')).Lines
"""


def _report(arm: str, **changes: str) -> dict[str, str]:
    before = arm in ("A1", "A2", "A3")
    r = {
        "arm": arm,
        "utc": "2026-11-04T06:10:00.0000000Z" if before else "2026-11-04T06:20:00.0000000Z",
        "uptime_ms": "400000" if before else "90000",
        "boot_utc": "2026-11-04T06:03:20.0000000Z" if before else "2026-11-04T06:18:30.0000000Z",
        "identity": "NT SERVICE\\MeforDpapiReboot",
        "sid": SID,
        "action": "protect" if arm == "A1" else "unprotect",
        "plain_sha256": "ab" * 32,
        "user_unprotect": "OK match",
        "machine_unprotect": "OK match",
        "control_foreign": BAD_KEY,
        "control_tampered": "FAIL win32=13",
    }
    if arm == "A1":
        r["protect_user"] = "OK"
        r["protect_machine"] = "OK"
    r.update(changes)
    return r


def _write(
    tmp_path: Path,
    reports: dict[str, dict[str, str] | None],
    crosscheck: str = f"admin_open={BAD_KEY} by REVTEST01\\Administrator exit=0",
    profile: str = "loaded_before_start=True profile=C:\\Windows\\ServiceProfiles\\MeforDpapiReboot",
) -> Path:
    for arm, r in reports.items():
        if r is not None:
            body = "".join(f"{k}={v}\n" for k, v in r.items())
            (tmp_path / f"report-{arm}.txt").write_text(body, encoding="ascii")
    (tmp_path / "crosscheck.txt").write_text(crosscheck + "\n", encoding="ascii")
    (tmp_path / "profile-A3.txt").write_text(profile + "\n", encoding="ascii")
    return tmp_path


def _all(**overrides: dict[str, str] | None) -> dict[str, dict[str, str] | None]:
    reports: dict[str, dict[str, str] | None] = {
        a: _report(a) for a in ("A1", "A2", "A3", "A4", "A5")
    }
    reports.update(overrides)
    return reports


def _judge(directory: Path, rebooted: bool = True) -> dict[str, str]:
    """The judge's lines, keyed by the arm (A1..A5), plus VERDICT and crosscheck."""
    driver = directory / "driver.ps1"
    driver.write_text(_DRIVER, encoding="ascii")
    assert _PWSH is not None
    out = subprocess.run(
        [
            _PWSH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(driver),
            "-Rig",
            str(_RIG),
            "-Dir",
            str(directory),
            "-Rebooted",
            "1" if rebooted else "0",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    lines: dict[str, str] = {}
    for line in out.stdout.splitlines():
        assert line.startswith("DPAPI-REBOOT "), line
        rest = line[len("DPAPI-REBOOT ") :]
        key = rest.split(" ", 1)[0].rstrip(":")
        lines[key] = rest
    return lines


def _verdict(lines: dict[str, str], arm: str) -> str:
    """The verdict word(s) of one arm line: what follows the colon, up to the reason."""
    return lines[arm].split(": ", 1)[1].split(" (", 1)[0]


def test_all_good_reads_survives(tmp_path: Path) -> None:
    j = _judge(_write(tmp_path, _all()))
    assert _verdict(j, "VERDICT") == "SURVIVES"
    assert [_verdict(j, a) for a in ("A1", "A2", "A4", "A5")] == ["YES"] * 4
    # The profile stayed loaded, as on the 2026-11-04 runs: A3 cannot be answered, and says so.
    assert _verdict(j, "A3") == "INCONCLUSIVE"
    assert "not seen unloaded" in j["A3"]


def test_unloaded_profile_lets_a3_answer(tmp_path: Path) -> None:
    j = _judge(_write(tmp_path, _all(), profile="loaded_before_start=False profile=x"))
    assert _verdict(j, "A3") == "YES"


def test_refused_demand_start_reads_does_not_survive(tmp_path: Path) -> None:
    j = _judge(_write(tmp_path, _all(A5=_report("A5", user_unprotect="FAIL win32=-2146893813"))))
    assert _verdict(j, "A5") == "NO"
    assert _verdict(j, "VERDICT") == "DOES NOT SURVIVE"


def test_refused_boot_start_only_is_not_a_survival_failure(tmp_path: Path) -> None:
    j = _judge(_write(tmp_path, _all(A4=_report("A4", user_unprotect="FAIL win32=-2146893813"))))
    assert _verdict(j, "A4") == "NO"
    assert _verdict(j, "VERDICT") == "SURVIVES, BUT NOT AT THE BOOT-TIME START"


def test_a5_is_judged_without_a4(tmp_path: Path) -> None:
    j = _judge(
        _write(tmp_path, _all(A4=None, A5=_report("A5", user_unprotect="FAIL win32=-2146893813")))
    )
    assert _verdict(j, "A4") == "INCONCLUSIVE"
    assert _verdict(j, "A5") == "NO"
    assert _verdict(j, "VERDICT") == "DOES NOT SURVIVE"


def test_no_reboot_shown_is_inconclusive(tmp_path: Path) -> None:
    same_boot = {"uptime_ms": "500000", "boot_utc": "2026-11-04T06:03:20.0000000Z"}
    j = _judge(_write(tmp_path, _all(A4=_report("A4", **same_boot), A5=_report("A5", **same_boot))))
    assert _verdict(j, "A4") == "INCONCLUSIVE"
    assert "no reboot shown" in j["A4"]
    assert _verdict(j, "VERDICT") == "INCONCLUSIVE"


def test_uptime_reset_proves_a_reboot_under_a_skewed_clock(tmp_path: Path) -> None:
    # The guest clock read early at boot is an hour behind, so boot_utc moved backwards; the tick
    # count still went down, which only a boot does.
    skewed = {"uptime_ms": "30000", "boot_utc": "2026-11-04T05:18:30.0000000Z"}
    j = _judge(_write(tmp_path, _all(A4=_report("A4", **skewed), A5=_report("A5", **skewed))))
    assert _verdict(j, "VERDICT") == "SURVIVES"


@pytest.mark.parametrize(
    "change",
    [
        {"control_foreign": "FAIL win32=13"},  # a garbage foreign blob, not a key refusal
        {"control_foreign": "OPENED"},
        {"control_tampered": "OPENED"},
        {"machine_unprotect": "FAIL win32=13"},
        {"identity": "NT AUTHORITY\\SYSTEM"},
        {"action": "protect"},  # the blob was made at this start, so nothing survived anything
    ],
)
def test_a_failed_control_never_answers(tmp_path: Path, change: dict[str, str]) -> None:
    j = _judge(
        _write(tmp_path, _all(A5=_report("A5", user_unprotect="FAIL win32=-2146893813", **change)))
    )
    assert _verdict(j, "A5") == "INCONCLUSIVE"
    assert _verdict(j, "VERDICT") == "INCONCLUSIVE"


def test_an_admin_who_opens_the_service_blob_voids_every_arm(tmp_path: Path) -> None:
    j = _judge(
        _write(tmp_path, _all(), crosscheck="admin_open=OPENED by REVTEST01\\Administrator exit=0")
    )
    assert [_verdict(j, a) for a in ("A1", "A2", "A3", "A4", "A5")] == ["INCONCLUSIVE"] * 5
    assert _verdict(j, "VERDICT") == "INCONCLUSIVE"


def test_a1_protect_failure_is_no_only_beside_a_working_machine_scope(tmp_path: Path) -> None:
    no = _judge(_write(tmp_path, _all(A1=_report("A1", protect_user="FAIL win32=5"))))
    assert _verdict(no, "A1") == "NO"
    both = tmp_path / "both"
    both.mkdir()
    j = _judge(
        _write(
            both,
            _all(A1=_report("A1", protect_user="FAIL win32=5", protect_machine="FAIL win32=5")),
        )
    )
    assert _verdict(j, "A1") == "INCONCLUSIVE"


def test_without_a_reboot_the_reboot_arms_read_not_run(tmp_path: Path) -> None:
    j = _judge(_write(tmp_path, _all(A4=None, A5=None)), rebooted=False)
    assert _verdict(j, "A4") == "NOT RUN"
    assert _verdict(j, "A5") == "NOT RUN"
    assert _verdict(j, "VERDICT") == "NOT RUN"
