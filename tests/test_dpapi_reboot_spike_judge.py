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

Every scenario is judged in ONE pwsh process (the tier's cost is pwsh start-up). They need pwsh,
and nothing of Windows: the judge reads files.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_RIG = _REPO / "scripts" / "research" / "dpapi-reboot-spike" / "dpapi_reboot_spike.ps1"
_PWSH = shutil.which("pwsh")

pytestmark = pytest.mark.skipif(_PWSH is None, reason="pwsh not on PATH")

SID = "S-1-5-80-4122042409-3321711707-2963677527-2474584594-1716172443"
BAD_KEY = "FAIL win32=-2146893813"
CROSS_OK = f"admin_open={BAD_KEY} by REVTEST01\\Administrator exit=0"
PROFILE_LOADED = "loaded_before_start=True profile=C:\\Windows\\ServiceProfiles\\MeforDpapiReboot"

# Lifts the judge and the assignments it reads out of the rig, and runs nothing else of it: the
# rig's top level is a circuit breaker and a mode switch. A parse error anywhere in the rig fails
# here, since no CI leg runs the rig's Host-mode code. Then it judges each scenario folder.
_LIFT = r"""
param([string]$Rig, [string]$Arg)
$ErrorActionPreference = 'Stop'
$errors = $null
$tree = [System.Management.Automation.Language.Parser]::ParseFile($Rig, [ref]$null, [ref]$errors)
if ($errors.Count -ne 0) { throw "the rig does not parse: $($errors[0].Message)" }
$top = @($tree.EndBlock.Statements)
foreach ($n in 'ServiceName', 'Account', 'NteBadKeyState') {
    $a = @($top | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq "`$$n" })
    if ($a.Count -ne 1) { throw "the rig assigns `$$n $($a.Count) times at top level" }
    . ([scriptblock]::Create($a[0].Extent.Text))
}
foreach ($n in FUNCTIONS) {
    $f = @($top | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $n })
    if ($f.Count -ne 1) { throw "the rig defines $n $($f.Count) times at top level" }
    . ([scriptblock]::Create($f[0].Extent.Text))
}
"""


def _lift(*functions: str) -> str:
    return _LIFT.replace("FUNCTIONS", ", ".join(f"'{f}'" for f in functions))


def _run_pwsh(driver: Path, arg: Path, timeout: int) -> str:
    """Runs a lifting driver against the rig; returns its stdout, and fails on a non-zero exit."""
    assert _PWSH is not None
    proc = subprocess.run(
        [
            _PWSH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(driver),
            "-Rig",
            str(_RIG),
            "-Arg",
            str(arg),
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


_DRIVER = (
    _lift("Read-Report", "Get-Verdict", "Get-BootReading", "Get-BootRelation", "Invoke-Judge")
    + r"""
foreach ($row in Get-Content -LiteralPath $Arg) {
    $name, $dir, $rebooted = $row -split '\|'
    "==== $name"
    $j = Invoke-Judge $dir ($rebooted -eq '1')
    $j.Lines
    "DPAPI-REBOOT prepass: $($j.PrePass)"
}
"""
)

Reports = dict[str, dict[str, str] | None]


def _report(arm: str, **changes: str) -> dict[str, str]:
    before = arm in ("A1", "A2", "A3")
    r = {
        "arm": arm,
        "utc": "2026-11-04T06:10:00.0000000Z" if before else "2026-11-04T06:20:00.0000000Z",
        "uptime_ms": "400000" if before else "90000",
        "boot_utc": "2026-11-04T06:03:20.0000000Z" if before else "2026-11-04T06:18:30.0000000Z",
        "boot_id": "7" if before else "8",
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


def _all(**overrides: dict[str, str] | None) -> Reports:
    reports: Reports = {a: _report(a) for a in ("A1", "A2", "A3", "A4", "A5")}
    reports.update(overrides)
    return reports


REFUSED = {"user_unprotect": BAD_KEY}
# No boot counter, so the judge falls back to the tick count and then the clock.
NO_ID = {"boot_id": ""}
# What every start reports once A1's user-scope protect failed: there is no user.blob to open or
# to tamper with, and the administrator's crosscheck finds none either.
NO_BLOB = {"user_unprotect": "ABSENT", "control_tampered": "ABSENT"}
CROSS_ABSENT = "admin_open=ABSENT by REVTEST01\\Administrator exit=0"


def _no_blob_run(a1: dict[str, str], every: dict[str, str]) -> Reports:
    return {
        a: _report(a, **NO_BLOB, **every, **(a1 if a == "A1" else {}))
        for a in ("A1", "A2", "A3", "A4", "A5")
    }


# The boot counter stayed put across a reboot the tick count and the boot time both show.
STUCK_ID = {"boot_id": "7"}


class Scenario:
    def __init__(
        self,
        reports: Reports,
        crosscheck: str = CROSS_OK,
        profile: str = PROFILE_LOADED,
        rebooted: bool = True,
    ) -> None:
        self.reports = reports
        self.crosscheck = crosscheck
        self.profile = profile
        self.rebooted = rebooted


SCENARIOS: dict[str, Scenario] = {
    "all_good": Scenario(_all()),
    "profile_unloaded": Scenario(_all(), profile="loaded_before_start=False profile=x"),
    "a5_refused": Scenario(_all(A4=_report("A4", **REFUSED), A5=_report("A5", **REFUSED))),
    "a4_refused": Scenario(_all(A4=_report("A4", **REFUSED))),
    "a4_opened_a5_refused": Scenario(_all(A5=_report("A5", **REFUSED))),
    "a4_missing_a5_refused": Scenario(_all(A4=None, A5=_report("A5", **REFUSED))),
    # The counter did not move, but the tick count went down and the boot time moved later.
    "stuck_id_tick_down": Scenario(
        _all(A4=_report("A4", **STUCK_ID), A5=_report("A5", **STUCK_ID))
    ),
    # As above, and A5 came late enough that its tick count is past A3's: only A4 shows the reboot,
    # and A5 is from A4's boot.
    "stuck_id_a5_late": Scenario(
        _all(
            A4=_report("A4", **STUCK_ID),
            A5=_report(
                "A5", uptime_ms="900000", boot_utc="2026-11-04T06:18:30.0000000Z", **STUCK_ID
            ),
        )
    ),
    # The same counter, a tick count that went up and one boot time: no reboot happened.
    "same_boot_id": Scenario(
        _all(
            A4=_report(
                "A4", uptime_ms="500000", boot_utc="2026-11-04T06:03:20.0000000Z", **STUCK_ID
            ),
            A5=_report(
                "A5", uptime_ms="510000", boot_utc="2026-11-04T06:03:20.0000000Z", **STUCK_ID
            ),
        )
    ),
    # The same counter and a tick count that went down, but a boot time that moved earlier: the
    # signals disagree.
    "same_id_tick_down_boot_earlier": Scenario(
        _all(
            A4=_report("A4", boot_utc="2026-11-04T05:00:00.0000000Z", **STUCK_ID),
            A5=_report(
                "A5", uptime_ms="95000", boot_utc="2026-11-04T05:00:00.0000000Z", **STUCK_ID
            ),
        )
    ),
    "two_boots": Scenario(_all(A5=_report("A5", boot_id="9"))),
    # No counter, a tick count that went up and a boot time two minutes back: a clock correction
    # inside one boot, not a reboot.
    "no_id_clock_back": Scenario(
        _all(
            A3=_report("A3", **NO_ID),
            A4=_report("A4", uptime_ms="500000", boot_utc="2026-11-04T06:01:20.0000000Z", **NO_ID),
            A5=_report("A5", uptime_ms="510000", boot_utc="2026-11-04T06:01:20.0000000Z", **NO_ID),
        )
    ),
    # No counter and a tick count past A3's, but boot times 15 minutes apart: the clock shows it.
    "no_id_clock_rebooted": Scenario(
        _all(
            A3=_report("A3", **NO_ID),
            A4=_report("A4", uptime_ms="500000", **NO_ID),
            A5=_report("A5", uptime_ms="510000", **NO_ID),
        )
    ),
    "no_id_same_boot": Scenario(
        _all(
            A3=_report("A3", **NO_ID),
            A4=_report("A4", uptime_ms="500000", boot_utc="2026-11-04T06:03:20.0000000Z", **NO_ID),
            A5=_report("A5", uptime_ms="510000", boot_utc="2026-11-04T06:03:20.0000000Z", **NO_ID),
        )
    ),
    # The guest clock read early at boot is an hour behind, so boot_utc moved backwards; the tick
    # count still went down, which only a boot does.
    "no_id_skewed_clock": Scenario(
        _all(
            A3=_report("A3", **NO_ID),
            A4=_report("A4", uptime_ms="30000", boot_utc="2026-11-04T05:18:30.0000000Z", **NO_ID),
            A5=_report("A5", uptime_ms="60000", boot_utc="2026-11-04T05:18:30.0000000Z", **NO_ID),
        )
    ),
    "no_id_empty_uptime": Scenario(
        _all(
            A3=_report("A3", **NO_ID),
            A4=None,
            A5=_report("A5", uptime_ms="", boot_utc="2026-11-04T06:03:20.0000000Z", **NO_ID),
        )
    ),
    "foreign_garbage": Scenario(_all(A5=_report("A5", control_foreign="FAIL win32=13", **REFUSED))),
    "foreign_opened": Scenario(_all(A5=_report("A5", control_foreign="OPENED", **REFUSED))),
    "tampered_opened": Scenario(_all(A5=_report("A5", control_tampered="OPENED", **REFUSED))),
    "machine_failed": Scenario(
        _all(A5=_report("A5", machine_unprotect="FAIL win32=13", **REFUSED))
    ),
    "wrong_identity": Scenario(_all(A5=_report("A5", identity="NT AUTHORITY\\SYSTEM", **REFUSED))),
    "a5_protected_afresh": Scenario(_all(A5=_report("A5", action="protect", **REFUSED))),
    "admin_opened": Scenario(
        _all(), crosscheck="admin_open=OPENED by REVTEST01\\Administrator exit=0"
    ),
    "admin_data_error": Scenario(
        _all(), crosscheck="admin_open=FAIL win32=13 by REVTEST01\\Administrator exit=0"
    ),
    # A failed user-scope protect leaves no blob, so the crosscheck reads ABSENT because of it.
    "a1_protect_refused": Scenario(
        _no_blob_run({"protect_user": "FAIL win32=5"}, {}), crosscheck=CROSS_ABSENT
    ),
    "a1_dpapi_down": Scenario(
        _no_blob_run(
            {"protect_user": "FAIL win32=5", "protect_machine": "FAIL win32=5"},
            {"machine_unprotect": "ABSENT"},
        ),
        crosscheck=CROSS_ABSENT,
    ),
    # A refusal before the reboot is a broken instrument or setup, whatever A4 and A5 then say.
    "a2_refused_a5_refused": Scenario(
        _all(
            A2=_report("A2", **REFUSED),
            A3=_report("A3", **REFUSED),
            A4=_report("A4", **REFUSED),
            A5=_report("A5", **REFUSED),
        )
    ),
    "a2_refused_a5_opened": Scenario(_all(A2=_report("A2", **REFUSED))),
    # The profile stayed loaded, so A3 was one more restart, and it was refused.
    "a3_refused_loaded": Scenario(_all(A3=_report("A3", **REFUSED))),
    "a3_damaged_loaded": Scenario(_all(A3=_report("A3", user_unprotect="FAIL win32=13"))),
    "a3_no_report": Scenario(_all(A3=None), rebooted=False),
    # A3's control failed: A4 and A5 open the blob, but nothing before the reboot shows A3 working.
    "a3_control_failed": Scenario(_all(A3=_report("A3", control_tampered="OPENED"))),
    # A failed precondition does not hide a damaged blob.
    "cross_failed_a2_damaged": Scenario(
        _all(A2=_report("A2", user_unprotect="FAIL win32=13")),
        crosscheck="admin_open=OPENED by REVTEST01\\Administrator exit=0",
    ),
    "a5_damaged": Scenario(_all(A5=_report("A5", user_unprotect="FAIL win32=13"))),
    "a4_mismatch": Scenario(_all(A4=_report("A4", user_unprotect="OK mismatch"))),
    "a5_other_value": Scenario(_all(A5=_report("A5", plain_sha256="cd" * 32))),
    "a1_no_sha": Scenario(_all(A1=_report("A1", plain_sha256=""))),
    "a4_missing_a5_opened": Scenario(_all(A4=None)),
    "not_rebooted": Scenario(_all(A4=None, A5=None), rebooted=False),
    "not_rebooted_a2_refused": Scenario(
        _all(A2=_report("A2", **REFUSED), A4=None, A5=None), rebooted=False
    ),
}


def _parse(stdout: str) -> dict[str, dict[str, str]]:
    """Each scenario's judge lines, keyed by the word after DPAPI-REBOOT: A1..A5, VERDICT, crosscheck."""
    out: dict[str, dict[str, str]] = {}
    current: dict[str, str] = {}
    for line in stdout.splitlines():
        if line.startswith("==== "):
            current = out.setdefault(line[len("==== ") :], {})
            continue
        assert line.startswith("DPAPI-REBOOT "), line
        rest = line[len("DPAPI-REBOOT ") :]
        current[rest.split(" ", 1)[0].rstrip(":,")] = rest
    return out


@pytest.fixture(scope="module")
def judged(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, str]]:
    root = tmp_path_factory.mktemp("dpapi-reboot-judge")
    rows = []
    for name, sc in SCENARIOS.items():
        d = root / name
        d.mkdir()
        for arm, r in sc.reports.items():
            if r is not None:
                (d / f"report-{arm}.txt").write_text(
                    "".join(f"{k}={v}\n" for k, v in r.items()), encoding="ascii"
                )
        (d / "crosscheck.txt").write_text(sc.crosscheck + "\n", encoding="ascii")
        (d / "profile-A3.txt").write_text(sc.profile + "\n", encoding="ascii")
        rows.append(f"{name}|{d}|{'1' if sc.rebooted else '0'}")
    (root / "list.txt").write_text("\n".join(rows) + "\n", encoding="ascii")
    (root / "driver.ps1").write_text(_DRIVER, encoding="ascii")
    out = _parse(_run_pwsh(root / "driver.ps1", root / "list.txt", 300))
    assert set(out) == set(SCENARIOS)
    return out


Judged = dict[str, dict[str, str]]


def _v(judged: Judged, scenario: str, key: str) -> str:
    """The verdict word(s) of one line: what follows the first ': ', up to the reason."""
    return judged[scenario][key].split(": ", 1)[1].split(" (", 1)[0]


def test_all_good_reads_survives(judged: Judged) -> None:
    assert _v(judged, "all_good", "VERDICT") == "SURVIVES"
    assert [_v(judged, "all_good", a) for a in ("A1", "A2", "A4", "A5")] == ["YES"] * 4
    # The profile stayed loaded, as on the 2026-11-04 runs: A3 cannot be answered, and says so.
    assert _v(judged, "all_good", "A3") == "INCONCLUSIVE"
    assert "not seen unloaded" in judged["all_good"]["A3"]
    assert "crosscheck" in judged["all_good"]


def test_unloaded_profile_lets_a3_answer(judged: Judged) -> None:
    assert _v(judged, "profile_unloaded", "A3") == "YES"


_OVERALL: list[tuple[str, str]] = [
    ("a5_refused", "DOES NOT SURVIVE"),
    ("a4_opened_a5_refused", "INCONCLUSIVE, A4 OPENED AND A5 DID NOT"),
    ("a4_refused", "SURVIVES, BUT NOT AT THE BOOT-TIME START"),
    ("a4_missing_a5_refused", "DOES NOT SURVIVE"),
    ("a4_missing_a5_opened", "INCONCLUSIVE"),
    ("stuck_id_tick_down", "SURVIVES"),
    ("stuck_id_a5_late", "SURVIVES"),
    ("same_boot_id", "INCONCLUSIVE"),
    ("same_id_tick_down_boot_earlier", "INCONCLUSIVE"),
    ("two_boots", "INCONCLUSIVE"),
    ("no_id_same_boot", "INCONCLUSIVE"),
    ("no_id_skewed_clock", "SURVIVES"),
    ("no_id_clock_rebooted", "SURVIVES"),
    ("no_id_empty_uptime", "INCONCLUSIVE"),
    ("not_rebooted", "NOT RUN"),
    ("a2_refused_a5_refused", "INVALID"),
    ("a2_refused_a5_opened", "INVALID"),
    ("a3_refused_loaded", "INVALID"),
    ("a3_damaged_loaded", "INVALID"),
    ("a5_damaged", "INVALID"),
    ("a4_mismatch", "INVALID"),
    ("a5_other_value", "INVALID"),
    ("a1_protect_refused", "INVALID"),
    ("a1_no_sha", "INCONCLUSIVE"),
    ("a3_control_failed", "INCONCLUSIVE"),
    ("cross_failed_a2_damaged", "INVALID"),
    ("no_id_clock_back", "INCONCLUSIVE"),
    ("a1_dpapi_down", "INCONCLUSIVE"),
    ("not_rebooted_a2_refused", "INVALID"),
]


@pytest.mark.parametrize(("scenario", "overall"), _OVERALL)
def test_overall_verdict(judged: Judged, scenario: str, overall: str) -> None:
    assert _v(judged, scenario, "VERDICT") == overall


def test_a5_is_judged_without_a4(judged: Judged) -> None:
    assert _v(judged, "a4_missing_a5_refused", "A4") == "INCONCLUSIVE"
    assert _v(judged, "a4_missing_a5_refused", "A5") == "NO"


def test_a5_from_another_boot_than_a4_is_not_judged(judged: Judged) -> None:
    assert _v(judged, "two_boots", "A4") == "YES"
    assert _v(judged, "two_boots", "A5") == "INCONCLUSIVE"
    assert "not shown to be from the boot report-A4 is from" in judged["two_boots"]["A5"]


def test_empty_uptime_proves_no_reboot(judged: Judged) -> None:
    assert _v(judged, "no_id_empty_uptime", "A5") == "INCONCLUSIVE"
    assert "unknown" in judged["no_id_empty_uptime"]["A5"]


_BROKEN_CONTROLS = [
    "foreign_garbage",
    "foreign_opened",
    "tampered_opened",
    "machine_failed",
    "wrong_identity",
    "a5_protected_afresh",
]


@pytest.mark.parametrize("scenario", _BROKEN_CONTROLS)
def test_a_failed_control_never_answers(judged: Judged, scenario: str) -> None:
    # Each scenario refuses A5's user-scope blob, which would read NO if the control were ignored.
    assert _v(judged, scenario, "A5") == "INCONCLUSIVE"
    assert _v(judged, scenario, "VERDICT") == "INCONCLUSIVE"


@pytest.mark.parametrize("scenario", ["admin_opened", "admin_data_error"])
def test_a_failed_crosscheck_voids_every_arm(judged: Judged, scenario: str) -> None:
    assert [_v(judged, scenario, a) for a in ("A1", "A2", "A3", "A4", "A5")] == ["INCONCLUSIVE"] * 5
    assert _v(judged, scenario, "VERDICT") == "INCONCLUSIVE"


def test_a1_protect_failure_is_no_only_beside_a_working_machine_scope(judged: Judged) -> None:
    # The crosscheck read ABSENT because the protect failed; the protect is what A1 reports.
    assert _v(judged, "a1_protect_refused", "A1") == "NO"
    assert "protect_user FAIL win32=5" in judged["a1_protect_refused"]["A1"]
    assert _v(judged, "a1_dpapi_down", "A1") == "INCONCLUSIVE"
    assert "protect_machine FAIL win32=5" in judged["a1_dpapi_down"]["A1"]
    # Every later arm has no blob to open, and the absent crosscheck still voids them.
    for a in ("A2", "A3", "A4", "A5"):
        assert _v(judged, "a1_protect_refused", a) == "INCONCLUSIVE"


def test_without_a_reboot_the_reboot_arms_read_not_run(judged: Judged) -> None:
    assert _v(judged, "not_rebooted", "A4") == "NOT RUN"
    assert _v(judged, "not_rebooted", "A5") == "NOT RUN"


@pytest.mark.parametrize(
    ("scenario", "arm"),
    [("a2_refused_a5_refused", "A2"), ("a2_refused_a5_opened", "A2"), ("a3_refused_loaded", "A3")],
)
def test_a_refusal_before_the_reboot_voids_the_verdict(
    judged: Judged, scenario: str, arm: str
) -> None:
    assert _v(judged, scenario, arm) == "NO"
    assert f"{arm} NO" in judged[scenario]["VERDICT"]
    assert judged[scenario]["prepass"].endswith("False")


@pytest.mark.parametrize(
    ("scenario", "arm", "why"),
    [
        ("a5_damaged", "A5", "user_unprotect FAIL win32=13"),
        ("a4_mismatch", "A4", "user_unprotect OK mismatch"),
        ("a3_damaged_loaded", "A3", "user_unprotect FAIL win32=13"),
        ("a5_other_value", "A5", "is not report-A1's"),
    ],
)
def test_a_damaged_blob_or_value_is_invalid(
    judged: Judged, scenario: str, arm: str, why: str
) -> None:
    assert _v(judged, scenario, arm) == "INVALID"
    assert why in judged[scenario][arm]
    assert f"{arm} INVALID" in judged[scenario]["VERDICT"]


def test_a_yes_needs_a1s_value(judged: Judged) -> None:
    assert _v(judged, "a1_no_sha", "A1") == "YES"
    for a in ("A2", "A3", "A4", "A5"):
        assert _v(judged, "a1_no_sha", a) == "INCONCLUSIVE"
        assert "no plain_sha256" in judged["a1_no_sha"][a]


def test_payload_pass_holds_only_for_an_unobserved_unload(judged: Judged) -> None:
    assert judged["all_good"]["prepass"].endswith("True")
    assert judged["not_rebooted"]["prepass"].endswith("True")
    assert judged["profile_unloaded"]["prepass"].endswith("True")
    for scenario in (
        "a3_refused_loaded",
        "a3_damaged_loaded",
        "a3_no_report",
        "a3_control_failed",
        "a1_protect_refused",
    ):
        assert judged[scenario]["prepass"].endswith("False"), scenario


def test_a_stuck_boot_counter_does_not_hide_a_reboot(judged: Judged) -> None:
    assert _v(judged, "stuck_id_tick_down", "A4") == "YES"
    assert _v(judged, "stuck_id_tick_down", "A5") == "YES"
    # A5's own tick count is past A3's; A4, from the same boot, shows the reboot.
    assert _v(judged, "stuck_id_a5_late", "A5") == "YES"
    assert "same" in judged["same_boot_id"]["A4"]
    assert "unknown" in judged["same_id_tick_down_boot_earlier"]["A4"]


def test_the_boots_line_carries_the_raw_readings(judged: Judged) -> None:
    boots = judged["all_good"]["boots"]
    assert "A3 boot_id=7 uptime_ms=400000 boot_utc=2026-11-04T06:03:20.0000000Z" in boots
    assert "A4 boot_id=8 uptime_ms=90000 boot_utc=2026-11-04T06:18:30.0000000Z" in boots
    assert "A4 no report" in judged["a4_missing_a5_opened"]["boots"]


def test_a5_opening_without_a4_is_not_a_survival_verdict(judged: Judged) -> None:
    assert _v(judged, "a4_missing_a5_opened", "A4") == "INCONCLUSIVE"
    assert _v(judged, "a4_missing_a5_opened", "A5") == "YES"


_LOCK_DRIVER = (
    _lift("Enter-HvTestLock")
    + r"""
$VMName = 'REVTEST01'
$Dir = $Arg
$path = Join-Path $Dir 'revtest01.lock'
$held = Enter-HvTestLock $path
try { $null = Enter-HvTestLock $path; 'second=OPENED' } catch { "second=$($_.Exception.Message)" }
$held.Dispose()
# A directory where the file should be: access denied, not a sharing violation.
$null = New-Item -ItemType Directory -Path (Join-Path $Dir 'dir.lock')
try { $null = Enter-HvTestLock (Join-Path $Dir 'dir.lock'); 'dir=OPENED' } catch { "dir=$($_.Exception.Message)" }
"""
)


@pytest.mark.skipif(sys.platform != "win32", reason="the sharing-violation HRESULT is Windows'")
def test_only_a_sharing_or_lock_violation_reads_busy(tmp_path: Path) -> None:
    driver = tmp_path / "lock.ps1"
    driver.write_text(_LOCK_DRIVER, encoding="ascii")
    second, other = _run_pwsh(driver, tmp_path, 120).strip().splitlines()
    assert second.startswith("second=STOP     REVTEST01 is busy"), second
    assert other.startswith("dir=STOP     cannot open hvtest's lock file"), other
    assert "HRESULT 0x80070005" in other, other
    assert "busy" not in other


# Host mode runs only on MEFORHV01, once. So its reboot wait and its cleanup run here against
# stand-ins for the Hyper-V and remoting cmdlets: a function shadows a cmdlet of the same name.
_HOST_DRIVER = (
    _lift("Wait-GuestSession", "Get-VMStateText", "Stop-AndRevert")
    + r"""
$VMName = 'REVTEST01'; $Checkpoint = 'cp'
$script:states = @(); $script:uptimes = @(); $script:stopFails = $false
function Write-Log([string]$Line) { }
function Start-Sleep { }
function New-PSSession { 'session' }
function Remove-PSSession { }
function Get-VM {
    $s = 'Off'
    if ($script:states.Count) { $s, $script:states = $script:states }
    [pscustomobject]@{ Heartbeat = 'OkApplicationsHealthy'; State = $s }
}
$script:reads = 0
# Past the list, a guest that has been up for days.
function Get-GuestUptimeMs {
    $script:reads++
    if ($script:reads -le $script:uptimes.Count) { $script:uptimes[$script:reads - 1] } else { 999999999 }
}
function Stop-VM { if ($script:stopFails) { throw 'stop refused' } }
function Restore-VMSnapshot { }

# No reboot asked: the first session is the one.
"none=$(Wait-GuestSession $null $null 60)"
# The first session is still the boot before (up longer than the 120 s since the ask), the second
# is the new boot.
$script:uptimes = @(900000, 30000)
"rebooted=$(Wait-GuestSession $null (Get-Date).AddSeconds(-120) 60) reads=$script:reads"
# A guest that never reboots never reads as back.
$script:reads = 0; $script:uptimes = @()
try { $null = Wait-GuestSession $null (Get-Date).AddSeconds(-120) 1; 'never=RETURNED' } catch { "never=$($_.Exception.Message)" }

$script:states = @('Off', 'Off')
"clean=[$(Stop-AndRevert $null)]"
$script:stopFails = $true; $script:states = @('Running', 'Off', 'Off')
"stopfail=$(Stop-AndRevert $null)"
$script:stopFails = $false; $script:states = @('Off', 'Saved', 'Saved')
"saved=$(Stop-AndRevert $null)"
"""
)


def test_host_reboot_wait_and_cleanup(tmp_path: Path) -> None:
    driver = tmp_path / "host.ps1"
    driver.write_text(_HOST_DRIVER, encoding="ascii")
    lines = _run_pwsh(driver, tmp_path, 120).strip().splitlines()
    out = dict(line.split("=", 1) for line in lines)
    assert out["none"] == "session"
    assert out["rebooted"] == "session reads=2"
    assert out["never"].startswith("STOP     no PowerShell Direct session"), out["never"]
    assert out["clean"] == "[]"
    assert "Stop-VM failed: stop refused" in out["stopfail"]
    assert "after Stop-VM it was Running, not Off" in out["stopfail"]
    assert out["stopfail"].startswith("STOP     REVTEST01 was not turned off and reverted")
    assert "after the revert it was Saved, not Off" in out["saved"]
    assert "it is Saved now" in out["saved"]
