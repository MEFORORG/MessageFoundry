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
_DRIVER = r"""
param([string]$Rig, [string]$List)
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
foreach ($n in 'Read-Report', 'Get-Verdict', 'Get-BootReading', 'Get-BootRelation', 'Invoke-Judge') {
    $f = @($top | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $n })
    if ($f.Count -ne 1) { throw "the rig defines $n $($f.Count) times at top level" }
    . ([scriptblock]::Create($f[0].Extent.Text))
}
foreach ($row in Get-Content -LiteralPath $List) {
    $name, $dir, $rebooted = $row -split '\|'
    "==== $name"
    (Invoke-Judge $dir ($rebooted -eq '1')).Lines
}
"""

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
    "same_boot_id": Scenario(_all(A4=_report("A4", boot_id="7"), A5=_report("A5", boot_id="7"))),
    "two_boots": Scenario(_all(A5=_report("A5", boot_id="9"))),
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
    "a1_protect_refused": Scenario(_all(A1=_report("A1", protect_user="FAIL win32=5"))),
    "a1_dpapi_down": Scenario(
        _all(A1=_report("A1", protect_user="FAIL win32=5", protect_machine="FAIL win32=5"))
    ),
    "a1_refused_cross_absent": Scenario(
        _all(A1=_report("A1", protect_user="FAIL win32=5")),
        crosscheck="admin_open=ABSENT by x exit=0",
    ),
    "not_rebooted": Scenario(_all(A4=None, A5=None), rebooted=False),
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
    assert _PWSH is not None
    proc = subprocess.run(
        [
            _PWSH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(root / "driver.ps1"),
            "-Rig",
            str(_RIG),
            "-List",
            str(root / "list.txt"),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = _parse(proc.stdout)
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
    ("same_boot_id", "INCONCLUSIVE"),
    ("two_boots", "INCONCLUSIVE"),
    ("no_id_same_boot", "INCONCLUSIVE"),
    ("no_id_skewed_clock", "SURVIVES"),
    ("no_id_empty_uptime", "INCONCLUSIVE"),
    ("not_rebooted", "NOT RUN"),
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
    assert _v(judged, "a1_protect_refused", "A1") == "NO"
    assert _v(judged, "a1_dpapi_down", "A1") == "INCONCLUSIVE"
    # The crosscheck is a precondition of every arm, A1's NO included.
    assert _v(judged, "a1_refused_cross_absent", "A1") == "INCONCLUSIVE"


def test_without_a_reboot_the_reboot_arms_read_not_run(judged: Judged) -> None:
    assert _v(judged, "not_rebooted", "A4") == "NOT RUN"
    assert _v(judged, "not_rebooted", "A5") == "NOT RUN"
