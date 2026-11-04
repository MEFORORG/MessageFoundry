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
# Windows PowerShell 5.1, which PowerShell Direct opens in the guest: Host mode's guest steps run on
# it, and Payload mode runs each guest step on it too.
_WINPS = shutil.which("powershell.exe") if sys.platform == "win32" else None
_NEEDS_WINPS = pytest.mark.skipif(_WINPS is None, reason="Windows PowerShell 5.1 not on PATH")

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
foreach ($n in VARIABLES) {
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


def _lift(*functions: str, variables: tuple[str, ...] = ()) -> str:
    names = ("ServiceName", "Account", "NteBadKeyState", *variables)
    return _LIFT.replace("VARIABLES", ", ".join(f"'{n}'" for n in names)).replace(
        "FUNCTIONS", ", ".join(f"'{f}'" for f in functions)
    )


def _run_pwsh(driver: Path, arg: Path, timeout: int, shell: str | None = _PWSH) -> str:
    """Runs a lifting driver against the rig, under pwsh unless ``shell`` names another; returns
    its stdout, and fails on a non-zero exit."""
    assert shell is not None
    proc = subprocess.run(
        [
            shell,
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
    # A stuck counter, and A5 from a second boot ten minutes after A4's, with a tick count past
    # A4's: the clock disagrees with "same boot", so A5 is not judged against A4.
    "stuck_id_second_boot": Scenario(
        _all(
            A4=_report("A4", **STUCK_ID),
            A5=_report(
                "A5", uptime_ms="200000", boot_utc="2026-11-04T06:28:30.0000000Z", **STUCK_ID
            ),
        )
    ),
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
    "a1_protect_key_refused": Scenario(
        _no_blob_run({"protect_user": BAD_KEY}, {}), crosscheck=CROSS_ABSENT
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
    # The profile WAS seen unloaded and A3 was refused: a real answer, not a broken rig.
    "a3_refused_unloaded": Scenario(
        _all(A3=_report("A3", **REFUSED)), profile="loaded_before_start=False profile=x"
    ),
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
    # The review's case: the counter stuck at one value, report-A4 a real reboot, and report-A5's
    # uptime and boot time empty. Nothing shows A5 after a reboot, nor from A4's boot.
    "stuck_id_a5_empty_clock": Scenario(
        _all(
            A4=_report("A4", **STUCK_ID),
            A5=_report("A5", uptime_ms="", boot_utc="", **STUCK_ID),
        )
    ),
    # The same with report-A4 empty instead: A5 shows its reboot, A4 shows none.
    "stuck_id_a4_empty_clock": Scenario(
        _all(
            A4=_report("A4", uptime_ms="", boot_utc="", **STUCK_ID),
            A5=_report("A5", **STUCK_ID),
        )
    ),
    # A counter that moved, and report-A5's clock empty: A5's own counter shows the reboot, but
    # nothing shows it from report-A4's boot, so A4 cannot narrow it.
    "a5_empty_clock": Scenario(_all(A5=_report("A5", uptime_ms="", boot_utc=""))),
    # Two boot_id lines in report-A4 and in report-A5 read "7; 7", which once differed from
    # report-A3's "7" and passed for a changed counter. It is no counter at all.
    "a5_two_counters": Scenario(
        _all(
            A4=_report("A4", boot_id="7; 7"),
            A5=_report("A5", boot_id="7; 7", uptime_ms="", boot_utc=""),
        )
    ),
    # Payload mode runs no reboot, and its verdict word still says INCONCLUSIVE where the
    # pre-reboot arms do not pass.
    "payload_a3_refused_unloaded": Scenario(
        _all(A3=_report("A3", **REFUSED), A4=None, A5=None),
        profile="loaded_before_start=False profile=x",
        rebooted=False,
    ),
    "payload_a2_failed": Scenario(
        _all(A2=_report("A2", user_unprotect="FAIL win32=5"), A4=None, A5=None), rebooted=False
    ),
}

# Refusals that are not the key-state refusal: access denied, the RPC server unavailable, a FAIL
# with no last error, and invalid parameter. None names a lost key, so none may read NO. 87 is one
# the docs say tampering may also give, but nothing here measured it as damage, so it is not read
# as INVALID either: only 13, which the instrument's own tampered control gets, is. The REFUSED
# scenarios above are the positive control that the key-state refusal still reads NO.
OTHER_CODES = ("5", "1722", "0", "87")
for _c in OTHER_CODES:
    _fail = {"user_unprotect": f"FAIL win32={_c}"}
    SCENARIOS[f"a5_fail_{_c}"] = Scenario(
        _all(A4=_report("A4", **_fail), A5=_report("A5", **_fail))
    )
    SCENARIOS[f"a2_fail_{_c}"] = Scenario(_all(A2=_report("A2", **_fail)))
    SCENARIOS[f"a3_fail_{_c}_unloaded"] = Scenario(
        _all(A3=_report("A3", **_fail)), profile="loaded_before_start=False profile=x"
    )
# A boot-time start refused with a code that names no lost key, beside an A5 that opened.
SCENARIOS["a4_fail_1722_a5_opened"] = Scenario(
    _all(A4=_report("A4", user_unprotect="FAIL win32=1722"))
)


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


def _write_report(path: Path, report: dict[str, str]) -> None:
    """Writes a report as the service does: one key=value line each."""
    path.write_text("".join(f"{k}={v}\n" for k, v in report.items()), encoding="ascii")


@pytest.fixture(scope="module")
def judge_input(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A folder holding each scenario's reports, the list of them, and the judging driver."""
    root = tmp_path_factory.mktemp("dpapi-reboot-judge")
    rows = []
    for name, sc in SCENARIOS.items():
        d = root / name
        d.mkdir()
        for arm, r in sc.reports.items():
            if r is not None:
                _write_report(d / f"report-{arm}.txt", r)
        (d / "crosscheck.txt").write_text(sc.crosscheck + "\n", encoding="ascii")
        (d / "profile-A3.txt").write_text(sc.profile + "\n", encoding="ascii")
        rows.append(f"{name}|{d}|{'1' if sc.rebooted else '0'}")
    (root / "list.txt").write_text("\n".join(rows) + "\n", encoding="ascii")
    (root / "driver.ps1").write_text(_DRIVER, encoding="ascii")
    return root


@pytest.fixture(scope="module")
def judged(judge_input: Path) -> dict[str, dict[str, str]]:
    out = _parse(_run_pwsh(judge_input / "driver.ps1", judge_input / "list.txt", 300))
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
    ("a1_protect_refused", "INCONCLUSIVE"),
    ("a1_protect_key_refused", "INVALID"),
    ("a1_no_sha", "INCONCLUSIVE"),
    ("a3_control_failed", "INCONCLUSIVE"),
    ("cross_failed_a2_damaged", "INVALID"),
    ("stuck_id_second_boot", "INCONCLUSIVE"),
    ("a3_refused_unloaded", "INCONCLUSIVE"),
    ("no_id_clock_back", "INCONCLUSIVE"),
    ("a1_dpapi_down", "INCONCLUSIVE"),
    ("not_rebooted_a2_refused", "INVALID"),
    ("stuck_id_a5_empty_clock", "INCONCLUSIVE"),
    ("stuck_id_a4_empty_clock", "INCONCLUSIVE"),
    ("a5_empty_clock", "INCONCLUSIVE"),
    ("a5_two_counters", "INCONCLUSIVE"),
    ("payload_a3_refused_unloaded", "INCONCLUSIVE"),
    ("payload_a2_failed", "INCONCLUSIVE"),
    ("a3_no_report", "INCONCLUSIVE"),
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


def test_a1_protect_failure_is_no_only_for_the_key_refusal_beside_machine_scope(
    judged: Judged,
) -> None:
    # The crosscheck read ABSENT because the protect failed; the protect is what A1 reports.
    assert _v(judged, "a1_protect_key_refused", "A1") == "NO"
    assert f"protect_user {BAD_KEY}" in judged["a1_protect_key_refused"]["A1"]
    # Access denied is not the key refusal, even beside a machine scope that worked.
    assert _v(judged, "a1_protect_refused", "A1") == "INCONCLUSIVE"
    assert "protect_user FAIL win32=5" in judged["a1_protect_refused"]["A1"]
    assert _v(judged, "a1_dpapi_down", "A1") == "INCONCLUSIVE"
    assert "protect_machine FAIL win32=5" in judged["a1_dpapi_down"]["A1"]
    # Every later arm has no blob to open, and the absent crosscheck still voids them.
    for a in ("A2", "A3", "A4", "A5"):
        assert _v(judged, "a1_protect_refused", a) == "INCONCLUSIVE"


@pytest.mark.parametrize("code", OTHER_CODES)
def test_only_the_key_state_refusal_reads_no(judged: Judged, code: str) -> None:
    fail = f"FAIL win32={code}"
    for arm in ("A4", "A5"):
        assert _v(judged, f"a5_fail_{code}", arm) == "INCONCLUSIVE"
        assert f"user_unprotect {fail}, not the key-state refusal" in judged[f"a5_fail_{code}"][arm]
    # Not DOES NOT SURVIVE: the reboot arms answered nothing.
    assert _v(judged, f"a5_fail_{code}", "VERDICT") == "INCONCLUSIVE"
    # Before the reboot it is not a broken instrument either, but nor is A1 to A3 shown working.
    assert _v(judged, f"a2_fail_{code}", "A2") == "INCONCLUSIVE"
    assert fail in judged[f"a2_fail_{code}"]["A2"]
    assert _v(judged, f"a2_fail_{code}", "VERDICT") == "INCONCLUSIVE"
    assert "did not all open the blob" in judged[f"a2_fail_{code}"]["VERDICT"]
    assert judged[f"a2_fail_{code}"]["prepass"].endswith("False")
    # After a seen unload too: only the key refusal is the real A3 NO.
    assert _v(judged, f"a3_fail_{code}_unloaded", "A3") == "INCONCLUSIVE"
    assert "A3 NO" not in judged[f"a3_fail_{code}_unloaded"]["VERDICT"]


def test_an_inconclusive_verdict_names_the_reboot_arms(judged: Judged) -> None:
    # Not SURVIVES, BUT NOT AT THE BOOT-TIME START: A4's refusal names no lost key.
    verdict = judged["a4_fail_1722_a5_opened"]["VERDICT"]
    assert _v(judged, "a4_fail_1722_a5_opened", "VERDICT") == "INCONCLUSIVE"
    assert "(A4 INCONCLUSIVE, A5 YES: no survival verdict reads from these)" in verdict, verdict


def test_the_key_state_refusal_still_reads_no(judged: Judged) -> None:
    # The positive control for the test above, at each place a NO is read.
    assert _v(judged, "a5_refused", "A5") == "NO"
    assert _v(judged, "a2_refused_a5_opened", "A2") == "NO"
    assert _v(judged, "a3_refused_unloaded", "A3") == "NO"


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


def test_payload_pass_needs_a3_to_open_the_blob(judged: Judged) -> None:
    # A3 counts as passing where it opened the blob, the unload seen or not.
    assert judged["all_good"]["prepass"].endswith("True")
    assert judged["not_rebooted"]["prepass"].endswith("True")
    assert judged["profile_unloaded"]["prepass"].endswith("True")
    for scenario in (
        "a3_refused_unloaded",
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
    # Nor does it join two boots into one.
    assert _v(judged, "stuck_id_second_boot", "A5") == "INCONCLUSIVE"
    assert (
        "not shown to be from the boot report-A4 is from: unknown"
        in judged["stuck_id_second_boot"]["A5"]
    )


def test_an_a3_refusal_after_a_seen_unload_is_a_real_no(judged: Judged) -> None:
    assert _v(judged, "a3_refused_unloaded", "A3") == "NO"
    assert "A3 NO after a seen profile unload" in judged["a3_refused_unloaded"]["VERDICT"]


def test_the_boots_line_carries_the_raw_readings(judged: Judged) -> None:
    boots = judged["all_good"]["boots"]
    assert "A3 boot_id=7 uptime_ms=400000 boot_utc=2026-11-04T06:03:20.0000000Z" in boots
    assert "A4 boot_id=8 uptime_ms=90000 boot_utc=2026-11-04T06:18:30.0000000Z" in boots
    assert "A4 no report" in judged["a4_missing_a5_opened"]["boots"]


def test_a5_opening_without_a4_is_not_a_survival_verdict(judged: Judged) -> None:
    assert _v(judged, "a4_missing_a5_opened", "A4") == "INCONCLUSIVE"
    assert _v(judged, "a4_missing_a5_opened", "A5") == "YES"


_NO_REBOOT_SHOWN = "no reboot shown between report-A3 and report-{}: unknown"
_NOT_A4S_BOOT = "not shown to be from the boot report-A4 is from: unknown"


@pytest.mark.parametrize(
    ("scenario", "arm", "verdict", "why"),
    [
        # The review's case: an unmoved counter beside report-A5's empty uptime and boot time once
        # read as "same boot as A4", which carried A4's reboot over to A5 and read SURVIVES.
        ("stuck_id_a5_empty_clock", "A4", "YES", "user_unprotect OK match"),
        ("stuck_id_a5_empty_clock", "A5", "INCONCLUSIVE", _NO_REBOOT_SHOWN.format("A5")),
        # The same for A4: A5 shows its own reboot, but not that it is from report-A4's boot.
        ("stuck_id_a4_empty_clock", "A4", "INCONCLUSIVE", _NO_REBOOT_SHOWN.format("A4")),
        ("stuck_id_a4_empty_clock", "A5", "INCONCLUSIVE", _NOT_A4S_BOOT),
        # A moved counter shows A5's reboot, but not that A5 is from A4's boot.
        ("a5_empty_clock", "A5", "INCONCLUSIVE", _NOT_A4S_BOOT),
        # Two counters in one report are no counter, not a changed one.
        ("a5_two_counters", "A5", "INCONCLUSIVE", _NO_REBOOT_SHOWN.format("A5")),
    ],
)
def test_an_empty_reading_never_shows_a_reboot(
    judged: Judged, scenario: str, arm: str, verdict: str, why: str
) -> None:
    # Their overall verdicts are in _OVERALL, beside the positive controls stuck_id_tick_down and
    # stuck_id_a5_late: the same stuck counter with the readings present still reads SURVIVES.
    assert _v(judged, scenario, arm) == verdict
    assert why in judged[scenario][arm], judged[scenario][arm]


def test_the_payload_verdict_word_matches_its_exit_code(judged: Judged) -> None:
    # Payload mode judges with no reboot, and its exit code is the prepass. The overall words are
    # in _OVERALL; a payload that passes still reads NOT RUN there (not_rebooted).
    verdict = judged["payload_a3_refused_unloaded"]["VERDICT"]
    assert "A3 NO after a seen profile unload" in verdict, verdict
    assert judged["payload_a3_refused_unloaded"]["prepass"].endswith("False")
    verdict = judged["payload_a2_failed"]["VERDICT"]
    assert "did not all open the blob" in verdict, verdict
    assert judged["payload_a2_failed"]["prepass"].endswith("False")
    for arm in ("A4", "A5"):
        assert _v(judged, "payload_a2_failed", arm) == "NOT RUN"
    assert judged["not_rebooted"]["prepass"].endswith("True")


@_NEEDS_WINPS
def test_the_judge_reads_the_same_under_windows_powershell(
    judge_input: Path, judged: Judged
) -> None:
    # The rig parses under 5.1 (the lift throws on a parse error), and its judge reads every
    # scenario as pwsh 7 does.
    out = _parse(_run_pwsh(judge_input / "driver.ps1", judge_input / "list.txt", 300, _WINPS))
    assert out == judged


_REPORT_DRIVER = (
    _lift("Show-File", "Step-Report")
    + r"""
$Work = $Arg
Step-Report
"""
)


@_NEEDS_WINPS
def test_the_report_step_prints_under_windows_powershell(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    _write_report(work / "report-A1.txt", _report("A1"))
    (work / "crosscheck.txt").write_text(CROSS_OK + "\n", encoding="ascii")
    (work / "plain.bin").write_bytes(b"not a report")
    driver = tmp_path / "report.ps1"
    driver.write_text(_REPORT_DRIVER, encoding="ascii")
    out = _run_pwsh(driver, work, 120, _WINPS)
    # Every .txt in name order, each under its own header, and nothing else.
    assert out.splitlines() == [
        "===== crosscheck.txt =====",
        CROSS_OK,
        "===== report-A1.txt =====",
        *(f"{k}={v}" for k, v in _report("A1").items()),
    ]


_PAYLOAD_STEP_DRIVER = (
    _lift("Invoke-Native", "Invoke-PayloadStep")
    + r"""
$RigPath = $Rig
$log = Join-Path $Arg 'step.txt'
try { Invoke-PayloadStep $log 'Report' ''; 'step=RETURNED' } catch { "step=$($_.Exception.Message)" }
foreach ($line in Get-Content -LiteralPath $log) { "log=$line" }
"""
)


@_NEEDS_WINPS
def test_a_payload_step_runs_the_rig_under_windows_powershell(tmp_path: Path) -> None:
    # Run under pwsh 7, as hvtest runs the payload. The step's child is the rig itself under
    # powershell.exe, whose breaker refuses this machine and exits 1, so the parent fails the step.
    driver = tmp_path / "step.ps1"
    driver.write_text(_PAYLOAD_STEP_DRIVER, encoding="ascii")
    lines = _run_pwsh(driver, tmp_path, 120).splitlines()
    step = next(line for line in lines if line.startswith("step="))
    winps = "windowspowershell\\v1.0\\powershell.exe"
    assert step.startswith("step=the guest step Report failed under "), step
    assert f"{winps}; its output is in " in step.lower(), step
    assert step.endswith(str(tmp_path / "step.txt")), step
    log = [line[len("log=") :] for line in lines if line.startswith("log=")]
    assert log[0] == "----- guest step Report  -----", log
    assert any(f"{winps} -noprofile" in line.lower() and "exited '1'" in line for line in log), log
    assert any("STOP     this must run inside the VM REVTEST01" in line for line in log), log


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
    _lift("Wait-Guest", "Get-VMStateText", "Stop-AndRevert")
    + r"""
$VMName = 'REVTEST01'; $Checkpoint = 'cp'
$script:states = @(); $script:uptimes = @(); $script:stopFails = $false; $script:credFails = $false
function Write-Log([string]$Line) { }
function Start-Sleep { }
function Get-VM {
    $s = 'Off'
    if ($script:states.Count) { $s, $script:states = $script:states }
    [pscustomobject]@{ Heartbeat = 'OkApplicationsHealthy'; State = $s }
}
$script:reads = 0
# Past the list, a guest that has been up for days.
function Get-GuestUptimeMs {
    $script:reads++
    if ($script:credFails) { throw 'The credential is invalid.' }
    if ($script:reads -le $script:uptimes.Count) { $script:uptimes[$script:reads - 1] } else { 999999999 }
}
function Stop-VM { if ($script:stopFails) { throw 'stop refused' } }
function Restore-VMSnapshot { }

# No reboot asked: the first answer is the one.
Wait-Guest $null $null 60
"none=reads=$script:reads"
# The first answer is still the boot before (up longer than the 120 s since the ask), the second
# is the new boot.
$script:reads = 0; $script:uptimes = @(900000, 30000)
Wait-Guest $null ([DateTime]::UtcNow.AddSeconds(-120)) 60
"rebooted=reads=$script:reads"
# A guest that never reboots never reads as back, nor does a tick count that wrapped negative.
$script:reads = 0; $script:uptimes = @(-5)
try { $null = Wait-Guest $null ([DateTime]::UtcNow.AddSeconds(-120)) 1; 'never=RETURNED' } catch { "never=$($_.Exception.Message) reads>1=$($script:reads -gt 1)" }
# A refused credential stops the wait at the first answer.
$script:reads = 0; $script:credFails = $true
try { $null = Wait-Guest $null $null 60; 'cred=RETURNED' } catch { "cred=$($_.Exception.Message) reads=$script:reads" }
$script:credFails = $false

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
    assert out["none"] == "reads=1"
    assert out["rebooted"] == "reads=2"
    assert out["never"].startswith("STOP     no PowerShell Direct answer"), out["never"]
    assert out["never"].endswith("reads>1=True"), out["never"]
    assert out["cred"].startswith("STOP     the VM credential was refused"), out["cred"]
    assert out["cred"].endswith("reads=1"), out["cred"]
    assert out["clean"] == "[]"
    assert "Stop-VM failed: stop refused" in out["stopfail"]
    assert "after Stop-VM it was Running, not Off" in out["stopfail"]
    assert out["stopfail"].startswith("STOP     REVTEST01 was not turned off and reverted")
    assert "after the revert it was Saved, not Off" in out["saved"]
    assert "it is Saved now" in out["saved"]


# Every Host-mode guest call is a thread job with a timeout. Here Start-GuestJob is a stand-in that
# hands back a real thread job running a script in place of Invoke-Command -VMName, so the waiting,
# streaming and abandoning run as written, and the rig's behaviour on a hang (stop the job without
# waiting on it, revert, release the lock, name the arm) runs end to end. What the stand-in cannot
# show is PowerShell Direct itself: that runs only on MEFORHV01.
_HANG_DRIVER = (
    _lift(
        "Invoke-GuestCall",
        "Invoke-Guest",
        "Copy-GuestReports",
        "Get-GuestUptimeMs",
        "Wait-Guest",
        "Get-VMStateText",
        "Stop-AndRevert",
        "Invoke-Rig",
        "Invoke-HostRun",
        variables=(
            "Root",
            "Work",
            "ReportWaitSeconds",
            "BootReportWaitSeconds",
            "ProfileWaitSeconds",
            "StopWaitSeconds",
            "GuestCallSeconds",
            "PreRebootSteps",
            "AbandonedJobs",
        ),
    )
    + r"""
$VMName = 'REVTEST01'; $Checkpoint = 'cp'
# Loaded before Import-Module is shadowed below.
$null = Start-ThreadJob { 1 } | Wait-Job | Remove-Job
# Short, but long enough that a thread job meant to finish does so on a loaded runner.
foreach ($k in @($GuestCallSeconds.Keys)) { $GuestCallSeconds[$k] = 5 }
$script:log = [Collections.Generic.List[string]]::new()
$script:calls = [Collections.Generic.List[string]]::new()
$script:behaviour = @{}
$script:restores = 0; $script:stops = 0; $global:released = $false
function Write-Log([string]$Line) { $script:log.Add($Line) }
function Start-Sleep { }
function Start-Transcript { }
function Stop-Transcript { }
function Test-HostElevated { $true }
function Import-Module { }
function Get-Credential { 'cred' }
function Enter-HvTestLock {
    $o = [pscustomobject]@{}
    $o | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $global:released = $true }
    $o
}
function Get-VM { [pscustomobject]@{ Heartbeat = 'OkApplicationsHealthy'; State = 'Off' } }
function Get-VMSnapshot { [pscustomobject]@{ Name = 'cp' } }
function Get-VMSwitch { [pscustomobject]@{ SwitchType = 'Private' } }
$script:nic = $null
function Get-VMNetworkAdapter { $script:nic }
function Start-VM { }
function Stop-VM { $script:stops++ }
function Restore-VMSnapshot { $script:restores++ }
function Invoke-Judge { @{ Lines = @('DPAPI-REBOOT VERDICT: judged') } }
function Start-GuestJob($Credential, [hashtable]$Call) {
    # Keyed, not truthy: a lifted function has no $PSCommandPath, so FilePath arrives empty here.
    if ($Call.ContainsKey('FilePath')) { $label = "step $($Call.ArgumentList[1]) $($Call.ArgumentList[2])".TrimEnd() }
    elseif ($Call.ContainsKey('ArgumentList')) { $label = 'copy' } else { $label = 'uptime' }
    $script:calls.Add($label)
    switch ([string]$script:behaviour[$label]) {
        # Blocked in native code, where a stop request cannot reach it: a call that waited for
        # the stop would wait the whole 8 s.
        'hang' { Start-ThreadJob { 'partial line'; [Threading.Thread]::Sleep(8000) } }
        'fail' { Start-ThreadJob { 'before the error'; throw 'guest boom' } }
        # Ends Stopped with no error record, as a dropped transport may: stopped once it has run,
        # since a job stopped before it starts makes Receive-Job raise an error of its own.
        'stopped' {
            $j = Start-ThreadJob { 'out'; Start-Sleep -Seconds 30 }
            while (-not $j.HasMoreData) { [Threading.Thread]::Sleep(50) }
            [Threading.Thread]::Sleep(300)
            Stop-Job -Job $j
            $j
        }
        # The copy at the end hangs, the one after A3 does not.
        'hang-second' {
            $script:copies++
            if ($script:copies -ge 2) { Start-ThreadJob { [Threading.Thread]::Sleep(8000) } }
            else { Start-ThreadJob { [pscustomobject]@{ Name = 'report-A1.txt'; Bytes = [byte[]](104, 105); Error = '' } } }
        }
        default {
            if ($label -eq 'uptime') { Start-ThreadJob { 0 } }
            # A guest-supplied name with a path in it, of which only the leaf may be written, and
            # a file the guest could not read, which costs only itself.
            elseif ($label -eq 'copy') {
                Start-ThreadJob {
                    # '/', which GetFileName splits on Windows and Linux alike; on the host a '\' too.
                    [pscustomobject]@{ Name = '../report-A1.txt'; Bytes = [byte[]](104, 105); Error = '' }
                    [pscustomobject]@{ Name = 'crash-1.txt'; Bytes = $null; Error = 'in use' }
                }
            } else { $l = $label; Start-ThreadJob { "ok $using:l" } }
        }
    }
}
function Show-Run([string]$Name) {
    foreach ($line in $script:log) { "$Name log=$line" }
    "$Name calls=$($script:calls -join ',')"
    $script:allAbandoned = @($script:allAbandoned) + @($script:AbandonedJobs)
    $kept = @(Get-Job | Where-Object { $script:allAbandoned -notcontains $_ }).Count
    "$Name restores=$script:restores stops=$script:stops released=$global:released jobs=$kept"
    $script:log.Clear(); $script:calls.Clear(); $script:restores = 0; $script:stops = 0; $global:released = $false
    # Each run counts only the calls it left hung.
    $script:AbandonedJobs = @()
}

# One call: its output, an error after output, a hang, a job that ended Stopped, and no budget.
"ok=$((Invoke-GuestCall 'cred' 'x' 10 @{ FilePath = 'f'; ArgumentList = 'Guest', 'Report', '' }) -join ',')"
$script:behaviour = @{ 'step Fail' = 'fail'; 'step Hang' = 'hang'; 'step Stopped' = 'stopped' }
$got = @()
try { Invoke-GuestCall 'cred' 'x' 10 @{ FilePath = 'f'; ArgumentList = 'Guest', 'Fail', '' } | ForEach-Object { $got += $_ }; 'fail=RETURNED' }
catch { "fail=$($_.Exception.Message) got=$($got -join ',')" }
$got = @()
$t = [Diagnostics.Stopwatch]::StartNew()
try { Invoke-GuestCall 'cred' 'the guest step Hang' 3 @{ FilePath = 'f'; ArgumentList = 'Guest', 'Hang', '' } | ForEach-Object { $got += $_ }; 'hang=RETURNED' }
catch { "hang=$($_.Exception.GetType().Name)|$($_.Exception.Message)|got=$($got -join ',')|fast=$($t.Elapsed.TotalSeconds -lt 7)|kept=$(@(Get-Job | Where-Object { $script:AbandonedJobs -notcontains $_ }).Count)|abandoned=$(@($script:AbandonedJobs).Count)" }
try { Invoke-GuestCall 'cred' 'the guest step Stopped' 10 @{ FilePath = 'f'; ArgumentList = 'Guest', 'Stopped', '' }; 'stopped=RETURNED' }
catch { "stopped=$($_.Exception.Message)" }
try { Invoke-GuestCall 'cred' 'the guest step Unbudgeted' 0 @{ FilePath = 'f'; ArgumentList = 'Guest', 'Report', '' }; 'budget=RETURNED' }
catch { "budget=$($_.Exception.Message) calls=$($script:calls.Count)" }
$script:calls.Clear(); $script:allAbandoned = @($script:AbandonedJobs); $script:AbandonedJobs = @()

# A hang before the reboot, through Invoke-HostRun, so the lock release is seen.
$OutDir = Join-Path $Arg 'pre'
$script:behaviour = @{ 'step Start A2' = 'hang' }
try { Invoke-HostRun; 'pre run=RETURNED' } catch { "pre run=$($_.Exception.Message)" }
"pre leaf=$(Test-Path -LiteralPath (Join-Path (Join-Path $OutDir 'reports') 'report-A1.txt')) escaped=$(Test-Path -LiteralPath (Join-Path $OutDir 'report-A1.txt'))"
Show-Run 'pre'

# A hang after the reboot, at A5.
$OutDir = Join-Path $Arg 'post'
$null = New-Item -ItemType Directory -Path (Join-Path $OutDir 'reports')
$script:behaviour = @{ 'step Start A5' = 'hang' }
try { Invoke-Rig 'cred' $null (Join-Path $OutDir 'reports'); 'post run=RETURNED' } catch { "post run=$($_.Exception.Message)" }
Show-Run 'post'

# A STOP that is not a hang, before the VM starts: it too is printed again last.
$OutDir = Join-Path $Arg 'nic'
$script:behaviour = @{}; $script:nic = [pscustomobject]@{ SwitchName = 'External' }
try { Invoke-HostRun; 'nic run=RETURNED' } catch { "nic run=$($_.Exception.Message)" }
$script:nic = $null
Show-Run 'nic'

# Every step answers, and the copy at the end hangs: that loses report-A4 and report-A5, so it is
# a STOP too, though nothing failed before it.
$OutDir = Join-Path $Arg 'endcopy'
$script:behaviour = @{ 'copy' = 'hang-second' }; $script:copies = 0
try { Invoke-HostRun; 'endcopy run=RETURNED' } catch { "endcopy run=$($_.Exception.Message)" }
Show-Run 'endcopy'

# No hang: the whole run, and the uninstall at its end.
$OutDir = Join-Path $Arg 'clean'
$script:behaviour = @{}
try { Invoke-HostRun; 'clean run=RETURNED' } catch { "clean run=$($_.Exception.Message)" }
Show-Run 'clean'
"""
)


@pytest.fixture(scope="module")
def hang_lines(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    root = tmp_path_factory.mktemp("dpapi-reboot-hang")
    driver = root / "hang.ps1"
    driver.write_text(_HANG_DRIVER, encoding="ascii")
    return _run_pwsh(driver, root, 180).strip().splitlines()


def _run_lines(lines: list[str], name: str, key: str) -> list[str]:
    prefix = f"{name} {key}="
    return [line[len(prefix) :] for line in lines if line.startswith(prefix)]


def test_a_guest_call_returns_its_output_and_its_error(hang_lines: list[str]) -> None:
    assert "ok=ok step Report" in hang_lines
    fail = next(line for line in hang_lines if line.startswith("fail="))
    assert fail == "fail=guest boom got=before the error", fail


def test_a_hung_guest_call_is_abandoned_without_waiting_and_named(hang_lines: list[str]) -> None:
    hang = next(line for line in hang_lines if line.startswith("hang="))
    kind, message, got, fast, kept, abandoned = hang[len("hang=") :].split("|")
    assert kind == "TimeoutException"
    # No STOP at this depth: Wait-Guest retries a hung probe, so only the rig words it as a STOP.
    assert message == "the guest step Hang did not finish within 3 s", message
    # The output before the hang is still returned.
    assert got == "got=partial line"
    # Back well before the job's 8 s native block ends, so nothing waited for the stop.
    assert fast == "fast=True"
    # The hung job is left, recorded, and no other job is.
    assert kept == "kept=0"
    assert abandoned == "abandoned=1"


def test_a_job_that_ends_other_than_completed_is_a_failure(hang_lines: list[str]) -> None:
    # Stopped with output and no error record: only the state check can fail it.
    stopped = next(line for line in hang_lines if line.startswith("stopped="))
    assert stopped.startswith("stopped=the guest step Stopped ended Stopped"), stopped
    budget = next(line for line in hang_lines if line.startswith("budget="))
    # Refused before any job starts, rather than read as a hang at 0 s.
    assert budget == "budget=no timeout is set for the guest step Unbudgeted calls=4", budget


@pytest.mark.parametrize(("run", "arm"), [("pre", "Start A2"), ("post", "Start A5")])
def test_a_hang_reverts_names_the_arm_and_skips_the_rest(
    hang_lines: list[str], run: str, arm: str
) -> None:
    log = _run_lines(hang_lines, run, "log")
    stop = f"STOP     the guest step {arm} did not finish within 5 s"
    # The run fails with the STOP line, and prints it again last. It claims no revert, which its
    # own line reports.
    run_error = _run_lines(hang_lines, run, "run")[0]
    assert run_error.startswith(stop), run_error
    assert "revert" not in run_error
    assert log[-1].startswith(stop), log[-1]
    assert any(line.startswith("FAILED: System.TimeoutException") for line in log)
    # The finally ran whole: reports copied, uninstall skipped, VM reverted, judge read.
    assert "uninstall skipped: a guest call hung" in log
    assert "REVTEST01 turned off and reverted to cp; output in" in " ".join(log)
    assert "DPAPI-REBOOT VERDICT: judged" in log
    # The hung job is still in its native block at the revert, and the log says so.
    assert any(line.startswith("1 hung guest call(s) still running") for line in log), log
    calls = _run_lines(hang_lines, run, "calls")[0].split(",")
    assert calls[-1] == "copy"
    assert f"step {arm}" in calls
    assert "step Uninstall" not in calls
    # One restore at the start, one in the revert; the job is gone.
    counts = _run_lines(hang_lines, run, "restores")[0]
    assert counts.startswith("2 stops=1"), counts
    assert counts.endswith("jobs=0"), counts


def test_a_hang_still_releases_the_hvtest_lock(hang_lines: list[str]) -> None:
    assert _run_lines(hang_lines, "pre", "restores")[0].split()[2] == "released=True"
    # Only the leaf of the guest's file name is written, and a file the guest could not read is
    # logged and costs only itself.
    assert "pre leaf=True escaped=False" in hang_lines
    assert "could not copy crash-1.txt at the end: in use" in _run_lines(hang_lines, "pre", "log")
    assert "could not copy crash-1.txt after A3: in use" in _run_lines(hang_lines, "post", "log")


def test_any_stop_that_ends_the_run_is_printed_last(hang_lines: list[str]) -> None:
    stop = "STOP     REVTEST01 has an adapter on 'External', not MEFOR-Lab; not started"
    assert _run_lines(hang_lines, "nic", "run") == [stop]
    log = _run_lines(hang_lines, "nic", "log")
    assert log[-1] == stop, log[-1]
    # No guest call was made, and the uninstall is not skipped for a hang that did not happen.
    assert _run_lines(hang_lines, "nic", "calls") == [""]
    assert "uninstall skipped: a guest call hung" not in log
    assert _run_lines(hang_lines, "nic", "restores")[0] == "2 stops=1 released=True jobs=0"


def test_a_hang_in_the_end_copy_is_a_stop_too(hang_lines: list[str]) -> None:
    # Nothing failed before the copy, so the run returns, and the STOP is printed last.
    assert _run_lines(hang_lines, "endcopy", "run") == ["RETURNED"]
    log = _run_lines(hang_lines, "endcopy", "log")
    assert log[-1].startswith(
        "STOP     the copy of the reports at the end did not finish within 5 s"
    ), log[-1]
    calls = _run_lines(hang_lines, "endcopy", "calls")[0].split(",")
    assert calls[-1] == "copy"
    assert "step Start A5" in calls
    assert "step Uninstall" not in calls
    assert "REVTEST01 turned off and reverted to cp; output in" in " ".join(log)
    assert any(line.startswith("1 hung guest call(s) still running") for line in log), log


def test_a_run_without_a_hang_reaches_a5_and_uninstalls(hang_lines: list[str]) -> None:
    assert _run_lines(hang_lines, "clean", "run") == ["RETURNED"]
    calls = _run_lines(hang_lines, "clean", "calls")[0].split(",")
    reboot, boot, a5 = (
        calls.index(c) for c in ("step Reboot A4", "step BootReport A4", "step Start A5")
    )
    assert reboot < boot < a5
    assert calls[-1] == "step Uninstall"
    log = _run_lines(hang_lines, "clean", "log")
    assert not any(line.startswith("STOP") for line in log)
    assert not any("hung guest call" in line for line in log)
    assert _run_lines(hang_lines, "clean", "restores")[0] == "2 stops=1 released=True jobs=0"
