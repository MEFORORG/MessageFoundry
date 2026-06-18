# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the parity report aggregator (tee/report.py)."""

from __future__ import annotations

from tee.correlate import CorepointOutput, MeforOutput
from tee.report import build_report


def _msg(
    *,
    app: str = "APP",
    recv: str = "DOWN",
    recvfac: str = "DFAC",
    dt: str = "20260604120000",
    ctrl: str = "C",
    pid3: str = "100^^^H^MR",
    pid5: str = "DOE^JANE",
    msgtype: str = "ADT^A01",
) -> str:
    return (
        f"MSH|^~\\&|{app}|SF|{recv}|{recvfac}|{dt}||{msgtype}|{ctrl}|P|2.5.1\r"
        f"PID|1||{pid3}||{pid5}\r"
    )


def test_build_report_counts() -> None:
    exact_body = _msg(ctrl="C1", pid3="100^^^H^MR")
    mefor = [
        MeforOutput("m1", "C1", "OB", exact_body),  # exact
        MeforOutput("m2", "C2", "OB", _msg(ctrl="C2", pid3="200^^^H^MR", app="MEFOR")),  # semantic
        MeforOutput(
            "m3", "C3", "OB", _msg(ctrl="C3", pid3="300^^^H^MR", pid5="DOE^JANE")
        ),  # mismatch
        MeforOutput("m4", "C4", "OB", _msg(ctrl="C4", pid3="444^^^H^MR")),  # missing on Corepoint
    ]
    corepoint = [
        CorepointOutput("C1", exact_body),
        # same control id (correlates) but sending-app + datetime differ -> all ignored -> semantic
        CorepointOutput(
            "C2", _msg(ctrl="C2", pid3="200^^^H^MR", app="COREPOINT", dt="20260604120059")
        ),
        CorepointOutput(
            "C3", _msg(ctrl="C3", pid3="300^^^H^MR", pid5="DOE^JOHN")
        ),  # PID-5 -> mismatch
        CorepointOutput("C9", _msg(ctrl="C9", pid3="999^^^H^MR")),  # missing on MEFOR
    ]
    s = build_report(mefor, corepoint)["summary"]
    assert s["exact"] == 1
    assert s["semantic"] == 1
    assert s["mismatch"] == 1
    assert s["matched"] == 3
    assert s["missing_on_corepoint"] == 1
    assert s["missing_on_mefor"] == 1
    assert s["mefor_outputs"] == 4
    assert s["corepoint_outputs"] == 4
    assert s["match_methods"] == {"control_id": 3}


def test_diffs_excluded_by_default() -> None:
    body = _msg(ctrl="C1")
    report = build_report([MeforOutput("m1", "C1", "OB", body)], [CorepointOutput("C1", body)])
    assert "diffs" not in report  # PHI field values are off by default


def test_diffs_included_when_requested_carry_phi_values() -> None:
    mefor = [MeforOutput("m3", "C3", "OB", _msg(ctrl="C3", pid3="300^^^H^MR", pid5="DOE^JANE"))]
    corepoint = [CorepointOutput("C3", _msg(ctrl="C3", pid3="300^^^H^MR", pid5="DOE^JOHN"))]
    report = build_report(mefor, corepoint, include_diffs=True)
    [diff] = report["diffs"]
    assert diff["kind"] == "mismatch"
    assert diff["method"] == "control_id"
    assert diff["control_id"] == "C3"
    assert diff["destination"] == ["DOWN", "DFAC"]
    pid5 = next(fd for fd in diff["field_diffs"] if fd["location"] == "PID-5")
    assert (pid5["left"], pid5["right"], pid5["ignored"]) == ("DOE^JANE", "DOE^JOHN", False)


def test_exact_pair_emits_no_diff_entry_even_when_requested() -> None:
    body = _msg(ctrl="C1")
    report = build_report(
        [MeforOutput("m1", "C1", "OB", body)], [CorepointOutput("C1", body)], include_diffs=True
    )
    assert report["summary"]["exact"] == 1
    assert report["diffs"] == []
