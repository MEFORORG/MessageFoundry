# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5447: a source vuln_metrics.py could not read is reported, never recorded as zero.

The weekly RV.2 run records these metrics as evidence. A failed ``gh`` call, or a failed CISA KEV or
FIRST EPSS fetch, used to come back as an empty result that ``compute`` scored as zero exposure, and
``main`` exited 0, so a feed outage read as "no KEV exposure" in the record. Each now leaves its
metrics ``n/a`` with the source named, and ``main`` exits 2.

No test here touches the network: ``gh`` and every HTTP fetch are stubbed at the module's own
``subprocess.run`` and ``urlopen`` seams, so the failure handling under test is the script's own.
"""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import subprocess
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "security" / "vuln_metrics.py"
_NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
#: Synthetic identifiers in the CVE shape the script parses; none names a real advisory.
_CVE_KEV = "CVE-2099-0001"
_CVE_OTHER = "CVE-2099-0002"


def _load():
    spec = importlib.util.spec_from_file_location("vuln_metrics_5447", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _prs() -> list[dict[str, Any]]:
    opened = (_NOW - timedelta(days=10)).isoformat()
    return [
        {
            "number": 1,
            "title": f"Bump libx for {_CVE_KEV}",
            "body": "",
            "state": "OPEN",
            "createdAt": opened,
            "mergedAt": None,
            "labels": [{"name": "security"}],
        },
        {
            "number": 2,
            "title": f"Bump liby for {_CVE_OTHER}",
            "body": "",
            "state": "MERGED",
            "createdAt": (_NOW - timedelta(days=4)).isoformat(),
            "mergedAt": (_NOW - timedelta(days=3)).isoformat(),
            "labels": [{"name": "security"}],
        },
    ]


class _Resp(io.BytesIO):
    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _stub(
    monkeypatch: pytest.MonkeyPatch,
    mod,
    *,
    gh_ok: bool = True,
    kev_ok: bool = True,
    epss_ok: bool = True,
) -> None:
    def run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if not gh_ok:
            raise subprocess.CalledProcessError(1, argv, "", "gh: synthetic failure")
        return subprocess.CompletedProcess(argv, 0, json.dumps(_prs()), "")

    def urlopen(req: Any, timeout: float = 0) -> _Resp:
        url = req.full_url
        if url == mod.KEV_URL:
            if not kev_ok:
                raise urllib.error.URLError("synthetic KEV outage")
            return _Resp(json.dumps({"vulnerabilities": [{"cveID": _CVE_KEV}]}).encode())
        if url.startswith(mod.EPSS_URL):
            if not epss_ok:
                raise TimeoutError("synthetic EPSS timeout")
            rows = [{"cve": _CVE_KEV, "epss": "0.9"}, {"cve": _CVE_OTHER, "epss": "0.1"}]
            return _Resp(json.dumps({"data": rows}).encode())
        raise AssertionError(f"unexpected fetch {url}")

    monkeypatch.setattr(mod.subprocess, "run", run)
    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)


def _main(mod, tmp_path: Path) -> tuple[int, dict[str, str]]:
    out = tmp_path / "m.csv"
    code = mod.main(["--repo", "example/repo", "--csv", str(out), "--now", _NOW.isoformat()])
    with out.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    return code, rows[0]


def test_control_every_source_answers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Control: with every source answering, the run exits 0 and the KEV age is measured."""
    mod = _load()
    _stub(monkeypatch, mod)
    code, row = _main(mod, tmp_path)
    assert code == 0, row
    assert row["kev_exposure_max_age_days"] == "10.0"
    assert row["epss_coverage_pct"] == "100"
    assert row["dependabot_prs_window"] == "2"


def test_a_failed_gh_call_is_not_an_empty_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mod = _load()
    _stub(monkeypatch, mod, gh_ok=False)
    code, row = _main(mod, tmp_path)
    assert code == 2, row
    for key in (
        "dependabot_prs_window",
        "security_prs_window",
        "kev_exposure_max_age_days",
        "epss_ge_0_7_count",
    ):
        assert row[key].startswith("n/a"), (key, row[key])


def test_a_failed_kev_fetch_is_not_zero_exposure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The open PR's CVE is on KEV; with KEV unreadable the age must not read as 0."""
    mod = _load()
    _stub(monkeypatch, mod, kev_ok=False)
    code, row = _main(mod, tmp_path)
    assert code == 2, row
    assert row["kev_exposure_max_age_days"].startswith("n/a"), row
    assert row["dep_mttr_kev_days"].startswith("n/a"), row
    assert row["dependabot_prs_window"] == "2", "a KEV outage must not blank the PR metrics"


def test_a_failed_epss_fetch_is_not_zero_coverage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mod = _load()
    _stub(monkeypatch, mod, epss_ok=False)
    code, row = _main(mod, tmp_path)
    assert code == 2, row
    assert row["epss_coverage_pct"].startswith("n/a"), row
    assert row["epss_ge_0_7_count"].startswith("n/a"), row
    assert row["kev_exposure_max_age_days"] == "10.0", "an EPSS outage must not blank KEV"


def test_a_kev_catalog_with_renamed_fields_is_unread(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A catalog whose entries carry no cveID answered, but not as KEV: not zero exposure."""
    mod = _load()
    _stub(monkeypatch, mod)
    real = mod.urllib.request.urlopen

    def urlopen(req: Any, timeout: float = 0) -> _Resp:
        if req.full_url == mod.KEV_URL:
            return _Resp(json.dumps({"vulnerabilities": [{"cveId": _CVE_KEV}]}).encode())
        return real(req, timeout)

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    code, row = _main(mod, tmp_path)
    assert code == 2, row
    assert row["kev_exposure_max_age_days"].startswith("n/a"), row


def test_epss_rows_with_renamed_fields_are_unread(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mod = _load()
    _stub(monkeypatch, mod)
    real = mod.urllib.request.urlopen

    def urlopen(req: Any, timeout: float = 0) -> _Resp:
        if req.full_url.startswith(mod.EPSS_URL):
            # One good row beside one that does not parse: a partial answer, not a measurement.
            rows = [{"cve": _CVE_OTHER, "epss": "0.1"}, {"cve_id": _CVE_KEV, "score": "0.9"}]
            return _Resp(json.dumps({"data": rows}).encode())
        return real(req, timeout)

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    code, row = _main(mod, tmp_path)
    assert code == 2, row
    assert row["epss_ge_0_7_count"].startswith("n/a"), row


def test_control_a_kev_outage_with_no_cve_seen_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Control: with no security PR citing a CVE, KEV is not asked, so its outage cannot red the run."""
    mod = _load()
    _stub(monkeypatch, mod, kev_ok=False)

    def run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        plain = [{**p, "title": "Bump libz", "labels": []} for p in _prs()]
        return subprocess.CompletedProcess(argv, 0, json.dumps(plain), "")

    monkeypatch.setattr(mod.subprocess, "run", run)
    code, row = _main(mod, tmp_path)
    assert code == 0, row
    assert row["kev_exposure_max_age_days"] == "0"
