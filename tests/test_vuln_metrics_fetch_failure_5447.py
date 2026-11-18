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

import base64
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


def test_a_kev_catalog_with_one_malformed_entry_is_unread(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A good entry beside a malformed one is not a partial catalog: the malformed entry's CVE
    would score an open PR as off KEV, so the whole catalog is unread."""
    mod = _load()
    _stub(monkeypatch, mod)
    real = mod.urllib.request.urlopen

    def urlopen(req: Any, timeout: float = 0) -> _Resp:
        if req.full_url == mod.KEV_URL:
            vulns = [{"cveID": _CVE_KEV}, {"cveId": _CVE_OTHER}]
            return _Resp(json.dumps({"vulnerabilities": vulns}).encode())
        return real(req, timeout)

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    code, row = _main(mod, tmp_path)
    assert code == 2, row
    assert row["kev_exposure_max_age_days"].startswith("n/a"), row


_RELEASE = {"tag": "v1.2.0", "at": (_NOW - timedelta(days=6)).isoformat()}


def _adopter(
    monkeypatch: pytest.MonkeyPatch,
    mod,
    requirements: str | None,
    *,
    content: str | None = None,
    release: dict[str, Any] | None = None,
    others: list[dict[str, Any]] | None = None,
) -> str:
    """``adopter_lag`` over one synthetic adopter whose requirements.txt holds ``requirements``,
    or whose contents answer carries the raw ``content`` string. The releases answer holds
    ``release`` (the engine's) after ``others``, newest first as the API lists them."""
    if content is None:
        assert requirements is not None
        content = base64.b64encode(requirements.encode()).decode()
    releases = [*(others or []), release or _RELEASE]

    def run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if argv[2].startswith("repos/example/repo/releases"):
            return subprocess.CompletedProcess(argv, 0, json.dumps(releases), "")
        return subprocess.CompletedProcess(argv, 0, json.dumps({"content": content}), "")

    monkeypatch.setattr(mod.subprocess, "run", run)
    return mod.adopter_lag("example/repo", ["example/adopter"], _NOW, 1.0)


@pytest.mark.parametrize(
    "requirements",
    [
        pytest.param("messagefoundry[vault]>=1.0\n", id="extras-range"),
        pytest.param("messagefoundry>=0.1\n", id="range"),
        pytest.param("messagefoundry~=1.2\n", id="compatible-release"),
        pytest.param("messagefoundry==1.*\n", id="wildcard"),
        pytest.param("httpx==0.28.1\n", id="no-engine-line"),
        pytest.param("messagefoundry-toolkit==0.1\n", id="toolkit-only"),
        pytest.param("messagefoundry==1.1\nmessagefoundry==1.2.0\n", id="two-lines"),
        pytest.param("messagefoundry==1.2.0\nmessagefoundry>=1.0\n", id="exact-and-range"),
    ],
)
def test_adopter_lag_is_never_zero_without_an_exact_pin(
    monkeypatch: pytest.MonkeyPatch, requirements: str
) -> None:
    mod = _load()
    lag = _adopter(monkeypatch, mod, requirements)
    assert lag.startswith("n/a") and "example/adopter" in lag, lag


@pytest.mark.parametrize(
    ("requirements", "expected"),
    [
        pytest.param("messagefoundry==1.2.0\n", "0", id="current"),
        pytest.param(
            "messagefoundry[vault] == v1.2.0 ; python_version>='3.14'\n", "0", id="extras"
        ),
        pytest.param("# pins\nmessagefoundry==1.1.0 \\\n    --hash=sha256:00\n", "6.0", id="stale"),
    ],
)
def test_control_adopter_lag_measures_an_exact_pin(
    monkeypatch: pytest.MonkeyPatch, requirements: str, expected: str
) -> None:
    """Control: an exact pin, with or without extras, a marker or a hash, is still measured."""
    mod = _load()
    assert _adopter(monkeypatch, mod, requirements) == expected


def test_adopter_content_that_is_not_base64_is_na(monkeypatch: pytest.MonkeyPatch) -> None:
    """A body that does not decode is an unread file, n/a naming it, not a crash to exit 1."""
    mod = _load()
    lag = _adopter(monkeypatch, mod, None, content="abc")
    assert lag.startswith("n/a") and "example/adopter" in lag, lag


@pytest.mark.parametrize(
    "requirements",
    [
        pytest.param("messagefoundry==1.2\n", id="padded-release"),
        pytest.param("\ufeffmessagefoundry==1.2.0\n", id="bom"),
    ],
)
def test_an_up_to_date_pin_is_not_a_lag(monkeypatch: pytest.MonkeyPatch, requirements: str) -> None:
    """``1.2`` is ``1.2.0`` under PEP 440, and a BOM does not hide a first-line pin."""
    mod = _load()
    assert _adopter(monkeypatch, mod, requirements) == "0"


def test_another_distribution_released_later_is_not_the_engine_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The repo's newest release can be another distribution's (webconsole-v...), or a draft or
    pre-release; the lag is measured against the engine release, so a current pin is still 0."""
    mod = _load()
    later = (_NOW - timedelta(days=1)).isoformat()
    others: list[dict[str, Any]] = [
        {"tag": "webconsole-v9.0.0", "at": later},
        {"tag": "v1.3.0", "at": later, "draft": True},
        {"tag": "v1.3.0rc1", "at": later, "pre": True},
    ]
    assert _adopter(monkeypatch, mod, "messagefoundry==1.2.0\n", others=others) == "0"


def test_marker_split_pins_that_agree_are_one_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load()
    requirements = (
        'messagefoundry==1.1.0 ; sys_platform == "win32"\n'
        'messagefoundry==1.1.0 ; sys_platform != "win32"\n'
    )
    assert _adopter(monkeypatch, mod, requirements) == "6.0"


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param({"labels": None}, id="null-labels"),
        pytest.param({"labels": [{"name": None}]}, id="null-label-name"),
        pytest.param({"title": None}, id="null-title"),
        pytest.param({"createdAt": 7}, id="numeric-date"),
    ],
)
def test_a_pr_list_with_a_malformed_item_is_an_unread_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bad: dict[str, Any]
) -> None:
    """A PR item whose fields the metrics cannot read crashed the run to exit 1 with no row; the
    list is an unread source instead, n/a and exit 2."""
    mod = _load()
    _stub(monkeypatch, mod)

    def run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        prs = _prs()
        prs[0].update(bad)
        return subprocess.CompletedProcess(argv, 0, json.dumps(prs), "")

    monkeypatch.setattr(mod.subprocess, "run", run)
    code, row = _main(mod, tmp_path)
    assert code == 2, row
    assert row["dependabot_prs_window"].startswith("n/a"), row


def test_an_unread_release_is_not_no_release(monkeypatch: pytest.MonkeyPatch) -> None:
    """A gh failure reading the release is named as one, not as the absence of a release."""
    mod = _load()

    def run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(argv, 1.0)

    monkeypatch.setattr(mod.subprocess, "run", run)
    lag = mod.adopter_lag("example/repo", ["example/adopter"], _NOW, 1.0)
    assert lag.startswith("n/a") and "could not read" in lag, lag


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(subprocess.TimeoutExpired(["gh"], 1.0), id="timeout"),
        pytest.param(PermissionError("synthetic"), id="not-executable"),
    ],
)
def test_a_hung_or_unexecutable_gh_is_an_unread_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: Exception
) -> None:
    mod = _load()
    _stub(monkeypatch, mod)

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert kwargs.get("timeout"), "every gh call carries a timeout"
        raise error

    monkeypatch.setattr(mod.subprocess, "run", run)
    code, row = _main(mod, tmp_path)
    assert code == 2, row
    assert row["dependabot_prs_window"].startswith("n/a"), row


def test_epss_rows_for_cves_not_asked_do_not_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mod = _load()
    _stub(monkeypatch, mod)
    real = mod.urllib.request.urlopen

    def urlopen(req: Any, timeout: float = 0) -> _Resp:
        if req.full_url.startswith(mod.EPSS_URL):
            rows = [
                {"cve": _CVE_KEV, "epss": "0.9"},
                {"cve": _CVE_OTHER, "epss": "0.1"},
                {"cve": "CVE-2099-0003", "epss": "0.95"},
            ]
            return _Resp(json.dumps({"data": rows}).encode())
        return real(req, timeout)

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    code, row = _main(mod, tmp_path)
    assert code == 0, row
    assert row["epss_coverage_pct"] == "100", row
    assert row["epss_ge_0_7_count"] == "1", row


def test_a_stale_pin_against_an_undated_release_is_na(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stale pin whose lag cannot be dated is not a lag of 0."""
    mod = _load()
    lag = _adopter(monkeypatch, mod, "messagefoundry==1.1.0\n", release={"tag": "v1.2.0"})
    assert lag.startswith("n/a"), lag
