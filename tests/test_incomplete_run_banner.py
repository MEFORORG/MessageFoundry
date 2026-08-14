# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The incomplete-run banner (BACKLOG #1230, loud-omission half).

Proved in BOTH directions, because a banner that always prints and a banner that never prints are
both indistinguishable from a working one if you only ever observe the state you happen to be in.
This worktree's venv is missing all five extras, so the "fires" direction is the ambient case and
the SILENT direction is the one that needs staging.
"""

from __future__ import annotations

from typing import Any

from tests import _extras_probe as probe


class _FakeReporter:
    """Captures what the summary hook writes. Mirrors only the two methods the hook uses."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.seps: list[str] = []

    def write_line(self, line: str, **_: Any) -> None:
        self.lines.append(line)

    def write_sep(self, _sep: str, title: str = "", **_kw: Any) -> None:
        self.seps.append(title)


def test_a_resolvable_sentinel_reads_as_installed() -> None:
    """Positive control: the probe must be capable of returning True at all, or every other
    assertion here would pass against a predicate that can only ever say 'absent'."""
    assert probe.extra_is_installed(("json",)) is True
    assert probe.extra_is_installed(("json", "pathlib")) is True


def test_an_absent_sentinel_reads_as_missing() -> None:
    assert probe.extra_is_installed(("mefor_no_such_module_1230",)) is False


def test_one_absent_sentinel_condemns_the_whole_extra() -> None:
    """A half-installed extra must read as absent -- its tests still cannot be collected."""
    assert probe.extra_is_installed(("json", "mefor_no_such_module_1230")) is False


def test_a_missing_parent_package_reads_as_missing_not_as_present() -> None:
    """``find_spec`` RAISES rather than returning None when the parent package is absent. If that
    arm were not caught, the fhir extra (``fhir.resources``) would report as installed."""
    assert probe.extra_is_installed(("mefor_no_such_parent_1230.child",)) is False


def test_silent_when_every_extra_resolves(monkeypatch: Any) -> None:
    """The direction this venv cannot show on its own: nothing missing means nothing printed."""
    monkeypatch.setattr(probe, "OPTIONAL_EXTRAS", {"stdlib": ("json",)})
    assert probe.missing_extras() == []
    assert probe.report_header_lines() == []
    reporter = _FakeReporter()
    probe.write_incomplete_run_summary(reporter)
    assert reporter.lines == []
    assert reporter.seps == []


def test_loud_when_an_extra_is_absent(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        probe, "OPTIONAL_EXTRAS", {"stdlib": ("json",), "ghost": ("mefor_no_such_module_1230",)}
    )
    assert probe.missing_extras() == ["ghost"]
    header = probe.report_header_lines()
    assert len(header) == 1
    assert "ghost" in header[0]

    reporter = _FakeReporter()
    probe.write_incomplete_run_summary(reporter)
    body = "\n".join(reporter.lines)
    assert "ghost" in body
    assert "stdlib" not in body  # only what is actually absent is named
    assert any("INCOMPLETE RUN" in title for title in reporter.seps)
    # The remedy has to be present and has to name the absent extra, or the banner states a problem
    # without a way out and gets ignored.
    assert 'pip install --constraint constraints.lock -e ".[dev,harness,ghost]"' in body


def test_the_real_extra_table_matches_pyproject() -> None:
    """The table is hand-maintained beside pyproject.toml; assert it still names the five extras CI
    installs, so a renamed or dropped extra fails here instead of silently never being reported."""
    assert set(probe.OPTIONAL_EXTRAS) == {"fhir", "dicom", "x12", "xml", "webauthn"}
