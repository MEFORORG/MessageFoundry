# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A keep that overrides a default scrub is logged, by both copies of ``load_rules`` (BACKLOG #2268).

A keep does two jobs: it records a field as reviewed, and it cancels any default scrub on that
path. Keeping ``PID-5`` to clear a coverage refusal therefore turns the name scrub off, and before
this nothing said so. The tee's own console line for the same event is pinned in
``tests/test_anon_b193_2267.py``, beside the single rule load it depends on.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry.anon import rules as engine_rules
from tee.anon import rules as tee_rules

_BOTH = pytest.mark.parametrize("rules", [engine_rules, tee_rules], ids=["engine", "tee"])


def _overlay(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "anon.toml"
    path.write_text(body, encoding="utf-8")
    return path


def _warnings(caplog: pytest.LogCaptureFixture, rules: ModuleType) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == rules.__name__ and r.levelno == logging.WARNING
    ]


@_BOTH
def test_keeping_a_default_scrubbed_field_warns(
    rules: ModuleType, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["PID-5"]\n')
    with caplog.at_level(logging.WARNING, logger=rules.__name__):
        loaded = rules.load_rules(overlay)

    (line,) = _warnings(caplog, rules)
    # The field and the kind it lost, so the reader knows which scrub is now off.
    assert "PID-5" in line
    assert "name" in line
    assert [(r.path, r.kind) for r in rules.kept_defaults(loaded)] == [
        ("PID-5", rules.SurrogateKind.NAME)
    ]


@_BOTH
def test_keeping_an_unmapped_field_does_not_warn(
    rules: ModuleType, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # EVN-1 has no default rule, so this keep only records a review. Nothing was turned off.
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["EVN-1", "ZPD-2"]\n')
    with caplog.at_level(logging.WARNING, logger=rules.__name__):
        loaded = rules.load_rules(overlay)

    assert _warnings(caplog, rules) == []
    assert rules.kept_defaults(loaded) == ()


@_BOTH
def test_each_overridden_default_gets_its_own_line(
    rules: ModuleType, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["PID-13", "EVN-1", "PID-5"]\n')
    with caplog.at_level(logging.WARNING, logger=rules.__name__):
        rules.load_rules(overlay)

    lines = _warnings(caplog, rules)
    assert len(lines) == 2
    assert any("PID-5" in line and "name" in line for line in lines)
    assert any("PID-13" in line and "phone" in line for line in lines)
    assert not any("EVN-1" in line for line in lines)


@_BOTH
def test_a_keep_written_as_a_field_kind_warns_too(
    rules: ModuleType, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # `"PID-5" = "keep"` under [hl7.fields] cancels the scrub exactly as the keep list does.
    overlay = _overlay(tmp_path, '[hl7.fields]\n"PID-5" = "keep"\n')
    with caplog.at_level(logging.WARNING, logger=rules.__name__):
        rules.load_rules(overlay)

    (line,) = _warnings(caplog, rules)
    assert "PID-5" in line


@_BOTH
def test_an_overlay_that_still_scrubs_the_field_does_not_warn(
    rules: ModuleType, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # A retarget and a drop both still rewrite the field, and a drop beats a keep on one path.
    overlay = _overlay(
        tmp_path,
        '[hl7]\nkeep = ["PID-13"]\ndrop = ["PID-13", "PID-11"]\n[hl7.fields]\n"PID-5" = "id"\n',
    )
    with caplog.at_level(logging.WARNING, logger=rules.__name__):
        loaded = rules.load_rules(overlay)

    assert _warnings(caplog, rules) == []
    assert rules.kept_defaults(loaded) == ()


@_BOTH
def test_no_overlay_means_no_warning(rules: ModuleType, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=rules.__name__):
        loaded = rules.load_rules(None)

    assert _warnings(caplog, rules) == []
    assert rules.kept_defaults(loaded) == ()
