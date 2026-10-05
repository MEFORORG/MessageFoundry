# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A keep that overrides a default scrub is logged, by both copies of ``load_rules`` (BACKLOG #2268).

A keep does two jobs: it records a field as reviewed, and it cancels any default scrub on that
path. A keep on ``PID-5`` therefore turns the name scrub off, and before this nothing said so.
The tee's own console line for the same event is pinned in ``tests/test_anon_b193_2267.py``,
beside the single rule load it depends on.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
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


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno == logging.WARNING:
            self.lines.append(record.getMessage())


@contextmanager
def _warnings(rules: ModuleType) -> Iterator[list[str]]:
    """The WARNING lines the module's own logger emits inside the block.

    A handler on the emitting logger, not ``caplog``: that fixture reads through the root logger,
    and ``tests/test_revocation_guard_remaining_hops.py`` records it losing records under xdist.
    """
    logger = logging.getLogger(rules.__name__)
    handler = _Collect()
    level, disabled, floor = logger.level, logger.disabled, logging.root.manager.disable
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    logger.disabled = False
    logging.disable(logging.NOTSET)
    try:
        yield handler.lines
    finally:
        logging.disable(floor)
        logger.disabled = disabled
        logger.setLevel(level)
        logger.removeHandler(handler)


@_BOTH
def test_keeping_a_default_scrubbed_field_warns(rules: ModuleType, tmp_path: Path) -> None:
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["PID-5"]\n')
    with _warnings(rules) as lines:
        loaded = rules.load_rules(overlay)

    (line,) = lines
    # The field and the kind it lost, so the reader knows which scrub is now off.
    assert "PID-5" in line
    assert "default name scrub" in line
    assert [(r.path, r.kind) for r in rules.kept_defaults(loaded)] == [
        ("PID-5", rules.SurrogateKind.NAME)
    ]


@_BOTH
def test_keeping_an_unmapped_field_does_not_warn(rules: ModuleType, tmp_path: Path) -> None:
    # EVN-1 has no default rule, so this keep only records a review. Nothing was turned off.
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["EVN-1", "ZPD-2"]\n')
    with _warnings(rules) as lines:
        loaded = rules.load_rules(overlay)

    assert lines == []
    assert rules.kept_defaults(loaded) == ()


@_BOTH
def test_each_overridden_default_gets_its_own_line(rules: ModuleType, tmp_path: Path) -> None:
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["PID-13", "EVN-1", "PID-5"]\n')
    with _warnings(rules) as lines:
        rules.load_rules(overlay)

    assert len(lines) == 2
    assert any("PID-5" in line and "default name scrub" in line for line in lines)
    assert any("PID-13" in line and "default phone scrub" in line for line in lines)
    assert not any("EVN-1" in line for line in lines)


@_BOTH
def test_a_keep_written_as_a_field_kind_warns_too(rules: ModuleType, tmp_path: Path) -> None:
    # `"PID-5" = "keep"` under [hl7.fields] cancels the scrub exactly as the keep list does.
    overlay = _overlay(tmp_path, '[hl7.fields]\n"PID-5" = "keep"\n')
    with _warnings(rules) as lines:
        rules.load_rules(overlay)

    (line,) = lines
    assert "PID-5" in line


@_BOTH
def test_an_overlay_with_no_keep_on_a_default_does_not_warn(
    rules: ModuleType, tmp_path: Path
) -> None:
    # A retarget and a drop are not keeps, and a drop beats a keep on one path. A retarget to a
    # narrower kind can still leave part of a field: that is not this warning's subject.
    overlay = _overlay(
        tmp_path,
        '[hl7]\nkeep = ["PID-13"]\ndrop = ["PID-13", "PID-11"]\n[hl7.fields]\n"PID-5" = "id"\n',
    )
    with _warnings(rules) as lines:
        loaded = rules.load_rules(overlay)

    assert lines == []
    assert rules.kept_defaults(loaded) == ()


@_BOTH
def test_no_overlay_means_no_warning(rules: ModuleType) -> None:
    with _warnings(rules) as lines:
        loaded = rules.load_rules(None)

    assert lines == []
    assert rules.kept_defaults(loaded) == ()
