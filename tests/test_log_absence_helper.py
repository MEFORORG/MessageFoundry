# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The log-absence positive control fails where an absence check would pass on nothing (vault
BACKLOG #3766 item 9). Each red arm is a capture that cannot see the logger; the green arm shows
the probe is taken back out, so the absence check after it is unchanged."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator

import pytest

from tests._log_absence import assert_capture_sees, assert_capture_sees_tree, assert_no_records

_NAME = "messagefoundry.tests.log_absence_probe"


@pytest.fixture
def probe_logger(monkeypatch: pytest.MonkeyPatch) -> Iterator[logging.Logger]:
    log = logging.getLogger(_NAME)
    level = log.level
    # monkeypatch restores what an arm sets on the attributes; the level goes through setLevel,
    # which also clears the logger cache that a bare assignment would leave stale.
    monkeypatch.setattr(log, "propagate", log.propagate)
    monkeypatch.setattr(log, "disabled", log.disabled)
    try:
        yield log
    finally:
        log.setLevel(level)


def test_a_visible_logger_passes_and_the_probe_is_taken_out(
    caplog: pytest.LogCaptureFixture, probe_logger: logging.Logger
) -> None:
    with caplog.at_level(logging.WARNING, logger=_NAME):
        probe_logger.warning("a record of the code's own")
        assert_capture_sees(caplog, _NAME)
        assert [r.getMessage() for r in caplog.records] == ["a record of the code's own"]
        assert_capture_sees(caplog, probe_logger)  # a Logger object works as well as a name
        assert not [r for r in caplog.records if r.name == _NAME and "probe" in r.getMessage()]


def test_the_probe_leaves_no_text_and_reaches_no_other_handler(
    caplog: pytest.LogCaptureFixture, probe_logger: logging.Logger
) -> None:
    """Vault BACKLOG #3766 item 35: the probe line stayed in ``caplog.text`` and reached every
    other handler on its way up. The code's own record, on both sides of it, is the control."""

    class _Keep(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.messages: list[str] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.messages.append(record.getMessage())

    other = _Keep()
    probe_logger.addHandler(other)
    try:
        with caplog.at_level(logging.WARNING, logger=_NAME):
            probe_logger.warning("before the probe")
            assert_capture_sees(caplog, _NAME)
            probe_logger.warning("after the probe")
    finally:
        probe_logger.removeHandler(other)
    assert other.messages == ["before the probe", "after the probe"]
    assert "capture probe" not in caplog.text
    assert "before the probe" in caplog.text and "after the probe" in caplog.text
    assert not other.filters  # the drop filter is taken off again


def _propagate_off(log: logging.Logger) -> None:
    log.propagate = False


def _disabled(log: logging.Logger) -> None:
    log.disabled = True


def _level_above(log: logging.Logger) -> None:
    log.setLevel(logging.ERROR)


@pytest.mark.parametrize(
    "blind", [_propagate_off, _disabled, _level_above], ids=["propagate-off", "disabled", "level"]
)
def test_a_capture_that_cannot_see_the_logger_fails(
    caplog: pytest.LogCaptureFixture,
    probe_logger: logging.Logger,
    blind: Callable[[logging.Logger], None],
) -> None:
    with caplog.at_level(logging.WARNING, logger=_NAME):
        blind(probe_logger)
        # The absence check this guards would pass here: nothing reaches the capture.
        probe_logger.warning("lost")
        assert not [r for r in caplog.records if r.name == _NAME]
        with pytest.raises(AssertionError, match="would pass on nothing"):
            assert_capture_sees(caplog, _NAME)


def test_a_tree_probe_fails_where_a_child_hides_what_a_root_probe_misses(
    caplog: pytest.LogCaptureFixture, probe_logger: logging.Logger
) -> None:
    """Vault BACKLOG #3766 item 29: probing the root alone passes while a child with
    ``propagate=False`` keeps its records from the capture. The tree probe names that child."""
    root = _NAME.rsplit(".", 1)[0]
    with caplog.at_level(logging.WARNING):
        probe_logger.propagate = False
        assert_capture_sees(caplog, root)  # the root still reaches the capture
        with pytest.raises(AssertionError, match=_NAME):
            assert_capture_sees_tree(caplog, root)
        probe_logger.propagate = True
        assert_capture_sees_tree(caplog, root)


def test_no_records_probes_the_logger_it_checks(
    caplog: pytest.LogCaptureFixture, probe_logger: logging.Logger
) -> None:
    """Vault BACKLOG #3766 item 36: the absence check and its probe name one logger, so a blind
    capture fails the check rather than passing it, and a matching record fails it too."""
    with caplog.at_level(logging.WARNING, logger=_NAME):
        probe_logger.warning("unrelated")
        assert_no_records(caplog, _NAME, lambda r: "secret" in r.getMessage())
        probe_logger.warning("a secret line")
        with pytest.raises(AssertionError, match="matched"):
            assert_no_records(caplog, _NAME, lambda r: "secret" in r.getMessage())
        probe_logger.propagate = False
        with pytest.raises(AssertionError, match="would pass on nothing"):
            assert_no_records(caplog, _NAME, lambda r: False)
