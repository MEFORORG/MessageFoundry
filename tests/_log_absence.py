# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A log-absence check needs a positive control: proof that ``caplog`` sees the logger at all.

``assert not [r for r in caplog.records if ...]`` passes on nothing when the capture cannot see the
logger the code under test writes through, at least: a logger with ``propagate=False``, a disabled
one, and a level above the probe's (vault BACKLOG #3766 item 9).

What it proves, and what it does not. It proves the capture sees that logger at that level WHEN THE
PROBE RUNS. Inside the act's ``caplog.at_level`` block that is the act's own capture; after the
block it shows at least that the logger still propagates to the capture and is not disabled, not
that a lower-level record from the act was captured. It does not prove the code under test logs
through that logger, or that it reached the line that would have logged.
"""

from __future__ import annotations

import logging

import pytest

#: Marks the probe on the record, so a filter that rewrites the message in place cannot hide it.
_PROBE_ATTR = "_log_absence_probe"


def assert_capture_sees(
    caplog: pytest.LogCaptureFixture, logger: str | logging.Logger, level: int = logging.WARNING
) -> None:
    """Fail unless ``caplog`` captures a ``level`` record sent through ``logger``, then take it out
    of ``caplog.records`` so the absence check after this call is unchanged."""
    log = logger if isinstance(logger, logging.Logger) else logging.getLogger(logger)
    log.log(level, "log-absence capture probe", extra={_PROBE_ATTR: True})
    probes = [r for r in caplog.records if getattr(r, _PROBE_ATTR, False)]
    assert len(probes) == 1, (
        f"caplog did not capture a {logging.getLevelName(level)} record sent through "
        f"{log.name!r}, so an absence check over that logger would pass on nothing"
    )
    caplog.records.remove(probes[0])
