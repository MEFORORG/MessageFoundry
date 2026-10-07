# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The planted-token leak scan the dead-letter WARNING tests share (BACKLOG #3043, #3108).

One copy on purpose: a second scanner can drift, and a weaker copy passes a leak.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Iterable

# The planted token. ASCII on purpose: a test may put a non-ASCII character right after it, so the
# token itself is what an ASCII-safe leak (a repr, an escaped string) would still carry.
TOKEN = "ZQXPLANTEDTOKEN"


def record_texts(record: logging.LogRecord) -> Iterable[str]:
    """Every text a record can carry: message, args and other attributes, exc_info, stack_info."""
    yield record.getMessage()
    yield repr(vars(record))  # msg, args and any extra attribute
    if record.exc_info and record.exc_info[1] is not None:
        yield "".join(traceback.format_exception(record.exc_info[1]))
    if record.exc_text:
        yield record.exc_text
    if record.stack_info:
        yield record.stack_info


def assert_no_token(
    records: Iterable[logging.LogRecord], *, skip_prefix: str | None = None
) -> None:
    """Fail if any record carries :data:`TOKEN`. ``skip_prefix`` names one exact message shape the
    caller has reported elsewhere and is not testing; nothing else is skipped."""
    leaks = [
        f"{r.name}:{r.levelname}:{r.getMessage()}"
        for r in records
        if not (skip_prefix and r.getMessage().startswith(skip_prefix))
        and any(TOKEN in text for text in record_texts(r))
    ]
    assert not leaks, f"a log record carries the planted payload token: {leaks}"
