# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What the widened DSN reading's segments may hold (BACKLOG #5386, added items 3 and 4).

Synthetic values only. Item 3: an empty user's first password segment refused "%", "[" and "]",
so a password-only DSN holding one printed whole. It admits them now, except a "%" that opens an
encoded HL7 separator, which the PHI pass reads a run by. Item 4: the run after the first segment
refused every ";", so a password whose own "@" was followed by a ";" before the host's "@" was cut
at that "@" and its tail printed. It admits a ";" now, except one that opens a ``key=`` member,
whose label the member pass needs. Each hidden value below printed on the code before.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from messagefoundry import secretscrub as scrub_mod
from messagefoundry.logging_setup import scrub_log_text
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.support.redact import redact_log_line

_ENTRY_POINTS: tuple[Callable[[str], str], ...] = (
    scrub_credentials,
    scrub_log_text,
    redact_log_line,
)
_IDS = ("scrub_credentials", "write-time chain", "redact_log_line")

#: Each line with the values that must not print and the text that must survive.
_NOW_HIDDEN = (
    # Item 3: "%", "[" and "]" in an empty user's first segment.
    ("connect redis://:p%40Kv9x@db.invalid failed", ("Kv9x",), "redis://:"),
    ("connect redis://:p%2FKv9x@db.invalid failed", ("Kv9x",), "redis://:"),
    ("connect redis://:Kv9x%Zq7@db.invalid failed", ("Kv9x", "Zq7"), "redis://:"),
    ("connect redis://:Kv9x[Zq7]@db.invalid failed", ("Kv9x", "Zq7"), "redis://:"),
    ("connect redis://:Kv9x]Zq7@db.invalid failed", ("Kv9x", "Zq7"), "redis://:"),
    # Item 4: a ";" that opens no member, after the password's own "@" or inside it.
    ("connect postgres://svc:Kv9x@Zq7;w@db.example.invalid/x failed", ("Kv9x", "Zq7"), "://svc:"),
    ("connect postgres://:Kv9x@Zq7;w@db.example.invalid/x failed", ("Kv9x", "Zq7"), "postgres://:"),
    ("connect redis://:Kv9x;Zq7@db.invalid failed", ("Kv9x", "Zq7"), "redis://:"),
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize(("line", "secrets", "kept"), _NOW_HIDDEN)
def test_a_segment_holding_a_newly_admitted_character_is_hidden_whole(
    line: str, secrets: tuple[str, ...], kept: str, call: Callable[[str], str]
) -> None:
    out = call(line)
    for secret in secrets:
        assert secret not in out, out
    assert kept in out and "@db." in out, out


#: The characters that still stop a segment, each with the label or separator it protects.
_STILL_STOPPED = (
    # An encoded HL7 separator in an empty user's first segment, either case.
    "connect redis://:p%7CKv9x@db.invalid failed",
    "connect redis://:p%7cKv9x@db.invalid failed",
    "connect redis://:p%5EKv9x@db.invalid failed",
    "connect redis://:p%26Kv9x@db.invalid failed",
    "connect redis://:p%7EKv9x@db.invalid failed",
    # A ";" that opens a member, in the run after the first segment.
    "connect redis://:pw;k=Kv9x@db.invalid failed",
)


@pytest.mark.parametrize("line", _STILL_STOPPED)
def test_an_encoded_separator_or_a_member_key_still_stops_the_reading(line: str) -> None:
    """Residuals, pinned so a change to them is noticed. The pattern does not match, so the line
    prints as it did before #5386."""
    assert scrub_mod._WIDE_DSN_PASSWORD.search(line) is None, line
    assert "Kv9x" in scrub_credentials(line)


@pytest.mark.parametrize(
    ("line", "secret"),
    [
        # A member after the host, its value holding an "@": its label survives to the member pass.
        (
            "store dsn postgres://svc:pw-M1@db.invalid:5432;sslpassword=Tail@Mem_Sec-76",
            "Mem_Sec-76",
        ),
        ("store dsn redis://:pw-M1@db.invalid;PWD=Tail@Mem_Sec-77", "Mem_Sec-77"),
        ("store dsn redis://:pw-M1@db.invalid;w;PWD=Tail@Mem_Sec-78", "Mem_Sec-78"),
        # A member key with a space before its "=", as ODBC writes ``User ID``: the space ends it.
        ("store dsn redis://:pw-M1@db.invalid;User ID=Tail@Mem_Sec-79", "pw-M1"),
    ],
)
def test_a_semicolon_that_opens_a_member_keeps_its_label(line: str, secret: str) -> None:
    for call in _ENTRY_POINTS:
        out = call(line)
        assert secret not in out and "pw-M1" not in out, out


def test_the_admitted_semicolon_is_the_one_that_opens_no_key() -> None:
    """The lookahead itself: a ";" is taken only where no ``=`` follows before the next ";", "@",
    "/" or whitespace."""
    wide = scrub_mod._WIDE_DSN_PASSWORD
    match = wide.search("postgres://svc:<redacted>@Zq7;w@db")
    assert match is not None and match.group(0).endswith("Zq7;w@"), match
    # A ";" before ``w=`` is refused, so the match backs off to the placeholder's own "@".
    match = wide.search("postgres://svc:<redacted>@Zq7;w=x@db")
    assert match is not None and match.group(0) == "postgres://svc:<redacted>@", match
    match = wide.search("redis://:Kv9x;a@b=c@db")
    assert match is not None and match.group(0) == "redis://:Kv9x;a@b=c@", match
