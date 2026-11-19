# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What the widened DSN reading's segments may hold (BACKLOG #5386, added items 3 and 4).

Synthetic values only. Item 3: an empty user's first password segment refused "%", "[" and "]",
so a password-only DSN holding one printed whole. It admits a "%" now, except one that opens an
encoded HL7 separator, which the PHI pass reads a run by, or the encoded form of a character it
stops at for structure, such as ",". "[" and "]" it still refuses, so it
never crosses a placeholder. Item 4, a ";" that opens no member in the run after the first segment,
was built and declined: the declined form printed a value ``origin/main`` hides, pinned below. The
comment on ``secretscrub._WIDE_DSN_PASSWORD`` says why each was kept or declined.
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

#: Item 3: a "%" in an empty user's first segment. Each hid nothing on the code before.
_NOW_HIDDEN = (
    ("connect redis://:p%40Kv9x@db.invalid failed", ("Kv9x",)),
    ("connect redis://:p%2FKv9x@db.invalid failed", ("Kv9x",)),
    ("connect redis://:Kv9x%Zq7@db.invalid failed", ("Kv9x", "Zq7")),
    ("connect redis://:Kv9x%25Zq7@db.invalid failed", ("Kv9x", "Zq7")),
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize(("line", "secrets"), _NOW_HIDDEN)
def test_a_percent_in_an_empty_users_password_is_hidden_whole(
    line: str, secrets: tuple[str, ...], call: Callable[[str], str]
) -> None:
    out = call(line)
    for secret in secrets:
        assert secret not in out, out
    assert "redis://:" in out and "@db.invalid failed" in out, out


#: Residuals, each matching nothing, so the line prints as it did before #5386: an encoded HL7
#: separator in either case, an encoded "," or ";", a bracket, and a ";" in the run after the
#: first segment.
_STILL_STOPPED = (
    "connect redis://:p%7CKv9x@db.invalid failed",
    "connect redis://:p%2CKv9x@db.invalid failed",
    "connect redis://:p%3bKv9x@db.invalid failed",
    "connect redis://:p%7cKv9x@db.invalid failed",
    "connect redis://:p%5EKv9x@db.invalid failed",
    "connect redis://:p%26Kv9x@db.invalid failed",
    "connect redis://:p%7EKv9x@db.invalid failed",
    "connect redis://:p[Kv9x]@db.invalid failed",
    "connect redis://:p;Kv9x@db.invalid failed",
)


@pytest.mark.parametrize("line", _STILL_STOPPED)
def test_an_encoded_separator_a_bracket_or_a_semicolon_still_stops_the_reading(line: str) -> None:
    assert scrub_mod._WIDE_DSN_PASSWORD.search(line) is None, line
    assert "Kv9x" in scrub_credentials(line)


def test_a_semicolon_after_a_users_placeholder_still_ends_the_match() -> None:
    """Item 4's residual: the run after the narrow pass's placeholder stops at a ";", so the
    password's tail after its own "@" prints, as on ``origin/main``."""
    match = scrub_mod._WIDE_DSN_PASSWORD.search("postgres://svc:<redacted>@Zq7;w@db")
    assert match is not None and match.group(0) == "postgres://svc:<redacted>@", match
    assert "Zq7;w" in scrub_credentials("connect postgres://svc:Kv9x@Zq7;w@db.invalid failed")


#: Lines the declined ";" alternative printed a value on, each with that value. In each a DSN is a
#: camelCase label's value, and the ";" it hid is the one the bundle's reading of the write-time
#: log line ended that value at; or the run named the wrong host.
_DECLINED_SEMICOLON = (
    ("cfg accessToken=redis://:Kv9;w@cache,userPwd='Sec_77;PWD=';UID=u;PWD=p", "Sec_77"),
    ("cfg accessToken=redis://:Kv9@Zq;w@cache,apiSecret='Sec_78;PWD=';UID=u;PWD=p", "Sec_78"),
)


@pytest.mark.parametrize(("line", "secret"), _DECLINED_SEMICOLON)
def test_the_bundle_reading_the_log_hides_the_value_the_declined_semicolon_reading_printed(
    line: str, secret: str
) -> None:
    """Only these two lines, each with a ";" inside the DSN password. It shows the shipped
    reading does not print what the declined ";" alternative printed, not that a value after a
    DSN label is hidden in general. A residual, printed on ``origin/main`` as here and not this
    test's subject: with no ";" in the password,
    ``cfg accessToken=redis://:Kv9@cache,userPwd='Sec_77;PWD='`` prints ``Sec_77`` through the
    same chain, with or without members after the quote."""
    assert secret not in redact_log_line(scrub_log_text(line))


#: KNOWN RESIDUALS, pinned as printed so the comment on ``secretscrub._WIDE_DSN_PASSWORD`` cannot
#: drift back to saying a percent-encoded password-only DSN is read wherever its "%" sits; that
#: comment states the rule. Each line with what an entry point prints of it, ``{placeholder}``
#: standing for that entry point's own. A red here means the reading changed: fix the comment
#: with it.
_PERCENT_AFTER_FIRST_SEGMENT = (
    (
        "connect redis://:p=s%40Kv9x@db.invalid failed",
        "connect redis://:p=s%40Kv9x@db.invalid failed",
    ),
    (
        "connect redis://:p%40s@Kv9x%41@db.invalid failed",
        "connect redis://:{placeholder}@Kv9x%41@db.invalid failed",
    ),
)
_PLACEHOLDERS = ("<redacted>", "<redacted>", "[REDACTED]")


@pytest.mark.parametrize(
    ("call", "placeholder"), list(zip(_ENTRY_POINTS, _PLACEHOLDERS, strict=True)), ids=_IDS
)
@pytest.mark.parametrize(("line", "printed"), _PERCENT_AFTER_FIRST_SEGMENT)
def test_known_residual_a_percent_after_the_first_segment_is_printed(
    line: str, printed: str, call: Callable[[str], str], placeholder: str
) -> None:
    assert call(line) == printed.format(placeholder=placeholder)


def test_a_semicolon_separated_address_list_keeps_its_host() -> None:
    line = "notify smtp://ops:pw@mail.local:587;alerts@corp.example failed"
    out = scrub_credentials(line)
    assert "@mail.local:587;alerts@corp.example failed" in out and "pw@" not in out, out


def test_an_encoded_comma_after_a_port_keeps_its_host() -> None:
    """An encoded "," stops an empty user's first segment as a literal one does: taken, it read
    the port and ``cc=admin`` as a password and named the recipient's domain as the host."""
    line = "notify smtp://:587%2Ccc=admin@corp.example failed"
    assert scrub_credentials(line) == line
