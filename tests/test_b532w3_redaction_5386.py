# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DSN and connection-string member readings, BACKLOG #5386's remainder (batch 532, wave 3).

Synthetic values only. Each ``_NOW_HIDDEN`` line printed some of its secret on ``origin/main`` at
``9421dcbf27``: a member value after a quote glued inside it, a user holding an "@", a user's
password starting with "@", and an empty user's password holding a "[" or "]". The controls are
lines that must still print whole or stay hidden, so the widening is neither a pattern that hides
everything nor one that prints what ``origin/main`` hid. The known residuals are pinned as printed.
The growth tests hold the widened DSN pattern and the member pattern linear.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import pytest

from messagefoundry import secretscrub as scrub_mod
from messagefoundry.logging_setup import scrub_log_text
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.support.redact import redact_log_line
from tests._growth import _growth_between


def _chain_then_bundle(line: str) -> str:
    return redact_log_line(scrub_log_text(line))


_ENTRY_POINTS: tuple[Callable[[str], str], ...] = (
    scrub_credentials,
    scrub_log_text,
    redact_log_line,
    _chain_then_bundle,
)
_IDS = ("scrub_credentials", "write-time chain", "redact_log_line", "chain then bundle")

#: Each line with the pieces of its secret that must not print, and text that must survive so an
#: operator can still tell which store or key it was.
_NOW_HIDDEN = (
    # A quote glued between word characters inside a member value ended the value there.
    ("x;sslpassword=P'Kv9_Sec;", ("Kv9", "Sec"), ";sslpassword="),
    ('x;sslpassword=P"Kv9_Sec;', ("Kv9", "Sec"), ";sslpassword="),
    ("x;sslpassword=P'Kv9_Sec' refused", ("Kv9", "Sec"), "' refused"),
    ("x;PWD={a}b'Kv9_Sec;", ("Kv9", "Sec"), ";PWD="),
    # A user holding an "@", the user@server login of a hosted database.
    (
        "connect postgres://us@er:Kv9xZq7w@db.example.invalid/x failed",
        ("Kv9x", "Zq7w"),
        "://us@er:",
    ),
    ("connect postgres://ops@srv:Kv9_Az@srv.example.invalid/x failed", ("Kv9_Az",), "://ops@srv:"),
    # A user's password that starts with "@".
    ("store dsn postgres://svc:@Lead_At-74@db.invalid/m", ("Lead_At-74",), "://svc:@"),
    ("store dsn postgres://svc:@@Kv9x_Lead@db.invalid/m", ("Kv9x_Lead",), "://svc:@@"),
    # An empty user's password holding a "[" that opens no bracketed word, or a "]".
    ("connect redis://:p[Kv9x]@db.invalid failed", ("Kv9x",), "redis://:"),
    ("connect redis://:Kv9x]Zq7@db.invalid failed", ("Kv9x", "Zq7"), "redis://:"),
    ("connect redis://:[Kv9x@db.invalid failed", ("Kv9x",), "redis://:"),
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize(("line", "secrets", "kept"), _NOW_HIDDEN)
def test_the_secret_is_hidden_on_every_surface(
    line: str, secrets: tuple[str, ...], kept: str, call: Callable[[str], str]
) -> None:
    out = call(line)
    for secret in secrets:
        assert secret not in out, out
    assert kept in out, out


#: Lines that hold no secret the widening may take, or a placeholder's shape it must not cross:
#: each prints exactly as it arrives on every surface.
_UNCHANGED = (
    "store dsn postgres://svc@db.invalid:5432/mefor",
    "proxy http://user@host.invalid:8080,admin@corp.invalid up",
    "notify smtp://ops@mail.local:587;alerts@corp.example failed",
    "connect redis://:[REDACTED]@db.invalid failed",
    "connect redis://:<redacted>@db.invalid failed",
    # After user@host, a run of digits no word character follows is a port (code review).
    "proxy http://user@host.invalid:8080!admin@corp.invalid up",
    "proxy http://user@host.invalid:8080]admin@corp.invalid up",
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize("line", _UNCHANGED)
def test_a_line_with_no_password_prints_whole(line: str, call: Callable[[str], str]) -> None:
    assert call(line) == line


#: Lines ``origin/main`` hides on every surface, each with what must stay hidden. A draft of the
#: JDBC no-user fix, since backed out, printed each of these (code review).
_STILL_HIDDEN = (
    ("jdbc:sqlserver://db.invalid:1433;sslpassword=Mykey:Zq7w@Tail;", ("Mykey", "Zq7w")),
    ("connect postgres://svc:Ab;Mypass=Zq7@db.invalid/x failed", ("Mypass", "Zq7", "Ab;")),
    ("jdbc:mysql://svc:2024;Zq7Kpass=Kv9@db.invalid/x", ("Zq7Kpass", "Kv9")),
    ("jdbc:sqlserver://db.invalid:1433;user=svc;sslpassword=P'Kv9_Sec@x", ("Kv9", "Sec")),
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize(("line", "secrets"), _STILL_HIDDEN)
def test_what_origin_main_hid_stays_hidden(
    line: str, secrets: tuple[str, ...], call: Callable[[str], str]
) -> None:
    """Controls, not fail-befores: each line is hidden on ``origin/main``."""
    out = call(line)
    for secret in secrets:
        assert secret not in out, out


@pytest.mark.parametrize("call", [redact_log_line, _chain_then_bundle], ids=_IDS[2:])
def test_the_bundle_still_hides_a_camelcase_value_after_a_jdbc_member(
    call: Callable[[str], str],
) -> None:
    """A control on the bundle only: ``origin/main`` hides ``Zq7`` there, and prints it on the
    write-time chain and in one scrub, as this code does."""
    out = call("jdbc:sqlserver://db.invalid:1433;sslpassword=P@ss; note userPwd='Zq7;PWD='")
    assert "Zq7" not in out, out


def test_a_quote_that_ends_a_member_value_still_ends_it() -> None:
    """The text after a closing quote stays readable: a quote after a space, or before one, or
    before a separator, is not glued between word characters."""
    for line, after in (
        ("'Server=h;PWD=a b' refused", "' refused"),
        ('{"cs":"Server=h;PWD=abc","next":"v"}', '","next":"v"}'),
        ("x;xpass=nonnumeric port: 'd4q@h'", "'d4q@h'"),
    ):
        assert scrub_credentials(line).endswith(after), line


def test_prose_after_a_glued_apostrophe_is_masked_to_the_next_semicolon() -> None:
    """The cost of the glued-quote rule, pinned so a change shows up: ``origin/main`` printed
    ``'t accepted`` here, and the word after the apostrophe is now masked too."""
    assert scrub_credentials("x;sslpassword=Kv9_Sec wasn't accepted") == (
        "x;sslpassword=xx0_xxx xxxx'x xxxxxxxx"
    )


#: KNOWN RESIDUALS, pinned as printed, each printing as on ``origin/main``. A red means the reading
#: changed, and the comments on ``secretscrub._WIDE_DSN_PASSWORD`` and
#: ``_CONNECTION_STRING_MEMBER`` must change with it. Each pairs a line with what prints.
_KNOWN_RESIDUALS = (
    # A key _CREDENTIAL_KV reads first ends its value at the glued quote.
    ("x;PWD=P'Kv9_Sec;", "Kv9_Sec"),
    ("Server=h;Password=P'Kv9_Sec;Database=d", "Kv9_Sec"),
    ('x;pwd=P"Kv9_Sec;', "Kv9_Sec"),
    # A JDBC DSN with no user before its host: the narrow match takes the member's key.
    ("jdbc:sqlserver://db.invalid:1433;user=svc;sslpassword=P@ss_Sec9;", "ss_Sec9"),
    # After user@host: a password opening with digits then a non-word character, a host word
    # holding "_", and a user holding two "@".
    ("postgres://ops@srv:12-Kv9Az@srv.example.invalid/x", "12-Kv9Az"),
    ("postgres://ops@srv_1:Kv9_Az@srv.example.invalid/x", "Kv9_Az"),
    ("postgres://a@b@srv:Kv9_Az@srv.example.invalid/x", "Kv9_Az"),
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize(("line", "printed"), _KNOWN_RESIDUALS)
def test_known_residual_prints(line: str, printed: str, call: Callable[[str], str]) -> None:
    assert printed in call(line)


def test_a_placeholder_is_never_crossed_by_an_empty_users_segment() -> None:
    """The bracket admission stops at a bracketed word of letters, which is every placeholder's
    shape, so the tail after one prints as it did; control: a bracket around a non-word is taken."""
    wide = scrub_mod._WIDE_DSN_PASSWORD
    for line in (
        "redis://:[REDACTED]tail@db",
        "redis://:x[redacted]tail@db",
        "redis://:p[abc]q@db",
    ):
        assert wide.search(line) is None, line
    assert wide.search("redis://:p[ab9]q@db") is not None


# --- GROWTH -----------------------------------------------------------------------------------
#
# 1k to 16k, 16x the length: linear near 16x, quadratic near 256x. The bar is 48x. A 64k input was
# measured by hand (in the commit) and is not run here: a quadratic regression would stall the
# suite there rather than fail. The control is a quadratic subject that must exceed the bar on this
# box, so a bar the shipped code passes is one a quadratic one fails.

_SHORT, _LONG = 1024, 16384
_CONTROL_SHORT, _CONTROL_LONG = 512, 8192
_MAX_GROWTH = 48.0

#: The widened pattern's skeleton with backtracking first segments, the same control
#: ``tests/test_b532r_redaction_dsn.py`` keeps, copied so this file imports no other test module.
_BACKTRACKING_WIDE = re.compile(
    r"(?i)(?<![a-z0-9+.\-])([a-z0-9+.\-]+://[^\s:/@]*):"
    r"(?:(?<=//:)[^\s/@?#&=;,()|^~{}<>\[\]%\x27\x22]*|(?<!//:)[^\s/@<>\[\]]+)"
    r"[^\s/;?#&,()|^~{}<>\[\]%\x27\x22]*@"
)


def _assert_linear(label: str, call: Callable[[str], object], shape: Callable[[int], str]) -> None:
    ratio = _growth_between(call, shape(_SHORT), shape(_LONG), rounds=3)
    assert ratio <= _MAX_GROWTH, f"{label}: {ratio:.1f}x for {_LONG // _SHORT}x the length"


_SHAPES: tuple[tuple[str, Callable[[int], str]], ...] = (
    ("empty user, bracket run", lambda n: "redis://:" + ("[a" * n)[:n]),
    ("empty user, closing bracket run", lambda n: "redis://:" + ("a]" * n)[:n]),
    ("empty user, bracket lookahead run", lambda n: "redis://:" + ("[aaaa" * n)[:n]),
    ("user with an at sign, one class", lambda n: "postgres://u@h:" + "a" * n),
    ("user with an at sign, at-sign run", lambda n: "postgres://u@h:" + ("a@" * n)[:n] + " "),
    ("user with an at sign, digit run", lambda n: "postgres://u@h:" + "1" * n),
    ("user, at-sign run", lambda n: "postgres://" + ("a@" * n)[:n]),
    ("lead at signs", lambda n: "postgres://svc:" + "@" * n),
    ("lead at signs and letters", lambda n: "postgres://svc:" + ("@a" * n)[:n] + " "),
    ("user at-host pairs", lambda n: "postgres://" + ("x@y:" * n)[:n]),
    ("glued heads with an at-sign user", lambda n: ("a://u@h:" * n)[:n]),
)

_MEMBER_SHAPES: tuple[tuple[str, Callable[[int], str]], ...] = (
    ("glued quotes", lambda n: ";pwd=" + ("a'" * n)[:n]),
    ("braced then glued quotes", lambda n: ";pwd={x}" + ("a'" * n)[:n]),
    ("member keys", lambda n: (";pwd=a'b" * n)[:n]),
)


def test_the_backtracking_control_grows_past_the_bar() -> None:
    ratio = _growth_between(
        lambda text: _BACKTRACKING_WIDE.sub("x", text),
        "redis://:" + "a" * _CONTROL_SHORT,
        "redis://:" + "a" * _CONTROL_LONG,
        rounds=2,
    )
    assert ratio > _MAX_GROWTH, f"the backtracking control grew only {ratio:.1f}x"


@pytest.mark.parametrize(("label", "shape"), _SHAPES, ids=[s[0] for s in _SHAPES])
def test_the_widened_dsn_pattern_grows_linearly(label: str, shape: Callable[[int], str]) -> None:
    _assert_linear(label, lambda text: scrub_mod._WIDE_DSN_PASSWORD.sub("x", text), shape)


@pytest.mark.parametrize(("label", "shape"), _MEMBER_SHAPES, ids=[s[0] for s in _MEMBER_SHAPES])
def test_the_member_pattern_grows_linearly(label: str, shape: Callable[[int], str]) -> None:
    _assert_linear(label, lambda text: scrub_mod._CONNECTION_STRING_MEMBER.sub("x", text), shape)
