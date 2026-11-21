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

import functools
import logging
import re
from collections.abc import Callable

import pytest

from messagefoundry import secretscrub as scrub_mod
from messagefoundry.logging_setup import _install_phi_filters, scrub_log_text
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
    # After user@host, a run of digits no word character follows is a port (code review).
    "proxy http://user@host.invalid:8080!admin@corp.invalid up",
    "proxy http://user@host.invalid:8080]admin@corp.invalid up",
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize("placeholder", ["[REDACTED]", "<redacted>", "[redacted]"])
def test_a_placeholder_alone_before_the_at_sign_is_read_back(
    placeholder: str, call: Callable[[str], str]
) -> None:
    """In every widened branch a placeholder the "@" follows is read back, so it becomes the
    surface's own placeholder and nothing else changes; ``origin/main`` left these as they came."""
    for head in ("redis://:", "postgres://ops@srv:", "postgres://svc:@"):
        out = call(f"connect {head}{placeholder}@db.invalid failed")
        assert out in {
            f"connect {head}<redacted>@db.invalid failed",
            f"connect {head}[REDACTED]@db.invalid failed",
        }, out


#: The store error text logged and bundled, with an empty user whose password holds a bracket:
#: wave 3 lets that segment take "[" and "]", so the bundle's first pass writes its placeholder
#: after ``//:``, and before the read-back the second pass printed ``Zq2x`` (code review).
_EMPTY_USER_BRACKET_LINES = (
    "x ws://:p[w9]@h;pwd=x9 state=Zq1@z<Server=h;sslpassword=p%40p userPwd='Zq2x;PWD='",
    "x ws://:]x@h;pwd=x9 state=Zq1@z<Server=h;sslpassword=p%40p userPwd='Zq2x;PWD='",
    "x redis://:[Kv9@h;pwd=x9 state=Zq1@z<Server=h;sslpassword=p%40p userPwd='Zq2x;PWD='",
)


@pytest.mark.parametrize("line", _EMPTY_USER_BRACKET_LINES)
def test_an_empty_users_bracket_password_prints_nothing_main_hid_through_store_log_bundle(
    line: str,
) -> None:
    out = _store_log_bundle(line)
    assert "Zq2x" not in out, out


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


def _one_handler(text: str) -> str:
    """``text`` after the filter chain ``_install_phi_filters`` puts on one handler, in order, the
    helper ``tests/test_log_redaction_secret_domain.py`` keeps, copied so this file imports no
    other test module."""
    handler = logging.NullHandler()
    _install_phi_filters(handler)
    record = logging.LogRecord("mefor.test", logging.ERROR, __file__, 1, text, None, None)
    for handler_filter in handler.filters:
        assert isinstance(handler_filter, logging.Filter)
        handler_filter.filter(record)
    return record.getMessage()


def _two_handlers(line: str) -> str:
    return _one_handler(_one_handler(line))


def _store_path(line: str) -> str:
    """The store error text: the bundle's redactor, cut to 300, then one handler."""
    return _one_handler(redact_log_line(line)[:300])


def _store_log_bundle(line: str) -> str:
    """The store error text redacted, logged through one handler, then read again by the bundle."""
    return redact_log_line(_one_handler(redact_log_line(line)))


_CHAINED = {
    "chain then bundle": _chain_then_bundle,
    "two handlers": _two_handlers,
    "store path": _store_path,
    "store, log, bundle": _store_log_bundle,
}

#: The store error text, logged and then bundled, after a user holding an "@": the bundle's first
#: pass wrote its placeholder after ``ops@srv:``, the write-time chain did not read it back, and
#: the bundle, finding its own placeholder in the line, did not split on it, so ``Zq2x`` printed
#: (code review). It printed on ``b532w3-5386`` at ``47e61981770``; ``origin/main`` hides it.
_STORE_LOG_BUNDLE_LINE = (
    "x ws://ops@srv:pw@h;pwd=x9 state=Zq1@z<Server=h;sslpassword=p%40p userPwd='Zq2x;PWD='"
)

#: Lines a password's leading "@" let print on a chained path where ``origin/main`` hid the value:
#: on the lead arm's first build the segment after the "@" signs was the user's, which takes ";",
#: "|", "^", "#", "&" and quotes (code review, findings 1 and 2). Each is the line, the path, and
#: the value. Each printed that value on ``b532w3-5386`` at ``47e61981770`` and is hidden on
#: ``origin/main``.
_LEAD_CHAINED = (
    (
        "cfg accessToken=redis://ops:@Kv9;w@cache,userPwd='Sec_77;PWD=';UID=u;PWD=p",
        "chain then bundle",
        "Sec_77",
    ),
    (
        "cfg accessToken=redis://ops:@Kv9\"w@cache,userPwd='Sec_77;PWD=';UID=u;PWD=p",
        "chain then bundle",
        "Sec_77",
    ),
    (
        "cfg accessToken=redis://ops:@Kv9;w@cache,userPwd='Sec_77;PWD='#UID=u;PWD=p",
        "two handlers",
        "Sec_77",
    ),
    (
        "cfg accessToken=redis://ops:@@@Kv9'w@cache,userPwd='Sec_77;PWD='|UID=u;PWD=p",
        "two handlers",
        "Sec_77",
    ),
    (
        "x ws://svc:Qc7728_Sec-0w@h:587&dbPassword=mrn7728y1t(redis://ops:S7728k2j@h\\nPassword: "
        "Tk7728x3q;mrn7728y93t<http://a.b:Tk7728x4q@Qc7728_Sec-55w@h:8765+redis://ops:@Tk7728x5q|"
        "mrn7728y56t@Qc7728_Sec-57w:pw7728Z58v@h:587",
        "store path",
        "mrn7728y93t",
    ),
    (
        "x ws://svc:Qc7728_Sec-0w@h:587&dbPassword=mrn7728y1t(redis://ops:S7728k2j@h\\nPassword: "
        "Tk7728x3q;mrn7728y93t<http://a.b:@Tk7728x4q^Qc7728_Sec-55w@h:8765+redis://ops:@Tk7728x5q#"
        "mrn7728y56t@Qc7728_Sec-57w:pw7728Z58v@h:587",
        "store path",
        "mrn7728y93t",
    ),
    (_STORE_LOG_BUNDLE_LINE, "store, log, bundle", "Zq2x"),
)

#: Controls on the same chained paths, each hidden on ``origin/main`` and on the first build: the
#: user@host forms of the first four lines above, and the plain-user form of the bundle lines. The
#: plain-user form through two handlers prints ``Sec_77`` on ``origin/main`` too, so it is no
#: control.
_CHAINED_CONTROLS = (
    (_STORE_LOG_BUNDLE_LINE.replace("ops@srv:", "svc:@"), "store, log, bundle", "Zq2x"),
    (
        "cfg accessToken=redis://ops@srv:Kv9;w@cache,userPwd='Sec_77;PWD=';UID=u;PWD=p",
        "chain then bundle",
        "Sec_77",
    ),
    (
        "cfg accessToken=redis://ops:Kv9;w@cache,userPwd='Sec_77;PWD=';UID=u;PWD=p",
        "chain then bundle",
        "Sec_77",
    ),
    (
        "cfg accessToken=redis://ops@srv:Kv9\"w@cache,userPwd='Sec_77;PWD=';UID=u;PWD=p",
        "chain then bundle",
        "Sec_77",
    ),
    (
        "cfg accessToken=redis://ops:Kv9\"w@cache,userPwd='Sec_77;PWD=';UID=u;PWD=p",
        "chain then bundle",
        "Sec_77",
    ),
    (
        "cfg accessToken=redis://ops@srv:Kv9;w@cache,userPwd='Sec_77;PWD='#UID=u;PWD=p",
        "two handlers",
        "Sec_77",
    ),
    (
        "cfg accessToken=redis://ops@srv:Kv9'w@cache,userPwd='Sec_77;PWD='|UID=u;PWD=p",
        "two handlers",
        "Sec_77",
    ),
    (
        "cfg accessToken=redis://ops@srv:@@Kv9'w@cache,userPwd='Sec_77;PWD='|UID=u;PWD=p",
        "two handlers",
        "Sec_77",
    ),
)


@pytest.mark.parametrize(("line", "path", "secret"), _LEAD_CHAINED + _CHAINED_CONTROLS)
def test_a_lead_or_user_at_host_dsn_prints_nothing_main_hid_on_a_chained_path(
    line: str, path: str, secret: str
) -> None:
    out = _CHAINED[path](line)
    assert secret not in out, out


def test_a_lead_is_followed_by_the_empty_users_segment() -> None:
    """After a password's leading "@" signs the segment stops where an empty user's does, so a
    separator there ends the match; the same password with no lead is the user's, which takes it,
    as ``_DSN_PASSWORD`` does."""
    wide = scrub_mod._WIDE_DSN_PASSWORD
    for sep in (";", "|", "^", "#", "&", "'", '"'):
        assert wide.search(f"redis://ops:@Kv9{sep}w@cache") is None, sep
    assert wide.search("redis://ops:Kv9;w@cache") is not None
    match = wide.search("redis://ops:@Kv9w@cache")
    assert match is not None and match.group("lead") == "@", match
    # After user@host a password that opens with "@", and an empty one, are not read: that branch
    # has no group to keep the "@" signs in (code review).
    for line in ("postgres://u@h:@pw@x", "smtp://u@h:@x"):
        assert wide.search(line) is None, line


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
    # After user@host or a lead, the segment is an empty user's, which stops at ";", "#", a quote,
    # "," and the rest, and an all-digit password reads as a port; after user@host a password that
    # opens with "@" is not read. The same password after a plain user is hidden.
    ("x postgres://ops@srv:Kv9;x@db.invalid", "Kv9;x"),
    ("x postgres://ops@srv:Kv9#x@db.invalid", "Kv9#x"),
    ("x postgres://ops@srv:Kv9'x@db.invalid", "Kv9'x"),
    ("x postgres://ops@srv:Kv9,x@db.invalid", "Kv9,x"),
    ("x postgres://ops@srv:123456@db.invalid", "123456"),
    ("x postgres://ops@srv:@Kv9x@db.invalid", "Kv9x"),
    ("x postgres://svc:@Kv9;x@db.invalid", "Kv9;x"),
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize(("line", "printed"), _KNOWN_RESIDUALS)
def test_known_residual_prints(line: str, printed: str, call: Callable[[str], str]) -> None:
    assert printed in call(line)


def test_a_placeholder_is_never_crossed_by_an_empty_users_segment() -> None:
    """The bracket admission stops at a bracketed word of letters, the shape of ``<redacted>``,
    ``[redacted]`` and ``[REDACTED]``, so the tail after one prints as it did; control: a bracket
    around a non-word is taken."""
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
# 1k to 16k, 16x the length: linear near 16x, quadratic near 256x. The bar is 48x. A 64k input is
# not run here: a quadratic regression would stall the suite there rather than fail. The control is
# a quadratic subject that must exceed the bar on this box, so a bar the shipped code passes is one
# a quadratic one fails. It runs in the same test as every shape, so no selection runs the shapes
# without it.

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
    ("lead then bracket run", lambda n: "postgres://svc:@" + ("[a" * n)[:n]),
    ("lead then bracket lookahead run", lambda n: "postgres://svc:@" + ("[aaaa" * n)[:n]),
    ("lead then equals run", lambda n: "postgres://svc:@" + ("a=" * n)[:n]),
    ("lead then separators", lambda n: "postgres://svc:@a" + ("=b|" * n)[:n]),
)

_MEMBER_SHAPES: tuple[tuple[str, Callable[[int], str]], ...] = (
    ("glued quotes", lambda n: ";pwd=" + ("a'" * n)[:n]),
    ("braced then glued quotes", lambda n: ";pwd={x}" + ("a'" * n)[:n]),
    ("member keys", lambda n: (";pwd=a'b" * n)[:n]),
)


def test_the_dsn_and_member_patterns_grow_linearly_and_the_control_does_not() -> None:
    """One test, so the control cannot be deselected apart from the shapes it vouches for."""
    ratio = _growth_between(
        lambda text: _BACKTRACKING_WIDE.sub("x", text),
        "redis://:" + "a" * _CONTROL_SHORT,
        "redis://:" + "a" * _CONTROL_LONG,
        rounds=2,
    )
    assert ratio > _MAX_GROWTH, f"the backtracking control grew only {ratio:.1f}x"
    for pattern, shapes in (
        (scrub_mod._WIDE_DSN_PASSWORD, _SHAPES),
        (scrub_mod._CONNECTION_STRING_MEMBER, _MEMBER_SHAPES),
    ):
        for label, shape in shapes:
            _assert_linear(label, functools.partial(pattern.sub, "x"), shape)
