# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Four shapes the secret scrubber printed through every log surface (BACKLOG #8429).

Each would expose a credential in the write-time log, the support bundle and ``GET /logs/tail`` on
first deployment. Measured on ``origin/main`` before the fix, through ``scrub_credentials``, the
filter chain ``_install_phi_filters`` puts on a handler, and ``redact_log_line``:

1. A connection-string member whose whole key is a query-credential word, ``;key=``, ``;sig=``,
   ``;signature=``, ``;auth=`` or ``;jwt=``, printed its value whole: the member pass read a key
   only where it ENDS in a credential word or ``token``.
2. A quoted member value after a ``;pwd=x`` stop printed: a quote glued right after an earlier
   pass's placeholder ended the member value (``;PWD=P'Kv9_Sec;``), and so did a ";" inside a
   closed quoted value (``;sslpassword='Zq7;Vw9Kp2'``).
3. A password word that holds a kept word before a ":" or "=", ``Passage``, ``Statement``,
   ``Barcode``, ``Compass`` and ``Codename`` among them, printed whole: the member mask kept a word
   holding a kept word ANYWHERE, though a later pass reads one only as a whole label.
4. A label right after a backslash escape written as text, ``foo\\npassword=abc123zz`` and the
   ``%r`` of a multi-line configuration, printed its value: the escape's last letter is a word
   character, so ``\\b`` did not fire before the label.

Values are synthetic."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable

import pytest

from messagefoundry import secretscrub
from messagefoundry.logging_setup import _install_phi_filters
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.support import redact as bundle_redact
from messagefoundry.support.redact import redact_log_line
from tests.test_connection_string_member_scrub import _every_redaction_path


def _through_the_chain(fmt: str, *args: object) -> str:
    """``fmt % args`` after the filter chain ``_install_phi_filters`` puts on one handler."""
    handler = logging.NullHandler()
    _install_phi_filters(handler)
    record = logging.LogRecord("mefor.test", logging.ERROR, __file__, 1, fmt, args or None, None)
    assert handler.filter(record)
    return record.getMessage()


_SURFACES: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("scrub_credentials", scrub_credentials),
    ("handler chain", lambda line: _through_the_chain("%s", line)),
    ("redact_log_line", redact_log_line),
)
_SURFACE_IDS = [name for name, _ in _SURFACES]

#: The planted value's pieces: a mask that keeps a character's class still hides each of them.
_FRAGMENTS = ("Zq7", "Vw9", "Kp2")


def _printed(out: str) -> list[str]:
    return [fragment for fragment in _FRAGMENTS if fragment in out]


# --- 1. A bare query-credential member key ------------------------------------------------------

_BARE_MEMBERS = (
    "DRIVER={Acme};SERVER=db1.example;key=Zq7Vw9Kp2;DATABASE=mf",
    "DRIVER={Acme};SERVER=db1.example;sig=Zq7Vw9Kp2;DATABASE=mf",
    "DRIVER={Acme};SERVER=db1.example;signature=Zq7Vw9Kp2;DATABASE=mf",
    "DRIVER={Acme};SERVER=db1.example;auth=Zq7Vw9Kp2;DATABASE=mf",
    "DRIVER={Acme};SERVER=db1.example;jwt=Zq7Vw9Kp2;DATABASE=mf",
    "DRIVER={Acme};SERVER=db1.example;KEY=Zq7 Vw9,Kp2",
    "DRIVER={Acme};SERVER=db1.example;Jwt='Zq7 Vw9Kp2'",
)


@pytest.mark.parametrize("line", _BARE_MEMBERS)
@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=_SURFACE_IDS)
def test_a_member_whose_whole_key_is_a_query_credential_word_is_masked(
    surface: str, apply: Callable[[str], str], line: str
) -> None:
    out = apply(line)
    assert not _printed(out), f"{surface}: {out!r}"
    # The key stays, so a reader still sees which member was there.
    key = line.split(";")[2].split("=")[0]
    assert f";{key}=" in out, f"{surface}: {out!r}"


@pytest.mark.parametrize(
    "line",
    [
        # A key that only ends in one of the words is not read: these name ordinary members.
        "SERVER=db1.example;cache_key=Ab3;oauth=Ab3;monkey=Ab3",
        # The words alone, with no member, are left to the vocabulary that leaves them out.
        "cache lookup key=Ab3 failed, auth=Ab3",
    ],
)
def test_a_query_credential_word_that_is_not_a_whole_member_key_is_left_alone(line: str) -> None:
    assert scrub_credentials(line) == line


def test_the_member_pass_reads_each_query_credential_word_as_a_whole_key() -> None:
    """The pattern spells the words literally, for the regex scanner; this holds them to the tuple,
    and the gate to the same spelling."""
    pattern = secretscrub._CONNECTION_STRING_MEMBER.pattern
    for word in secretscrub._QUERY_CREDENTIAL_WORDS:
        assert f"(?<=;{word})" in pattern, word
        assert f";{word}=" in secretscrub._MEMBER_BARE_HINT, word
    # The union's member key leaves them out on purpose (the comment on ``_MEMBER_KEY``).
    for word in secretscrub._QUERY_CREDENTIAL_WORDS:
        assert secretscrub._MEMBER_KEY.match(f";{word}=") is None, word
        assert secretscrub._CONNECTION_STRING_MEMBER.match(f";{word}=v") is not None, word


# --- 2. A quoted member value after a stop -----------------------------------------------------

_QUOTED_AFTER_A_STOP = (
    # A quote glued right after the placeholder the label pattern wrote for "P".
    "DRIVER={Acme};SERVER=db1.example;PWD=P'Zq7Vw9_Kp2;DATABASE=mf",
    'DRIVER={Acme};SERVER=db1.example;pwd=x"Zq7 Vw9Kp2";DATABASE=mf',
    # A closed quoted value holding a ";", after a pwd=x member.
    "DRIVER={Acme};SERVER=db1.example;pwd=x;sslpassword='Zq7;Vw9 Kp2';DATABASE=mf",
    'DRIVER={Acme};SERVER=db1.example;pwd=x;sslpassword="Zq7;Vw9;Kp2" refused',
)


@pytest.mark.parametrize("line", _QUOTED_AFTER_A_STOP)
@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=_SURFACE_IDS)
def test_a_quoted_member_value_after_a_stop_is_masked(
    surface: str, apply: Callable[[str], str], line: str
) -> None:
    out = apply(line)
    assert not _printed(out), f"{surface}: {out!r}"


@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=_SURFACE_IDS)
def test_text_after_a_closed_quoted_value_keeps_its_words(
    surface: str, apply: Callable[[str], str]
) -> None:
    """The quoted value ends at its closer, so the rest of the line stays readable."""
    out = apply("connect;sslpassword='Zq7;Vw9 Kp2' refused, retry in 5s")
    assert not _printed(out), f"{surface}: {out!r}"
    assert "refused, retry in 5s" in out, f"{surface}: {out!r}"


# --- 3. A password word holding a kept word -----------------------------------------------------

_WORDS_HOLDING_A_KEPT_WORD = ("Passage", "Statement", "Barcode", "Compass", "Codename", "Bypass")


@pytest.mark.parametrize("separator", [":", "="])
@pytest.mark.parametrize("word", _WORDS_HOLDING_A_KEPT_WORD)
@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=_SURFACE_IDS)
def test_a_password_word_holding_a_kept_word_is_masked(
    surface: str, apply: Callable[[str], str], word: str, separator: str
) -> None:
    line = f"DRIVER={{Acme}};SERVER=db1.example;sslpassword={word}{separator}Zq7Vw9Kp2;PORT=1"
    out = apply(line)
    assert word not in out, f"{surface}: {word!r} printed -- {out!r}"
    assert not _printed(out), f"{surface}: {out!r}"


@pytest.mark.parametrize(
    ("line", "kept"),
    [
        # A label a later pass reads: a whole word, after a label prefix's separator, at a camelCase
        # capital, right after a "%XX" escape or a backslash escape written as text.
        (";sslpassword=a1q token=b2q;", "token"),
        (";sslpassword=a1q ad_bind_password=b2q;", "ad_bind_password"),
        (";sslpassword=a1q x.secret=b2q;", "x.secret"),
        (";sslpassword=a1q myPassword=b2q;", "myPassword"),
        (";sslpassword=a1q SharedAccessKey=b2q;", "SharedAccessKey"),
        (";sslpassword=a1q%3Bpassword=b2q;", "3Bpassword"),
        (";sslpassword=a1q\\npassword=b2q;", "npassword"),
        (";sslpassword=a1q ?code=b2q;", "code"),
        # The words read inside a longer word: the MEFOR_ prefix and the DICOM labels.
        (";sslpassword=a1q MEFOR_X=b2q;", "MEFOR_X"),
        (";sslpassword=a1q IssuerOfPatientID=b2q;", "IssuerOfPatientID"),
    ],
)
def test_a_kept_word_where_a_label_may_open_stays_whole(line: str, kept: str) -> None:
    out = scrub_credentials(line)
    assert kept in out, out
    assert "a1q" not in out and "b2q" not in out, out


def test_the_held_words_are_kept_words() -> None:
    """The words a word may hold anywhere are kept words; every other kept word is a label word."""
    held = secretscrub._MEMBER_HELD.pattern.removeprefix("(?i)").split("|")
    kept = {word.lower() for word in secretscrub._MEMBER_KEEP_WORDS}
    assert set(held) <= kept
    assert set(secretscrub._MEMBER_LABEL_WORDS) == kept - set(held)


# --- 4. A label right after a backslash escape written as text -----------------------------------

_ESCAPED_LINES = (
    "foo\\npassword=Zq7Vw9Kp2",
    "foo\\r\\npwd=Zq7Vw9Kp2",
    "foo\\ttoken=Zq7Vw9Kp2",
    "foo\\napi_key=Zq7Vw9Kp2",
    "foo\\nsecret: Zq7Vw9Kp2",
    "foo\\nprivate_key=Zq7Vw9Kp2",
    "foo\\x0cpassword=Zq7Vw9Kp2",
    "foo\\u2028password=Zq7Vw9Kp2",
    "ValueError('bad config:\\npassphrase=Zq7Vw9Kp2')",
)


@pytest.mark.parametrize("line", _ESCAPED_LINES)
@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=_SURFACE_IDS)
def test_a_label_after_an_escape_written_as_text_is_read(
    surface: str, apply: Callable[[str], str], line: str
) -> None:
    out = apply(line)
    assert not _printed(out), f"{surface}: {out!r}"


@pytest.mark.parametrize(
    "config",
    [
        "[db]\nhost = h\npassword = Zq7Vw9Kp2\n",
        "host=h\npassword=Zq7Vw9Kp2\nport=5432\n",
        "host=h\r\ntoken: Zq7Vw9Kp2\r\n",
    ],
)
def test_the_repr_of_a_multi_line_config_hides_its_credential(config: str) -> None:
    """``%r`` writes each line break as the two characters ``\\n``, so the label follows a word
    character. The control is the same line with a space before the label."""
    for out in (
        _through_the_chain("loaded config %r", config),
        scrub_credentials(repr(config)),
        redact_log_line(repr(config)),
    ):
        assert not _printed(out), out
    assert not _printed(scrub_credentials("x password=Zq7Vw9Kp2"))


def test_the_escape_start_is_part_of_the_reading_the_union_checks() -> None:
    """The start is in the three label patterns' start, which :func:`secretscrub._pre_camel` swaps
    back whole, and not in ``_LABEL_START``, which ``_AUTH_SCHEME``, the bundle's copy and the
    reading before the union share."""
    start = secretscrub._ESCAPE_START
    assert start in secretscrub._LABEL_OR_CAMEL_START
    assert start not in secretscrub._LABEL_START
    assert bundle_redact._LABEL_START == secretscrub._LABEL_START
    for name in ("_BEARER", "_CREDENTIAL_KV", "_KEY_MATERIAL"):
        pattern: re.Pattern[str] = getattr(secretscrub, name)
        assert start in pattern.pattern, name
        assert start not in secretscrub._pre_camel(pattern).pattern, name
        assert start not in secretscrub._without_escape(pattern).pattern, name
    for name in ("_AUTH_SCHEME", "_MEFOR_SECRET"):
        assert start not in getattr(secretscrub, name).pattern, name
    # A line holding one is sent to the union; a line with only a backslash is not.
    assert secretscrub._reads_camel("foo\\npassword=x", "foo\\npassword=x", "<redacted>")
    assert not secretscrub._reads_camel("C:\\data password=x", "c:\\data password=x", "<redacted>")


@pytest.mark.parametrize(
    "line",
    [
        # The shape the differential found when the start was in ``_LABEL_START``: ``_AUTH_SCHEME``
        # read the scheme word and took ``secret:`` as its credential, and the value printed.
        "x\\tBearer secret: Zq7Vw9Kp2",
        ';AccessToken=^"c3q;d4q"\\tBearer secret: mfb64:v1:\\tZq7Vw9Kp2Token=',
        # Code review: checked against the reading before BACKLOG #5545 alone, an escape label's
        # value ran over a later camelCase or compound label ``origin/main`` read, and over a
        # later member key the bundle's member pass reads.
        "ValueError('bad config:\\ntoken=xyz,accountKey: Zq7Vw9Kp2')",
        '{"err": "bad\\nsession=abc;userPassword: Zq7Vw9Kp2"}',
        "x\\ntoken=abc/clientSecret: Zq7Vw9Kp2",
        "config\\ntoken=abc;Pwd=Zq7 Vw9Kp2",
        "config\\ntoken=abc;PWD=Zq7 Vw9Kp2;",
    ],
)
def test_a_scheme_word_after_an_escape_does_not_take_a_later_label(line: str) -> None:
    for surface, apply in _SURFACES:
        assert not _printed(apply(line)), surface


@pytest.mark.parametrize(
    "line",
    [
        *_BARE_MEMBERS,
        *_QUOTED_AFTER_A_STOP,
        *(
            f"DRIVER={{Acme}};sslpassword={word}:Zq7Vw9Kp2;PORT=1"
            for word in _WORDS_HOLDING_A_KEPT_WORD
        ),
        *_ESCAPED_LINES,
    ],
)
def test_no_fragment_prints_on_a_later_redaction(line: str) -> None:
    """The member-mask regressions showed on the later paths: a second or third handler, a chain
    line the bundle reads back, and store error text. Each line is hidden on all nine."""
    paths = _every_redaction_path(line)
    assert {path: out for path, out in paths.items() if _printed(out)} == {}


@pytest.mark.parametrize(
    ("line", "read"),
    [
        # The escape letter is read case-sensitively: ``\N`` is no escape (code review).
        ("C:\\Temp\\Npassword=Zq7Vw9Kp2", False),
        # Python's eight-digit escape opens a label too.
        ("x\\U0001f600password=Zq7Vw9Kp2", True),
    ],
)
def test_the_escape_letter_is_read_as_python_writes_it(line: str, read: bool) -> None:
    for surface, apply in _SURFACES:
        assert (not _printed(apply(line))) == read, surface


@pytest.mark.parametrize("word", ["SecretName", "UserName", "ZipCode", "x_name", "x_state"])
@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=_SURFACE_IDS)
def test_a_phi_or_query_word_glued_inside_a_password_word_is_masked(
    surface: str, apply: Callable[[str], str], word: str
) -> None:
    """A query-filter key or a PHI anchor is read only at a word boundary, so a password word that
    ends in one after a capital or a "_" is masked (code review)."""
    out = apply(f"DRIVER={{Acme}};sslpassword={word}:Zq7Vw9Kp2;PORT=1")
    assert word not in out and not _printed(out), f"{surface}: {out!r}"


@pytest.mark.parametrize(
    "line",
    [
        '{"conn": "Server=h;sslpassword=\'Zq7;Vw9 Kp2\'"}',
        'Server=h;sslpassword="Zq7;Vw9 Kp2"\'',
        "<Server=h;sslpassword='Zq7;Vw9 Kp2'>",
    ],
)
def test_a_quoted_member_value_closed_before_an_outer_quote_is_masked(line: str) -> None:
    for surface, apply in _SURFACES:
        assert not _printed(apply(line)), surface
