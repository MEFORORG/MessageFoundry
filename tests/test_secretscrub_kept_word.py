# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connection-string member mask keeps a word before a ":" or "=" only where a later pass reads
it as a label (BACKLOG #8429 item 1, BACKLOG #5030 added item 9), and three neighbouring shapes the
mask does not reach yet, pinned as strict expected failures.

Measured on ``origin/main`` before the change, through ``scrub_credentials``, the filter chain
``_install_phi_filters`` puts on a handler, and ``redact_log_line``: inside a member value, a
password word that HOLDS a kept word anywhere, such as ``Passage``, ``Statement``, ``Barcode``,
``Compass``, ``Codename`` or ``Bypass``, printed whole before a ":" or "=", though no pass reads a
label there. On first deployment that word of a password would reach the write-time log, the
support bundle and ``GET /logs/tail``.

Values are synthetic."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable

import pytest

from messagefoundry import secretscrub
from messagefoundry.logging_setup import _install_phi_filters
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.support.redact import redact_log_line
from tests.test_connection_string_member_scrub import _NEVER, _every_redaction_path


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


# --- The kept-word fix --------------------------------------------------------------------------

_WORDS_HOLDING_A_KEPT_WORD = ("Passage", "Statement", "Barcode", "Compass", "Codename", "Bypass")
#: A PHI JSON key word after a "." or "-": the PHI pass reads one only as a whole quoted key.
_PHI_WORDS_INSIDE_A_WORD = ("my-name", "x.address", "a-b.given", "x.birthDate")


def _member(word: str, separator: str) -> str:
    return f"DRIVER={{Acme}};SERVER=db1.example;sslpassword={word}{separator}Zq7Vw9Kp2;PORT=1"


@pytest.mark.parametrize("separator", [":", "="])
@pytest.mark.parametrize("word", _WORDS_HOLDING_A_KEPT_WORD + _PHI_WORDS_INSIDE_A_WORD)
@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=_SURFACE_IDS)
# Per surface, for a readable failure id; the nine-path test below covers the same lines too.
def test_a_password_word_holding_a_kept_word_is_masked(
    surface: str, apply: Callable[[str], str], word: str, separator: str
) -> None:
    out = apply(_member(word, separator))
    assert word not in out, f"{surface}: {word!r} printed -- {out!r}"
    assert not _printed(out), f"{surface}: {out!r}"


@pytest.mark.parametrize(
    ("line", "kept"),
    [
        # A label a later pass reads: a whole word, after a label prefix's "_" or a ".", at a
        # camelCase capital, or right after a "%XX" escape.
        (";sslpassword=a1q token=b2q;", "token"),
        (";sslpassword=a1q ad_bind_password=b2q;", "ad_bind_password"),
        (";sslpassword=a1q x.secret=b2q;", "x.secret"),
        (";sslpassword=a1q myPassword=b2q;", "myPassword"),
        (";sslpassword=a1q SharedAccessKey=b2q;", "SharedAccessKey"),
        (";sslpassword=a1q StorageAccountKey=b2q;", "StorageAccountKey"),
        (";sslpassword=a1q%3Bpassword=b2q;", "3Bpassword"),
        (";sslpassword=a1q ?code=b2q;", "code"),
        (";sslpassword=a1q x.code=b2q;", "x.code"),
        # A PHI JSON key word, whole.
        (";sslpassword=a1q name=b2q;", "name"),
        # A query-filter key the filter reads whole, though it holds two kept words elsewhere.
        (";sslpassword=a1q session_state=b2q;", "session_state"),
        (";sslpassword=a1q x.session_state=b2q;", "x.session_state"),
        # A member key right after a ";" inside a braced value, which the member pass reads.
        (";sslpassword={a1q;sslkeypassword=b2q};", "sslkeypassword"),
        # The words read inside a longer word: the MEFOR_ prefix and the DICOM labels.
        (";sslpassword=a1q MEFOR_X=b2q;", "MEFOR_X"),
        (";sslpassword=a1q IssuerOfPatientID=b2q;", "IssuerOfPatientID"),
    ],
)
def test_a_kept_word_where_a_label_may_open_stays_whole(line: str, kept: str) -> None:
    out = scrub_credentials(line)
    assert kept in out, out
    assert "a1q" not in out and "b2q" not in out, out


def test_the_label_words_are_the_kept_words_outside_the_held_ones() -> None:
    """The words a word may hold anywhere are kept words; every other kept word, and each key the
    write-time query filter reads, is a label word, and each passes the kept-word gate
    ``_kept_word`` checks first, so none is refused before ``_read_as_label`` sees it."""
    held = secretscrub._MEMBER_HELD.pattern.removeprefix("(?i)").split("|")
    kept = {word.lower() for word in secretscrub._MEMBER_KEEP_WORDS}
    assert set(held) <= kept
    query = set(secretscrub._CREDENTIAL_QUERY_KEYS)
    assert set(secretscrub._MEMBER_LABEL_WORDS) == (kept - set(held)) | query
    for word in secretscrub._MEMBER_LABEL_WORDS:
        assert secretscrub._MEMBER_KEEP.search(word) is not None, word
    assert {w.lower() for w in secretscrub._CAMEL_WORDS} == secretscrub._MEMBER_CAMEL_LABELS
    for word in secretscrub._MEMBER_KEY_WORDS:
        assert f"(?<={word})" in secretscrub._CONNECTION_STRING_MEMBER.pattern, word


_MASKED_WORDS = _WORDS_HOLDING_A_KEPT_WORD + _PHI_WORDS_INSIDE_A_WORD
_KEPT_WORD_LINES = tuple(_member(word, sep) for sep in ":=" for word in _MASKED_WORDS)


@pytest.mark.parametrize("line", _KEPT_WORD_LINES)
def test_no_fragment_prints_on_a_later_redaction(line: str) -> None:
    """The member-mask regressions showed on the later paths: a second or third handler, a chain
    line the bundle reads back, and store error text. Each line is hidden on all nine."""
    paths = _every_redaction_path(line)
    assert {path: out for path, out in paths.items() if _printed(out)} == {}


def test_the_kept_words_print_under_the_rule_before(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE NEGATIVE CONTROL: with ``_read_as_label`` swapped for the rule before BACKLOG #8429,
    which kept a word holding a kept word anywhere, each word prints on every surface again, so the
    function is what hides it."""
    monkeypatch.setattr(secretscrub, "_read_as_label", lambda _text, _word, _start: True)
    for word in _MASKED_WORDS:
        for surface, apply in _SURFACES:
            assert word in apply(_member(word, ":")), (surface, word)


#: Each opening ``_read_as_label`` keeps a word at, switched off, with a line the seeded
#: differential against ``origin/main`` found then printing, on a later path, a value the rule
#: before hid. So each opening is there for a measured reason. In order: ``PatientName`` masked is
#: no DICOM label for the PHI pass, which took the rest of the line; ``session_state``, ``.code``,
#: ``_token`` and ``myPassword`` masked are no label for the query filter or the label passes of a
#: later redaction, which read on past the member's end.
_OPENING_CONTROLS = (
    (
        "held words anywhere",
        "_MEMBER_HELD",
        _NEVER,
        "DRIVER={X};SERVER=h;KeyStorepwd=,PatientName:\n{d4q e5q}'AToken\"=a1qxx_state': "
        "'d4q e5q' tail b2q",
    ),
    (
        "query-filter keys",
        "_MEMBER_LABEL_WORDS",
        tuple(w for w in secretscrub._MEMBER_LABEL_WORDS if w != "session_state"),
        "postgres://svc:;sslpassword=session_state=a1qa1qdigestx=;'d4q e5q'' refused",
    ),
    (
        "a label start",
        "_MEMBER_WORD_AT",
        _NEVER,
        "Barcode19800505id_token;sslpassword=x.code=;%5Eb2qgivenkey=",
    ),
    (
        "a label prefix's underscore",
        "_MEMBER_PREFIX_AT",
        _NEVER,
        'DRIVER={X};SERVER=h;PWD="Codename#a1q&x-family="a1q@dbxaccess_token": '
        "Zq7Vw9a1qaccess_token:\nf6q;b2q;PORT=1",
    ),
    (
        "a camelCase capital",
        "_MEMBER_CAMEL_AT",
        _NEVER,
        ";KeyStorepwd=myPassword:\n^e5qa1qpwdBearer ",
    ),
)

_PLANTED = re.compile(r"[a-f][1-6]q|Zq7Vw9")


def _printed_where_the_rule_before_hid(line: str, before: dict[str, str]) -> list[str]:
    """The paths where a planted value prints more often than under the rule before. Counted, not
    only present, since these lines plant one value several times and the rule before may hide
    one copy and print another; the planted values are read from the output, which may be
    respelled."""
    paths = _every_redaction_path(line)
    return [
        path
        for path, out in paths.items()
        if any(out.count(f) > before[path].count(f) for f in set(_PLANTED.findall(out)))
    ]


@pytest.mark.parametrize(
    ("attr", "off", "line"),
    [control[1:] for control in _OPENING_CONTROLS],
    ids=[control[0] for control in _OPENING_CONTROLS],
)
def test_each_opening_is_needed(
    monkeypatch: pytest.MonkeyPatch, attr: str, off: object, line: str
) -> None:
    """With the rule before as the baseline, the shipped rule prints nothing on any path the
    baseline hid; with one opening off, it does."""
    with monkeypatch.context() as patched:
        patched.setattr(secretscrub, "_read_as_label", lambda _text, _word, _start: True)
        before = _every_redaction_path(line)
    assert _printed_where_the_rule_before_hid(line, before) == []
    assert getattr(secretscrub, attr) != off  # the switch is not a no-op
    monkeypatch.setattr(secretscrub, attr, off)
    assert _printed_where_the_rule_before_hid(line, before)


# --- Shapes the member mask does not reach yet, pinned as strict expected failures --------------
#
# Each test asserts the value is HIDDEN and fails on this code. A first attempt at each (branch
# p12/scrubber-gaps) printed on the first pass a value ``origin/main`` hides, so each waits on the
# single-scan redesign of the label passes, BACKLOG #3122. A change that hides one turns its test
# green, and the strict marker then fails the run, so the change must move it here.

_REDESIGN = (
    "the fix needs the single-scan redesign of BACKLOG #3122: a first attempt (branch "
    "p12/scrubber-gaps) printed on the first pass a value origin/main hides"
)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BACKLOG #5030 added item 7: a member whose whole key is key, sig, auth or jwt would print "
        "its value on first deployment, since the member pass reads a key only where it ENDS in a "
        "credential word or token; " + _REDESIGN
    ),
)
@pytest.mark.parametrize("key", ["key", "sig", "auth", "jwt"])
@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=_SURFACE_IDS)
def test_a_member_whose_whole_key_is_a_query_credential_word_is_hidden(
    surface: str, apply: Callable[[str], str], key: str
) -> None:
    out = apply(f"DRIVER={{Acme}};SERVER=db1.example;{key}=Zq7Vw9Kp2;DATABASE=mf")
    assert not _printed(out), f"{surface}: {out!r}"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BACKLOG #5030 added item 8: a quoted value after a ;pwd=x stop would print on first "
        "deployment, since the member value ends at the quote; " + _REDESIGN
    ),
)
@pytest.mark.parametrize(
    "line",
    [
        "DRIVER={Acme};SERVER=db1.example;PWD=P'Zq7Vw9_Kp2;DATABASE=mf",
        "DRIVER={Acme};SERVER=db1.example;pwd=x;sslpassword='Zq7;Vw9 Kp2';DATABASE=mf",
    ],
)
@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=_SURFACE_IDS)
def test_a_quoted_member_value_after_a_stop_is_hidden(
    surface: str, apply: Callable[[str], str], line: str
) -> None:
    out = apply(line)
    assert not _printed(out), f"{surface}: {out!r}"


_ESCAPED_NEWLINE = (
    "the escaped-newline finding, filed by this pass's ledger pass as a vault row: a label right "
    "after a backslash escape written as text would print its value on first deployment, since "
    "the escape's last letter is a word character and no label start fires; " + _REDESIGN
)


@pytest.mark.xfail(strict=True, reason=_ESCAPED_NEWLINE)
@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=_SURFACE_IDS)
def test_a_label_after_an_escaped_newline_is_hidden(
    surface: str, apply: Callable[[str], str]
) -> None:
    # A literal backslash and "n", as a repr or a JSON string writes a line break.
    out = apply("foo\\npassword=Zq7Vw9Kp2")
    assert not _printed(out), f"{surface}: {out!r}"


@pytest.mark.xfail(strict=True, reason=_ESCAPED_NEWLINE)
@pytest.mark.parametrize(
    "apply",
    [
        lambda config: scrub_credentials(repr(config)),
        lambda config: _through_the_chain("loaded config %r", config),
        lambda config: redact_log_line(repr(config)),
    ],
    ids=_SURFACE_IDS,
)
def test_the_repr_of_a_multi_line_config_hides_its_credential(apply: Callable[[str], str]) -> None:
    out = apply("[db]\nhost = h\npassword = Zq7Vw9Kp2\n")
    assert not _printed(out), out


def test_the_escaped_newline_control_hides_its_credential() -> None:
    """The control for the two tests above: the same label after a space, or after a real line
    break, is read, so the escape is what the label start misses."""
    for line in ("foo password=Zq7Vw9Kp2", "foo\npassword=Zq7Vw9Kp2"):
        for surface, apply in _SURFACES:
            assert not _printed(apply(line)), (surface, line)
