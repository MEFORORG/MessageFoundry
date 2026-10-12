# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2968: a credential label glued to the end of an HL7 field run's token.

The field run replaces a whole token. In ``x|y|z;password: <value>`` the token runs from ``x`` to the
colon, so the run took the label too. The credential filters run after the redactor and key on the
label, so they found none and the value would have reached the log on first deployment. The run now
keeps a trailing credential label (``redaction._TRAILING_CREDENTIAL_LABEL``).

Every arm runs the real filter chain, in the order ``_install_phi_filters`` installs it, by the log
routes the engine uses: straight to a handler, after ``safe_text`` or ``safe_exc`` (which redact at
the call site, before any handler), and through two handlers. Values are synthetic. A shape is used
only where the credential stage alone scrubs it with no run in front, so no arm passes on a shape
nothing reads."""

from __future__ import annotations

import logging
import re
from typing import Any

import pytest

from messagefoundry import logging_setup, redaction, secretscrub
from messagefoundry.redaction import redact, safe_exc, safe_text

#: A synthetic credential: lowercase-led with digits, so no name or date pass is what removes it.
_VALUE = "zq9hunter2z"
#: Field runs of each kind the literal pattern takes: pipes, carets, and a URL whose query holds two
#: ampersands.
_RUNS = {"pipe": "x|y|z", "caret": "d^j^k", "url": "http://h.example/p?a=1&b=2&c=3"}
#: Characters that glue a label to the run with no whitespace between. At least these.
_GLUE = "\"',})(;{[]/.-_|:?#>!*=@+$\\"
#: Separators written the way the credential stage reads them: the ``:`` or ``=`` in the run's token,
#: then whitespace before the value. ``label=value`` with no space is a control, not a case: the run
#: takes the value with the token.
_SEPARATORS = (": ", "= ", ":\t", ":\n  ")
_LABELS = ("password", "token", "client_secret")


def _through_the_chain(text: str) -> str:
    """``text`` as a log message through the filters ``_install_phi_filters`` puts on a handler."""
    handler = logging.Handler()
    logging_setup._install_phi_filters(handler)
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "%s", (text,), None)
    assert handler.filter(record)
    return record.getMessage()


def _log_paths(text: str) -> dict[str, str]:
    """``text`` by the log routes that end in the credential filters, at least these."""
    return {
        "once": _through_the_chain(text),
        "safe_text": _through_the_chain(safe_text(text, limit=100_000)),
        "safe_exc": _through_the_chain(safe_exc(ValueError(text), limit=100_000)),
        "two handlers": _through_the_chain(_through_the_chain(text)),
    }


def _paths_keeping(text: str, *values: str) -> list[str]:
    """Each ``path: value`` that a log route prints."""
    return [
        f"{path}: {value}"
        for path, out in _log_paths(text).items()
        for value in values
        if value in out
    ]


def _the_credential_stage_reads(shape: str) -> bool:
    """The control: the credential stage alone scrubs ``shape``, with no run in front of it."""
    return _VALUE in shape and _VALUE not in secretscrub.scrub_credentials(shape)


@pytest.mark.parametrize("separator", _SEPARATORS, ids=repr)
@pytest.mark.parametrize("run", list(_RUNS.values()), ids=list(_RUNS))
def test_a_credential_label_glued_to_a_field_run_loses_its_value(run: str, separator: str) -> None:
    """Red before BACKLOG #2968 on every glue, label and route: the run took the label."""
    kept = []
    for glue in _GLUE:
        for label in _LABELS:
            # A plain word in the run's place, so a glue such as "_" still joins a label prefix.
            assert _the_credential_stage_reads(f"x w{glue}{label}{separator}{_VALUE}"), (
                glue,
                label,
            )
            kept += [
                f"{glue!r} {label}: {where}"
                for where in _paths_keeping(f"x {run}{glue}{label}{separator}{_VALUE}", _VALUE)
            ]
    assert not kept, kept[:10]


@pytest.mark.parametrize(
    "label",
    [
        *secretscrub._CREDENTIAL_WORDS,
        *secretscrub._TOKEN_WORDS,
        *secretscrub._KEY_MATERIAL_WORDS,
        "db_password",
        "db.password",
        "a_b_c_d_e_f_password",
        "PWD",
        "Password",
    ],
)
def test_every_credential_label_word_is_kept_after_a_field_run(label: str) -> None:
    """Read from ``secretscrub``'s own tuples, so a word added there and not to the run's tail
    pattern goes red here by behaviour as well as in the word-list gate below."""
    shape = f"x ;{label}: {_VALUE}"
    assert _the_credential_stage_reads(shape)
    assert not _paths_keeping(f"x {_RUNS['pipe']};{label}: {_VALUE}", _VALUE)


@pytest.mark.parametrize(
    ("text", "control"),
    [
        (f"x|y|z,password = {_VALUE}", f"x ,password = {_VALUE}"),
        (f"x|y|z,password\t= {_VALUE}", f"x ,password\t= {_VALUE}"),
        (f'x|y|z,"password" : "{_VALUE}"', f'x ,"password" : "{_VALUE}"'),
        (f'{{"q":"x|y|z","password": "{_VALUE}"}}', f'{{"q":"x","password": "{_VALUE}"}}'),
        (f"x|y|z,Authorization: Basic {_VALUE}", f"x ,Authorization: Basic {_VALUE}"),
        (f"x|y|z,Authorization:Digest {_VALUE}", f"x ,Authorization:Digest {_VALUE}"),
        (f"x|y|z,Authorization:Bearer {_VALUE}", f"x ,Authorization:Bearer {_VALUE}"),
        (f"x|y|z,Bearer {_VALUE}", f"x ,Bearer {_VALUE}"),
        (f"x|y|z,BEARER {_VALUE}", f"x ,BEARER {_VALUE}"),
        (f"x|y|z|db_password: {_VALUE}", f"x |db_password: {_VALUE}"),
        # A quoted value with a long line after it: the value ends at its closing quote.
        (f"x|y|z;password: '{_VALUE}' " + "w " * 2_200, f"x ;password: '{_VALUE}' w"),
        # The separator pass runs over the delimiters MSH declares, and keeps the label the same way.
        (f"MSH*$~\\&*APP\nx$y$z;password: {_VALUE}", f"x ;password: {_VALUE}"),
    ],
    ids=[
        "spaced-equals",
        "tab-before-equals",
        "quoted-key-spaced-colon",
        "compact-json",
        "basic-scheme",
        "glued-digest-scheme",
        "glued-bearer-scheme",
        "bare-bearer",
        "bare-bearer-upper",
        "prefixed-label-after-a-pipe",
        "quoted-value-on-a-long-line",
        "declared-delimiters",
    ],
)
def test_other_label_shapes_glued_to_a_field_run_lose_their_value(text: str, control: str) -> None:
    """Shapes past ``label: value``, at least these: a separator after whitespace, a quoted key, an
    auth scheme glued to its label or alone, and a run over the delimiters MSH declares."""
    assert _the_credential_stage_reads(control)
    assert not _paths_keeping(text, _VALUE)


@pytest.mark.parametrize(
    ("text", "printed"),
    [
        (f"x {_RUNS['pipe']} password: {_VALUE}", False),  # whitespace, not glue
        (f"x {_RUNS['pipe']};password={_VALUE}", False),  # the run takes the value with the token
        (f"x {_RUNS['pipe']};password {_VALUE}", True),  # not a credential shape at all
    ],
    ids=["spaced-glue", "value-in-the-token", "no-separator"],
)
def test_the_controls_answer_as_the_credential_stage_alone_does(text: str, printed: bool) -> None:
    """Shapes the run never hid a label in. The third prints with no run in front of it too."""
    assert (_VALUE in secretscrub.scrub_credentials(text.replace(_RUNS["pipe"], "w"))) is printed
    assert bool(_paths_keeping(text, _VALUE)) is printed


@pytest.mark.parametrize(
    "text",
    [
        f"x|y|z;MEFOR_ZQDOE_ZQJANE_4455667: {_VALUE}",
        f"x|y|ZQDOE_MEFOR_4455667_ZQJANE= {_VALUE}",
    ],
)
def test_an_env_name_is_not_kept(text: str) -> None:
    """A ``MEFOR_`` name is free ``[A-Z0-9_]`` text, so keeping one would print the data the run
    scrubbed. The price, stated: its value prints, as it did before #2968."""
    assert redact(text).startswith("[redacted] "), redact(text)
    assert not _paths_keeping(text, "ZQDOE", "ZQJANE", "4455667")


def test_the_kept_label_carries_no_prefix() -> None:
    """A label's dotted or underscored prefix is data, so the run takes it: only the word stays."""
    text = f"MRN^4455667^ZQDOE_ZQJANE.password: {_VALUE}"
    out = redact(text)
    assert out == "[redacted]password: " + _VALUE, out
    assert not _paths_keeping(text, "ZQDOE", "ZQJANE", "4455667", _VALUE)


@pytest.mark.parametrize(
    "text",
    [
        "MRN^ZQDOE^PASS = 4",
        "MRN^ZQDOE^SECRET : 4",
        "MRN^ZQDOE^BEARER ward",
        "x|ZQDOE|Session = 4",
    ],
)
def test_a_bare_component_is_not_kept(text: str) -> None:
    """A word with no separator in the token, right after one of the run's own separators, is a
    component of the field, so it is data and goes with the run. The price, stated: a credential
    written as ``x|y|z|password = <value>`` still prints its value, as it did before #2968."""
    out = redact(text)
    assert out.startswith("[redacted] "), out


@pytest.mark.parametrize(
    "glued", ["x|y|z;Bearer", "x|y|z;Authorization:Bearer", "x|y|z;token=Basic"]
)
def test_a_kept_scheme_word_does_not_join_a_name_run(glued: str) -> None:
    """The name run takes at most four words. A capitalised scheme word kept in front of a
    four-word name would take its place in that match and leave the last name. The run alone
    scrubbed all four, so the scheme word is kept in lower case."""
    names = ("Janelle", "Doering", "Smithson", "Roeland")
    text = f"{glued} {' '.join(names)}"
    out = redact(text)
    assert not [name for name in names if name in out], out
    assert not _paths_keeping(text, *names)


def test_a_kept_label_does_not_switch_the_encoded_run_off() -> None:
    """``redact`` leaves the percent-encoded run off a text that holds a credential shape. A label
    the literal run kept is one, and reading it would leave the encoded run's PHI in view where the
    run applied before #2968. Both values go."""
    phi = "ZQDOE%5EZQJANE%5E4455667"
    text = f"x|y|z;password: {_VALUE} q={phi}"
    assert redaction._CREDENTIAL_AHEAD.search(redaction._redact_stages(text)) is not None
    assert not _paths_keeping(text, _VALUE, "ZQDOE", "ZQJANE", "4455667")


def test_a_kept_label_on_a_later_call_does_not_switch_the_encoded_run_off() -> None:
    """Two handlers filter one record. The line break keeps the encoded run off on the first pass,
    where the credential filter writes ``password=<redacted>`` over it. Before #2968 the second
    pass found no credential shape and applied the run; the kept label must not stop it now."""
    phi = "ZQDOE%5EZQJANE%5E4455667"
    text = f"x|y|z;password=\n {_VALUE} q={phi}"
    out = _through_the_chain(_through_the_chain(text))
    assert not [value for value in (_VALUE, "ZQDOE", "ZQJANE", "4455667") if value in out], out


@pytest.mark.parametrize(
    "text",
    [
        f"x|y|z;session: PWD:\t{_VALUE}",
        f"x|y|z;token= )api-key: {_VALUE}",
        f"x|y|z;secret: 'a password: {_VALUE}'",
    ],
    ids=["label-as-value", "glued-label-as-value", "label-in-a-quoted-value"],
)
def test_a_label_whose_value_holds_a_label_is_not_kept(text: str) -> None:
    """The credential filters take a value whole and do not stop at a label inside it. A kept label
    would take the next label as its value, and that label's value would print, where the run used
    to take the first label and the filters read the second. So such a label goes with the run."""
    assert redact(text).startswith("[redacted] "), redact(text)
    assert not _paths_keeping(text, _VALUE)


def test_a_label_a_later_pass_glues_into_the_value_is_read_again() -> None:
    """The value is read when the run keeps the label, and the passes after the run can change it.
    Here the name run replaces the two names, which glues ``,secret:`` to the kept label's value,
    so the finished output is read again and the label is not kept."""
    text = f"x|y|z;pwd: Wilhelmina Pemberly,secret: {_VALUE}"
    assert redact(text).startswith("[redacted] "), redact(text)
    assert not _paths_keeping(text, _VALUE, "Wilhelmina", "Pemberly")


def test_every_tail_word_holds_a_hint() -> None:
    """The check on a kept label's value looks for these substrings, so every label word must hold
    one or a label inside a value would go unseen."""
    words = _label_words(redaction._TRAILING_CREDENTIAL_LABEL.pattern).split("|")
    for word in [*words, "MEFOR_X"]:
        assert any(hint in word.casefold() for hint in redaction._LABEL_HINTS), word


def test_a_credential_label_glued_to_an_encoded_run_still_loses_its_value() -> None:
    """Closing step 3 of the row, one glue here. The encoded run still takes a glued label with its
    token; the value goes because ``redact`` leaves that run off a text holding a credential
    shape. ``tests/test_redaction.py`` plants every glue."""
    assert not _paths_keeping(f"x%7Cy%7Cz;password: {_VALUE}", _VALUE)


@pytest.mark.parametrize(
    "text",
    [
        f"x|y|z;password: {_VALUE}",
        f"x|y|z;Bearer {_VALUE}",
        f"x|y|z,Authorization:Basic {_VALUE}",
        f'x|y|z,"password" : "{_VALUE}"',
        f"x|y|z;password: {_VALUE} q=ZQDOE%5EZQJANE%5E4455667",
        f"MSH*$~\\&*APP\nx$y$z;password: {_VALUE}",
    ],
)
def test_a_second_call_changes_nothing(text: str) -> None:
    """``safe_text`` or ``safe_exc`` redacts, then the handler's filter redacts the result again."""
    once = redact(text)
    assert redact(once) == once


def _label_words(pattern: str) -> str:
    """The credential word alternation inside a pattern's source."""
    found = re.search(r"encryption_keys_retired[a-z_|-]*?\|pwd\b", pattern)
    assert found is not None, pattern
    return found.group()


def test_the_tail_words_are_the_credential_arm_words() -> None:
    """Both tail patterns hold a copy of the label arm of ``_CREDENTIAL_AHEAD``, which is in turn
    held to ``secretscrub``. A plain literal each, so the static regex gate reads them."""
    words = _label_words(redaction._CREDENTIAL_AHEAD.pattern)
    assert _label_words(redaction._TRAILING_CREDENTIAL_LABEL.pattern) == words
    assert _label_words(redaction._KEPT_LABEL.pattern) == words
    every = (
        *secretscrub._CREDENTIAL_WORDS,
        *secretscrub._TOKEN_WORDS,
        *secretscrub._KEY_MATERIAL_WORDS,
    )
    assert set(every) <= set(words.split("|"))


class _Recorder:
    """Stands in for the tail pattern and records how much of the text each search may read."""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self.pattern = pattern
        self.spans: list[int] = []

    def search(self, text: str, pos: int, endpos: int) -> Any:
        self.spans.append(endpos - pos)
        return self.pattern.search(text, pos, endpos)


def test_the_tail_search_reads_a_bounded_span_of_each_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The run's own scan is linear, and the tail search must not give that back: it reads at most
    a fixed span from the end of each token, however long the token is."""
    recorder = _Recorder(redaction._TRAILING_CREDENTIAL_LABEL)
    monkeypatch.setattr(redaction, "_TRAILING_CREDENTIAL_LABEL", recorder)
    text = "a|b|" + "c" * 200_000 + f";password: {_VALUE} " + "d|e|f " * 2_000
    assert redact(text).startswith("[redacted]password: ")
    assert recorder.spans and max(recorder.spans) <= redaction._TRAILING_LABEL_SPAN
