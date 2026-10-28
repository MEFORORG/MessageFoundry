# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2968: a credential label glued to the end of an HL7 field run's token. PARTIAL.

The field run replaces a whole token. In ``x|y|z;password: <value>`` the token runs from ``x`` to the
colon, so the run takes the label too. The credential filters run after the redactor and key on the
label, so they find none, and the value would reach the log on first deployment. ``safe_text`` and
``safe_exc`` redact at about 243 call sites before any handler, so a filter reorder (#3005) does not
close it.

**The value is now masked in place, as a glued PHI value is (BACKLOG #3318).** Where the value is one
plain word, ``redaction._glued_value`` masks it letter for letter, so every route's answer is the
answer with this rule off, with some letters and digits masked to their class, and nothing else
changed. The sweep below holds that property; it rules out a value printing that the rule-off
answer hid, by construction. A fix that kept the trailing label instead was built and withdrawn
under batch 255: its own differential printed no new value, but a code review's denser fuzz found
credential values it printed that this redactor hid. This one keeps no label.

**The residual arms are open defects, pinned strictly.** Each still prints its value, and each goes
red the day a change makes it pass. The rule leaves each one exactly as it was: every route prints
the same text with the rule on and off (``test_each_residual_prints_as_the_rule_off_redactor_does``).

**The guards are shapes the withdrawn fix printed and this redactor does not.** A fix must keep them
green: a kept label taking a later label as its value, a kept quote or label ending an earlier
quoted value, a scheme word before a later label, an env name or a label prefix that is data, and a
name run that a kept scheme word would join.

Every arm runs the real filter chain, in the order ``_install_phi_filters`` installs it, by the log
routes the engine uses: straight to a handler, after ``safe_text`` or ``safe_exc``, through two
handlers, and the support bundle's line scrubber. Values are synthetic. A pinned shape is used only
where the credential stage alone scrubs it with no run in front, so no arm passes on a shape nothing
reads."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from messagefoundry import logging_setup, redaction, secretscrub
from messagefoundry.redaction import redact, safe_exc, safe_text
from messagefoundry.support.redact import redact_log_line

#: A synthetic credential: lowercase-led with digits, so no name or date pass is what removes it.
_VALUE = "zq9hunter2z"
#: Field runs of each kind the literal pattern takes: pipes, carets, and a URL whose query holds two
#: ampersands.
_RUNS = {"pipe": "x|y|z", "caret": "d^j^k", "url": "http://h.example/p?a=1&b=2&c=3"}
#: Characters that glue a label to the run with no whitespace between. At least these.
_GLUE = "\"',})(;{[]/.-_|:?#>!*=@+$\\"
_LABELS = ("password", "token", "client_secret")
#: A percent-encoded field run carrying synthetic PHI.
_ENCODED_PHI = "q=ZQDOE%5EZQJANE%5E4455667"
_PHI = ("ZQDOE", "ZQJANE", "4455667")

_RESIDUAL = pytest.mark.xfail(
    strict=True,
    reason="BACKLOG #2968 residual: the rule leaves this shape as it was, and its value prints",
)


def _through_the_chain(text: str) -> str:
    """``text`` as a log message through the filters ``_install_phi_filters`` puts on a handler."""
    handler = logging.Handler()
    logging_setup._install_phi_filters(handler)
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "%s", (text,), None)
    assert handler.filter(record)
    return record.getMessage()


def _log_paths(text: str) -> dict[str, str]:
    """``text`` by the log routes that end in the credential filters, at least these."""
    once = _through_the_chain(text)
    return {
        "once": once,
        "safe_text": _through_the_chain(safe_text(text, limit=100_000)),
        "safe_exc": _through_the_chain(safe_exc(ValueError(text), limit=100_000)),
        "two handlers": _through_the_chain(once),
    }


def _all_paths(text: str) -> dict[str, str]:
    """The log routes, and the support bundle's line scrubber over the raw text and over a handler's
    line. The guards below hold the log routes only: the bundle prints some of their values with the
    rule off too, by its own patterns, which this item does not touch."""
    paths = _log_paths(text)
    paths["bundle"] = redact_log_line(text)
    paths["bundle of a handler's line"] = redact_log_line(paths["once"])
    return paths


def _keeping(paths: dict[str, str], *values: str) -> list[str]:
    """Each ``path: value`` that one of ``paths`` prints."""
    return [f"{path}: {value}" for path, out in paths.items() for value in values if value in out]


def _paths_keeping(text: str, *values: str) -> list[str]:
    """Each ``path: value`` that a log route prints."""
    return _keeping(_log_paths(text), *values)


def _all_paths_keeping(text: str, *values: str) -> list[str]:
    """Each ``path: value`` that a log route or the bundle prints."""
    return _keeping(_all_paths(text), *values)


def _the_credential_stage_reads(shape: str, value: str = _VALUE) -> bool:
    """The control: the credential stage alone scrubs ``shape``, with no run in front of it."""
    return value in shape and value not in secretscrub.scrub_credentials(shape)


@contextmanager
def _rule_off() -> Iterator[None]:
    """The redactor as it was before BACKLOG #2968: no credential label is read at a run's end."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(redaction, "_GLUED_CREDENTIAL_LABEL", re.compile(r"(?!)"))
        yield


def _is_masked(out: str, plain: str) -> bool:
    """Whether ``out`` is ``plain`` with some letters and digits masked to their class, and nothing
    else changed."""
    return len(out) == len(plain) and all(
        a == b or (b.isascii() and b.isalnum() and a == b.translate(redaction._SHAPE))
        for a, b in zip(out, plain, strict=True)
    )


def _glued(run: str, separator: str) -> list[str]:
    """``x <run><glue><label><separator><value>`` under every glue and label here."""
    return [f"x {run}{glue}{label}{separator}{_VALUE}" for glue in _GLUE for label in _LABELS]


# --- The fix, and the residual separators, by every glue, label and route ----------------------

_SEPARATORS = (
    ": ",
    "= ",
    pytest.param(":\t", marks=_RESIDUAL),  # the masked rest opens with a space
    pytest.param(":\n  ", marks=_RESIDUAL),
)


@pytest.mark.parametrize("separator", _SEPARATORS, ids=repr)
@pytest.mark.parametrize("run", list(_RUNS.values()), ids=list(_RUNS))
def test_a_credential_label_glued_to_a_field_run_loses_its_value(run: str, separator: str) -> None:
    """The run takes the label; the value is masked, under every glue and label here."""
    kept = []
    texts = _glued(run, separator)
    for glue in _GLUE:
        for label in _LABELS:
            # A plain word in the run's place, so a glue such as "_" still joins a label prefix.
            assert _the_credential_stage_reads(f"x w{glue}{label}{separator}{_VALUE}"), (
                glue,
                label,
            )
    for text in texts:
        kept += [f"{text!r}: {where}" for where in _all_paths_keeping(text, _VALUE)]
    assert len(texts) == len(_GLUE) * len(_LABELS) == 78
    assert not kept, kept[:10]


@pytest.mark.parametrize("run", list(_RUNS.values()), ids=list(_RUNS))
def test_the_rule_is_what_scrubs_a_glued_credential(run: str) -> None:
    """THE POSITIVE CONTROL: with the rule off, every text above prints its value on the handler
    route, so the green above is the rule's work and not a shape nothing reads."""
    texts = _glued(run, ": ") + _glued(run, "= ")
    with _rule_off():
        printed = [text for text in texts if _VALUE in _through_the_chain(text)]
    assert len(printed) == len(texts) == 156


#: Every label word ``secretscrub`` reads, from its own tuples.
_SCRUB_WORDS = (
    *secretscrub._CREDENTIAL_WORDS,
    *secretscrub._TOKEN_WORDS,
    *secretscrub._KEY_MATERIAL_WORDS,
)
_LABEL_WORDS = [
    *_SCRUB_WORDS,
    "db_password",
    "db.password",
    "a_b_c_d_e_f_password",
    "PWD",
    "Password",
    "MEFOR_STORE_PW",
]


@pytest.mark.parametrize("label", _LABEL_WORDS)
def test_every_credential_label_word_glued_to_a_field_run_loses_its_value(label: str) -> None:
    """Read from ``secretscrub``'s own tuples, so a word added there is pinned here too."""
    text = f"x {_RUNS['pipe']};{label}: {_VALUE}"
    assert _the_credential_stage_reads(f"x ;{label}: {_VALUE}")
    assert not _all_paths_keeping(text, _VALUE)
    with _rule_off():
        assert _VALUE in _through_the_chain(text)


def test_the_glued_label_spells_the_credential_ahead_vocabulary() -> None:
    """The glued label is :data:`redaction._CREDENTIAL_AHEAD`'s label arm, spelled out for the static
    regex gate. A word added there and missed here fails this, and so does a ``secretscrub`` word
    neither pattern reads."""

    def label_arm(pattern: re.Pattern[str]) -> str:
        source = pattern.pattern
        return source[source.index(r"\b(?:MEFOR_") : source.index(r")))\b") + len(r")))\b")]

    assert label_arm(redaction._GLUED_CREDENTIAL_LABEL) == label_arm(redaction._CREDENTIAL_AHEAD)
    for word in _SCRUB_WORDS:
        for separator in (":", "=", '":', "'="):
            assert redaction._GLUED_CREDENTIAL_LABEL.search(f"a|b;{word}{separator}"), word
    # Not a label: a word glued in front, a word after the keyword, no separator at the end.
    for tail in ("xpassword:", "password_file:", "password", "password: "):
        assert not redaction._GLUED_CREDENTIAL_LABEL.search(f"a|b;{tail}"), tail


def test_the_value_is_masked_in_place() -> None:
    """Every answer is the rule-off answer with letters and digits masked to their class."""
    assert redact(f"bad x|y|z;password: {_VALUE} ok") == "bad [redacted] xx0xxxxxx0x ok"
    assert redact("bad x|y|z;token= Zq9Hunter") == "bad [redacted] Xx0Xxxxxx"


#: ``(text, control)``: label shapes past ``label: value``, at least these. A ``pytest.param`` with
#: the residual mark is a shape the rule leaves as it was.
_OTHER_SHAPES = [
    pytest.param(
        f"x|y|z|db_password: {_VALUE}",
        f"x |db_password: {_VALUE}",
        id="prefixed-label-after-a-pipe",
    ),
    # The separator-aware pass runs over the delimiters MSH declares.
    pytest.param(
        f"MSH*$~\\&*APP\nx$y$z;password: {_VALUE}",
        f"x ;password: {_VALUE}",
        id="declared-delimiters",
    ),
    pytest.param(
        f"x|y|z,password = {_VALUE}", f"x ,password = {_VALUE}", id="spaced-equals", marks=_RESIDUAL
    ),
    pytest.param(
        f"x|y|z,password\t= {_VALUE}",
        f"x ,password\t= {_VALUE}",
        id="tab-before-equals",
        marks=_RESIDUAL,
    ),
    pytest.param(
        f'x|y|z,"password" : "{_VALUE}"',
        f'x ,"password" : "{_VALUE}"',
        id="quoted-key-spaced-colon",
        marks=_RESIDUAL,
    ),
    pytest.param(
        f'{{"q":"x|y|z","password": "{_VALUE}"}}',
        f'{{"q":"x","password": "{_VALUE}"}}',
        id="compact-json",
        marks=_RESIDUAL,
    ),
    pytest.param(
        f"x|y|z,Authorization: Basic {_VALUE}",
        f"x ,Authorization: Basic {_VALUE}",
        id="basic-scheme",
        marks=_RESIDUAL,
    ),
    pytest.param(
        f"x|y|z,Authorization:Digest {_VALUE}",
        f"x ,Authorization:Digest {_VALUE}",
        id="glued-digest-scheme",
        marks=_RESIDUAL,
    ),
    pytest.param(
        f"x|y|z,Bearer {_VALUE}", f"x ,Bearer {_VALUE}", id="bare-bearer", marks=_RESIDUAL
    ),
    pytest.param(
        f"x|y|z;password: '{_VALUE}' " + "w " * 2_200,
        f"x ;password: '{_VALUE}' w",
        id="quoted-value-on-a-long-line",
        marks=_RESIDUAL,
    ),
]


@pytest.mark.parametrize(("text", "control"), _OTHER_SHAPES)
def test_other_label_shapes_glued_to_a_field_run_lose_their_value(text: str, control: str) -> None:
    """Shapes past ``label: value``, at least these: a separator after whitespace, a quoted key, an
    auth scheme glued to its label or alone, and a run over the delimiters MSH declares."""
    assert _the_credential_stage_reads(control)
    assert not _all_paths_keeping(text, _VALUE)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(f"x|y|z;password: {_VALUE} {_ENCODED_PHI}", id="one-call"),
        pytest.param(
            f"x|y|z;password=\n {_VALUE} {_ENCODED_PHI}",
            id="a-line-break-and-two-handlers",
            marks=_RESIDUAL,
        ),
    ],
)
def test_a_glued_label_and_an_encoded_run_both_lose_their_values(text: str) -> None:
    """The credential half of the guard below: a fix must scrub the value too."""
    assert not _all_paths_keeping(text, _VALUE)


#: A value the mask refuses, so it prints as before: ``(text, value, control)``. Class (a), a value
#: holding punctuation, had no pin before; the rest are the other refusals of ``_glued_value``.
_REFUSED_VALUES = {
    "punctuation-bang": (f"x|y|z;password: {_VALUE}!q", _VALUE, f"x ;password: {_VALUE}!q"),
    "punctuation-dot": (f"x|y|z;password: {_VALUE}.q", _VALUE, f"x ;password: {_VALUE}.q"),
    "punctuation-slash": (f"x|y|z;token: {_VALUE}/q", _VALUE, f"x ;token: {_VALUE}/q"),
    "punctuation-at": (f"x|y|z;secret= {_VALUE}@q", _VALUE, f"x ;secret= {_VALUE}@q"),
    "punctuation-hyphen-first": (f"x|y|z;pwd: q-{_VALUE}", _VALUE, f"x ;pwd: q-{_VALUE}"),
    "punctuation-comma-after": (f"x|y|z;password: {_VALUE},q", _VALUE, f"x ;password: {_VALUE},q"),
    "quoted-value": (f"x|y|z;password: '{_VALUE}'", _VALUE, f"x ;password: '{_VALUE}'"),
    "all-digits-at-the-end": ("x|y|z;password: 98765432", "98765432", "x ;password: 98765432"),
    "longer-than-64": (
        f"x|y|z;password: {_VALUE * 6}",
        _VALUE * 6,
        f"x ;password: {_VALUE * 6}",
    ),
    "a-word-another-pass-reads-the-head-of": (
        "x|y|z;password: nonnumer",
        "nonnumer",
        "x ;password: nonnumer",
    ),
    "non-ascii-letter": ("x|y|z;password: zq9hünter", "zq9hünter", "x ;password: zq9hünter"),
    "a-line-break-before-the-value": (
        f"x|y|z;password:\n{_VALUE}",
        _VALUE,
        f"x ;password:\n{_VALUE}",
    ),
}


@_RESIDUAL
@pytest.mark.parametrize(
    ("text", "value", "control"), list(_REFUSED_VALUES.values()), ids=list(_REFUSED_VALUES)
)
def test_a_value_the_mask_refuses_still_prints(text: str, value: str, control: str) -> None:
    """Open: the mask takes one plain ASCII word of at most 64 characters, so these print."""
    assert _the_credential_stage_reads(control, value)
    assert not _all_paths_keeping(text, value)


def _residual_texts() -> list[str]:
    """Every text a residual arm above plants."""
    texts = [
        text for run in _RUNS.values() for sep in (":\t", ":\n  ") for text in _glued(run, sep)
    ]
    texts += [str(param.values[0]) for param in _OTHER_SHAPES if param.marks]
    texts += [f"x|y|z;password=\n {_VALUE} {_ENCODED_PHI}"]
    texts += [text for text, _, _ in _REFUSED_VALUES.values()]
    return texts


def test_each_residual_prints_as_the_rule_off_redactor_does() -> None:
    """A residual may stay open only if the rule leaves it exactly as it was: every route prints the
    same text with the rule on and off. The commit that added this compared the rule-off redactor
    with an exported ``origin/main`` and found them equal on every text it ran."""
    texts = _residual_texts()
    assert len(texts) == 6 * 78 + 8 + 1 + len(_REFUSED_VALUES)
    on = [_all_paths(text) for text in texts]
    with _rule_off():
        off = [_all_paths(text) for text in texts]
    changed = [text for text, a, b in zip(texts, on, off, strict=True) if a != b]
    assert not changed, changed[:5]


# --- Guards: green on this redactor, and a fix must keep them green ----------------------------


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
        f"MRN^4455667^ZQDOE_ZQJANE.password: {_VALUE}",
        "MRN^ZQDOE^ZQJANE^4455667^PASS = 4",
        "MRN^ZQDOE^ZQJANE^4455667^BEARER ward",
    ],
    ids=["env-name", "env-name-after-data", "label-prefix", "bare-component", "bare-scheme"],
)
def test_data_in_or_before_a_label_is_never_printed(text: str) -> None:
    """A ``MEFOR_`` name is free ``[A-Z0-9_]`` text, and a label's dotted or underscored prefix is
    data, so a fix that keeps a label must keep neither. A component that is only a label word may
    be data too."""
    assert not _paths_keeping(text, *_PHI)


@pytest.mark.parametrize(
    "glued", ["x|y|z;Bearer", "x|y|z;Authorization:Bearer", "x|y|z;token=Basic"]
)
def test_a_scheme_word_does_not_join_a_name_run(glued: str) -> None:
    """The name run takes at most four words. A capitalised scheme word left in front of a
    four-word name would take its place in that match and leave the last name."""
    names = ("Janelle", "Doering", "Smithson", "Roeland")
    assert not _paths_keeping(f"{glued} {' '.join(names)}", *names)


def test_a_glued_label_does_not_leave_an_encoded_run_in_view() -> None:
    """``redact`` leaves the percent-encoded run off a text that holds a credential shape. A label
    a fix keeps is one, and it must not leave the run's PHI in view where this redactor scrubs it."""
    assert not _paths_keeping(f"x|y|z;password: {_VALUE} {_ENCODED_PHI}", *_PHI)


def test_a_glued_label_does_not_leave_an_encoded_run_in_view_on_a_second_handler() -> None:
    """The line break keeps the encoded run off on the first handler, and the control-character
    filter writes it as visible text, so the second handler applies the run. A label a fix keeps,
    rewritten to ``password=<redacted>`` by the first handler, must not switch it off there. The
    first handler prints the PHI on this redactor too, so only the second is held."""
    out = _through_the_chain(_through_the_chain(f"x|y|z;password=\n {_VALUE} {_ENCODED_PHI}"))
    assert not [value for value in _PHI if value in out], out


@pytest.mark.parametrize(
    "text",
    [
        f"x|y|z;session: PWD:\t{_VALUE}",
        f"x|y|z;token= )api-key: {_VALUE}",
        f"x|y|z;secret: 'a password: {_VALUE}'",
        f"x|y|z;pwd: Wilhelmina Pemberly,secret: {_VALUE}",
        f"x|y|z;Authorization: Digest username=aa,token: {_VALUE}",
        f"x|y|z;bearer: Digest zq9aa1z,pwd: {_VALUE}",
        f"x|y|z;token: Basic aa,secret: {_VALUE}",
        f'password: "aa x|y|z;secret" : {_VALUE} "',
        f"password: 'aa x|y|z;token' = {_VALUE} bb'",
        f'password: "aa {_VALUE} x|y|z;api_key: "zq9cc3z',
        f"client_secret='aa {_VALUE} x|y|z;api_key:\t'zq9cc3z",
        f"d^j^k]Bearer = bearer 'zq9aa1z,(,),a%7Cb%7Cc;client_secret :{_VALUE}",
    ],
    ids=[
        "label-as-value",
        "glued-label-as-value",
        "label-in-a-quoted-value",
        "name-run-glues-a-label-into-the-value",
        "digest-then-label",
        "bearer-label-digest-then-label",
        "basic-then-label",
        "kept-quote-closes-an-earlier-value",
        "kept-single-quote-closes-an-earlier-value",
        "inside-an-earlier-open-value",
        "inside-an-earlier-open-single-quoted-value",
        "bearer-label-with-a-spaced-separator",
    ],
)
def test_a_later_label_keeps_its_value_scrubbed(text: str) -> None:
    """Shapes where the withdrawn fix kept a glued label that then took a later label as its value,
    or ended an earlier label's quoted value early, and a value this redactor scrubs printed. Found
    by that fix's differential and by two code review rounds on it."""
    assert not _paths_keeping(text, _VALUE)


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
        f"x|y|z;password: {_VALUE} {_ENCODED_PHI}",
        f"MSH*$~\\&*APP\nx$y$z;password: {_VALUE}",
    ],
)
def test_a_second_call_changes_nothing(text: str) -> None:
    """``safe_text`` or ``safe_exc`` redacts, then the handler's filter redacts the result again."""
    once = redact(text)
    assert redact(once) == once


# --- A label-dense sweep: every route answers the rule-off redactor, masked ---------------------

_SWEEP_RUNS = ("x|y|z", "A^B^C", "http://h.example/p?a=1&b=2&c=3", "MSH*$~\\&*A\rx$y$z")
_SWEEP_GLUE = ("", ";", ",", '"', "'", "}", ")", "_", ".", "=", "\\", "|")
_SWEEP_LABELS = ("password", "db_password", "Token", "api-key", "MEFOR_DB_PW", "'secret'")
_SWEEP_SEPARATORS = (": ", "= ", "=  ")
_SWEEP_VALUES = ("zq9hunter2z", "zqpw84", "Zqhunter", "ZQHUNTER7")
_SWEEP_TAILS = (
    "",
    " rest",
    ",secret: zqlater1",
    " token=zqlater2",
    " Plantone Planttwo",
    f" {_ENCODED_PHI}",
    "'",
    ' "',
)
#: Text a caller writes around an answer: an open quoted credential value before it, a word a name
#: run could join after it, and digits a date arm could join.
_SWEEP_AROUND = (("", ""), ("password: '", "' x"), ("", " Plantsuf x"), ("", "0505 retry"))
_SWEEP_PLANTED = ("zq9hunter2z", "zqpw84", "Zqhunter", "ZQHUNTER7", "zqlater", "Plant", "ZQDOE")


def _sweep() -> Iterator[str]:
    for index, (run, glue, label) in enumerate(
        (run, glue, label) for run in _SWEEP_RUNS for glue in _SWEEP_GLUE for label in _SWEEP_LABELS
    ):
        # Each combination takes every separator, and one value and tail in turn, so the sweep stays
        # small while every value and tail meets every run.
        for offset, separator in enumerate(_SWEEP_SEPARATORS):
            value = _SWEEP_VALUES[(index + offset) % len(_SWEEP_VALUES)]
            tail = _SWEEP_TAILS[(index + offset) % len(_SWEEP_TAILS)]
            yield f"bad {run}{glue}{label}{separator}{value}{tail}"


def _sweep_routes(text: str) -> dict[str, str]:
    routes = _all_paths(text)
    routes["redact twice"] = redact(redact(text))
    for limit in (40, 80):
        routes[f"store after safe_exc {limit}"] = safe_text(safe_exc(ValueError(text), limit=limit))
    for before, after in _SWEEP_AROUND:
        routes[f"around {before!r} {after!r}"] = _through_the_chain(
            before + safe_exc(ValueError(text)) + after
        )
    return routes


def test_every_route_of_the_sweep_answers_the_rule_off_redactor_masked() -> None:
    """Every text of the sweep, by every route, with the rule on and off: the output is the rule-off
    output, masked. That rules out any value the rule-off redactor hid printing, by construction
    rather than by a list of values. It also counts the routes the rule fixed, so a sweep it never
    touched cannot pass."""
    texts = list(_sweep())
    assert len(texts) == len(_SWEEP_RUNS) * len(_SWEEP_GLUE) * len(_SWEEP_LABELS) * 3 == 864
    broken: list[str] = []
    fixed = 0
    afters = [_sweep_routes(text) for text in texts]
    with _rule_off():
        befores = [_sweep_routes(text) for text in texts]
    for text, after, before in zip(texts, afters, befores, strict=True):
        for path, out in after.items():
            if not _is_masked(out, before[path]):
                broken.append(f"{path}: {text!r}")
            fixed += any(value in before[path] and value not in out for value in _SWEEP_PLANTED)
    assert not broken, broken[:10]
    assert fixed > 2000, fixed
