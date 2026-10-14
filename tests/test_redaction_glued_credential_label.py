# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2968: a credential label glued to the end of an HL7 field run's token. OPEN, PINNED.

The field run replaces a whole token. In ``x|y|z;password: <value>`` the token runs from ``x`` to the
colon, so the run takes the label too. The credential filters run after the redactor and key on the
label, so they find none, and the value would reach the log on first deployment. ``safe_text`` and
``safe_exc`` redact at about 243 call sites before any handler, so a filter reorder (#3005) does not
close it.

**The xfail arms pin the defect, strictly.** Each goes red, and so fails the suite, the day a fix
makes it pass, so the fix must remove the mark. A fix that keeps the trailing label was built and
withdrawn under batch 255: its own differential printed no new value, but a code review's denser
fuzz still found credential values it printed that this redactor hid. The branch history holds it.

**The other arms are guards a fix must keep green.** Each passes on this redactor. They hold the
shapes that fix printed and this redactor does not: a kept label taking a later label as its value,
a kept quote or label ending an earlier quoted value, a scheme word before a later label, an env
name or a label prefix that is data, and a name run that a kept scheme word would join.

Every arm runs the real filter chain, in the order ``_install_phi_filters`` installs it, by the log
routes the engine uses: straight to a handler, after ``safe_text`` or ``safe_exc``, and through two
handlers. Values are synthetic. A pinned shape is used only where the credential stage alone scrubs
it with no run in front, so no arm passes on a shape nothing reads."""

from __future__ import annotations

import logging

import pytest

from messagefoundry import logging_setup, secretscrub
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
#: A percent-encoded field run carrying synthetic PHI.
_ENCODED_PHI = "q=ZQDOE%5EZQJANE%5E4455667"
_PHI = ("ZQDOE", "ZQJANE", "4455667")

_OPEN = pytest.mark.xfail(
    strict=True,
    reason="BACKLOG #2968 is open: the field run takes a credential label glued to its token",
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


# --- The pin: red on this redactor, by every glue, label, separator and route --------------------


@_OPEN
@pytest.mark.parametrize("separator", _SEPARATORS, ids=repr)
@pytest.mark.parametrize("run", list(_RUNS.values()), ids=list(_RUNS))
def test_a_credential_label_glued_to_a_field_run_loses_its_value(run: str, separator: str) -> None:
    """The run takes the label, so the value prints, under every glue and label here."""
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


@_OPEN
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
def test_every_credential_label_word_glued_to_a_field_run_loses_its_value(label: str) -> None:
    """Read from ``secretscrub``'s own tuples, so a word added there is pinned here too."""
    assert _the_credential_stage_reads(f"x ;{label}: {_VALUE}")
    assert not _paths_keeping(f"x {_RUNS['pipe']};{label}: {_VALUE}", _VALUE)


@_OPEN
@pytest.mark.parametrize(
    ("text", "control"),
    [
        (f"x|y|z,password = {_VALUE}", f"x ,password = {_VALUE}"),
        (f"x|y|z,password\t= {_VALUE}", f"x ,password\t= {_VALUE}"),
        (f'x|y|z,"password" : "{_VALUE}"', f'x ,"password" : "{_VALUE}"'),
        (f'{{"q":"x|y|z","password": "{_VALUE}"}}', f'{{"q":"x","password": "{_VALUE}"}}'),
        (f"x|y|z,Authorization: Basic {_VALUE}", f"x ,Authorization: Basic {_VALUE}"),
        (f"x|y|z,Authorization:Digest {_VALUE}", f"x ,Authorization:Digest {_VALUE}"),
        (f"x|y|z,Bearer {_VALUE}", f"x ,Bearer {_VALUE}"),
        (f"x|y|z|db_password: {_VALUE}", f"x |db_password: {_VALUE}"),
        (f"x|y|z;password: '{_VALUE}' " + "w " * 2_200, f"x ;password: '{_VALUE}' w"),
        # The separator-aware pass runs over the delimiters MSH declares.
        (f"MSH*$~\\&*APP\nx$y$z;password: {_VALUE}", f"x ;password: {_VALUE}"),
    ],
    ids=[
        "spaced-equals",
        "tab-before-equals",
        "quoted-key-spaced-colon",
        "compact-json",
        "basic-scheme",
        "glued-digest-scheme",
        "bare-bearer",
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


@_OPEN
@pytest.mark.parametrize(
    "text",
    [
        f"x|y|z;password: {_VALUE} {_ENCODED_PHI}",
        f"x|y|z;password=\n {_VALUE} {_ENCODED_PHI}",
    ],
    ids=["one-call", "a-line-break-and-two-handlers"],
)
def test_a_glued_label_and_an_encoded_run_both_lose_their_values(text: str) -> None:
    """The credential half of the guard below: a fix must scrub the value too."""
    assert not _paths_keeping(text, _VALUE)


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
