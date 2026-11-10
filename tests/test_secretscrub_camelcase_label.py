# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5545: a camelCase or PascalCase credential label, such as ``accessToken=`` or
``clientSecret=``, is read by the credential scrub.

Every label pattern in :mod:`messagefoundry.secretscrub` started at a word boundary, a "%XX" escape or
a "._-" separated prefix, so a keyword glued to a lower-case letter by a capital had no start
position, and its value would print in the write-time log on first deployment. The same module
already read those spellings as credentials in a URL query (``_camel_tail``). The fix adds a second
label start, ``_LABEL_OR_CAMEL_START``, at a capital after a lower-case letter or a digit, where a
label word starts and ends the word.

Each value here is built from parts at import time, so no credential-shaped literal sits in this
file. Every value is synthetic."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from functools import partial

import pytest

from messagefoundry import secretscrub
from messagefoundry.logging_setup import _install_phi_filters
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials
from messagefoundry.support.redact import redact_log_line
from tests._growth import _growth_between

#: A synthetic value, joined from parts so the file holds no credential-shaped literal.
_VALUE = "".join(("zq", "7", "cml", "-", "Vx", "_", "42"))

#: Lines whose label is glued on by a camelCase capital, with the label as it must survive.
_CAMEL_LINES = (
    (f"accessToken={_VALUE}", "accessToken="),
    (f"clientSecret={_VALUE}", "clientSecret="),
    (f"refreshToken: {_VALUE}", "refreshToken"),
    (f"userPassword={_VALUE}", "userPassword="),
    (f"idToken={_VALUE}", "idToken="),
    (f"sessionToken={_VALUE}", "sessionToken="),
    (f"oauth2Token={_VALUE}", "oauth2Token="),
    (f"cfg.clientSecret={_VALUE}", "cfg.clientSecret="),
    (f'token response {{"accessToken": "{_VALUE}", "expiresIn": 3600}}', "accessToken"),
    (f"grant failed: refreshToken={_VALUE}&scope=read", "refreshToken="),
    (f"ldap bind: bindPassword='{_VALUE}' refused", "bindPassword="),
    (f"vault: rootPwd={_VALUE}", "rootPwd="),
)


def _through_the_chain(text: str) -> str:
    """``text`` as a log message through the filters ``_install_phi_filters`` puts on a handler."""
    handler = logging.NullHandler()
    _install_phi_filters(handler)
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "%s", (text,), None)
    assert handler.filter(record)
    return record.getMessage()


#: The three surfaces a log line reaches.
_SURFACES = (
    ("scrub_credentials", scrub_credentials),
    ("write-time chain", _through_the_chain),
    ("support bundle", redact_log_line),
)


@pytest.mark.parametrize(("line", "label"), _CAMEL_LINES, ids=[line for line, _ in _CAMEL_LINES])
def test_a_camelcase_label_loses_its_value_on_every_surface(line: str, label: str) -> None:
    printed = [name for name, apply in _SURFACES if _VALUE in apply(line)]
    assert not printed, (line, printed)
    out = scrub_credentials(line)
    assert label in out and CREDENTIAL_PLACEHOLDER in out, out


def _without_the_camel_start(patch: pytest.MonkeyPatch) -> None:
    """The three label patterns as they were before BACKLOG #5545: ``_LABEL_START`` alone."""
    for name in ("_BEARER", "_CREDENTIAL_KV", "_KEY_MATERIAL"):
        pattern: re.Pattern[str] = getattr(secretscrub, name)
        assert pattern.pattern.count(secretscrub._LABEL_OR_CAMEL_START) == 1, name
        old = pattern.pattern.replace(secretscrub._LABEL_OR_CAMEL_START, secretscrub._LABEL_START)
        patch.setattr(secretscrub, name, re.compile(old, pattern.flags))


def test_every_camelcase_line_prints_its_value_without_the_camel_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE POSITIVE CONTROL: with the camelCase start taken back out, every line above prints its
    value on the credential scrub, so the green above is that start's work."""
    _without_the_camel_start(monkeypatch)
    printed = [line for line, _ in _CAMEL_LINES if _VALUE in scrub_credentials(line)]
    assert printed == [line for line, _ in _CAMEL_LINES]


#: Words that hold a capital and are no label, or a label word that does not END the word.
_NOT_LABELS = (
    "accessTokenValue=abc",
    "pageSize=20 isEnabled=true",
    "compassHeading=12 bypassMode=on",
    "userName=jdoe sessionCount=4",
    "PasswordPolicy=strict TokenEndpoint=https://idp.example.invalid/t",
)


@pytest.mark.parametrize("line", _NOT_LABELS)
def test_a_capital_that_opens_no_label_word_leaves_the_line_alone(line: str) -> None:
    assert scrub_credentials(line) == line


#: Spellings the camelCase start does not reach, each a residual its comment names: a capital
#: after a capital, and a label word glued on with no capital at all.
_RESIDUALS = (f"SASToken={_VALUE}", f"accesstoken={_VALUE}")


@pytest.mark.parametrize("line", _RESIDUALS)
def test_the_named_residuals_still_print(line: str) -> None:
    """Pinned so a change that reaches one of these updates the comment on ``_CAMEL_START`` too."""
    assert _VALUE in scrub_credentials(line)


#: A later camelCase label with a quoted value, after a first label of every family, glued on by
#: each separator the stop is written for and by none at all. The stop before a later quoted label
#: checks in front of every camelCase unit of a run, so the first label's plain value stops there
#: and the later label's own pattern takes its quoted value.
_SWALLOW_FIRST = (
    "password",
    "client_secret",
    "api_token",
    "session",
    "private_key",
    "MEFOR_STORE_PW",
    "Authorization: Bearer",
)
_SWALLOW_SEPARATORS = (";", "&", ",", ":", "=", "|", ".", "-", "_", "", " ")
_SWALLOW_SECOND = ("accessToken", "clientSecret", "userPassword", "refreshToken", "bindPwd")
_SWALLOW_VALUES = tuple(f"{_VALUE}{n}" for n in range(3))


def _swallow_lines() -> list[str]:
    first_value, head, tail = _SWALLOW_VALUES
    return [
        f"connect failed {first}={first_value}{sep}{second}={q}{head} {tail}{q} for svc"
        if not first.endswith("Bearer")
        else f"connect failed {first} {first_value}{sep}{second}={q}{head} {tail}{q} for svc"
        for first in _SWALLOW_FIRST
        for sep in _SWALLOW_SEPARATORS
        for second in _SWALLOW_SECOND
        for q in ("'", '"')
    ]


def _printing(lines: list[str], apply: Callable[[str], str]) -> list[str]:
    return [line for line in lines if any(value in apply(line) for value in _SWALLOW_VALUES)]


def test_a_plain_value_does_not_swallow_a_later_quoted_camelcase_label() -> None:
    """On the write-time surfaces, no value of any line prints."""
    lines = _swallow_lines()
    assert len(lines) == 7 * 11 * 5 * 2
    for name, apply in _SURFACES[:2]:
        printed = _printing(lines, apply)
        assert not printed, f"{name}: {len(printed)} lines printed, first {printed[:3]}"


def test_the_support_bundle_still_prints_a_swallowed_camelcase_label() -> None:
    """A RESIDUAL, pinned so its closing is noticed. ``support/redact.py`` runs its own copy of the
    label patterns first, and that copy has neither the camelCase start nor the split walk, so its
    plain value runs over the later camelCase label as every copy did before BACKLOG #5545. Its
    second layer, this module, then sees only the placeholder and the quoted value after it."""
    assert _printing(_swallow_lines(), redact_log_line)


def test_the_swallow_lines_print_without_the_split_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE POSITIVE CONTROL: with each walk taking a whole run of letters and digits again, as
    before BACKLOG #5545, most lines print, so the green above is the split walk's work."""
    for name in ("_MEFOR_SECRET", "_BEARER", "_AUTH_SCHEME", "_CREDENTIAL_KV", "_KEY_MATERIAL"):
        pattern: re.Pattern[str] = getattr(secretscrub, name)
        assert secretscrub._RUN_UNIT in pattern.pattern, name
        old = pattern.pattern.replace(secretscrub._RUN_UNIT, "[A-Za-z0-9]++")
        monkeypatch.setattr(secretscrub, name, re.compile(old, pattern.flags))
    lines = _swallow_lines()
    printed = _printing(lines, scrub_credentials)
    # Measured 2026-11-10: every line but those whose first value class already stops at the
    # separator. A floor, so a later change to a terminator set does not red this for the wrong
    # reason.
    assert len(printed) >= len(lines) // 2, f"only {len(printed)} of {len(lines)} printed"


# --- The compound key-material words: AccountKey, SharedAccessKey and the like ----------------------

#: Synthetic Azure-shaped connection strings and SDK settings, each with its key value in the middle.
_COMPOUND_KEY_LINES = (
    f"DefaultEndpointsProtocol=https;AccountName=zqacct;AccountKey={_VALUE};EndpointSuffix=x.invalid",
    f"Endpoint=sb://zq.example.invalid/;SharedAccessKeyName=RootManage;SharedAccessKey={_VALUE}",
    f"storage init failed: storageAccountKey={_VALUE}",
    f'{{"accessKey": "zqid", "secretKey": "{_VALUE}"}}',
    f"cfg AUTHKEY={_VALUE}",
    f'jwk load failed {{"privateKey": "{_VALUE}"}}',
    f"smart: smartPrivateKey={_VALUE} encryptionKey=zq",
)


@pytest.mark.parametrize("line", _COMPOUND_KEY_LINES)
def test_a_compound_key_label_loses_its_value_on_every_surface(line: str) -> None:
    printed = [name for name, apply in _SURFACES if _VALUE in apply(line)]
    assert not printed, (line, printed)


def test_the_compound_key_lines_print_without_the_compound_words(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE POSITIVE CONTROL: with ``_KEY_MATERIAL`` reading only ``_KEY_MATERIAL_WORDS`` again, every
    line above prints its value on the credential scrub."""
    pattern = secretscrub._KEY_MATERIAL
    words = secretscrub._alternation(secretscrub._KEY_LABEL_WORDS)
    assert pattern.pattern.count(words) == 1
    old = pattern.pattern.replace(words, secretscrub._alternation(secretscrub._KEY_MATERIAL_WORDS))
    monkeypatch.setattr(secretscrub, "_KEY_MATERIAL", re.compile(old, pattern.flags))
    printed = [line for line in _COMPOUND_KEY_LINES if _VALUE in scrub_credentials(line)]
    assert printed == list(_COMPOUND_KEY_LINES)


def test_the_compound_key_words_stay_clear_of_the_query_exclusions() -> None:
    """``_QUERY_NOT_CREDENTIAL_TAILS`` names keys that are not secrets, such as ``partitionKey``. No
    compound word may end one of them, or be ended by one, and each key exclusion, written in
    camelCase as a whole word and after a lower-case word, keeps its value. Driven by both tuples, so
    a word added to either is checked."""
    exclusions = secretscrub._QUERY_NOT_CREDENTIAL_TAILS
    for word in secretscrub._COMPOUND_KEY_WORDS:
        for excluded in exclusions:
            assert not word.endswith(excluded) and not excluded.endswith(word), (word, excluded)
    key_exclusions = [word for word in exclusions if word.endswith("key")]
    assert len(key_exclusions) >= 5, key_exclusions
    for excluded in key_exclusions:
        camel = excluded[:-3] + "Key"
        line = f"lookup {camel}={_VALUE} and x{camel.capitalize()[:-3]}Key={_VALUE}"
        assert scrub_credentials(line) == line, line


def test_a_key_name_that_only_names_a_key_keeps_its_value() -> None:
    """A compound word must END the label: ``SharedAccessKeyName`` names a key and holds none."""
    line = "SharedAccessKeyName=RootManage;accessKeyId=zqid"
    assert scrub_credentials(line) == line


def test_every_compound_key_word_is_a_stop_label() -> None:
    """The stop and the run-on read the compound words too, so a plain value stops before one whose
    value is quoted, as it does before ``private_key``."""
    quoted = re.compile(secretscrub._QUOTED_LABEL)
    run_on = re.compile(secretscrub._RUN_ON_LABEL)
    for word in secretscrub._COMPOUND_KEY_WORDS:
        for spelling in (word, word.upper()):
            assert quoted.match(f'{spelling}="v w"'), spelling
            assert run_on.match(f"{spelling}= "), spelling
        line = f"token=x;{word}='{_VALUE} {_VALUE}'"
        assert _VALUE not in scrub_credentials(line), line


# --- Found by code review: the split walk must keep what the whole-run walk kept ------------------


def test_the_walk_unit_takes_every_gate_fold_letter() -> None:
    """``(?i)[A-Za-z0-9]`` takes the four fold letters, so the case-sensitive unit names them. Held to
    ``_GATE_FOLDS``, the module's measured set, so the two cannot drift."""
    unit = re.compile(secretscrub._RUN_UNIT)
    for char, _letter in secretscrub._GATE_FOLDS:
        assert unit.fullmatch(f"ab{char}cd"), hex(ord(char))


#: Values opening on, or holding, a fold letter, each hidden on ``origin/main``. Built with ``chr``.
_FOLD_LINES = (
    (f"ValueError('login failed password={chr(0x131)}lk{_VALUE}')", _VALUE),
    (f'error: "api_key={chr(0x130)}st{_VALUE}"', _VALUE),
    (f'token=abc{chr(0x17F)}{_VALUE};password="v w"', _VALUE),
    (f"password='pw1 s{chr(0x131)}{_VALUE} pw3, private_key='p w q'", _VALUE),
)


@pytest.mark.parametrize(("line", "value"), _FOLD_LINES, ids=ascii)
def test_a_value_holding_a_fold_letter_is_still_walked_whole(line: str, value: str) -> None:
    for name, apply in _SURFACES[:2]:
        assert value not in apply(line), (name, ascii(apply(line)))


def test_a_later_quoted_value_holding_a_camelcase_label_is_hidden_whole() -> None:
    """The inner run-on walk keeps its whole ASCII run: split at a camelCase label inside the later
    value, it refused the run-on, and the later value's head printed."""
    for inner in ("userPwd= ", "isPass:"):
        line = f"password='a, private_key='{_VALUE} {inner}zq2'"
        assert _VALUE not in scrub_credentials(line), line


#: The length span and the growth allowed across it, as ``tests/test_log_redaction_secret_domain.py``
#: sets them for the label patterns' other growth arms: 8x the length, linear near 8.
_SPAN = (2048, 16384)
_MAX_GROWTH = 24.0


def _mixed_case_run(length: int) -> str:
    """A mixed-case run with a capital after every lower-case letter, then a label, so the
    admission gate admits the line and every capital in the run is a candidate start."""
    return "aB" * (length // 2) + " token=x"


def _quote_ended_value(length: int) -> str:
    """A token value of camelCase units whose capitals open label-word initials, ending on a quote."""
    return "token=" + "pS" * (length // 2) + '"'


def test_the_camelcase_start_grows_linearly_in_line_length() -> None:
    """The start runs on every admitted record, on text an attacker can influence. THE POSITIVE
    CONTROL is ``_BEARER`` with the same capital start and no label-word lookahead: every capital in
    the run then starts a prefix walk to the run's end, the quadratic. The control runs at a quarter
    of the span's lengths, the same 8x, so it stays fast."""
    shipped = secretscrub._BEARER
    growth = _growth_between(
        partial(shipped.sub, "x"), _mixed_case_run(_SPAN[0]), _mixed_case_run(_SPAN[1]), rounds=5
    )
    assert growth < _MAX_GROWTH, f"the shipped camelCase start grew {growth:.1f}x for 8x the length"
    # The split walk: a value of alternating lower-case and capital letters ending on a quote, so the
    # fast path refuses it and the stop is checked before every unit.
    walk = _growth_between(
        scrub_credentials, _quote_ended_value(_SPAN[0]), _quote_ended_value(_SPAN[1]), rounds=5
    )
    assert walk < _MAX_GROWTH, f"the split value walk grew {walk:.1f}x for 8x the length"
    no_lookahead = secretscrub._LABEL_OR_CAMEL_START.replace(
        r"(?=(?i:" + secretscrub._alternation(secretscrub._CAMEL_WORDS) + r")\b)", ""
    )
    assert no_lookahead != secretscrub._LABEL_OR_CAMEL_START
    control = re.compile(
        shipped.pattern.replace(secretscrub._LABEL_OR_CAMEL_START, no_lookahead), shipped.flags
    )
    control_growth = _growth_between(
        partial(control.sub, "x"), _mixed_case_run(512), _mixed_case_run(4096), rounds=5
    )
    assert control_growth > _MAX_GROWTH, (
        f"the quadratic control grew only {control_growth:.1f}x, so this box cannot tell the two apart"
    )
