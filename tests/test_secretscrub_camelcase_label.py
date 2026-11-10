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


#: The length span and the growth allowed across it, as ``tests/test_log_redaction_secret_domain.py``
#: sets them for the label patterns' other growth arms: 8x the length, linear near 8.
_SPAN = (2048, 16384)
_MAX_GROWTH = 24.0


def _mixed_case_run(length: int) -> str:
    """A mixed-case run with a capital after every lower-case letter, then a label, so the
    admission gate admits the line and every capital in the run is a candidate start."""
    return "aB" * (length // 2) + " token=x"


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
