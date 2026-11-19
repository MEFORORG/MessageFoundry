# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``secretscrub._union`` decides its shortcut on the narrow reading before (BACKLOG #5386).

Synthetic values only. ``_union`` returns the shipped reading alone where the reading before
changes nothing. Decided on the reading before WITH the widened DSN pass, a line where that pass
was the only change left the shortcut, reached the member-key branch and kept the reading before
whole. That reading reads no camelCase label, so the label's value printed where ``origin/main``
hid it (code review of the change that ran the widened pass on the reading before). Each line here
pairs with the value that printed; ``origin/main`` hides each, through every entry point below.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

import pytest

from messagefoundry import secretscrub as scrub_mod
from messagefoundry.logging_setup import CredentialScrubFilter, scrub_log_text
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials
from messagefoundry.support.redact import redact_log_line

_SHORTCUT_LINES = (
    ("connect redis://:Zq-Pw_1@h failed; userPwd='Kv9q;PWD='", "Kv9q"),
    ('connect redis://:Zq@h clientSecret="Kv9q;AccessToken="', "Kv9q"),
    ("connect smtp://:Pw@h:587 apiSecret='Kv9q;UID=u;PWD='", "Kv9q"),
    ("connect redis://:Zq-Pw_1@db.example.invalid:5432/x failed; userPwd='Kv9q;PWD='", "Kv9q"),
)


def _write_time_filter(line: str) -> str:
    """``line`` after :class:`CredentialScrubFilter` alone, as a handler would emit it."""
    record = logging.LogRecord("mefor.test", logging.ERROR, __file__, 1, line, None, None)
    assert CredentialScrubFilter().filter(record)
    return record.getMessage()


_ENTRY_POINTS: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("scrub_credentials", scrub_credentials),
    ("write-time filter", _write_time_filter),
    ("write-time chain", scrub_log_text),
    ("redact_log_line", redact_log_line),
)


@pytest.mark.parametrize("call", [c for _, c in _ENTRY_POINTS], ids=[n for n, _ in _ENTRY_POINTS])
@pytest.mark.parametrize(("line", "secret"), _SHORTCUT_LINES)
def test_a_line_the_widened_pass_alone_changes_hides_its_camelcase_value(
    line: str, secret: str, call: Callable[[str], str]
) -> None:
    out = call(line)
    assert secret not in out, out
    # The DSN password is hidden too, so the widened pass still ran, in the shipped reading.
    assert "Zq-Pw_1" not in out and "://:Zq@" not in out and "://:Pw@" not in out, out


@pytest.mark.parametrize(("line", "secret"), _SHORTCUT_LINES)
def test_a_line_the_widened_pass_alone_changes_takes_the_shortcut(line: str, secret: str) -> None:
    """The class of line: the narrow reading before changes nothing, the widened one does, and
    ``scrub_credentials`` returns the shipped reading whole, which is what the shortcut returns."""
    folded = scrub_mod._gate_fold(line)
    before = scrub_mod._pre_camel_sub
    assert scrub_mod._run(line, CREDENTIAL_PLACEHOLDER, folded, before, wide=False) == line
    assert scrub_mod._run(line, CREDENTIAL_PLACEHOLDER, folded, before) != line
    shipped = scrub_mod._run(line, CREDENTIAL_PLACEHOLDER, folded)
    assert secret not in shipped
    assert scrub_credentials(line) == shipped


#: Lines that took the shortcut on ``origin/main`` and still do: the reading before changes nothing
#: with or without the widened pass, here because no DSN password is read at all.
_PLAIN_SHORTCUT_LINES = (
    "connect redis://h failed; userPwd='Kv9q;PWD='",
    'connect clientSecret="Kv9q;AccessToken="',
    "store apiSecret='Kv9q;UID=u;PWD='",
)


@pytest.mark.parametrize("line", _PLAIN_SHORTCUT_LINES)
def test_a_line_the_reading_before_leaves_alone_still_takes_the_shortcut(line: str) -> None:
    folded = scrub_mod._gate_fold(line)
    assert scrub_mod._run(line, CREDENTIAL_PLACEHOLDER, folded, scrub_mod._pre_camel_sub) == line
    out = scrub_credentials(line)
    assert out == scrub_mod._run(line, CREDENTIAL_PLACEHOLDER, folded)
    assert "Kv9q" not in out, out


def test_a_shortcut_line_prints_nothing_the_widened_reading_before_hides() -> None:
    """The shortcut's claim, measured: on every line of the camelCase differential corpus that
    takes the union and leaves the narrow reading before unchanged, the shipped reading, which is
    all the shortcut returns, prints no atom the widened reading before hid. The control: on some
    of those lines the widened reading before hides something, so the claim is tested at all."""
    from tests.test_secretscrub_camelcase_label import _ATOM, _DSN_LINES, _dense_lines, _prints

    before = scrub_mod._pre_camel_sub
    tested = 0
    for line in _dense_lines(2000, 5386) + list(_DSN_LINES):
        folded = scrub_mod._gate_fold(line)
        if not scrub_mod._admits(folded, scrub_mod._ANY_HINT):
            continue
        if not scrub_mod._reads_camel(line, folded, CREDENTIAL_PLACEHOLDER):
            continue
        if scrub_mod._run(line, CREDENTIAL_PLACEHOLDER, folded, before, wide=False) != line:
            continue
        widened = scrub_mod._run(line, CREDENTIAL_PLACEHOLDER, folded, before)
        if widened == line:
            continue
        tested += 1
        out = scrub_credentials(line)
        for atom in set(_ATOM.findall(line)):
            assert not (_prints(atom, out) and not _prints(atom, widened)), (atom, line, out)
    assert tested > 20, tested
