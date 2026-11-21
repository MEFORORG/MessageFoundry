# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two DSN password shapes the widened reading printed, and the placeholder claim (BACKLOG #5386).

Synthetic values only. An empty user's password holding a bracket (added item 3) and a
";"-split tail after a user's own "@" (added item 4) each printed on the code before. Each is
hidden now on every entry point, and the reading still crosses no placeholder except a user's
whole first password segment, the claim ``support.redact`` and ``docs/PHI.md`` make. The comment
on ``secretscrub._WIDE_DSN_PASSWORD`` says how, and what each rule still leaves.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable

import pytest

from messagefoundry import secretscrub as scrub_mod
from messagefoundry.logging_setup import scrub_log_text
from messagefoundry.redaction import _REDACTED as PHI_PLACEHOLDER
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials
from messagefoundry.support.redact import REDACTION_PLACEHOLDER, redact_log_line

_ENTRY_POINTS: tuple[Callable[[str], str], ...] = (
    scrub_credentials,
    scrub_log_text,
    redact_log_line,
    lambda line: redact_log_line(scrub_log_text(line)),
)
_IDS = ("scrub_credentials", "write-time chain", "redact_log_line", "bundle of a chain line")
_PLACEHOLDERS = (CREDENTIAL_PLACEHOLDER, PHI_PLACEHOLDER, REDACTION_PLACEHOLDER)

#: Each printed the secrets named beside it on the code before this change.
_NOW_HIDDEN = (
    ("connect postgres://:Kv[9]x@db.invalid/x failed", ("Kv", "9]x"), "@db.invalid/x failed"),
    ("connect redis://:p[Kv9x]@db.invalid failed", ("Kv9x",), "@db.invalid failed"),
    ("connect redis://:Kv9]x[@db.invalid failed", ("Kv9",), "@db.invalid failed"),
    (
        "connect postgres://svc:Kv9x@Zq7;w@db.example.invalid/x failed",
        ("Kv9x", "Zq7", ";w@"),
        "postgres://svc:",
    ),
    ("connect postgres://svc:Kv9x@Zq7;w;Mx4@db failed", ("Kv9x", "Zq7", "Mx4"), "@db failed"),
    ("connect postgres://svc:Kv9x@;Wq4@db failed", ("Kv9x", "Wq4"), "@db failed"),
    ("connect postgres://svc:Kv9x@Zq7;;Wq4@db failed", ("Zq7", "Wq4"), "@db failed"),
    ("connect postgres://svc:Kv9x@Zq7;Wq4;@db failed", ("Zq7", "Wq4"), "@db failed"),
    ("connect postgres://svc:Kv9@Aa1;Bb2@Cc3;Dd4@h2 failed", ("Aa1", "Bb2", "Cc3", "Dd4"), "@h2"),
    ("connect postgres://svc:Kv9x@Zq7@Wq4;Mx5@db failed", ("Zq7", "Wq4", "Mx5"), "@db failed"),
)


#: Lines whose first redaction a second one must leave as it is, so the bundle of a chain line
#: matches the chain line.
_TWICE = (
    "connect postgres://svc:Kv9@a;b@h1;u2@h2 failed",
    "connect postgres://svc:Kv9x@Zq7;w@db.example.invalid/x failed",
    "connect postgres://svc:Kv9x@Zq7;w@mail.local:587;x@corp failed",
    # Review round 2: a group with no ";" before or after a ";" group, and an empty group.
    "connect postgres://svc:Kv9x@Zq7@w;x@db failed",
    "connect postgres://svc:Kv9@a;b@x.y@z failed",
    "connect postgres://svc:=@;@@@mail.local:587 failed",
)


@pytest.mark.parametrize("line", _TWICE)
def test_a_second_redaction_leaves_the_tail_rules_output_as_it_is(line: str) -> None:
    once = scrub_credentials(line)
    assert scrub_credentials(once) == once, once
    chain = scrub_log_text(line)
    assert redact_log_line(chain) == chain.replace(CREDENTIAL_PLACEHOLDER, REDACTION_PLACEHOLDER)


def test_a_camelcase_labelled_dsn_keeps_its_host_and_reads_as_origin_main() -> None:
    """Review round 3: the union joined the label pass's reading and the tail's into
    ``dbPassword=<redacted>db``, losing the host's "@", and a second pass hid the host too. The
    reading before now leaves the tail out, so the line is written as ``origin/main`` wrote it,
    host kept, and a second pass leaves it as it is. Its ``;w`` prints, as on ``origin/main``."""
    line = "dbPassword=postgres://svc:Kv9x@Zq7;w@db failed"
    expected = f"dbPassword={CREDENTIAL_PLACEHOLDER};w@db failed"
    assert scrub_credentials(line) == expected
    assert scrub_credentials(expected) == expected
    chain = scrub_log_text(line)
    assert chain == expected and scrub_log_text(chain) == chain
    bundle = redact_log_line(chain)
    assert bundle == expected.replace(CREDENTIAL_PLACEHOLDER, REDACTION_PLACEHOLDER)
    assert redact_log_line(bundle) == bundle


def test_known_residual_a_labelled_dsn_tail_prints() -> None:
    """Pinned as printed, as on ``origin/main``: a credential label before the DSN takes the DSN
    up to the ";" in its own pass, so the tail rule never sees it. A red means the reading changed."""
    for line in (
        "password: postgres://svc:Kv9x@Zq7;w@db failed",
        "dbPassword=postgres://svc:Kv9x@Zq7;w@db failed",
    ):
        assert ";w@db failed" in scrub_credentials(line), line


_CORPUS_PIECES = ("Kv9", "a", "Zq7", ";", ";", "@", "@", ".", ":", "=", "w", "x.y", "587", "[9]")
_CORPUS_SCHEMES = ("postgres://svc:", "smtp://ops:", "redis://:")
_CORPUS_LABELS = ("", "dbPassword=", "password: ", "accessToken=", "userPwd=", "x ")
_CORPUS_ENDS = (" failed", "; userPwd=x", ",userPwd='a;PWD=b'", "")


def _corpus() -> list[str]:
    rng = random.Random(5386)
    lines = []
    for _ in range(1500):
        body = "".join(rng.choice(_CORPUS_PIECES) for _ in range(rng.randint(2, 10)))
        host = rng.choice(("db", "h.invalid", "mail.local:587"))
        lines.append(
            rng.choice(_CORPUS_LABELS)
            + rng.choice(_CORPUS_SCHEMES)
            + body
            + "@"
            + host
            + rng.choice(_CORPUS_ENDS)
        )
    return lines


def _stable(line: str) -> tuple[bool, bool]:
    once = scrub_credentials(line)
    chain = scrub_log_text(line)
    bundle = redact_log_line(chain)
    return scrub_credentials(once) == once, redact_log_line(bundle) == bundle


def test_the_tail_makes_no_line_of_the_corpus_unstable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Over a seeded corpus, every line a second scrub, or a second bundle read of a chain line,
    leaves unchanged with the tail left out of the widened pattern, it leaves unchanged with the
    tail too. The control drops the tail on both callers."""
    import messagefoundry.support.redact as redact_mod

    lines = _corpus()
    # The corpus is not empty, so "no line got worse" is a reading over lines, not over none.
    assert len(lines) >= 1500
    shipped = [_stable(line) for line in lines]
    shipped_out = [scrub_credentials(line) for line in lines]
    control = re.compile(
        scrub_mod._WIDE_DSN_PASSWORD.pattern.replace(scrub_mod._DSN_TAIL, ""),
        scrub_mod._WIDE_DSN_PASSWORD.flags,
    )
    monkeypatch.setattr(scrub_mod, "_WIDE_DSN_PASSWORD", control)
    monkeypatch.setattr(redact_mod, "_WIDE_DSN_PASSWORD", control)
    without = [_stable(line) for line in lines]
    worse = [
        line
        for line, a, b in zip(lines, shipped, without, strict=True)
        if (b[0] and not a[0]) or (b[1] and not a[1])
    ]
    assert not worse, worse[:5]
    # Positive control: the tail changes the output of some lines of the corpus.
    assert any(scrub_credentials(line) != out for line, out in zip(lines, shipped_out, strict=True))


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize(("line", "secrets", "kept"), _NOW_HIDDEN)
def test_a_bracket_or_a_semicolon_tail_in_a_dsn_password_is_hidden(
    line: str, secrets: tuple[str, ...], kept: str, call: Callable[[str], str]
) -> None:
    out = call(line)
    for secret in secrets:
        assert secret not in out, out
    assert kept in out, out


#: Hosts the tail rule must not take: a "." or ":" in the run before the ";", or a ``key=``
#: member after it. Each is the output the code before gave too.
_HOST_KEPT = (
    "notify smtp://ops:pw@mail.local:587;alerts@corp.example failed",
    "notify smtp://ops:pw@db;sslpassword=Tail@Sec9 failed",
)


@pytest.mark.parametrize("line", _HOST_KEPT)
def test_the_tail_rule_keeps_a_host_or_a_member(line: str) -> None:
    out = scrub_credentials(line)
    assert "pw@" not in out, out
    head = line.split("pw@", 1)[1].split(";", 1)[0]
    assert f"{CREDENTIAL_PLACEHOLDER}@{head};" in out, out


def test_an_empty_users_dsn_takes_no_semicolon_tail() -> None:
    """The tail rule sits on the user's alternative only. An empty user whose password ends in a
    bracket, the one way its match can end in one, still stops at the ";" after it."""
    match = scrub_mod._WIDE_DSN_PASSWORD.search("redis://:Kv[9a]@Zq;w@db")
    assert match is not None and match.group(0) == "redis://:Kv[9a]@", match


# --- THE PLACEHOLDER CLAIM ------------------------------------------------------------------------
#
# ``support.redact`` and ``docs/PHI.md`` say the widened reading crosses a placeholder only where it
# is the whole first segment of a password with a user. Each line below holds a placeholder some
# earlier pass could have written; every match the pattern makes on it must hold no placeholder
# except right after ``user:``.

_PLACEHOLDER_SHAPE = re.compile(r"(?i)\[[a-z]+\]|<[a-z]+>")
_CLAIM_TEMPLATES = (
    "redis://:{p}x@db",
    "redis://:Kv{p}@db",
    "redis://:Kv[9]{p}@db",
    "redis://:[9{p}@db",
    "redis://:Kv]{p}x@db",
    "redis://:a@{p}@db",
    "postgres://svc:{p}@{p};w@db",
    "postgres://svc:{p}@Zq;{p}@db",
    "postgres://svc:{p}@Zq;w{p}@db",
    "postgres://svc:Kv{p}@db",
    "postgres://svc:Kv9@Zq;{p}@db",
    "postgres://svc:{p}@Zq;w@{p}@db",
)


@pytest.mark.parametrize("placeholder", _PLACEHOLDERS)
@pytest.mark.parametrize("template", _CLAIM_TEMPLATES)
def test_the_widened_reading_crosses_no_placeholder_but_a_users_first_segment(
    template: str, placeholder: str
) -> None:
    line = template.format(p=placeholder)
    for match in scrub_mod._WIDE_DSN_PASSWORD.finditer(line):
        password = match.group(0)[len(match.group(1)) + 1 :]
        held = list(_PLACEHOLDER_SHAPE.finditer(password))
        if not held:
            continue
        # With a user, the one placeholder allowed is the whole first segment, at the very start.
        assert not match.group(1).endswith("//"), (line, match.group(0))
        assert len(held) == 1 and held[0].start() == 0, (line, match.group(0))
        assert password[held[0].end()] == "@", (line, match.group(0))


def test_the_claim_test_reads_matches_that_hold_a_placeholder() -> None:
    """Positive control: the templates do reach a match holding a user's placeholder, so the
    test above is not passing on lines the pattern never matches."""
    line = "postgres://svc:<redacted>@Zq;w@db"
    match = scrub_mod._WIDE_DSN_PASSWORD.search(line)
    assert match is not None and match.group(0) == "postgres://svc:<redacted>@Zq;w@", match
