# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Parity gate: the published context-word deny-list equals ``CONTEXT_WORDS`` (ASVS 6.1.2 / 6.2.11).

Both requirements grade one artifact. 6.1.2 asks that a list of context-specific words be
documented; 6.2.11 asks that the documented list be the one used to refuse passwords.
``docs/SECURITY.md`` publishes all the terms under the heading "The context-word deny-list, in
full.", and ``messagefoundry/auth/policy.py`` enforces ``CONTEXT_WORDS``. Before this module nothing
tied the two together, so an edit to either one would leave the other stating something false while
every check stayed green (BACKLOG #1132, #1135).

What this module holds, and why each part is here:

* **Set equality, both directions.** A term enforced but not published fails 6.1.2; a term published
  but not enforced fails 6.2.11. Each direction is reported separately so the failure says which.
* **Every published term is refused, by behaviour.** The parsed list is fed through
  ``PasswordPolicy`` rather than compared only to the constant, so "the documented list is used" is
  measured, not inferred.
* **The spelled count, where the gate reads it.** The ``docs/SECURITY.md`` lead-in says "twelve
  terms" and ``docs/CONFIGURATION.md`` says "The **twelve** terms" and "five of the twelve are". A
  thirteenth term would leave those words stale, so they are derived from ``len(CONTEXT_WORDS)``.
  One further site is not read; see "What is NOT covered" below.
* **The refusal names the list.** The message a user sees used to say "application or vendor terms",
  which mis-described the list: several members are generic credential words. It must now name the
  deny-list by the heading a reader can search for.
* **No setting adds a term.** Both documents say the list is fixed. Every setting reaches the
  screen through ``PasswordPolicy``, so its field set is pinned: any new field reds here and sends
  the author to check that claim.

**What is deliberately NOT pinned.** ``docs/CONFIGURATION.md`` also says "five of the twelve are
generic credential words". Nothing in code classifies the members, so that five cannot be derived:
the bundled breach corpus holds four of the twelve (``bootstrap`` is not in it), which is a different
set. Pinning a number this module did not derive would be a second hand-kept copy, which is the
defect it exists to remove. Only the total is pinned.

**What is NOT covered.** The prose paragraph after the list in ``docs/SECURITY.md`` also spells the
total ("four of the twelve" at the time of writing). This module does not read that paragraph, for
the reason below, so a change in the count would leave that phrase stale with this gate green.

**The parser reads the list paragraph and nothing else.** The paragraph after the list also names
some members in backticks, and it is prose that other changes rewrite. Reading it would let a stray
backticked word pass as a member. ``test_the_parser_stops_at_the_list`` holds that boundary, and the
self-tests below prove a parse that finds no terms goes red rather than passing on an empty set.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest

from messagefoundry.auth.policy import CONTEXT_WORDS, PasswordPolicy
from messagefoundry.config.settings import AuthSettings

_ROOT = Path(__file__).resolve().parent.parent
_SECURITY_DOC = _ROOT / "docs" / "SECURITY.md"
_CONFIG_DOC = _ROOT / "docs" / "CONFIGURATION.md"

#: The bold lead-in that opens the published list. The list itself is the NEXT paragraph.
_HEADING = "**The context-word deny-list, in full.**"
#: The name a reader searches for. The refusal message must carry it so a refused user can find
#: the list in the documentation.
_LIST_NAME = "context-word deny-list"
#: The ``docs/CONFIGURATION.md`` row that republishes the count.
_CONFIG_ROW_PREFIX = "| `password_check_context` |"

#: ``PasswordPolicy``'s fields, pinned whole. A name or type filter cannot tell a new term source
#: apart: ``breach_corpus_file`` is a ``str | None`` path to a word list, so a second one shaped like
#: it would pass both. A new field must be added here on purpose, after checking the docs' claim.
_POLICY_FIELDS = frozenset(
    {
        "min_length",
        "require_uppercase",
        "require_lowercase",
        "require_digit",
        "require_symbol",
        "check_breached",
        "check_context",
        "check_username",
        "breach_corpus_file",
        "lockout_threshold",
        "lockout_minutes",
    }
)
#: The row's sub-count sentence, "five of the twelve are ...". Anchored on "are" so an unrelated
#: "either of the two" is not read as the total, and bold-tolerant because the row bolds numbers.
_SUBCOUNT_TOTAL = re.compile(r"\b\w+ of the \**(\w+)\**\s+are\b", re.IGNORECASE)

_TERM = re.compile(r"`([^`\s]+)`")
_NUMBER_WORDS = {
    1: "one",
    2: "two",
    3: "three",
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine",
    10: "ten",
    11: "eleven",
    12: "twelve",
    13: "thirteen",
    14: "fourteen",
    15: "fifteen",
    16: "sixteen",
    17: "seventeen",
    18: "eighteen",
    19: "nineteen",
    20: "twenty",
}


def _count_word(n: int) -> str:
    assert n in _NUMBER_WORDS, (
        f"CONTEXT_WORDS holds {n} terms, past this module's number words; extend _NUMBER_WORDS "
        "rather than dropping the count check"
    )
    return _NUMBER_WORDS[n]


def _stale_totals(text: str, n: int) -> list[str]:
    """Totals in "<k> of the <N> are" phrases that disagree with ``n``, as a word or as digits."""
    totals = [t.lower() for t in _SUBCOUNT_TOTAL.findall(text)]
    return [t for t in totals if t != _count_word(n) and t != str(n)]


def _heading_and_list(text: str) -> tuple[str, str]:
    """Return ``(intro, list_paragraph)``: the paragraph the heading opens, then the one after it.

    Raises ``AssertionError`` if the heading is missing or appears more than once, so a renamed or
    duplicated heading reds rather than parsing some other paragraph."""
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith(_HEADING)]
    assert len(starts) == 1, (
        f"expected exactly one line starting {_HEADING!r}, found {len(starts)}; the parity gate "
        "cannot find the published list"
    )
    i = starts[0]
    intro: list[str] = []
    while i < len(lines) and lines[i].strip():
        intro.append(lines[i].strip())
        i += 1
    while i < len(lines) and not lines[i].strip():
        i += 1
    listed: list[str] = []
    while i < len(lines) and lines[i].strip():
        listed.append(lines[i].strip())
        i += 1
    # A blank line inside the list would end the parse early and blame the doc for terms a reader
    # can see. Name that cause instead. The next paragraph is a continuation only when it is terms
    # and separators alone; prose that happens to open with a backticked word is not.
    while i < len(lines) and not lines[i].strip():
        i += 1
    following: list[str] = []
    while i < len(lines) and lines[i].strip():
        following.append(lines[i].strip())
        i += 1
    after = " ".join(following)
    leftover = _TERM.sub("", after).replace(",", " ").split()
    assert not (_TERM.search(after) and set(leftover) <= {"and"}), (
        f"the published list continues after a blank line ({after!r}); keep it one paragraph"
    )
    return " ".join(intro), " ".join(listed)


def _parse_terms(list_paragraph: str) -> list[str]:
    """The backticked terms in the list paragraph, in order.

    The paragraph must hold backticked terms and separators only. A term written without backticks
    would otherwise be silently skipped, and an empty parse would compare as an empty set."""
    terms = _TERM.findall(list_paragraph)
    residue = _TERM.sub("", list_paragraph).replace(",", "").strip()
    assert not residue, (
        f"the published list holds text outside backticked terms: {residue!r}. Write every member "
        "as `term`, comma-separated, so this gate can read it"
    )
    assert terms, "parsed ZERO terms from the published list; a parser that finds nothing must fail"
    return terms


def _parity_problems(published: set[str], enforced: frozenset[str]) -> list[str]:
    problems: list[str] = []
    unpublished = sorted(enforced - published)
    unenforced = sorted(published - enforced)
    if unpublished:
        problems.append(
            f"enforced by CONTEXT_WORDS but missing from docs/SECURITY.md: {unpublished} "
            "(the documented list is incomplete, ASVS 6.1.2)"
        )
    if unenforced:
        problems.append(
            f"published in docs/SECURITY.md but not in CONTEXT_WORDS: {unenforced} "
            "(the documented list is not the one used, ASVS 6.2.11)"
        )
    return problems


def _published_terms() -> list[str]:
    _, listed = _heading_and_list(_SECURITY_DOC.read_text(encoding="utf-8"))
    return _parse_terms(listed)


def _refusal_clause() -> str:
    """The clause ``PasswordPolicy`` emits for a context word, read from the code, not retyped."""
    # Any member will do; taking one from the constant keeps this from breaking when a term leaves.
    # The clause is what adding the term ADDS, so another screen firing on the filler does not hide it.
    policy = PasswordPolicy(check_breached=False)
    base = "zqzqzqzqzqzqzqzq-"
    added = set(policy.violations(base + min(CONTEXT_WORDS))) - set(policy.violations(base))
    assert len(added) == 1, f"expected adding a term to add one clause, got {sorted(added)}"
    return added.pop()


# ---------------------------------------------------------------------------------------------
# The gate, against the real documents and the real constant.
# ---------------------------------------------------------------------------------------------


def test_published_list_equals_context_words_both_ways() -> None:
    terms = _published_terms()
    assert len(terms) == len(set(terms)), f"the published list repeats a term: {terms}"
    problems = _parity_problems(set(terms), CONTEXT_WORDS)
    assert not problems, "\n".join(problems)


def test_every_published_term_is_refused_by_the_policy() -> None:
    """6.2.11's verb is that the DOCUMENTED list is used. Feed each published term through the policy,
    upper-cased and inside a longer passphrase, since the screen is a case-insensitive substring
    match."""
    policy = PasswordPolicy(check_breached=False)
    clause = _refusal_clause()
    template = "zq-{}-vy-long-passphrase"
    # Control on the loop's own template with the term left out: if the filler ever held a member,
    # every iteration would pass and the loop would prove nothing.
    assert clause not in policy.violations(template.format("")), template
    not_refused = [
        term
        for term in _published_terms()
        if clause not in policy.violations(template.format(term.upper()))
    ]
    assert not not_refused, f"published terms the policy does not refuse: {not_refused}"


def test_security_doc_spells_the_count() -> None:
    intro, _ = _heading_and_list(_SECURITY_DOC.read_text(encoding="utf-8"))
    expected = f"{_count_word(len(CONTEXT_WORDS))} terms"
    assert expected in intro.lower(), (
        f"docs/SECURITY.md's deny-list lead-in should say {expected!r} to match CONTEXT_WORDS; "
        f"it reads: {intro!r}"
    )


def test_configuration_row_spells_the_count() -> None:
    rows = [
        line
        for line in _CONFIG_DOC.read_text(encoding="utf-8").splitlines()
        if line.startswith(_CONFIG_ROW_PREFIX)
    ]
    assert len(rows) == 1, (
        f"expected one {_CONFIG_ROW_PREFIX!r} row in CONFIGURATION.md, found {rows}"
    )
    row = rows[0]
    word = _count_word(len(CONTEXT_WORDS))
    assert f"**{word}** terms" in row, f"the row should say '**{word}** terms': {row!r}"
    # "five of the twelve are" names the total too. Only the total is checked; the sub-count is not
    # derivable from code, see the module docstring.
    stale = _stale_totals(row, len(CONTEXT_WORDS))
    assert not stale, f"the row states a total of {stale}, but CONTEXT_WORDS holds {word}"
    assert "CONTEXT_WORDS" in row, "the row should name CONTEXT_WORDS as where the list lives"


def test_refusal_message_names_the_deny_list() -> None:
    clause = _refusal_clause()
    assert _LIST_NAME in clause, f"the refusal should name the {_LIST_NAME!r}: {clause!r}"
    assert _LIST_NAME in _HEADING, "the refusal and the heading must use the same name"
    # The retired description. Several members are generic credential words, not vendor terms.
    assert "vendor" not in clause.lower() and "application" not in clause.lower(), clause


def test_no_setting_adds_or_removes_a_term() -> None:
    """Both documents say the list is fixed in code and only switchable as a whole. A setting that
    feeds terms in would make that false, so its arrival must red here and send the author to the
    docs."""
    marker = re.compile(r"context|deny|term")
    settings_fields = {f for f in AuthSettings.model_fields if marker.search(f)}
    assert settings_fields == {"password_check_context"}, settings_fields
    # The name filter above misses a setting called, say, `password_blocklist_file`. Every setting
    # reaches the screen through PasswordPolicy.from_settings, so pin that dataclass's fields whole.
    policy_fields = {f.name for f in dataclasses.fields(PasswordPolicy)}
    assert policy_fields == _POLICY_FIELDS, (
        f"PasswordPolicy fields changed: added {sorted(policy_fields - _POLICY_FIELDS)}, removed "
        f"{sorted(_POLICY_FIELDS - policy_fields)}. docs/SECURITY.md and docs/CONFIGURATION.md both "
        "say no setting adds a term to the context-word screen. If a new field does, change both "
        "documents; either way, update _POLICY_FIELDS"
    )


# ---------------------------------------------------------------------------------------------
# Self-tests: the parser must be able to fail.
# ---------------------------------------------------------------------------------------------

_GOOD = f"""Intro text.

{_HEADING} A password is refused if it contains any of these
three terms:

`alpha`, `beta`,
`gamma`

The earlier text named `alpha` and `notaterm` in prose.
"""


def test_the_parser_reads_a_well_formed_list() -> None:
    intro, listed = _heading_and_list(_GOOD)
    assert _parse_terms(listed) == ["alpha", "beta", "gamma"]
    assert "three terms" in intro


def test_the_parser_stops_at_the_list() -> None:
    _, listed = _heading_and_list(_GOOD)
    assert "notaterm" not in _parse_terms(listed)


@pytest.mark.parametrize(
    "doc",
    [
        pytest.param(f"{_HEADING} intro.\n", id="heading-with-no-list"),
        pytest.param(f"{_HEADING} intro.\n\nno backticks here\n", id="list-with-no-terms"),
        pytest.param(f"{_HEADING} intro.\n\n`alpha`, and beta\n", id="bare-word-member"),
        pytest.param(f"{_HEADING} intro.\n\n`alpha`,\n\n`beta`\n", id="list-split-by-blank"),
        pytest.param(f"{_HEADING} intro.\n\n`alpha`,\n\nand `beta`\n", id="split-with-and"),
        pytest.param("no heading at all\n\n`alpha`\n", id="heading-missing"),
        pytest.param(f"{_HEADING} a.\n\n`alpha`\n\n{_HEADING} b.\n\n`beta`\n", id="heading-twice"),
    ],
)
def test_the_parser_fails_rather_than_returning_nothing(doc: str) -> None:
    with pytest.raises(AssertionError):
        _, listed = _heading_and_list(doc)
        _parse_terms(listed)


def test_parity_reds_on_a_planted_extra_or_missing_term() -> None:
    real = set(CONTEXT_WORDS)
    assert _parity_problems(real, CONTEXT_WORDS) == []
    extra = _parity_problems(real | {"plantedterm"}, CONTEXT_WORDS)
    assert len(extra) == 1 and "plantedterm" in extra[0] and "6.2.11" in extra[0]
    dropped = sorted(real)[0]
    missing = _parity_problems(real - {dropped}, CONTEXT_WORDS)
    assert len(missing) == 1 and dropped in missing[0] and "6.1.2" in missing[0]
    assert _parity_problems(set(), CONTEXT_WORDS), "an empty published set must not pass"


def test_the_parser_accepts_prose_that_opens_with_a_term() -> None:
    doc = f"{_HEADING} intro.\n\n`alpha`, `beta`\n\n`alpha` is described in prose here.\n"
    _, listed = _heading_and_list(doc)
    assert _parse_terms(listed) == ["alpha", "beta"]


def test_the_total_check_can_fire() -> None:
    assert _stale_totals("five of the twelve are generic", 12) == []
    assert _stale_totals("five of the **twelve** are generic", 13) == ["twelve"]
    assert _stale_totals("Five Of The 12 are generic", 13) == ["12"]
    assert _stale_totals("either of the two screens", 13) == []
