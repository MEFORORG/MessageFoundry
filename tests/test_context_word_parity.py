# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Doc-vs-code parity gate for the password context-word deny-list (ASVS 6.1.2 / 6.2.11).

Both requirements grade the same artifact: the documented list of context-specific words a password
may not contain. 6.1.2 asks that the list be documented; 6.2.11 asks that the documented list be the
one enforced. So the published enumeration IS the control, and an enumeration that drifts from
``CONTEXT_WORDS`` fails both at once, silently, with nothing red.

Two files publish it and both have to move together:

* ``docs/SECURITY.md`` carries the enumeration itself, the retraction of the old characterization,
  and the substring semantics;
* ``docs/CONFIGURATION.md`` republishes the **cardinality**, a sub-count, the substring semantics
  and the "no setting adds or removes a term" claim -- it links but it also repeats, so a one-file
  gate would red for one document while the other kept asserting the old count.

Nothing here hard-codes a term. The set comes from the module and the enumeration is scraped, so the
only way to make this module green is to change both together.

**The parser is the weak point, so it is tested too.** A doc-scraping gate that matches nothing
passes vacuously and looks exactly like a gate that is working -- which is the decay both
requirements were filed against. ``test_the_parser_cannot_pass_vacuously`` plants the mutation: it
feeds the parser a document with the enumeration removed and requires an empty result, then requires
the parity comparison built on that result to fail.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from messagefoundry.auth.policy import CONTEXT_WORDS, PasswordPolicy
from messagefoundry.config.settings import AuthSettings

_ROOT = Path(__file__).resolve().parent.parent
#: The security narrative -- carries the enumeration itself.
_DOC = _ROOT / "docs" / "SECURITY.md"
#: The operator configuration reference. It republishes the cardinality and the tunability claim, so
#: it is a publishing site in its own right, not a pointer.
_CONFIG_DOC = _ROOT / "docs" / "CONFIGURATION.md"
_POLICY = _ROOT / "messagefoundry" / "auth" / "policy.py"

# --- anchors the gate slices on (change a doc lead-in -> change these together) ----------------------
_ENUM_LEAD = "**The context-word deny-list, in full"
_ENUM_END = "**What a deploying site can and cannot tune here.**"
_CONFIG_ROW = "| `password_check_context` |"

#: The characterization ``docs/SECURITY.md`` retracted in place: five of the members are generic
#: credential words with no connection to this application, to a vendor, or to HL7, so the phrase
#: mis-stated the rule in a way a reader could act on. It may still appear as a QUOTED retraction --
#: never as a live description, and never in the refusal message an operator receives.
_RETIRED_DOC_PHRASE = "app/vendor/HL7 terms"
_RETIRED_REFUSAL = "application or vendor terms"
#: A paragraph quoting the retired phrase has to mark it as retired. This is the marker it uses.
_RETRACTION_MARKER = "earlier revision"

#: Requirement numbers the context-word screen owns, against the ASVS 5.0.0 corpus: 6.1.2 is
#: "a list of context-specific words is documented", 6.2.11 is "the documented list ... is used".
#: A reviewed pair, not a derivation -- the corpus is not carried in this repository.
_OWN_REQUIREMENTS = ("6.1.2", "6.2.11")
#: 6.2.5 is the no-mandatory-composition requirement. The deny-list is not a composition rule, so
#: tagging the constant with it pointed a reader at the wrong verb.
_NOT_ITS_REQUIREMENT = "6.2.5"

_NUMBER_WORDS: dict[str, int] = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
}

#: The two shapes in which a document spells the size of the WHOLE list: "these twelve terms" /
#: "The **twelve** terms", and "of the twelve" in the retraction sentences. A sub-count ("five
#: members") is deliberately not matched -- it counts a subset, not the list.
_CARDINALITY_RE = re.compile(
    r"(?:these|the)\s+\*{0,2}([a-z]+)\*{0,2}\s+terms\b|of\s+the\s+\*{0,2}([a-z]+)\*{0,2}\b",
    re.IGNORECASE,
)

#: A backticked lower-case token inside the enumeration paragraph.
_TERM_RE = re.compile(r"`([a-z0-9]+)`")


# --- parsers ----------------------------------------------------------------------------------------


def _deny_list_region(text: str) -> str:
    """The ``docs/SECURITY.md`` block that publishes the deny-list.

    Raises ``ValueError`` if either anchor is gone. A missing section must be an error, never an
    empty string that every downstream assertion then passes over.
    """
    try:
        start = text.index(_ENUM_LEAD)
        end = text.index(_ENUM_END, start)
    except ValueError as exc:  # re-raised with the anchor named, so the failure is actionable
        raise ValueError(
            f"the deny-list section anchors are gone from the document: {exc}. "
            f"Expected {_ENUM_LEAD!r} followed by {_ENUM_END!r}."
        ) from exc
    return text[start:end]


def _published_terms(text: str) -> frozenset[str]:
    """The terms enumerated in ``docs/SECURITY.md``.

    The enumeration is the second paragraph of the region -- the first is the lead-in that states
    the substring semantics, the third is the retraction, which quotes five members and would
    otherwise be scraped as if it were the list.
    """
    paragraphs = _deny_list_region(text).split("\n\n")
    if len(paragraphs) < 2:
        return frozenset()
    return frozenset(_TERM_RE.findall(paragraphs[1]))


def _config_row(text: str) -> str:
    """The ``password_check_context`` row of the ``[auth]`` settings table."""
    for line in text.splitlines():
        if line.startswith(_CONFIG_ROW):
            return line
    raise ValueError(f"no {_CONFIG_ROW!r} row in the settings reference")


def _spelled_cardinalities(region: str) -> list[int]:
    """Every place the region spells the size of the whole list, as integers."""
    found: list[int] = []
    for whole, of_the in _CARDINALITY_RE.findall(region):
        word = (whole or of_the).lower()
        if word in _NUMBER_WORDS:
            found.append(_NUMBER_WORDS[word])
    return found


def _context_words_comment() -> str:
    """The ``#:`` comment block attached to ``CONTEXT_WORDS`` in ``auth/policy.py``."""
    lines = _POLICY.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if line.startswith("CONTEXT_WORDS"):
            block: list[str] = []
            cursor = index - 1
            while cursor >= 0 and lines[cursor].lstrip().startswith("#"):
                block.append(lines[cursor])
                cursor -= 1
            return "\n".join(reversed(block))
    raise ValueError("no CONTEXT_WORDS assignment in auth/policy.py")


def _context_refusal_clause() -> str:
    """The one clause the shipped policy appends when a password hits the deny-list.

    Derived by running the policy over a member of the constant rather than by reading the source,
    so it is the string an operator would actually receive.
    """
    term = sorted(CONTEXT_WORDS)[0]
    # min_length=1 and the breach screen off, so exactly one clause can fire.
    clauses = PasswordPolicy(min_length=1, check_breached=False).violations(f"zzq-{term}-qzz")
    assert len(clauses) == 1, f"expected the context clause alone, got {clauses}"
    return clauses[0]


# --- the parity assertions --------------------------------------------------------------------------


def test_published_enumeration_equals_the_shipped_constant() -> None:
    """The list a reader is given IS the list the engine enforces -- compared both directions."""
    published = _published_terms(_DOC.read_text(encoding="utf-8"))
    assert published, "the enumeration paragraph scraped empty -- the gate would pass vacuously"
    assert published - CONTEXT_WORDS == frozenset(), "documented but not enforced: " + ", ".join(
        sorted(published - CONTEXT_WORDS)
    )
    assert CONTEXT_WORDS - published == frozenset(), "enforced but not documented: " + ", ".join(
        sorted(CONTEXT_WORDS - published)
    )


def test_every_spelled_cardinality_matches_the_constant() -> None:
    """Both publishing sites spell the size of the list. Neither may fall behind the other."""
    sites = {
        "docs/SECURITY.md": _deny_list_region(_DOC.read_text(encoding="utf-8")),
        "docs/CONFIGURATION.md": _config_row(_CONFIG_DOC.read_text(encoding="utf-8")),
    }
    for name, region in sites.items():
        counts = _spelled_cardinalities(region)
        assert counts, f"{name} spells no cardinality for the list -- the assertion is vacuous"
        assert set(counts) == {len(CONTEXT_WORDS)}, (
            f"{name} spells the list as {sorted(set(counts))} but the constant holds "
            f"{len(CONTEXT_WORDS)} terms"
        )


def test_the_parser_cannot_pass_vacuously() -> None:
    """A planted mutation: a parser that extracts nothing must red, not pass.

    This is the assertion the module exists for. A doc-scraping gate whose selector stops matching
    goes green on a document that says nothing at all, which is indistinguishable from a gate that
    is working -- and is exactly the silent decay ASVS 6.1.2 and 6.2.11 were filed against here.
    """
    doc = _DOC.read_text(encoding="utf-8")

    # Positive control first: the parser finds the real list, so a later empty result means the
    # mutation bit, not that the parser was broken all along.
    assert _published_terms(doc) == CONTEXT_WORDS

    # 1. Enumeration removed, section intact -> no terms, and the parity comparison fails.
    region = _deny_list_region(doc)
    paragraphs = region.split("\n\n")
    gutted = doc.replace(
        region, "\n\n".join([paragraphs[0], "(enumeration removed)", *paragraphs[2:]])
    )
    assert _published_terms(gutted) == frozenset()
    with pytest.raises(AssertionError):
        _assert_parity(_published_terms(gutted))

    # 2. Section anchor gone -> the parser raises rather than returning an empty set quietly.
    with pytest.raises(ValueError):
        _published_terms(doc.replace(_ENUM_LEAD, "**Some other lead-in.**"))

    # 3. A thirteenth term in the document alone -> caught, in the direction a doc edit drifts.
    padded = doc.replace(paragraphs[1], paragraphs[1] + ", `notaterm`")
    with pytest.raises(AssertionError):
        _assert_parity(_published_terms(padded))


def _assert_parity(published: frozenset[str]) -> None:
    """The comparison under test in the mutation self-test, kept in one place."""
    assert published, "the enumeration scraped empty"
    assert published == CONTEXT_WORDS


def test_the_retired_characterization_is_not_a_live_claim() -> None:
    """ "app/vendor/HL7 terms" may be quoted as retracted. It may not describe the list."""
    hits = 0
    for name, path in (("docs/SECURITY.md", _DOC), ("docs/CONFIGURATION.md", _CONFIG_DOC)):
        for paragraph in path.read_text(encoding="utf-8").split("\n\n"):
            # Collapse the hard line wraps first: both the phrase and the marker straddle one
            # somewhere in these files, and a raw substring test would miss the wrapped copy.
            flat = re.sub(r"\s+", " ", paragraph)
            occurrences = flat.count(_RETIRED_DOC_PHRASE)
            if not occurrences:
                continue
            hits += occurrences
            # Quoted, so it reads as a phrase being reported. An unquoted copy is the document
            # saying it -- which is the failure. Paragraph-level marker words are not enough on
            # their own: a paragraph can retract one thing and assert another in the next sentence.
            assert flat.count(f'"{_RETIRED_DOC_PHRASE}"') == occurrences, (
                f"{name} states the retired characterization {_RETIRED_DOC_PHRASE!r} as its own "
                "claim; it may only be quoted as a phrase this page has withdrawn"
            )
            assert _RETRACTION_MARKER in flat, (
                f"{name} quotes {_RETIRED_DOC_PHRASE!r} in a paragraph that does not mark it retired"
            )
    # Both files carry the retraction, so a zero here means the scan stopped matching, not that the
    # phrase is gone. Retiring the retraction itself is a deliberate edit that must red first.
    assert hits >= 2, (
        f"the retraction scan found {hits} paragraphs; it reads two files that have it"
    )


def test_the_refusal_message_does_not_carry_the_retired_characterization() -> None:
    """The refusal clause is the ONE statement of this rule an operator ever receives.

    It reaches a JSON caller in the 400 body (``api/auth_routes.py`` joins the clauses behind
    "password must ") and the web console re-renders that body verbatim on its password form, where
    it is the only statement of the policy on the page. So a wrong characterization here is not a
    stale comment -- it is the rule, as told to the person who has to satisfy it.
    """
    clause = _context_refusal_clause()
    assert _RETIRED_REFUSAL not in clause, (
        f"the refusal message still carries the retracted characterization: {clause!r}"
    )
    # It reads as a "password must ..." continuation, like its siblings in the same list.
    assert clause == clause.lstrip() and not clause.endswith("."), clause
    assert clause.startswith("not contain"), clause
    # A reader who receives it can find the list: the noun it uses is the noun the document defines.
    region = _deny_list_region(_DOC.read_text(encoding="utf-8"))
    assert "deny-list" in clause and "deny-list" in region, (
        f"the refusal message and the published section do not share a name for the list: {clause!r}"
    )


def test_no_setting_adds_or_removes_a_term() -> None:
    """Both documents tell a site the check is whole-list on/off. Pin that absence.

    An operator-supplied context-word setting would make the published enumeration incomplete for
    that deployment, so the documents' claim and the settings surface have to move together.
    """
    context_fields = {name for name in AuthSettings.model_fields if "context" in name}
    assert context_fields == {"password_check_context"}, (
        "a new context-word setting exists; both documents still say no setting adds or removes a "
        f"term: {sorted(context_fields)}"
    )
    assert AuthSettings().password_check_context is True


def test_the_context_word_screen_carries_its_own_requirement_numbers() -> None:
    """The list is labelled with the requirements that grade it, and no others.

    Before this gate the shipped artifacts tagged the context-word screen with 6.2.5 (the
    no-mandatory-composition requirement) and gave 6.2.11 to the username-in-password screen, so a
    reader following either number arrived at the wrong control.
    """
    region = _deny_list_region(_DOC.read_text(encoding="utf-8"))
    for requirement in _OWN_REQUIREMENTS:
        assert requirement in region, f"the deny-list section does not cite ASVS {requirement}"

    comment = _context_words_comment()
    assert "6.2.11" in comment, "CONTEXT_WORDS is not tagged with the requirement that grades it"
    assert _NOT_ITS_REQUIREMENT not in comment, (
        f"CONTEXT_WORDS is still tagged ASVS {_NOT_ITS_REQUIREMENT}, which is a different verb"
    )

    # 6.2.11 names the deny-list, so no line in the policy module may attach it to the username
    # screen. (``config/settings.py`` carries the same mislabel on its ``password_check_username``
    # comment; extend this loop to that file once the line is corrected.)
    for number, line in enumerate(_POLICY.read_text(encoding="utf-8").splitlines(), start=1):
        if "6.2.11" in line:
            assert "username" not in line.lower(), (
                f"auth/policy.py line {number} labels the username screen ASVS 6.2.11: {line.strip()}"
            )
