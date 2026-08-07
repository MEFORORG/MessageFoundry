# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Stability guard for the ``SDS-<section>.<n>`` rule identifiers in the Secure Development Standards.

WHY THIS EXISTS. The standard's requirements used to be citable only by section number, and a section
number is a position rather than a name. The document has already been renumbered once — its Version
history records ``§5–§9 → §6–§10`` when Spec-Driven Development was inserted as the new §5 — and the
citations written against the old scheme did not error, did not render differently, and were not
noticed. They simply began naming different requirements. Ten of them in the maintainer's private
security documents still resolve to the wrong section today: four cite "§5.4 (release gate)" when
release gates are §6.4 and §5.4 is now "Clarify and analyze".

Identifiers fix that only if something keeps them stable, which is what this module is. The convention
it enforces is stated in the standard itself under "How to read the rules"; the assertions here are
that text made mechanical.

WHAT IT DELIBERATELY DOES NOT CATCH.

* **A reworded rule that changed what it demands.** Rewording under the same identifier is legal and
  retiring is a judgment call about meaning, which no regex makes. ``test_no_unaccounted_gaps`` catches
  the *mechanical* half — a rule that vanished without a tombstone — and nothing here can tell an
  editorial rewrite from a semantic one. That remains a review obligation.
* **A citation in the private security vault.** ``git ls-files docs/security/`` returns nothing in this
  repository, so the ten known-stale citations are invisible where CI runs. This guard sees the
  standard, its siblings and the code; it cannot see the vault, and a green run here is not evidence
  about the vault's citations.
* **A citation in the published PDF or the website copy of this standard.** Both live in the separate
  ``messagefoundry-website`` repository, which this guard cannot read and which runs no CI of its own.
  Whether that copy still matches this document is checked nowhere, so a green run here says nothing
  about what is being served publicly.
* **Anything derived from git history.** The required test leg checks out at ``fetch-depth: 1``, so an
  identifier's past is not readable here. Every check below is derivable from the working tree alone.

Paths in failure messages are repository-relative on purpose: absolute paths on a developer machine
carry a worktree slug, and a bare slug is exactly the shape the forbidden-content guard does not catch
before it reaches this public repository.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SDS = _REPO / "docs" / "Secure_Development_Standards.md"

#: Heading under which the tombstones live. Changing it here and in the document together is fine;
#: changing it in only one place fails ``test_retired_rules_table_is_present``.
_RETIRED_HEADING = "## Retired rules"

#: The RFC 2119 keywords that give a rule its force. Capitals only — the standard says so explicitly,
#: and a lowercase "should" in a requirement cell is the defect this catches.
_RFC2119 = ("MUST NOT", "MUST", "SHOULD NOT", "SHOULD", "MAY")

#: A full identifier anywhere in prose or in a table cell.
_ID_ANYWHERE = re.compile(r"\bSDS-\d+(?:\.\d+)+\b")

#: A heading, capturing its dotted number when it has one (``### 4.3 Produce ...`` -> ``4.3``).
_HEADING = re.compile(r"^(#{2,4})\s+(?:(A?\.?\d+(?:\.\d+)*)\.?\s+)?(.*)$")

#: An inline rule: a bullet opening with a bolded identifier and its requirement. Anchored at the start
#: of the line so a bolded identifier mid-sentence stays a citation.
_INLINE_RULE = re.compile(r"^\s*[-*]\s+\*\*(SDS-\d+(?:\.\d+)+)\s*[—-]\s*(.+?)\*\*")

#: The evidence clause an inline rule carries in place of a table's third column.
_EVIDENCE_CLAUSE = re.compile(r"\*Evidence:\*\s*(.+?)(?:\s*\*\(|$)")


@dataclass(frozen=True)
class Rule:
    """One identified requirement, as parsed from a table row."""

    rule_id: str
    section: str
    number: int
    requirement: str
    evidence: str
    line: int
    heading_number: str


@dataclass(frozen=True)
class Retired:
    """One tombstone row from the Retired rules table."""

    rule_id: str
    line: int


def _split_row(line: str) -> list[str]:
    """Split a markdown table row into stripped cells, dropping the leading/trailing empties."""
    if not line.lstrip().startswith("|"):
        return []
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _parse_id(rule_id: str) -> tuple[str, int] | None:
    """Split ``SDS-7.4.3`` into its section (``7.4``) and its number (``3``)."""
    if not rule_id.startswith("SDS-"):
        return None
    parts = rule_id[len("SDS-") :].split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts):
        return None
    return ".".join(parts[:-1]), int(parts[-1])


def parse_rules(text: str) -> list[Rule]:
    """Every identified rule defined in ``text``, in document order.

    Two definition shapes, because the standard has two kinds of section.

    A TABLE row whose first cell is exactly an identifier defines a rule. That is the shape used
    wherever a section is a list of obligations.

    An INLINE rule is a bullet opening ``- **SDS-x.y - <requirement>.**``, used where the requirement
    is inseparable from the argument that justifies it. Sections 3 and 5 are essays whose evidence IS
    the surrounding prose -- the dated audit that produced a rule, the retracted claims that named it --
    and tabling them would throw away the part that makes them persuasive. An inline rule still carries
    its evidence, in a trailing ``*Evidence:* ...`` clause, so no rule anywhere escapes the requirement
    to say what settles it.

    An identifier appearing anywhere else is a CITATION, not a definition.
    """
    rules: list[Rule] = []
    heading_number = ""
    in_retired = False
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if line.startswith("## "):
            in_retired = line.strip() == _RETIRED_HEADING
        match = _HEADING.match(line)
        if match and match.group(2):
            # Only a NUMBERED heading changes the section context. An unnumbered subheading -- "A note
            # on claims and wording", "Reviewing security prose" -- sits inside its parent section, and
            # blanking the context here would silently skip the mis-siting check for every rule under
            # it, which is precisely where the prose rules live.
            heading_number = match.group(2)
        if in_retired:
            continue

        cells = _split_row(line)
        if len(cells) >= 3 and (parsed := _parse_id(cells[0])) is not None:
            rules.append(
                Rule(
                    rule_id=cells[0],
                    section=parsed[0],
                    number=parsed[1],
                    requirement=cells[1],
                    evidence=cells[2],
                    line=lineno,
                    heading_number=heading_number,
                )
            )
            continue

        inline = _INLINE_RULE.match(line)
        if inline is None:
            continue
        parsed = _parse_id(inline.group(1))
        if parsed is None:
            continue
        rules.append(
            Rule(
                rule_id=inline.group(1),
                section=parsed[0],
                number=parsed[1],
                requirement=inline.group(2),
                evidence=_inline_evidence(lines, lineno - 1),
                line=lineno,
                heading_number=heading_number,
            )
        )
    return rules


def _inline_evidence(lines: list[str], start: int) -> str:
    """The ``*Evidence:*`` clause of the inline rule beginning at ``lines[start]``.

    A bullet in this document wraps across several indented source lines, so the clause is looked for
    across the whole bullet rather than on its first line. Returning "" when there is none is what makes
    ``test_every_rule_carries_evidence`` fail, which is the intent -- a prose rule is not exempt.
    """
    body: list[str] = [lines[start]]
    for line in lines[start + 1 :]:
        if (
            not line.strip()
            or _INLINE_RULE.match(line)
            or line.lstrip().startswith(("-", "|", "#"))
        ):
            break
        body.append(line)
    found = _EVIDENCE_CLAUSE.search(" ".join(part.strip() for part in body))
    return found.group(1).strip() if found else ""


def parse_retired(text: str) -> list[Retired]:
    """Every identifier listed in the Retired rules table."""
    retired: list[Retired] = []
    in_retired = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.startswith("## "):
            in_retired = line.strip() == _RETIRED_HEADING
            continue
        if not in_retired:
            continue
        cells = _split_row(line)
        if not cells:
            continue
        if _parse_id(cells[0]) is not None:
            retired.append(Retired(rule_id=cells[0], line=lineno))
    return retired


def find_gaps(rules: list[Rule], retired: list[Retired]) -> list[str]:
    """Identifiers between 1 and the section's highest that are neither live nor tombstoned.

    A rule deleted without a tombstone leaves its number free for reuse, which is the failure the
    whole convention exists to prevent. Retiring it closes the gap; deleting it silently does not.
    """
    live: dict[str, set[int]] = {}
    for rule in rules:
        live.setdefault(rule.section, set()).add(rule.number)
    gone: dict[str, set[int]] = {}
    for tomb in retired:
        parsed = _parse_id(tomb.rule_id)
        if parsed is not None:
            gone.setdefault(parsed[0], set()).add(parsed[1])
    missing: list[str] = []
    for section, numbers in sorted(live.items()):
        highest = max(numbers)
        accounted = numbers | gone.get(section, set())
        missing.extend(f"SDS-{section}.{n}" for n in range(1, highest + 1) if n not in accounted)
    return missing


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _rel(path: Path) -> str:
    """Repository-relative path, so no failure message can leak a worktree slug."""
    return path.relative_to(_REPO).as_posix()


@pytest.fixture(scope="module")
def sds_text() -> str:
    return _read(_SDS)


@pytest.fixture(scope="module")
def rules(sds_text: str) -> list[Rule]:
    return parse_rules(sds_text)


@pytest.fixture(scope="module")
def retired(sds_text: str) -> list[Retired]:
    return parse_retired(sds_text)


# --- the convention is present at all ---------------------------------------------------------------


def test_convention_section_is_present(sds_text: str) -> None:
    """The rules mean nothing without the paragraph that defines how to read them."""
    assert "## How to read the rules" in sds_text, (
        f"{_rel(_SDS)} must define the identifier convention; every assertion in this module is a "
        "restatement of that section and is meaningless if it is gone."
    )


def test_retired_rules_table_is_present(sds_text: str) -> None:
    assert _RETIRED_HEADING in sds_text, (
        f"{_rel(_SDS)} must keep the '{_RETIRED_HEADING}' table. Without it a retired identifier has "
        "nowhere to land and an outliving citation resolves to whatever took the number."
    )


# --- the live corpus --------------------------------------------------------------------------------


def test_every_rule_id_is_well_formed(rules: list[Rule]) -> None:
    bad = [r for r in rules if _parse_id(r.rule_id) is None]
    assert not bad, "\n".join(
        f"{_rel(_SDS)}:{r.line} malformed identifier {r.rule_id!r}" for r in bad
    )


def test_no_duplicate_rule_ids(rules: list[Rule]) -> None:
    seen: dict[str, int] = {}
    clashes: list[str] = []
    for rule in rules:
        if rule.rule_id in seen:
            clashes.append(
                f"{_rel(_SDS)}:{rule.line} {rule.rule_id} already defined at line {seen[rule.rule_id]}"
            )
        else:
            seen[rule.rule_id] = rule.line
    assert not clashes, "\n".join(
        ["An identifier names exactly one requirement. Duplicates:", *clashes]
    )


def test_rule_id_section_matches_its_heading(rules: list[Rule]) -> None:
    """``SDS-7.4.3`` must be defined under §7.4. A mis-sited rule is a citation pointing elsewhere."""
    wrong = [r for r in rules if r.heading_number and r.section != r.heading_number.lstrip(".")]
    assert not wrong, "\n".join(
        [
            "A rule's identifier must carry the section it is defined under:",
            *(
                f"{_rel(_SDS)}:{r.line} {r.rule_id} sits under section {r.heading_number}"
                for r in wrong
            ),
        ]
    )


def test_no_unaccounted_gaps(rules: list[Rule], retired: list[Retired]) -> None:
    missing = find_gaps(rules, retired)
    assert not missing, (
        "These identifiers are neither live nor tombstoned, so their numbers are free to be reused "
        f"by a later rule — which is how a citation silently changes meaning: {', '.join(missing)}. "
        f"Retire them in '{_RETIRED_HEADING}' rather than deleting them."
    )


def test_retired_ids_are_not_live(rules: list[Rule], retired: list[Retired]) -> None:
    live = {r.rule_id for r in rules}
    reissued = sorted(t.rule_id for t in retired if t.rule_id in live)
    assert not reissued, (
        "A retired identifier is never reissued; these are both tombstoned and live: "
        f"{', '.join(reissued)}"
    )


def test_every_rule_states_an_rfc2119_keyword(rules: list[Rule]) -> None:
    toothless = [r for r in rules if not any(k in r.requirement for k in _RFC2119)]
    assert not toothless, "\n".join(
        [
            "Every rule states its force in capitals (MUST / MUST NOT / SHOULD / SHOULD NOT / MAY):",
            *(f"{_rel(_SDS)}:{r.line} {r.rule_id} — {r.requirement[:80]}" for r in toothless),
        ]
    )


def test_every_rule_carries_evidence(rules: list[Rule]) -> None:
    """A rule with no checkable evidence is an aspiration, which the standard says in those words."""
    empty = [r for r in rules if not r.evidence or r.evidence in {"-", "—", "TBD"}]
    assert not empty, "\n".join(
        [
            "Every rule names the evidence that settles it:",
            *(f"{_rel(_SDS)}:{r.line} {r.rule_id} has no evidence" for r in empty),
        ]
    )


# --- citations across the repository ----------------------------------------------------------------


def _citation_sources() -> list[Path]:
    """Tracked prose and code that may cite a rule. The vault and the website are out of reach.

    Code is included because the section-number citations this convention replaces are already there —
    the CLI help, the DAST receipt constant and a CI pin all name parts of this standard — so an
    identifier will end up in code the moment one of those migrates.

    ``tests/`` is deliberately excluded: the self-bite fixtures below define synthetic identifiers
    (``SDS-9.1`` and friends) that name no real rule by design, and scanning them would make this guard
    fail on its own evidence.
    """
    paths = [
        _REPO / "CLAUDE.md",
        *sorted((_REPO / "docs").rglob("*.md")),
        *sorted((_REPO / "messagefoundry").rglob("*.py")),
        *sorted((_REPO / "scripts").rglob("*.py")),
    ]
    return [p for p in paths if p.is_file()]


def test_every_cited_id_resolves(rules: list[Rule], retired: list[Retired]) -> None:
    """A citation naming no rule is the defect in its final form: it reads fine and says nothing."""
    known = {r.rule_id for r in rules} | {t.rule_id for t in retired}
    dangling: list[str] = []
    for path in _citation_sources():
        for lineno, line in enumerate(_read(path).splitlines(), start=1):
            for cited in _ID_ANYWHERE.findall(line):
                if cited not in known:
                    dangling.append(f"{_rel(path)}:{lineno} cites {cited}, which is not a rule")
    assert not dangling, "\n".join(
        ["Every cited identifier must resolve to a live or retired rule:", *dangling]
    )


# --- prove the instrument ---------------------------------------------------------------------------
#
# Each check above is fired at input built to break it. A guard that has never been observed to fail is
# not evidence, and these assertions are what make the green above mean something while the live corpus
# is still small.

_HEADER = "## How to read the rules\n\n## Retired rules\n\n| Retired ID | Retired in |\n|---|---|\n"


def test_selfbite_duplicate_ids_are_detected() -> None:
    text = (
        "### 9. Evidence\n\n| ID | Requirement | Evidence |\n|---|---|---|\n"
        "| SDS-9.1 | **MUST** do a thing | The thing |\n"
        "| SDS-9.1 | **MUST** do another | The other |\n"
    )
    parsed = parse_rules(text)
    assert len(parsed) == 2
    assert len({r.rule_id for r in parsed}) == 1, "the duplicate must survive parsing to be caught"


def test_selfbite_a_deleted_rule_leaves_a_gap() -> None:
    text = (
        "### 9. Evidence\n\n| ID | Requirement | Evidence |\n|---|---|---|\n"
        "| SDS-9.1 | **MUST** a | x |\n"
        "| SDS-9.3 | **MUST** c | z |\n"
    )
    assert find_gaps(parse_rules(text), []) == ["SDS-9.2"]


def test_selfbite_a_tombstone_closes_the_gap() -> None:
    text = (
        "### 9. Evidence\n\n| ID | Requirement | Evidence |\n|---|---|---|\n"
        "| SDS-9.1 | **MUST** a | x |\n"
        "| SDS-9.3 | **MUST** c | z |\n"
        f"\n{_RETIRED_HEADING}\n\n| Retired ID | Why |\n|---|---|\n| SDS-9.2 | superseded |\n"
    )
    assert find_gaps(parse_rules(text), parse_retired(text)) == []


def test_selfbite_retired_rows_are_not_parsed_as_live() -> None:
    """The tombstone table is full of identifiers; reading them as definitions would mask every gap."""
    text = f"{_RETIRED_HEADING}\n\n| Retired ID | Why |\n|---|---|\n| SDS-9.2 | superseded |\n"
    assert parse_rules(text) == []
    assert [t.rule_id for t in parse_retired(text)] == ["SDS-9.2"]


def test_selfbite_a_lowercase_keyword_is_toothless() -> None:
    text = (
        "### 9. Evidence\n\n| ID | Requirement | Evidence |\n|---|---|---|\n"
        "| SDS-9.1 | should probably do a thing | x |\n"
    )
    (rule,) = parse_rules(text)
    assert not any(k in rule.requirement for k in _RFC2119), (
        "lowercase 'should' must not satisfy the keyword check; the standard says capitals only"
    )


def test_selfbite_a_missited_rule_is_detected() -> None:
    text = (
        "### 7.4 Interface authentication\n\n| ID | Requirement | Evidence |\n|---|---|---|\n"
        "| SDS-6.3.1 | **MUST** do a thing | x |\n"
    )
    (rule,) = parse_rules(text)
    assert rule.section == "6.3" and rule.heading_number == "7.4"


def test_selfbite_a_citation_is_not_a_definition() -> None:
    """An identifier inside a sentence must not register as defining that rule."""
    text = "Deviation from SDS-4.3.7 is recorded in A.6.\n"
    assert parse_rules(text) == []
    assert _ID_ANYWHERE.findall(text) == ["SDS-4.3.7"]


def test_selfbite_an_inline_rule_is_parsed_with_its_evidence() -> None:
    text = (
        "### 3. Claims\n\n"
        "- **SDS-3.1 — MUST state a fact once.** A repo that states it twice will state it two ways.\n"
        "  *Evidence:* the source of record, linked rather than restated.\n"
    )
    (rule,) = parse_rules(text)
    assert rule.rule_id == "SDS-3.1"
    assert rule.requirement == "MUST state a fact once."
    assert rule.evidence == "the source of record, linked rather than restated."


def test_selfbite_an_inline_rule_without_evidence_is_caught() -> None:
    """A prose rule is not exempt from naming what settles it; empty evidence must reach the check."""
    text = (
        "### 3. Claims\n\n- **SDS-3.1 — MUST state a fact once.** Some argument, but no clause.\n"
    )
    (rule,) = parse_rules(text)
    assert rule.evidence == ""


def test_selfbite_a_bolded_identifier_mid_sentence_is_not_a_definition() -> None:
    """Otherwise citing a rule emphatically would define a second, evidence-free copy of it."""
    text = "### 3. Claims\n\nThe deviation cites **SDS-3.1** and records its owner.\n"
    assert parse_rules(text) == []
    assert _ID_ANYWHERE.findall(text) == ["SDS-3.1"]


def test_selfbite_an_inline_rule_inherits_its_numbered_parent_heading() -> None:
    """Prose rules live under UNNUMBERED subheadings; the mis-siting check must still see section 3."""
    text = (
        "## 3. How this maps to NIST\n\n"
        "#### Reviewing security prose\n\n"
        "- **SDS-3.1 — MUST ask what a reader would do.** *Evidence:* the review record.\n"
    )
    (rule,) = parse_rules(text)
    assert rule.heading_number == "3", "an unnumbered subheading must not blank the section context"
    assert rule.section == "3"


def test_selfbite_evidence_does_not_bleed_across_bullets() -> None:
    """Two adjacent inline rules must not share one clause, which would mask a missing one."""
    text = (
        "### 3. Claims\n\n"
        "- **SDS-3.1 — MUST do a thing.** No clause here.\n"
        "- **SDS-3.2 — MUST do another.** *Evidence:* the second one's own evidence.\n"
    )
    first, second = parse_rules(text)
    assert first.evidence == ""
    assert second.evidence == "the second one's own evidence."


def test_selfbite_malformed_identifiers_are_rejected() -> None:
    for bad in ("SDS-", "SDS-4", "SDS-4.x", "SD-4.1", "SDS-4..1"):
        assert _parse_id(bad) is None, f"{bad!r} must not parse as an identifier"
    assert _parse_id("SDS-4.3.7") == ("4.3", 7)
    assert _parse_id("SDS-9.2") == ("9", 2)
