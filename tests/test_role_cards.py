# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A role card is injected at SessionStart, so a WRONG one outranks the document that corrects it.

THE FAILURE THESE TESTS PIN. `CLAUDE.md` reaches a session as context. A card reaches it at session
start, before the session has read anything, and it reads as settled. So a card that disagrees with
the working agreement does not lose the argument -- it wins it, silently, for the whole session.

THE CARDS CAME FROM KORUS AND WERE NOT COPIED. Three ways a straight copy would have been wrong,
each measured 2026-09-06 and each guarded below:

  1. ROSTER. korus and this table have never matched, and neither leads the other. The MANAGER
     joined this table on 2026-09-10, when the owner retired the Console (BACKLOG #1529). The
     SPECIAL seat joined on 2026-09-16, taking the table to six. On 2026-09-19 the owner retired
     the REGULATOR and added the WATCHDOG, which holds the table at six and is NOT its successor:
     it measures whether reds are cleared and never says whose one is. The `elsewhere` bucket
     emptied on 2026-09-16 by owner instruction, so the tests below guard its MECHANISM rather
     than an occupant.
  2. PUSH AUTHORITY. korus's cards say pushing needs the owner. Section 5 carries the opposite as an
     anchored ruling, `refs/liaison/owner-ruling-20260829-push`.
  3. PLAYBOOK PATHS. korus's cards cite `roles/COMMON.md`. No such path exists in this checkout.

Each of those is a class, not an instance, which is why each gets a test rather than a fix.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import unittest
from functools import cache
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]

CARD_DIR = _REPO / "docs" / "roles"
SEATS_PATH = CARD_DIR / "seats.json"
AGREEMENT = _REPO / "CLAUDE.md"
HOOK = _REPO / "scripts" / "hooks" / "role-card-inject.ps1"
SEAT_SCRIPT = _REPO / "scripts" / "coord" / "seat.ps1"
SETTINGS = _REPO / ".claude" / "settings.json"

#: The marker and the injected copy. BOTH MUST STAY GIT-IGNORED, and the ignore rule here is the
#: INVERSE of korus's: `/.claude/*` covers the directory and one negation re-adds settings.json.
MARKER_RELPATH = ".claude/seat.local.txt"
ROLE_COPY_RELPATH = ".claude/ROLE.local.md"

#: Section 5's table governs. SIX seats: SPECIAL joined 2026-09-16, and on 2026-09-19 the owner
#: retired the REGULATOR and added the WATCHDOG, which is not its successor.
EXPECTED_SEATS = frozenset({"manager", "builder", "watchdog", "steward", "lander", "special"})

#: Seats live in korus and absent here. They must resolve to a card-less explanation, never to
#: silence. EMPTY SINCE 2026-09-16 by owner instruction, and empty is the correct state -- so any
#: assertion that LOOPS over it now examines nothing. The class below asserts the emptiness
#: directly and guards the two scripts by reading their source, instead of iterating a container
#: that cannot fail.
EXPECTED_ELSEWHERE: frozenset[str] = frozenset()

#: The seven seats CLAUDE.md section 5 retired on 2026-09-01. PINNED AS A SET, the way
#: CONSOLE_SPELLINGS is, because iterating whatever the file happens to contain cannot notice an
#: omission. Measured 2026-09-18: `asvs-tracker` was missing from every map, so the 12 records
#: carrying it resolved to the "MATCHES NO SEAT" typo branch -- reading as a misspelling rather
#: than as the roster fact it is, which is the exact failure CONSOLE_SPELLINGS exists to prevent.
SECTION_5_RETIRED_2026_09_01 = frozenset(
    {
        "dispatcher",
        "liaison",
        "pm",
        "cleaner",
        "role-manager",
        "process-improvement",
        "asvs-tracker",
    }
)

#: Retired 2026-09-10. Every observed spelling is listed in `retired` ON PURPOSE: an alias must land
#: on a live seat, so a spelling left out would resolve to "MATCHES NO SEAT" and read as a typo.
CONSOLE_SPELLINGS = frozenset({"console", "console1", "console-1", "consul"})

REQUIRED_SECTIONS = (
    "What this seat owns",
    "What it must not do",
    "Its authority",
    "On arrival",
    "The full playbook",
)

CARD_MAX_LINES = 150
CARD_MAX_BYTES = 6 * 1024


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def seats() -> dict:
    return json.loads(read(SEATS_PATH))


def _split_command(command: str | None) -> list[str]:
    """Tokenise a hook's `command` string the way a Windows shell would.

    `posix=False` is required, because a POSIX split eats the backslashes in a Windows path. It
    also KEEPS the quote characters inside each token, so `"C:/x/hook.ps1"` arrives with its
    quotes attached and `Path(token).name` then ends in one. Measured 2026-09-18: that alone made
    a `command`-field duplicate invisible to the wiring test, which is the defect this helper was
    written to close -- so the quotes come off here, once, rather than at each call site.
    """
    out = []
    for tok in shlex.split(command or "", posix=False):
        if len(tok) > 1 and tok[0] == tok[-1] and tok[0] in "\"'":
            tok = tok[1:-1]
        out.append(tok)
    return out


def session_start_args() -> list[list[str]]:
    """One token list per SessionStart hook, flattened across the setting's groups.

    TWO THINGS HAVE TO BE FLATTENED AND EACH WAS MISSED ONCE.

    The GROUPS, because a hook wired a second time in a second group is still wired twice and a
    test that inspects one group cannot see it. That is the shape the duplicate took on 2026-09-08.

    And the two FIELDS a harness hook may use. `args` is a list; `command` may instead carry the
    whole command line as one string. Measured 2026-09-18: a duplicate expressed through `command`
    left both wiring tests green, while the same duplicate expressed as `args` went red -- so an
    args-only reader guards the shape the 2026-09-08 duplicate happened to take and no other. That
    other shape is live on this machine, in the user-scope `settings.json`.

    SCOPE IS THIS FUNCTION ONLY. `.claude/settings.local.json` and the user-scope roots also carry
    SessionStart hooks, and this reader sees neither. The user-scope wrapper IS graded, further down
    this file under "the USER-SCOPE wrapper" -- by a separate reader, on a different question. Do
    not merge the two: this one asks whether the REPOSITORY wires the hook once and correctly, and
    that one asks whether N machine-local copies still agree and still warn.
    """
    wired = json.loads(read(SETTINGS))["hooks"]["SessionStart"]
    out: list[list[str]] = []
    for entry in wired:
        for h in entry.get("hooks", []):
            # `command` FIRST, then `args`: that is the invocation order, so a caller reading the
            # tokens after the script path sees the script's own arguments and not the executable.
            out.append(_split_command(h.get("command")) + list(h.get("args") or []))
    return out


def script_parameters(hook: Path) -> set[str]:
    """The parameter names the hook declares at script level.

    Only the `param(...)` block that follows `[CmdletBinding()]`. A function's own `param(...)`
    further down the file is not a script parameter and must not widen this set.

    THREE SHAPES BROKE THE FIRST VERSION OF THIS, and two of them mattered in opposite
    directions. Measured 2026-09-18:

      - A COMMENT inside the block naming a superseded spelling re-admitted it, so the wiring this
        file exists to catch went green. This repository's house style records a superseded
        spelling in place, so that comment is the likeliest edit the hook will ever get. Comments
        are stripped first.
      - An UNTYPED parameter was invisible, because the pattern demanded a leading `[type]`, so a
        legitimate `-Quiet` would be reported as undeclared. The type prefix is now optional.
      - An ATTRIBUTE between `[CmdletBinding()]` and `param` broke the match entirely and the
        assertion then failed saying the hook no longer declares its parameter, which is the
        instrument failing while blaming the subject.
    """
    # THE ATTRIBUTE RUN AND THE `param(` BODY ARE SCANNED BY BRACKET DEPTH, NOT MATCHED BY A
    # REGEX. The regex that did this wrote the attribute arm as `\[(?:[^\[\]]|\[[^\[\]]*\])*\]`
    # and starred it again inside `(?:\s*...)*`, which is the same nested-quantifier shape that
    # earned the alert below. CodeQL did NOT flag this one -- the alert named the `findall`
    # pattern, and an earlier pass here rewrote this search first on the assumption that it had.
    # The scan is kept anyway: a depth scan cannot backtrack at all, it drops the old pattern's
    # `^\)` requirement that the closing paren sit at column 0 (a formatting rule the hook was
    # never told about), and it handles an attribute nested to any depth -- `[OutputType([string])]`
    # -- rather than the one level the regex allowed.
    text = read(hook)
    head = re.search(r"\[CmdletBinding\([^)]*\)\]", text)
    if head is None:
        return set()

    def past_balanced(src: str, i: int, opener: str, closer: str) -> int | None:
        """Index just past the balanced run starting at `i`, or None if it never closes."""
        depth = 0
        while i < len(src):
            if src[i] == opener:
                depth += 1
            elif src[i] == closer:
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return None

    # Walk the optional attribute run between `[CmdletBinding()]` and `param`.
    cursor = head.end()
    while True:
        nxt = cursor
        while nxt < len(text) and text[nxt].isspace():
            nxt += 1
        if nxt >= len(text) or text[nxt] != "[":
            cursor = nxt
            break
        end = past_balanced(text, nxt, "[", "]")
        if end is None:
            return set()
        cursor = end

    if not text.startswith("param(", cursor):
        return set()
    body_start = cursor + len("param(")
    body_end = past_balanced(text, cursor + len("param"), "(", ")")
    if body_end is None:
        return set()
    body = re.sub(r"#[^\n]*", "", text[body_start : body_end - 1])
    # The `$name` capture carries no leading type or attribute arm. One used to sit in front of
    # it -- `(?:\[[\w\[\]]+\]\s*)*` -- and it was INERT, because a `*` group matches zero
    # times and every name it could skip past is found without it. It was also the ReDoS: the
    # class `[\w\[\]]` admits both brackets, so `\[[\w\[\]]+\]` starred again is ambiguous,
    # and CodeQL named the input shape exactly -- "starting with '[' and containing many
    # repetitions of '0]['". Dropping it is measured to change nothing: seven param-body shapes,
    # typed, untyped, arrayed, attributed, nested-generic and multi-declaration, return
    # identical sets from both patterns.
    return set(re.findall(r"\$(\w+)\s*(?:=|,|\)|$)", body, re.M))


#: Added by `[CmdletBinding()]`, so the wiring may legitimately pass one.
POWERSHELL_COMMON_PARAMETERS = frozenset(
    {
        "Verbose",
        "Debug",
        "ErrorAction",
        "WarningAction",
        "InformationAction",
        "ProgressAction",
        "ErrorVariable",
        "WarningVariable",
        "InformationVariable",
        "OutVariable",
        "OutBuffer",
        "PipelineVariable",
    }
)


def card_paths() -> list[Path]:
    return sorted(CARD_DIR.glob("*.card.md"))


class TheRosterIsGovernedByTheWorkingAgreement(unittest.TestCase):
    """`CLAUDE.md` section 5 governs. `seats.json` must follow it, never lead it."""

    def test_the_roster_is_the_one_the_agreement_declares(self):
        self.assertEqual(EXPECTED_SEATS, set(seats()["live"]))

    def test_every_live_seat_has_a_card(self):
        missing = sorted(s for s in EXPECTED_SEATS if not (CARD_DIR / f"{s}.card.md").is_file())
        self.assertEqual([], missing, f"live seats with no card: {missing}")

    def test_no_card_exists_for_a_seat_that_is_not_live(self):
        stray = sorted(
            p.name for p in card_paths() if p.name[: -len(".card.md")] not in EXPECTED_SEATS
        )
        self.assertEqual([], stray, f"cards for seats this repository does not run: {stray}")

    def test_the_agreement_names_every_seat_the_roster_declares(self):
        """The drift guard. The table and the roster cannot disagree silently."""
        table = read(AGREEMENT).lower()
        absent = sorted(s for s in seats()["live"] if f"**{s}**" not in table)
        self.assertEqual(
            [],
            absent,
            f"seats.json declares these but CLAUDE.md's table omits them: {absent}. "
            "The table governs, so either the table gained a seat or the roster invented one.",
        )

    def test_no_seat_is_both_live_and_filed_elsewhere(self):
        """The error this port nearly shipped: a korus seat live where the table omits it.

        Reads the SHIPPED roster, not `EXPECTED_ELSEWHERE`. That matters now the constant is empty:
        intersecting two empty sets passes while examining nothing, whereas this goes red the moment
        a future occupant is also declared live.
        """
        both = sorted(set(seats().get("elsewhere", {})) & set(seats()["live"]))
        self.assertEqual(
            [],
            both,
            f"{both} are filed as korus-only AND declared live here. A card for one would hand a "
            "session a seat the working agreement does not run.",
        )


class ASeatThatIsNotRunHereSaysSoRatherThanGoingSilent(unittest.TestCase):
    """Silence reads as a missing file. A roster difference is not a missing file.

    THE BUCKET IS EMPTY AND EMPTY IS CORRECT. Its one occupant was removed on 2026-09-16 by owner
    instruction. Every loop over it therefore passes while examining nothing -- the gate-that-
    examined-nothing shape this repository names more than any other. So the emptiness is asserted
    DIRECTLY, the two scripts are guarded by reading their source, and the verdict's own behaviour
    is exercised against an INJECTED occupant in `tests/test_coord_seat_roster_verdict.py`, which is
    the only place it can still be run.
    """

    def test_every_seat_section_5_retired_resolves_to_a_retirement(self):
        """AS A SET, because iterating the file cannot notice what the file omits.

        Measured 2026-09-18: `asvs-tracker` was in no map at all, so the 12 records carrying it
        got the "MATCHES NO SEAT" typo branch. A retired seat reading as a typo sends the reader
        looking for a spelling error instead of telling them the seat was ended.
        """
        retired = seats()["retired"]
        missing = sorted(SECTION_5_RETIRED_2026_09_01 - set(retired))
        self.assertEqual(
            [],
            missing,
            f"these seats section 5 retired resolve to nothing instead of a retirement: {missing}",
        )

    def test_no_seat_section_5_retired_is_live_or_an_alias(self):
        reachable = sorted(
            SECTION_5_RETIRED_2026_09_01 & (set(seats()["live"]) | set(seats()["aliases"]))
        )
        self.assertEqual([], reachable, f"these retired seats are still reachable: {reachable}")

    def test_the_bucket_is_empty_and_the_file_says_that_is_deliberate(self):
        """Without this, an empty bucket cannot be told from a half-finished edit."""
        self.assertEqual(EXPECTED_ELSEWHERE, set(seats().get("elsewhere", {})))
        self.assertEqual({}, seats().get("elsewhere", {}))
        blob = " ".join(seats()["_elsewhere_comment"]).lower()
        self.assertIn(
            "empty is the correct current state",
            blob,
            "the file does not say the empty bucket is deliberate, so the next reader takes it for "
            "an unfinished edit and refills it",
        )

    def test_any_future_occupant_carries_a_reason_and_no_card(self):
        """Vacuous today ON PURPOSE, and it stays: this is the arm that fires the moment someone
        refills the bucket, which is the only moment it can have anything to say."""
        for label, why in seats().get("elsewhere", {}).items():
            with self.subTest(seat=label):
                self.assertTrue(why.strip(), f"{label} is listed with no reason")
                self.assertFalse(
                    (CARD_DIR / f"{label}.card.md").exists(),
                    f"{label} has a card here, which contradicts the roster",
                )

    def test_the_declaration_script_keeps_the_branch_no_occupant_can_reach(self):
        """The mechanism must outlive its last occupant, or refilling the bucket is a silent no-op."""
        source = read(SEAT_SCRIPT)
        self.assertIn("NOT A SEAT IN THIS REPOSITORY", source)
        self.assertIn("not a typo and not a retirement", source)

    def test_the_hook_distinguishes_it_from_a_typo(self):
        source = read(HOOK)
        self.assertIn(
            "IS NOT A SEAT IN THIS REPOSITORY",
            source,
            "the hook has no branch for a seat that is live in korus and absent here, so one reads "
            "as 'MATCHES NO SEAT' -- which sounds like a misspelling rather than a roster fact.",
        )


class RetiredSeatsResolveToNothingAndSayWhy(unittest.TestCase):
    def test_no_retired_seat_is_also_live(self):
        overlap = sorted(set(seats()["retired"]) & set(seats()["live"]))
        self.assertEqual([], overlap, f"a seat is both retired and live: {overlap}")

    def test_every_retired_seat_carries_its_reason(self):
        thin = sorted(k for k, v in seats()["retired"].items() if len(v.strip()) < 20)
        self.assertEqual([], thin, f"retired seats with no usable reason: {thin}")

    def test_no_retired_seat_has_a_card(self):
        stray = sorted(k for k in seats()["retired"] if (CARD_DIR / f"{k}.card.md").exists())
        self.assertEqual([], stray, f"retired seats that still have a card: {stray}")


class TheAliasMapCollapsesDrift(unittest.TestCase):
    def test_no_canonical_seat_is_an_alias_key(self):
        bad = sorted(k for k in seats()["aliases"] if k in EXPECTED_SEATS)
        self.assertEqual([], bad, f"a canonical seat is an alias key and resolves twice: {bad}")

    def test_every_alias_lands_on_a_live_seat(self):
        bad = sorted(
            f"{k} -> {v}" for k, v in seats()["aliases"].items() if v not in EXPECTED_SEATS
        )
        self.assertEqual([], bad, f"aliases pointing at no live seat: {bad}")


class EveryCardStaysWithinItsBudget(unittest.TestCase):
    """Only one card is ever injected, so the cost is one card. The cap keeps that true.

    MEASURE THE BYTE CAP THE WAY THE CHECKOUT WILL. `core.autocrlf=true` here, so every card lands
    CRLF in a Windows working tree and one byte per line is invisible on a LF-authored draft. A card
    written at 6120 LF bytes passes the author's own reading and arrives at 6241 on checkout, over
    the cap, red on the Windows leg only. `stat().st_size` below reads the checked-out file, which
    is the question; a length taken off LF source is the adjacent one.
    """

    def test_no_card_exceeds_the_line_cap(self):
        over = [
            f"{p.name}: {len(read(p).splitlines())}"
            for p in card_paths()
            if len(read(p).splitlines()) > CARD_MAX_LINES
        ]
        self.assertEqual([], over, f"cards over {CARD_MAX_LINES} lines: {over}")

    def test_no_card_exceeds_the_byte_cap(self):
        over = [
            f"{p.name}: {p.stat().st_size}"
            for p in card_paths()
            if p.stat().st_size > CARD_MAX_BYTES
        ]
        self.assertEqual([], over, f"cards over {CARD_MAX_BYTES} bytes: {over}")

    def test_every_card_carries_every_required_section(self):
        """As a HEADING, not as a phrase anywhere in the file.

        This asserted `s not in read(p)`, a bare substring over the whole card. Measured
        2026-09-18: renaming all five headings in `steward.card.md` while appending one prose line
        that happened to carry the five phrases left the suite green. So a card could lose every
        required section as STRUCTURE and pass, and the five deletion arms only went red because
        each phrase happens to appear nowhere else in its card. `docs/ROLE-CARDS.md` calls these
        sections pinned; requiring the heading is what makes that true.
        """
        offenders = [
            f"{p.name} has no '## {s}' heading"
            for p in card_paths()
            for s in REQUIRED_SECTIONS
            if f"## {s}" not in read(p)
        ]
        self.assertEqual([], offenders, "\n  ".join(offenders))

    def test_every_card_names_the_marker_that_selected_it(self):
        silent = [p.name for p in card_paths() if MARKER_RELPATH not in read(p)]
        self.assertEqual([], silent, f"cards that do not say what selected them: {silent}")

    def test_the_card_scan_actually_reads_cards(self):
        """The empty-corpus guard. Every absence test above passes trivially against no cards."""
        self.assertEqual(len(EXPECTED_SEATS), len(card_paths()))


class NoCardContradictsAnAnchoredRuling(unittest.TestCase):
    """The second way the korus copy would have been wrong, and the most expensive.

    korus's cards read *"Pushing, opening a PR and merging need the Owner's explicit approval."*
    Section 5 here carries the opposite, anchored at `refs/liaison/owner-ruling-20260829-push`
    (`987705dfb`): *"Sessions push their own."*

    A card saying otherwise stops every seat before its push, and supplies an authoritative-sounding
    reason for stopping. Nothing would report it.
    """

    #: (pattern, why it is wrong here). Matched case-insensitively over the whole card.
    FORBIDDEN = (
        (
            re.compile(r"push(?:ing)?[^.\n]{0,80}(?:owner|explicit)[^.\n]{0,40}approval", re.I),
            "pushing needs no approval here (owner ruling 2026-08-29)",
        ),
        (
            re.compile(r"open(?:ing)? (?:a |the )?PR[^.\n]{0,60}approval", re.I),
            "opening a PR needs no approval here (owner ruling 2026-08-29)",
        ),
        # The SECOND shape, added 2026-09-18. This screen was built from the push case alone and
        # therefore found only that shape -- builder.card.md carried "Declare its own seat. Your
        # Manager does that." for the whole time this class existed. CLAUDE.md:418 records the
        # opposite and says why the old rule was worth naming: it was SELF-CONFIRMING, because a
        # Builder told it cannot declare does not try, renders undeclared, and confirms the rule.
        # The shipped shape: "**Declare its own seat.** Your Manager does that." Note it crosses a
        # sentence boundary, so the window CANNOT exclude "." the way the push patterns do -- the
        # first draft of this pattern used `[^.\n]` and stayed quiet on the very line it was
        # written for. `test_the_scan_fires_on_the_seat_declaration_line_this_card_shipped` is
        # what caught that, which is the whole reason a positive control is not optional.
        (
            re.compile(
                r"declare\b[^\n]{0,30}\bseat\b[^\n]{0,20}(?:your |the )?"
                r"(?:manager|console|owner)\s+does",
                re.I,
            ),
            "a seat declares its own seat (CLAUDE.md:418, measured 2026-09-02); the Manager "
            "supplies the seat and goal at dispatch but does not declare for it",
        ),
        (
            re.compile(r"(?:cannot|can't|must not|never)\s+declare\b[^\n]{0,30}\bseat\b", re.I),
            "a seat CAN declare itself through the Bash tool (CLAUDE.md:418, measured 2026-09-02)",
        ),
    )

    def test_no_card_says_a_push_needs_approval(self):
        offenders = []
        for p in card_paths():
            text = read(p)
            for rx, why in self.FORBIDDEN:
                if rx.search(text):
                    offenders.append(f"{p.name}: {why}")
        self.assertEqual([], offenders, "\n  ".join(offenders))

    def test_the_scan_fires_on_the_line_that_korus_ships(self):
        """The positive control. Without it, a pattern that matches nothing passes silently."""
        planted = "**Pushing, opening a PR and merging need the Owner's explicit approval.**"
        self.assertTrue(
            any(rx.search(planted) for rx, _ in self.FORBIDDEN),
            "the scan did not fire on the exact sentence korus's cards carry, so it guards nothing",
        )

    def test_the_scan_fires_on_the_seat_declaration_line_this_card_shipped(self):
        """The second positive control, for the shape this screen missed for its whole life.

        A screen built from one case finds one shape. This exact sentence sat in
        `builder.card.md` while every test in this class was green.
        """
        planted = "- **Declare its own seat.** Your Manager does that."
        self.assertTrue(
            any(rx.search(planted) for rx, _ in self.FORBIDDEN),
            "the scan did not fire on the seat-declaration line builder.card.md actually carried",
        )

    def test_the_scan_accepts_the_wording_this_repository_uses(self):
        """The negative arm. A guard that fires on the correct text is worse than none."""
        good = "**Push your own branch and open your own PR, without asking.** Owner ruling 2026-08-29."
        self.assertFalse(
            any(rx.search(good) for rx, _ in self.FORBIDDEN),
            "the scan flagged this repository's own ruling",
        )

    def test_every_card_states_the_push_authority_it_holds(self):
        """Silence on authority is how a seat falls back to the most cautious guess it knows."""
        silent = [p.name for p in card_paths() if "without asking" not in read(p)]
        self.assertEqual([], silent, f"cards that never state the push authority: {silent}")


class NoCardCitesAPlaybookPathThatDoesNotExistHere(unittest.TestCase):
    """The third way the copy would have been wrong, and the quietest.

    The playbooks moved to korus on 2026-09-02 (`a3df144`, which also added `roles/README.md`;
    the repository itself was initialised 35 minutes earlier). 2026-09-04 is the separate, later
    owner ruling that they are READ at `origin/main`, and conflating the two dates the move two
    days late. A bare `roles/BUILDER.md` resolves to nothing in this checkout, and an absent file
    is the failure that reports nothing at all.
    """

    BARE = re.compile(r"(?<![:/\w])roles/[A-Z][A-Z-]*\.md")

    def test_no_card_cites_a_bare_roles_path(self):
        offenders = []
        for p in card_paths():
            for line in read(p).splitlines():
                if "korus" in line.lower() or "origin/main:" in line:
                    continue
                for hit in self.BARE.findall(line):
                    offenders.append(f"{p.name}: {hit} -- no such path in this checkout")
        self.assertEqual([], offenders, "\n  ".join(offenders))

    def test_the_scan_fires_on_the_shape_korus_ships(self):
        self.assertTrue(
            self.BARE.findall("1. Read `roles/COMMON.md`, then `roles/BUILDER.md`."),
            "the scan did not fire on korus's own wording, so it guards nothing",
        )

    def test_the_scan_accepts_a_korus_qualified_reference(self):
        self.assertEqual(
            [],
            [
                h
                for h in self.BARE.findall("git -C <korus clone> show origin/main:roles/BUILDER.md")
                if True
            ]
            if "origin/main:" not in "git -C <korus clone> show origin/main:roles/BUILDER.md"
            else [],
            "a korus-qualified reference must not be flagged",
        )

    def test_every_card_names_where_the_playbook_actually_lives(self):
        silent = [p.name for p in card_paths() if "korus" not in read(p).lower()]
        self.assertEqual([], silent, f"cards that never say where the playbook is: {silent}")


class TheMarkerCannotRideIntoACommit(unittest.TestCase):
    """Both are machine-local. Here they are ignored by the `/.claude/*` wildcard.

    DO NOT ADD A NEGATION TO MAKE THIS PASS. `.gitignore` warns, above its one existing negation,
    that a second would expose nested checkouts carrying `.venv` and the local database.
    """

    def _ignored(self, rel: str) -> bool:
        return (
            subprocess.run(
                ["git", "check-ignore", "-q", rel], cwd=_REPO, capture_output=True
            ).returncode
            == 0
        )

    def test_the_seat_marker_is_ignored(self):
        self.assertTrue(self._ignored(MARKER_RELPATH), f"{MARKER_RELPATH} is not git-ignored")

    def test_the_injected_copy_is_ignored(self):
        self.assertTrue(self._ignored(ROLE_COPY_RELPATH), f"{ROLE_COPY_RELPATH} is not git-ignored")

    def test_the_check_can_tell_ignored_from_tracked(self):
        """The control. `check-ignore -q` returns non-zero for a tracked path."""
        self.assertFalse(
            self._ignored("CLAUDE.md"), "the ignore check calls a tracked file ignored"
        )


class TheHookIsWiredAndNeverBreaksATurn(unittest.TestCase):
    def test_the_hook_exists(self):
        self.assertTrue(HOOK.is_file(), f"{HOOK} is missing")

    def test_the_hook_is_wired_exactly_once_at_session_start(self):
        """TWICE IS NOT HARMLESS, and the test that was here could not tell one from two.

        It asserted `any(...)`, which a duplicate passes. Measured 2026-09-18: two commits had
        each added a wiring, `origin/main` carried both, and this test reported green for the 13
        days in between.

        WHAT THE DUPLICATE COST depends on whether a seat resolved. With no marker the hook prints
        its no-seat note, so 103 of the 104 wired worktrees printed that twice. Where a marker
        existed the CARD doubled: worktree `manager-112d2a` has two injection records 17 ms apart,
        5,203 characters each, so that session paid 10,406 for one card -- and the 150-line and
        6 KB caps cannot see it, because each copy is inside budget.
        """
        commands = [a for a in session_start_args() if any(Path(x).name == HOOK.name for x in a)]
        self.assertEqual(
            1,
            len(commands),
            f"{HOOK.name} is wired {len(commands)} times at SessionStart, expected once: "
            f"{[' '.join(a) for a in commands]}",
        )

    def test_the_wiring_passes_the_worktree_root_spelled_in_full(self):
        """POWERSHELL BINDS AN UNAMBIGUOUS PREFIX, so a shortened parameter works and looks right.

        Measured 2026-09-18: the wiring passed `-Worktree` and PowerShell bound it to
        `-WorktreeRoot`. The hook resolved the correct seat, so nothing reported a problem.

        TWO LATER EDITS BREAK IT, and they break it differently. Add a second `-Worktree...`
        parameter and `-Worktree` becomes AMBIGUOUS: PowerShell refuses the invocation with exit 1
        and empty stdout, the body never runs, and the card silently disappears -- the hook's
        never-fail guarantee cannot cover it, because binding precedes every `exit 0`. RENAME
        `WorktreeRoot` to another `-Worktree...` spelling instead and the prefix still binds while
        `$WorktreeRoot` falls back to `$PWD`, so the hook resolves whatever directory it happened
        to start in. Only the second produces a wrong seat; both are red here.

        ASSERTED POSITIVELY, because subtracting known names pins nothing. Measured the same day:
        dropping the `-WorktreeRoot` token and leaving the value as a bare trailing argument passed
        the subtract-only version, and a positional value binds by declaration order the moment a
        second parameter exists -- which is the very failure above.
        """
        declared = script_parameters(HOOK) | POWERSHELL_COMMON_PARAMETERS
        self.assertIn(
            "WorktreeRoot",
            declared,
            "could not find a script-level -WorktreeRoot declaration in the hook. Either the hook "
            "no longer declares it, or script_parameters() cannot read the shape it is written in.",
        )

        seen = 0
        for args in session_start_args():
            at = [i for i, a in enumerate(args) if Path(a).name == HOOK.name]
            if not at:
                continue
            seen += 1
            tail = args[at[0] + 1 :]
            self.assertEqual(
                ["-WorktreeRoot", "${CLAUDE_PROJECT_DIR}"],
                tail,
                "the wiring must pass -WorktreeRoot, spelled in full, and the project directory, "
                f"and nothing else. It passes: {tail}",
            )
        self.assertEqual(1, seen, f"expected one {HOOK.name} wiring to inspect, found {seen}")

    def test_the_hook_keeps_the_existing_session_start_hook(self):
        """Adding a hook must not replace the one that was there."""
        commands = [" ".join(a) for a in session_start_args()]
        self.assertTrue(
            any("seat-declare-prompt.ps1" in c for c in commands),
            "the seat declaration prompt was dropped when the role card hook was added",
        )

    def test_every_exit_in_the_hook_is_zero(self):
        """A hook that can fail a turn is a worse fault than an undeclared seat."""
        bad = [ln.strip() for ln in read(HOOK).splitlines() if re.match(r"^\s*exit\s+(?!0\b)", ln)]
        self.assertEqual([], bad, f"non-zero exits in the hook: {bad}")


class TheHookNeverGuessesASeat(unittest.TestCase):
    """A worktree name is a creation-time label nothing keeps current.

    A card is injected at the weight of the working agreement, so a WRONG card outranks the document
    the session should have been reading. Silence costs one printed line.

    THIS CLASS READS ONE PATH, AND THAT IS NOT THE WHOLE RULE. `NoHookGuessesASeatFromAName` below
    carries it across every hook in the directory, which is the scope an untracked `builder-nudge.ps1`
    broke for a month without anything going red.
    """

    def test_the_hook_reads_no_branch_or_directory_name(self):
        source = read(HOOK)
        for probe in ("rev-parse", "--abbrev-ref", "git branch", "Split-Path -Leaf $WorktreeRoot"):
            with self.subTest(probe=probe):
                self.assertNotIn(probe, source, f"the hook reads {probe!r} and could guess a seat")

    def test_the_hook_resolves_only_the_marker_and_the_variable(self):
        source = read(HOOK)
        self.assertIn(MARKER_RELPATH, source)
        self.assertIn("KORUS_SEAT", source)


# ------------------------------------------------- the same rule, over every hook rather than one

HOOKS_DIR = _REPO / "scripts" / "hooks"

#: The extensions a hook is written in here. Three languages, and the scan below handles all three
#: because the defect it was written against could have been written in any of them.
HOOK_SUFFIXES = (".ps1", ".py", ".sh")

#: Ways a script can learn a NAME instead of reading a declaration. AT LEAST these -- the list is
#: the shapes measured in this directory on 2026-09-20, not a proof that no other shape exists.
#: `(Get-Item $PWD).Name`, `$PWD.Path.Split('\')[-1]` and `%CD%` are all unmodelled.
NAME_SOURCES = re.compile(
    r"Split-Path[^\n]*?-Leaf"
    r"|-Leaf[^\n]*?Split-Path"
    r"|--abbrev-ref"
    r"|--show-toplevel"
    r"|symbolic-ref"
    r"|basename"
    r"|GetFileName",
    re.I,
)

#: An assignment in any of the three languages: `$x = ...`, `x = ...`, `x: str = ...`,
#: `export X=...`. Scanned with `finditer` rather than matched at the start of the line, so an
#: assignment nested inside an `if` body on one line is still tracked. The `[^=]` tail keeps `==`
#: out. A derivation that never lands in a named variable -- passed straight to a function, or
#: built in a pipeline -- is still a miss, and so is one handed to a dot-sourced library.
#:
#: THE LOOKBEHIND REJECTS A LEADING HYPHEN, and without it `--path-format=absolute` reads as an
#: assignment to a variable called `format`. Measured 2026-09-20: five hooks then carried a phantom
#: `format`, and any later line mentioning that common word would have been graded against the seat
#: labels.
_ASSIGNMENT = re.compile(r"(?<![-\w])\$?([A-Za-z_][\w:]*)\s*(?::\s*[^=\n]+?)?\s*=[^=]")

_POWERSHELL_BLOCK_COMMENT = re.compile(r"<#.*?#>", re.S)

# `.*?` UNDER `re.S`, NEVER `(?:.|\n)*?`. The alternation is the ReDoS shape CodeQL already named
# once in this file: with DOTALL both branches match a newline, so every position has two ways to
# match and a lazy run that never finds its terminator backtracks exponentially. Measured
# 2026-09-20 while arming this scan -- `scripts/coord/claim.ps1` carries a PowerShell escaped-quote
# run that reads as an unterminated `"""`, and the ambiguous pattern hung for over three minutes on
# one file before it was killed. The safe form scans each start position once.
_PYTHON_TRIPLE_QUOTE = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.S)

#: The hook this rule was written against, reconstructed from the two lines that mattered, and the
#: positive control for the scan below. `NoHookGuessesASeatFromAName` carries the incident.
BUILDER_NUDGE_SOURCE = (
    "$seat = Split-Path (git rev-parse --show-toplevel) -Leaf\n"
    "if ($seat -notmatch '(?i)builder') { exit 0 }\n"
)

#: Hooks that DO pair a name read with a seat label today. The ratchet: the scan's result must equal
#: this map exactly, so a new violator goes red and so does a stale entry left behind after a fix.
#: Each entry states the defect, because a bare name here is an allow-list nobody can review.
KNOWN_NAME_DERIVED_SEAT_HOOKS: dict[str, str] = {
    "lane-level.ps1": (
        "Lines 183-186 and 205 take the worktree leaf and the branch name and match them against "
        "'builder' and 'dispatcher' to decide which role THIS session holds. The same file states "
        "the opposite rule 45 lines further down and applies it correctly to every OTHER lane it "
        "discovers: 'MATCH ON THE DECLARED SEAT ONLY, NEVER ON THE WORKTREE NAME', measured "
        "2026-08-23 when a Cleaner sat in a worktree named builder-handoff-seat. Two further facts "
        "for whoever repairs it: 'dispatcher' was retired on 2026-09-01, so that arm matches no "
        "seat the roster runs; and the installed Stop wrapper prefers the VAULT copy of this "
        "script over the engine copy, which no test here can read. NOT REPAIRED IN THE CHANGE THAT "
        "ADDED THIS GUARD, on purpose: fixing a hook and widening its guard together means nothing "
        "independent checked either."
    ),
}


def hook_files() -> list[Path]:
    """EVERY file in the hooks directory whatever its extension, tracked or not, sorted by name.

    THE WORKING TREE IS THE SUBJECT, and that is deliberate: `builder-nudge.ps1` was never
    committed, so a reader built on `git ls-files` would have returned a clean result for the whole
    month it ran. The cost is that CI, which checks out only tracked files, cannot see an untracked
    hook either -- so the untracked arm below only ever grades a developer box, the way the
    user-scope wrapper test at the foot of this file does.

    UNFILTERED, because the provenance question does not care what language a hook is written in
    and a suffix filter would hide a `.cmd` or `.psm1` one from it entirely.
    """
    return sorted((p for p in HOOKS_DIR.iterdir() if p.is_file()), key=lambda p: p.name)


def hook_scripts() -> list[Path]:
    """The hook files the content scan can read. A file of any other type is a finding, not a skip.

    Kept apart from `hook_files` so an unreadable type -- an image, an archive -- errors in the
    suffix assertion with a clear message instead of a decode failure mid-scan.
    """
    return [p for p in hook_files() if p.suffix in HOOK_SUFFIXES]


def seat_labels() -> list[str]:
    """Every label that names a seat: live, alias, retired. Two characters or fewer are dropped.

    DRIVEN BY THE ROSTER rather than hand-listed, so a seat added tomorrow is covered without an
    edit here. RETIRED LABELS ARE IN because guessing a retired seat from a name is the same defect
    with a worse outcome -- the session acts on rules no seat holds. The length floor drops `pm`,
    which is too short to distinguish a seat from a variable.
    """
    roster = seats()
    every = set(roster["live"]) | set(roster["aliases"]) | set(roster["retired"])
    return sorted(label for label in every if len(label) >= 3)


def _code_lines(text: str, suffix: str = "") -> list[str]:
    """Source with comments and docstrings blanked, one entry per original line.

    Blanked rather than removed so a reported line number still points at the file. This has to
    happen: `lane-level.ps1` explains the very rule it breaks, in prose, naming both 'builder' and
    the worktree name in one paragraph, and a scan that reads comments reports the explanation.

    THE TRIPLE-QUOTE STRIP IS SCOPED TO PYTHON, and the reason is the same claim.ps1 line that
    exposed the ReDoS above. PowerShell escapes a quote by doubling it, so an escaped quote at the
    very end of a double-quoted string puts three quote characters in a row and that is not a
    triple quote. Run the Python strip over PowerShell and two such runs in one file blank
    everything between them -- hiding a real violation, quietly, in the language every hook here is
    written in. This paragraph is why the sentence above spells the shape out in words rather than
    showing it: written literally, it would end this docstring.
    """
    blanked = _POWERSHELL_BLOCK_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    if suffix == ".py":
        blanked = _PYTHON_TRIPLE_QUOTE.sub(lambda m: "\n" * m.group(0).count("\n"), blanked)
    return ["" if ln.lstrip().startswith("#") else ln for ln in blanked.splitlines()]


@cache
def _label_pattern(labels: tuple[str, ...]) -> re.Pattern[str]:
    """One compiled alternation over every seat label, built once per label set.

    THE ONLY BOUNDARY IS A WORD CHARACTER, deliberately, and a hyphen is not one. Worktree names
    here are hyphenated, so `'^mefor-builder'` is the likeliest spelling of the defect this scan
    hunts; a lookbehind that excluded a leading hyphen would read that line as clean.
    """
    return re.compile(r"(?<!\w)(" + "|".join(re.escape(x) for x in labels) + r")(?!\w)", re.I)


def name_derived_seat_hits(
    text: str, labels: list[str] | None = None, suffix: str = ""
) -> list[str]:
    """Lines where a value read from a NAME is tested against a SEAT LABEL. Empty means clean.

    TWO STEPS, because neither half is a finding alone. A hook may read `--show-toplevel` all day
    to resolve a path -- `worktree_gate.ps1` does it eight times -- and a hook may name a seat all
    day in the text it prints. The defect is the JOIN: a variable assigned from a name source, then
    compared against a seat label.

    WHAT IT CANNOT SEE, stated because a scan that implies completeness is worse than one that does
    not. It follows a variable NAME within one file, so a derivation handed to a function or a
    dot-sourced library escapes it. It models the name sources listed in `NAME_SOURCES` and no
    others. And it reads text, so a label built at runtime is invisible.
    """
    labels = labels if labels is not None else seat_labels()
    lines = _code_lines(text, suffix)

    tracked: set[str] = set()
    for line in lines:
        for m in _ASSIGNMENT.finditer(line):
            if NAME_SOURCES.search(line[m.end(1) :]):
                tracked.add(m.group(1))
    if not tracked:
        return []

    label_rx = _label_pattern(tuple(labels))
    # `\bNAME\b` catches `$leaf` in PowerShell, `$SEAT` in sh and a bare `seat` in Python with one
    # pattern, because `$` is not a word character. CASE-INSENSITIVE, because PowerShell variable
    # names are: `$Leaf = Split-Path ... -Leaf` and `if ($leaf -match ...)` are one variable, and a
    # case-sensitive reader calls that file clean.
    used_rx = {name: re.compile(r"\b" + re.escape(name) + r"\b", re.I) for name in tracked}

    hits = []
    for number, line in enumerate(lines, start=1):
        if not any(rx.search(line) for rx in used_rx.values()):
            continue
        found = sorted({x.lower() for x in label_rx.findall(line)})
        if found:
            hits.append(f"line {number} tests a name against {found}: {line.strip()[:120]}")
    return hits


class NoHookGuessesASeatFromAName(unittest.TestCase):
    """`TheHookNeverGuessesASeat` above pins ONE path. This pins the directory.

    WHAT THE NARROW SCOPE COST. An untracked Stop hook, `scripts/hooks/builder-nudge.ps1`, took the
    worktree basename and matched it against 'builder' to decide whether to nag. It broke the rule
    the class above exists to enforce, for about a month, and nothing reported it -- because that
    class reads `role-card-inject.ps1` and nothing else. A guard scoped to one file grades one file.

    BOTH CLASSES STAY. They ask different questions. The one above asks whether the reference
    implementation still resolves a seat the one correct way, by the marker and the variable; it can
    demand the total ABSENCE of a probe because that hook needs none. This one cannot: most hooks
    here legitimately call `rev-parse` for a path, so it asks the narrower question of whether a
    name ever reaches a seat comparison.
    """

    def test_no_hook_tests_a_name_against_a_seat_label(self):
        labels = seat_labels()
        found = {
            p.name: hits
            for p in hook_scripts()
            if (hits := name_derived_seat_hits(read(p), labels, p.suffix))
        }
        self.assertEqual(
            sorted(KNOWN_NAME_DERIVED_SEAT_HOOKS),
            sorted(found),
            "the set of hooks that derive a seat from a name has changed.\n"
            + "\n".join(f"  {name}: {'; '.join(h)}" for name, h in sorted(found.items()))
            + "\nA NEW name is a new defect: resolve the seat from .claude/seat.local.txt the way "
            "role-card-inject.ps1 does. A name that DISAPPEARED means the hook was repaired, so "
            "delete its row from KNOWN_NAME_DERIVED_SEAT_HOOKS -- a stale row is an allow-list "
            "entry that would let the same file re-offend in silence.",
        )

    def test_every_known_violator_still_exists_and_carries_a_reason(self):
        """A row for a deleted file would sit here forever, unreachable and unfalsifiable."""
        present = {p.name for p in hook_scripts()}
        for name, why in KNOWN_NAME_DERIVED_SEAT_HOOKS.items():
            with self.subTest(hook=name):
                self.assertIn(name, present, f"{name} is listed as a violator and does not exist")
                self.assertGreater(len(why.strip()), 80, f"{name} is listed with no usable reason")

    def test_the_scan_grades_the_files_it_claims_to(self):
        """The empty-corpus control. Every assertion above passes against a broken glob."""
        names = [p.name for p in hook_scripts()]
        self.assertGreaterEqual(
            len(names), 15, f"only {len(names)} hook scripts discovered: {names}"
        )
        for expected in ("role-card-inject.ps1", "lane-level.ps1", "push_guard.py"):
            self.assertIn(expected, names, f"the scan cannot see {expected}, so it grades a subset")

    def test_no_hook_is_written_in_a_language_the_scan_cannot_read(self):
        """A fourth language arriving must be a decision, not a silent exemption.

        `hook_scripts` filters by suffix, so a `.cmd` or `.psm1` hook would be skipped by every
        content check above while looking like it had passed them.
        """
        unreadable = sorted(p.name for p in hook_files() if p.suffix not in HOOK_SUFFIXES)
        self.assertEqual(
            [],
            unreadable,
            f"files in scripts/hooks the scan does not read: {unreadable}. Either these are not "
            f"hooks and belong elsewhere, or HOOK_SUFFIXES needs the new language and "
            "name_derived_seat_hits needs a control proving it reads that language.",
        )

    def test_the_scan_fires_on_the_hook_this_guard_was_written_against(self):
        """The positive control. A scan that matches nothing is indistinguishable from a clean tree."""
        self.assertTrue(
            name_derived_seat_hits(BUILDER_NUDGE_SOURCE, suffix=".ps1"),
            "the scan did not fire on builder-nudge.ps1's own two lines, so it guards nothing",
        )

    def test_the_scan_fires_on_the_same_shape_in_python_and_in_shell(self):
        """Hooks here are written in three languages, so one working control proves one third."""
        python = 'seat = os.path.basename(toplevel)\nif seat.startswith("builder"):\n    pass\n'
        shell = 'SEAT=$(basename "$(git rev-parse --show-toplevel)")\ncase "$SEAT" in builder*) ;; esac\n'
        self.assertTrue(
            name_derived_seat_hits(python, suffix=".py"), "the scan is blind to the Python shape"
        )
        self.assertTrue(
            name_derived_seat_hits(shell, suffix=".sh"), "the scan is blind to the shell shape"
        )

    def test_the_scan_fires_on_a_hyphenated_name_and_on_a_recased_variable(self):
        """Two shapes a first draft of this scan missed, and both are the likely spelling here.

        HYPHEN. Worktree names in this repository are hyphenated, so a hook matching `'^mefor-
        builder'` is more probable than one matching a bare `'builder'`. A lookbehind that excluded
        a leading hyphen read that line as clean.

        CASE. PowerShell variable names are case-insensitive, so `$Leaf` and `$leaf` are one
        variable and a case-sensitive reader loses the link between the assignment and the test.
        """
        hyphenated = (
            "$leaf = Split-Path $PWD -Leaf\nif ($leaf -match '^mefor-builder') { exit 0 }\n"
        )
        recased = "$Leaf = Split-Path $PWD -Leaf\nif ($leaf -match 'builder') { exit 0 }\n"
        self.assertTrue(
            name_derived_seat_hits(hyphenated, suffix=".ps1"),
            "a seat label behind a hyphen is invisible to the scan",
        )
        self.assertTrue(
            name_derived_seat_hits(recased, suffix=".ps1"),
            "the scan loses a PowerShell variable to a change of case",
        )

    def test_the_scan_does_not_invent_a_variable_out_of_a_command_flag(self):
        """`--path-format=absolute` reads as an assignment to `format` unless the scan says no.

        A phantom variable named after a common word grades every later line mentioning that word
        against the seat labels, which is how a scan like this starts reporting noise and gets
        switched off. Measured 2026-09-20: five hooks carried this one before the fix.
        """
        flag_only = (
            "$top = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)\n"
            "Write-Output 'format: the builder report'\n"
        )
        self.assertEqual([], name_derived_seat_hits(flag_only, suffix=".ps1"))

    def test_the_python_docstring_strip_does_not_run_over_powershell(self):
        """The regression arm for the ReDoS repair, and it guards the OTHER half of that fix.

        PowerShell escapes a quote by doubling it, so a string ending in an escaped quote puts
        three quote characters in a row without being a triple quote -- `scripts/coord/claim.ps1`
        carries exactly that. Two such runs in one file would blank everything between them if the
        Python strip ran over PowerShell, and a violation sitting in that gap would never be
        reported. `planted` below holds the shape; it is built rather than shown for the reason
        `_code_lines` states.
        """
        planted = (
            '$first = "say ""hi"""\n'
            "$leaf = Split-Path $PWD -Leaf\n"
            '$second = "say ""bye"""\n'
            "if ($leaf -match 'builder') { exit 0 }\n"
        )
        self.assertTrue(
            name_derived_seat_hits(planted, suffix=".ps1"),
            "the scan lost a PowerShell violation between two doubled-quote runs",
        )
        # The other half of the control: this input IS swallowed when the Python strip runs, so the
        # arm above is measuring the scoping rather than passing for an unrelated reason.
        self.assertEqual(
            [],
            name_derived_seat_hits(planted, suffix=".py"),
            "the planted source survives the Python strip, so the arm above proves nothing",
        )

    def test_the_scan_accepts_a_hook_that_reads_the_marker_at_a_resolved_path(self):
        """The negative arm, and it is the whole discriminator.

        Resolving the worktree PATH with `rev-parse` and reading the declaration out of it is the
        correct shape. Taking that path's LEAF is the defect. A guard that cannot tell them apart
        would red every hook here and be switched off within a week.
        """
        correct = (
            "$top = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)\n"
            "$seat = (Get-Content (Join-Path $top '.claude/seat.local.txt') -Raw).Trim()\n"
            "if ($seat -eq 'builder') { Write-Output 'hello' }\n"
        )
        self.assertEqual(
            [],
            name_derived_seat_hits(correct, suffix=".ps1"),
            "the scan flagged the shape role-card-inject.ps1 uses, so it forbids the fix",
        )

    def test_the_reference_implementation_is_clean_under_this_scan_too(self):
        self.assertEqual([], name_derived_seat_hits(read(HOOK), suffix=HOOK.suffix))

    def test_the_label_set_covers_live_and_retired_seats(self):
        """Control for `seat_labels()`: an empty or live-only set makes the scan quietly weaker."""
        labels = set(seat_labels())
        self.assertLessEqual(set(EXPECTED_SEATS), labels, "a live seat is missing from the labels")
        self.assertIn("dispatcher", labels, "retired seats dropped out of the label set")
        self.assertNotIn("pm", labels, "a two-character label is too short to be a seat name here")


class EveryHookScriptIsTracked(unittest.TestCase):
    """An untracked script in this directory runs in real sessions and is reviewed by nobody.

    `builder-nudge.ps1`, the hook the class above records, was exactly that. This one asks about
    PROVENANCE rather than content, which is the half a pattern match cannot cover: it fires on a
    new hook whatever the hook is written in and whatever it does.

    IT ONLY EVER GRADES A DEVELOPER BOX, for the reason `hook_files` gives. The control below is
    what keeps the emptiness meaningful where the arm is not vacuous.
    """

    def _tracked(self) -> set[str]:
        # `-z` because `git ls-files` otherwise QUOTES and octal-escapes any path outside ASCII,
        # and a quoted name never equals the name on disk -- a tracked file would read as untracked.
        out = subprocess.run(
            ["git", "ls-files", "-z", "--", "scripts/hooks"],
            cwd=_REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        return {path.rsplit("/", 1)[-1] for path in out.stdout.split("\0") if path.strip()}

    def test_the_tracked_read_returns_something(self):
        """The control. An empty read makes the assertion below pass by examining nothing."""
        tracked = self._tracked()
        self.assertIn(
            "role-card-inject.ps1", tracked, f"git ls-files returned {len(tracked)} paths"
        )

    def test_no_hook_script_is_untracked(self):
        untracked = sorted({p.name for p in hook_files()} - self._tracked())
        self.assertEqual(
            [],
            untracked,
            f"hook scripts in scripts/hooks that git does not track: {untracked}. One of these "
            "runs in every session on this machine and has been through no review. Commit it, or "
            "delete it and unwire it.",
        )


class TheConsoleRetirementSaysTheManagerIsNotARenameOfIt(unittest.TestCase):
    """BACKLOG #1529. The measured error: a Manager read a Console pointer as "substitute the Console".

    `seats.json` used to say of the Manager label: *"A korus seat, not one here. CLAUDE.md section 5
    runs the Console instead."* That sentence is true about which CARD resolves and says nothing
    about which SEAT you hold, and a Manager session read it as an instruction to act as a Console.
    It then looked for a spawn grant it does not need and an enqueue authority it does not have.

    So the retirement notice must do more than retire the label. It must say the replacement is NOT
    a rename, because the substitution is the failure and a bare "retired" invites it.
    """

    def test_every_console_spelling_resolves_to_a_retirement(self):
        retired = seats()["retired"]
        missing = sorted(CONSOLE_SPELLINGS - set(retired))
        self.assertEqual(
            [],
            missing,
            f"these Console spellings resolve to nothing instead of a retirement: {missing}. "
            "A label that matches no seat reads as a misspelling, not as a roster fact.",
        )

    def test_no_console_spelling_is_live_or_an_alias(self):
        live_or_alias = sorted(CONSOLE_SPELLINGS & (set(seats()["live"]) | set(seats()["aliases"])))
        self.assertEqual([], live_or_alias, f"the Console is still reachable as: {live_or_alias}")

    def test_the_canonical_notice_names_the_manager_and_denies_the_rename(self):
        why = seats()["retired"]["console"]
        self.assertIn("MANAGER", why, "the notice does not say which seat replaces it")
        self.assertRegex(
            why.lower(),
            r"not a renamed console",
            "the notice retires the label without denying the rename, which is the whole defect: "
            "a reader who learns only that the Console is gone substitutes the Manager for it",
        )

    def test_the_notice_names_at_least_one_concrete_difference(self):
        """A denial with no difference beside it is a slogan. Name what would actually mislead."""
        why = seats()["retired"]["console"].lower()
        present = [k for k in ("subagent", "spawn grant", "enqueue") if k in why]
        self.assertTrue(
            present,
            "the notice denies the rename but names no difference, so a reader has nothing to "
            "act on. Name the workers, the spawn grant, or the enqueue authority.",
        )

    def test_the_agreement_retires_the_console_rather_than_going_quiet(self):
        """Deleting every mention would leave the stale documents unanswered and nothing to cite."""
        text = read(AGREEMENT)
        self.assertIn(
            "There is no Console seat",
            text,
            "CLAUDE.md no longer states the retirement, so a document that routes work through a "
            "Console has nothing contradicting it",
        )
        self.assertIn(
            "NOT a renamed Console",
            text,
            "the agreement retires the seat without denying the rename",
        )

    def test_the_manager_card_denies_the_rename_too(self):
        """The card outranks the agreement in a session's context, so the warning must be on it."""
        card = read(CARD_DIR / "manager.card.md")
        self.assertIn("not a renamed Console", card)

    def test_the_scan_would_fire_on_the_wording_that_caused_this(self):
        """Positive control. Without it, every assertion above passes against a rewritten notice."""
        planted = "A korus seat, not one here. CLAUDE.md section 5 runs the Console instead."
        self.assertNotRegex(
            planted.lower(),
            r"not a renamed console",
            "the check cannot tell the misleading sentence from a compliant one, so it guards "
            "nothing",
        )


class TheRegulatorRetirementDeniesTheWatchdogSucceededIt(unittest.TestCase):
    """Owner instruction 2026-09-19. The Watchdog arrived the same day, which is the whole risk.

    The Console's retirement needed a rename denial because a Manager arrived to be mistaken for
    it. This one needs the SAME denial for a sharper reason: nothing replaced the Regulator at all,
    so a reader who substitutes the Watchdog does not merely apply the wrong rules -- they wait for
    a verdict that no seat now issues, and nothing times that wait out.

    Without this class the notice is unguarded. Every other assertion in this file passes against a
    notice trimmed to a bare "Retired 2026-09-19": the label is not live, it has no card, and the
    reason clears the 20-character floor. The denial would vanish with nothing going red.
    """

    #: Every spelling of the seat that must resolve to a retirement rather than to silence.
    SPELLINGS = frozenset({"regulator", "regulator1", "regulator-1", "reg"})

    def test_every_regulator_spelling_resolves_to_a_retirement(self):
        missing = sorted(self.SPELLINGS - set(seats()["retired"]))
        self.assertEqual(
            [],
            missing,
            f"these Regulator spellings resolve to nothing instead of a retirement: {missing}. "
            "A label that matches no seat reads as a misspelling, not as a roster fact.",
        )

    def test_no_regulator_spelling_is_live_or_an_alias(self):
        reachable = sorted(self.SPELLINGS & (set(seats()["live"]) | set(seats()["aliases"])))
        self.assertEqual([], reachable, f"the Regulator is still reachable as: {reachable}")

    def test_the_canonical_notice_says_nothing_replaced_it(self):
        why = seats()["retired"]["regulator"].lower()
        self.assertIn(
            "nothing replaced it",
            why,
            "the notice retires the label without saying the seat was not replaced, so a reader "
            "goes looking for the successor",
        )

    def test_the_notice_denies_the_watchdog_succeeded_it_by_name(self):
        why = seats()["retired"]["regulator"].lower()
        self.assertIn("watchdog", why, "the notice never names the seat it will be confused with")
        self.assertRegex(
            why,
            r"not its successor",
            "the notice names the Watchdog without denying the succession, which is worse than "
            "not naming it: it reads as a handover note",
        )

    def test_the_notice_says_what_a_watchdog_returns_instead(self):
        """A denial with no replacement behaviour beside it leaves the reader still waiting."""
        why = seats()["retired"]["regulator"].lower()
        self.assertIn(
            "verdict",
            why,
            "the notice denies the succession but never says a Watchdog issues no verdict, so a "
            "session can still send it a red and wait",
        )

    def test_the_watchdog_is_live_and_carries_its_own_card(self):
        self.assertIn("watchdog", seats()["live"])
        self.assertTrue((CARD_DIR / "watchdog.card.md").is_file())

    def test_the_agreement_retires_the_regulator_rather_than_going_quiet(self):
        """Deleting every mention would leave the stale documents unanswered and nothing to cite.

        Matched over whitespace-collapsed text. A prose file rewraps whenever a word changes
        length, so an assertion carrying a newline pins the wrap column rather than the sentence
        and goes red on a reflow that changed nothing.
        """
        flat = " ".join(read(AGREEMENT).split())
        self.assertIn(
            "NO SEAT ATTRIBUTES A RED NOW",
            flat,
            "CLAUDE.md no longer states that nobody attributes a red, so a document routing a red "
            "to a Regulator has nothing contradicting it",
        )
        self.assertIn(
            "**not the Regulator's successor**",
            flat,
            "the agreement retires the seat without denying the Watchdog succeeded it",
        )

    def test_the_whitespace_collapse_can_still_fail(self):
        """Control for the test above: collapsing must not make every string match."""
        flat = " ".join(read(AGREEMENT).split())
        self.assertNotIn("ZZQX NO SUCH SENTENCE", flat)

    def test_no_card_sends_a_red_somewhere_for_a_ruling(self):
        """The card outranks the agreement in a session's context, so the cards must agree too.

        manager.card.md carried "the ruling on a red" in its not-owned list, which was true under
        the old roster and implies a ruler under this one.
        """
        offenders = [
            p.name
            for p in card_paths()
            if re.search(r"the ruling on a red\.", read(p))
            and "nothing replaced it" not in read(p).lower()
        ]
        self.assertEqual(
            [],
            offenders,
            f"these cards name a ruling on a red without saying nobody issues one: {offenders}",
        )

    def test_the_scan_would_fire_on_the_wording_that_caused_this(self):
        """Positive control. Without it every assertion above passes against a rewritten notice."""
        planted = "Retired 2026-09-19 by owner decision."
        self.assertNotRegex(
            planted.lower(),
            r"not its successor",
            "the check cannot tell a bare retirement from one that denies the succession, so it "
            "guards nothing",
        )


if __name__ == "__main__":
    unittest.main()


# ================================================================ the USER-SCOPE wrapper
#
# `session_start_args()` above says, correctly, that its scope is this repository's own
# `.claude/settings.json` and that nothing there can see the user-scope roots. This section is the
# other half. It reads those roots directly.
#
# WHAT IT GUARDS, AND WHY THAT IS NOT THE SAME QUESTION. The project wiring names a path inside the
# worktree, so a stale worktree simply has no file to run. The USER-SCOPE wrapper is different: it
# tries the worktree, falls back to the parent of `--git-common-dir` (the primary checkout), and
# until 2026-09-20 it `exit 0`-ed in silence when neither had the hook. That silence is how the
# whole defect went unnoticed for two weeks -- 13 of 171 worktrees on the development box resolved
# nothing and said nothing. The wrapper now prints one line in that case, in the shape
# `mefor-announce` beside it already used.
#
# THE WRAPPER HAS NO COMMITTED SOURCE. It exists only as N copies, one per config root, with no
# installer and no parity check -- which is precisely the installed-copy drift this suite keeps
# meeting. Nothing here can say which copy is authoritative, so it does not try: it asserts they
# AGREE WITH EACH OTHER and that each still carries the warning branch. A hand-edit to one root
# fails; an identical edit to all of them does not, and that limit is stated rather than papered
# over.


USER_SCOPE_MARKER = "korus-role-card"
#: The branch whose absence is the silent failure. Matched on the emitted text, not on the code
#: around it, so reformatting the wrapper does not red this while a deleted warning would.
WARNING_SUBSTRING = "is absent from this worktree"


def user_scope_role_card_wrappers() -> list[tuple[Path, str]]:
    """Every user-scope `settings.json` carrying the role-card wrapper, with its command text.

    Reads `Path.home().glob(".claude*")` the way `test_selfheal_installed_parity.py` does -- the
    box runs several config roots and a session uses exactly one, so any of them can be the one
    that matters and none of them is discoverable from the repository.
    """
    out: list[tuple[Path, str]] = []
    for d in sorted(Path.home().glob(".claude*")):
        if not d.is_dir():
            continue
        f = d / "settings.json"
        if not f.is_file():
            continue
        try:
            cfg = json.loads(f.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, OSError):
            continue  # a root this test cannot parse is not a finding about role cards
        for groups in cfg.get("hooks", {}).values():
            for group in groups:
                for hook in group.get("hooks", []):
                    command = str(hook.get("command", ""))
                    if USER_SCOPE_MARKER in command:
                        out.append((f, command))
    return out


def wrapper_disagreements(wrappers: list[tuple[Path, str]]) -> list[str]:
    """Findings over a set of wrapper copies. Empty list means they agree and each warns.

    PURE, so the failing paths can be driven without touching a real config root. Every arm below
    that matters is unreachable on a healthy box, which is the state in which a guard is least
    likely to be correct and least likely to be noticed.
    """
    if not wrappers:
        return []
    findings = []
    bodies = {command for _, command in wrappers}
    if len(bodies) > 1:
        findings.append(
            f"{len(bodies)} DIFFERENT wrapper bodies across {len(wrappers)} config root(s): "
            + ", ".join(sorted(str(p) for p, _ in wrappers))
        )
    missing = sorted(str(p) for p, command in wrappers if WARNING_SUBSTRING not in command)
    if missing:
        findings.append(
            "the no-hit warning branch is GONE from: "
            + ", ".join(missing)
            + " -- these roots go back to exiting 0 in silence when neither the worktree nor the "
            "primary has role-card-inject.ps1, which is the failure that hid this for two weeks"
        )
    return findings


def test_the_user_scope_wrappers_agree_and_still_warn() -> None:
    wrappers = user_scope_role_card_wrappers()
    if not wrappers:
        pytest.skip(
            "SKIP (nothing compared): no user-scope settings.json on this machine carries the "
            f"{USER_SCOPE_MARKER!r} wrapper. Expected on CI, which has no config roots -- so this "
            "arm is honest there and only ever grades a developer box."
        )
    print(f"compared {len(wrappers)} user-scope wrapper(s): {[str(p) for p, _ in wrappers]}")
    findings = wrapper_disagreements(wrappers)
    assert not findings, "\n".join("  * " + f for f in findings)


@pytest.mark.parametrize(
    ("bodies", "expect"),
    [
        ([], 0),  # nothing installed -- not a finding, the caller skips
        (["A warns: is absent from this worktree"], 0),
        (["A warns: is absent from this worktree"] * 6, 0),
        (["A warns: is absent from this worktree", "B differs: is absent from this worktree"], 1),
        (["silent wrapper with no warning"], 1),
        (["silent one", "another silent one"], 2),  # both disagreement AND missing warning
    ],
)
def test_the_wrapper_probe_reports_each_failure_shape(bodies: list[str], expect: int) -> None:
    """Exhaustive over the decision, because five of these six cannot occur on a healthy box."""
    made = [(Path(f"root{i}/settings.json"), b) for i, b in enumerate(bodies)]
    assert len(wrapper_disagreements(made)) == expect, wrapper_disagreements(made)
