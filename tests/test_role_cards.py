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
     SPECIAL seat joined on 2026-09-16, taking the table to six. The `elsewhere` bucket emptied
     the same day by owner instruction, so the tests below guard its MECHANISM rather than an
     occupant.
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
from pathlib import Path

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

#: Section 5's table governs. SIX seats since 2026-09-16, when the owner added SPECIAL.
EXPECTED_SEATS = frozenset({"manager", "builder", "regulator", "steward", "lander", "special"})

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

    SCOPE IS THIS FILE ONLY. `.claude/settings.local.json` and the user-scope roots also carry
    SessionStart hooks, and nothing here can see them.
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
    # An attribute may itself contain brackets -- `[OutputType([string])]` -- so the attribute
    # arm allows one level of nesting. A flat `[^\]]+` stops at the inner `]` and the whole match
    # fails, which is the third shape in the docstring.
    attribute = r"\[(?:[^\[\]]|\[[^\[\]]*\])*\]"
    block = re.search(
        r"\[CmdletBinding\([^)]*\)\](?:\s*" + attribute + r")*\s*param\((.*?)^\)",
        read(hook),
        re.S | re.M,
    )
    if block is None:
        return set()
    body = re.sub(r"#[^\n]*", "", block.group(1))
    return set(re.findall(r"(?:\[[\w\[\]]+\]\s*)*\$(\w+)\s*(?:=|,|\)|$)", body, re.M))


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


if __name__ == "__main__":
    unittest.main()
