# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A role card is injected at SessionStart, so a WRONG one outranks the document that corrects it.

THE FAILURE THESE TESTS PIN. `CLAUDE.md` reaches a session as context. A card reaches it at session
start, before the session has read anything, and it reads as settled. So a card that disagrees with
the working agreement does not lose the argument -- it wins it, silently, for the whole session.

THE CARDS CAME FROM KORUS AND WERE NOT COPIED. Three ways a straight copy would have been wrong,
each measured 2026-09-06 and each guarded below:

  1. ROSTER. korus runs seven seats. Section 5's table here runs five: no Manager, no Reviewer.
  2. PUSH AUTHORITY. korus's cards say pushing needs the owner. Section 5 carries the opposite as an
     anchored ruling, `refs/liaison/owner-ruling-20260829-push`.
  3. PLAYBOOK PATHS. korus's cards cite `roles/COMMON.md`. No such path exists in this checkout.

Each of those is a class, not an instance, which is why each gets a test rather than a fix.
"""

from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]

CARD_DIR = _REPO / "docs" / "roles"
SEATS_PATH = CARD_DIR / "seats.json"
AGREEMENT = _REPO / "CLAUDE.md"
HOOK = _REPO / "scripts" / "hooks" / "role-card-inject.ps1"
SETTINGS = _REPO / ".claude" / "settings.json"

#: The marker and the injected copy. BOTH MUST STAY GIT-IGNORED, and the ignore rule here is the
#: INVERSE of korus's: `/.claude/*` covers the directory and one negation re-adds settings.json.
MARKER_RELPATH = ".claude/seat.local.txt"
ROLE_COPY_RELPATH = ".claude/ROLE.local.md"

#: Section 5's table governs. FIVE seats, not korus's seven.
EXPECTED_SEATS = frozenset({"console", "builder", "regulator", "steward", "lander"})

#: Live in korus, absent here. They must resolve to a card-less explanation, never to silence.
EXPECTED_ELSEWHERE = frozenset({"manager", "reviewer"})

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

    def test_a_korus_seat_is_not_quietly_live_here(self):
        """The specific error this port nearly shipped: seven seats where the table names five."""
        overreach = sorted(EXPECTED_ELSEWHERE & set(seats()["live"]))
        self.assertEqual(
            [],
            overreach,
            f"{overreach} are korus seats and are not in this repository's table. A card for one "
            "would hand a session a seat the working agreement does not run.",
        )


class ASeatThatIsNotRunHereSaysSoRatherThanGoingSilent(unittest.TestCase):
    """Silence reads as a missing file. A roster difference is not a missing file."""

    def test_every_korus_only_seat_is_named_with_its_reason(self):
        elsewhere = seats().get("elsewhere", {})
        self.assertEqual(EXPECTED_ELSEWHERE, set(elsewhere))
        for label, why in elsewhere.items():
            self.assertTrue(why.strip(), f"{label} is listed with no reason")

    def test_a_korus_only_seat_resolves_to_no_card(self):
        for label in EXPECTED_ELSEWHERE:
            with self.subTest(seat=label):
                self.assertFalse(
                    (CARD_DIR / f"{label}.card.md").exists(),
                    f"{label} has a card here, which contradicts the roster",
                )

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
    """Only one card is ever injected, so the cost is one card. The cap keeps that true."""

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
        offenders = [
            f"{p.name} is missing '{s}'"
            for p in card_paths()
            for s in REQUIRED_SECTIONS
            if s not in read(p)
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

    The playbooks moved to korus on 2026-09-04. A bare `roles/BUILDER.md` resolves to nothing in
    this checkout, and an absent file is the failure that reports nothing at all.
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

    def test_the_hook_is_wired_at_session_start(self):
        wired = json.loads(read(SETTINGS))["hooks"]["SessionStart"]
        commands = [" ".join(h.get("args", [])) for entry in wired for h in entry.get("hooks", [])]
        self.assertTrue(
            any("role-card-inject.ps1" in c for c in commands),
            f"role-card-inject.ps1 is not wired at SessionStart. Wired: {commands}",
        )

    def test_the_hook_keeps_the_existing_session_start_hook(self):
        """Adding a hook must not replace the one that was there."""
        wired = json.loads(read(SETTINGS))["hooks"]["SessionStart"]
        commands = [" ".join(h.get("args", [])) for entry in wired for h in entry.get("hooks", [])]
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


if __name__ == "__main__":
    unittest.main()
