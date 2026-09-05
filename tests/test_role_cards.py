# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Role cards: the seat marker, the alias map, the cards, and the injection hook.

SUBJECT IS THE HARNESS, not the engine -- this spawns real ``pwsh`` children and reads
``scripts/hooks/``. Listed in ``tests/tooling_manifest.txt`` for that reason.

WHAT THESE GUARD, stated once so the reasons do not have to be re-derived from the asserts:

1. **A card budget that is not enforced drifts.** The vault playbooks reached 242 KB by nobody
   measuring. A card is injected into every session holding that seat, so its size is a running
   cost and the ceiling belongs in a test rather than in prose.
2. **A resolution order that is not tested for SILENCE is one bug away from guessing.** CLAUDE.md
   section 5 records that a worktree name is a creation-time label nothing keeps current, and that
   one is known to describe work its session never did. So the branch-name test asserts a
   NEGATIVE: given a branch that looks exactly like a seat, the hook must still say nothing.
3. **The hook must never fail a turn.** ``seat-record.ps1`` and ``seat-declare-prompt.ps1`` both
   exit 0 unconditionally, and this one runs at SessionStart in every worktree of a repo with a
   live fleet in it. Every path below asserts exit 0, including the broken ones.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_HOOK = _REPO / "scripts" / "hooks" / "role-card-inject.ps1"
_ROLES = _REPO / "docs" / "roles"
_SEATS_JSON = _ROLES / "seats.json"

#: From CLAUDE.md section 5. That table is the authority: the vault's roles/README.md still lists
#: seven retired seats and calls itself a partial list, so it loses on every disagreement.
_LIVE_SEATS = ("console", "builder", "reviewer", "regulator", "steward", "lander")

#: Measured 2026-09-05 across 968 worktree seat records: eight spellings of one seat.
_BUILDER_SPELLINGS = (
    "builder",
    "Builder",
    "BUILDER1",
    "BUILDER2",
    "builder1",
    "builder2",
    "builder-2",
    "builder3",
)

#: Retired by CLAUDE.md section 5, still present in live seat records.
_RETIRED = ("dispatcher", "liaison", "pm", "cleaner", "role-manager", "asvs-tracker")

_MAX_LINES = 150
_MAX_BYTES = 6 * 1024


def _seats() -> dict[str, object]:
    loaded: object = json.loads(_SEATS_JSON.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict), "seats.json must hold an object"
    return loaded


def _seat_list() -> tuple[str, ...]:
    v = _seats()["seats"]
    assert isinstance(v, list)
    return tuple(str(x) for x in v)


def _str_map(key: str) -> dict[str, str]:
    v = _seats()[key]
    assert isinstance(v, dict), f"seats.json['{key}'] must hold an object"
    return {str(k): str(x) for k, x in v.items()}


def _run_hook(worktree: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(_HOOK),
            "-Worktree",
            str(worktree),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _card_text(out: str) -> str:
    """The injected card, however the hook chose to emit it.

    Accepts either shape so the test pins BEHAVIOUR and not the wire format: the JSON
    ``hookSpecificOutput.additionalContext`` form when the harness supports it, or the plain
    stdout that ``seat-declare-prompt.ps1`` already proves reaches a session.
    """
    try:
        payload = json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return out
    specific = payload.get("hookSpecificOutput", {}) if isinstance(payload, dict) else {}
    return str(specific.get("additionalContext", out))


# --------------------------------------------------------------------------------------------
# The cards themselves
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("seat", _LIVE_SEATS)
def test_every_live_seat_has_a_card(seat: str) -> None:
    assert (_ROLES / f"{seat}.card.md").is_file(), (
        f"CLAUDE.md section 5 lists '{seat}' as a live seat with no card at "
        f"docs/roles/{seat}.card.md. A seat the hook cannot resolve gets silence."
    )


@pytest.mark.parametrize("seat", _LIVE_SEATS)
def test_card_stays_within_budget(seat: str) -> None:
    card = _ROLES / f"{seat}.card.md"
    raw = card.read_bytes()
    lines = raw.decode("utf-8").count("\n") + 1
    assert lines <= _MAX_LINES, f"{card.name}: {lines} lines, ceiling is {_MAX_LINES}"
    assert len(raw) <= _MAX_BYTES, f"{card.name}: {len(raw)} bytes, ceiling is {_MAX_BYTES}"


@pytest.mark.parametrize("seat", _LIVE_SEATS)
def test_card_carries_no_glyphs(seat: str) -> None:
    """CLAUDE.md section 11. A card is prose written back to a session, so the rule binds."""
    text = (_ROLES / f"{seat}.card.md").read_text(encoding="utf-8")
    offenders = sorted({c for c in text if ord(c) > 127})
    assert not offenders, f"{seat}.card.md carries non-ASCII: {offenders!r}. Say the word."


@pytest.mark.parametrize("seat", _LIVE_SEATS)
def test_card_points_at_its_long_playbook(seat: str) -> None:
    """A card is a summary. It has to say so, or it reads as the whole rule set."""
    text = (_ROLES / f"{seat}.card.md").read_text(encoding="utf-8").lower()
    assert "playbook" in text, f"{seat}.card.md never names where the long form lives"


# --------------------------------------------------------------------------------------------
# The alias map
# --------------------------------------------------------------------------------------------


def test_seats_json_lists_exactly_the_live_roster() -> None:
    assert _seat_list() == _LIVE_SEATS


@pytest.mark.parametrize("spelling", _BUILDER_SPELLINGS)
def test_every_observed_builder_spelling_maps_to_builder(spelling: str) -> None:
    assert _str_map("aliases").get(spelling.lower()) == "builder", (
        f"'{spelling}' was observed in a live seat record and does not resolve to 'builder'"
    )


@pytest.mark.parametrize("seat", _RETIRED)
def test_retired_seat_maps_to_nothing_and_says_why(seat: str) -> None:
    retired = _str_map("retired")
    assert seat in retired, f"'{seat}' is retired by CLAUDE.md section 5 and is not recorded"
    assert retired[seat].strip(), f"'{seat}' is recorded as retired with no reason beside it"
    assert seat not in _str_map("aliases"), f"'{seat}' is retired and must not alias to a live seat"


# --------------------------------------------------------------------------------------------
# The hook
# --------------------------------------------------------------------------------------------


def test_hook_with_no_marker_prints_the_setting_command_and_injects_nothing(
    tmp_path: Path,
) -> None:
    r = _run_hook(tmp_path)
    assert r.returncode == 0, r.stderr
    assert ".claude\\seat" in r.stdout or ".claude/seat" in r.stdout, (
        "an unset seat must print the one command that sets it"
    )
    assert "What this seat owns" not in _card_text(r.stdout), "no marker must mean no card"


def test_hook_injects_the_card_named_by_the_marker(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "seat").write_text("builder\n", encoding="utf-8")
    r = _run_hook(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "What this seat owns" in _card_text(r.stdout)


def test_hook_normalises_a_drifted_spelling(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "seat").write_text("BUILDER2\n", encoding="utf-8")
    r = _run_hook(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "What this seat owns" in _card_text(r.stdout)


def test_hook_writes_the_resolved_card_where_a_compacted_session_can_re_read_it(
    tmp_path: Path,
) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "seat").write_text("lander\n", encoding="utf-8")
    r = _run_hook(tmp_path)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / ".claude" / "ROLE.md").is_file()


def test_hook_does_not_guess_a_seat_from_a_branch_that_looks_like_one(tmp_path: Path) -> None:
    """The NEGATIVE that keeps rung 4 silent. See the module docstring, point 2."""
    subprocess.run(["git", "init", "-q", "-b", "claude/lander-x", str(tmp_path)], check=True)
    r = _run_hook(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "What this seat owns" not in _card_text(r.stdout), (
        "a branch named after a seat is not a declaration; CLAUDE.md section 5 records that a "
        "worktree label goes stale and one described work its session never did"
    )


def test_hook_says_a_retired_seat_is_retired_rather_than_injecting_one(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "seat").write_text("dispatcher\n", encoding="utf-8")
    r = _run_hook(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "retired" in r.stdout.lower()
    assert "What this seat owns" not in _card_text(r.stdout)


def test_hook_exits_zero_when_the_marker_is_unreadable_nonsense(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "seat").write_text("\x00\x01 not a seat \x02", encoding="utf-8")
    r = _run_hook(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "What this seat owns" not in _card_text(r.stdout)


# --------------------------------------------------------------------------------------------
# The marker must never dirty a tree
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", [".claude/seat", ".claude/ROLE.md"])
def test_marker_and_written_card_are_git_ignored(path: str) -> None:
    r = subprocess.run(
        ["git", "check-ignore", "-q", path], cwd=_REPO, capture_output=True, text=True
    )
    assert r.returncode == 0, (
        f"'{path}' is not ignored. It would show as untracked in every worktree and could ride "
        f"into a commit on `git add -A`."
    )


def test_hook_falls_back_to_the_environment_when_no_marker_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rung 2. The Console sets this when it spawns, before any marker exists."""
    monkeypatch.setenv("MEFOR_SEAT", "reviewer")
    r = _run_hook(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "What this seat owns" in _card_text(r.stdout)


def test_a_written_marker_outranks_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "seat").write_text("lander\n", encoding="utf-8")
    monkeypatch.setenv("MEFOR_SEAT", "reviewer")
    r = _run_hook(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "lander" in _card_text(r.stdout).lower()
    assert "Reviewer" not in _card_text(r.stdout).splitlines()[0]
