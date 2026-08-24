# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A screen that has not been made to fire on a real instance is not evidence.

``Identity.username`` is reassignable; ``user_id`` is not. A username used as an ACCESS KEY lets
a recreated account inherit the previous holder's objects, while the same username used to LABEL
an audit row is correct and wanted. BACKLOG #1226 asks for a screen over that distinction rather
than a sweep of today's instances, on the evidence that the class was found three times by
accident in three subsystems and zero times on purpose.

The fixtures below are the REAL SHAPES from BACKLOG #1225, copied from
``messagefoundry/api/app.py`` as it stood at ``dd90232ec`` -- before those four sites were re-keyed
onto ``user_id``. They are embedded rather than read out of git history on purpose: a CI checkout
may be shallow, and a proof that silently skips when the history is absent is the vacuous-gate
class this screen exists to catch.

Two properties are pinned because BACKLOG #1226 records both as learned the expensive way:

  * IT MUST SEE THE WRITE SITE. #1225 was filed naming three preset sites when there were four,
    and the missed one was ``upsert_search_preset`` -- the write that sets what the other three
    read. A fix to the readers alone would not have held.
  * IT MUST EMIT CANDIDATES, NEVER VERDICTS. Several real hits are correct code, including
    ``save(uploader=identity.username)`` where the username is deliberately the display label and
    a sibling ``uploader_id`` carries the key. The screen therefore exits 0 whatever it finds, and
    a test asserting "zero hits on correct code" would be unsatisfiable by design.

**AMENDED (#1226 wiring): that remains exactly true of the DEFAULT invocation, and ``--baseline``
does not weaken it.** Baseline mode fails only on a key nobody has JUDGED yet -- never on a
candidate being present -- so the screen still emits candidates rather than verdicts. The baseline
records that a human read the site; one of its entries is a confirmed defect, which is precisely
why it must not be read as an approval list.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCREEN = ROOT / "scripts" / "quality" / "username_access_key_screen.py"

#: The four BACKLOG #1225 sites as they really stood, pre-fix. Three reads and one WRITE.
_PRESET_SITES_AS_THEY_WERE = """
async def list_search_presets(identity, engine):
    rows = await engine.store.list_search_presets(identity.username)
    return rows


async def create_search_preset(identity, engine, body):
    effective_id, replaced = await engine.store.upsert_search_preset(
        preset_id=body.preset_id,
        owner_user_id=identity.username,
        payload=body.payload,
    )
    return effective_id


async def delete_search_preset(identity, engine, preset_id):
    deleted = await engine.store.delete_search_preset(
        preset_id=preset_id, owner_user_id=identity.username
    )
    return deleted


async def get_one(identity, engine, preset_id):
    row = await engine.store.get_search_preset(preset_id=preset_id, owner_user_id=identity.username)
    return row
"""

#: Correct code the screen must NOT report: a username labelling an audit row, and a username
#: handed positionally to a call that scopes nothing.
_CORRECT_LABEL_SITES = """
def record(audit, identity, request):
    audit.write(actor=identity.username, action="read")
    audit.write(acting_user=identity.username, action="read")
    logger.warning("rejected %s", identity.username)
    note(engine.store, identity.username, channel_id, exposed)
"""


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCREEN), *args], capture_output=True, text=True, timeout=90
    )


def test_it_reports_all_four_preset_sites_including_the_write(tmp_path: Path) -> None:
    """The proof that matters: fire on a real instance, and do not miss the write.

    Asserted on the greppable ``callee::slot`` shapes rather than line numbers, because the same
    defect site is ``create_search_preset`` or ``upsert_search_preset`` depending on where you
    stand, at different line numbers depending on your base.
    """
    sample = tmp_path / "app.py"
    sample.write_text(_PRESET_SITES_AS_THEY_WERE, encoding="utf-8")
    proc = run(str(sample))
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout

    assert "upsert_search_preset(owner_user_id=...)" in out, (
        "the WRITE key was missed -- see BACKLOG #1225"
    )
    assert "delete_search_preset(owner_user_id=...)" in out
    assert "get_search_preset(owner_user_id=...)" in out
    assert "list_search_presets(arg0=...)" in out, "the positional read scoping was missed"


def test_it_does_not_report_a_username_that_labels_an_audit_row(tmp_path: Path) -> None:
    """The negative control. A screen that fires on correct audit code gets switched off."""
    sample = tmp_path / "routes.py"
    sample.write_text(_CORRECT_LABEL_SITES, encoding="utf-8")
    proc = run(str(sample))
    assert proc.returncode == 0, proc.stderr
    assert "0 candidate(s)" in proc.stdout, proc.stdout
    assert "4 audit-label site(s) excluded" in proc.stdout, proc.stdout


def test_it_reports_candidates_rather_than_failing(tmp_path: Path) -> None:
    """Exit 0 even when it finds things: an AST sees shape, and correctly-keyed is semantics.

    This is not leniency. BACKLOG #1226 records that the two ways to make this gate exit non-zero
    on correct code were both destructive -- fail forever, or widen the exclusions until the class
    it watches for drops out.
    """
    sample = tmp_path / "app.py"
    sample.write_text(_PRESET_SITES_AS_THEY_WERE, encoding="utf-8")
    proc = run(str(sample))
    assert proc.returncode == 0
    assert "CANDIDATES, not defects" in proc.stdout


def test_it_prints_what_it_matched_and_not_only_a_count(tmp_path: Path) -> None:
    """``13`` looks identical whether it caught the write key or missed it."""
    sample = tmp_path / "app.py"
    sample.write_text(_PRESET_SITES_AS_THEY_WERE, encoding="utf-8")
    proc = run(str(sample))
    body = [line for line in proc.stdout.splitlines() if line.startswith("app.py:")]
    assert len(body) >= 4, proc.stdout
    assert all("--" in line for line in body), "each hit must carry the source it matched"


def test_the_live_api_scope_still_surfaces_the_unjudged_candidate() -> None:
    """Run over the real default scope, and pin the one site BACKLOG #1226 names as unjudged.

    ``security_events_for(identity.username)`` in ``api/auth_routes.py`` is not asserted to be a
    defect -- the item calls it an unjudged candidate and so does this. What is asserted is that
    the screen still SEES it, because a screen that stops surfacing a known instance has gone
    quiet without anything reporting so.
    """
    proc = run()
    assert proc.returncode == 0, proc.stderr
    assert "security_events_for(arg0=...)" in proc.stdout, proc.stdout
    assert "audit-label site(s) excluded as correct" in proc.stdout


# ---------------------------------------------------------------------------------------------
# BACKLOG #1226, the wiring limb. The screen shipped and NOTHING INVOKED IT, so it read as
# coverage and produced none. Measured before the fix, with a control:
#     git grep -l username_access_key origin/main -> BACKLOG.md, the screen, 2 test files
#     git grep -l control_char_check  origin/main -> ci.yml AND .pre-commit-config.yaml
# A wired screen shows up in those two files. This one did not.
# ---------------------------------------------------------------------------------------------

BASELINE = ROOT / "scripts" / "quality" / "username_access_key_baseline.txt"
CI = ROOT / ".github" / "workflows" / "ci.yml"
PRECOMMIT = ROOT / ".pre-commit-config.yaml"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCREEN), *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        check=False,
    )


def test_the_live_baseline_covers_every_site_the_screen_reports() -> None:
    """MUST NOT FIRE, and it is the arm that keeps the wiring honest.

    If this reds, a new username-as-access-key site has appeared and nobody has read it yet. That
    is the entire purpose of the step; the fix is to read the site and record a judgement, never to
    delete the arm."""
    proc = _run("--baseline", str(BASELINE))
    assert proc.returncode == 0, f"unjudged site(s) present:\n{proc.stdout}"


def test_an_unjudged_site_makes_the_step_FAIL(tmp_path: Path) -> None:
    """MUST FIRE. Without this the wiring would install a step that cannot fail for the reason it
    exists -- decoration that reads as coverage, which is the class this screen was written to
    catch, reproduced in its own gate."""
    thinned = tmp_path / "baseline.txt"
    kept = [
        ln
        for ln in BASELINE.read_text(encoding="utf-8").splitlines()
        if not ln.strip().startswith("auth_routes.py::security_events_for")
    ]
    assert len(kept) < len(BASELINE.read_text(encoding="utf-8").splitlines()), (
        "the line this arm removes is absent -- the mutation would be a no-op reporting success"
    )
    thinned.write_text("\n".join(kept), encoding="utf-8")

    proc = _run("--baseline", str(thinned))
    assert proc.returncode == 1, f"an unjudged site did not fail the step:\n{proc.stdout}"
    assert "NEW UNJUDGED SITE" in proc.stdout
    assert "security_events_for" in proc.stdout


def test_without_a_baseline_it_stays_ADVISORY() -> None:
    """MUST NOT FIRE -- the property the module docstring pins, preserved.

    Eight candidates are reported on the default scope and the exit code is still 0. Baseline mode
    is opt-in, so nothing that invoked this screen before behaves differently now."""
    proc = _run()
    assert proc.returncode == 0
    assert "candidate(s) FOR JUDGEMENT" in proc.stdout


def test_no_baseline_key_carries_a_line_number() -> None:
    """The item states this as a hard rule: cite the greppable name, never a line.

    The same site is ``create_search_preset`` or ``upsert_search_preset`` depending where you
    stand, at different lines depending on your base. A baseline keyed on lines would go stale on
    the next rebase and re-fire on sites already judged -- a false alarm that teaches the reader to
    delete the step."""
    for raw in BASELINE.read_text(encoding="utf-8").splitlines():
        key = raw.split("#", 1)[0].strip()
        if not key:
            continue
        assert not any(part.isdigit() for part in key.split("::")), f"line-keyed entry: {key}"


def test_the_screen_is_wired_in_BOTH_places_like_its_sibling() -> None:
    """THE ANTI-VACUITY ARM, and the one that decays. A screen wired in one place and not the other
    is half a gate, and the half that is missing is invisible in a green run.

    ``control_char_check`` is the POSITIVE CONTROL: it is wired in both, so if this test's own
    reading were broken the control would fail first and say so."""
    ci = CI.read_text(encoding="utf-8")
    pre = PRECOMMIT.read_text(encoding="utf-8")

    assert "control_char_check" in ci and "control_char_check" in pre, (
        "the positive control is missing from one of the two files -- this test cannot be trusted"
    )
    assert "username_access_key_screen" in ci, "not wired into CI"
    assert "username_access_key_screen" in pre, "not wired into pre-commit"
    assert "--baseline" in ci and "--baseline" in pre, (
        "wired WITHOUT --baseline, which installs a step that can never fail"
    )
