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
from types import ModuleType

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


# ---------------------------------------------------------------------------------------------
# BACKLOG #1226, THE PROOF CLAUSE. The screen can be silently narrowed to nothing, and every
# assertion above stays GREEN while it happens.
#
# MEASURED, not reasoned. Move "uploader" from ACCESS_KEY_NAMES into LABEL_NAMES -- a one-line
# edit that looks like reclassifying a field -- and:
#     the suite                         10 passed, unchanged
#     the live report      8 candidates -> 7,  excluded 80 -> 81
#     app.py save(uploader=...)         DISAPPEARS from the report
# The uploads site stops being surfaced for judgement and is silently recorded as
# "excluded as correct" instead. Nothing reds. That is the defect this clause closes.
#
# A DISJOINTNESS TEST DOES NOT CATCH IT, which is the trap worth naming: the mutation REMOVES the
# name from one set and ADDS it to the other, so the two stay disjoint throughout. Membership has
# to be PINNED, the same device `test_the_pinned_list_has_not_silently_shrunk` uses in
# tests/test_private_paths_stay_ignored.py.
# ---------------------------------------------------------------------------------------------


def _load_screen() -> ModuleType:
    """Import the screen as a module so its constants can be asserted on directly.

    It lives under scripts/ rather than in an installed package, so it is loaded by path -- the
    same device tests/test_scan_forbidden.py uses for the leak scanner.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("username_access_key_screen", SCREEN)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


#: Access-key names whose REMOVAL would empty part of the report. Pinned rather than derived: this
#: list existing is the point, and a name leaving it must be a reviewed edit rather than a side
#: effect of reclassifying a field. "at least these" -- adding is free, removing must red.
_PINNED_ACCESS_KEY_NAMES = frozenset({"owner", "uploader", "user", "key"})


def test_the_access_key_names_have_not_silently_shrunk() -> None:
    screen = _load_screen()
    missing = _PINNED_ACCESS_KEY_NAMES - screen.ACCESS_KEY_NAMES
    assert not missing, (
        f"{sorted(missing)} left ACCESS_KEY_NAMES. Each one is a shape that scopes a RESOURCE by "
        "username -- the class this screen exists for. Removing one narrows the report with no "
        "other signal: the suite stays green and the sites it covered are recorded as excluded."
    )


def test_no_access_key_name_is_also_an_audit_label() -> None:
    """The two sets must not overlap, and this is the WEAKER of the two guards on purpose.

    It cannot catch the measured mutation -- moving a name from one set to the other keeps them
    disjoint. It catches the sloppier edit that adds a name to LABEL_NAMES without removing it,
    where the exclusion would silently win.
    """
    screen = _load_screen()
    both = screen.ACCESS_KEY_NAMES & screen.LABEL_NAMES
    assert not both, (
        f"{sorted(both)} is in BOTH ACCESS_KEY_NAMES and LABEL_NAMES. The exclusion wins, so those "
        "sites vanish from the report while the name still reads as covered."
    )


def test_the_uploads_site_stays_REVIEWABLE_rather_than_absent() -> None:
    """THE PROOF CLAUSE ITSELF, and it is deliberately about the REPORT, not about the sets.

    The item's requirement is that the uploads report stay reviewable -- each hit adjudicated as
    correctly-keyed rather than ABSENT. `save(uploader=...)` in api/app.py is the site that carries
    that: `uploader=identity.username` may well be correct code (a sibling `uploader_id` can carry
    the key), and this test does NOT assert it is a defect. It asserts the reader still gets to see
    it and decide.

    Asserted on the SHIPPED SCREEN's output rather than on its constants, so ANY narrowing that
    removes the site reds here -- a set edit, a rule change, a scope change. The two set-level tests
    above cover one route each; this covers the outcome regardless of route.
    """
    proc = run()
    assert proc.returncode == 0, proc.stderr
    assert "save(uploader=...)" in proc.stdout, (
        "the uploads site is no longer surfaced for judgement. The screen has gone quiet on the "
        "shape BACKLOG #1226 is about, and being absent from the report is indistinguishable from "
        f"having been adjudicated correct.\n{proc.stdout}"
    )
