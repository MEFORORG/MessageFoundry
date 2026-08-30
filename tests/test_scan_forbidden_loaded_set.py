# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #321, build half -- per-class coverage that exercises the LOADED token set.

WHY THIS FILE EXISTS, AND WHY THE EXISTING PER-CLASS TESTS DO NOT COVER IT. Every per-class test in
``test_scan_forbidden.py`` runs behind the ``sf`` fixture, which monkeypatches SYNTHETIC values over
``FORBIDDEN`` / ``ESTATE_TOKENS`` / ``SITE_CODE_RE`` / ``_SITE_CODE_FILE``. Those tests prove the
MACHINERY matches a pattern someone handed it. They never touch the load path, so they say nothing
about whether a real token set arrives compiled and able to match.

THE FAILURE MODE THAT MAKES THAT A DEFECT RATHER THAN A GAP. With no prefix loaded, ``SITE_CODE_RE``
and ``_SITE_CODE_FILE`` both fall back to ``_NEVER`` (``scan_forbidden.py:194``), an empty negative
lookahead that matches NOTHING ANYWHERE. A blind scanner and a scanner with nothing to report are
the same green tick. So the suite that looks like per-class coverage cannot fail when the real set is
wrong -- which is the shape of the original defect, reproduced inside its own tests.

THE TWO ARMS, and the split is about what each is allowed to touch:

* THE BEHAVIOURAL ARM pins the source to the COMMITTED SYNTHETIC EXAMPLE and drives the REAL
  pipeline -- ``MEFOR_FORBIDDEN_TOKENS`` -> ``_resolve_token_text`` -> ``_parse_tokens`` ->
  compilation -> ``scan_file``. Nothing is monkeypatched onto the globals. Probes are DERIVED from
  what actually loaded, so a set that loads blind cannot reach the assertion: the derivation itself
  fails first.
* THE REAL-SET ARM runs only where a real (non-synthetic) source is configured, and asserts
  STRUCTURE ONLY -- present, not ``_NEVER``, counted. It never reads, builds with, or reports a real
  token, because this repository's forbidden-content guard exists to keep exactly those values out of
  files like this one (CLAUDE.md sec. 9). A test that embedded one to prove the scanner catches it
  would be the leak it is testing for.

TWO THINGS THIS FILE DELIBERATELY DOES NOT ASSERT:

* NOT REASON TEXT. The scanner substitutes a generic reason when a reason string would itself match a
  detector, so an assertion on reason wording reads the substituted value rather than the finding.
  These tests assert that a hit OCCURRED, on a probe line constructed so nothing else could have
  produced it.
* NOT A BARE DETECTOR COUNT. A token added under ``[estate_body_only]`` raises the ``estate`` count
  identically to one under ``[estate]`` while never entering ``scan_file``. Counting alone therefore
  cannot tell a token that is scanned from one that is merely listed, so the estate arm asserts the
  ``scan_file`` path itself.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "security"))

import scan_forbidden as sfm  # noqa: E402

pytestmark = pytest.mark.tooling

EXAMPLE = Path(sfm.__file__).parent / "scan-tokens.local.txt.example"


def _load(monkeypatch: pytest.MonkeyPatch, source: str | None) -> Any:
    """Drive the REAL load path and hand back the module.

    Deliberately NOT a monkeypatch of the globals: the point of this file is that everything from
    ``_resolve_token_text`` through pattern compilation actually runs.
    """
    if source is None:
        monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", "")
    else:
        monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", source)
    sfm.reload_tokens()
    return sfm


@pytest.fixture
def example(monkeypatch: pytest.MonkeyPatch) -> Any:
    """The committed synthetic example, loaded through the real pipeline.

    Restored afterwards by reloading from the ambient environment, so a real local token file is not
    left displaced for the rest of the session.
    """
    mod = _load(monkeypatch, str(EXAMPLE))
    yield mod
    monkeypatch.undo()
    sfm.reload_tokens()


def _word_probes_for_names(text: str) -> list[str]:
    """Words a ``\\b``-anchored ``[names]`` entry is expected to match, RECOVERED FROM THE SOURCE.

    A ``[names]`` entry is ``regex | reason | flags``, so the loaded table holds compiled patterns and
    the literal is gone -- and a regex cannot be inverted into a matching string in general. Rather
    than type a probe here (which would drift silently from the file it is meant to exercise), this
    recovers the plain-word entries, which are the shape the class is overwhelmingly made of, and
    ignores the rest. Recovering NOTHING is treated as a failure by the caller, so a source whose
    shape changed cannot quietly turn this into a no-op.
    """
    import re as _re

    probes: list[str] = []
    in_names = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_names = line.lower().startswith("[names]")
            continue
        if not in_names or not line or line.startswith("#"):
            continue
        pattern = line.split("|")[0].strip()
        if m := _re.fullmatch(r"\\b([A-Za-z][A-Za-z0-9]*)\\b", pattern):
            probes.append(m.group(1))
    return probes


# --- the anti-vacuity guards: these run FIRST because every assertion below is worthless without ---


def test_the_example_load_produces_non_blind_detectors(example: Any) -> None:
    """THE GUARD THE REST OF THIS FILE STANDS ON.

    ``_NEVER`` matches nothing anywhere, so a scanner that loaded nothing reports a clean tree and a
    scanner with nothing to find reports a clean tree. Asserting the detectors are not the sentinel is
    what makes every "no hit" result below mean something.
    """
    assert example.TOKENS_PRESENT, "the example did not load as a usable token source"
    assert example.SITE_CODE_RE is not example._NEVER
    assert example._SITE_CODE_FILE is not example._NEVER

    counts = example.loaded_token_counts()
    for section in ("names", "estate", "site_prefixes"):
        assert counts[section] > 0, f"class {section!r} loaded ZERO detectors from the example"
    # estate_file_scanned is the subset that scan_file can actually reach. Zero here with a non-zero
    # estate count means every token is body-only, which no file-scan assertion could detect.
    assert counts["estate_file_scanned"] > 0


def test_a_source_that_loads_nothing_is_reported_blind_rather_than_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE NEGATIVE CONTROL FOR THE GUARD ABOVE -- it must be able to observe the blind state.

    Without this, the guard could be asserting a condition that is simply always true, and would pass
    just as happily if ``_NEVER`` were unreachable. This pins that the blind state EXISTS and is
    distinguishable, which is the whole premise of the file.
    """
    mod = _load(monkeypatch, None)
    try:
        assert not mod.TOKENS_PRESENT
        assert mod.SITE_CODE_RE is mod._NEVER
        assert mod._SITE_CODE_FILE is mod._NEVER
        counts = mod.loaded_token_counts()
        assert counts["names"] == 0 and counts["estate"] == 0 and counts["site_prefixes"] == 0
    finally:
        monkeypatch.undo()
        sfm.reload_tokens()


# --- per class, over what actually loaded ---------------------------------------------------------


def test_the_loaded_names_class_matches_a_token_it_loaded(example: Any, tmp_path: Path) -> None:
    """Class [names], driven end-to-end rather than through a handed-in pattern.

    The probe is recovered FROM THE SOURCE that loaded rather than typed here, so it cannot drift away
    from the file it is meant to exercise, and a source that failed to load reaches no assertion at
    all: there is nothing to recover a probe from.
    """
    probes = _word_probes_for_names(EXAMPLE.read_text(encoding="utf-8"))
    assert probes, "recovered no plain-word [names] entry to probe with -- the source shape changed"

    # THE PROBE MUST BE ATTRIBUTABLE TO THIS CLASS ALONE, and the first candidate is not: the sets
    # OVERLAP BY DESIGN (a customer name is typically in [names] AND [estate]), so a word drawn from
    # [names] is often an estate token too, and the estate detector then produces the hit. Measured:
    # with `FORBIDDEN` forced empty this test still PASSED on the first candidate -- green against the
    # very class it names. Discard any candidate another detector can explain.
    def _line(word: str) -> str:
        return f"contact {word} about the interface"

    estate_pats = [pat for _token, pat in example._ESTATE_FILE_RES]
    usable = [
        w
        for w in probes
        if not any(p.search(_line(w)) for p in estate_pats)
        and not example._SITE_CODE_FILE.search(_line(w))
    ]
    assert usable, (
        "every recovered [names] probe is also matched by another class, so no hit here could be "
        "attributed to [names] -- this arm cannot be made to mean anything against this source"
    )

    probe = tmp_path / "note.md"
    probe.write_text(_line(usable[0]) + "\n", encoding="utf-8")
    hits = example.scan_file(probe)

    assert hits, "a loaded [names] token in a file body produced no hit"


def test_the_loaded_estate_class_is_caught_on_the_FILE_SCAN_path(
    example: Any, tmp_path: Path
) -> None:
    """Class [estate], asserted through ``scan_file`` -- NOT through a count and NOT through scan_text.

    THE DISTINCTION IS THE POINT. ``[estate_body_only]`` tokens are excluded from ``_ESTATE_FILE_RES``
    and therefore never enter ``scan_file`` at all, while still raising the ``estate`` detector count
    exactly as a scanned token does. So a test that watched the count could not tell a token the file
    scanner can see from one it cannot, and the leak this class exists for is a token sitting in a
    tracked file.

    The probe butts the token against identifier characters on an otherwise-unremarkable line: estate
    patterns run LAST in ``scan_file`` and only on a line no other detector flagged, so this shape is
    both the case only estate can reach and the one that keeps the hit attributable.
    """
    scanned = [token for token, _pat in example._ESTATE_FILE_RES]
    assert scanned, "no estate token is file-scanned, so this path cannot be exercised"

    probe = tmp_path / "config.txt"
    probe.write_text(f"OB_{scanned[0]}_ORU\n", encoding="utf-8")
    hits = example.scan_file(probe)

    assert hits, "a file-scanned estate token butted against identifier characters produced no hit"


def test_the_loaded_site_prefix_class_matches_a_prefix_it_loaded(
    example: Any, tmp_path: Path
) -> None:
    """Class [site_prefix], built from the prefix that actually loaded plus a four-digit run.

    ``SITE_CODE_RE`` is the detector that falls back to ``_NEVER``, so this is the class where a
    silent load failure is indistinguishable from a clean tree.
    """
    assert example._SITE_PREFIXES, "no site prefix loaded, so this class cannot be exercised"
    code = f"{example._SITE_PREFIXES[0]}0000"

    probe = tmp_path / "note.md"
    probe.write_text(f"the record was filed under {code} last week\n", encoding="utf-8")
    hits = example.scan_file(probe)

    assert hits, "a site code built from a loaded prefix produced no hit"


def test_a_digit_run_with_no_loaded_prefix_is_not_flagged(example: Any, tmp_path: Path) -> None:
    """The per-class negative control: the site detector must not match any six-digit run.

    Without this the class arm above is satisfied by a detector that flags everything, which is the
    other way an instrument stops discriminating.
    """
    probe = tmp_path / "note.md"
    probe.write_text("order 4815162342 shipped\n", encoding="utf-8")

    assert example.scan_file(probe) == []


# --- the real set, when one is configured ---------------------------------------------------------


def test_a_configured_REAL_token_set_is_loaded_and_not_blind() -> None:
    """The arm that covers the environment the gate actually protects.

    STRUCTURE ONLY, AND THAT IS NOT A SHORTCUT. Asserting a real token matches would require putting
    one in this file, which is precisely the disclosure the scanner exists to prevent (CLAUDE.md
    sec. 9) -- the test would become the leak. What is checkable without handling a value is that the
    set LOADED, that no class fell back to the sentinel, and that every class is populated. That is
    the blind-set failure, which is the one this item is about.

    Skips where no real set is configured, and says which state it saw: a silent skip here would be
    indistinguishable from a pass, and this is the arm most likely to be silently absent in CI.
    """
    sfm.reload_tokens()
    # A SOURCE THAT EXISTS BUT PARSED TO NOTHING IS A FAILURE, NOT A SKIP -- and separating the two is
    # the point. Both states leave TOKENS_PRESENT false, so skipping on that alone would turn the
    # documented mangling case (headers lost, comments only, a BOM ahead of the first section -- the
    # cutover runbook has the owner paste a whole file into a secret box) into a green tick, which is
    # the vacuous pass this item exists to remove. Only the ABSENCE of any source is a legitimate skip.
    configured = sfm._resolve_token_text() is not None
    if not configured:
        pytest.skip("no token source configured in this environment")
    assert sfm.TOKENS_PRESENT, (
        "a token source IS configured but parsed to zero detectors -- the source is present and "
        "unusable, which reports identically to having none"
    )
    if sfm.is_synthetic_token_set():
        pytest.skip("token source is the shipped synthetic example, not a real set")

    counts = sfm.loaded_token_counts()
    assert sfm.SITE_CODE_RE is not sfm._NEVER
    assert sfm._SITE_CODE_FILE is not sfm._NEVER
    for section in ("names", "estate", "site_prefixes"):
        assert counts[section] > 0, f"real token set loaded ZERO detectors for class {section!r}"
    assert counts["estate_file_scanned"] > 0, (
        "every real estate token is body-only, so scan_file covers none of them"
    )
