# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1420: the connscale rate window must be described as the window the code computes.

`_run_one_step` appends the step's FINAL engine sample **after** `sampler_stop.set()` has stopped the
in-hold sampler, after `driver.stop(_STOP_GRACE)`, after `poller.await_drain(...)` and after
`asyncio.sleep(_SETTLE)`. `_empty_claim_rates` then reads `samples[0]` and `samples[-1]`, so the
window every empty-claim and throughput rate is computed over ENDS AT A POST-DRAIN READING. Five
sites once described that window as "first to last in-hold samples". The last sample is not in-hold,
so the described window and the computed window were not the same window.

Fix (b) corrected all five (commit 58b3d96b3, on `main` at a2eef0f37): the span is stated ONCE, in
`_empty_claim_rates`, and the other four point there rather than restate it (SDS-3.5). The tail stays
INSIDE the numbers.

**THIS MODULE IS THE GUARD AGAINST THAT CORRECTION AND THE CODE DRIFTING APART AGAIN.** It pins both
halves, because either one moving alone re-opens the defect:

* the ORDERING in `_run_one_step` -- the final sample really is appended after the sampler stops;
* the DESCRIPTION -- the one definition still says the tail is inside, the other sites still point at
  it, and no site re-asserts the retired sentence.

**A GUARD NOBODY CAN SHOW FIRING IS NOT EVIDENCE, so the controls are tests, not a one-off terminal
run.** `test_the_scanner_flags_every_sentence_fix_b_retired` feeds the scanner the five sentences
VERBATIM from `fd44b0f17` -- the commit before fix (b) -- and requires all five to flag. It found a
real defect while this module was being written: the first draft's quote carve-out treated a `\"\"\"`
docstring delimiter as an ordinary quote pair and silently swallowed the `_empty_claim_rates` site,
so 4 of 5 flagged and the miss looked like a pass. That fix is pinned by
`test_a_docstring_delimiter_does_not_hide_an_assertion`.

**WHY A QUOTE CARVE-OUT EXISTS, and why it is narrow.** `_empty_claim_rates` quotes the retired
sentence as the record of what was fixed. Quoting the retired wording is how you talk about it;
asserting it is the defect. So the scanner strips double-quoted spans before matching, and
`test_quoting_the_retired_sentence_is_allowed_but_asserting_it_is_not` proves the carve-out does not
blanket-pass the same words unquoted.
"""

from __future__ import annotations

import inspect
import pathlib
import re

import pytest

from harness.load.connscale import report as report_module
from harness.load.connscale import runner as runner_module
from harness.load.connscale.runner import (
    _empty_claim_rates,
    _empty_claims_per_msg,
    _run_one_step,
    _throughput_rates,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# The corpus whose scope BACKLOG #1420 states with its count of five. `docs/` is deliberately OUT:
# the ledger and the closed archive quote the retired sentence as history, which is exactly the use
# the carve-out below permits, and policing prose in the ledger is a different job from policing the
# description of a live metric.
_CORPUS_DIR = _REPO_ROOT / "harness" / "load" / "connscale"
_CORPUS_EXTRA = (_REPO_ROOT / "tests" / "test_connscale_empty_claims_per_msg.py",)

# Python string delimiters. Stripped BEFORE the quote carve-out, because `\"\"\"` is three quote
# characters and the carve-out would otherwise pair two of them across a whole docstring body and
# strip the assertion inside it. This is the defect the pre-fix control caught.
_DELIMITER_RUN = re.compile(r"\"{3,}|'{3,}")

# An ordinary double-quoted span: the sanctioned way to name the retired sentence without asserting it.
_QUOTED_SPAN = re.compile(r'"[^"\n]{0,400}"')

# The retired claim: a FIRST-to-LAST window described as in-hold. `[^.]` keeps the match inside one
# sentence, so a later, separate sentence mentioning "in-hold" cannot manufacture a hit.
_RETIRED_WINDOW_CLAIM = re.compile(
    r"first\s*(?:→|->|-to-|to)\s*last\b[^.]{0,60}?in-hold",
    re.IGNORECASE,
)

# The five sentences fix (b) retired, VERBATIM from `fd44b0f17` (the commit before 58b3d96b3).
# Reproduced exactly, wrapping and all, so the control measures the real historical text rather than
# a paraphrase of it that might be easier to catch than the original was.
_RETIRED_AT_FD44B0F17 = {
    "report.py:119": (
        "    # Empty claims PER MESSAGE absorbed, over the same first→last in-hold window as "
        "the rates above.\n"
    ),
    "runner.py:922": (
        "    # are Δ/span over the same first→last in-hold samples, so dividing them "
        "cancels the span exactly and\n"
    ),
    "runner.py:1149": (
        '    """Empty-claim rates over the hold window: (total/s, idle_poll/s, wake_fanout/s), '
        "from the FIRST\n    to LAST in-hold sample. SEPARATED — never summed into one number "
        '(critic must-change #3)."""\n'
    ),
    "runner.py:1166": (
        "    Both inputs are Δ/span over the SAME first→last in-hold samples, so ``span`` "
        "cancels and this is\n    exactly ``Δempty_claims / Δread``.\n"
    ),
    "test_connscale_empty_claims_per_msg.py:11": (
        "The fix reads ``empty_claims_per_msg`` instead. Both inputs are deltas over the SAME "
        "first-to-last\nin-hold samples, so the span cancels and the quantity is exactly "
        "``Δempty_claims / Δread``.\n"
    ),
}

# The claims `_empty_claim_rates` must keep making. Reverting any of them is the drift this guards.
_DEFINITION_CLAIMS = (
    "samples[-1]",
    "NOT in-hold",
    "sampler_stop.set()",
    "await_drain",
    "the hold PLUS",
    "INSIDE the number",
)

# The ordering that makes the final sample post-drain, in the order `_run_one_step` runs it.
_ORDERING = (
    "sampler_stop.set()",
    "await driver.stop(_STOP_GRACE)",
    "await poller.await_drain(",
    "await asyncio.sleep(_SETTLE)",
    "samples.append(final)",
)


def _normalize(text: str) -> str:
    """Collapse whitespace, then drop string delimiters. Order matters: the docstrings this scans are
    WRAPPED PARAGRAPHS, so two of the five retired sentences straddle a line break and only match once
    the wrapping is gone."""
    return _DELIMITER_RUN.sub(" ", re.sub(r"\s+", " ", text))


def retired_window_claims(text: str) -> list[str]:
    """Every ASSERTION that the rate window runs first-to-last in-hold. Quoted spans are excluded --
    naming the retired sentence is allowed, restating it as fact is not."""
    return [
        m.group(0) for m in _RETIRED_WINDOW_CLAIM.finditer(_QUOTED_SPAN.sub(" ", _normalize(text)))
    ]


def first_out_of_order(source: str, landmarks: tuple[str, ...]) -> str | None:
    """The first landmark that does not appear after the one before it, or None if all are in order.

    Each search resumes where the previous landmark matched, so a landmark appearing more than once in
    the function (`driver.stop(_STOP_GRACE)` also runs in the step's cleanup path) is read in sequence
    rather than by its first occurrence anywhere.
    """
    at = 0
    for landmark in landmarks:
        found = source.find(landmark, at)
        if found < 0:
            return landmark
        at = found + len(landmark)
    return None


def _corpus_files() -> list[pathlib.Path]:
    # The guard's own file is excluded: it holds the retired sentences as control data, and a scanner
    # that reds on its own fixtures tests nothing about the code it guards.
    here = pathlib.Path(__file__).resolve()
    files = sorted(_CORPUS_DIR.glob("*.py"))
    files.extend(p for p in _CORPUS_EXTRA if p.resolve() != here)
    return files


# --- controls: the scanner can fire, and does not fire on the corrected text ----------------------


@pytest.mark.parametrize("site", sorted(_RETIRED_AT_FD44B0F17))
def test_the_scanner_flags_every_sentence_fix_b_retired(site: str) -> None:
    """POSITIVE CONTROL, on real pre-fix text. All five sentences fix (b) retired must flag, one each.

    Without this, a scanner that quietly matched nothing would report a clean corpus and read exactly
    like a passing guard.
    """
    hits = retired_window_claims(_RETIRED_AT_FD44B0F17[site])
    assert len(hits) == 1, (
        f"the retired sentence at {site} did not flag -- the scanner cannot catch the defect it "
        f"exists to catch; got {ascii(hits)}"
    )


def test_the_scanner_does_not_flag_the_corrected_sentences() -> None:
    """NEGATIVE CONTROL. Fix (b)'s replacement wording must pass, or the guard is unsatisfiable and
    the next author's only way out is to delete it."""
    corrected = (
        "Empty claims PER MESSAGE absorbed, over the same first→last sample window as the "
        "rates above. That window is the hold PLUS the step's post-drain tail."
    )
    assert retired_window_claims(corrected) == []


def test_quoting_the_retired_sentence_is_allowed_but_asserting_it_is_not() -> None:
    """The carve-out must be NARROW: the same words flag unquoted and pass quoted. One arm alone
    proves nothing -- a scanner that passed both would look identical on the quoted arm."""
    quoted = 'Five sites called this window "first to last in-hold samples", and the last is not.'
    asserted = (
        "Both inputs are deltas over the same first to last in-hold samples, so span cancels."
    )
    assert retired_window_claims(quoted) == [], "quoting the retired sentence must stay legal"
    assert len(retired_window_claims(asserted)) == 1, (
        "the carve-out is too wide -- it passes the assertion, not just the quotation"
    )


def test_a_docstring_delimiter_does_not_hide_an_assertion() -> None:
    """REGRESSION on a defect the pre-fix control caught in this module's own first draft.

    A `\"\"\"` delimiter is three quote characters. A quote carve-out applied before the delimiters are
    removed pairs two of them and strips the entire docstring body, so an assertion INSIDE a docstring
    -- which is where four of the five retired sentences lived -- silently passes.
    """
    inside_docstring = (
        '    """Empty-claim rates over the hold window, from the FIRST\n'
        '    to LAST in-hold sample. SEPARATED."""\n'
    )
    assert len(retired_window_claims(inside_docstring)) == 1, (
        "an assertion inside a docstring must flag -- the delimiter is not a quotation"
    )


def test_the_ordering_check_reports_a_final_sample_taken_before_the_sampler_stops() -> None:
    """CONTROL for the ordering half. Against a mutant that appends the final sample BEFORE
    `sampler_stop.set()` -- which would make the sample genuinely in-hold and the current description
    wrong in the other direction -- the check must name the landmark that moved."""
    mutant = "\n".join(
        (
            "samples.append(final)",
            "sampler_stop.set()",
            "await driver.stop(_STOP_GRACE)",
            "await poller.await_drain(timeout=1.0)",
            "await asyncio.sleep(_SETTLE)",
        )
    )
    assert first_out_of_order(mutant, _ORDERING) == "samples.append(final)"
    in_order = "\n".join(_ORDERING)
    assert first_out_of_order(in_order, _ORDERING) is None


# --- the guard proper -----------------------------------------------------------------------------


def test_the_final_sample_is_appended_after_the_sampler_stops() -> None:
    """THE ORDERING HALF. `samples[-1]` is a post-drain reading, which is what every description of
    the window now says. If this reds, the code moved and the descriptions below need re-reading --
    the fix is not to loosen this test."""
    source = inspect.getsource(_run_one_step)
    offender = first_out_of_order(source, _ORDERING)
    assert offender is None, (
        f"`_run_one_step` no longer runs {_ORDERING} in that order -- {offender!r} moved. "
        "The rate window's description assumes the final sample is taken after the sampler stops "
        "(BACKLOG #1420); re-read `_empty_claim_rates` before changing this."
    )
    assert source.count("samples.append(") == 1, (
        "a second `samples.append(` appeared in the step -- which sample ends the rate window is no "
        "longer obvious from the ordering, so the description cannot be checked against it"
    )


def test_the_window_is_defined_once_and_still_says_the_tail_is_inside_it() -> None:
    """THE DESCRIPTION HALF, at the single definition site (SDS-3.5). `_empty_claim_rates` is the one
    place BACKLOG #1420 allows to state the span; these are the claims it must keep making."""
    doc = " ".join((_empty_claim_rates.__doc__ or "").split())
    missing = [claim for claim in _DEFINITION_CLAIMS if claim not in doc]
    assert not missing, (
        f"`_empty_claim_rates` stopped saying {missing} -- it is the ONE place that defines the rate "
        "window, and every other site points here instead of restating it (BACKLOG #1420)"
    )


def test_every_other_site_points_at_the_definition_rather_than_restating_it() -> None:
    """SDS-3.5: state a load-bearing fact once and link to it. The four non-definition sites must
    name `_empty_claim_rates`; a site that re-derives the span is how the five diverged before."""
    pointers = {
        "runner._empty_claims_per_msg": _empty_claims_per_msg.__doc__ or "",
        "runner._throughput_rates": _throughput_rates.__doc__ or "",
        "runner._build_record comment": inspect.getsource(runner_module._build_record),
        "report.ConnScaleRecord": inspect.getsource(report_module.ConnScaleRecord),
        "tests.test_connscale_empty_claims_per_msg": (
            (_REPO_ROOT / "tests" / "test_connscale_empty_claims_per_msg.py").read_text(
                encoding="utf-8"
            )
        ),
    }
    silent = [name for name, text in pointers.items() if "_empty_claim_rates" not in text]
    assert not silent, (
        f"{silent} describe the rate window without pointing at `_empty_claim_rates`, which is where "
        "BACKLOG #1420 put the single definition"
    )


def test_no_connscale_source_asserts_the_retired_window_description() -> None:
    """THE CORPUS SWEEP. No site may re-assert that the window runs first-to-last in-hold. Quoting the
    retired sentence stays legal; asserting it does not."""
    offenders: dict[str, list[str]] = {}
    for path in _corpus_files():
        hits = retired_window_claims(path.read_text(encoding="utf-8"))
        if hits:
            offenders[path.relative_to(_REPO_ROOT).as_posix()] = [ascii(h) for h in hits]
    assert not offenders, (
        f"{offenders} describe the rate window as first-to-last IN-HOLD. The last sample is taken "
        "after `sampler_stop.set()`, `driver.stop`, `await_drain` and `sleep(_SETTLE)`, so it is not "
        "in-hold (BACKLOG #1420). Point at `_empty_claim_rates` instead of restating the span."
    )


def test_the_corpus_actually_contains_the_files_this_guard_claims_to_cover() -> None:
    """A sweep over an empty corpus passes and means nothing. Pin that the scope BACKLOG #1420 states
    is really being read, and that the definition site is inside it."""
    files = _corpus_files()
    names = {p.name for p in files}
    assert len(files) >= 5, f"the connscale corpus collapsed to {sorted(names)}"
    for required in ("runner.py", "report.py", "test_connscale_empty_claims_per_msg.py"):
        assert required in names, f"{required} left the corpus this guard sweeps"
