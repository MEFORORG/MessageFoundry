# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1420: the connscale rate window must be described as the window the code computes.

`_run_one_step` appends the step's FINAL engine sample **after** `sampler_stop.set()` has stopped the
in-hold sampler, after `driver.stop(_STOP_GRACE)`, after `poller.await_drain(...)` and after
`asyncio.sleep(_SETTLE)`. It counts `in_hold_samples` BEFORE that append, and `_build_record` cuts the
rate window as `samples[:in_hold_samples]`. So the window every empty-claim and throughput rate is
computed over now STOPS BEFORE the post-drain reading. That is fix (a).

The history, in order. Five sites once described a window ending at the post-drain final as "first to
last in-hold samples". Fix (b) (commit 58b3d96b3) corrected the words and kept the tail in the
numbers. BACKLOG #1430's sampler floor then guaranteed two readings before the final, and fix (a)
took the tail out. The window is defined ONCE, in `_empty_claim_rates`, and the other sites point
there rather than restate it (SDS-3.5).

**THE WINDOW IS STILL NOT "THE HOLD".** It holds the in-hold readings plus up to
`_MIN_IN_HOLD_SAMPLES` make-up floor ticks, which the sampler can take after the hold ends. So the
retired sentence stays retired, and the scanner below still reds on it.

**THIS MODULE IS THE GUARD AGAINST THE DESCRIPTION AND THE CODE DRIFTING APART.** It pins three
things, because any one moving alone re-opens the defect:

* the ORDERING in `_run_one_step` -- `in_hold_samples` is counted after the sampler stops and before
  the final sample is appended;
* the SLICE in `_build_record` -- both rate functions get the same window, and it excludes the final;
* the DESCRIPTION -- the one definition says the tail is OUTSIDE, the other sites point at it, and no
  site re-asserts the retired sentence.

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
from harness.load.connscale.report import ConnScaleRecord
from harness.load.connscale.runner import (
    _empty_claim_rates,
    _empty_claims_per_msg,
    _run_one_step,
    _throughput_rates,
)
from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.metrics import Counters, Histogram

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

# The claims `_empty_claim_rates` must keep making since fix (a). Reverting any of them is the drift
# this guards: the slice, the make-up ticks that stop it being "the hold", the exclusion, and the
# warning that readings either side of the change do not compare.
_DEFINITION_CLAIMS = (
    "samples[:in_hold_samples]",
    "make-up floor ticks",
    "sampler_stop.set()",
    "await_drain",
    "EXCLUDES the post-drain final",
    "OUTSIDE the number",
    "NOT COMPARABLE",
    "rate_window",
)

# Fix (b)'s claims that the tail is IN the number. Any of them coming back means the description has
# reverted while the code has not.
_RETIRED_DEFINITION_CLAIMS = (
    "the hold PLUS",
    "INSIDE the number",
)

# The ordering that keeps the final sample out of the rate window, in the order `_run_one_step` runs
# it. `in_hold_samples` must be counted after the sampler stops and before the final is appended:
# `_build_record` slices `samples[:in_hold_samples]`, so a count taken after the append would put the
# post-drain final back inside every rate.
_ORDERING = (
    "sampler_stop.set()",
    "in_hold_samples = len(samples)",
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
    """NEGATIVE CONTROL. Acceptable wording must pass, or the guard is unsatisfiable and the next
    author's only way out is to delete it. Two PARAPHRASES are fed in, one in the fix (a) sense and one
    in fix (b)'s older sense: the scanner polices the retired "in-hold" sentence, not which side of
    the tail a site is on -- the definition test below polices that. The corpus sweep further down
    is what reads the real sources."""
    current = (
        "Empty claims PER MESSAGE absorbed, over the same rate window as the rates above. That "
        "window EXCLUDES the step's post-drain final, and runs first→last over the readings it holds."
    )
    fix_b = (
        "Empty claims PER MESSAGE absorbed, over the same first→last sample window as the "
        "rates above. That window is the hold PLUS the step's post-drain tail."
    )
    assert retired_window_claims(current) == []
    assert retired_window_claims(fix_b) == []


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


@pytest.mark.parametrize(
    ("mutant", "offender"),
    [
        pytest.param(
            (
                "samples.append(final)",
                "sampler_stop.set()",
                "in_hold_samples = len(samples)",
                "await driver.stop(_STOP_GRACE)",
                "await poller.await_drain(timeout=1.0)",
                "await asyncio.sleep(_SETTLE)",
            ),
            "samples.append(final)",
            id="final-appended-before-the-sampler-stops",
        ),
        pytest.param(
            (
                "sampler_stop.set()",
                "await driver.stop(_STOP_GRACE)",
                "await poller.await_drain(timeout=1.0)",
                "await asyncio.sleep(_SETTLE)",
                "samples.append(final)",
                "in_hold_samples = len(samples)",
            ),
            # The check resumes each search where the last landmark matched, so it reports the first
            # landmark it cannot find AFTER the moved count -- the driver stop, not the count itself.
            "await driver.stop(_STOP_GRACE)",
            id="count-taken-after-the-final-is-appended",
        ),
    ],
)
def test_the_ordering_check_reports_a_landmark_that_moved(
    mutant: tuple[str, ...], offender: str
) -> None:
    """CONTROL for the ordering half, against the two mutants that matter.

    The first appends the final sample BEFORE `sampler_stop.set()`, which would make it genuinely
    in-hold. The second counts `in_hold_samples` AFTER the append, which would put the post-drain
    final back inside the rate window while every description says it is out. The check must reject
    both, and accept the real order."""
    assert first_out_of_order("\n".join(mutant), _ORDERING) == offender
    in_order = "\n".join(_ORDERING)
    assert first_out_of_order(in_order, _ORDERING) is None


def _engine_sample(elapsed: float, *, read: int, empty: int) -> EngineSample:
    return EngineSample(
        elapsed_s=elapsed,
        pending=0,
        inflight=0,
        done=0,
        dead=0,
        read=read,
        written=read,
        out_dead=0,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=elapsed,
        empty_claims=empty,
        empty_claims_idle_poll=empty,
    )


def _record_over(samples: list[EngineSample], in_hold_samples: int) -> ConnScaleRecord:
    poller = EnginePoller("http://127.0.0.1:1", token=None, origin=0.0)
    poller._samples = [samples[0], samples[-1]]
    return runner_module._build_record(
        claim_mode="per_lane",
        fuse_mode=False,
        batch_mode=False,
        mode="fixed_aggregate",
        count=4,
        aggregate_rate=10.0,
        metrics_counters=Counters(sent=samples[-1].read),
        ack_hist=Histogram(),
        poller=poller,
        samples=samples,
        in_hold_samples=in_hold_samples,
        in_hold_floor_ticks=0,
        proc_readings=[],
        drain_seconds=1.0,
        reload_seconds=None,
    )


def test_every_rate_is_computed_over_the_in_hold_slice_and_not_the_post_drain_final() -> None:
    """THE SLICE, measured on the record rather than read off the source.

    Three in-hold readings a second apart absorb 40 messages and 500 empty claims over 2 s, at an
    UNEVEN pace, so a slice off by one reading at either end gives a different number for every
    rate, the per-message ratio included. The post-drain final then lands 8 s later having absorbed
    5 more messages and 400 more empty claims: the idle-drain regime fix (a) exists to keep out. Every rate must come from the first
    three, and the numerator and denominator of `empty_claims_per_msg` must come from the SAME three.

    THE CONTROL ARM runs the same list with the count taken after the append, which is the mutant the
    ordering check above guards. It must move every number, or this test cannot tell the slice from
    no slice."""
    samples = [
        _engine_sample(0.0, read=0, empty=0),
        _engine_sample(1.0, read=10, empty=100),
        _engine_sample(2.0, read=40, empty=500),
        _engine_sample(10.0, read=45, empty=900),  # the post-drain final
    ]
    rec = _record_over(samples, in_hold_samples=3)
    # 40 messages and 500 empty claims over 2 s. `samples[:2]` would give 10/s, 100/s and 10.0 per
    # message; `samples[1:3]` 30/s, 400/s and about 13.3. Neither off-by-one passes any assert.
    assert rec.achieved_read_per_s == pytest.approx(20.0)
    assert rec.achieved_written_per_s == pytest.approx(20.0)
    assert rec.empty_claims_per_s == pytest.approx(250.0)
    assert rec.idle_poll_per_s == pytest.approx(250.0)
    assert rec.empty_claims_per_msg == pytest.approx(12.5)
    # The no-loss reconcile still sees the post-drain final: it reads `poller.final`, not the window.
    assert rec.no_loss.engine_read == 45

    tail_in = _record_over(samples, in_hold_samples=len(samples))
    assert tail_in.achieved_read_per_s == pytest.approx(4.5)
    assert tail_in.empty_claims_per_s == pytest.approx(90.0)
    assert tail_in.empty_claims_per_msg == pytest.approx(20.0)


def test_a_single_in_hold_reading_leaves_wall_3_undefined_rather_than_borrowing_the_final() -> None:
    """With one reading before the final there is no window. The rates must be the guards' zeros and
    the ratio `None`, NOT a number quietly computed against the post-drain final. This is the state
    the #1430 floor prevents. On a live run the smoke's per-step floor assertion catches it, and
    its `assert graded` is the run-level backstop."""
    samples = [
        _engine_sample(0.0, read=0, empty=0),
        _engine_sample(10.0, read=25, empty=900),  # the post-drain final
    ]
    rec = _record_over(samples, in_hold_samples=1)
    assert rec.achieved_read_per_s == 0.0
    assert rec.empty_claims_per_s == 0.0
    assert rec.empty_claims_per_msg is None


# --- the guard proper -----------------------------------------------------------------------------


def test_the_final_sample_is_appended_after_the_sampler_stops() -> None:
    """THE ORDERING HALF. `in_hold_samples` is counted after the sampler stops and before the
    post-drain final is appended, so `samples[:in_hold_samples]` excludes that final. If this reds,
    the code moved and the descriptions below need re-reading -- the fix is not to loosen this
    test."""
    source = inspect.getsource(_run_one_step)
    offender = first_out_of_order(source, _ORDERING)
    assert offender is None, (
        f"`_run_one_step` no longer runs {_ORDERING} in that order -- {offender!r} moved. "
        "The rate window's description assumes `in_hold_samples` is counted after the sampler stops "
        "and before the post-drain final is appended (BACKLOG #1420); re-read `_empty_claim_rates` "
        "before changing this."
    )
    assert source.count("samples.append(") == 1, (
        "a second `samples.append(` appeared in the step -- which sample ends the rate window is no "
        "longer obvious from the ordering, so the description cannot be checked against it"
    )


def test_the_window_is_defined_once_and_says_the_tail_is_outside_it() -> None:
    """THE DESCRIPTION HALF, at the single definition site (SDS-3.5). `_empty_claim_rates` is the one
    place BACKLOG #1420 allows to state the span; these are the claims it must keep making, and fix
    (b)'s claims that the tail is inside must not come back."""
    doc = " ".join((_empty_claim_rates.__doc__ or "").split())
    missing = [claim for claim in _DEFINITION_CLAIMS if claim not in doc]
    assert not missing, (
        f"`_empty_claim_rates` stopped saying {missing} -- it is the ONE place that defines the rate "
        "window, and every other site points here instead of restating it (BACKLOG #1420)"
    )
    reverted = [claim for claim in _RETIRED_DEFINITION_CLAIMS if claim in doc]
    assert not reverted, (
        f"`_empty_claim_rates` says {reverted} again. That was fix (b)'s wording, when the post-drain "
        "tail was inside the rates; since fix (a) it is outside them (BACKLOG #1420)"
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
        f"{offenders} describe the rate window as first-to-last IN-HOLD. Its last reading can be a "
        "make-up floor tick taken after the hold ended, so the window is not the hold (BACKLOG "
        "#1420, #1430). Point at `_empty_claim_rates` instead of restating the span."
    )


def test_the_corpus_actually_contains_the_files_this_guard_claims_to_cover() -> None:
    """A sweep over an empty corpus passes and means nothing. Pin that the scope BACKLOG #1420 states
    is really being read, and that the definition site is inside it."""
    files = _corpus_files()
    names = {p.name for p in files}
    assert len(files) >= 5, f"the connscale corpus collapsed to {sorted(names)}"
    for required in ("runner.py", "report.py", "test_connscale_empty_claims_per_msg.py"):
        assert required in names, f"{required} left the corpus this guard sweeps"
