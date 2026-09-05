# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""PHI redaction on the exception/logging path (WP-6c, ASVS 16.2.5 / PHI.md P1-3): redact() scrubs
HL7-shaped content; safe_exc() keeps the exception type while redacting + bounding the message."""

from __future__ import annotations

import re
import time

import pytest

from messagefoundry import redaction
from messagefoundry.redaction import redact, safe_exc, safe_text

ADT = (
    "MSH|^~\\&|SENDINGAPP|FAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "PID|1||100^^^H^MR||DOE^JANE||19800101|M\r"
)


def test_redact_scrubs_full_hl7_keeps_segment_ids() -> None:
    out = redact(ADT)
    assert "DOE" not in out and "JANE" not in out and "100^^^H^MR" not in out
    assert "MSH" in out and "PID" in out  # segment IDs kept (not PHI, useful)
    assert "[redacted]" in out


def test_redact_field_run_without_segment_header() -> None:
    # a component/field dump (≥2 HL7 delimiters) is redacted even without a segment header
    assert "DOE" not in redact("patient name was DOE^JANE^M today")
    assert redact("mrn 100^^^H^MR here") == "mrn [redacted] here"


def test_redact_passes_through_plain_text() -> None:
    assert redact("connection refused: timeout after 5s") == "connection refused: timeout after 5s"
    assert redact("") == ""


def test_safe_exc_keeps_type_and_redacts_body() -> None:
    out = safe_exc(ValueError(f"cannot parse {ADT}"))
    assert out.startswith("ValueError:")  # exception type preserved
    assert "DOE" not in out and "JANE" not in out


def test_safe_exc_truncates_long_messages() -> None:
    out = safe_exc(RuntimeError("x" * 5000), limit=50)
    assert len(out) < 120 and "(+" in out  # bounded + a truncation marker


def test_safe_exc_bare_exception_is_just_the_type() -> None:
    assert safe_exc(KeyError()) == "KeyError"


def test_safe_text_scrubs_and_bounds_free_text() -> None:
    # safe_text is the string analog of safe_exc (no type prefix) — used for the strict-validation
    # joined errors and the store-layer chokepoint (#120).
    out = safe_text(f"strict error near {ADT}")
    assert "DOE" not in out and "JANE" not in out and "100^^^H^MR" not in out
    long = safe_text("y" * 5000, limit=40)
    assert len(long) < 120 and "(+" in long


def test_safe_text_preserves_nonphi_diagnostics() -> None:
    # The field NAME / non-delimited diagnostic survives (operator diagnosability) — only HL7-field-
    # shaped values (a run of >=2 delimiters) are cut. So an hl7apy "invalid value for PID-3" keeps the
    # field reference while the offending component dump is redacted.
    scrubbed = safe_text("invalid value for field PID-3: 100^^^H^MR")
    assert scrubbed.startswith("invalid value for field PID-3:") and "100^^^H^MR" not in scrubbed
    assert safe_text("hl7 version 2.5.1 != expected 2.3") == "hl7 version 2.5.1 != expected 2.3"


def test_safe_text_is_idempotent_on_safe_exc_output() -> None:
    # The store-layer chokepoint (#120) may re-apply safe_text to an already-safe_exc'd value; it must
    # not reintroduce PHI or garble the type prefix (redact is a fixed point once delimiter runs are gone).
    once = safe_exc(ValueError(f"bad {ADT}"))
    twice = safe_text(once)
    assert twice.startswith("ValueError:") and "DOE" not in twice and "JANE" not in twice


# --- SEC-023: free-text (delimiter-less) PHI heuristic ---------------------------------------------


def test_redact_scrubs_free_text_name_and_dob() -> None:
    # A developer who writes a delimiter-free leak (no |^~&) — a name run + a DOB — is now narrowed:
    # the multi-token name run and the date are scrubbed even with no HL7 structure around them.
    out = redact("patient DOE JANE dob 1980-05-05 not found")
    assert "DOE JANE" not in out and "1980-05-05" not in out
    assert "[redacted]" in out


def test_redact_scrubs_hl7_birthdate_run() -> None:
    # A bare 8-digit HL7 YYYYMMDD birthdate carried in free text is redacted.
    assert "19800101" not in redact("dob 19800101 mismatch")


def test_redact_preserves_operational_text() -> None:
    # Single capitalized/CamelCase operational words and version strings must survive (no false redaction
    # that would garble ordinary ops diagnostics).
    assert redact("connection refused: timeout after 5s") == "connection refused: timeout after 5s"
    assert redact("ValueError raised in Handler archive") == "ValueError raised in Handler archive"
    assert redact("hl7 version 2.5.1 != expected 2.3") == "hl7 version 2.5.1 != expected 2.3"


def test_redact_is_fixed_point() -> None:
    # redact must be a fixed point (the store-layer re-apply chokepoint depends on it): scrubbing an
    # already-scrubbed string is a no-op. Cover both the new free-text path and the existing HL7 fixture.
    name_dob = "patient DOE JANE dob 1980-05-05 not found"
    assert redact(redact(name_dob)) == redact(name_dob)
    assert redact(redact(ADT)) == redact(ADT)


def test_safe_exc_redacts_free_text_phi() -> None:
    # safe_exc flows free-text exception messages through redact: the type is kept; the name run and the
    # date are gone.
    out = safe_exc(ValueError("patient DOE JANE dob 1980-05-05 not found"))
    assert out.startswith("ValueError:")
    assert "DOE JANE" not in out and "1980-05-05" not in out


# --- BACKLOG #1437: the field-run scan must stay linear ---------------------------------------------

#: The pre-fix pattern: possessive quantifiers, no ``(?<![^\s|^~&])`` lookbehind. This is what shipped
#: before #1437, and below it is the live positive control run through the real ``redact``.
#:
#: Controlling against THIS rather than the older non-possessive form is the point. The possessive-only
#: form is the half-fix: it is ~2x faster than fully unguarded and still quadratic. A control that only
#: a fully unguarded pattern could fail would leave a band in which the half-fix cleared both arms,
#: which is exactly the state #1437 found shipped and the old arm could not see.
_PRE_GUARD_FIELD_RUN = re.compile(r"[^\s|^~&]*+[|^~&][^\s|^~&]*+(?:[|^~&][^\s|^~&]*+)+")

#: Length of the delimiter-free run the cost arms measure.
#:
#: A base64 blob is exactly this shape. The base64 alphabet holds none of ``| ^ ~ &`` and no
#: whitespace, so an ``mfb64:v1:`` payload (ADR 0028) quoted into an exception message or a rendered
#: traceback is ONE token to this scan. 16,000 characters is a 12 KiB attachment, which is a small one.
#:
#: **The real input is not capped, so this is a floor on the worst case rather than the worst case.**
#: ``safe_text`` truncates AFTER ``redact`` has run, and the logging handler filter in
#: ``messagefoundry.logging_setup`` redacts whole rendered tracebacks with no bound at all.
_HOSTILE_RUN_CHARS = 16_000

#: The one line both cost arms are measured against, sitting between the two costs. The margins run in
#: OPPOSITE directions across it, which is why a single number does the work of two.
#:
#: **Above the line (the production arm) a stall turns a pass into a failure, so the margin is large:**
#: 93x against the worst of 15 samples measured 2026-09-03 (0.000537 s), and the estimate is best-of-5,
#: so a runner would have to stall for 50 ms five separate times inside a 0.5 ms window to fake a red.
#:
#: **Below the line (the control arm) a stall can only help, so the margin stays tighter:** 12.9x
#: against the BEST of 15 samples (0.643 s), and one sample is enough there because noise cannot
#: deflate it.
#:
#: **Deliberately one number rather than a ceiling plus a separate floor.** A floor beneath the ceiling
#: would open a band in which a half-fixed scan cleared both arms. Sharing the line makes the control
#: prove that this exact budget discriminates. If some future CPython makes the pre-guard scan fast
#: enough to slip under it, the control reds, which is the correct thing to be told: at that point the
#: instrument has stopped discriminating and the number needs re-deriving.
_SCAN_BUDGET_SECONDS = 0.05


def _hostile_free_text() -> str:
    """An exception-shaped message carrying one long delimiter-free run, the input the field-run scan
    is quadratic on.

    The run is built from the base64 alphabet rather than a repeated character so the fixture matches
    the shape that really reaches ``redact``. What makes it hostile is asserted in
    :func:`test_the_hostile_fixture_is_actually_hostile`, which every arm below depends on."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    blob = (alphabet * (_HOSTILE_RUN_CHARS // len(alphabet) + 1))[:_HOSTILE_RUN_CHARS]
    return f"cannot decode mfb64:v1:{blob} at offset 0"


def _longest_token(text: str) -> int:
    """Length of the longest run of characters the field-run scan treats as one token, i.e. carrying no
    delimiter and no whitespace. This is the ONLY property of an input that makes the scan expensive,
    so it is what an arm must assert about its fixture."""
    return max(len(run) for run in re.split(r"[\s|^~&]", text))


def _redact_seconds(reps: int) -> float:
    """Best-of-``reps`` seconds for the shipping ``redact`` on the hostile message.

    The MINIMUM is the noise-free estimate: a scheduling hiccup can only inflate a sample, never
    deflate one, so one slow slice on a loaded runner cannot fake a red."""
    text = _hostile_free_text()
    best = float("inf")
    for _ in range(reps):
        start = time.perf_counter()
        redaction.redact(text)
        best = min(best, time.perf_counter() - start)
    return best


def test_the_hostile_fixture_is_actually_hostile() -> None:
    """Non-vacuity for the two cost arms, and the whole reason #1437 exists.

    **The arm this replaced timed ``"A " * 5000`` against a 1.0 s bound.** Its longest token is ONE
    character, so no quantifier in the module has anything to backtrack or restart over: the pre-guard
    pattern, the shipped pattern and a deliberately broken one all finish that input in under a
    millisecond. The arm asserted a linear-scan property using an input on which every candidate is
    trivially linear, so from ``2a6693f33`` (2026-08-13) to #1437 it passed green over a quadratic
    scan.

    A cost arm is only as good as the token length of its fixture, so assert that directly."""
    hostile = _hostile_free_text()
    assert _longest_token(hostile) >= _HOSTILE_RUN_CHARS, (
        f"the fixture's longest delimiter-free token is {_longest_token(hostile)}, under the "
        f"{_HOSTILE_RUN_CHARS} the cost arms are calibrated against. A shorter token makes both arms "
        f"cheap and the budget stops measuring anything."
    )
    assert _longest_token("A " * 5000) == 1  # the replaced arm's input, for the record


def test_a_delimiter_free_run_stays_inside_the_scan_budget() -> None:
    """A long run carrying no ``| ^ ~ &`` must not cost the field-run scan quadratic time.

    ``redact`` is installed as a **logging handler filter** (``messagefoundry.logging_setup``), so it
    runs synchronously on whatever emitted the record, which for the engine is the asyncio event loop.
    Its input is a whole rendered traceback and is not bounded: ``safe_text``'s ``limit`` truncates
    AFTER ``redact`` has run. A quadratic scan here is a whole-engine stall, not a slow log line, and
    the run is attacker-influenceable because a Router or Handler can raise with a message built from
    the received body (ADR 0028 base64 carriage makes that body one token).

    **This replaced a one-sample wall-clock assertion, and both halves of it were wrong.** The old arm
    took a single sample of an input whose longest token was one character and compared it to a bare
    ``< 1.0`` literal. It could not fail for the reason it named, and it did not: measured 2026-09-03,
    the shipped scan cost **1.05 s** on a 20,000-character run while that arm passed in under a
    millisecond."""
    seconds = _redact_seconds(5)
    assert seconds < _SCAN_BUDGET_SECONDS, (
        f"redacting one {_HOSTILE_RUN_CHARS}-character delimiter-free run cost {seconds:.4f}s of the "
        f"event loop against a {_SCAN_BUDGET_SECONDS}s budget"
    )


def test_the_pre_guard_pattern_blows_that_same_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """Live positive control: the SAME message and the SAME budget, with the ``(?<![^\\s|^~&])``
    lookbehind removed from the shipping path.

    Without it the arm above is unfalsifiable. A budget nothing on this input could ever exceed would
    pass while measuring nothing, and so would a fixture that had quietly stopped being hostile, which
    is precisely how the replaced arm passed. This one patches the module global ``redact`` reads, so
    the whole shipping path runs pre-guard rather than a regex held off to one side.

    One rep, deliberately. The assertion is that the scan is SLOW, so noise moves it the safe way."""
    monkeypatch.setattr(redaction, "_HL7_FIELD_RUN", _PRE_GUARD_FIELD_RUN)
    seconds = _redact_seconds(1)
    assert seconds > _SCAN_BUDGET_SECONDS, (
        f"the pre-guard pattern redacted the hostile run in {seconds:.4f}s, inside the "
        f"{_SCAN_BUDGET_SECONDS}s budget. The budget no longer separates a linear scan from a "
        f"quadratic one, so the arm above is not measuring anything"
    )


@pytest.mark.parametrize(
    "line",
    [
        "MSH|^~\\&|SENDINGAPP|FAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1",
        "PID|1||100^^^H^MR||DOE^JANE||19800101|M",
        "OBX|1|NM|GLU^Glucose^L||99|mg/dL|70-110|N|||F",
        "patient name was DOE^JANE^M today",
        "mrn 100^^^H^MR here",
        "invalid value for field PID-3: 100^^^H^MR",
        "hl7apy: bad value (100^^^H^MR) in ADT_A01",
        "connection refused: timeout after 5s",
        "hl7 version 2.5.1 != expected 2.3",
        "abc|def",  # one delimiter: below the >=2 threshold, must stay untouched
        "a|b|c",
        "a|b|c|d e|f|g",
        "x^y trailing^ ^leading",
        "\tx|y|z\n",
        "^^^",
        "|",
        "[redacted]",
        "no-delims-at-all",
    ],
)
def test_the_linear_scan_guard_does_not_change_what_is_redacted(line: str) -> None:
    """The ``(?<![^\\s|^~&])`` guard must be a pure performance change.

    The lookbehind is the exact complement of the character class that follows it, so it can only
    forbid starts that could never have produced a different span. That is an argument, not evidence,
    and this is a PHI control, so pin the behaviour against the pattern it replaced. A ``\\b`` guard
    would have been the tempting spelling and would NOT be equivalent: ``-``, ``.`` and ``:`` are word
    boundaries but also live inside ``[^\\s|^~&]``, so ``\\b`` would drop them from the front of a
    redacted span."""
    assert redaction._HL7_FIELD_RUN.sub("[redacted]", line) == _PRE_GUARD_FIELD_RUN.sub(
        "[redacted]", line
    )
