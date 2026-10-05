# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""PHI redaction on the exception/logging path (WP-6c, ASVS 16.2.5 / PHI.md P1-3): redact() scrubs
HL7-shaped content; safe_exc() keeps the exception type while redacting + bounding the message;
safe_name() derives a safe label for a partner-chosen file name, which redact() is measured blind to
(BACKLOG #1748)."""

from __future__ import annotations

import http.client
import logging
import random
import re
import time
from collections.abc import Callable
from typing import Any, SupportsIndex

import pytest
from _phi_log_capture import IDENTIFIER_SHAPED_NAMES, SAFE_NAME_SUFFIXES

from messagefoundry import logging_setup, redaction, secretscrub
from messagefoundry.redaction import (
    clamp_untrusted,
    redact,
    redact_untrusted,
    safe_error,
    safe_exc,
    safe_name,
    safe_text,
)

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
#: **The real input IS capped now, at ``_REDACT_WINDOW`` (BACKLOG #1576), and this fixture sits under
#: that cap on purpose.** It used to be a floor on the worst case rather than the worst case, because
#: ``safe_text`` truncated AFTER ``redact`` had run and the logging handler filter redacted whole
#: rendered tracebacks with no bound at all. Both clamp their input first now, so the worst case a
#: pattern here can be charged is one window — and 16,000 characters is a quarter of one, which keeps
#: these arms measuring the SCAN rather than the bound that now precedes it. Raising this above the
#: window would silently convert them into tests of ``_clamp``.
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


def _best_of(work: Callable[[], object], reps: int = 3) -> float:
    """Best-of-``reps`` seconds for ``work``.

    The MINIMUM is the noise-free estimate: a scheduling hiccup can only inflate a sample, never
    deflate one, so one slow slice on a loaded runner cannot fake a red. Every cost arm in this file
    shares it, so the sampling rule is argued once and a change to it lands everywhere."""
    best = float("inf")
    for _ in range(reps):
        start = time.perf_counter()
        work()
        best = min(best, time.perf_counter() - start)
    return best


def _redact_seconds(reps: int) -> float:
    """Best-of-``reps`` seconds for the shipping ``redact`` on the hostile message."""
    text = _hostile_free_text()
    return _best_of(lambda: redaction.redact(text), reps)


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
    A quadratic scan here is a whole-engine stall, not a slow log line, and the run is
    attacker-influenceable because a Router or Handler can raise with a message built from the received
    body (ADR 0028 base64 carriage makes that body one token).

    The input is bounded to one window before it reaches this scan now (BACKLOG #1576), so a quadratic
    scan would cost a window rather than a frame cap. That is a smaller stall, not an acceptable one —
    a window of the shape below is 64 KiB, sixteen times this fixture — which is why the guard #1437
    put in stays and this arm stays with it.

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


# --- BACKLOG #1572: read the delimiters MSH declares, do not assume them ----------------------------

#: A message whose FIELD separator is custom (``*``) but whose encoding characters are the defaults
#: (``^~\&``). The MSH segment still carries ``^``, ``~`` and ``&``, so the hardcoded field-run pattern
#: fires on that one line by coincidence and the header looks scrubbed. The PID segment carries no
#: default delimiter at all, so its identifiers walk straight through.
#:
#: **Calibrate to the fixture below, not to this one.** The BACKLOG row's own example had this shape
#: and therefore understated the defect.
ADT_CUSTOM_FIELD_SEP = (
    "MSH*^~\\&*SENDINGAPP*FAC*RECV*RFAC*20260604**ADT^A01*MSG1*P*2.5.1\r"
    "PID*1**MRN12345*DOE*JANE*19800101*M\r"
)

#: A message whose encoding characters are custom TOO (``$`` component, ``@`` repetition, ``#`` escape,
#: ``%`` subcomponent). Nothing here contains ``| ^ ~ &``, so before #1572 the only thing the redactor
#: removed was the 8-digit date run: the record identifier, the surname and the given name all survived
#: ``safe_exc``, the installed four-filter logging chain, and the support-bundle redactor.
ADT_FULLY_CUSTOM = (
    "MSH*$@#%*SENDINGAPP*FAC*RECV*RFAC*20260604**ADT$A01*MSG1*P*2.5.1\r"
    "PID*1**MRN12345$$$H$MR**DOE$JANE**19800101*M\r"
)

#: The synthetic identifiers both fixtures carry. No real PHI (PHI.md §9).
_CUSTOM_IDENTIFIERS = ("MRN12345", "DOE", "JANE")

#: Ordinary operational text a redactor must never touch, and the reason this fix SNIFFS rather than
#: widening :data:`~messagefoundry.redaction._HL7_FIELD_RUN`'s character class. Widening it to cover
#: ``*``/``$``/``@``/``%`` costs almost nothing in CPU and scrubs every line below, wrecking the two
#: artefacts designed to leave the box (the support bundle and the forwarded log stream).
_OPERATIONAL_LINES = (
    "2026-09-11T04:12:07Z INFO     messagefoundry.pipeline: IB_ACME_ADT started",
    "loaded config from C:/ProgramData/MessageFoundry/config/connections.toml",
    "GET https://fhir.example.org/Patient?identifier=urn:oid:1.2.3 -> 200 in 41ms",
    "connect 192.0.2.10:2575 failed: WinError 10061",
    "retry 3/5 scheduled at 04:12:37 (backoff 2.5s)",
    "ValueError raised in Handler archive",
    "hl7 version 2.5.1 != expected 2.3",
)


def _pre_sniff_redact(text: str) -> str:
    """``redact`` exactly as it shipped BEFORE #1572: the four hardcoded-delimiter passes, in order.

    This is the byte-identity control. The fix must add a pass that fires only when MSH declares a
    delimiter outside ``| ^ ~ &``; on everything else the output has to be unchanged down to the byte,
    or the fix has quietly become the character-class widening it was chosen instead of."""
    if not text:
        return text
    scrubbed = redaction._HL7_SEGMENT.sub(lambda m: f"{m.group(1)}|[redacted]", text)
    scrubbed = redaction._HL7_FIELD_RUN.sub("[redacted]", scrubbed)
    scrubbed = redaction._DATE_RUN.sub("[redacted]", scrubbed)
    return redaction._NAME_RUN.sub("[redacted]", scrubbed)


def _custom_delimiter_message(segments: int) -> str:
    """A fully-custom-delimiter message of ``segments`` OBX segments, for the cost arm. Long, one
    whitespace-free token per line -- the shape the separator-aware scan is measured against."""
    header = "MSH*$@#%*SENDINGAPP*FAC*RECV*RFAC*20260604**ORU$R01*MSG1*P*2.5.1\r"
    body = "".join(
        f"OBX*{i}*NM*GLU$Glucose$L**99*mg/dL*70-110*N***F\r" for i in range(1, segments + 1)
    )
    return header + body


@pytest.mark.parametrize("message", [ADT_CUSTOM_FIELD_SEP, ADT_FULLY_CUSTOM])
def test_redact_scrubs_a_custom_delimiter_message(message: str) -> None:
    """Both custom-delimiter shapes: the identifiers must be gone, the segment IDs must stay.

    A deploying site with a custom-delimiter feed would otherwise have these reach its logs whenever a
    Router or Handler raised carrying the body."""
    out = redact(message)
    for identifier in _CUSTOM_IDENTIFIERS:
        assert identifier not in out, f"{identifier!r} survived redaction of {message!r}"
    assert "PID" in out and "[redacted]" in out  # segment IDs kept (not PHI, useful)


@pytest.mark.parametrize("message", [ADT_CUSTOM_FIELD_SEP, ADT_FULLY_CUSTOM])
def test_safe_exc_scrubs_a_custom_delimiter_message(message: str) -> None:
    """The realistic vector, end to end: user code raises with the body interpolated in."""
    out = safe_exc(ValueError(f"cannot transform {message}"), limit=10_000)
    assert out.startswith("ValueError:")
    for identifier in _CUSTOM_IDENTIFIERS:
        assert identifier not in out


@pytest.mark.parametrize("message", [ADT_CUSTOM_FIELD_SEP, ADT_FULLY_CUSTOM])
def test_the_support_bundle_redactor_scrubs_a_custom_delimiter_message(message: str) -> None:
    """The support path (``messagefoundry.support.redact``) delegates its PHI pass to ``redact``, so it
    inherits the fix. Pinned here because a support bundle is one of the two artefacts designed to
    leave the box, and it reads a log line at a time."""
    from messagefoundry.support.redact import redact_log_line

    out = redact_log_line(f"ERROR pipeline: cannot transform {message}")
    for identifier in _CUSTOM_IDENTIFIERS:
        assert identifier not in out


@pytest.mark.parametrize("message", [ADT_CUSTOM_FIELD_SEP, ADT_FULLY_CUSTOM])
def test_redact_is_a_fixed_point_on_a_custom_delimiter_message(message: str) -> None:
    """``safe_text`` re-applies ``redact`` at the store-layer chokepoint, so the separator-aware pass
    must not keep rewriting its own output. The second pass sniffs an already-scrubbed MSH, finds no
    delimiter declaration, and does nothing."""
    assert redact(redact(message)) == redact(message)


@pytest.mark.parametrize(
    "line",
    [
        *_OPERATIONAL_LINES,
        ADT,
        "MSH|^~\\&|SENDINGAPP|FAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1",
        "PID|1||100^^^H^MR||DOE^JANE||19800101|M",
        "patient DOE JANE dob 1980-05-05 not found",
        "mrn 100^^^H^MR here",
        "abc|def",
        "a|b|c",
        "[redacted]",
        "no-delims-at-all",
        "",
        # Prose that MENTIONS a segment id. A looser sniff read a delimiter set out of these and
        # over-redacted the line -- measured against this module's own docstrings while building the
        # fix, and the reason the encoding-characters field is pinned to its conformant width.
        "#: a 3-char segment ID (``MSH``/``PID``/``OBX``) followed by the field separator",
        "the delimiters are **read from MSH** rather than assumed",
        "see MSH-1 and MSH-2, at the offsets HL7 declares them",
        "MSH||A|B",  # a degenerate empty MSH-2: nothing to recover, and all defaults anyway
    ],
)
def test_the_separator_sniff_leaves_default_delimiter_output_byte_identical(line: str) -> None:
    """The sniff must be inert on everything that does not declare a non-default delimiter.

    This is the arm that fails if someone reaches for the obvious fix and widens the hardcoded
    character class instead. Widening scrubs ISO timestamps, ``C:/`` paths, ``https://`` URLs and
    ``host:port`` out of ordinary operational text; sniffing cannot, because the extra pass never runs
    on text with no custom-delimiter MSH in it."""
    assert redact(line) == _pre_sniff_redact(line)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("MSH|^~\\&|A|B", frozenset("|^~&")),  # the defaults, read rather than assumed
        ("MSH|^~\\&#|A|B", frozenset("|^~&")),  # 2.7 truncation char is not a field boundary
        ("MSH*$@#%*A*B", frozenset("*$@%")),  # fully custom; the escape char (#) is skipped
        ("MSH*^~\\&*A*B", frozenset("*^~&")),  # custom field separator, default encoding chars
        ("BHS+$@#%+A", frozenset("+$@%")),  # a batch header declares the same delimiters
        ("no header here at all", frozenset()),  # the headerless residual
        ("the delimiters are **read from MSH** rather than assumed", frozenset()),
    ],
)
def test_the_sniff_reads_what_the_header_declares(text: str, expected: frozenset[str]) -> None:
    """Isolates the sniff from the passes that consume it, so a regression in either is visible."""
    assert redaction._sniff_delimiters(text) == expected


def test_disabling_the_sniff_restores_the_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    """Live negative control, and the reason the arms above are not vacuous.

    With the sniff stubbed out to find nothing, the separator-aware pass never runs and the fully-custom
    fixture leaks every identifier again -- while the default-delimiter output is unchanged either way.
    That pairing is the whole claim: the new pass is what closes #1572, and it is doing nothing at all
    to the default path."""
    monkeypatch.setattr(redaction, "_sniff_delimiters", lambda text: frozenset())
    leaked = redaction.redact(ADT_FULLY_CUSTOM)
    for identifier in _CUSTOM_IDENTIFIERS:
        assert identifier in leaked, (
            f"{identifier!r} was scrubbed with the sniff disabled, so something OTHER than the "
            f"separator-aware pass is removing it and the arms above are not measuring the fix"
        )
    assert redaction.redact(ADT) == _pre_sniff_redact(ADT)


def test_the_separator_sniff_stays_inside_the_scan_budget() -> None:
    """Cost, on the two inputs that matter: a block of ordinary operational text carrying no MSH (the
    sniff runs and finds nothing) and a long fully-custom message (the sniff runs and the extra pass
    fires). Both share the ``_SCAN_BUDGET_SECONDS`` line the #1437 arms use, and best-of-5 for the same
    reason: a scheduling hiccup can only inflate a sample."""
    ops_block = "\n".join(_OPERATIONAL_LINES * 40)  # about 10 KB, no MSH anywhere
    assert len(ops_block) > 9_000
    custom = _custom_delimiter_message(300)

    for label, text in (("ops text", ops_block), ("300-segment custom message", custom)):
        best = _best_of(lambda text=text: redact(text), 5)  # type: ignore[misc]
        assert best < _SCAN_BUDGET_SECONDS, (
            f"redacting {len(text)} characters of {label} cost {best:.4f}s of the event loop against "
            f"a {_SCAN_BUDGET_SECONDS}s budget"
        )

    assert "MRN12345" not in redact(custom) and "Glucose" not in redact(custom)


def test_a_headerless_custom_delimiter_fragment_is_an_accepted_residual() -> None:
    """DOCUMENTED RESIDUAL, pinned so a future change to it is deliberate.

    The sniff reads MSH-1 and MSH-2. A fragment carrying custom delimiters but no MSH header declares
    nothing, so there is no delimiter set to recover and it passes through. This fix does NOT claim
    completeness: the "never put PHI in an exception message" convention remains the control for a
    headerless fragment, exactly as it does for a bare single-token identifier.

    The fixture read ``mrn MRN123$$$H$MR here`` until BACKLOG #2079, whose labelled-MRN pass now
    scrubs the value after that ``mrn`` label. That is a different pass reaching it, not the sniff, so
    the fixture lost its label to keep pinning what it was written for; the labelled form is pinned
    beside it."""
    assert redact("id MRN123$$$H$MR here") == "id MRN123$$$H$MR here"
    assert redact("mrn MRN123$$$H$MR here") == "mrn [redacted]$$$H$MR here"


# --- safe_name: a partner-chosen FILE NAME (BACKLOG #1748) --------------------


@pytest.mark.parametrize("name", IDENTIFIER_SHAPED_NAMES)
def test_redact_is_blind_to_an_identifier_shaped_file_name(name: str) -> None:
    """The measurement this fix rests on, pinned so it cannot quietly change meaning.

    ``_NAME_RUN`` needs ``\\s+`` between its tokens and ``_DATE_RUN`` needs a word boundary before the
    digits; a file name supplies neither, so all three of these pass through untouched. The control
    below proves the same chain is not simply inert."""
    line = f"file {name} exceeds max_file_bytes (10); routing to error dir"
    assert redact(line) == line


def test_redact_control_a_whitespace_name_with_a_delimited_date_is_caught() -> None:
    """The positive control for the test above. Without it, ``redact(line) == line`` would be equally
    consistent with a redactor that had stopped working altogether."""
    line = "file DOE JANE 1980-05-05.hl7 exceeds max_file_bytes (10); routing to error dir"
    out = redact(line)
    assert "DOE JANE" not in out and "1980-05-05" not in out
    assert out.count("[redacted]") == 2


@pytest.mark.parametrize("name", IDENTIFIER_SHAPED_NAMES)
def test_safe_name_drops_every_identifier_shape(name: str) -> None:
    label = safe_name(name)
    assert name not in label
    for token in ("MRN123456789", "DOE", "JANE", "19800505", "100001"):
        assert token not in label
    assert re.fullmatch(r"\[name:[0-9a-f]{12}\.hl7\]", label)


def test_safe_name_is_stable_and_distinguishing() -> None:
    """Both halves are the point: stable, so an operator recognises the same stuck file across polls;
    distinguishing, so two files in one directory are not one line."""
    assert safe_name("a.hl7") == safe_name("a.hl7")
    assert safe_name("a.hl7") != safe_name("b.hl7")


def test_safe_name_keeps_a_double_extension_so_the_gzip_mode_stays_legible() -> None:
    assert safe_name("msg1.hl7.gz").endswith(".hl7.gz]")


@pytest.mark.parametrize(
    ("name", "expected_suffix"),
    [
        ("patient.MRN123456789", "]"),  # not a format marker, so nothing is carried through
        ("drop.2026_MRN00042", "]"),  # nor this
        ("plainname", "]"),  # no extension at all
        ("msg.HL7", ".hl7]"),  # recognised case-insensitively, emitted lower-cased
        ("msg.hl7", ".hl7]"),
    ],
)
def test_safe_name_only_carries_a_known_format_marker(name: str, expected_suffix: str) -> None:
    """The extension is the one part of a partner's name that passes through, so it is an allowlist."""
    assert safe_name(name).endswith(expected_suffix)


# --- the suffix allowlist: a length bound let a dotted identifier through (BACKLOG #1748) ------
#
# Measured on the pre-fix `_SAFE_SUFFIX = re.compile(r"\.[A-Za-z0-9]{1,8}\Z")`: any segment of eight
# or fewer alphanumerics qualified as an "extension", and a dotted identifier is exactly that. Nine
# characters failed the bound and eight passed it, so it separated a long identifier from a short one
# rather than an identifier from an extension. Each value below is SYNTHETIC.

#: A partner-chosen name whose trailing dotted segment is an identifier, paired with the fragment the
#: pre-fix code carried into the log line. Reverting the allowlist turns every one of these red.
LEAKED_DOTTED_IDENTIFIERS = [
    ("ACC.12345678.hl7", "12345678"),  # an 8-digit accession
    ("patient.MRN12345.hl7", "MRN12345"),  # an MRN token
    ("DOE.19800505.hl7", "19800505"),  # a birthdate `_DATE_RUN` exists to catch
    ("A.87654321.txt", "87654321"),
]

#: Names the product itself builds or ingests, whose marker MUST still reach the log line. These are
#: the control arm: they pass before and after the fix, so a red one means the fix over-reached.
KEPT_FORMAT_MARKERS = [
    ("report.hl7.gz", ".hl7.gz]"),  # the FILE destination's own gzip-mode name
    ("x.dcm", ".dcm]"),
    ("scan.xml", ".xml]"),
    ("note.txt", ".txt]"),
    ("msg1.hl7", ".hl7]"),
]


@pytest.mark.parametrize(("name", "leaked"), LEAKED_DOTTED_IDENTIFIERS)
def test_safe_name_drops_a_dotted_identifier_that_a_length_bound_admitted(
    name: str, leaked: str
) -> None:
    """A dotted segment is kept only when it IS a format marker, so an identifier that happens to be
    short contributes nothing. On a first deployment the pre-fix code would have written the fragment
    asserted absent here into the general application log."""
    label = safe_name(name)
    assert leaked not in label
    # And what IS kept is the real marker, not simply everything dropped.
    assert label.endswith(f".{name.rsplit('.', 1)[-1]}]")


@pytest.mark.parametrize(("name", "expected_suffix"), KEPT_FORMAT_MARKERS)
def test_safe_name_keeps_the_format_markers_the_product_reads_and_writes(
    name: str, expected_suffix: str
) -> None:
    """The compatibility arm of the control above. ``.hl7.gz`` is the load-bearing one: the FILE
    destination appends ``.gz`` to the rendered name in gzip mode, so collapsing it to ``.gz`` would
    lose which format the operator is looking at."""
    assert safe_name(name).endswith(expected_suffix)


def test_safe_name_suffix_is_a_literal_from_the_allowlist_never_partner_bytes() -> None:
    """The property the length bound could not state: the label's suffix is a concatenation of at most
    two literals from a fixed set, so nothing a partner chose survives the digest — not even a segment
    that looks like an extension."""
    for name, _ in [*LEAKED_DOTTED_IDENTIFIERS, ("weird.MRN1.Z9", "")]:
        suffix = safe_name(name).removeprefix("[name:")[12:].removesuffix("]")
        parts = [f".{p}" for p in suffix.split(".") if p]
        assert len(parts) <= redaction._SAFE_SUFFIX_MAX
        assert all(p in redaction._SAFE_SUFFIXES for p in parts)


def test_safe_name_allowlist_covers_every_format_the_engine_discriminates() -> None:
    """The drift gate the allowlist's own comment promises. ``redaction`` is pure stdlib by design and
    cannot import ``parsing``, so the entries are duplicated literals; this asserts the duplication
    stays a superset of the source maps rather than silently falling behind one."""
    from messagefoundry.parsing import sniff
    from messagefoundry.uploads import _ALLOWED_UPLOAD_EXTENSIONS

    for source in (
        sniff._EXTENSION_CONTENT_TYPE,
        sniff._EXTENSION_MAGIC,
        _ALLOWED_UPLOAD_EXTENSIONS,
    ):
        assert set(source) <= redaction._SAFE_SUFFIXES


def test_log_capture_helper_marker_list_matches_the_allowlist() -> None:
    """``_phi_log_capture`` keeps its own copy of the markers on purpose — it decides what is stripped
    out of a log line before that line is scanned for an identifier, so deriving it from the module it
    is grading would let a widened allowlist widen the strip. Independent, but not free to rot."""
    assert {f".{s}" for s in SAFE_NAME_SUFFIXES} == redaction._SAFE_SUFFIXES


def test_safe_name_takes_the_basename_so_a_path_never_leaks() -> None:
    """Callers pass a basename today, but a directory component can itself embed an identifier, so the
    helper is total rather than trusting its callers."""
    label = safe_name("/drops/MRN123456789/ADT_DOE_JANE.hl7")
    assert "MRN123456789" not in label and "DOE" not in label
    assert safe_name("C:\\drops\\ADT_DOE_JANE.hl7") == safe_name("ADT_DOE_JANE.hl7")


@pytest.mark.parametrize("name", [*IDENTIFIER_SHAPED_NAMES, "msg1.hl7.gz", "plainname"])
def test_safe_name_output_survives_the_redactor_unchanged(name: str) -> None:
    """The label is emitted INTO a log line the RedactionFilter then redacts. If ``redact`` ate part of
    it, the operator would lose the correlation the label exists to give."""
    label = safe_name(name)
    assert redact(label) == label


@pytest.mark.parametrize("name", IDENTIFIER_SHAPED_NAMES)
def test_safe_exc_file_name_swaps_the_name_out_of_the_exception_message(name: str) -> None:
    """An OSError renders its path INTO its message, so routing a file source's error arm through
    ``safe_exc`` alone would keep the name. This is the half of #1748 that the call-site swap to
    ``safe_name`` does not reach on its own."""
    exc = OSError(f"[WinError 32] file in use: 'C:\\\\drops\\\\{name}'")
    out = safe_exc(exc, file_name=name)
    assert name not in out
    assert out.startswith("OSError:")  # the type survives
    assert "WinError 32" in out  # and so does the OS diagnostic, which is the point of keeping it
    assert safe_name(name) in out


def test_safe_exc_without_file_name_is_unchanged() -> None:
    """The parameter is opt-in: every existing caller keeps its exact rendering."""
    exc = ValueError("patient DOE JANE dob 1980-05-05 not found")
    assert safe_exc(exc, file_name=None) == safe_exc(exc)


def test_safe_exc_file_name_covers_a_bare_basename_too() -> None:
    """A remote client quotes the name without a directory; the swap must still fire."""
    out = safe_exc(
        OSError("550 no such file: MRN123456789_ADT.hl7"), file_name="MRN123456789_ADT.hl7"
    )
    assert "MRN123456789" not in out and "550" in out


def test_safe_name_is_exported() -> None:
    assert "safe_name" in redaction.__all__


# --- safe_error: the optional, opt-in-gated form the CLI surfaces use (BACKLOG #1668) -------------


def test_safe_error_passes_none_through() -> None:
    """An absent error is not a value to redact -- the CLIs emit it as JSON ``null``, not ``""``."""
    assert safe_error(None) is None
    assert safe_error(None, show_phi=True) is None


def test_safe_error_redacts_by_default_and_keeps_the_prose() -> None:
    """The stage prefix and the author's own words survive; only the HL7-shaped runs collapse.

    That is the whole reason this is ``safe_text`` and not a whole-string drop: the diagnostic is what
    somebody ran ``dryrun`` to read."""
    raised = "router/handler error: unmapped patient DOE^JANE^Q mrn 900123456^^^H^MR"
    out = safe_error(raised)
    assert out is not None
    assert "DOE" not in out and "900123456" not in out
    assert out.startswith("router/handler error: unmapped patient ")


def test_safe_error_show_phi_returns_the_text_unchanged() -> None:
    """The opt-in arm is byte-identical -- a caller that may see it gets exactly what was raised."""
    raised = "router/handler error: unmapped patient DOE^JANE^Q"
    assert safe_error(raised, show_phi=True) == raised


def test_safe_error_defaults_closed() -> None:
    """A surface with no opt-in (the ``check`` gate) passes no keyword, so the default must redact."""
    raised = "parse error: PID|1||900123456^^^H^MR"
    assert safe_error(raised) == safe_error(raised, show_phi=False)
    assert "900123456" not in str(safe_error(raised))


def test_safe_error_is_exported() -> None:
    assert "safe_error" in redaction.__all__


# --- bounding the input: clamp_untrusted (BACKLOG #1576) ----------------------

#: A filler token carrying no delimiter, no digit and no name shape, so a fixture built from it
#: measures the BOUND and nothing else. Whitespace between the tokens is the point: it gives ``_clamp``
#: real boundaries to cut at, which is the case an operator actually sees. A fixture of one solid run
#: has no boundary anywhere and is dropped whole, which passes every leak arm below vacuously.
_FILLER = "ordinary-ops-filler "


def _filler(chars: int) -> str:
    return (_FILLER * (chars // len(_FILLER) + 1))[:chars]


def _over_window(tail: str) -> str:
    """Filler plus ``tail``, sized so the window's cut falls inside ``tail``.

    **The cut is not at ``_REDACT_WINDOW``, and sizing to that number is how this helper silently
    stopped positioning anything.** ``clamp_untrusted`` reserves ``_CLAMP_MARKER_BUDGET`` for its note
    and takes it off the CUT, so the real boundary is 74 characters earlier. Sized to the window
    instead, every fixture's tail began after the cut and was dropped wholesale: the token walk never
    ran, ``_ends_with_name_token`` never returned True anywhere in this suite, and the two arms that
    name the walk asserted absence for the wrong reason. Both numbers are read from the module rather
    than restated, so moving either moves this.

    The tail ends ON the boundary, so the cut lands at its last whitespace. The trailing run is
    non-whitespace on purpose: it carries the string past the window -- without it a budget-aware
    fixture is under the window and is not clamped at all -- while offering no later place to cut."""
    cut = redaction._REDACT_WINDOW - redaction._CLAMP_MARKER_BUDGET
    assert any(char in redaction._CUT_CHARS for char in tail), (
        f"{tail!r} holds no whitespace, so the cut cannot land inside it and this fixture would "
        f"position nothing"
    )
    return _filler(cut - len(tail)) + tail + "Q" * redaction._REDACT_WINDOW


def test_the_fence_a_naive_prefix_truncation_leaks_the_name() -> None:
    """THE MEASUREMENT THE WHOLE DESIGN RESTS ON, pinned so nobody "simplifies" ``_clamp`` back into
    ``text[:window]``.

    ``redact(text[:window])`` is the obvious bound and it is the wrong one. The cut lands inside a
    field run, the surviving fragment carries ONE delimiter where ``_HL7_FIELD_RUN`` needs two, and the
    surname walks through into the log. This arm asserts the leak on the SHIPPED redactor, so it is a
    statement about the pattern rather than about a strawman."""
    window = redaction._REDACT_WINDOW
    leaky = _filler(window - 4) + " DOE^JANE^M trailing"
    assert "DOE" in redact(leaky[:window]), (
        "the naive truncation no longer strands a fragment, so the fence this design was built "
        "against has moved and _clamp's extra work needs re-justifying"
    )


def test_clamp_closes_the_fence_it_was_built_against() -> None:
    """The positive half of the arm above: the same input, through the shipped bound, keeps nothing."""
    window = redaction._REDACT_WINDOW
    leaky = _filler(window - 4) + " DOE^JANE^M trailing"
    assert "DOE" not in redact(clamp_untrusted(leaky))


def test_the_over_window_fixture_really_puts_the_cut_inside_the_tail() -> None:
    """THE POSITIVE CONTROL for every arm ``_over_window`` builds, and the one this file was missing.

    Sized to ``_REDACT_WINDOW`` rather than to the boundary the clamp actually uses, the helper put
    every tail 74 characters PAST the cut. The tail was dropped wholesale, the token walk never ran,
    and each absence arm below passed for a reason that had nothing to do with what it names. **An
    absence assertion cannot tell a working walk from a fixture that never reached it**, so the
    position is asserted here, in two lines that fail when it moves: the cut lands inside the tail,
    and the walk then actually fires."""
    tail = " DOE JANE tail"
    text = _over_window(tail)
    tail_start = len(text) - redaction._REDACT_WINDOW - len(tail)
    assert text[tail_start : tail_start + len(tail)] == tail
    assert len(text) > redaction._REDACT_WINDOW, "the fixture is not over the window at all"

    cut = redaction._last_cut(text, redaction._REDACT_WINDOW - redaction._CLAMP_MARKER_BUDGET)
    assert cut > tail_start, (
        f"the cut landed at {cut}, before the tail at {tail_start}: the fixture drops its tail "
        f"wholesale and every arm built on it is vacuous"
    )
    assert redaction._drop_trailing_name_tokens(text, cut) < cut, (
        "the cut is inside the tail but the walk dropped nothing, so _ends_with_name_token still "
        "never returns True in this suite"
    )


def test_clamp_does_not_strand_a_name_run_split_by_the_cut() -> None:
    """``_NAME_RUN`` spans whitespace, so a whitespace cut alone can still strand it: ``DOE JANE`` cut
    between its tokens leaves ``DOE`` under the two-token threshold. The token walk drops the
    neighbours whole. It is not the only such pattern in the module -- ``_CUT_CHARS`` names the other
    and the test to apply to a new one."""
    out = redact(clamp_untrusted(_over_window(" DOE JANE SMITH tail")))
    assert "DOE" not in out and "JANE" not in out and "SMITH" not in out


def test_the_walk_does_not_strand_a_name_the_unbounded_redactor_scrubs() -> None:
    """THE ARM THE WALK WAS REBUILT FOR: clamping must never keep a token that not clamping scrubs.

    The walk used to stop after a fixed three tokens, on the reasoning that ``_NAME_RUN`` joins at
    most four and the cut consumes one. **Dropping a token strands its own left partner**, which was
    over the two-token threshold only because of the token just dropped, so no fixed budget is a fixed
    point. Four name tokens behind the cut is the smallest case that shows it: the walk spent its
    three steps on ``ROE``, ``JANE`` and ``DOE``, and ``SMITH`` was left standing alone -- kept by the
    bound, scrubbed without it.

    The third assertion is the direction that must not regress: the fix is the clamped path catching
    up to the unbounded one, never the unbounded one being loosened to agree with it."""
    text = _over_window(" SMITH DOE JANE ROE ")

    assert "SMITH" not in redact(text), (
        "the unbounded redactor no longer scrubs this run, so the arm below cannot distinguish a "
        "closed leak from a fixture the redactor was never going to catch"
    )
    assert "SMITH" not in redact(clamp_untrusted(text))
    assert "SMITH" not in safe_text(text, limit=100_000)


def test_clamp_steps_over_a_whitespace_run_between_name_tokens() -> None:
    """``_NAME_RUN`` joins its tokens with ``\\s+``, so the walk has to step over a whitespace RUN. A
    walk that stopped on the empty token inside one would leave ``JANE`` standing."""
    out = redact(clamp_untrusted(_over_window(" patient JANE   SMITHTAIL")))
    assert "JANE" not in out


# --- bounding the input: a credential span the cut broke (BACKLOG #1576, #1793) ---

#: A synthetic password head for the arms below. **Lowercase-led and digit-tailed on purpose.** An
#: ALLCAPS or Capitalized head is dropped by the NAME walk, so a fixture built from one would pass
#: every arm here whether the credential walk existed or not.
_PASSWORD_HEAD = "pw0rdhead1"


def _split_credential_over_window() -> str:
    """An ``http.client`` invalid-URL message whose quoted password carries a SPACE, sized so the
    clamp's cut lands on exactly that space.

    That is the whole defect. ``_INVALID_URL_USERINFO`` needs its trailing ``@``; the cut puts that
    ``@`` past the window; the pattern that exists to scrub the password stops matching, and the head
    before the cut is written out. A password can hold a space because ``http.client`` formats the
    quoted "port" with ``'%s'`` -- whatever the userinfo decoded to goes out verbatim."""
    cut = redaction._REDACT_WINDOW - redaction._CLAMP_MARKER_BUDGET
    opening = " " + redaction._USERINFO_OPENER + _PASSWORD_HEAD + " "
    return _filler(cut - len(opening)) + opening + "z" * 100 + "@host'" + " tail" * 30


def _clamp_without_the_credential_walk(text: str, window: int) -> tuple[str, int]:
    """``_clamp`` as it stood before this walk: the whitespace cut and the name walk, and nothing for a
    span the cut broke. The positive control for the arm below and for nothing else."""
    if len(text) <= window:
        return text, 0
    cut = max(redaction._last_cut(text, window), 0)
    cut = redaction._drop_trailing_name_tokens(text, cut)
    return text[:cut], len(text) - cut


def test_the_credential_constants_still_describe_the_pattern_they_bound() -> None:
    """THE DRIFT GATE for a duplication the module takes on purpose.

    ``_INVALID_URL_USERINFO`` spells its opener and its tail bound out as literals rather than
    interpolating ``_USERINFO_OPENER`` and ``_USERINFO_TAIL_MAX``, because
    ``tests/test_security_static.py`` resolves every ``re.compile`` argument in the tree statically and
    an f-string would record this one as a blind spot -- over the only pattern here that matches a
    CREDENTIAL. The cost of that choice is two spellings, and this is what keeps them one fact.

    **The clamp reads the constants and the scrub reads the pattern**, so a drift between them is not
    a tidiness problem: ``_first_truncated_userinfo`` would search for an opener the pattern no longer
    has, find nothing, and report a cut it never checked."""
    pattern = redaction._INVALID_URL_USERINFO.pattern
    assert pattern.startswith(f"({redaction._USERINFO_OPENER})"), (
        f"_USERINFO_OPENER is not what the pattern opens with, so the clamp searches for a literal "
        f"the scrub does not have: {pattern!r}"
    )
    assert f"{{1,{redaction._USERINFO_TAIL_MAX}}}@" in pattern, (
        f"_USERINFO_TAIL_MAX is not the pattern's tail bound, so _USERINFO_SPAN understates or "
        f"overstates how far back of a cut a span can start: {pattern!r}"
    )
    # The span is what bounds the search, so state it against the pattern rather than against itself.
    longest = redaction._USERINFO_OPENER + "z" * redaction._USERINFO_TAIL_MAX + "@"
    match = redaction._INVALID_URL_USERINFO.match(longest)
    assert match is not None and match.end() == len(longest) == redaction._USERINFO_SPAN


def test_the_split_credential_fixture_really_breaks_the_span_at_the_cut() -> None:
    """THE POSITIVE CONTROL for the arms below, in the shape
    ``test_the_over_window_fixture_really_puts_the_cut_inside_the_tail`` established. Each of those
    asserts an absence, and an absence cannot tell a working walk from a fixture whose credential never
    came near the cut. Four lines say where the cut actually lands."""
    text = _split_credential_over_window()
    assert len(text) > redaction._REDACT_WINDOW, "the fixture is not over the window at all"

    cut = redaction._last_cut(text, redaction._REDACT_WINDOW - redaction._CLAMP_MARKER_BUDGET)
    opener = text.rfind(redaction._USERINFO_OPENER, 0, cut)
    assert opener >= 0, "the opener is not inside the window, so no span can straddle the cut"
    assert text[opener + len(redaction._USERINFO_OPENER) : cut] == _PASSWORD_HEAD, (
        "the cut no longer falls between the two halves of the quoted password"
    )
    assert "@" not in text[opener:cut], (
        "the terminator is inside the head, so the span is not broken"
    )


def test_the_fence_a_whitespace_cut_hands_half_a_credential_to_the_log() -> None:
    """THE DEFECT, on the shipped pattern rather than a strawman, pinned so nobody drops the second
    walk as redundant with the first.

    A whitespace cut is safe for a pattern that either cannot hold whitespace or still matches with
    its tail gone. ``_INVALID_URL_USERINFO`` is neither: its trailing ``@`` is REQUIRED, so a cut
    inside its span does not shorten the match, it kills it. The name walk cannot cover that --
    ``_ends_with_name_token`` asks a name-shaped question, and this head is deliberately not
    name-shaped."""
    text = _split_credential_over_window()
    head, dropped = _clamp_without_the_credential_walk(
        text, redaction._REDACT_WINDOW - redaction._CLAMP_MARKER_BUDGET
    )
    assert dropped, "the control clamp dropped nothing, so it is not exercising a cut at all"
    assert _PASSWORD_HEAD not in redact(text), (
        "the unbounded redactor no longer scrubs this credential, so the arms below cannot tell a "
        "closed leak from a fixture the pattern was never going to catch"
    )
    assert _PASSWORD_HEAD in redact(head), (
        "the whitespace cut alone no longer strands the credential, so the fence this walk was built "
        "against has moved and _drop_truncated_userinfo needs re-justifying"
    )


def test_the_clamp_drops_a_credential_span_its_own_cut_broke() -> None:
    """The positive half of the arm above, through every entry point that clamps.

    ``safe_text`` is listed separately because it calls ``_clamp`` directly rather than through
    ``clamp_untrusted``, so a fix wired only into the public pairing would leave the stored
    ``last_error`` leaking."""
    text = _split_credential_over_window()
    assert _PASSWORD_HEAD not in redact_untrusted(text)
    assert _PASSWORD_HEAD not in redact(clamp_untrusted(text))
    assert _PASSWORD_HEAD not in safe_text(text, limit=100_000)


def test_one_credential_span_can_cover_a_second_opener_and_both_go() -> None:
    """The tail is ``[^\\r\\n]``, so it spans whitespace and spans a second opener: one match can cover
    several credentials. A walk that dropped only the opener nearest the cut would leave the first
    one's password standing, which is why ``_first_truncated_userinfo`` returns the LEFTMOST straddling
    opener rather than the last."""
    cut = redaction._REDACT_WINDOW - redaction._CLAMP_MARKER_BUDGET
    second_head = "second0head1"
    opening = (
        " "
        + redaction._USERINFO_OPENER
        + _PASSWORD_HEAD
        + " "
        + redaction._USERINFO_OPENER
        + second_head
        + " "
    )
    text = _filler(cut - len(opening)) + opening + "z" * 60 + "@host'" + " tail" * 30

    assert _PASSWORD_HEAD not in redact(text) and second_head not in redact(text), (
        "the unbounded redactor no longer covers both openers with one match, so this fixture is not "
        "the case the leftmost rule exists for"
    )
    out = redact_untrusted(text)
    assert _PASSWORD_HEAD not in out and second_head not in out


def test_the_credential_walk_is_bounded_by_the_window_not_by_the_peer() -> None:
    """THE COST HALF, on the argument ``test_the_token_walk_is_bounded_by_the_window_not_by_the_peer``
    makes: the PEER chooses how many passes the walk takes, so each pass has to stay inside the
    region it drops. That arm reads a count now (BACKLOG #2896); this one still reads a budget.

    It does, on two bounds that are both properties rather than counts. A pass searches one
    ``_USERINFO_SPAN``-wide region behind the cut -- further back than that, a span ends inside the
    head, where the head's bytes are the text's bytes and the match still stands. And a pass consumes
    at least one opener, so the passes cannot outnumber the openers a window holds. The searched
    regions OVERLAP between passes, unlike the token walk's, so the cost is passes times the span and
    not one sweep of the window -- ``_drop_truncated_userinfo`` carries that correction.

    **A sweep, because the cost is not monotone in the shape and one sample of it measures nothing.**
    The fixture is the worst of a sweep of the gap between opener and terminator, in steps of 5 from
    0 to 125: openers close enough together that a span reaches past the cut, far enough apart that a
    pass steps back over only a few. A gap of 120 or more takes ONE pass and 0.05 ms, because past
    that no span can reach an ``@`` beyond the cut. Measured on the author's box: 348 passes and
    1.6 ms at the worst gap, against the same ``_SCAN_BUDGET_SECONDS`` the #1437 arms use."""
    window = redaction._REDACT_WINDOW - redaction._CLAMP_MARKER_BUDGET
    block = redaction._USERINFO_OPENER + "x" * 75 + "@"
    hostile = (block * (window // len(block) + 2))[: window + 200] + "Q" * 200_000

    best = _best_of(lambda: clamp_untrusted(hostile))
    assert best < _SCAN_BUDGET_SECONDS, (
        f"clamping a {window}-character wall of credential spans cost {best:.4f}s of the event loop "
        f"against a {_SCAN_BUDGET_SECONDS}s budget -- the walk is no longer linear in the window"
    )
    # Non-vacuity: a walk that stopped after a pass or two would be fast for the wrong reason.
    head, _ = redaction._clamp(hostile, window)
    assert len(head) < redaction._USERINFO_SPAN, (
        f"the walk stopped with {len(head)} characters still in hand, so this fixture is not "
        f"measuring a full-window walk and the budget above proves nothing about one"
    )


def test_the_credential_walk_costs_an_ordinary_message_nothing() -> None:
    """THE CONTROL the arms above need, and the one a careless run drops. Everything else here asserts
    that a credential is ABSENT, and dropping the string wholesale would satisfy every one of them.

    A complete span under the window is untouched by the walk and redacted by the pattern, so the
    diagnostic still says WHERE the endpoint pointed -- which is the whole reason the host after the
    ``@`` is kept."""
    message = "InvalidURL: nonnumeric port: 'pw0rdhead1 more@ops.example'"
    assert clamp_untrusted(message) == message
    assert redact_untrusted(message) == "InvalidURL: nonnumeric port: '[redacted]@ops.example'"


def test_clamp_never_cuts_inside_a_token() -> None:
    """A cut at an arbitrary offset is the leak in a second costume: it can take one delimiter off a
    two-delimiter run just as a prefix truncation does. The cut lands on whitespace or on nothing, so a
    field run with no whitespace after it is dropped whole rather than halved."""
    window = redaction._REDACT_WINDOW
    out = redact(clamp_untrusted(_filler(100) + " A^B^C" + "Q" * (window * 2)))
    assert "A^B" not in out and "B^C" not in out


def test_clamp_yields_nothing_when_the_window_holds_no_boundary() -> None:
    """The honest end of the same rule. One solid run offers no safe cut anywhere, so the answer is the
    note alone -- over-redaction, never a fragment."""
    window = redaction._REDACT_WINDOW
    clamped = clamp_untrusted("MRN123456^H^MR" + "A" * (window + 100))
    assert "MRN123456" not in clamped
    assert clamped.strip().startswith("[redaction bound:")


def test_clamp_is_idempotent_because_two_handlers_filter_one_record() -> None:
    """``_install_phi_filters`` attaches a chain per handler, so a record going to stdout AND the
    off-box forwarder is scrubbed twice. A bound that re-cut on the second pass would ship two sinks
    two different strings. Idempotence comes from the result fitting the window, not from recognising
    the note -- see the arm below for why that distinction is load-bearing."""
    once = clamp_untrusted(_over_window(" DOE^JANE^M trailing"))
    assert len(once) <= redaction._REDACT_WINDOW
    assert clamp_untrusted(once) == once


def test_a_peer_cannot_bypass_the_bound_by_writing_the_note_into_its_payload() -> None:
    """The obvious way to make the clamp idempotent is to look for its own note and return early. A
    remote peer writes the text of an MSA-3, so it can write that note -- and a bound a peer can switch
    off is not a bound. The length check cannot be spoofed."""
    note = clamp_untrusted(_over_window(" tail"))[-60:]
    hostile = _filler(redaction._REDACT_WINDOW * 2) + note
    assert len(clamp_untrusted(hostile)) <= redaction._REDACT_WINDOW


def test_clamp_reports_what_it_dropped_without_becoming_redactable() -> None:
    """The note has to survive ``redact`` unchanged, or re-applying ``safe_text`` at the store-layer
    chokepoint would rewrite it and break the fixed point. So: no delimiter pair, no capitalized token
    that could pair into a name run, and a separator in the count so an eight-digit one is not read as
    a bare ``YYYYMMDD`` by ``_DATE_RUN``."""
    note = redaction._clamp_marker(19_800_505)
    assert redact(note) == note
    assert "19_800_505" in note


def test_clamp_leaves_anything_short_enough_to_read_byte_identical() -> None:
    """The ordinary case is every case an operator sees. ``dropped == 0`` must mean untouched, or this
    change would be a rewrite of every stored ``last_error`` rather than a bound on a hostile one."""
    for text in ("connection refused: timeout after 5s", "", ADT, "y" * 5000):
        assert clamp_untrusted(text) == text


def test_the_bound_does_not_cost_a_normal_message_its_redaction() -> None:
    """THE CONTROL a careless run drops. Every arm above asserts that something is ABSENT, and dropping
    the whole input satisfies all of them at once. This says the redactor still works on the input it
    was built for."""
    out = safe_text(f"router error near {ADT}")
    for token in ("DOE", "JANE", "100^^^H^MR", "19800101"):
        assert token not in out
    assert out.startswith("router error near MSH|[redacted]")
    assert "[redaction bound:" not in out
    assert "DOE" not in safe_text("patient DOE JANE dob 1980-05-05 not found")
    assert safe_text("hl7 version 2.5.1 != expected 2.3") == "hl7 version 2.5.1 != expected 2.3"


def test_safe_text_reports_the_two_counts_apart() -> None:
    """``(+N chars)`` is redacted text held back; the note is raw characters never scanned. Adding them
    would report a total in neither unit. Both appear when both happened."""
    out = safe_text(_over_window(" tail"), limit=40)
    assert "…(+" in out and "[redaction bound:" in out


#: The three 16 MiB shapes the cost arms use, built on demand.
#:
#: **Built by a factory rather than passed as ``parametrize`` VALUES**, because pytest renders a
#: parameter into the test id: three 16 MiB strings as values produced a 168 MB report and a
#: ``ValueError`` out of ``os`` on the path built from one. The id is the label now.
_FRAME_CAP_SHAPES = {
    "segment-shaped": lambda: "PID|1||100^^^H^MR||DOE^JANE^M||19800505|F\r" * 400_000,
    "delimiter-free prose": lambda: "the quick brown fox jumped over it " * 500_000,
    "one solid run": lambda: "A" * 16_000_000,
}


@pytest.mark.parametrize("label", sorted(_FRAME_CAP_SHAPES))
def test_a_frame_cap_sized_input_no_longer_buys_the_event_loop(label: str) -> None:
    """THE ROW'S ACCEPTANCE ARM: event-loop responsiveness against an input a remote peer sizes.

    A negative acknowledgment's MSA-3 runs to the 16 MiB frame cap, and ``safe_text`` scanned all of it
    before truncating to 200 characters. Measured unbounded on the author's box: 0.29 s for the
    segment shape and 0.78 s for prose, which matches the 0.53-0.94 s band measured independently on
    another. Bounded, the same inputs cost 1.2 ms and 3.1 ms.

    The budget is ``_SCAN_BUDGET_SECONDS`` -- the same line the #1437 cost arms use, so a regression
    that reopened the scan would fail here at the same threshold it fails there -- and best-of-3
    because a scheduling hiccup can only inflate a sample."""
    text = _FRAME_CAP_SHAPES[label]()
    assert len(text) >= 16_000_000
    best = _best_of(lambda: safe_text(text))
    assert best < _SCAN_BUDGET_SECONDS, (
        f"safe_text on {len(text)} characters of {label} cost {best:.4f}s of the event loop against "
        f"a {_SCAN_BUDGET_SECONDS}s budget"
    )


def test_control_the_same_inputs_are_expensive_unbounded() -> None:
    """Non-vacuity for the arm above, in the shape ``test_the_hostile_fixture_is_actually_hostile``
    established: without it, a fast ``safe_text`` would be equally consistent with a fixture too cheap
    to measure anything. ``redact`` is called directly, which is what ``safe_text`` did before the
    bound."""
    # The shape from the table above, not a re-typed copy of it: a control has to measure the same
    # fixture as the arm it controls, and a duplicated literal is free to drift out from under it.
    text = _FRAME_CAP_SHAPES["delimiter-free prose"]()
    best = _best_of(lambda: redact(text))
    assert best > _SCAN_BUDGET_SECONDS, (
        f"the unbounded scan cost only {best:.4f}s, under the {_SCAN_BUDGET_SECONDS}s budget the "
        f"bounded arm clears -- this fixture no longer discriminates and the budget needs re-deriving"
    )


#: The corpus the property arm below draws from. **Whole tokens, not characters.** The leak needs a
#: RUN of adjacent name-shaped tokens behind the cut, and a uniform character alphabet essentially
#: never builds one: the first cut of that arm drew characters, and its own control found zero leaks
#: on the KNOWN-LEAKY walk -- which made its zero on the fixed walk worth nothing.
#:
#: **The credential message is a token here rather than a separate corpus**, so the arm below reaches
#: both leak classes the cut has produced: the name run the walk was built for, and the span whose
#: required ``@`` a cut destroys. It carries a space inside the quoted password on purpose -- that is
#: the only shape a whitespace cut can break -- and the head is lowercase-led so the NAME walk is not
#: what removes it.
_FUZZ_TOKENS = (
    "SMITH", "DOE", "JANE", "ROE", "AA", "BB", "MR", "ADT",
    "Smith", "Doe", "Jane", "Ab",
    "ok", "rejected", "patient", "x", "12", "1980-05-05",
    "a^b", "P|Q", "100^^^H^MR", "-", "(DOE", "DOE)",
    "nonnumeric port: 'pw0rd head1@host'",
)  # fmt: skip


def _fuzz_text(rand: random.Random) -> str:
    parts: list[str] = []
    for _ in range(rand.randint(0, 25)):
        parts.append(rand.choice(_FUZZ_TOKENS))
        parts.append(rand.choice((" ", " ", " ", "  ", "\t", "\n")))
    return "".join(parts)


def _last_cut_walk(text: str, cut: int, steps: int) -> int:
    """The name walk spelled the way PR 1319 shipped it, for at most ``steps`` tokens.

    Two controls are cut from this one spelling, so they cannot drift apart. Capped at three steps it
    is the LEAK ``_three_step_clamp`` reproduces. Left to run until it stops it is the COST
    ``test_the_last_cut_spelling_of_the_walk_is_quadratic_on_the_same_meter`` reproduces: each step
    copies ``text[:cut]`` from index 0 and ``_last_cut`` scans back to index 0."""
    for _ in range(steps):
        if not cut:
            break
        end = len(text[:cut].rstrip(redaction._CUT_CHARS))
        start = redaction._last_cut(text, end) + 1
        if not redaction._ends_with_name_token(text[start:end]):
            break
        cut = start
    return cut


def _three_step_clamp(text: str, window: int) -> tuple[str, int]:
    """``_clamp`` with the walk PR 1319 shipped: at most three tokens, then stop.

    Kept as the positive control for the arm below and for nothing else. An absence arm over a random
    corpus is worthless until something shows the corpus can produce the thing being asserted absent,
    and the honest something is the defect itself."""
    if len(text) <= window:
        return text, 0
    cut = _last_cut_walk(text, max(redaction._last_cut(text, window), 0), steps=3)
    return text[:cut], len(text) - cut


def _clamp_leaks(clamp: Callable[[str, int], tuple[str, int]], trials: int) -> int:
    """How many trials keep a token through ``clamp`` that the UNBOUNDED redactor scrubs."""
    rand = random.Random(1576)  # seeded: a flaky PHI arm gets muted, so this one cannot flake
    leaks = 0
    for _ in range(trials):
        text = _fuzz_text(rand)
        head, dropped = clamp(text, rand.randint(1, max(len(text), 1)))
        if not dropped:
            continue
        if set(redact(head).split()) - set(redact(text).split()):
            leaks += 1
    return leaks


def test_no_token_survives_the_clamp_that_the_unbounded_scan_scrubs() -> None:
    """THE LEAK PROPERTY, over a corpus rather than the one reproduction that exposed it.

    The rule the arms above are instances of: clamping may drop anything, and may over-redact
    freely, but it may never KEEP a token the unbounded redactor would have scrubbed. That is what
    BACKLOG #1576 must not trade away for its bound.

    **Two controls, because the clamp now has two walks and one control cannot arm both.** Each is a
    pre-fix spelling on the same seed and the same corpus, since an absence over random input proves
    nothing until something proves the input can produce the thing. Measured at 1,500 trials: 0 here,
    against 113 on the three-step name walk and 98 with the credential walk removed.

    **The three-step number was 31 before the corpus grew an ``_INVALID_URL_USERINFO`` token.** The
    rise is the corpus reaching a second leak class, not the name walk getting worse.

    **WHAT THIS CORPUS REACHES, which is still less than the rule it checks.** ``_fuzz_text`` joins
    whole tokens with whitespace, so it exercises leaks that turn on where the cut falls BETWEEN
    tokens. It cannot reach a leak that turns on text the window never sees: a clamp that drops the
    ``MSH`` declaring custom delimiters leaves ``_sniff_delimiters`` nothing to read, and no token
    list produces that, because the dependency is on the whole text rather than on a span. That one
    is a known open gap recorded on the pull request, and both controls share the blind spot, so a
    zero here is evidence about the two walks and about nothing else."""
    shipped = _clamp_leaks(redaction._clamp, 1_500)
    name_control = _clamp_leaks(_three_step_clamp, 1_500)
    credential_control = _clamp_leaks(_clamp_without_the_credential_walk, 1_500)
    assert name_control, (
        "the pre-fix name walk leaked nothing on this corpus, so the corpus cannot produce that "
        "defect and the assertion below is vacuous -- re-check _FUZZ_TOKENS before trusting a zero"
    )
    assert credential_control, (
        "dropping the credential walk leaked nothing on this corpus, so the corpus no longer "
        "produces a cut inside a quoted password -- re-check _FUZZ_TOKENS before trusting a zero"
    )
    assert not shipped, f"{shipped} of 1,500 trials kept a token the unbounded scan scrubs"


class _MeteredText(str):
    """A ``str`` that counts the characters each read of it touches: the clamp's cost with the clock
    taken out.

    An index is one character, a slice is the characters it copies, and a search is the characters
    between where it starts and where it stops. Each read hands back a plain ``str``, so the count is
    of work done on the WHOLE text, which is where a quadratic walk spends it.

    **Why characters and not calls.** The two spellings of the name walk take the same number of
    steps. What separates them is how far each step reaches, so a step count reads them as equal.

    **WHAT IT CANNOT SEE, which is more than the floor in ``_walk_cost`` covers.** Work done on a
    plain copy is charged nothing past the copy, and neither is a read made by the regex engine, by an
    operator (``in``, ``+``) or by an unbound ``str.rfind(text, ...)``. The floor refuses a walk the
    meter saw NOTHING of. It passes at least these two, both measured: a quadratic walk run on one
    ``text[:cut]`` copy, and an unseen scan added beside the shipped index reads. So the two walk arms
    show that the shipped spelling is linear and that the ``_last_cut`` spelling is caught. They do
    not show that every quadratic spelling is."""

    touched = 0

    def __getattribute__(self, name: str) -> Any:
        if name in _UNMETERED_READS:
            raise AssertionError(
                f"str.{name} read a _MeteredText, and the meter does not charge for it. Override it "
                f"in _MeteredText with its cost before trusting a count taken through it"
            )
        return super().__getattribute__(name)

    def __getitem__(self, key: SupportsIndex | slice, /) -> str:
        got = super().__getitem__(key)
        self.touched += len(got)
        return got

    def find(
        self, sub: str, start: SupportsIndex | None = None, end: SupportsIndex | None = None, /
    ) -> int:
        at = super().find(sub, start, end)
        low, high, _ = slice(start, end).indices(len(self))
        self.touched += max((at + len(sub) if at >= 0 else high) - low, 0)
        return at

    def rfind(
        self, sub: str, start: SupportsIndex | None = None, end: SupportsIndex | None = None, /
    ) -> int:
        at = super().rfind(sub, start, end)
        low, high, _ = slice(start, end).indices(len(self))
        self.touched += max(high - (at if at >= 0 else low), 0)
        return at


#: Every public ``str`` method ``_MeteredText`` does not charge for. Reading the text through one of
#: them is REFUSED rather than passed through, because an uncharged read is how a quadratic walk would
#: come back with a linear count. **Derived from the class, so charging a method is one edit:**
#: override it there and it leaves this set.
_UNMETERED_READS = frozenset(
    name for name in dir(str) if not name.startswith("_") and name not in vars(_MeteredText)
)

#: N for the two walk arms; 2N is twice it. **An eighth of the shipped window, on purpose.** The meter
#: counts characters rather than seconds, so the growth it reads does not depend on the size, and the
#: quadratic control is still run for real: about 0.1 s here, over a second at the shipped window.
_WALK_WINDOW = 8_192

#: The one line both walk arms are read against, in the shape ``_SCAN_BUDGET_SECONDS`` argues for: a
#: shared line, so the control proves this exact number discriminates. A linear walk doubles when the
#: window doubles and a quadratic one quadruples, so the line sits halfway. **No margin is spent on
#: noise, because there is none:** the count is the same on every run and every machine.
_WALK_GROWTH_LINE = 3.0


def _name_token_wall(window: int) -> str:
    """The most steps a ``window`` can buy the name walk: the shortest legal ALLCAPS token plus one
    space, 21,820 of them at the shipped window, with a non-whitespace run behind so the cut lands at
    the end of the run and the walk has to travel the whole way back.

    **The run behind grows with the window.** It is the part of the text the PEER sizes, so a step
    that searched it would cost more as it grew, and a tail of one fixed length would hide that from
    a growth reading. Behind this one, one unbounded ``rfind`` per step reads a growth of 4.00."""
    return ("AA " * (window // 3 + 1))[:window] + "Q" * (3 * window)


def _walk_cost(window: int) -> int:
    """Characters the name walk touches inside ``redaction._clamp``, on a ``_name_token_wall``.

    **The walk's own share, not the clamp's total.** ``_clamp`` opens with one ``_last_cut`` over the
    window, and on this wall that single call is two thirds of everything charged. Left in, it hides
    a walk the meter cannot see: such a walk reads as free, and the total still doubles with the
    window. So the opening call is read on its own and taken off.

    Both checks run before anything is divided, because a ratio hides a broken reading: two walks that
    each stopped early, or two counts that each missed the walk, divide to a clean 2."""
    wall = _name_token_wall(window)
    text = _MeteredText(wall)
    head, _ = redaction._clamp(text, window)
    assert not head, (
        f"the walk stopped {len(head)} characters short of the start of a {window}-character run, "
        f"so this reading is not of a full-window walk"
    )
    opening = _MeteredText(wall)
    cut = redaction._last_cut(opening, window)
    walked = text.touched - opening.touched
    assert walked >= cut, (
        f"the meter charged the walk {walked} characters for dropping {cut}. A walk has to read "
        f"every character it drops to judge its token, so this one reads the text through something "
        f"_MeteredText cannot see and the growth would measure nothing"
    )
    return walked


def _walk_growth() -> float:
    """``_walk_cost`` at 2N over ``_walk_cost`` at N. Near 2 is a walk linear in the window; near 4 is
    a quadratic one."""
    return _walk_cost(2 * _WALK_WINDOW) / _walk_cost(_WALK_WINDOW)


def test_the_token_walk_is_bounded_by_the_window_not_by_the_peer() -> None:
    """THE OTHER HALF OF THE LEAK FIX, and the one an absence arm cannot see.

    The walk drops name-shaped tokens until it meets one that is not, rather than a fixed three, so
    the PEER chooses how many steps it takes. That is only safe while each step's work stays inside
    the region being dropped. Spelled the obvious way -- ``text[:cut].rstrip(...)`` paired with
    ``_last_cut`` -- each step copies from index 0 and rescans from index 0, and the walk is quadratic
    in the window: the exact cost class BACKLOG #1576 exists to bound, rebuilt inside the fix for it.

    **This asserts LINEARITY, and it replaced a wall-clock budget that measured the runner (BACKLOG
    #2896).** The arm used to time one clamp of the shipped window against ``_SCAN_BUDGET_SECONDS``:
    6.2 ms on the author's box, against 630 ms for the ``_last_cut`` spelling. BACKLOG #2896 records it
    going red on loaded hosted runners with the walk unchanged. A fixed number of seconds is a claim
    about the machine as much as about the walk, and the property was never "under 50 ms". It is that
    doubling the window doubles the work, so that is what is read now: the characters the walk
    touches at 2N over the characters it touches at N (``_walk_growth``). No clock is involved, so
    load cannot move the answer.

    Measured on the shipped walk: 19,108 characters at 8,192 and 38,225 at 16,384, a growth of 2.00.
    The control below reads 4.00 for the ``_last_cut`` spelling on the same meter and the same line.

    **What this gave up, so nobody reads it as more than it is.** The budget bounded the seconds one
    shipped-window clamp may cost, whatever the spelling. This arm bounds neither: a linear walk with
    a large constant passes, and so does a quadratic one the meter cannot see (``_MeteredText`` names
    the cases). A count was chosen over a timed ratio because a count cannot go red on a busy
    runner, and going red there is the defect being fixed."""
    growth = _walk_growth()
    assert growth < _WALK_GROWTH_LINE, (
        f"doubling the window multiplied the characters the walk touches by {growth:.2f}, over the "
        f"{_WALK_GROWTH_LINE} line -- the walk is no longer linear in the window"
    )
    # The same walk at the SHIPPED window, through the public entry. The growth is read at an eighth
    # of it, and ``_walk_cost`` checks those two walks ran to index 0. This checks the one a peer
    # reaches does too: every token is name-shaped back to index 0, so nothing is kept but the note.
    hostile = _name_token_wall(redaction._REDACT_WINDOW - redaction._CLAMP_MARKER_BUDGET)
    assert clamp_untrusted(hostile).strip().startswith("[redaction bound:"), (
        "the walk stopped before the start of the run at the shipped window, so the growth above is "
        "of a walk the public entry does not finish"
    )


def test_the_last_cut_spelling_of_the_walk_is_quadratic_on_the_same_meter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live positive control: the SAME fixture, the SAME meter and the SAME line, with the walk swapped
    for the ``text[:cut].rstrip(...)`` plus ``_last_cut`` spelling inside the shipping ``_clamp``.

    Without it the arm above is unfalsifiable. A meter that saw none of the work, or saw the same work
    whatever the walk did, would read one growth for both spellings, and one number cannot sit on both
    sides of a line. This patches the module global ``_clamp`` reads, so the whole shipping path runs
    with the quadratic walk rather than a copy of the clamp held off to one side.

    The step cap is ``cut``, which is no cap at all: a step drops at least one character."""
    monkeypatch.setattr(
        redaction,
        "_drop_trailing_name_tokens",
        lambda text, cut: _last_cut_walk(text, cut, steps=cut),
    )
    growth = _walk_growth()
    assert growth > _WALK_GROWTH_LINE, (
        f"doubling the window multiplied the characters the ``_last_cut`` spelling touches by only "
        f"{growth:.2f}, under the {_WALK_GROWTH_LINE} line. The meter no longer separates a linear "
        f"walk from a quadratic one, so the arm above is not measuring anything"
    )


def test_the_meter_charges_each_read_for_the_characters_it_touches() -> None:
    """The instrument's own control. Both walk arms divide two readings of ``_MeteredText``, and a
    ratio hides a meter that charges every read the same wrong amount.

    One reading per kind of read ``_clamp`` makes, on a text small enough to count by hand: an index,
    a slice from 0, a backward search that hits, one that runs out, and a forward search. The forward
    search is the credential walk's; neither name-walk arm reaches it."""
    text = _MeteredText("ab cd ef")
    charged = []
    for read in (
        lambda: text[4],  # one character
        lambda: text[:5],  # the five characters copied
        lambda: text.rfind(" ", 0, 8),  # hits at 5, having read 7, 6 and 5
        lambda: text.rfind("\t", 0, 8),  # no hit, so all eight
        lambda: text.find(" ", 3),  # hits at 5, having read 3, 4 and 5
    ):
        before = text.touched
        read()
        charged.append(text.touched - before)
    assert charged == [1, 5, 3, 8, 3]
    with pytest.raises(AssertionError, match="rsplit"):
        text.rsplit(None, 1)


def test_a_walk_the_meter_cannot_see_is_refused_not_read_as_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The floor's own control. ``_walk_cost`` refuses a walk charged under one touch per character
    it dropped, and nothing else here shows that refusal can fire.

    The walk is the QUADRATIC spelling run on a plain ``str`` copy, so the meter is charged nothing
    for it. Without the floor that reads as a walk costing zero at both windows."""
    monkeypatch.setattr(
        redaction,
        "_drop_trailing_name_tokens",
        lambda text, cut: _last_cut_walk(str(text), cut, steps=cut),
    )
    with pytest.raises(AssertionError, match="cannot see"):
        _walk_cost(_WALK_WINDOW)


def test_clamp_untrusted_is_exported() -> None:
    assert "clamp_untrusted" in redaction.__all__


# --- bounding the input: a structured span the cut broke (BACKLOG #1576, #1711) ---
#
# The register on ``_CUT_CHARS`` asks each new pattern one question: if a cut at a space falls inside
# your span, does what is left still MATCH you? For the structured passes the answer is yes, because
# an unterminated region runs to the end of the text, and these arms pin it. Each fragment is
# lower-case on purpose: a name-shaped fragment is dropped by the token walk whatever the structured
# passes do, and the arm would pass for the wrong reason.

_STRUCTURED_CUTS = {
    "json-string": (' {"family": "zqxa vornb', "_redact_json_fields"),
    "json-array": (' {"given": ["qlee", "zqxa vornb', "_redact_json_fields"),
    "xml-attribute": (' <family value="zqxa vornb', "_redact_xml_elements"),
    "xml-text": (" <family>zqxa vornb", "_redact_xml_elements"),
    # Any script's letter is markup evidence, not only ASCII.
    "xml-text-non-ascii": (" <family>Øzqxa vornb", "_redact_xml_elements"),
    "dicom-tag": (" (0010,0010) PN [zqxa vornb", "_redact_dicom_tags"),
    "dicom-label": (" PatientName=zqxa vornb", "_redact_dicom_labels"),
}


@pytest.mark.parametrize(
    ("tail", "pass_name"), list(_STRUCTURED_CUTS.values()), ids=list(_STRUCTURED_CUTS)
)
def test_a_cut_inside_a_structured_span_strands_nothing(
    tail: str, pass_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = _over_window(tail)
    head = clamp_untrusted(text)
    assert "zqxa" in head and "vornb" not in head, "the cut did not land inside the span"

    for out in (redact_untrusted(text), safe_text(text, limit=100_000)):
        assert "zqxa" not in out, out[-200:]
    # The region runs to the end of the head, and the bound note after it must survive.
    assert redact_untrusted(text).endswith(head.rpartition("\n")[2])

    # The positive control: the fragment is this pass's to catch, not a neighbour's.
    monkeypatch.setattr(redaction, pass_name, lambda t, *_, **__: t)
    assert "zqxa" in redact_untrusted(text)


@pytest.mark.parametrize("tail", [" <family> zqxa vornb", " <family>(zqxa vornb"])
def test_a_cut_after_whitespace_or_punctuation_led_xml_text_is_a_stated_residual(tail: str) -> None:
    """The "no" answers in the register, stated on ``_redact_xml_elements`` as "at least these": an
    unclosed element whose text opens with whitespace or punctuation reads as a prose placeholder
    (``--username <name> --email``), so the fragment before the cut survives. Pinned so a fix is
    noticed and this arm is turned round."""
    assert "zqxa" in redact_untrusted(_over_window(tail))


# --- json_loads_or_refusal (BACKLOG #2048) ------------------------------------


def test_json_loads_or_refusal_returns_the_value_and_no_hint() -> None:
    assert "json_loads_or_refusal" in redaction.__all__
    assert redaction.json_loads_or_refusal('{"a": [1, 2]}') == ({"a": [1, 2]}, None)
    assert redaction.json_loads_or_refusal(b"[]") == ([], None)


@pytest.mark.parametrize(
    ("build", "hint"),
    [
        # A decode error: position only, never the document.
        pytest.param(lambda m: '{"k": ' + m, "JSONDecodeError at line 1, column 7", id="bad-json"),
        # Bytes that are not UTF-8: the class name only, never the bytes.
        pytest.param(lambda m: (m + "\xff").encode("latin-1"), "UnicodeDecodeError", id="bad-utf8"),
    ],
)
def test_json_loads_or_refusal_hint_is_content_free(
    build: Callable[[str], str | bytes], hint: str
) -> None:
    """The hint carries the position or the class name and nothing of the input. The marker is built
    at run time so the check cannot pass on a literal that sits in this file's source."""
    marker = "SYNTH" + str(random.getrandbits(64))
    value, refusal = redaction.json_loads_or_refusal(build(marker))
    assert value is None
    assert refusal == hint
    assert marker not in refusal


# --- a labelled MRN in prose (BACKLOG #2079) ----------------------------------
#
# A bare ``MRN 12345678`` carried no delimiter, no date and no second capitalized token, so every
# pass walked it through. BACKLOG #1711 measured the leak and left it outside its closing criteria.

#: ``(text, value)``: the value must be gone, and every one of them leaks with the pass disabled.
_LABELLED_MRNS = (
    ("patient with MRN 12345678 not found", "12345678"),
    ("mrn: A1234 rejected", "A1234"),
    ("MRN#000-123 on file", "000-123"),
    ("Mrn = 4455667 twice", "4455667"),
    ("lookup MRN\t7654321 failed", "7654321"),
    ('{"mrn": "12345", "status": "active"}', "12345"),
    ("query {'mrn': 7654321}", "7654321"),
    # A letter prefix joined by a separator, snake_case keys, an array value, a dotted value and a
    # doubled separator: all measured leaking on the first revision.
    ("mrn MR-00123 on file", "00123"),
    ("MRN: E_12345 rejected", "12345"),
    ('{"patient_mrn": "12345"}', "12345"),
    ('{"mrn": ["12345"]}', "12345"),
    ("MRN 123.456 on file", "456"),
    ("MRN: #12345 rejected", "12345"),
)

#: A pattern that never matches, standing in for the pass when a control switches it off.
_NEVER = re.compile(r"(?!)()")


@pytest.mark.parametrize(("text", "value"), _LABELLED_MRNS)
def test_a_labelled_mrn_in_prose_is_scrubbed(text: str, value: str) -> None:
    out = redact(text)
    assert value not in out, out
    assert redact(out) == out
    assert value not in safe_text(text)


@pytest.mark.parametrize(("text", "value"), _LABELLED_MRNS)
def test_a_labelled_mrn_leaks_with_its_pass_disabled(
    text: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE POSITIVE CONTROL: the green above is this pass's work, not a neighbour's."""
    monkeypatch.setattr(redaction, "_MRN_LABELLED", _NEVER)
    assert value in redact(text)


def test_the_mrn_label_is_kept_so_a_reader_sees_what_was_withheld() -> None:
    assert redact("patient with MRN 12345678 not found") == "patient with MRN [redacted] not found"
    assert redact('{"mrn": "12345"}') == '{"mrn": "[redacted]"}'


@pytest.mark.parametrize(
    "line",
    [
        # Ordinary numbers carry no label.
        "retry 3/5 scheduled at 04:12:37 (backoff 2.5s)",
        "connect 192.0.2.10:2575 failed: WinError 10061",
        "delivered 12345 rows in 41ms",
        # The label with no number after it is prose.
        "MRN field missing in 12345 rows",
        "the MRN was not found after 3 attempts",
        "set mrn_field = PID-3 in config",
    ],
)
def test_ordinary_numbers_and_a_bare_mrn_label_survive(line: str) -> None:
    assert redact(line) == line


def test_a_fused_mrn_token_is_a_stated_residual() -> None:
    """``MRN4455667`` is ONE token, the single-token residual the module docstring names. Pinned so a
    change to it is deliberate: widening the label to swallow it would also scrub every structured
    fixture's MRN in ``tests/test_redaction_structured_shapes.py`` and blind their positive controls."""
    assert redact("rejected MRN4455667 today") == "rejected MRN4455667 today"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Partner negative-acknowledgment text: the name run takes the word before the label and keeps
        # the label, so the second stage still reads the number after it.
        ("INVALID MRN 12345678 rejected", "[redacted] MRN [redacted] rejected"),
        ("PATIENT MRN 12345 not found", "[redacted] MRN [redacted] not found"),
        ("DUPLICATE MRN: 12345678", "[redacted] MRN: [redacted]"),
        ("Unknown Mrn 4455667 here", "[redacted] Mrn [redacted] here"),
    ],
)
def test_an_mrn_label_ending_a_name_run_is_kept_and_its_number_scrubbed(
    text: str, expected: str
) -> None:
    assert redact(text) == expected
    assert redact(redact(text)) == expected


def test_an_all_caps_word_after_the_label_is_a_stated_residual() -> None:
    """``MRN AB`` is a name run that ENDS in ``AB``, so the label goes with it and the number stands
    alone, exactly as it did before BACKLOG #2079. Pinned so a change is deliberate."""
    assert redact("MRN AB-12345 not found") == "[redacted]-12345 not found"


def test_the_label_is_the_only_name_run_token_kept() -> None:
    """A name BESIDE the label still goes: only the trailing ``MRN`` survives a run."""
    assert redact("ZQXDOE JANEX MRN 12345") == "[redacted] MRN [redacted]"
    assert redact("MRN ZQXDOE JANEX 12345") == "[redacted] 12345"


@pytest.mark.parametrize(
    ("tail", "head_holds_value"),
    [
        # The cut falls between the label and the value: the value goes with the dropped tail.
        (" mrn 12345678", False),
        # The cut falls after the value: the whole span stays in the head and is scrubbed there.
        (" mrn 12345678 ", True),
    ],
)
def test_a_cut_cannot_split_a_labelled_mrn(tail: str, head_holds_value: bool) -> None:
    """The register on ``_CUT_CHARS`` asks each pattern whether a cut at a space can leave a fragment
    it no longer matches. The value holds no whitespace, so the only cut inside the span falls between
    label and value, and that drops the value whole. The label is lower case so the name walk leaves
    it alone and this arm measures the MRN pass, not the walk."""
    text = _over_window(tail)
    assert ("12345678" in clamp_untrusted(text)) is head_holds_value, (
        "the cut did not land as named"
    )
    for out in (redact_untrusted(text), safe_text(text, limit=100_000)):
        assert "12345678" not in out, out[-200:]


#: Inputs shaped to make the MRN pass work hardest: a match every few characters, one very long
#: value, and a label repeated with no value after it.
_MRN_HOSTILE = {
    "many-matches": "MRN 1 ",
    "long-value": "MRN " + "1" * 200 + " ",
    "labels-without-values": "MRN MRN mrn: ",
    # Labels joined by a character the value lookahead also reads, with no digit anywhere: unbounded,
    # the lookahead from each start ran to the end of the run, 620 ms a window.
    "labels-joined-by-hyphens": "MRN-",
    "labels-joined-by-dots": "mrn.",
}


@pytest.mark.parametrize("unit", list(_MRN_HOSTILE.values()), ids=list(_MRN_HOSTILE))
def test_the_mrn_pass_stays_linear_and_affordable(unit: str) -> None:
    """8x the input must cost well under 64x the time, and a whole window stays well under a second
    on the event loop. The ratio ceiling is the one the structured passes use."""

    def sized(chars: int) -> str:
        return (unit * (chars // len(unit) + 1))[:chars]

    small, large = sized(8 * 1024), sized(64 * 1024)
    t_small = max(_best_of(lambda: redact(small)), 1e-4)
    t_large = _best_of(lambda: redact(large))
    assert t_large / t_small < 24, f"{t_large / t_small:.1f}x for 8x the input on {unit!r}"
    window = sized(redaction._REDACT_WINDOW)
    assert _best_of(lambda: redact(window)) < 0.5


# --- BACKLOG #2171: a percent-encoded separator counts like the literal one -------------------------

#: The FHIR search shape the row names: one literal separator and two encoded ones. Synthetic values.
_FHIR_SEARCH = "GET /fhir/Patient?identifier=MRN%7C4455667&name=ZQXDOE%5EVANJA"
#: What must not survive it, through any entry point.
_FHIR_PLANTED = ("4455667", "ZQXDOE", "VANJA")


def _every_entry_point(text: str) -> dict[str, str]:
    """``text`` through each way the engine reaches the redactor, named for the failure message."""
    once = redact(text)
    return {
        "redact": once,
        "redact twice": redact(once),
        "safe_text(safe_exc())": safe_text(safe_exc(ValueError(text))),
        "redact_untrusted": redact_untrusted(text),
    }


@pytest.mark.parametrize("encoded", ["%7C", "%7c", "%5E", "%5e", "%7E", "%7e", "%26"])
def test_an_encoded_separator_counts_like_the_literal_one(encoded: str) -> None:
    """Each of the four default separators, in either case, makes a field run on its own."""
    for name, out in _every_entry_point(f"id MRN{encoded}4455667{encoded}H here").items():
        assert "4455667" not in out, f"{name}: {out!r}"
        assert out.endswith("here"), f"{name} took the text after the run: {out!r}"


def test_literal_and_encoded_separators_count_together() -> None:
    """One of each is two, which is the threshold the literal pattern uses. The literal pattern alone
    sees one separator here and passes it."""
    assert redaction._HL7_FIELD_RUN.search("x ZQXDOE|VANJA%5E4455667 y") is None
    for name, out in _every_entry_point("x ZQXDOE|VANJA%5E4455667 y").items():
        for planted in ("ZQXDOE", "VANJA", "4455667"):
            assert planted not in out, f"{name}: {out!r}"


def test_the_fhir_search_shape_is_scrubbed_through_every_entry_point() -> None:
    """The shape the row names. Before this, the literal pattern counted only the ``&`` and the whole
    query walked through."""
    assert redaction._HL7_FIELD_RUN.search(_FHIR_SEARCH) is None, "the control no longer holds"
    for name, out in _every_entry_point(_FHIR_SEARCH).items():
        for planted in _FHIR_PLANTED:
            assert planted not in out, f"{name}: {out!r}"
        assert "GET" in out, f"{name} took the verb with the query: {out!r}"


@pytest.mark.parametrize(
    "text",
    [
        # A search URL glued to the XML element after it: whole-token, the run took `<name><family`.
        '<Patient><meta><source value="Patient?identifier=urn%7C1%5EMR"/></meta>'
        '<name><family value="ZQXDOE"/></name></Patient>',
        # The same in compact JSON: whole-token, the run took the `"name":` key.
        '{"id":"a%7Cb%7Cc","name": "Zqxdoe"}',
        # Before the name run, the encoded run took JANE and left ZQXDOE under the two-token threshold.
        "patient ZQXDOE JANE%7Cx%7Cy",
        # A DICOM keyword glued to the run by punctuation, with its value in the next token.
        "lookup failed: url=/q?a=x%7Cy%7Cz;PatientID= ZQXDOE",
        # The same for a labelled MRN, which only the widened stage reads.
        "lookup failed: x%7Cy%7Cz;mrn: 4455667",
    ],
    ids=["xml-label", "json-key", "name-run", "dicom-keyword", "mrn-label"],
)
def test_the_encoded_run_takes_no_label_or_name_another_pass_needed(text: str) -> None:
    """THE NO-REGRESSION ARM. Each value here was scrubbed before this pattern existed, by a pass that
    needed a label or a second token the encoded run could swallow. It must still go, which is why
    the run comes after both stages of ``redact``."""
    for name, out in _every_entry_point(text).items():
        for planted in ("ZQXDOE", "Zqxdoe", "4455667"):
            assert planted not in out, f"{name}: {out!r}"


def test_a_fhir_or_list_is_one_run() -> None:
    """FHIR joins alternatives with a comma, which must not split the run into one-separator parts."""
    text = "GET /fhir/Patient?identifier=urn%7C4455667,urn%7C7788990"
    for name, out in _every_entry_point(text).items():
        assert "4455667" not in out and "7788990" not in out, f"{name}: {out!r}"


def test_the_screen_spells_the_separators_the_pattern_counts() -> None:
    """THE DRIFT GATE for the screen. ``redact`` skips the encoded run when ``_ENCODED_SEPARATOR``
    finds nothing, so a separator the pattern counts and the screen does not would pass unscrubbed.
    Every ``%`` in the pattern must be inside a copy of the screen's own spelling."""
    pattern = redaction._HL7_ENCODED_FIELD_RUN.pattern
    screen = redaction._ENCODED_SEPARATOR.pattern
    assert screen in pattern
    assert "%" not in pattern.replace(screen, "")


@pytest.mark.parametrize(
    "text",
    [
        "GET /files/a%20b%20c%20d.txt",  # a run of %20 is ordinary text, however long
        # One encoded separator is under the threshold, as one literal one is. A stated residual on
        # the pattern, not an endorsement: FHIR's `identifier=system%7Cvalue` keeps its value.
        "path a%7Cb kept",
        "rate 50%25 of %7 cap",  # an escape that is not a separator, and a truncated one
        "id x%2Fy%2Fz",  # an encoded slash is not an HL7 separator
    ],
)
def test_an_ordinary_escape_is_not_a_field_run(text: str) -> None:
    """THE CONTROL. Every arm above asserts an absence, and scrubbing every ``%`` would satisfy them
    all."""
    assert redact(text) == text


def test_the_placeholder_never_matches_the_encoded_run() -> None:
    """The fixed point ``safe_text`` relies on. ``[redacted]`` holds no separator of either kind."""
    assert redaction._HL7_ENCODED_FIELD_RUN.search(redaction._REDACTED) is None
    once = redact(_FHIR_SEARCH)
    assert redact(once) == once


@pytest.mark.parametrize(
    ("tail", "head_holds_run"),
    [
        # The cut falls before the run: the run goes with the dropped tail.
        (" id=mrn%7c4455667%5e9", False),
        # The cut falls after the run: the whole run stays in the head and is scrubbed there.
        (" id=mrn%7c4455667%5e9 ", True),
    ],
)
def test_a_cut_cannot_split_an_encoded_run(tail: str, head_holds_run: bool) -> None:
    """The register on ``_CUT_CHARS`` asks each pattern whether a cut at a space can leave a fragment
    it no longer matches. The encoded run holds no whitespace, so a cut never falls inside it, and the
    run is kept or dropped whole. Both placements are checked. The run is lower case and ends on a
    digit so the name walk leaves it alone and this arm measures the encoded pass, not the walk."""
    text = _over_window(tail)
    assert ("4455667" in clamp_untrusted(text)) is head_holds_run, "the cut did not land as named"
    for out in (redact_untrusted(text), safe_text(text, limit=100_000)):
        assert "4455667" not in out, out[-200:]


# --- PR 2011 review finding 1: a credential filter runs after this module -----------------------------
#
# The log handler chain runs ``RedactionFilter`` first and the credential filters after it. A run that
# takes a whole token, or the second run of the stages after it, can take a mark those filters read.
# So ``redact`` leaves the encoded run off a text that holds any credential shape. Every arm here goes
# through the real chain in its installed order, ONCE and TWICE: the engine's usual error log calls
# ``safe_exc`` or ``safe_text`` first, and the handler's filter redacts the result again.

#: A synthetic credential: lowercase-led with digits, so no name or date pass is what removes it.
_CREDENTIAL_VALUE = "zq9hunter2z"
#: A token the encoded run takes: two encoded separators and no literal one.
_ENCODED_TOKEN = "x%7Cy%7Cz"
#: Characters that glue a credential label to the run with no whitespace between. At least these;
#: each one kept the value at 6563110bab, which is the reading the fix was measured against.
_LABEL_GLUE = "\"',})(;{[]/.-_|:?#>!*=@+$\\"
#: A pattern that matches nothing. With it in place of the encoded run, ``redact`` is the two stages
#: alone, which is what it was before BACKLOG #2171.
_NO_ENCODED_RUN = re.compile(r"(?!)")


def _through_the_log_filter_chain(text: str) -> str:
    """``text`` as a log message through the filters ``_install_phi_filters`` puts on every handler,
    in their installed order."""
    handler = logging.Handler()
    logging_setup._install_phi_filters(handler)
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "%s", (text,), None)
    assert handler.filter(record)
    return record.getMessage()


def _every_log_path(text: str) -> dict[str, str]:
    """``text`` by routes the engine uses, at least these: straight to the handler, redacted
    first by ``safe_text`` or ``safe_exc`` as an error log call does, the store's two calls, and
    two handlers on one record."""
    return {
        "once": _through_the_log_filter_chain(text),
        "safe_text": _through_the_log_filter_chain(safe_text(text, limit=100_000)),
        "safe_exc": _through_the_log_filter_chain(safe_exc(ValueError(text), limit=100_000)),
        # The store's own two calls, with no handler after them.
        "store": safe_text(safe_exc(ValueError(text), limit=100_000), limit=100_000),
        # One record through two handlers. Each runs the whole chain, control-character
        # filter included, so the second sees what the first wrote.
        "two handlers": _through_the_log_filter_chain(_through_the_log_filter_chain(text)),
    }


def _kept_that_the_stages_alone_scrub(
    monkeypatch: pytest.MonkeyPatch, text: str, values: tuple[str, ...]
) -> list[str]:
    """Each ``path: value`` this head keeps and the redactor without the encoded run scrubs.

    The baseline is this module with the run switched off, on the same three log paths. It stands in
    for the redactor before BACKLOG #2171 inside the suite. It is not that redactor exactly: the
    BACKLOG #2312 change to the backstop is in both arms. The differential against the earlier
    file itself is on the pull request."""
    head = _every_log_path(text)
    with monkeypatch.context() as patched:
        patched.setattr(redaction, "_HL7_ENCODED_FIELD_RUN", _NO_ENCODED_RUN)
        base = _every_log_path(text)
    return [
        f"{path}: {value}"
        for path in head
        for value in values
        if value in text and value in head[path] and value not in base[path]
    ]


def _assert_the_chain_drops_the_credential(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    """The value is gone from the chain's output, and no log path keeps it where the stages alone
    would scrub it. THE CONTROL comes first: the credential stage alone must scrub this shape, or the
    arm would pass on a shape nothing reads."""
    assert _CREDENTIAL_VALUE in text
    assert _CREDENTIAL_VALUE not in secretscrub.scrub_credentials(text), "the control does not hold"
    out = _through_the_log_filter_chain(text)
    assert _CREDENTIAL_VALUE not in out, out
    assert not _kept_that_the_stages_alone_scrub(monkeypatch, text, (_CREDENTIAL_VALUE,))


@pytest.mark.parametrize("glue", list(_LABEL_GLUE))
def test_a_credential_label_glued_to_an_encoded_run_still_loses_its_value(
    glue: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The label sits in the run's token and its value in the next one."""
    _assert_the_chain_drops_the_credential(
        monkeypatch, f"{_ENCODED_TOKEN}{glue}password: {_CREDENTIAL_VALUE}"
    )


@pytest.mark.parametrize(
    "label",
    [
        *secretscrub._CREDENTIAL_WORDS,
        *secretscrub._TOKEN_WORDS,
        *secretscrub._KEY_MATERIAL_WORDS,
        f"{secretscrub._ENV_PREFIX}VALUE_PW",
        "db_password",
        "a_b_c_d_e_f_password",
        "PWD",
    ],
)
def test_every_credential_label_word_is_still_read_after_an_encoded_run(
    label: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Read from ``secretscrub``'s own tuples, so a word added there and not to
    ``redaction._CREDENTIAL_AHEAD`` goes red here by behaviour as well as in the gate below. The
    six-segment label holds the prefix bound to the credential stage's."""
    _assert_the_chain_drops_the_credential(
        monkeypatch, f"{_ENCODED_TOKEN},{label}: {_CREDENTIAL_VALUE}"
    )


@pytest.mark.parametrize(
    "text",
    [
        '{"q":"' + _ENCODED_TOKEN + '","password": "' + _CREDENTIAL_VALUE + '"}',
        f"({_ENCODED_TOKEN})secret: {_CREDENTIAL_VALUE}",
        f"{_ENCODED_TOKEN},password = {_CREDENTIAL_VALUE}",
        f'{_ENCODED_TOKEN},"password" : "{_CREDENTIAL_VALUE}"',
        f"{_ENCODED_TOKEN},Authorization: Basic {_CREDENTIAL_VALUE}",
        f"{_ENCODED_TOKEN},Authorization:Digest {_CREDENTIAL_VALUE}",
        f"{_ENCODED_TOKEN},Bearer {_CREDENTIAL_VALUE}",
        f"{_ENCODED_TOKEN},password:\n  {_CREDENTIAL_VALUE}",
        f"{_ENCODED_TOKEN}%7Cdb_password: {_CREDENTIAL_VALUE}",
        # The label is outside the run's token, and the run takes one end of a quoted value.
        f'password: "{_ENCODED_TOKEN} {_CREDENTIAL_VALUE} tail"',
        f'password: "aa {_CREDENTIAL_VALUE} {_ENCODED_TOKEN}"',
        f'password: "aa {_CREDENTIAL_VALUE} {_ENCODED_TOKEN}"tail',
        f'password :"{_ENCODED_TOKEN} {_CREDENTIAL_VALUE} tail"',
        f'password:\n "aa {_CREDENTIAL_VALUE} {_ENCODED_TOKEN}"',
        # The value opens inside the run's token and closes outside it.
        f'{_ENCODED_TOKEN},password="aa {_CREDENTIAL_VALUE} tail"',
        f"{_ENCODED_TOKEN};PWD={{aa {_CREDENTIAL_VALUE}}}",
        f"PWD={{{_ENCODED_TOKEN} {_CREDENTIAL_VALUE}}}",
        f"PWD={{aa\n{_CREDENTIAL_VALUE} {_ENCODED_TOKEN}}}",
        f"PWD={{aa\nsecret: b\n{_CREDENTIAL_VALUE} {_ENCODED_TOKEN}}}",
        f"PWD={{aa token: q}} bb\n{_CREDENTIAL_VALUE} {_ENCODED_TOKEN}}}",
    ],
    ids=[
        "compact-json",
        "parenthesis",
        "spaced-equals",
        "quoted-key-spaced-colon",
        "basic-scheme",
        "glued-digest-scheme",
        "bare-bearer",
        "value-on-next-line",
        "prefixed-label-after-separator",
        "quoted-value-run-first",
        "quoted-value-run-last",
        "quoted-value-closed-inside-token",
        "separator-leads-the-token",
        "quoted-value-on-next-line",
        "quoted-value-opens-in-token",
        "braced-value-opens-in-token",
        "braced-value-run-first",
        "brace-closes-in-the-run-token",
        "brace-with-a-label-inside",
        "brace-with-an-early-closer-inside",
    ],
)
def test_a_credential_span_that_crosses_an_encoded_run_is_still_scrubbed(
    text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ways a credential match can reach across the run's token, at least these: the label, the
    separator, an auth scheme, or one end of a quoted or braced value inside it, and the rest
    outside."""
    _assert_the_chain_drops_the_credential(monkeypatch, text)


@pytest.mark.parametrize(
    "text",
    [
        # Found against the cuts of this fix that kept a label inside the replaced token.
        f"secret: abc;x%7Cy%7C_password: {_CREDENTIAL_VALUE}",
        f"db_password: &url%26x%7Cy%7Cdb_password: {_CREDENTIAL_VALUE}",
        f"x%7Cy|_password: secret: {_CREDENTIAL_VALUE}",
        f"mode=a%7Cb%7Coauth_bearer password: {_CREDENTIAL_VALUE}",
        f"lookup x%7Cy%7Cz;vault_token=Basic {_CREDENTIAL_VALUE}",
        f"x%7Cy%7Cuser_Session Token: {_CREDENTIAL_VALUE}",
        f"x%7Cy%7CDB_PWD SECRET={_CREDENTIAL_VALUE}",
        f"x%7Cy%7CDB_PWD| password:\n {_CREDENTIAL_VALUE}",
        '{"name": "x%7Cy%7C.password": "' + _CREDENTIAL_VALUE + '"}',
        f"nonnumeric port: 'x a%7Cb%7C{'c' * 300} secret: abc@{_CREDENTIAL_VALUE}",
        # Found against the cut that skipped only the tokens a credential match could reach: the
        # run's token ended a label-anchored PHI value, and the stages, run again, read on past the
        # placeholder and took the credential label.
        "PatientID=123 url=http://h/fhir?identifier=a%7Cb%7Cc "
        f"Authorization: Basic {_CREDENTIAL_VALUE}==",
        f"PatientName=x key=a%7Cb%7Cc password:\n{_CREDENTIAL_VALUE}",
        f"(0010,0010) PN Doe (0008,0018)x%7Cy%7Cz secret:\n{_CREDENTIAL_VALUE}",
        f"a&Doe Jane&password: {_CREDENTIAL_VALUE}\nGET /q?id=x%7Cy%7Cz",
        f'password: "aa {_CREDENTIAL_VALUE} token: Basic\nabc x%7Cy%7Cz"',
        f'password: "aa {_CREDENTIAL_VALUE} Authorization: Digest\nabc x%7Cy%7Cz"',
        # A credential with no label: the stages, run again, cut it at the `;`.
        f"PatientID=123 q=a%7Cb%7Cc connect postgres://admin:zq9;{_CREDENTIAL_VALUE}@db/x",
        f"PatientID=123 q=a%7Cb%7Cc GET /cb?code=zq9;{_CREDENTIAL_VALUE}",
        f"connect failed postgres://admin:{_CREDENTIAL_VALUE}@db.internal/x?a=1%7C2%7C3",
    ],
    ids=[
        "value-ends-at-semicolon",
        "ampersand-leads-the-token",
        "not-a-label-to-the-stage",
        "underscore-prefixed-bearer",
        "underscore-prefixed-token",
        "title-case-label-words",
        "upper-case-label-words",
        "label-word-before-a-pipe",
        "json-name-string",
        "backstop-on-a-shortened-line",
        "run-ended-a-dicom-value",
        "run-ended-a-dicom-value-next-line",
        "run-ended-a-dicom-tag-value",
        "second-run-finishes-a-literal-run",
        "basic-scheme-then-line-break",
        "digest-scheme-then-line-break",
        "url-password-cut-at-a-semicolon",
        "query-code-cut-at-a-semicolon",
        "url-password-in-the-run-token",
    ],
)
def test_the_shapes_three_code_reviews_found_keep_no_credential(
    text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each kept its value at some head of this pull request, on one call or on the second:
    e68fbc2896, 6c018c5e16, 229e63cf82 or a7cbd25488."""
    assert _CREDENTIAL_VALUE in text
    assert not _kept_that_the_stages_alone_scrub(monkeypatch, text, (_CREDENTIAL_VALUE,))
    assert _CREDENTIAL_VALUE not in _through_the_log_filter_chain(text)


@pytest.mark.parametrize(
    ("password", "word"),
    [
        ("password", "password"),
        ("secret", "secret"),
        ("Token", "Token"),
        ("my.secret", "secret"),
        ("prod-pass", "pass"),
        ("db.basic-9", "basic"),
        ("MEFOR_PROD_2024", "MEFOR_PROD_2024"),
    ],
)
def test_a_url_password_spelled_like_a_label_word_is_scrubbed(
    password: str, word: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A password with NO label, in a URL's userinfo, beside an encoded run in the query (PR 2011
    review finding N1). At 6c018c5e16 the run kept bare label words, so the word came out between
    two placeholders, whole or as the dot- or dash-bounded part of a longer password. THE CONTROL:
    the credential stage alone scrubs it."""
    text = f"GET https://svc:{password}@db.internal/fhir/Patient?identifier=x%7Cy%7Cz failed"
    assert f":{password}@" not in secretscrub.scrub_credentials(text), "the control does not hold"
    for path, out in _every_log_path(text).items():
        if path != "store":  # no credential filter runs on the store's own path, then or now
            assert word not in out, f"{path}: {out!r}"
    # The URL password is what switches the run off here. Without that, the run takes the
    # token whole and the arm above still passes, so it would not hold the rule.
    assert redact(text) == redaction._redact_stages(text)


#: The grammar the second reviewer named as the instrument for this change: a label-anchored PHI
#: value, then an encoded run, then a credential form or none. Synthetic values throughout.
_GRAMMAR_PHI = ("Zqxdoe", "ZQXDOE", "VANJA", "12345", "4455667", "1980-05-05")
_GRAMMAR_HEADS = (
    "PatientID=12345",
    "PatientName=Zqxdoe",
    "(0010,0010) PN Zqxdoe",
    "(0010,0020) LO 4455667",
    "PatientBirthDate=1980-05-05",
    "OtherPatientIDs=4455667",
    '"family": "Zqxdoe",',
    "mrn: 4455667",
    '<family value="Zqxdoe"/>',
    "patient ZQXDOE VANJA",
    "MRN 4455667",
    "dob 1980-05-05",
)
_GRAMMAR_RUNS = (
    "url=https://h/fhir?identifier=a%7Cb%7Cc",
    "key=a%7Cb%7Cc",
    "(0008,0018)x%7Cy%7Cz",
    "q=a%7Cb&c",
    "'x%5Ey%5Ez'",
    "id=u%7Cv%7Cw,",
)
_GRAMMAR_CREDENTIALS = (
    f"Authorization: Basic {_CREDENTIAL_VALUE}==",
    f"Authorization: Bearer {_CREDENTIAL_VALUE}",
    f"password: {_CREDENTIAL_VALUE}",
    f"password:\n{_CREDENTIAL_VALUE}",
    f"password={_CREDENTIAL_VALUE}",
    f'secret: "aa {_CREDENTIAL_VALUE} bb"',
    f"PWD={{aa {_CREDENTIAL_VALUE}}}",
    f"Bearer {_CREDENTIAL_VALUE}",
    f"token={_CREDENTIAL_VALUE}",
    f"api_key: {_CREDENTIAL_VALUE}=",
    f"MEFOR_X={_CREDENTIAL_VALUE}",
    f"private_key={_CREDENTIAL_VALUE}=",
    f'password = "{_CREDENTIAL_VALUE}"',
    f"postgres://admin:{_CREDENTIAL_VALUE}@db/x",
    f"postgres://admin:zq9;{_CREDENTIAL_VALUE}@db/x",
    f"GET /cb?code={_CREDENTIAL_VALUE}",
    f"GET /cb?code=zq9;{_CREDENTIAL_VALUE}",
    f"session: {_CREDENTIAL_VALUE}",
    f"db_password:\n {_CREDENTIAL_VALUE}",
    f"Authorization: Digest\n{_CREDENTIAL_VALUE}",
    f"secret:\t{_CREDENTIAL_VALUE}==",
    # No credential: the texts the encoded run applies to.
    "",
    "status 404 not found",
)


def _grammar_texts() -> list[str]:
    return [
        f"{head} {run}{glue}{credential}"
        for head in _GRAMMAR_HEADS
        for run in _GRAMMAR_RUNS
        for glue in (" ", "\n", ",")
        for credential in _GRAMMAR_CREDENTIALS
    ]


def test_no_log_path_keeps_what_the_stages_alone_scrub_over_the_grammar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NEVER WORSE THAN BEFORE THE ENCODED RUN, once through and twice through. Every text of the
    grammar goes to the log three ways, and nothing planted may survive where the redactor without
    the run scrubs it: not the credential, not a PHI value.

    Measured with this test at earlier heads of the pull request, texts of 4,968 with at least one
    such value on some path: 6563110bab 744, 229e63cf82 186, a7cbd25488 186. THE CONTROLS: the baseline does scrub the credential on most texts, and the run does
    apply on the texts that hold none."""
    values = (_CREDENTIAL_VALUE, *_GRAMMAR_PHI)
    worse = 0
    first = ""
    scrubbed_by_the_chain = 0
    for text in _grammar_texts():
        kept = _kept_that_the_stages_alone_scrub(monkeypatch, text, values)
        if kept:
            worse += 1
            first = first or f"{text!r}: {kept}"
        if _CREDENTIAL_VALUE in text:
            scrubbed_by_the_chain += _CREDENTIAL_VALUE not in _through_the_log_filter_chain(text)
    assert not worse, f"{worse} texts keep a value the stages alone scrub, first {first}"
    assert scrubbed_by_the_chain > 3_500, "the grammar no longer holds credentials the chain reads"
    plain = [text for text in _grammar_texts() if text.endswith("status 404 not found")]
    assert sum("%" not in redact(text) for text in plain) > len(plain) // 2, (
        "the encoded run no longer applies to the texts that hold no credential"
    )


def test_redact_is_a_fixed_point_over_the_grammar() -> None:
    """A second ``redact`` changes nothing, with a credential in the text or without one. At
    a7cbd25488 it did on 748 of the 4,968 texts of this grammar."""
    texts = _grammar_texts()
    assert len(texts) >= 4_000
    moved = [text for text in texts if redact(redact(text)) != redact(text)]
    assert not moved, f"{len(moved)} texts, first {moved[0]!r}"


def test_what_the_credential_filters_write_still_switches_the_run_off() -> None:
    """The rule must answer the same on a second call over the first call's output, when a second
    handler filters a record the first has already scrubbed. The filters keep the label, the scheme
    word, the URL user and the query key, and each of those still matches."""
    for credential in _GRAMMAR_CREDENTIALS[:-2]:
        text = f"id {_ENCODED_TOKEN} {credential}"
        once = _through_the_log_filter_chain(text)
        assert _CREDENTIAL_VALUE not in once, once
        assert "x%7Cy" in once, f"the run was not left alone on the first pass: {once!r}"
        assert redaction._CREDENTIAL_AHEAD.search(once) is not None, once
        assert _through_the_log_filter_chain(once) == once


def test_the_credential_pattern_is_held_to_its_sources() -> None:
    """THE DRIFT GATE, by spelling. ``redaction`` is stdlib-only and cannot import ``secretscrub``
    or ``logging_setup``, so each arm of ``_CREDENTIAL_AHEAD`` is a copy. The arm below it checks
    the same thing by behaviour."""
    pattern = redaction._CREDENTIAL_AHEAD.pattern
    assert secretscrub._LABEL_PREFIX in pattern
    assert secretscrub._ENV_PREFIX in pattern
    words = pattern.split(secretscrub._LABEL_PREFIX + "(?:")[1].split(")")[0].split("|")
    assert set(words) == {
        *secretscrub._CREDENTIAL_WORDS,
        *secretscrub._TOKEN_WORDS,
        *secretscrub._KEY_MATERIAL_WORDS,
    }
    assert "|".join(logging_setup._CREDENTIAL_QUERY_KEYS) in pattern
    url_arm = r"://[^\s:/@]+:[^\s/@]+@"
    assert url_arm in pattern
    assert secretscrub._DSN_PASSWORD.pattern.replace(")", "").endswith(url_arm)


def test_the_credential_pattern_matches_every_text_a_credential_filter_changes() -> None:
    """THE DRIFT GATE, by behaviour. If either credential filter would change a text, the pattern
    must match that text, or the encoded run could apply beside a credential. Seeded, over fragments
    that build each filter's shapes and near misses. THE CONTROL: the filters do change a large
    share of the corpus, and the pattern does not simply match everything."""
    fragments = (
        *secretscrub._CREDENTIAL_WORDS,
        *secretscrub._TOKEN_WORDS,
        *secretscrub._KEY_MATERIAL_WORDS,
        *logging_setup._CREDENTIAL_QUERY_KEYS,
        "MEFOR_X", "Basic", "Digest", "db_", "a.b-", "://", "postgres", "user", "host", "abc123",
        ":", "=", " ", " ", "\n", "\t", '"', "'", "{", "}", "@", "/", "?", "&", ";", ",", "x", "9",
        "_", ".", "-", "%7C",
    )  # fmt: skip
    rand = random.Random(2011)
    changed = unmatched = 0
    for _ in range(20_000):
        text = "".join(rand.choice(fragments) for _ in range(rand.randint(2, 9)))
        if (
            secretscrub.scrub_credentials(text) != text
            or logging_setup._scrub_credential_query(text) != text
        ):
            changed += 1
            assert redaction._CREDENTIAL_AHEAD.search(text) is not None, repr(text)
        elif redaction._CREDENTIAL_AHEAD.search(text) is None:
            unmatched += 1
    assert changed > 500 and unmatched > 2_000, (changed, unmatched)


@pytest.mark.parametrize(
    "text",
    [
        f"{_ENCODED_TOKEN},password: {_CREDENTIAL_VALUE}",
        f'password: "aa {_ENCODED_TOKEN}" tail',
        f"note Bearer {_ENCODED_TOKEN}",
        f"{_ENCODED_TOKEN} password: {_CREDENTIAL_VALUE}",
        f"password: {_CREDENTIAL_VALUE}\nid {_ENCODED_TOKEN} here",
        f"connect postgres://admin:{_CREDENTIAL_VALUE}@db/x id {_ENCODED_TOKEN}",
        f"GET /cb?code={_CREDENTIAL_VALUE} id {_ENCODED_TOKEN}",
        f"state=RUNNING id {_ENCODED_TOKEN}",
    ],
    ids=[
        "label-in-token",
        "token-in-quoted-value",
        "token-after-bearer",
        "run-before-label",
        "run-on-the-next-line",
        "url-password",
        "query-code",
        "ordinary-state-key",
    ],
)
def test_a_text_with_a_credential_shape_is_left_as_the_stages_left_it(text: str) -> None:
    """THE STATED PRICE, pinned so it cannot change unseen. A text that holds a credential shape
    anywhere gets exactly the two stages, as it did before the encoded run existed, and the run in
    it keeps its text. The last arm is the cost at its plainest: an ordinary ``state=`` is a query
    key the credential filter reads, so it switches the run off too."""
    assert redact(text) == redaction._redact_stages(text)
    assert "x%7Cy" in redact(text)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("id zqxdoe%7C4455667%7Cvanja here", "id [redacted] here"),
        # A word that only CONTAINS a label word, or runs on past one, is not a label.
        ("name=zqxdoe%5E4455667%5Ecompass: 404 here", "[redacted] 404 here"),
        ("bypass=zqxdoe%5E4455667%5Eq here", "[redacted] here"),
        ("passwords: 3 id zqxdoe%7C4455667%7Cvanja here", "passwords: 3 id [redacted] here"),
        # A label word with no separator after it, and a URL with no password in it.
        ("the session ended id zqxdoe%7C4455667%7Cvanja", "the session ended id [redacted]"),
        ("GET https://h/q?id=zqxdoe%7C4455667%7Cvanja failed", "GET [redacted] failed"),
    ],
    ids=[
        "no-label",
        "word-inside-a-word",
        "label-word-runs-on",
        "plural-label-word",
        "label-word-without-separator",
        "url-without-userinfo",
    ],
)
def test_a_text_with_no_credential_shape_still_loses_its_encoded_run(
    text: str, expected: str
) -> None:
    """THE CONTROL for the arm above, and the PHI arm: switching the run off everywhere would
    satisfy it."""
    assert redaction._CREDENTIAL_AHEAD.search(text) is None
    assert redact(text) == expected


@pytest.mark.parametrize(
    ("text", "planted"),
    [
        # A URL password split by a line break: one line once the first handler has escaped it.
        (
            f"connect postgres://user:pa%7Cx%7C\n{_CREDENTIAL_VALUE}@host failed",
            _CREDENTIAL_VALUE,
        ),
        # An escaped control character becomes text that completes a readable label.
        (f"x%7Cy%7C\x01_password: {_CREDENTIAL_VALUE}", _CREDENTIAL_VALUE),
        # A key glued to the run, its value after the break.
        ('Doe Janepw:%7E"mrn":PWD|44556674455667\n#Zqxdoe%7e', "Zqxdoe"),
    ],
    ids=["url-password-over-a-line-break", "escaped-control-character", "key-before-a-line-break"],
)
def test_a_text_with_an_unprintable_character_keeps_its_run_for_the_second_handler(
    text: str, planted: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One record through two handlers. The first handler's control-character filter writes a line
    break as visible text, so the second reads one line where the first read two, and scrubs a
    value that needed both halves. A run replaced on the first pass cannot be put back, so the run
    stays off such a text. THE CONTROL: with the run off, the second handler does scrub the value;
    with the unprintable-character rule removed from ``redact``, each arm goes red."""
    with monkeypatch.context() as patched:
        patched.setattr(redaction, "_HL7_ENCODED_FIELD_RUN", _NO_ENCODED_RUN)
        assert planted not in _every_log_path(text)["two handlers"], "the control does not hold"
    assert not _kept_that_the_stages_alone_scrub(monkeypatch, text, (planted,))
    assert redact(text) == redaction._redact_stages(text)


@pytest.mark.parametrize(
    ("text", "planted"),
    [
        ('&%7e - &ok%7E"name": 7788990 ', "7788990"),
        ('Qorvel Digest Zqxdoe%7E%5E"name":  <ok.Qorvel& ', "Qorvel"),
    ],
    ids=["bare-value-ends-the-text", "value-ends-the-text-after-a-strip"],
)
def test_a_key_the_widened_stage_reads_is_not_taken_by_the_run(
    text: str, planted: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second call can scrub a value the first kept, but only while its key is still there. Both
    shapes came from a fuzz, where the run took a ``"name":`` key glued to its token and the value
    then survived ``safe_text`` followed by the chain. THE CONTROL: without the encoded run, that
    path does scrub the value."""
    with monkeypatch.context() as patched:
        patched.setattr(redaction, "_HL7_ENCODED_FIELD_RUN", _NO_ENCODED_RUN)
        assert planted not in _every_log_path(text)["safe_text"], "the control does not hold"
    assert not _kept_that_the_stages_alone_scrub(monkeypatch, text, (planted,))
    assert redact(text) == redaction._redact_stages(text)


def test_the_stages_run_again_over_what_the_encoded_run_changed() -> None:
    """Pins the second ``_redact_stages`` call in ``redact`` (PR 2011 review finding 5): returning
    the run's output directly left every other test green. The shape came from a search over fuzzed
    inputs. THE CONTROL is the middle assertion: the name survives the stages and the run, so the
    second pass of the stages is what removes it."""
    text = "PatientName=patient   key=%7c,%7C%7e%26 zq9hunter2zQorvel:  Zqxdoe"
    staged = redaction._redact_stages(text)
    assert text.isprintable() and redact(text) != staged, "the run must apply to this text"
    assert redaction._CREDENTIAL_AHEAD.search(staged) is None, "the run must apply to this text"
    after_run = redaction._HL7_ENCODED_FIELD_RUN.sub(redaction._REDACTED, staged)
    assert "Zqxdoe" in after_run, "the control no longer holds"
    assert "Zqxdoe" not in redact(text)


@pytest.mark.parametrize(
    "text",
    [
        # The run would take the token that holds the opener's quote.
        f"nonnumeric port: 'a%7Cb%7Cc d|e|{'f' * 300} {_CREDENTIAL_VALUE}@host",
        # The run would take the token that holds the closing `@`.
        f"nonnumeric port: '{_CREDENTIAL_VALUE} d|e|{'f' * 300} x%7Cy%7Cz@host",
        # The run would shorten the line and bring the `@` within the backstop's bound.
        f"nonnumeric port: 'x a%7Cb%7C{'c' * 300} {_CREDENTIAL_VALUE}@host",
    ],
    ids=["run-holds-the-opener-quote", "run-holds-the-closing-at", "run-shortens-the-line"],
)
def test_the_backstop_opener_switches_the_encoded_run_off(
    text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The credential backstop reads an opener, a tail and an ``@`` on one line, and a second call
    can reach an ``@`` the first could not, once the literal run has shortened the line. The encoded
    run must not take either end of that span first. THE CONTROL: on the first two, the store's two
    calls do scrub the value when the run is off."""
    assert redact(text) == redaction._redact_stages(text)
    assert not _kept_that_the_stages_alone_scrub(monkeypatch, text, (_CREDENTIAL_VALUE,))
    if "d|e|" in text:
        assert _CREDENTIAL_VALUE not in _every_log_path(text)["store"]


# --- BACKLOG #2312: the credential backstop leaves its own output alone ------------------------------

#: The backstop as it shipped before #2312, for the positive control below and for nothing else.
_PRE_2312_BACKSTOP = re.compile(r"(nonnumeric port: ')[^\r\n]{1,256}@")

#: Synthetic passwords, lowercase-led and digit-bearing so no name or date pass is what removes them.
_PW_ONE = "ab0c" * 25
_PW_TWO = "zy9x" * 25
_PW_REAL = "realpw7q"


def _two_credential_spans() -> str:
    """Two ``http.client`` credential messages on one line, placed so the second ``@`` is past the
    bound from the first opener on the first pass and inside it once both passwords are scrubbed.

    That geometry is the whole defect: each scrub shortens the line, so a span the first pass could not
    reach comes within reach of the next. The ``keep`` words between are the operator text a second
    pass used to swallow."""
    return (
        f"first nonnumeric port: '{_PW_ONE}@h1.example'"
        + " keep" * 20
        + f" nonnumeric port: '{_PW_TWO}@h2.example' end"
    )


def _pre_2312_scrub(text: str) -> str:
    return _PRE_2312_BACKSTOP.sub(lambda m: f"{m.group(1)}[redacted]@", text)


def test_the_two_span_fixture_really_reaches_across_on_the_old_backstop() -> None:
    """THE POSITIVE CONTROL. An idempotence arm passes vacuously on a line no second pass could
    change, so show the pre-fix backstop really does swallow this gap on its second run."""
    once = _pre_2312_scrub(_two_credential_spans())
    assert "keep" in once, "the first pass already spans the gap, so the fixture is mis-sized"
    assert "keep" not in _pre_2312_scrub(once), (
        "the old backstop no longer swallows this gap on a second pass"
    )


def test_the_credential_backstop_is_a_fixed_point_on_two_spans_it_scrubbed() -> None:
    """BACKLOG #2312: a second pass over two scrubbed spans changes nothing, through ``redact`` and
    through the stored-error pairing ``safe_exc`` then ``safe_text``."""
    text = _two_credential_spans()
    once = redact(text)
    assert once == (
        "first nonnumeric port: '[redacted]@h1.example'"
        + " keep" * 20
        + " nonnumeric port: '[redacted]@h2.example' end"
    )
    assert redact(once) == once

    stored = safe_exc(ValueError(text), limit=100_000)
    restored = safe_text(stored, limit=100_000)
    assert restored == stored
    for out in (once, stored, restored, redact_untrusted(text)):
        assert _PW_ONE not in out and _PW_TWO not in out
        assert "keep" in out and "h1.example" in out and "h2.example" in out


def test_a_placeholder_inside_a_password_does_not_shield_what_follows_it() -> None:
    """Text can carry ``[redacted]@`` itself, and the tail stays greedy to the LAST ``@``. So a bare
    placeholder in the tail stops nothing, and the real password after it still goes. Only the
    opener and placeholder together mark a span as already scrubbed."""
    text = f"nonnumeric port: 'u:[redacted]@x:{_PW_REAL}@host.example'"
    out = redact(text)
    assert out == "nonnumeric port: '[redacted]@host.example'"
    assert redact(out) == out
    assert _PW_REAL not in redact_untrusted(text)
    assert _PW_REAL not in safe_text(safe_exc(ValueError(text)))


def test_the_real_producer_never_quotes_a_placeholder() -> None:
    """Why the stated residual on ``_INVALID_URL_USERINFO`` cannot reach the shape the backstop exists
    for. ``http.client`` quotes what follows the LAST ``:``, and only when no ``]`` comes after it, so
    the "port" it writes holds neither. Handed the hostile netloc above, it quotes only the real
    password and the host."""
    with pytest.raises(http.client.InvalidURL) as caught:
        http.client.HTTPConnection(f"u:[redacted]@x:{_PW_REAL}@host.example")
    message = str(caught.value)
    assert message == f"nonnumeric port: '{_PW_REAL}@host.example'"
    assert _PW_REAL not in redact(message)


def test_a_match_may_start_on_the_scrubbed_form_and_still_take_what_follows() -> None:
    """The start is not guarded, so text that opens with the scrubbed form is no shield. Only the
    tail's crossing of a LATER scrubbed span is refused."""
    text = f"nonnumeric port: '[redacted]@x {_PW_REAL}@host.example'"
    assert redact(text) == "nonnumeric port: '[redacted]@host.example'"


def test_a_later_pass_finishes_a_password_whose_last_at_was_past_the_bound() -> None:
    """Why the start is not guarded. A password with an inner ``@`` and its last ``@`` past the bound
    is scrubbed only to the inner one. A later pass sees a shorter line and reaches the last one. The
    stored error runs ``safe_exc`` then ``safe_text``, so that is the path that must finish it. A
    start guard kept the hundred characters after the inner ``@``."""
    text = "nonnumeric port: '" + "a" * 200 + "@" + "q7" * 50 + "@host.example'"
    once = redact(text)
    assert "q7" * 50 in once, "one pass already reaches the last @, so the fixture is mis-sized"
    assert "q7" not in redact(once)
    assert "q7" not in safe_text(safe_exc(ValueError(text)), limit=100_000)


def _opener_then_scrubbed_span() -> str:
    """An opener with no ``@`` of its own, then a credential message. The first pass cannot reach the
    second ``@`` from the first opener (it is past the bound) and scrubs only the second span. That
    shortens the line enough for the next pass to reach it. Only the tail guard stops that pass."""
    return "nonnumeric port: 'abc'" + " keep" * 44 + f" nonnumeric port: '{_PW_TWO}@h2.example' end"


def test_the_tail_guard_fixture_reaches_across_without_it() -> None:
    """THE POSITIVE CONTROL for the arm below. Its first opener is NOT scrubbed on the first pass, so
    only the tail guard, never a start guard, can be what holds the fixed point."""
    once = _pre_2312_scrub(_opener_then_scrubbed_span())
    assert "nonnumeric port: 'abc'" in once, "the first pass reached the second @ after all"
    assert "keep" not in _pre_2312_scrub(once), "the old backstop no longer swallows this gap"


def test_the_tail_never_crosses_a_later_scrubbed_span() -> None:
    """BACKLOG #2312, the arm that fails if the tail guard is removed."""
    once = redact(_opener_then_scrubbed_span())
    assert _PW_TWO not in once
    assert redact(once) == once
    assert "keep" in redact(once)


def test_the_tail_guard_spells_the_form_the_scrub_writes() -> None:
    """THE DRIFT GATE for the copy inside the tail guard. The pattern spells the opener and the
    placeholder again there, as literals for the static regex gate. If either drifts from the form
    the scrub writes, the guard stops recognising it and the fixed point breaks silently."""
    form = redaction._USERINFO_OPENER + re.escape(redaction._REDACTED) + "@"
    assert f"n(?!{form[1:]})" in redaction._INVALID_URL_USERINFO.pattern
    written = redaction._INVALID_URL_USERINFO.sub(
        lambda m: f"{m.group(1)}{redaction._REDACTED}@", f"x {redaction._USERINFO_OPENER}pw0@h"
    )
    assert written == f"x {redaction._USERINFO_OPENER}{redaction._REDACTED}@h"


#: Inputs shaped to make the backstop work hardest: openers with no ``@``, scrubbed forms with the
#: ``@`` missing so each lookahead reads nearly the whole form, and scrubbed spans packed tight.
_BACKSTOP_HOSTILE = {
    "openers-without-at": "nonnumeric port: '",
    "near-scrubbed-forms": "nonnumeric port: '[redacted]",
    "scrubbed-spans": "nonnumeric port: '[redacted]@h ",
    "opener-then-at": "nonnumeric port: 'x@",
}


#: Inputs shaped to make the encoded-run pass work hardest: a match every few characters, escapes
#: that are not separators, a separator prefix that never completes, and one-separator tokens. Every
#: unit but the first holds one encoded separator per token, so the screen lets it through and the
#: pattern's body lookahead runs at every ``%`` without a match to end the attempt early.
_ENCODED_HOSTILE = {
    "many-matches": "a%7Cb%5Ec ",
    "non-separator-escapes": "a%20%20%20%20%7Cb ",
    "unfinished-escapes": "%7%7%7%7%7Cb ",
    "bare-percents": "%%%%%7Cb ",
    # A literal separator per token, so the literal pass leaves it and the pattern restarts after it.
    "restart-after-literal": "a|b c%7Cd ",
    # One long token with one separator: a single attempt walks all of it.
    "one-long-token": "%20" * 1000 + "%7C ",
    # The credential scan runs once a qualifying run is found. With no credential shape in the
    # text it reads all of it, and a dotted and hyphenated run offers a label start at every
    # segment. The second unit holds label words with no separator after them.
    "label-prefix-run": "a-b.c-" * 40 + " x%7Cx%7Cy ",
    "label-words-no-separator": "pass-token.secret-" * 12 + "%7Cx%7Cy ",
}


@pytest.mark.parametrize(
    "unit",
    [*_BACKSTOP_HOSTILE.values(), *_ENCODED_HOSTILE.values()],
    ids=[
        *(f"backstop-{k}" for k in _BACKSTOP_HOSTILE),
        *(f"encoded-{k}" for k in _ENCODED_HOSTILE),
    ],
)
def test_the_backstop_and_the_encoded_run_stay_linear_and_affordable(unit: str) -> None:
    """8x the input must cost well under 64x the time, and a whole window stays well under a second
    on the event loop. The same ceilings as the MRN pass above."""

    def sized(chars: int) -> str:
        return (unit * (chars // len(unit) + 1))[:chars]

    small, large = sized(8 * 1024), sized(64 * 1024)
    t_small = max(_best_of(lambda: redact(small)), 1e-4)
    t_large = _best_of(lambda: redact(large))
    assert t_large / t_small < 24, f"{t_large / t_small:.1f}x for 8x the input on {unit!r}"
    window = sized(redaction._REDACT_WINDOW)
    assert _best_of(lambda: redact(window)) < 0.5
