# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""PHI redaction on the exception/logging path (WP-6c, ASVS 16.2.5 / PHI.md P1-3): redact() scrubs
HL7-shaped content; safe_exc() keeps the exception type while redacting + bounding the message;
safe_name() derives a safe label for a partner-chosen file name, which redact() is measured blind to
(BACKLOG #1748)."""

from __future__ import annotations

import random
import re
import time
from collections.abc import Callable

import pytest
from _phi_log_capture import IDENTIFIER_SHAPED_NAMES, SAFE_NAME_SUFFIXES

from messagefoundry import redaction
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
    headerless fragment, exactly as it does for a bare single-token identifier."""
    assert redact("mrn MRN123$$$H$MR here") == "mrn MRN123$$$H$MR here"


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
    """THE COST HALF, in the shape ``test_the_token_walk_is_bounded_by_the_window_not_by_the_peer``
    established: the PEER chooses how many passes the walk takes, so each pass has to stay inside the
    region it drops.

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


def _three_step_clamp(text: str, window: int) -> tuple[str, int]:
    """``_clamp`` with the walk PR 1319 shipped: at most three tokens, then stop.

    Kept as the positive control for the arm below and for nothing else. An absence arm over a random
    corpus is worthless until something shows the corpus can produce the thing being asserted absent,
    and the honest something is the defect itself."""
    if len(text) <= window:
        return text, 0
    cut = max(redaction._last_cut(text, window), 0)
    for _ in range(3):
        if not cut:
            break
        end = len(text[:cut].rstrip(redaction._CUT_CHARS))
        start = redaction._last_cut(text, end) + 1
        if not redaction._ends_with_name_token(text[start:end]):
            break
        cut = start
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


def test_the_token_walk_is_bounded_by_the_window_not_by_the_peer() -> None:
    """THE OTHER HALF OF THE LEAK FIX, and the one an absence arm cannot see.

    The walk drops name-shaped tokens until it meets one that is not, rather than a fixed three, so
    the PEER chooses how many steps it takes. That is only safe while each step's work stays inside
    the region being dropped. Spelled the obvious way -- ``text[:cut].rstrip(...)`` paired with
    ``_last_cut`` -- each step copies from index 0 and rescans from index 0, and the walk is quadratic
    in the window: the exact cost class BACKLOG #1576 exists to bound, rebuilt inside the fix for it.

    The fixture is the most steps a window can buy: the shortest legal ALLCAPS token plus one space,
    21,820 of them, with a non-whitespace run behind so the cut lands at the end of the run and the
    walk has to travel the whole way back. Measured best-of-3 on the author's box, 6.2 ms here against
    630 ms for the ``_last_cut`` spelling, which is why the budget separates them at all."""
    window = redaction._REDACT_WINDOW - redaction._CLAMP_MARKER_BUDGET
    run = ("AA " * (window // 3 + 1))[:window]
    hostile = run + "Q" * 200_000

    best = _best_of(lambda: clamp_untrusted(hostile))
    assert best < _SCAN_BUDGET_SECONDS, (
        f"clamping {len(run)} characters of name-shaped tokens cost {best:.4f}s of the event loop "
        f"against a {_SCAN_BUDGET_SECONDS}s budget -- the walk is no longer linear in the window"
    )
    # Non-vacuity: a walk that stopped early would be fast for the wrong reason. Every token here is
    # name-shaped back to index 0, so a walk that ran to completion keeps nothing but the note.
    assert clamp_untrusted(hostile).strip().startswith("[redaction bound:"), (
        "the walk stopped before the start of the run, so this fixture is not measuring a full-window "
        "walk and the budget above proves nothing about one"
    )


def test_clamp_untrusted_is_exported() -> None:
    assert "clamp_untrusted" in redaction.__all__
