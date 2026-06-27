# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""PHI redaction on the exception/logging path (WP-6c, ASVS 16.2.5 / PHI.md P1-3): redact() scrubs
HL7-shaped content; safe_exc() keeps the exception type while redacting + bounding the message."""

from __future__ import annotations

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


def test_redact_free_text_heuristic_is_linear() -> None:
    # Bounded {1,n} repetition over disjoint char classes — a long hostile input can't backtrack
    # quadratically. This must return well under a second.
    import time

    s = "A " * 5000
    start = time.perf_counter()
    redact(s)
    assert time.perf_counter() - start < 1.0
