"""PHI redaction on the exception/logging path (WP-6c, ASVS 16.2.5 / PHI.md P1-3): redact() scrubs
HL7-shaped content; safe_exc() keeps the exception type while redacting + bounding the message."""

from __future__ import annotations

from messagefoundry.redaction import redact, safe_exc

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
