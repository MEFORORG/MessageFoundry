# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Core anonymizer behaviour (ADR 0030): keying, the rule model, surrogates, the HL7 adapter, and the
fail-closed leak-check — engine side."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.anon import (
    DEFAULT_RULES,
    AnonError,
    FieldRule,
    Keyer,
    LeakError,
    RuleError,
    SurrogateKind,
    anonymize,
    anonymize_checked,
    leak_check,
    load_rules,
)
from messagefoundry.anon.surrogates import Seps, scrub_site_codes, surrogate_field

# The leak-check delegates to scripts/publish/scan_forbidden.py (the owner-managed publish guard — a
# dev/source-checkout tool, not in the wheel and deny-listed in the OSS mirror). Skip the two tests that
# exercise it where it's absent; the engine raises LeakCheckUnavailable there by design.
_LEAK_SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "publish" / "scan_forbidden.py"
_NO_SCANNER = pytest.mark.skipif(
    not _LEAK_SCANNER.exists(),
    reason="leak-check needs scripts/publish/scan_forbidden.py (private-only; OSS-mirror deny-list)",
)

_SALT = "unit-salt-0123456789abcdef"
_SEPS = Seps()


def _msg(*segments: str) -> str:
    return "\r".join(segments)


_SAMPLE = _msg(
    r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260101120000||ADT^A01|MSGCTRL|P|2.5.1",
    "EVN|A01|20260101120000",
    r"PID|1||12345^^^HOSP^MR~67890^^^OTH^MR||DOE^JOHN^Q||19800101|M|||9 REAL ST^^TOWN^CA^90210||5551234567",
    "NK1|1|DOE^JANE|SPO|9 REAL ST^^TOWN^CA^90210|5559998888",
    "OBX|1|NM|8480-6^Systolic^LN||128|mm[Hg]",
    "OBX|2|TX|NOTE^Note^LN||Patient JOHN DOE seen",
    "NTE|1||free text note",
)


# --- keying ---------------------------------------------------------------------------------------


def test_keyer_deterministic_and_salt_sensitive() -> None:
    a, b = Keyer("salt-aaaaaaaaaaaaaaaa"), Keyer("salt-aaaaaaaaaaaaaaaa")
    assert a.seed("mrn", "12345") == b.seed("mrn", "12345")
    assert a.seed("mrn", "12345") != a.seed("mrn", "54321")
    assert a.seed("mrn", "12345") != a.seed("name", "12345")  # kind is part of the key
    assert Keyer("other-saltttttttttt").seed("mrn", "12345") != a.seed("mrn", "12345")


def test_keyer_rejects_weak_salt() -> None:
    with pytest.raises(ValueError, match="at least"):
        Keyer("short")
    with pytest.raises(ValueError):
        Keyer("")


# --- rule model -----------------------------------------------------------------------------------


def test_default_rules_loaded_without_overlay() -> None:
    assert load_rules(None) == DEFAULT_RULES
    paths = {r.path for r in DEFAULT_RULES}
    assert {"PID-3", "PID-5", "PID-7", "MRG-1", "MRG-4", "OBX-5", "NTE-3"} <= paths
    # MSH / coded fields are NOT scrubbed (kept by omission)
    assert not any(r.path.startswith("MSH-") for r in DEFAULT_RULES)


def test_overlay_adds_retargets_keeps_drops(tmp_path) -> None:
    overlay = tmp_path / "anon.toml"
    overlay.write_text(
        '[hl7.fields]\n"ZPD-2" = "mrn"\n"PID-5" = "drop"\n\n[hl7]\nkeep = ["PID-13"]\n',
        encoding="utf-8",
    )
    rules = {r.path: r.kind for r in load_rules(overlay)}
    assert rules["ZPD-2"] is SurrogateKind.MRN  # added
    assert rules["PID-5"] is SurrogateKind.DROP  # retargeted
    assert "PID-13" not in rules  # keep cancels the default scrub


@pytest.mark.parametrize(
    "body",
    [
        '[hl7.fields]\n"PID-5.1" = "name"\n',  # component path rejected
        '[hl7.fields]\n"PID-5" = "scramble"\n',  # unknown kind rejected
        "[oops]\nx = 1\n",  # unknown top-level table rejected
        "[hl7]\nwat = 1\n",  # unknown [hl7] key rejected
    ],
)
def test_overlay_schema_is_enforced(tmp_path, body: str) -> None:
    overlay = tmp_path / "anon.toml"
    overlay.write_text(body, encoding="utf-8")
    with pytest.raises(RuleError):
        load_rules(overlay)


# --- surrogates -----------------------------------------------------------------------------------


def test_surrogate_field_maps_each_repetition_and_preserves_authority() -> None:
    keyer = Keyer(_SALT)
    out = surrogate_field(SurrogateKind.MRN, "12345^^^HOSP^MR~67890^^^OTH^MR", keyer, _SEPS)
    reps = out.split("~")
    assert len(reps) == 2
    assert reps[0].endswith("^^^HOSP^MR") and reps[1].endswith("^^^OTH^MR")  # authority kept
    assert "12345" not in out and "67890" not in out  # ids fabricated


def test_freetext_is_blunt_redacted() -> None:
    assert (
        surrogate_field(SurrogateKind.FREETEXT, "anything at all", Keyer(_SALT), _SEPS)
        == "[REDACTED]"
    )


def test_drop_blanks_and_empty_stays_empty() -> None:
    assert surrogate_field(SurrogateKind.DROP, "x", Keyer(_SALT), _SEPS) == ""
    assert surrogate_field(SurrogateKind.NAME, "", Keyer(_SALT), _SEPS) == ""


def test_site_code_scrub_is_field_anchored() -> None:
    keyer = Keyer(_SALT)
    # a whole component that IS a site code is replaced ...
    assert "541001" not in scrub_site_codes("WARD^541001^A", keyer, _SEPS)
    # ... but a 54xxxx INSIDE a longer value (timestamp) is left alone
    assert scrub_site_codes("20260154100123", keyer, _SEPS) == "20260154100123"


# --- HL7 adapter ----------------------------------------------------------------------------------


def test_anonymize_scrubs_phi_keeps_structure_and_routing() -> None:
    out = anonymize(_SAMPLE, salt=_SALT)
    # PHI gone
    for phi in ("DOE", "JOHN", "12345", "67890", "19800101", "9 REAL ST", "5551234567"):
        assert phi not in out, f"PHI {phi!r} leaked"
    # structure/routing kept
    assert "MSGCTRL" in out  # MSH-10 control id preserved (correlation)
    assert "ADT^A01" in out  # message type preserved (routing)
    assert "8480-6" in out and "128" in out  # numeric OBX result preserved
    assert out.count("\r") == _SAMPLE.count("\r")  # same segment count
    # two PID-3 repetitions survive as two repetitions
    pid = next(line for line in out.split("\r") if line.startswith("PID"))
    assert pid.split("|")[3].count("~") == 1


def test_obx5_freetext_only_when_value_type_textual() -> None:
    out = anonymize(_SAMPLE, salt=_SALT)
    obx = [line for line in out.split("\r") if line.startswith("OBX")]
    assert "128" in obx[0]  # NM result kept
    assert "[REDACTED]" in obx[1]  # TX note redacted
    assert "[REDACTED]" in next(line for line in out.split("\r") if line.startswith("NTE"))


def test_anonymize_is_deterministic_and_salt_sensitive() -> None:
    assert anonymize(_SAMPLE, salt=_SALT) == anonymize(_SAMPLE, salt=_SALT)
    assert anonymize(_SAMPLE, salt=_SALT) != anonymize(_SAMPLE, salt="different-saltttttttt")


def test_a40_merge_keeps_pid3_mrg1_linkage() -> None:
    msg = _msg(
        r"MSH|^~\&|A|B|C|D|20260101||ADT^A40|M1|P|2.5.1",
        "PID|1||55501^^^H^MR||SMITH^ANN||19700101|F",
        "MRG|55501^^^H^MR",
    )
    out = anonymize(msg, salt=_SALT)
    pid3 = next(line for line in out.split("\r") if line.startswith("PID")).split("|")[3]
    mrg1 = next(line for line in out.split("\r") if line.startswith("MRG")).split("|")[1]
    assert "55501" not in pid3 and pid3 == mrg1  # same surrogate => merge linkage survives


def test_anonymize_reads_custom_separators_from_msh() -> None:
    msg = "MSH!*~\\&!A!B!C!D!20260101!!ADT^A01!M1!P!2.5.1\rPID!1!!13579*x*x*H*MR!!POE*MARY!!19900101!F"
    out = anonymize(msg, salt=_SALT)
    assert (
        "13579" not in out and "POE" not in out
    )  # scrubbed despite '!' field / '*' component seps


# --- leak-check -----------------------------------------------------------------------------------


@_NO_SCANNER
def test_leak_check_clean_and_dirty() -> None:
    assert leak_check(anonymize(_SAMPLE, salt=_SALT)) == []
    hits = leak_check("note mentioning OMNICELL and 540099")
    assert any("omnicell" in h.lower() for h in hits)
    assert any("54" in h for h in hits)


@_NO_SCANNER
def test_anonymize_checked_fails_closed_and_is_phi_safe() -> None:
    # estate token in a KEPT field (MSH-3) survives surrogation -> must raise
    dirty = _msg(
        r"MSH|^~\&|OMNICELL|B|C|D|20260101||ADT^A01|M1|P|2.5.1",
        "PID|1||999^^^H^MR||DOE^JOHN||19800101|M",
    )
    with pytest.raises(LeakError) as exc:
        anonymize_checked(dirty, salt=_SALT)
    message = str(exc.value)
    assert "omnicell" in message.lower()  # names the token category
    assert "DOE" not in message and "999" not in message  # never echoes the body


def test_alphanumeric_identifier_preserves_width_and_shape() -> None:
    msg = _msg(
        r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1",
        "PID|1||AB0049^^^H^MR||X^Y",
    )
    out = anonymize(msg, salt=_SALT)
    id_part = next(line for line in out.split("\r") if line.startswith("PID")).split("|")[3]
    id_part = id_part.split("^")[0]
    assert "AB0049" not in out
    assert len(id_part) == 6  # width preserved (not shrunk to a digit count)
    assert id_part[:2].isalpha() and id_part[2:].isdigit()  # shape preserved: 2 letters + 4 digits


@pytest.mark.parametrize(("original", "width"), [("1980", 4), ("198001", 6), ("19800101", 8)])
def test_partial_dob_preserves_precision(original: str, width: int) -> None:
    msg = _msg(
        r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1",
        f"PID|1||9^^^H^MR||X^Y||{original}",
    )
    out = anonymize(msg, salt=_SALT)
    dob = next(line for line in out.split("\r") if line.startswith("PID")).split("|")[7]
    assert (
        len(dob) == width and dob.isdigit() and dob != original
    )  # precision/width kept, value fake


def test_no_msh_message_is_refused_fail_closed() -> None:
    with pytest.raises(AnonError):
        anonymize("PID|1||9^^^H^MR||DOE^JOHN||19800101|M", salt=_SALT)


def test_mllp_framed_message_is_anonymized() -> None:
    framed = "\x0b" + _SAMPLE + "\x1c\r"  # VT … FS CR framing
    out = anonymize(framed, salt=_SALT)
    assert "DOE" not in out and out.startswith("MSH")  # framing stripped, body scrubbed


def test_anonymize_with_explicit_rules_only_touches_those_fields() -> None:
    out = anonymize(_SAMPLE, salt=_SALT, rules=(FieldRule("PID-5", SurrogateKind.NAME),))
    pid = next(line for line in out.split("\r") if line.startswith("PID"))
    assert "DOE" not in pid.split("|")[5]  # PID-5 scrubbed
    assert "12345" in pid  # PID-3 left intact (not in the explicit rule set)
    assert "DOE^JANE" in out  # NK1-2 untouched (only PID-5 was in scope)
