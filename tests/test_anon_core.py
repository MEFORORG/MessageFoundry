# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Core anonymizer behaviour (ADR 0030): keying, the rule model, surrogates, the HL7 adapter, and the
fail-closed leak-check — engine side, with one exception. The OBX-5 preserve allowlist is asserted on
BOTH adapters here, because the rule is a property of the shared predicate rather than of either
seam's plumbing; engine/tee whole-message equality stays in ``test_anon_parity.py``."""

from __future__ import annotations

import functools
import secrets
import string
from collections.abc import Callable, Iterator
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
    leak,
    leak_check,
    leak_report,
    load_rules,
)
from messagefoundry.anon import rules as rules_module
from messagefoundry.anon.keying import (
    MAX_SALT_BYTES,
    MIN_SALT_ENTROPY_BITS,
    MIN_SALT_LEN,
    _estimated_entropy_bits,
)
from messagefoundry.anon.surrogates import Seps, scrub_site_codes, surrogate_field

# The OBX-5 allowlist below is asserted on BOTH adapters. The tee copy is a standalone vendored
# sibling (ADR 0030 §1) that cannot import `messagefoundry`, so it is imported here by its own name.
from tee.anon import anonymize as tee_anonymize
from tee.anon import anonymize_checked as tee_anonymize_checked
from tee.anon import leak as tee_leak
from tee.anon import rules as tee_rules

# The leak-check delegates to scripts/security/scan_forbidden.py (the relocated forbidden-content
# scanner). It ships on the public mirror but loads its real customer/vendor token list from a
# git-ignored local file / Actions secret, so on a fork checkout the token tables are EMPTY. The two
# leak tests below therefore INJECT synthetic tokens into the loaded scanner (rather than relying on the
# real list), so they exercise the mechanism identically with or without the secret and carry no real
# token. The scanner is still absent from an installed wheel (no scripts/), where the engine raises
# LeakCheckUnavailable by design — skip the two that need it there.
_LEAK_SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "security" / "scan_forbidden.py"
_NO_SCANNER = pytest.mark.skipif(
    not _LEAK_SCANNER.exists(),
    reason="leak-check needs scripts/security/scan_forbidden.py (absent on an installed wheel)",
)

_SALT = "unit-salt-0123456789abcdef"
_SEPS = Seps()


@pytest.fixture
def synthetic_site_prefix(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Inject a SYNTHETIC two-digit site-code prefix into the externalized detector, so the site-code
    tests exercise the real mechanism without any real prefix living in this (now-scanned) file."""
    from messagefoundry.anon import surrogates

    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", "[site_prefix]\n99\n")
    surrogates.reload_site_prefixes()
    yield "99"
    # Undo the patch BEFORE recomputing, and recompute from the environment that is actually restored.
    # `delenv` + reload was wrong in a way that only shows up when a real token source is configured:
    # it left the module globals derived from an environment with NO token source, and monkeypatch then
    # restored the real value afterwards with nothing to recompute the globals again. The engine's
    # `_SITE_PREFIXES` stayed stale for the rest of the session while the vendored `tee/anon` copy kept
    # its import-time value, so `test_anon_parity` — the engine/tee divergence guard — failed on an
    # unrelated message hundreds of tests later. `monkeypatch.undo()` puts the real environment back
    # first, so the reload below sees the same source the module saw at import.
    monkeypatch.undo()
    surrogates.reload_site_prefixes()


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
    a, b = Keyer("salt-7Kq2mVz9pLx4Rw"), Keyer("salt-7Kq2mVz9pLx4Rw")
    assert a.seed("mrn", "12345") == b.seed("mrn", "12345")
    assert a.seed("mrn", "12345") != a.seed("mrn", "54321")
    assert a.seed("mrn", "12345") != a.seed("name", "12345")  # kind is part of the key
    assert Keyer("other-saltttttttttt").seed("mrn", "12345") != a.seed("mrn", "12345")


def test_keyer_rejects_weak_salt() -> None:
    with pytest.raises(ValueError, match="at least"):
        Keyer("short")
    with pytest.raises(ValueError):
        Keyer("")


# A salt that is genuinely random yet REPEATS characters -- generated with secrets.token_hex(8),
# nine distinct characters over sixteen, one of them appearing five times. It is the POSITIVE
# CONTROL for the entropy gate: without it, a check that refused every salt would still satisfy the
# rejection tests below, and the gate would be indistinguishable from a permanent outage.
_REAL_RANDOM_SALT_WITH_REPEATS = "0222439f2bb823dd"


def test_keyer_accepts_real_high_entropy_salts_including_one_with_repeats() -> None:
    """POSITIVE CONTROL -- the gate must not refuse a salt an operator would actually generate."""
    assert len(set(_REAL_RANDOM_SALT_WITH_REPEATS)) < len(_REAL_RANDOM_SALT_WITH_REPEATS), (
        "this control is only meaningful if the salt repeats a character"
    )
    for salt in (
        _REAL_RANDOM_SALT_WITH_REPEATS,
        secrets.token_hex(8),  # 16 characters -- exactly at MIN_SALT_LEN, no length headroom
        secrets.token_urlsafe(24),
        secrets.token_hex(32),
    ):
        assert Keyer(salt).seed("mrn", "12345") > 0  # constructs and keys, no raise


def test_keyer_rejects_a_long_salt_with_too_little_entropy() -> None:
    """Character COUNT is not entropy: each of these clears MIN_SALT_LEN and is still guessable."""
    for salt in (
        "a" * MIN_SALT_LEN,  # the exact case the length-only gate accepted
        "a" * 64,  # length does not rescue a one-symbol salt
        "0" * 32,
        "abababababababab",  # two symbols
        "xxxxxxxxxxxxxxxy",  # skewed: diverse by distinct count, one symbol in practice
        "salt-aaaaaaaaaaaaaaaa",  # a plausible-looking placeholder
    ):
        assert len(salt) >= MIN_SALT_LEN, "the length gate must not be what fires here"
        with pytest.raises(ValueError, match="too predictable"):
            Keyer(salt)


def test_keyer_rejects_an_oversized_salt_at_construction_not_at_first_message() -> None:
    """A salt past BLAKE2b's keyed-mode limit used to build fine and crash on the FIRST message.

    Measured on the pre-fix code: ``Keyer(secrets.token_urlsafe(64))`` -- 86 bytes -- constructed
    without complaint, then raised a bare "maximum key length is 64 bytes" from inside ``seed``.
    On a first deployment that would surface as a mid-dataset failure rather than a rejected
    configuration. The boundary owns it now.
    """
    oversized = secrets.token_urlsafe(64)
    assert len(oversized.encode("utf-8")) > MAX_SALT_BYTES  # the case is what we think it is
    with pytest.raises(ValueError, match="at most"):
        Keyer(oversized)
    # ...and a salt exactly AT the ceiling still works -- the bound must not be off by one.
    at_ceiling = secrets.token_hex(MAX_SALT_BYTES // 2)
    assert len(at_ceiling.encode("utf-8")) == MAX_SALT_BYTES
    assert Keyer(at_ceiling).seed("mrn", "12345") > 0


def test_keyer_weak_salt_error_never_quotes_the_salt() -> None:
    """The salt is a re-identification key -- an exception that echoed it would leak it to a log."""
    salt = "a" * MIN_SALT_LEN
    with pytest.raises(ValueError) as excinfo:
        Keyer(salt)
    assert salt not in str(excinfo.value)
    assert "aaaa" not in str(excinfo.value)


def test_entropy_estimate_is_order_blind_which_is_the_declared_blind_spot() -> None:
    """Pin the limitation the estimator's docstring admits, so nobody later overstates the gate.

    Sixteen distinct characters in alphabetical order score the arithmetic maximum for that length
    and are ACCEPTED, even though the string is trivially guessable. A distribution-based estimator
    cannot see order; claiming otherwise would be the dishonest reading of this check.
    """
    assert _estimated_entropy_bits("abcdefghijklmnop") == _estimated_entropy_bits(
        "pnmlkjihgfedcba" + "o"
    )
    assert _estimated_entropy_bits("abcdefghijklmnop") >= MIN_SALT_ENTROPY_BITS
    Keyer("abcdefghijklmnop")  # accepted -- documented blind spot, not an oversight


def test_entropy_estimate_grades_the_measured_cases() -> None:
    """Executed values behind the floor, so a future edit to the estimator has to face them."""
    assert _estimated_entropy_bits("a" * MIN_SALT_LEN) == 0.0
    assert _estimated_entropy_bits("") == 0.0  # helper is safe on empty; the length gate owns it
    assert _estimated_entropy_bits("abababababababab") == pytest.approx(16.0)
    assert _estimated_entropy_bits(_REAL_RANDOM_SALT_WITH_REPEATS) == pytest.approx(46.39, abs=0.01)


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
    assert rules["PID-13"] is SurrogateKind.KEEP  # keep cancels the default scrub, and is recorded


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


def test_site_code_scrub_is_field_anchored(synthetic_site_prefix: str) -> None:
    keyer = Keyer(_SALT)
    # The site-code prefix is externalized; the fixture injects a synthetic one, so no real site code
    # sits in this (now-scanned) file.
    code = synthetic_site_prefix + "0088"  # a whole (synthetic) site code
    # a whole component that IS a site code is replaced ...
    assert code not in scrub_site_codes(f"WARD^{code}^A", keyer, _SEPS)
    # ... but the same run INSIDE a longer value (timestamp) is left alone (field-anchored)
    ts = f"2026{code}100"
    assert scrub_site_codes(ts, keyer, _SEPS) == ts


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


def test_obx5_freetext_preserved_only_for_allowlisted_value_type() -> None:
    out = anonymize(_SAMPLE, salt=_SALT)
    obx = [line for line in out.split("\r") if line.startswith("OBX")]
    assert "128" in obx[0]  # NM result kept
    assert "[REDACTED]" in obx[1]  # TX note redacted
    assert "[REDACTED]" in next(line for line in out.split("\r") if line.startswith("NTE"))


# --- OBX-5 preserve allowlist (both adapters) -------------------------------------------------------
#
# The rule, and why it is an allowlist rather than a blocklist, is stated once at
# `messagefoundry.anon.surrogates.preserve_obx5_value`. What is pinned here is that BOTH adapters
# apply it: the engine drives a parsed `Message`, the tee a pure stdlib splitter, and the two reach
# OBX-2/OBX-5 differently, so each case runs through both. Whole-message engine/tee equality stays
# in tests/test_anon_parity.py, which carries these fixtures in its own corpus.

_ADAPTERS = (anonymize, tee_anonymize)
_EACH_ADAPTER = pytest.mark.parametrize("adapter", _ADAPTERS, ids=("engine", "tee"))


def _obx_message(obx: str) -> str:
    """One OBX under a synthetic ORU (no real PHI — CLAUDE.md §9)."""
    return _msg(
        r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260101120000||ORU^R01|MSGCTRL|P|2.5.1",
        r"PID|1||12345^^^HOSP^MR||DOE^JOHN||19800101|M",
        obx,
    )


def _field_of(message: str, address: str, field_sep: str = "|") -> str:
    """The whole field at ``address`` (``PID-12``, ``MSH-7``) in the first segment of that id — read
    positionally, so a substring that happens to survive elsewhere in the message cannot make a
    redaction assertion pass by luck. MSH is numbered the MSH way (MSH-1 is the separator)."""
    seg_id, num = address.split("-")
    line = next(seg for seg in message.split("\r") if seg.startswith(seg_id + field_sep))
    fields = line.split(field_sep)
    index = int(num) - 1 if seg_id == "MSH" else int(num)
    return fields[index] if index < len(fields) else ""


def _obx5_of(message: str, field_sep: str = "|") -> str:
    """The OBX-5 field of the first OBX."""
    return _field_of(message, "OBX-5", field_sep)


# Every one of these must be REDACTED. `JVBERi0xLjQK` is the base64 of a PDF header ("%PDF-1.4"),
# which is what an ED document looks like on the wire; the narrative values are fabricated.
_OBX5_REDACTED = {
    "embedded document (ED)": "OBX|1|ED|DOC^Report^L||SENDER^AP^PDF^Base64^JVBERi0xLjQK|",
    "reference pointer (RP)": "OBX|1|RP|DOC^Report^L||http://example.invalid/r^^^^|",
    "empty value type": "OBX|1||DOC^Report^L||Patient JOHN DOE seen|",
    "unknown value type": "OBX|1|ZZZ|DOC^Report^L||Patient JOHN DOE seen|",
    # A DECLARED type is not taken on trust: the label says numeric, the value is a sentence.
    "NM label over prose": "OBX|1|NM|8480-6^Systolic^LN||Patient JOHN DOE seen|",
    "CWE with text component": "OBX|1|CWE|DX^Diagnosis^L||I10^Essential hypertension^ICD10|",
}

# Every one of these must be PRESERVED. Asserting these is not optional: over-redaction destroys
# legitimate coded and numeric results, and a scrubbed corpus still looks scrubbed, so nothing else
# in the suite would notice.
_OBX5_PRESERVED = {
    "numeric (NM)": ("OBX|1|NM|8480-6^Systolic^LN||128|mm[Hg]", "128"),
    "structured numeric (SN)": ("OBX|1|SN|RG^Range^L||>^100|", ">^100"),
    "timestamp (TS)": ("OBX|1|TS|CL^Collected^L||20260101120000|", "20260101120000"),
    "coded id (ID)": ("OBX|1|ID|SX^Sex^L||F|", "F"),
    "CWE with no text component": ("OBX|1|CWE|DX^Diagnosis^L||I10^^ICD10|", "I10^^ICD10"),
}


@_EACH_ADAPTER
@pytest.mark.parametrize("case", sorted(_OBX5_REDACTED), ids=lambda c: c.replace(" ", "_"))
def test_obx5_redacts_everything_off_the_allowlist(adapter: Callable[..., str], case: str) -> None:
    out = adapter(_obx_message(_OBX5_REDACTED[case]), salt=_SALT)
    assert _obx5_of(out) == "[REDACTED]", f"{case} left OBX-5 intact"


@_EACH_ADAPTER
@pytest.mark.parametrize("case", sorted(_OBX5_PRESERVED), ids=lambda c: c.replace(" ", "_"))
def test_obx5_preserves_allowlisted_value_types(adapter: Callable[..., str], case: str) -> None:
    obx, expected = _OBX5_PRESERVED[case]
    out = adapter(_obx_message(obx), salt=_SALT)
    assert _obx5_of(out) == expected, f"{case} was over-redacted"


@_EACH_ADAPTER
def test_obx5_allowlist_is_separator_aware(adapter: Callable[..., str]) -> None:
    """The allowlist reads the message's OWN encoding characters (CLAUDE.md §8), never ``|^~\\&``:
    the same CWE decision must hold under a message that declares different separators."""
    message = _msg(
        "MSH!*~\\&!SAPP!SFAC!RAPP!RFAC!20260101120000!!ORU*R01!MSGCTRL!P!2.5.1",
        "PID!1!!12345*x*x*HOSP*MR!!DOE*JOHN!!19800101!M",
        "OBX!1!CWE!DX*Diagnosis*L!!I10*Essential hypertension*ICD10!",
    )
    assert _obx5_of(adapter(message, salt=_SALT), field_sep="!") == "[REDACTED]"


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
def test_leak_check_clean_and_dirty(
    monkeypatch: pytest.MonkeyPatch, synthetic_site_prefix: str
) -> None:
    # Inject a SYNTHETIC estate token so the check is exercised whether or not the real list is loaded.
    monkeypatch.setattr(leak._scanner(), "ESTATE_TOKENS", ("acmecorp",))
    assert leak_check(anonymize(_SAMPLE, salt=_SALT)) == []
    site = (
        synthetic_site_prefix + "0088"
    )  # a synthetic site code — no real prefix in this scanned file
    hits = leak_check(f"note mentioning ACMECORP and {site}")
    assert any("acmecorp" in h.lower() for h in hits)  # estate token named
    assert any("site-code" in h.lower() for h in hits)  # field-anchored site-code pattern caught


@_NO_SCANNER
def test_anonymize_checked_fails_closed_and_is_phi_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    # synthetic estate token in a KEPT field (MSH-3) survives surrogation -> must raise
    monkeypatch.setattr(leak._scanner(), "ESTATE_TOKENS", ("acmecorp",))
    dirty = _msg(
        r"MSH|^~\&|ACMECORP|B|C|D|20260101||ADT^A01|M1|P|2.5.1",
        "PID|1||999^^^H^MR||DOE^JOHN||19800101|M",
    )
    with pytest.raises(LeakError) as exc:
        anonymize_checked(dirty, salt=_SALT)
    message = str(exc.value)
    assert "acmecorp" in message.lower()  # names the token category
    assert "DOE" not in message and "999" not in message  # never echoes the body


# --- structural PHI detection on UNMAPPED fields (BACKLOG #331) ------------------------------------
# The known-token denylist cannot see a real MRN/SSN in a field the rule map never mapped (a real MRN
# is not a denylisted string). These exercise the structural backstop over the UNMAPPED fields. All
# values are SYNTHETIC PHI SHAPES (fake, reserved-fictional, or component-structured) — never a real
# value — and each detector is falsified in the lane report. `ZST` is a site Z-segment carrying
# no default rule, so ZST-2/3 are the unmapped surface (the f3c6d348 blind-map case in miniature).

_SSN_MSG = _msg(
    r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260101120000||ADT^A01|M1|P|2.5.1",
    "PID|1||1^^^H^MR||X^Y",
    "ZST|1|123-45-6789",  # ZST-2: unmapped field carrying a synthetic dashed SSN
)


@_NO_SCANNER
def test_leak_check_catches_unmapped_ssn() -> None:
    """A synthetic dashed SSN in an unmapped field (ZST-2) is caught and fails closed.

    Falsified: deleting `_SSN_DASHED` from leak.py's structural set made leak_check() return [] and
    anonymize_checked() emit the dataset clean (RED), then restored.
    """
    hits = leak_check(_SSN_MSG, rules=DEFAULT_RULES)
    assert any("SSN" in h for h in hits), hits
    with pytest.raises(LeakError):
        anonymize_checked(_SSN_MSG, salt=_SALT)


@_NO_SCANNER
def test_leak_check_catches_unmapped_phone() -> None:
    """Synthetic punctuated NANP numbers (reserved-fictional 555-01XX) in unmapped fields are caught,
    both dashed and parenthesised.

    Falsified: removing the two phone detectors let the dataset slip through clean (RED), then restored.
    """
    msg = _msg(
        r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1",
        "PID|1||1^^^H^MR||X^Y",
        "ZST|1|202-555-0188|(202) 555-0188",  # ZST-2 dashed, ZST-3 parenthesised
    )
    hits = leak_check(msg, rules=DEFAULT_RULES)
    assert any("phone" in h for h in hits), hits
    assert any("ZST-2" in h for h in hits) and any("ZST-3" in h for h in hits), hits


@_NO_SCANNER
def test_leak_check_catches_unmapped_mrn() -> None:
    """A CX id typed `MR` in an unmapped field (PID-2, absent from DEFAULT_RULES) is caught by HL7
    structure, and the raw id never surfaces in the reason or the LeakError (PHI-safe).

    Falsified: removing the MR/MRN component detector let the unmapped MRN pass clean (RED), then
    restored — confirming the CX id-type signal, not a digit heuristic, is doing the work.
    """
    msg = _msg(
        r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1",
        "PID|1|98765^^^HOSP^MR||X^Y",  # PID-2: unmapped CX, id-typed MR
    )
    hits = leak_check(msg, rules=DEFAULT_RULES)
    assert any("MRN" in h and "PID-2" in h for h in hits), hits
    assert all("98765" not in h for h in hits)  # names the shape + address, never the id
    with pytest.raises(LeakError) as exc:
        anonymize_checked(msg, salt=_SALT)
    assert "98765" not in str(exc.value)


@_NO_SCANNER
def test_coverage_report_lists_unmapped_fields() -> None:
    """The coverage report enumerates present-but-unmapped fields (address only) — the batch_18
    regression: a field nobody mapped is now visible, not silent. The fail-path LeakError carries the
    value-free coverage clause.

    Falsified: stubbing `unmapped_field_values` to yield nothing emptied `.unmapped_fields` (RED),
    then restored.
    """
    benign = _msg(
        r"MSH|^~\&|A|B|C|D|20260101120000||ADT^A01|M1|P|2.5.1",
        "PID|1||1^^^H^MR||X^Y",
        "ZST|1|freeform",  # ZST-2: unmapped but benign — enumerated, not flagged
    )
    report = leak_report(benign, rules=DEFAULT_RULES)
    assert "ZST-2" in report.unmapped_fields
    assert report.structural_hits == []  # benign value → enumerated only, no shape hit
    with pytest.raises(LeakError) as exc:
        anonymize_checked(_SSN_MSG, salt=_SALT)
    text = str(exc.value)
    assert "checked" in text and "unmapped field" in text and "ZST-2" in text


@_NO_SCANNER
def test_false_positive_guard_benign_unmapped_fields() -> None:
    """Unmapped fields dense with dates/coded-values/order-numbers (the mass-false-positive surface
    ADR 0030 warns of) must NOT trip the check — why the bare-digit DOB/SSN heuristics were rejected.

    Falsified: broadening `_SSN_DASHED` to any 8+ digit run tripped the 14-digit EVN timestamp (RED),
    then restored.
    """
    benign = _msg(
        r"MSH|^~\&|A|B|C|D|20260101120000||ADT^A01|M1|P|2.5.1",
        "EVN|A01|20260101120000",  # 14-digit timestamp
        "OBX|1|NM|8480-6^Systolic^LN||128|mm[Hg]",  # coded observation id
        "ORC|NW|1000000042",  # unmapped order-number run
        "PID|1||1^^^H^MR||X^Y",
    )
    assert leak_check(benign, rules=DEFAULT_RULES) == []
    assert anonymize_checked(benign, salt=_SALT)  # clean → returns, no raise


@_NO_SCANNER
def test_token_floor_surfaced_when_tables_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty token load is no longer a SILENT green (#331): the report records it and the strict
    lever refuses on it — while the default keeps CI/OSS/fork runs (which have no token source) green,
    the structural detectors being the live backstop.

    The empty-token state is forced deterministically (this dev checkout has a token source; CI does
    not) by patching the loaded scanner's `TOKENS_PRESENT`. Falsified: stubbing `token_floor_failure`
    to return None made `.token_floor_reason` None and the strict path stop refusing (RED), restored.
    """
    monkeypatch.setattr(leak._scanner(), "TOKENS_PRESENT", False)
    clean = _msg(
        r"MSH|^~\&|A|B|C|D|20260101120000||ADT^A01|M1|P|2.5.1",
        "PID|1||1^^^H^MR||X^Y",
    )
    report = leak_report(clean, rules=DEFAULT_RULES)
    assert report.token_tables_live is False
    assert report.token_floor_reason is not None
    # the DEFAULT decision does NOT refuse on empty tokens alone (structural detectors are the backstop)
    assert anonymize_checked(clean, salt=_SALT)
    # the strict lever DOES refuse, naming the floor reason but no field value
    with pytest.raises(LeakError) as exc:
        anonymize_checked(clean, salt=_SALT, require_live_denylist=True)
    text = str(exc.value)
    assert "denylist not live" in text and "fail closed" in text


# --- the real fail-closed scope (BACKLOG #1710) -----------------------------------------------------
# docs/PHI.md section 9 states what anonymize_checked refuses and what it lets through. These pin both
# halves, so a change to either the detectors or the wording has a test to answer to.

_CHECKED = pytest.mark.parametrize(
    "checked", (anonymize_checked, tee_anonymize_checked), ids=("engine", "tee")
)


_UNREACHABLE_LINES = pytest.mark.parametrize(
    ("line", "needle"),
    [
        ("SMITH JANE|wrapped note", "SMITH"),  # first field is not a segment id
        ("LEE", "LEE"),  # a wrapped surname shaped like a segment id, with no field separator
        # A second, lowercase MSH line is not the header. It carries no SSN shape, so the
        # malformed-line hit is the only one that can refuse it (BACKLOG #2247).
        ("msh|ZZTEST SYNTH", "ZZTEST"),
    ],
    ids=("not-an-id", "no-separator", "second-msh"),
)


@_NO_SCANNER
@_CHECKED
@_UNREACHABLE_LINES
def test_a_malformed_segment_line_is_refused_and_its_text_is_never_named(
    checked: Callable[..., str], line: str, needle: str
) -> None:
    """A line no rule can reach is refused, and its text never becomes an address.

    The anonymizer refuses it first (BACKLOG #2246), so ``anonymize_checked`` raises ``AnonError``
    before the leak-check runs. The leak-check still refuses the same line when it is called on
    text directly, and there the malformed-line hit is the ONLY hit, so nothing else can be what
    refused it.
    """
    msg = _msg(r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1", "PID|1||1^^^H^MR||X^Y", line)
    reports: list[object] = []
    with pytest.raises(Exception, match="a line no rule can reach") as exc:
        checked(msg, salt=_SALT, on_report=reports.append)
    assert type(exc.value).__name__ == "AnonError"
    assert needle not in str(exc.value)
    assert reports == []  # refused before the leak-check, so no report was built
    module = leak if checked is anonymize_checked else tee_leak
    report = module.leak_report(msg, rules=DEFAULT_RULES)
    assert report.hits == ["line with a malformed segment id, which no rule can reach"]
    assert "(malformed segment)-0" in report.unmapped_fields
    assert all(needle not in a for a in report.unmapped_fields)


@_NO_SCANNER
@pytest.mark.parametrize("line", ["   ", "\x1a", "\x00\x00"], ids=("spaces", "sub", "nul"))
def test_a_line_with_no_printable_text_is_not_a_malformed_segment(line: str) -> None:
    """The control for the test above: a blank or padding line carries nothing and must not refuse."""
    msg = _msg(r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1", "PID|1||1^^^H^MR||X^Y", line)
    assert leak_report(msg, rules=DEFAULT_RULES).hits == []


@_NO_SCANNER
@_CHECKED
def test_a_clean_return_can_still_carry_a_name_a_date_and_an_undashed_ssn(
    checked: Callable[..., str],
) -> None:
    """The residual the docs state: shapes outside the three detectors pass in an unmapped field.
    The coverage report is the only record of them, which is why callers must surface it.

    If this starts refusing, the detectors changed. Update docs/PHI.md section 9 in the same change.
    """
    msg = _msg(
        r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1",
        "PID|1||1^^^H^MR||X^Y",
        "ZPD|ZZTEST^SYNTH|19700101|900000001",  # synthetic name, bare date, undashed SSN shape
    )
    reports: list[object] = []
    out = checked(msg, salt=_SALT, on_report=reports.append)
    assert "ZZTEST" in out and "19700101" in out and "900000001" in out
    (report,) = reports
    assert {"ZPD-1", "ZPD-2", "ZPD-3"} <= set(report.unmapped_fields)  # type: ignore[attr-defined]
    assert report.hits == []  # type: ignore[attr-defined]


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


def test_site_prefix_fixture_leaves_module_globals_consistent_with_the_environment() -> None:
    """Regression guard for a cross-module leak that cost a full-suite failure hundreds of tests later.

    ``synthetic_site_prefix`` patches ``MEFOR_FORBIDDEN_TOKENS`` and recomputes the ``surrogates``
    module globals from it. Its teardown used to ``delenv`` and reload BEFORE monkeypatch restored the
    real value, leaving ``_SITE_PREFIXES`` derived from an environment that no longer existed. Nothing
    recomputed them afterwards, so on any box with a real token source configured the engine's globals
    stayed stale for the rest of the session while the vendored ``tee/anon`` copy kept its import-time
    value — and ``test_anon_parity`` (the engine/tee divergence guard) failed on an unrelated message.

    Declared last in this module so it runs after every fixture user: it asserts the live globals still
    agree with a fresh recomputation from the CURRENT environment. It is only meaningful where a token
    source is actually configured, which is exactly the condition the original bug needed — and is why
    CI, which does not set one for the test job, never saw the failure.
    """
    from messagefoundry.anon import surrogates

    live = surrogates._SITE_PREFIXES
    surrogates.reload_site_prefixes()
    assert live == surrogates._SITE_PREFIXES, (
        "surrogates._SITE_PREFIXES drifted from what the current environment yields — a fixture "
        "recomputed them under a patched environment and did not restore them afterwards"
    )


# --- the per-character floor: length must not rescue a degenerate pattern ----------------------
#
# The total-bits floor is length-scaled, so a repeating two-symbol pattern reaches it by being
# long: "ab" x8 scored 16.00 bits and was refused, while the IDENTICAL pattern at "ab" x16 scored
# 32.00 and passed. That is the length floor defeating the entropy floor, not a blind spot the
# estimator can disclaim, so the RATE is now checked separately and a salt must clear both.


@pytest.mark.parametrize(
    "salt,label",
    [
        ("ab" * 16, "two symbols, 32 chars -- reached the total floor by length alone"),
        ("ab" * 32, "two symbols, 64 chars"),
        ("abc" * 21 + "a", "three symbols, 64 chars -- scored 101 bits on the total"),
    ],
)
def test_length_does_not_rescue_a_repeating_pattern(salt: str, label: str) -> None:
    with pytest.raises(ValueError, match="too few distinct characters"):
        Keyer(salt)


def test_real_generated_salts_are_still_accepted() -> None:
    """THE CONTROL THAT MATTERS. A floor that refuses everything would pass every rejection test
    above while making the anonymizer unusable, which is worse than the defect it fixes. Decimal is
    the narrowest alphabet a real generator would produce, so it is the binding case."""
    for salt in (
        secrets.token_urlsafe(24),
        secrets.token_hex(8),
        secrets.token_hex(16),
        "".join(secrets.choice(string.digits) for _ in range(MIN_SALT_LEN)),
    ):
        Keyer(salt)  # must not raise


def test_the_two_floors_are_independent() -> None:
    """Neither floor substitutes for the other, so both must be able to fire alone. A single
    repeated character fails the TOTAL (0 bits); a two-symbol pattern long enough to clear the
    total fails the RATE. If one message could serve both, one floor would be redundant."""
    with pytest.raises(ValueError, match="too predictable"):
        Keyer("a" * MIN_SALT_LEN)
    with pytest.raises(ValueError, match="too few distinct characters"):
        Keyer("ab" * MIN_SALT_LEN)


# --- a segment id is untrusted text too (BACKLOG #1710 repair) --------------------------------------
# A wrapped line such as `KIM|F` is shaped like a segment, so its first field used to become part of
# a coverage address (`KIM-1`) that the tee logs and LeakError carries. Only a segment id the message's
# HL7 version defines, or a Z-segment, may be named; anything else gets a fixed stand-in.

_NAME_SHAPED = pytest.mark.parametrize(
    "line",
    [
        "KIM|F",  # a wrapped surname, then a field
        "DOE|JOHN",  # wrapped name parts
        "DON|X",  # a real segment id only from v2.7, so unknown to this v2.5.1 message
    ],
    ids=("kim", "doe", "later-version-id"),
)


def _address_text(report: object) -> str:
    return " ".join(report.unmapped_fields) + " " + " ".join(report.hits)  # type: ignore[attr-defined]


@_NO_SCANNER
@_CHECKED
@_NAME_SHAPED
def test_an_unknown_segment_id_is_never_named(checked: Callable[..., str], line: str) -> None:
    needle = line.split("|", 1)[0]
    msg = _msg(r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1", "PID|1||1^^^H^MR||X^Y", line)
    reports: list[object] = []
    try:
        checked(msg, salt=_SALT, on_report=reports.append)
        raised = ""
    except Exception as exc:  # noqa: BLE001 - either outcome is fine; the NAME is what is tested
        raised = str(exc)
    (report,) = reports
    assert needle not in _address_text(report)
    assert needle not in raised
    tally = tee_leak.CoverageTally()
    tally.add(report)  # type: ignore[arg-type]
    assert needle not in tally.summary()  # the INFO line the tee logs


@_NO_SCANNER
@_CHECKED
def test_a_known_segment_and_a_z_segment_are_still_named(checked: Callable[..., str]) -> None:
    """The control for the test above: a real segment id and a Z-segment still print by address."""
    msg = _msg(
        r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1",
        "PID|1||1^^^H^MR||X^Y",
        "ZPD|free",
    )
    reports: list[object] = []
    checked(
        msg, salt=_SALT, rules=(FieldRule("PID-3", SurrogateKind.MRN),), on_report=reports.append
    )
    (report,) = reports
    tally = tee_leak.CoverageTally()
    tally.add(report)  # type: ignore[arg-type]
    assert "PID-5 x1" in tally.summary() and "ZPD-1 x1" in tally.summary()


@_NO_SCANNER
@_CHECKED
def test_a_second_msh_line_is_numbered_as_msh(checked: Callable[..., str]) -> None:
    """A second MSH line is numbered the MSH way (MSH-1 is the separator), so a rule mapping MSH-14
    cannot hide the value at real MSH-15."""
    second = r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M2|P|2.5.1|||123-45-6789"
    assert second.split("|")[14] == "123-45-6789"  # split index 14 is MSH-15
    msg = _msg(r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1", "PID|1||1^^^H^MR||X^Y", second)
    rules = (*DEFAULT_RULES, FieldRule("MSH-14", SurrogateKind.DROP))
    with pytest.raises(Exception, match="SSN-shaped value in MSH-15") as exc:
        checked(msg, salt=_SALT, rules=rules)
    assert type(exc.value).__name__ == "LeakError"


def test_the_segment_table_matches_hl7apy() -> None:
    """The leak-check's segment-id table is data held in both leak.py copies; hl7apy is its source."""
    import hl7apy
    from hl7apy import load_library

    for version in hl7apy.SUPPORTED_LIBRARIES:
        expected = {s for s in load_library(version).SEGMENTS if len(s) == 3 and s.isalnum()}
        expected = {s for s in expected if s[0].isalpha() and s.isupper()}
        assert leak.known_segments(version) == expected, version
        assert tee_leak.known_segments(version) == expected, version
    assert leak.known_segments("") >= leak.known_segments("2.5.1")  # unparseable: every version


# --- require_full_coverage: every present field was DECIDED (BACKLOG #1710 step 1) --------------------
# Off by default. On, it refuses any present field that no rule scrubs and no `keep` names, unless it
# is a set id, PID-8 or PV1-2. A kept field is decided but is still scanned for PHI shapes.

_HEADER = r"MSH|^~\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1"


def _overlay(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "anon.toml"
    path.write_text(body, encoding="utf-8")
    return path


@_NO_SCANNER
@_CHECKED
def test_full_coverage_off_ignores_undecided_fields(checked: Callable[..., str]) -> None:
    """Off (the default), a message with undecided fields is emitted exactly as anonymize() writes it,
    although the report does list those fields."""
    msg = _msg(_HEADER, "PID|1||1^^^H^MR||X^Y", "ZPD|ZZTEST^SYNTH|19700101")
    reports: list[object] = []
    out = checked(msg, salt=_SALT, on_report=reports.append)
    assert out == anonymize(msg, salt=_SALT)
    (report,) = reports
    assert report.undecided_fields == ("ZPD-1", "ZPD-2")  # type: ignore[attr-defined]


@_NO_SCANNER
@_CHECKED
def test_full_coverage_refuses_an_undecided_field_and_names_only_its_address(
    checked: Callable[..., str],
) -> None:
    msg = _msg(_HEADER, "PID|1||1^^^H^MR||X^Y", "ZPD|ZZTEST^SYNTH|19700101")
    with pytest.raises(Exception, match="no rule and no keep") as exc:
        checked(msg, salt=_SALT, require_full_coverage=True)
    assert type(exc.value).__name__ == "LeakError"
    text = str(exc.value)
    assert "2 field(s) with no rule and no keep: ZPD-1, ZPD-2" in text  # the cause names them
    assert "ZZTEST" not in text and "19700101" not in text


@_NO_SCANNER
@_CHECKED
def test_full_coverage_counts_an_explicit_keep_as_decided(
    checked: Callable[..., str], tmp_path: Path
) -> None:
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["ZPD-1", "ZPD-2"]\n')
    msg = _msg(_HEADER, "PID|1||1^^^H^MR||X^Y", "ZPD|ZZTEST^SYNTH|19700101")
    out = checked(msg, salt=_SALT, overlay=overlay, require_full_coverage=True)
    assert "ZZTEST^SYNTH" in out  # a keep leaves the field as it was


@_NO_SCANNER
@_CHECKED
def test_a_kept_field_is_still_scanned_for_phi_shapes(
    checked: Callable[..., str], tmp_path: Path
) -> None:
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["ZPD-1"]\n')
    msg = _msg(_HEADER, "PID|1||1^^^H^MR||X^Y", "ZPD|123-45-6789")
    for strict in (False, True):
        with pytest.raises(Exception, match="SSN-shaped value in ZPD-1"):
            checked(msg, salt=_SALT, overlay=overlay, require_full_coverage=strict)


@_NO_SCANNER
@_CHECKED
def test_full_coverage_passes_the_fixed_list(checked: Callable[..., str]) -> None:
    """Set ids, PID-8 and PV1-2 need no rule. Everything else in these segments is mapped by the
    default rules, so the message passes with the switch on."""
    msg = _msg(
        _HEADER,
        "PID|1||1^^^H^MR||X^Y||19800101|M",
        "PV1|1|I",
        "NK1|1|A^B",
        "AL1|1",
        "OBX|1",
    )
    assert checked(msg, salt=_SALT, require_full_coverage=True)


@_NO_SCANNER
@_CHECKED
@pytest.mark.parametrize(
    "line",
    ["NTE|DOE JANE", "PV1|1|INPATIENT WARD", "PV1|1|I^SMITH JOHN", "PV1|1|I~DOE"],
    ids=("name-in-set-id", "long-class", "text-component", "repetition"),
)
def test_a_fixed_list_field_with_the_wrong_shape_is_undecided(
    checked: Callable[..., str], line: str
) -> None:
    """The fixed list excuses a set id of one to four digits and a one- or two-character code, not
    whatever text a sender puts there."""
    msg = _msg(_HEADER, "PID|1||1^^^H^MR||X^Y", line)
    with pytest.raises(Exception, match="no rule and no keep"):
        checked(msg, salt=_SALT, require_full_coverage=True)


def test_the_set_id_list_matches_hl7apy() -> None:
    """The set-id part of the fixed list is exactly the segments whose field 1 is SI in HL7 2.5.1,
    or in the newest version that defines a segment 2.5.1 lacks."""
    import hl7apy
    from hl7apy import load_library
    from hl7apy.core import Field

    def key(version: str) -> tuple[int, ...]:
        return tuple(int(part) for part in version.split("."))

    newest: dict[str, str] = {}
    for version in sorted(hl7apy.SUPPORTED_LIBRARIES, key=key):
        for segment in load_library(version).SEGMENTS:
            if len(segment) == 3 and segment.isalnum() and segment.isupper() and segment != "MSH":
                newest[segment] = version
    in_251 = load_library("2.5.1").SEGMENTS

    def field_1(segment: str, version: str) -> str | None:
        try:
            return str(Field(f"{segment}_1", version=version).datatype)
        except Exception:  # noqa: BLE001 - hl7apy raises assorted errors for a missing definition
            return None

    expected = {
        f"{segment}-1"
        for segment, version in newest.items()
        if field_1(segment, "2.5.1" if segment in in_251 else version) == "SI"
    }
    assert {"PID-8", "PV1-2"} | expected == leak.ALWAYS_DECIDED
    assert leak.ALWAYS_DECIDED == tee_leak.ALWAYS_DECIDED


@_NO_SCANNER
def test_a_keep_from_the_other_package_still_counts_as_a_keep() -> None:
    """KEEP is compared by value, so an engine rule passed to the tee leak-check (as the parity test
    does) is still scanned, not treated as a scrub."""
    msg = _msg(_HEADER, "PID|1||1^^^H^MR||X^Y", "ZPD|123-45-6789")
    # FieldRule now normalizes a string kind, so the raw-string arm is built past that on purpose:
    # the leak-check must still compare by value for a kind nothing normalized.
    raw = FieldRule("ZPD-1", SurrogateKind.KEEP)
    object.__setattr__(raw, "kind", "keep")
    for rule in (FieldRule("ZPD-1", SurrogateKind.KEEP), raw):
        report = tee_leak.leak_report(msg, rules=(*DEFAULT_RULES, rule))  # type: ignore[arg-type]
        assert report.structural_hits, rule
        assert "ZPD-1" not in report.undecided_fields


def test_load_rules_keeps_a_keep_rule_and_anonymize_leaves_the_field(tmp_path: Path) -> None:
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["PID-13"]\n')
    rules = {r.path: r.kind for r in load_rules(overlay)}
    assert rules["PID-13"] is SurrogateKind.KEEP
    msg = _msg(_HEADER, "PID|1||1^^^H^MR||X^Y||||||||5550100")  # PID-13
    assert "5550100" in anonymize(msg, salt=_SALT, overlay=overlay)
    assert "5550100" not in anonymize(msg, salt=_SALT)


# --- the DATE kind and the date/location rules (BACKLOG #2248) --------------------------------------

_DATE_SHAPES = pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026", "2026"),
        ("202603", "202601"),
        ("20260315", "20260101"),
        ("2026031514", "2026010100"),
        ("202603151422", "202601010000"),
        ("20260315142233", "20260101000000"),
        ("20260315142233.1", "20260101000000.0"),
        ("20260315142233.1234", "20260101000000.0000"),
        # The offset is never kept: it would show daylight saving time, a sub-state zone, or (in
        # "2026-0315") a month and day. "+0000" is a placeholder, not a UTC conversion.
        ("20260315142233.12-0500", "20260101000000.00+0000"),
        ("202603151422+0100", "202601010000+0000"),
        ("2026-0315", "2026+0000"),
        ("1980+0612", "1980+0000"),
        ("1850", "1850"),  # both ends of the year window are years
        ("2199", "2199"),
        ("19991231235959", "19990101000000"),
        ("20260315^S", "20260101^S"),  # TS.1 inside a TS; the TS.2 precision code survives
        ("20260315^", "20260101^"),
        ("20260315142233~19991231", "20260101000000~19990101"),  # each repetition on its own
        ('""', '""'),  # the HL7 explicit null carries nothing
    ],
)


@_DATE_SHAPES
def test_date_keeps_the_year_and_fills_the_rest_at_the_same_width(
    value: str, expected: str
) -> None:
    assert surrogate_field(SurrogateKind.DATE, value, Keyer(_SALT), _SEPS) == expected


def test_date_leaves_an_empty_field_empty() -> None:
    assert surrogate_field(SurrogateKind.DATE, "", Keyer(_SALT), _SEPS) == ""


_MALFORMED_DATES = pytest.mark.parametrize(
    "value",
    [
        "2026-03-15",
        "03/15/2026",
        "DOE^JOHN",
        "20260315 ",
        "2026031",  # odd width
        "20260315.12",  # a fraction before the seconds
        "20260315^Q",  # an unknown precision code
        "20260315^S^X",  # a TS has two components
        "^S",
        "20260315&1",
        # A US MMDDYYYY is all digits and the right width, so only the range checks catch it. Kept
        # as a "year" it would carry the real month and day ("0315") into the output.
        "03152026",
        "031520261422",
        "20261315",  # month 13
        "20260000",  # month 00
        "20260132",  # day 32
        "2026031524",  # hour 24
        "２０２６０３１５",  # full-width digits
        "٢٠٢٦",  # Arabic-Indic digits
        # Outside the 1850-2199 year window, an MMDD or MMDDYY would be kept as the "year" with
        # its real month and day. Scrubbed like any malformed value.
        "1231",
        "1015",
        "101012",
        "1849",
        "2200",
    ],
)


@_MALFORMED_DATES
def test_a_malformed_date_is_scrubbed_to_empty_never_passed_through(value: str) -> None:
    assert surrogate_field(SurrogateKind.DATE, value, Keyer(_SALT), _SEPS) == ""


def test_date_is_unsalted_so_two_separately_anonymized_sides_agree() -> None:
    """The year-keeping fill uses no salt, so a date anonymized under two different secrets still
    matches, which is what lets two captured sides be correlated."""
    value = "20260315142233"
    a = surrogate_field(SurrogateKind.DATE, value, Keyer(_SALT), _SEPS)
    b = surrogate_field(SurrogateKind.DATE, value, Keyer(secrets.token_urlsafe(24)), _SEPS)
    assert a == b == "20260101000000"


def test_a_filled_date_still_parses_under_strict_hl7apy() -> None:
    """Month and day become 01, not 00: a zero month is not a valid HL7 date and strict hl7apy
    refuses it, which would stop a fixture replaying through a strict-validation connection."""
    from hl7apy.parser import parse_message

    out = anonymize(_msg(_HEADER, "EVN|A01|20260315142233", "PID|1||1^^^H^MR||X^Y"), salt=_SALT)
    evn = parse_message(out, validation_level=1).evn
    assert evn.evn_2.value == "20260101000000"
    with pytest.raises(ValueError, match="valid date"):
        parse_message(out.replace("20260101000000", "20260000000000"), validation_level=1)


# Every field #2248 maps, each carrying a synthetic value whose month, day or text would survive an
# unmapped field. The expected value is what the new rule must produce.
_DATE_LOCATION_MSG = _msg(
    r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ADT^A01|MSGCTRL|P|2.5.1",
    "EVN|A01|20260315142233||||20260314091500",
    "PID|1||12345^^^HOSP^MR||DOE^JOHN||19800101|M" + "|" * 21 + "20260320101000",
    "PV1|1|I|WARD^101^A^MAIN" + "|" * 41 + "20260310080000|20260318170000",
    "ORC|RE||||||||20260315100000",
    "OBR|1|||CBC^Blood count^L|||20260315110000",
    "OBX|1|NM|8480-6^Systolic^LN||128|mm[Hg]||||||||20260315113000",
)
_MAPPED = {
    "EVN-2": "20260101000000",
    "EVN-6": "20260101000000",
    "PID-29": "20260101000000",
    "PV1-3": "[REDACTED]",
    "PV1-44": "20260101000000",
    "PV1-45": "20260101000000",
    "ORC-9": "20260101000000",
    "OBR-7": "20260101000000",
    "OBX-14": "20260101000000",
}


@functools.cache
def _date_location_out(adapter: Callable[..., str]) -> str:
    """One anonymized copy per adapter; every per-field case reads from it."""
    return adapter(_DATE_LOCATION_MSG, salt=_SALT)


def test_the_positive_control_carries_a_real_value_in_every_mapped_field() -> None:
    """Without this, a field the control message never populated would read as scrubbed."""
    for address, expected in _MAPPED.items():
        assert _field_of(_DATE_LOCATION_MSG, address) not in ("", expected), address


@pytest.mark.parametrize("address", sorted(_MAPPED))
@_EACH_ADAPTER
def test_the_default_rules_scrub_every_date_and_location_field(
    adapter: Callable[..., str], address: str
) -> None:
    """One case per field, so a red names the field rather than stopping at the first."""
    assert _field_of(_date_location_out(adapter), address) == _MAPPED[address]


@_EACH_ADAPTER
def test_msh7_is_still_kept_whole(adapter: Callable[..., str]) -> None:
    """ADR 0030 keeps MSH-7 for tee correlation; the DATE rules must not reach it."""
    assert _field_of(_date_location_out(adapter), "MSH-7") == "20260315142233"


@_EACH_ADAPTER
def test_pid12_county_is_scrubbed(adapter: Callable[..., str]) -> None:
    msg = _msg(_HEADER, "PID|1||1^^^H^MR||X^Y" + "|" * 7 + "031^Cook County^FIPS")
    assert _field_of(msg, "PID-12") == "031^Cook County^FIPS"  # the control reaches PID-12
    assert _field_of(adapter(msg, salt=_SALT), "PID-12") == "[REDACTED]"


@_NO_SCANNER
def test_the_mapped_fields_leave_the_undecided_list() -> None:
    report = leak_report(anonymize(_DATE_LOCATION_MSG, salt=_SALT), rules=DEFAULT_RULES)
    assert not set(_MAPPED) & set(report.undecided_fields)
    assert "EVN-1" in report.undecided_fields  # control: an unmapped field is still listed


def test_drop_is_compared_by_value_so_a_plain_string_blanks_the_field() -> None:
    assert surrogate_field("drop", "x", Keyer(_SALT), _SEPS) == ""  # type: ignore[arg-type]
    assert surrogate_field("date", "20260315", Keyer(_SALT), _SEPS) == "20260101"  # type: ignore[arg-type]


def test_an_unknown_kind_refuses_rather_than_leaving_the_value() -> None:
    with pytest.raises(AnonError, match="no surrogate"):
        surrogate_field("dates", "20260315", Keyer(_SALT), _SEPS)  # type: ignore[arg-type]


def test_keep_reaching_surrogate_field_still_leaves_the_value() -> None:
    assert surrogate_field(SurrogateKind.KEEP, "x", Keyer(_SALT), _SEPS) == "x"


def test_a_field_rule_normalizes_its_kind_at_construction() -> None:
    """A plain string, or the tee package's member, becomes this package's member, so every
    identity check downstream holds; an unknown kind is refused before any message is read."""
    assert FieldRule("PID-5", "drop").kind is SurrogateKind.DROP  # type: ignore[arg-type]
    assert FieldRule("PID-5", tee_rules.SurrogateKind.DATE).kind is SurrogateKind.DATE  # type: ignore[arg-type]
    with pytest.raises(RuleError, match="unknown surrogate kind"):
        FieldRule("PID-5", "dates")  # type: ignore[arg-type]


@_EACH_ADAPTER
def test_a_freetext_rule_from_the_other_package_still_honours_the_obx5_allowlist(
    adapter: Callable[..., str],
) -> None:
    """Each adapter gets a rule built by the OTHER package, whose kind is the other package's
    member. Only a by-value comparison in ``_skip_obx5`` recognizes it as FREETEXT; ``is not``
    would redact the allowlisted numeric result."""
    other = tee_rules if adapter is anonymize else rules_module
    rules = (other.FieldRule("OBX-5", other.SurrogateKind.FREETEXT),)
    out = adapter(_obx_message("OBX|1|NM|8480-6^Systolic^LN||128|mm[Hg]"), salt=_SALT, rules=rules)
    assert _obx5_of(out) == "128"


@_EACH_ADAPTER
def test_an_anon_error_inside_the_adapter_keeps_its_own_reason(
    adapter: Callable[..., str],
) -> None:
    """The engine adapter re-raises an AnonError unchanged rather than relabelling it "malformed
    structure", so both adapters give the same reason. The kind is set past FieldRule's
    normalization, since a normally built rule can no longer carry an unknown kind."""
    rule = FieldRule("PID-5", SurrogateKind.NAME)
    object.__setattr__(rule, "kind", "dates")
    own_error = AnonError if adapter is anonymize else tee_rules.AnonError
    with pytest.raises(own_error, match="no surrogate for kind 'dates'"):
        adapter(_msg(_HEADER, "PID|1||1^^^H^MR||X^Y"), salt=_SALT, rules=(rule,))
