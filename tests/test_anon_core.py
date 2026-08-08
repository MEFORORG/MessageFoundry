# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Core anonymizer behaviour (ADR 0030): keying, the rule model, surrogates, the HL7 adapter, and the
fail-closed leak-check — engine side."""

from __future__ import annotations

from collections.abc import Iterator
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
from messagefoundry.anon.surrogates import Seps, scrub_site_codes, surrogate_field

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
# value — and each detector is falsified in the lane report. `DST` is a non-standard segment carrying
# no default rule, so DST-2/3 are the unmapped surface (the f3c6d348 blind-map case in miniature).

_SSN_MSG = _msg(
    r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260101120000||ADT^A01|M1|P|2.5.1",
    "PID|1||1^^^H^MR||X^Y",
    "DST|1|123-45-6789",  # DST-2: unmapped field carrying a synthetic dashed SSN
)


@_NO_SCANNER
def test_leak_check_catches_unmapped_ssn() -> None:
    """A synthetic dashed SSN in an unmapped field (DST-2) is caught and fails closed.

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
        "DST|1|202-555-0188|(202) 555-0188",  # DST-2 dashed, DST-3 parenthesised
    )
    hits = leak_check(msg, rules=DEFAULT_RULES)
    assert any("phone" in h for h in hits), hits
    assert any("DST-2" in h for h in hits) and any("DST-3" in h for h in hits), hits


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
        "DST|1|freeform",  # DST-2: unmapped but benign — enumerated, not flagged
    )
    report = leak_report(benign, rules=DEFAULT_RULES)
    assert "DST-2" in report.unmapped_fields
    assert report.structural_hits == []  # benign value → enumerated only, no shape hit
    with pytest.raises(LeakError) as exc:
        anonymize_checked(_SSN_MSG, salt=_SALT)
    text = str(exc.value)
    assert "checked" in text and "unmapped field" in text and "DST-2" in text


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
