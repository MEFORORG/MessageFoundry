# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Engine ↔ tee parity (ADR 0030 §1): the shared logic files stay byte-identical, the vendored pools
+ leak tokens stay in lockstep with their sources, and the two re-encoders produce identical output
on a golden corpus (the divergence guard the design depends on)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from messagefoundry.anon import DEFAULT_RULES
from messagefoundry.anon import anonymize as engine_anonymize
from messagefoundry.anon import leak as engine_leak
from messagefoundry.generators import (
    _core,
    _hl7data,
    all_types,  # noqa: F401  (registers message types)
)
from tee.anon import anonymize as tee_anonymize
from tee.anon import leak as tee_leak

_ROOT = Path(__file__).resolve().parents[1]
_BYTE_IDENTICAL = ("keying.py", "rules.py", "surrogates.py")
_SALT = "adversarial-salt-0123456789abcdef"

# Quirky-but-anonymizable inputs the conformant generator corpus never produces — the exact
# divergence surface ADR 0030 §1/Consequences warns about. Engine and tee must agree byte-for-byte.
_ADVERSARIAL = [
    "MSH!*~\\&!A!B!C!D!20260101!!ADT^A01!M1!P!2.5.1\rPID!1!!13579*x*x*H*MR!!POE*MARY!!19900101!F",
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR~2^^^O^MR||A&B^C||19800101",
    "MSH|^~\\&|A\\T\\B|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||9^^^H^MR||X^Y",
    "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|M1|P|2.5.1\rOBX|1\rPID|1||9^^^H^MR||X^Y",
    "\rMSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||9^^^H^MR||X^Y\r",
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||9^^^H^MR||X^Y\r\rNK1|1|Z^Q",
    "\x0bMSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||9^^^H^MR||X^Y\x1c\r",
]
# Inputs neither side can safely anonymize — BOTH must fail closed (refuse, never emit).
_REFUSED = ["", "PID|1||9^^^H^MR||DOE^JOHN", "MSH|^~|A|B", "not hl7 at all"]


def _load_scan_forbidden() -> object:
    # scripts/security/, not the retired scripts/publish/. The scanner is COMMITTED now, so this skip
    # should effectively never fire in a source checkout — it remains only for an installed wheel with
    # no scripts/ tree above it. Leaving the old path here silently skipped the parity assertions
    # below, which are the only thing keeping tee/anon/leak.py's tables identical to the guard's.
    path = _ROOT / "scripts" / "security" / "scan_forbidden.py"
    if not path.exists():
        pytest.skip("scan_forbidden.py not found above this tree", allow_module_level=True)
    spec = importlib.util.spec_from_file_location("scan_forbidden", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_shared_logic_files_are_byte_identical() -> None:
    for name in _BYTE_IDENTICAL:
        engine = (_ROOT / "messagefoundry" / "anon" / name).read_bytes()
        tee = (_ROOT / "tee" / "anon" / name).read_bytes()
        assert engine == tee, f"{name} drifted — re-copy messagefoundry/anon/{name} to tee/anon/"


def test_vendored_hl7data_matches_generator_source() -> None:
    engine = (_ROOT / "messagefoundry" / "generators" / "_hl7data.py").read_bytes()
    tee = (_ROOT / "tee" / "anon" / "_hl7data.py").read_bytes()
    assert engine == tee, "tee/anon/_hl7data.py drifted from messagefoundry/generators/_hl7data.py"


def test_leak_token_table_matches_publish_guard() -> None:
    sf = _load_scan_forbidden()
    assert tee_leak.ESTATE_TOKENS == sf.ESTATE_TOKENS  # type: ignore[attr-defined]
    assert tee_leak.SITE_CODE_RE.pattern == sf.SITE_CODE_RE.pattern  # type: ignore[attr-defined]
    assert [(p.pattern, r) for p, r in tee_leak.FORBIDDEN] == [
        (p.pattern, r)
        for p, r in sf.FORBIDDEN  # type: ignore[attr-defined]
    ]
    # the routable-IP detector is part of the same body-scan authority — pin it too (else a future
    # edit to scan_forbidden's IP regexes silently leaves the tee copy stale).
    assert tee_leak._IPV4.pattern == sf._IPV4.pattern  # type: ignore[attr-defined]
    assert tee_leak._ALLOWED_IP.pattern == sf._ALLOWED_IP.pattern  # type: ignore[attr-defined]


def test_leak_tables_load_empty_without_the_publish_guard(tmp_path: Path) -> None:
    # Where no guard is reachable (an installed wheel with no scripts/ above it) the token tables
    # must load EMPTY -- never a stale or fragmented copy -- so no customer/vendor token ships in
    # the tee. Exercise the loader against a tree that has no scripts/security above it.
    assert tee_leak._load_publish_guard(tmp_path / "no-guard-here" / "leak.py") is None  # type: ignore[attr-defined]


def test_leak_tables_are_sourced_from_the_guard_when_present() -> None:
    """The tee's tables are populated FROM the guard, never hard-coded in the published file.

    The gate here used to be "is the guard present", because the guard lived under the deny-listed
    scripts/publish/ AND carried its tokens as literals -- so present implied populated. Neither half
    holds now: the guard is committed at scripts/security/, and its tokens are EXTERNALIZED to a
    secret / git-ignored file. Guard-present therefore no longer implies tables-populated, and this
    test failed in CI on exactly that (present guard, no token source, empty tables) while passing
    locally only because the developer's checkout has the token file.

    Gate on the TOKEN SOURCE instead -- the condition that actually determines whether there is
    anything to source. The assertion still bites: blanking the bridge in tee/anon/leak.py reds it.
    """
    guard = tee_leak._load_publish_guard()  # type: ignore[attr-defined]
    if guard is None:
        pytest.skip("guard absent (e.g. an installed wheel with no scripts/ above it)")
    if not getattr(guard, "TOKENS_PRESENT", False):
        pytest.skip(
            "no token source configured (fork CI / fresh clone) — tables legitimately empty"
        )
    assert tee_leak.FORBIDDEN and tee_leak.ESTATE_TOKENS  # type: ignore[attr-defined]


# Synthetic-PHI-shape inputs (never a real value) whose UNMAPPED fields carry SSN/phone/MRN shapes,
# plus a benign case — the structural walk + coverage report + token-floor signal must agree between
# the engine (delegating to _scanner()) and the tee (reimplementing over _GUARD). The structural block
# is copied byte-for-byte between the two leak.py files; this is the divergence guard for it.
_LEAK_PARITY_INPUTS = [
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y\rDST|1|123-45-6789",
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"
    "\rDST|1|202-555-0188|(202) 555-0188",
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1|98765^^^HOSP^MR||X^Y",
    "MSH|^~\\&|A|B|C|D|20260101120000||ADT^A01|M1|P|2.5.1"
    "\rEVN|A01|20260101120000\rOBX|1|NM|8480-6^Systolic^LN||128|mm[Hg]",
]


def _structural_fields(report: object) -> tuple[object, ...]:
    """The STRUCTURAL/coverage fields of a LeakReport — the byte-copied #331 logic this guard pins.

    ``token_tables_live`` / ``token_floor_reason`` are intentionally excluded: they are derived from
    the token authority, not the structural walk, and the engine's ``_scanner()`` (lazily lru_cached
    on first call) and the tee's ``_GUARD`` (loaded at import) can snapshot the token source at
    different times within a full-suite run — a fixture that patches ``MEFOR_FORBIDDEN_TOKENS`` before
    the first ``_scanner()`` call poisons its token-floor view for the session. Those fields' cross-
    copy agreement is already pinned by ``test_leak_token_table_matches_publish_guard``; here we guard
    the detectors + coverage report, which are pure functions of (text, rules).
    """
    return (report.hits, report.unmapped_fields, report.structural_hits)  # type: ignore[attr-defined]


def test_leak_check_and_report_engine_equals_tee() -> None:
    for msg in _LEAK_PARITY_INPUTS:
        eng_hits = engine_leak.leak_check(msg, rules=DEFAULT_RULES)
        tee_hits = tee_leak.leak_check(msg, rules=DEFAULT_RULES)
        assert eng_hits == tee_hits, f"leak_check diverged on {msg!r}: {eng_hits!r} != {tee_hits!r}"
        eng_report = _structural_fields(engine_leak.leak_report(msg, rules=DEFAULT_RULES))
        tee_report = _structural_fields(tee_leak.leak_report(msg, rules=DEFAULT_RULES))
        assert eng_report == tee_report, (
            f"leak_report structural fields diverged on {msg!r}:"
            f"\n  ENG {eng_report!r}\n  TEE {tee_report!r}"
        )


def test_adversarial_inputs_engine_output_equals_tee_output() -> None:
    for msg in _ADVERSARIAL:
        engine = engine_anonymize(msg, salt=_SALT)
        tee = tee_anonymize(msg, salt=_SALT)
        assert engine == tee, f"engine/tee diverged on {msg!r}:\n  ENG {engine!r}\n  TEE {tee!r}"


def test_unanonymizable_inputs_fail_closed_on_both_sides() -> None:
    for msg in _REFUSED:
        with pytest.raises(ValueError):  # AnonError subclasses ValueError on both sides
            engine_anonymize(msg, salt=_SALT)
        with pytest.raises(ValueError):
            tee_anonymize(msg, salt=_SALT)


def test_surrogate_pools_carry_no_hl7_delimiter() -> None:
    # Whole-field writes assume a surrogate value never contains a delimiter; enforce it on the pools
    # so a future "realistic" name/street with ^ ~ & | can't silently diverge the two re-encoders.
    delimiters = set("|^~\\&")
    flat: list[str] = [
        *_hl7data.FAMILY_NAMES,
        *_hl7data.GIVEN_NAMES,
        *_hl7data.MIDDLE_INITIALS,
        *_hl7data.STREETS,
        *(v for row in _hl7data.CITIES for v in row),
        *(v for row in _hl7data.CLINICIANS for v in row),
    ]
    offenders = [v for v in flat if set(v) & delimiters]
    assert not offenders, f"surrogate pool values contain an HL7 delimiter: {offenders}"


def test_anon_files_do_not_self_trip_the_publish_guard() -> None:
    # The forbidden-content scanner runs in pre-commit/CI, not pytest — so a literal customer token
    # in a new (non-exempt) anon file would block the commit while pytest stayed green. Guard it here.
    sf = _load_scan_forbidden()
    files = [
        *(_ROOT / "messagefoundry" / "anon").glob("*.py"),
        *(_ROOT / "tee" / "anon").glob("*.py"),
    ]
    offenders = [hit for f in files for hit in sf.scan_file(f)]  # type: ignore[attr-defined]
    assert not offenders, f"anon files self-trip the forbidden-content guard: {offenders}"


def test_golden_corpus_engine_output_equals_tee_output() -> None:
    salt = "golden-salt-0123456789abcdef"
    checked = 0
    for code in _core.message_codes():
        for trigger in _core.triggers_for(code):
            raw = _core.generate_message(code, trigger, 1, seed="golden-parity")
            assert engine_anonymize(raw, salt=salt) == tee_anonymize(raw, salt=salt), (
                f"engine/tee output diverged on {code}^{trigger}"
            )
            checked += 1
    assert checked > 5, "golden corpus generated too few message types to be meaningful"
