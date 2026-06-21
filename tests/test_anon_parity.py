# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Engine ↔ tee parity (ADR 0030 §1): the shared logic files stay byte-identical, the vendored pools
+ leak tokens stay in lockstep with their sources, and the two re-encoders produce identical output
on a golden corpus (the divergence guard the design depends on)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from messagefoundry.anon import anonymize as engine_anonymize
from messagefoundry.generators import _core, _hl7data
from messagefoundry.generators import all_types  # noqa: F401  (registers message types)
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
    path = _ROOT / "scripts" / "publish" / "scan_forbidden.py"
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
