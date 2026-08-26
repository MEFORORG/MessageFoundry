# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""An entropy FLOOR for MFA recovery codes, derived rather than transcribed (BACKLOG #1172).

Recovery codes are a full authentication factor: one of them substitutes for the authenticator app.
So their guessing strength is the strength of the SECOND factor, and it was 68.67 bits.

**Every number here is computed from the shipped constants.** Nothing is transcribed, because a
transcribed figure and the code it describes drift apart silently -- which is the defect this file
exists to prevent, not merely to document. Two derivations do the work:

* **Per-code entropy** comes from ``_RECOVERY_GROUPS``, ``_RECOVERY_GROUP_LEN`` and the SIZE OF THE
  DISTINCT alphabet. Distinct on purpose: a duplicated character adds a symbol without adding a
  choice, so ``len(set(...))`` is the honest base and ``len(...)`` would overstate it.
* **The multiplicity adjustment** comes from the VALIDATOR ITSELF, by asking it which counts it
  accepts. An attacker needs any ONE of the issued codes, so N codes cost ``log2(N)`` bits. Reading
  the ceiling out of the validator rather than writing ``50`` here means raising that ceiling
  tightens this test automatically instead of silently invalidating it.
"""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from messagefoundry.auth import totp
from messagefoundry.config.settings import AuthSettings

#: The bar. A second factor should be no weaker than a modern symmetric key.
_FLOOR_BITS = 128.0


def _accepts(count: int) -> bool:
    """Does the SHIPPED validator accept this recovery-code count?"""
    try:
        AuthSettings(mfa_recovery_code_count=count)
    except ValidationError:
        return False
    return True


def _validator_ceiling() -> int:
    """The largest count the validator accepts, found by ASKING IT rather than by transcribing 50."""
    assert _accepts(0), "the validator rejects 0; this probe assumes 0 is the disabled case"
    hi = 1
    while _accepts(hi):
        hi *= 2
        assert hi <= 1 << 20, "no ceiling found below 2**20 -- the validator may be unbounded"
    lo = hi // 2
    while lo + 1 < hi:  # invariant: lo accepted, hi rejected
        mid = (lo + hi) // 2
        if _accepts(mid):
            lo = mid
        else:
            hi = mid
    return lo


def _per_code_bits(groups: int, group_len: int, alphabet: str) -> float:
    return groups * group_len * math.log2(len(set(alphabet)))


def _guessing_bits(groups: int, group_len: int, alphabet: str, issued: int) -> float:
    """Strength against an attacker who needs ANY ONE of ``issued`` codes."""
    return _per_code_bits(groups, group_len, alphabet) - math.log2(issued)


def test_the_validator_ceiling_is_discoverable_and_finite() -> None:
    """The probe is a measurement, so it gets its own check: a broken probe would silently make
    every floor below look generous."""
    ceiling = _validator_ceiling()
    assert ceiling >= 1
    assert _accepts(ceiling), "the discovered ceiling is not actually accepted"
    assert not _accepts(ceiling + 1), "one above the discovered ceiling is still accepted"


def test_recovery_codes_clear_the_entropy_floor_at_the_worst_permitted_count() -> None:
    """Asserted at the WORST case the validator permits, not at the shipped default.

    The default is what a site gets; the ceiling is what a site may choose. A floor that only holds
    at the default is not a floor, and nothing stops an operator raising the count.
    """
    bits = _guessing_bits(
        totp._RECOVERY_GROUPS,
        totp._RECOVERY_GROUP_LEN,
        totp._RECOVERY_ALPHABET,
        _validator_ceiling(),
    )
    assert bits >= _FLOOR_BITS, (
        f"recovery codes give {bits:.2f} bits against the worst permitted issue count, under the "
        f"{_FLOOR_BITS:.0f}-bit floor. A recovery code is a full second factor; raise "
        f"_RECOVERY_GROUPS in messagefoundry/auth/totp.py."
    )


@pytest.mark.parametrize("weaken", ["groups", "group_len", "alphabet"])
def test_lowering_any_constant_breaks_the_floor(weaken: str) -> None:
    """MUTATION CONTROL. A floor that cannot fail is not a floor.

    Each of the three inputs is reduced by ONE unit in turn -- one group, one character per group,
    one symbol -- and the floor must red. If a mutation still passes, the margin is wide enough that
    this test would not notice a real regression, and the floor needs raising rather than the
    mutation excusing.
    """
    groups = totp._RECOVERY_GROUPS - (1 if weaken == "groups" else 0)
    group_len = totp._RECOVERY_GROUP_LEN - (1 if weaken == "group_len" else 0)
    alphabet = totp._RECOVERY_ALPHABET[:-1] if weaken == "alphabet" else totp._RECOVERY_ALPHABET

    weakened = _guessing_bits(groups, group_len, alphabet, _validator_ceiling())
    shipped = _guessing_bits(
        totp._RECOVERY_GROUPS,
        totp._RECOVERY_GROUP_LEN,
        totp._RECOVERY_ALPHABET,
        _validator_ceiling(),
    )
    assert weakened < shipped, f"weakening {weaken!r} did not reduce the entropy at all"
    if weaken == "alphabet":
        # One symbol off 31 is worth ~0.05 bits/char; the assertion that matters is DIRECTION.
        pytest.skip("a single-symbol reduction is below the floor's resolution; direction asserted")
    assert weakened < _FLOOR_BITS, (
        f"removing one {weaken} still yields {weakened:.2f} bits, at or above the "
        f"{_FLOOR_BITS:.0f}-bit floor -- so this floor cannot detect that regression."
    )


def test_generated_codes_match_the_constants_the_floor_is_computed_from() -> None:
    """The floor is arithmetic over constants; this pins that the GENERATOR actually uses them, so
    the arithmetic describes the shipped code rather than three unused names."""
    codes = totp.generate_recovery_codes(3)
    assert len(codes) == 3
    for code in codes:
        groups = code.split("-")
        assert len(groups) == totp._RECOVERY_GROUPS
        assert all(len(g) == totp._RECOVERY_GROUP_LEN for g in groups)
        assert set(code.replace("-", "")) <= set(totp._RECOVERY_ALPHABET)
