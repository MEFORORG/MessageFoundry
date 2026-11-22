# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0019 and ADR 0173 point to the record that states a fact, rather than restating it.

ADR 0019's RNG amendment once restated ADR 0138's Transit start gate (vault BACKLOG #1173, item 3),
and ADR 0173's ODBC test amendment gave its times in two zones and restated its versions and
decision times (vault BACKLOG #3009, PR 2899 notes 3 and 4). SDS-3.5: a fact lives in one place.
"""

from __future__ import annotations

from pathlib import Path

_ADR = Path(__file__).resolve().parent.parent / "docs" / "adr"
_ADR_0019 = _ADR / "0019-pluggable-keyprovider-hsm-kms-vault.md"
_ADR_0173 = (
    _ADR
    / "0173-tls-peer-revocation-checking-and-ocsp-stapling-across-terminating-and-originating-surfaces.md"
)


def _between(text: str, start: str, end: str) -> str:
    head = text.index(start)
    return text[head : text.index(end, head)]


def test_adr_0019_point_4_does_not_restate_the_transit_gate() -> None:
    text = _ADR_0019.read_text(encoding="utf-8")
    point_4 = _between(
        text,
        "4. **Volume wears out a key, not the generator.**",
        "**What this statement does not cover.**",
    )
    # Stop before any correction note, which names what was removed.
    point_4 = point_4.split("*(Corrected", 1)[0]
    for restated in ("refuses to start", "logs a warning", "weaker than the counted bound"):
        assert restated not in point_4, restated
    assert "enforce_transit_bound_attestation" in point_4  # positive control: the pointer stays
    assert "0138-transit-bulk-crypto-provider" in point_4


def test_adr_0173_odbc_amendment_states_times_in_one_zone() -> None:
    text = _ADR_0173.read_text(encoding="utf-8")
    amendment = _between(
        text,
        "**Amendment 2026-11-11 -- what the ODBC Driver 18 test measured",
        "*(End of the amendment of 2026-11-11.",
    )
    # The amendment's own body, before the limits and the correction note that names what went.
    findings = amendment[: amendment.index("- **The limits.**")]
    assert "Central time" not in findings
    assert "logged at" not in amendment
    assert amendment.count("Windows Server 2022") == 1
    assert "02:22 to 02:25 UTC" in findings  # positive control: the UTC times stay
    grade_note = _between(text, "*(Note 2026-11-11: two recorded results exist", ")*")
    assert "logged at" not in grade_note
    assert "d20261112T022118464-c27c39" in grade_note  # positive control: the decision stays
