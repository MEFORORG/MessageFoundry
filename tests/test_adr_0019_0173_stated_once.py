# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0019 and ADR 0173 point to the record that states a fact, rather than restating it.

ADR 0019's RNG amendment point 4 once restated ADR 0138's Transit start gate (vault BACKLOG #1173,
item 3). ADR 0173's ODBC test amendment gave its run dates in two zones and repeated its versions
in its limits (vault BACKLOG #3009, PR 2899 notes 3 and 4). SDS-3.5: a fact lives in one place.

Each refused phrase is checked against the text it was removed from, so a phrase that drifts
from that wording fails here instead of passing for ever.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_ADR = Path(__file__).resolve().parent.parent / "docs" / "adr"
_ADR_0019 = _ADR / "0019-pluggable-keyprovider-hsm-kms-vault.md"
_ADR_0173 = (
    _ADR
    / "0173-tls-peer-revocation-checking-and-ocsp-stapling-across-terminating-and-originating-surfaces.md"
)

# The removed wording, as it read on origin/main before the fix: the negative controls.
_OLD_0019_POINT_4 = (
    "In its place, `Engine.start` calls `enforce_transit_bound_attestation` in "
    "`store/transit_attestation.py`, which checks for a recorded operator attestation naming the "
    "configured Transit data key (BACKLOG #2337). Without one, the engine refuses to start under "
    "`[security].enforcement = enforce` and only logs a warning under `warn`."
)
_OLD_0173_FINDINGS = (
    "Two runs with results, dated 2026-10-16 and 2026-10-17 in Central time. In UTC, the first "
    "run's legs ran from 02:22 to 02:25"
)
_OLD_0173_LIMIT = "Only that driver build, only Windows Server 2022, and only SQL Server 2022 RTM."

_REFUSED_0019 = ("in its place,", "refuses to start", "logs a warning", "naming the configured")
_REFUSED_0173_FINDINGS = ("in utc, the first run", "2026-10-17 in central time")
_REFUSED_0173_LIMIT = ("only windows server 2022", "only sql server 2022 rtm")


def _flat(text: str) -> str:
    """Join wrapped lines and fold case, so a phrase that wraps or opens a sentence still matches."""
    return " ".join(text.split()).lower()


def _between(text: str, start: str, end: str) -> str:
    head = text.index(start)
    return text[head : text.index(end, head)]


def _body(text: str) -> str:
    """Drop correction notes, which quote the removed words on purpose."""
    return text.split("*(Corrected 2026-11-21", 1)[0]


@pytest.mark.parametrize(
    ("old", "refused"),
    [
        (_OLD_0019_POINT_4, _REFUSED_0019),
        (_OLD_0173_FINDINGS, _REFUSED_0173_FINDINGS),
        (_OLD_0173_LIMIT, _REFUSED_0173_LIMIT),
    ],
)
def test_each_refused_phrase_matches_the_removed_wording(
    old: str, refused: tuple[str, ...]
) -> None:
    for phrase in refused:
        assert phrase in _flat(old), phrase


def test_adr_0019_point_4_does_not_restate_the_transit_gate() -> None:
    text = _ADR_0019.read_text(encoding="utf-8")
    point_4 = _flat(
        _body(
            _between(
                text,
                "4. **Volume wears out a key, not the generator.**",
                "**What this statement does not cover.**",
            )
        )
    )
    for phrase in _REFUSED_0019:
        assert phrase not in point_4, phrase
    # Positive controls: the pointer, the link and the caveat stay.
    assert "enforce_transit_bound_attestation" in point_4
    assert "0138-transit-bulk-crypto-provider" in point_4
    assert "weaker than the counted bound" in point_4


def test_adr_0173_odbc_amendment_states_dates_and_versions_once() -> None:
    text = _ADR_0173.read_text(encoding="utf-8")
    amendment = _body(
        _between(
            text,
            "**Amendment 2026-11-11 -- what the ODBC Driver 18 test measured",
            "*(End of the amendment of 2026-11-11.",
        )
    )
    head, _, limits = amendment.partition("- **The limits.**")
    findings, limits = _flat(head), _flat(limits)
    for phrase in _REFUSED_0173_FINDINGS:
        assert phrase not in findings, phrase
    for phrase in _REFUSED_0173_LIMIT:
        assert phrase not in limits, phrase
    # Positive controls: the UTC times and the versions are each still stated.
    assert "02:22 to 02:25 utc" in findings
    assert "windows server 2022 datacenter" in findings
    assert limits  # the limits list was found
