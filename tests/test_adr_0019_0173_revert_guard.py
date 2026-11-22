# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A revert guard: ADR 0019 and ADR 0173 do not take back the restatements removed from them.

ADR 0019's RNG amendment point 4 and its first 2026-10-10 note restated ADR 0138's Transit start
gate (vault BACKLOG #1173, item 3). ADR 0173's ODBC test amendment opened with its run dates in two
zones and repeated its versions in its limits (vault BACKLOG #3009, PR 2899 notes 3 and 4).

This refuses the removed phrasings only. It does not prove a fact is stated once anywhere else.
Each refused phrase is checked against the removed wording, so a phrase that drifts from that
wording fails here instead of passing for ever.
"""

from __future__ import annotations

import re
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
_OLD_0019_NOTE = (
    "Since BACKLOG #2337, an operator attests to the precondition with "
    "`messagefoundry store attest-transit-bound`, and `Engine.start` reads that record"
)
_OLD_0173_FINDINGS = (
    "Two runs with results, dated 2026-10-16 and 2026-10-17 in Central time. In UTC, the first "
    "run's legs ran from 02:22 to 02:25"
)
_OLD_0173_LIMIT = "Only that driver build, only Windows Server 2022, and only SQL Server 2022 RTM."

_REFUSED_0019 = ("in its place,", "refuses to start", "logs a warning", "naming the configured")
_REFUSED_0019_NOTE = ("attest-transit-bound", "reads that record")
_REFUSED_0173_FINDINGS = ("in utc, the first run", "2026-10-17 in central time")
_REFUSED_0173_LIMIT = ("only windows server 2022", "only sql server 2022 rtm")

# A 2026-11-21 correction note quotes the removed words on purpose; strip only the note itself.
_NOTE = re.compile(r"\*\(Corrected 2026-11-21,.*?\)\*", re.DOTALL)


def _flat(text: str) -> str:
    """Join wrapped lines, drop blockquote markers and fold case, so a wrapped phrase matches."""
    return " ".join(w for w in _NOTE.sub("", text).split() if w != ">").lower()


def _between(text: str, start: str, end: str) -> str:
    head = text.index(start)
    return text[head : text.index(end, head)]


@pytest.mark.parametrize(
    ("old", "refused"),
    [
        (_OLD_0019_POINT_4, _REFUSED_0019),
        (_OLD_0019_NOTE, _REFUSED_0019_NOTE),
        (_OLD_0173_FINDINGS, _REFUSED_0173_FINDINGS),
        (_OLD_0173_LIMIT, _REFUSED_0173_LIMIT),
    ],
)
def test_each_refused_phrase_matches_the_removed_wording(
    old: str, refused: tuple[str, ...]
) -> None:
    for phrase in refused:
        assert phrase in _flat(old), phrase


def test_adr_0019_does_not_revert_the_transit_gate_wording() -> None:
    text = _ADR_0019.read_text(encoding="utf-8")
    point_4 = _flat(
        _between(
            text,
            "4. **Volume wears out a key, not the generator.**",
            "**What this statement does not cover.**",
        )
    )
    note = _flat(
        _between(
            text,
            "> **Corrected 2026-10-10 (BACKLOG #1173).** The rotation precondition above",
            "**Status: 11.3.4",
        )
    )
    for phrase in _REFUSED_0019:
        assert phrase not in point_4, phrase
    for phrase in _REFUSED_0019_NOTE:
        assert phrase not in note, phrase
    # Positive controls: the pointer, the link and the caveat stay.
    assert "enforce_transit_bound_attestation" in point_4
    assert "0138-transit-bulk-crypto-provider" in point_4
    assert "weaker than the counted bound" in point_4
    assert "enforce_transit_bound_attestation" in note


def test_adr_0173_odbc_amendment_does_not_revert_its_opening_or_version_limit() -> None:
    text = _ADR_0173.read_text(encoding="utf-8")
    amendment = _between(
        text,
        "**Amendment 2026-11-11 -- what the ODBC Driver 18 test measured",
        "*(End of the amendment of 2026-11-11.",
    )
    head, _, limits = amendment.partition("- **The limits.**")
    findings, limits = _flat(head), _flat(limits)
    for phrase in _REFUSED_0173_FINDINGS:
        assert phrase not in findings, phrase
    for phrase in _REFUSED_0173_LIMIT:
        assert phrase not in limits, phrase
    # Positive controls: the UTC times, the versions and the version limit are each still stated.
    assert "02:22 to 02:25 utc" in findings
    assert "windows server 2022 datacenter" in findings
    assert "only the driver, windows and sql server versions above" in limits
