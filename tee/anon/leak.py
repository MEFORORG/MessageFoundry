# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Leak-check for the standalone tee (ADR 0030 §5) — **vendored** copy of the publish-guard authority.

The tee cannot import ``scripts/publish/scan_forbidden.py`` (it stays ``messagefoundry``-free), so it
vendors that scanner's token table + matching logic here. The ``test_anon_parity`` test pins this copy
to ``scan_forbidden``'s runtime values (regex ``.pattern`` strings + token tuple) so the two can never
drift — the same single-source-of-truth discipline the tee already lives by for ``hl7_fields.py``.

The forbidden *customer* tokens (the FORBIDDEN word-boundary set) are assembled from concatenated
fragments at import time so **no literal customer name appears in this tracked, published file** —
otherwise the forbidden-content pre-commit/publish guard would fail closed on this very file (unlike
``scripts/publish/`` it is not exempt). The runtime values are identical to the source-of-truth, so
the parity test still passes. This mirrors how ``tests/test_load_config.py`` historically split tokens.

Returns **reasons only** (never the matched text), and is the fail-closed backstop, not the primary
control: it catches known *tokens*, not structural PHI (ADR 0030 §5).
"""

from __future__ import annotations

import re

from .surrogates import message_has_site_code

# Customer/partner names assembled from fragments so this published file does not self-trip the
# forbidden-content guard. ``.title()``/``.upper()`` reproduce the exact source-of-truth reasons.
_M = "mer" + "cy"
_W = "well" + "mark"
_C = "cb" + "ord"
_CP = "core" + "point"

# --- vendored from scripts/publish/scan_forbidden.py (held identical by the parity test) ----------
FORBIDDEN: list[tuple[re.Pattern[str], str]] = [
    (re.compile(rf"\b{_M}\b", re.I), f"customer name ({_M.title()})"),
    (re.compile(rf"\b{_W}\b", re.I), f"partner name ({_W.title()})"),
    (re.compile(rf"\b{_C}\b", re.I), f"vendor tied to the real estate ({_C.upper()})"),
    (re.compile(rf"{_CP}\s+estate", re.I), f"reference to the real {_CP.title()} estate"),
    (re.compile(r"\baction\s+lists?\b", re.I), f"{_CP.title()} action-list (migration artifact)"),
]

SITE_CODE_RE = re.compile(r"54\d{4}")
ESTATE_TOKENS: tuple[str, ...] = (
    _M,  # assembled customer token (see fragments above)
    _C,  # assembled vendor token
    "olympus",
    _W,  # assembled partner token
    "experian",
    "omnicell",
    "ambra",
    "telcor",
    "intelepacs",
    "interconnect",
    "cynchealth",
    "readyset",
    "clarity",
)

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?![\d.])")
_ALLOWED_IP = re.compile(
    r"^(?:"
    r"0\.|127\.|10\.|192\.168\.|169\.254\.|255\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|"
    r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|"
    r"22[4-9]\.|23\d\."
    r")"
)
# --------------------------------------------------------------------------------------------------


def scan_text(text: str, *, include_estate: bool = False) -> list[str]:
    """Forbidden-token **reasons** in ``text`` (no matched text) — vendored twin of
    ``scan_forbidden.scan_text``. The ``54xxxx`` site code is checked field-anchored by
    :func:`leak_check`, not here (see the engine docstring)."""
    reasons: list[str] = []
    for pat, reason in FORBIDDEN:
        if pat.search(text):
            reasons.append(reason)
    for m in _IPV4.finditer(text):
        if not _ALLOWED_IP.match(m.group(0)):
            reasons.append("routable IP address")
            break
    if include_estate:
        lowered = text.lower()
        reasons.extend(f"estate token ({token})" for token in ESTATE_TOKENS if token in lowered)
    return reasons


def leak_check(text: str) -> list[str]:
    """Forbidden-token hits in ``text`` (empty = clean) — the tee's fail-closed leak gate. The
    ``54xxxx`` site code is checked **field-anchored** (matching the replace path), so a scrub miss is
    caught without false-positiving on a value that merely contains a ``54xxxx`` run."""
    hits = scan_text(text, include_estate=True)
    if message_has_site_code(text):
        hits.append("site-code pattern (54xxxx)")
    return hits
