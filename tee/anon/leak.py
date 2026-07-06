# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Leak-check for the standalone tee (ADR 0030 §5) — a thin front-end over the publish-guard authority.

The token tables (customer/partner names + estate-vendor tokens) are the owner-managed
``scripts/publish/scan_forbidden.py`` set; this file **loads them from that guard by path at import**
(the same way ``messagefoundry/anon/leak.py`` does) rather than vendoring a copy — so **no literal or
fragmented customer/vendor token appears in this tracked, published file**, and there is nothing to
drift (``test_anon_parity`` still pins the two equal). Loading by path keeps the tee ``messagefoundry``-free.

``scripts/publish/`` is deny-listed on the OSS mirror, so the guard is **absent** there: the name +
estate tables then load **empty** and the leak-check degrades to a no-op for those (a public checkout
has no customer estate to leak). The generic site-code / IP detectors keep a literal default so the
anonymizer's structural checks still function without the guard.

Returns **reasons only** (never the matched text), and is the fail-closed backstop, not the primary
control: it catches known *tokens*, not structural PHI (ADR 0030 §5).
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

from .surrogates import message_has_site_code


def _load_publish_guard(_start: Path | None = None) -> object | None:
    """Load the owner-managed publish guard (``scripts/publish/scan_forbidden.py``) by path, walking up
    from this file. It is the SINGLE source for the token tables, so none live literally here. Absent on
    the OSS mirror (``scripts/publish/`` is deny-listed) → returns ``None`` and the tables load empty.
    ``_start`` overrides the search origin for tests."""
    origin = (_start if _start is not None else Path(__file__)).resolve()
    for parent in origin.parents:
        candidate = parent / "scripts" / "publish" / "scan_forbidden.py"
        if candidate.exists():
            spec = importlib.util.spec_from_file_location("tee_anon_publish_guard", candidate)
            if spec is not None and spec.loader is not None:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod
    return None


_GUARD = _load_publish_guard()

# Customer/partner names + estate-vendor tokens — sourced from the publish guard (held identical to it
# by test_anon_parity), so NO literal or fragmented customer/vendor token appears in this published
# file. Empty when the guard is absent (the OSS mirror), where the leak-check is a no-op for these.
FORBIDDEN: list[tuple[re.Pattern[str], str]] = list(_GUARD.FORBIDDEN) if _GUARD else []  # type: ignore[attr-defined]
ESTATE_TOKENS: tuple[str, ...] = tuple(_GUARD.ESTATE_TOKENS) if _GUARD else ()  # type: ignore[attr-defined]

# Generic structural detectors (NOT customer data): loaded from the guard when present (parity), with a
# literal default so a public checkout's site-code / IP checks still work without the guard.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
SITE_CODE_RE = _GUARD.SITE_CODE_RE if _GUARD else re.compile(r"54\d{4}")  # type: ignore[attr-defined]
_IPV4 = _GUARD._IPV4 if _GUARD else re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?![\d.])")  # type: ignore[attr-defined]
_ALLOWED_IP = (
    _GUARD._ALLOWED_IP  # type: ignore[attr-defined]
    if _GUARD
    else re.compile(
        r"^(?:"
        r"0\.|127\.|10\.|192\.168\.|169\.254\.|255\.|"
        r"172\.(?:1[6-9]|2\d|3[01])\.|"
        r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|"
        r"22[4-9]\.|23\d\."
        r")"
    )
)


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
