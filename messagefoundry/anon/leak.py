# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Leak-check bridge (ADR 0030 §5) — the **non-parity seam** to the publish-guard's token authority.

A de-identified dataset is only safe to commit/share once it is **proven** free of known
customer/partner/site tokens — and that token set must be the SINGLE source of truth, not a third
copy that drifts (the very drift that already bit ``tests/test_load_config.py``). So the engine-side
leak-check delegates to ``scripts/publish/scan_forbidden.py`` — the owner-managed publish guard — via
its importable :func:`scan_text`. The standalone ``tee/anon/leak.py`` vendors the same token data
(held identical by the parity test), since the tee cannot reach ``scripts/``.

The check is the **fail-closed backstop**, not the primary control: it catches known *tokens*, not
structural PHI (a missed MRN field with no denylisted string sails through) — rule-map completeness
is the primary control (ADR 0030 §5). It is loaded lazily from the source checkout; an installed
wheel without ``scripts/`` raises a clear error (the anonymizer is a dev/migration tool, always run
from a checkout).
"""

from __future__ import annotations

import importlib.util
from functools import lru_cache
from pathlib import Path
from types import ModuleType

from .surrogates import message_has_site_code


class LeakCheckUnavailable(RuntimeError):
    """The publish-guard scanner could not be located (not run from a source checkout)."""


@lru_cache(maxsize=1)
def _scanner() -> ModuleType:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "scripts" / "publish" / "scan_forbidden.py"
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location("mefor_anon_scan_forbidden", candidate)
            if spec is not None and spec.loader is not None:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
    raise LeakCheckUnavailable(
        "could not locate scripts/publish/scan_forbidden.py — the anonymizer leak-check requires "
        "the source checkout (it is a dev/migration tool, not an installed-wheel runtime)"
    )


def leak_check(text: str) -> list[str]:
    """Forbidden-token hits in ``text`` (empty list = clean), using the publish-guard's authority.

    Substring + estate-token mode (ADR 0030 §5): catches a partner/site token anywhere in a message
    body, including inside a field, where the publish-prose word-boundary form would miss it. The
    ``54xxxx`` site code is checked **field-anchored** (``message_has_site_code``), matching the
    replace path, so a scrub *miss* is caught without false-positiving on a value that merely contains
    a ``54xxxx`` run (a timestamp, a fabricated 1954/2054 date).
    """
    hits = [str(h) for h in _scanner().scan_text(text, include_estate=True)]
    if message_has_site_code(text):
        hits.append("site-code pattern (54xxxx)")
    return hits
