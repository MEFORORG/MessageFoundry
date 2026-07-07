# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Small route helpers shared by the admin/account modules (moved from ``api.auth_routes``).

``_form_pairs`` is the stdlib urlencoded-form parser (no python-multipart dep) shared by every
body-carrying /ui admin/account POST; ``_client`` / ``_rate_limited`` are the account-lifecycle
throttle helpers re-implemented package-side (so the package never imports ``auth_routes``).
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qsl

from fastapi import HTTPException, Request, status

_log = logging.getLogger(__name__)


async def _form_pairs(request: Request) -> list[tuple[str, str]]:
    # stdlib urlencoded-form parsing (no python-multipart dep), like /ui/login. Pair order is
    # preserved so repeated fields (checkboxes, map rows) can be collected positionally.
    # keep_blank_values=True is LOAD-BEARING for the paired-row AD-map forms: a browser posts
    # blank fields (ad_group=, role=) for empty/half-filled rows, and dropping them (the
    # parse_qsl default) shifts the positional pairing so a role from one row silently binds
    # to a group from another — an RBAC mis-grant. With blanks kept, every row contributes
    # exactly one value per field and the row-wise "if g and r" filters drop incomplete rows
    # as intended. Scalar readers are unaffected (dict(pairs).get(k, "") yields "" either way;
    # checkbox values are never blank).
    return parse_qsl((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)


def _client(request: Request) -> str | None:
    # Already proxy-aware: uvicorn runs with forwarded_allow_ips = settings.api.trusted_proxies
    # (defaults to [] = trust nothing), so behind a declared trusted proxy this resolves to the
    # real client. Matches how ``api.auth_routes._client`` records it on the session.
    return request.client.host if request.client else None


def _rate_limited(request: Request, label: str) -> HTTPException:
    """Log a throttled (HTTP 429) attempt so password-spraying is no longer silent (ASVS 16.3.3),
    then return the exception to raise. We log (the rotating general log) rather than write an
    audit_log row per rejection so a sustained flood can't amplify into unbounded DB growth."""
    _log.warning("rate-limited %s attempt from client=%s", label, _client(request))
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts; please retry later")
