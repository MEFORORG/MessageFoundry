# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5529: HTTP Digest either runs as configured or the connection does not build.

Limb 3 (also #2707 closing step 1): ``ech_egress`` replaced the opener that held the Digest
handler, so a REST connection built and delivered with no Digest auth. The handler cannot simply
ride the ECH opener: its password manager is keyed on the destination URL, while the ECH request
goes to the sidecar URL, so no challenge would ever match. The pair is refused at construction.
"""

from __future__ import annotations

import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import Rest
from messagefoundry.transports import build_destination
from messagefoundry.transports.http_auth import with_http_digest
from messagefoundry.transports.rest import HttpAuthError, RestDestination
from tests._egress_policy import permitting

URL = "https://partner.example/ingest"
_PW = "digest-pw-synthetic"  # noqa: S105 -- a synthetic test credential, not a real secret
_SIDECAR = {"ech_egress": True, "ech_sidecar": "http://127.0.0.1:8123"}


def _build(ctype: ConnectorType, settings: dict[str, object]) -> object:
    return build_destination(
        Destination(name="OB_HTTP", type=ctype, settings=settings),
        egress=permitting(settings),
    )


def _digest_rest(**extra: object) -> dict[str, object]:
    settings = with_http_digest(Rest(url=URL), user="u", password=_PW).settings
    settings.update(extra)
    return settings


def _has_digest(dest: object) -> bool:
    handlers = dest._opener.handlers  # type: ignore[attr-defined]  # typeshed omits it
    return any(isinstance(h, urllib.request.HTTPDigestAuthHandler) for h in handlers)


# --- limb 3: ech_egress with Digest --------------------------------------------------------------


def test_ech_egress_with_digest_is_refused_at_construction() -> None:
    with pytest.raises(HttpAuthError, match="ech_egress and HTTP Digest") as ei:
        _build(ConnectorType.REST, _digest_rest(**_SIDECAR))
    assert _PW not in str(ei.value)


def test_control_digest_without_ech_builds_with_its_handler() -> None:
    dest = _build(ConnectorType.REST, _digest_rest())
    assert isinstance(dest, RestDestination)
    assert _has_digest(dest)


def test_control_ech_without_digest_builds() -> None:
    settings = Rest(url=URL).settings
    settings.update(_SIDECAR)
    dest = _build(ConnectorType.REST, settings)
    assert isinstance(dest, RestDestination)
    assert dest._ech_sidecar is not None
