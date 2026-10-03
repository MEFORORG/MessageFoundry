# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An egress policy for tests that build one connector to exercise its construction.

``build_destination`` runs the ``[egress]`` check itself (vault BACKLOG #2605), so a test that is
about a connector's own behaviour must hand it a policy that lets that connector through. This one
is the audited allow-any opt-out plus the two lists that stay deny-by-default under it: the
forward-proxy host and the recipient domains, each taken from the connection's own settings. It
permits exactly that connection and lists nothing else.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Mapping
from typing import Any

from messagefoundry.config.settings import EgressSettings
from messagefoundry.transports.email import envelope_recipients


def permitting(settings: Mapping[str, Any]) -> EgressSettings:
    """Allow-any egress that also lists this connection's proxy host and recipient domains."""
    proxy = urllib.parse.urlsplit(str(settings.get("proxy_url") or "")).hostname
    try:
        addresses = envelope_recipients(settings.get("recipients"))
    except ValueError:
        addresses = []  # a malformed list is the connector's to refuse, not this helper's
    return EgressSettings(
        deny_by_default=False,
        allowed_proxy=[proxy] if proxy else [],
        allowed_recipient_domains=sorted({a.rpartition("@")[2].lower() for a in addresses}),
    )
