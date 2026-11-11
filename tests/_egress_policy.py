# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An egress policy for tests that build one connector to exercise its construction.

``build_destination`` runs the ``[egress]`` check itself (vault BACKLOG #2605), so a test that is
about a connector's own behaviour must hand it a policy that lets that connector through. This one
is the audited allow-any opt-out plus at least these lists that stay deny-by-default under it: the
forward-proxy host, the ECH sidecar's host and port (BACKLOG #5528) and the recipient domains, each
taken from the connection's own settings. The recipient-domain list also gates an Email sender's
domain (vault BACKLOG #2912), so the sender's domain is listed too. It permits exactly that
connection and lists nothing else.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Mapping
from typing import Any

from messagefoundry.config.settings import EgressSettings, pinned_host_port
from messagefoundry.transports.egress import http_dial_port
from messagefoundry.transports.email import envelope_address_problem, envelope_recipients
from messagefoundry.transports.rest import ech_sidecar_url_from_settings


def _ech_sidecar_entries(settings: Mapping[str, Any]) -> list[str]:
    """The ``host:port`` entry that lists this connection's ECH sidecar, at the port urllib dials,
    or none when ``ech_egress`` is off or no entry could list the sidecar (the gate refuses that)."""
    try:
        sidecar = ech_sidecar_url_from_settings(settings)
        parts = urllib.parse.urlsplit(sidecar or "")
        port = parts.port
    except ValueError:
        return []
    if sidecar is None or not parts.hostname:
        return []
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    entry = f"{host}:{http_dial_port(parts.scheme, port)}"
    # A sidecar no entry could list (port 0) gets none, and the gate refuses it.
    return [entry] if pinned_host_port(entry) is not None else []


def permitting(settings: Mapping[str, Any]) -> EgressSettings:
    """Allow-any egress that also lists this connection's proxy host, its ECH sidecar, and its
    recipient and sender domains."""
    proxy = urllib.parse.urlsplit(str(settings.get("proxy_url") or "")).hostname
    try:
        addresses = envelope_recipients(settings.get("recipients"))
    except ValueError:
        addresses = []  # a malformed list is the connector's to refuse, not this helper's
    sender = settings.get("sender")
    if isinstance(sender, str) and envelope_address_problem(sender) is None:
        addresses.append(sender)  # a malformed sender is the connector's to refuse, as above
    return EgressSettings(
        deny_by_default=False,
        allowed_proxy=[proxy] if proxy else [],
        allowed_ech_sidecar=_ech_sidecar_entries(settings),
        allowed_recipient_domains=sorted({a.rpartition("@")[2].lower() for a in addresses}),
    )
