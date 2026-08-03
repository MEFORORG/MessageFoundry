# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Credential comparison and certificate-subject mapping — the ONE place a presented credential is
checked against a configured one.

Two planes share this, deliberately, so they can never disagree about what "this peer proved who it
is" means:

* the inbound connectors' per-connection ``intake_auth`` peer control (ADR 0154 D6), which compares an
  API key / bearer token off the wire and maps a client certificate to an allow-listed subject, and
* the operator API's mTLS client-certificate identity plane (``api/security.py``, ADR 0083), which
  maps the same certificate shape to a MessageFoundry username.

**Neutral and stdlib-only** — no engine, config, FastAPI or Qt imports — so both the transports (which
must not import the API) and the API (which must not import the transports) can depend on it. Lives at
the package root for that reason, next to the other neutral leaves (``netaddr``/``service_status``/
``redaction``), and for exactly the reason ``netaddr``'s docstring already gives.

Nothing here logs, and nothing here raises on bad input: every function is total and deny-by-default.
That is load-bearing rather than defensive — these run on the **unauthenticated** path, where an
exception becomes a ``500`` that skips the caller's audited-refusal branch.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable, Mapping
from typing import Any

__all__ = [
    "constant_time_match",
    "constant_time_match_any",
    "cert_name_candidates",
    "client_cert_principal",
]

# Compared in place of an unconfigured credential slot so the number of digest comparisons does not
# depend on how many slots an operator has filled. Its result is always DISCARDED, so this value can
# never authenticate anything even if a peer somehow presented it verbatim.
_UNCONFIGURED_SLOT = b"\x00messagefoundry:unconfigured-credential-slot"


def constant_time_match(presented: str | bytes | None, configured: str | bytes | None) -> bool:
    """Whether ``presented`` equals ``configured``, without leaking either by timing.

    Compares fixed-width SHA-256 digests of both sides rather than the raw values, so the
    credential's *length* cannot leak either — ``hmac.compare_digest`` is constant-time only across
    equal-length inputs.

    **An empty or absent value on either side returns ``False`` before anything is digested.** This
    precondition is the whole reason the function is written out rather than inlined:
    ``sha256(b"") == sha256(b"")``, so without it a request presenting **no credential at all**
    would authenticate against an unconfigured key slot — and an unconfigured slot is the default,
    because rotation is opt-in. The ASVS 11.2.4 drift guard in ``auth/totp.py`` is safe for the same
    reason: it validates the candidate *before* entering its no-break loop.

    A non-ASCII credential returns ``False`` rather than raising. Once both sides are digested
    ``compare_digest`` can no longer raise ``TypeError``, so the only hazard is the encode step, and
    a raise there on an unauthenticated path would ``500`` and skip the caller's audited refusal.
    """
    if not presented or not configured:
        return False
    try:
        presented_bytes = presented.encode("utf-8") if isinstance(presented, str) else presented
        configured_bytes = configured.encode("utf-8") if isinstance(configured, str) else configured
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(
        hashlib.sha256(presented_bytes).digest(),
        hashlib.sha256(configured_bytes).digest(),
    )


def constant_time_match_any(
    presented: str | bytes | None, configured: Iterable[str | bytes | None]
) -> bool:
    """Whether ``presented`` matches **any** configured, non-empty credential in ``configured``.

    The dual-key shape behind ``intake_api_key`` / ``intake_api_key_next``: a partner key rotates by
    configuring the next value alongside the current one, cutting over, then retiring the old — so
    rotation costs no outage.

    **No early return.** Every slot is compared even after one has matched, and an empty or absent
    slot is compared against a fixed dummy so the comparison count stays constant. Neither how many
    keys are configured nor which one matched is observable in the time taken. An absent
    ``presented`` short-circuits before the loop, per :func:`constant_time_match`'s precondition.
    """
    if not presented:
        return False
    matched = False
    for candidate in configured:
        if candidate:
            matched |= constant_time_match(presented, candidate)
        else:
            # Burn an equivalent comparison for an unconfigured slot. The result is discarded, so
            # _UNCONFIGURED_SLOT is not a credential and cannot authenticate anyone.
            constant_time_match(presented, _UNCONFIGURED_SLOT)
    return matched


def cert_name_candidates(peercert: Mapping[str, Any]) -> list[str]:
    """The qualified subject/SAN names of a ``ssl.getpeercert()`` dict, in match order (#200).

    Yields ``"CN:<commonName>"`` for each subject commonName RDN and ``"SAN:<type>:<value>"`` for each
    subjectAltName entry (e.g. ``"SAN:DNS:svc.internal"``). These are the exact keys an operator lists
    in ``[api].tls_client_cert_identities`` — qualifying the name space (CN vs SAN, SAN type) means a
    spoofed commonName can never collide with a pinned DNS SAN."""
    candidates: list[str] = []
    for rdn in peercert.get(
        "subject", ()
    ):  # subject = tuple of RDNs; each RDN = tuple of (attr, value)
        for pair in rdn:
            if len(pair) == 2 and pair[0] == "commonName":
                candidates.append(f"CN:{pair[1]}")
    for pair in peercert.get("subjectAltName", ()):
        if len(pair) == 2:
            candidates.append(f"SAN:{pair[0]}:{pair[1]}")
    return candidates


def client_cert_principal(
    peercert: Mapping[str, Any] | None, cert_map: Mapping[str, str]
) -> str | None:
    """The mapped MessageFoundry username for a verified peer cert, or ``None`` (deny-by-default) (#200).

    Pure: given a ``ssl.getpeercert()`` dict (only ever populated by ``ssl`` AFTER the chain verified
    against ``[api].tls_client_ca_file``) and the operator allow-list, return the first
    subject/SAN candidate present in the map. An empty/absent cert, an empty map, or a subject with no
    listed name all return ``None`` — an unmapped or spoofed-CN cert resolves to NO identity."""
    if not peercert or not cert_map:
        return None
    for candidate in cert_name_candidates(peercert):
        principal = cert_map.get(candidate)
        if principal:
            return principal
    return None
