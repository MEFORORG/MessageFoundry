# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Credential comparison and certificate-subject mapping — the ONE place a presented credential is
checked against a configured one.

Two planes share this, deliberately, so they can never disagree about how a presented credential or
certificate name compares:

* the inbound connectors' per-connection ``intake_auth`` peer control (ADR 0154 D6), which compares an
  API key / bearer token off the wire and maps a client certificate to an allow-listed subject, and
* the operator API's mTLS client-certificate identity plane (``api/security.py``, ADR 0083), which
  maps the same certificate shape to a MessageFoundry account id.

They share the subject match, and both first select the names listed under the certificate's own
verified issuer, the loaded CA whose key signed it (BACKLOG #2237 for the API plane, #2287 for the
intake plane's ``intake_client_subjects``), through :func:`client_cert_principal_under_issuer`.

**Neutral and stdlib-only** — no engine, config, FastAPI or Qt imports — so both the transports (which
must not import the API) and the API (which must not import the transports) can depend on it. Lives at
the package root for that reason, next to the other neutral leaves (``netaddr``/``service_status``/
``redaction``), and for exactly the reason ``netaddr``'s docstring already gives.

Nothing here logs, and nothing here raises on bad input: every function is total and deny-by-default.
That is load-bearing rather than defensive — these run on the **unauthenticated** path, where an
exception becomes a ``500`` that skips the caller's audited-refusal branch.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import ipaddress
import re
from collections.abc import Iterable, Mapping
from typing import Any

__all__ = [
    "QUALIFIED_CERT_NAME",
    "SAN_TYPES",
    "VERIFIED_ISSUER_KEY",
    "constant_time_equal",
    "constant_time_match",
    "constant_time_match_any",
    "cert_name_candidates",
    "client_cert_principal",
    "client_cert_principal_under_issuer",
    "unmatchable_san_reason",
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


def constant_time_equal(a: str | bytes, b: str | bytes) -> bool:
    """Whether two digests or identifiers are equal, by ``hmac.compare_digest`` over bytes.

    ASVS 11.2.4 (BACKLOG #1167): ``==`` stops at the first differing character. This is for values
    such as a session token hash, a credential-id hash or a config fingerprint, not for a presented
    credential, which is :func:`constant_time_match`'s job. It differs from that function in two
    ways, both on purpose: two empty values ARE equal here, and nothing is digested first, so a
    difference in LENGTH still shows. Every caller compares fixed-width digests.

    Total: ``surrogatepass`` encodes any ``str`` CPython can hold, so a caller's string can never
    raise ``TypeError`` out of the compare, and two distinct strings never map to the same bytes.
    """
    a_bytes = a.encode("utf-8", "surrogatepass") if isinstance(a, str) else a
    b_bytes = b.encode("utf-8", "surrogatepass") if isinstance(b, str) else b
    return hmac.compare_digest(a_bytes, b_bytes)


#: A configured name :func:`cert_name_candidates` can actually yield: ``CN:<value>`` or
#: ``SAN:<type>:<value>``, each part non-empty. Anything else loads and then never matches (#2237).
#: Shared by ``[api].tls_client_cert_identities`` and ``Http``'s ``intake_client_subjects`` (#2287).
#: It checks shape only; ``MLLP``'s ``tls_client_subjects`` also applies :func:`unmatchable_san_reason`.
QUALIFIED_CERT_NAME = re.compile(r"CN:.+|SAN:[^:]+:.+", re.DOTALL)

#: The ``subjectAltName`` types ``ssl.getpeercert()`` reports a real value for, spelled as it spells
#: them (CPython ``_ssl.c``, ``_get_peer_alt_names``). A ``SAN:<type>:`` with any other type, or the
#: same type in another case, is never yielded by :func:`cert_name_candidates` (BACKLOG #4907).
SAN_TYPES = ("DNS", "email", "URI", "IP Address", "Registered ID", "DirName", "othername")

#: The types ``ssl`` reports only as a placeholder: it hands x400Address and ediPartyName to OpenSSL's
#: ``GENERAL_NAME_print``, which writes ``X400Name:<unsupported>`` and ``EdiPartyName:<unsupported>``
#: whatever the name holds.
_PLACEHOLDER_ONLY_SAN_TYPES = frozenset({"X400Name", "EdiPartyName"})

#: The text ``ssl`` reports in place of a SAN it cannot render: ``<unsupported>`` for an otherName of a
#: type OpenSSL does not print, or whose value has the wrong ASN.1 type, and ``<invalid>`` for an
#: iPAddress of neither 4 nor 16 bytes. Measured on CPython 3.14.7 with OpenSSL 3.5.7 by decoding
#: certificates carrying each form. One such text stands for a whole class of names, so a listed
#: placeholder would admit every certificate carrying any name of that class (BACKLOG #4907).
_SAN_PLACEHOLDERS = ("<unsupported>", "<invalid>")

#: The SAN types CPython's ``_ssl.c`` copies or formats whole. Every other type, ``othername`` and
#: ``Registered ID`` among them, is printed by OpenSSL's ``GENERAL_NAME_print`` and read back with one
#: ``BIO_gets`` into a 2048-byte buffer, so ``ssl`` keeps at most :data:`_PRINTED_SAN_LINE_BYTES`
#: bytes of ``<type>:<value>`` and stops after the first newline. Measured on CPython 3.14.7 with
#: OpenSSL 3.5.7: a UPN ``al<LF>ce`` is reported ``UPN:al<LF>``, and a 2100-character UPN as 2036
#: characters of value. Such a value may be the first part of a longer name, so it stands for every
#: name that starts the same way, as a placeholder stands for a class (BACKLOG #4907).
_WHOLE_SAN_TYPES = frozenset({"DNS", "email", "URI", "IP Address", "DirName"})
_PRINTED_SAN_LINE_BYTES = 2046

#: Other spellings of a ``SAN_TYPES`` entry, folded, mapped to the one ``ssl`` writes, so a refusal
#: can name the right spelling: RFC 5280's names, and the short forms an operator might reach for.
_SAN_TYPE_SPELLINGS = {
    **{t.lower().replace(" ", ""): t for t in SAN_TYPES},
    "ip": "IP Address",
    "rid": "Registered ID",
    "dnsname": "DNS",
    "rfc822name": "email",
    "uniformresourceidentifier": "URI",
    "directoryname": "DirName",
}


def _is_placeholder_san(san_type: str, value: str) -> bool:
    """Whether ``SAN:<san_type>:<value>`` is text ``ssl`` reports in place of a name it cannot
    render. Fail-closed: a real name carrying the marker text is dropped too, and can only be
    refused, never admitted, by that."""
    return san_type in _PLACEHOLDER_ONLY_SAN_TYPES or any(p in value for p in _SAN_PLACEHOLDERS)


def _is_cut_short_san(san_type: str, value: str) -> bool:
    """Whether ``ssl`` may have cut ``SAN:<san_type>:<value>`` short (:data:`_WHOLE_SAN_TYPES`): it
    ends in a newline or fills the line ``ssl`` reads. Fail-closed, as :func:`_is_placeholder_san`:
    a whole name that happens to fill the line exactly is dropped too."""
    if san_type in _WHOLE_SAN_TYPES:
        return False
    line = f"{san_type}:{value}".encode("utf-8", "surrogatepass")
    return value.endswith("\n") or len(line) >= _PRINTED_SAN_LINE_BYTES


def _is_dirname_text(value: str) -> bool:
    """Whether ``value`` is a DirName as ``ssl`` reports it: a Python tuple of RDNs, rendered with
    ``repr``, such as ``((('commonName', 'x'),),)``."""
    try:
        parsed = ast.literal_eval(value)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False
    return isinstance(parsed, tuple) and repr(parsed) == value


def _ssl_ip_text(value: str) -> str | None:
    """``value`` as ``ssl`` writes an iPAddress SAN, or ``None`` when it is not an address.

    ``_ssl.c`` formats the raw bytes itself: IPv4 dotted, IPv6 as eight upper-case hex groups with
    no leading zeros and no ``::`` compression, so ``2001:db8::1`` is reported ``2001:DB8:0:0:0:0:0:1``."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version == 4:
        return str(address)
    packed = address.packed
    return ":".join(f"{(packed[i] << 8) | packed[i + 1]:X}" for i in range(0, 16, 2))


def unmatchable_san_reason(name: str) -> str | None:
    """Why :func:`cert_name_candidates` can never yield the ``SAN:`` name ``name``, or ``None``.

    ``None`` for any name that is not ``SAN:<type>:<value>``: :data:`QUALIFIED_CERT_NAME` checks
    shape. This refuses, at least, a type ``ssl`` never reports, including one of
    :data:`SAN_TYPES` in another case; a placeholder ``ssl`` reports for a name it cannot render; a
    value ``ssl`` may have cut short; an IP address in a spelling ``ssl`` never writes; a DirName
    that is not the tuple ``ssl`` reports; and an otherName with no ``<form>:`` before its value. It
    does not check any other value against what a certificate can hold. The reason quotes nothing the operator wrote, only ``ssl``'s own
    spellings, so it can go into an error message as it is."""
    if not name.startswith("SAN:") or name.count(":") < 2:
        return None
    _, san_type, value = name.split(":", 2)
    folded = san_type.lower().replace(" ", "")
    if _is_placeholder_san(san_type, value) or folded in {
        t.lower() for t in _PLACEHOLDER_ONLY_SAN_TYPES
    }:
        return (
            "a placeholder, such as 'SAN:othername:<unsupported>', that ssl reports in place of a "
            "name it cannot render. X400Name and EdiPartyName are only ever reported that way. "
            "Every certificate carrying such a name presents the same text, so it names no one "
            "sender, and a placeholder is never matched"
        )
    if _is_cut_short_san(san_type, value):
        return (
            "a value ssl may have cut short: it keeps at most 2046 bytes of an othername or "
            "Registered ID line and stops after a newline, so such an entry would match every "
            "name that starts the same way"
        )
    if san_type not in SAN_TYPES:
        spelling = _SAN_TYPE_SPELLINGS.get(folded)
        if spelling is not None:
            return f"a SAN type ssl never reports in that spelling; ssl writes it {spelling!r}"
        return "a SAN type ssl never reports; it reports " + ", ".join(repr(t) for t in SAN_TYPES)
    if san_type == "IP Address" and _ssl_ip_text(value) != value:
        return (
            "an IP address in a spelling ssl never writes: IPv4 dotted, and IPv6 as eight "
            "upper-case hex groups with no leading zeros and no '::'"
        )
    if san_type == "DirName" and not _is_dirname_text(value):
        return (
            "a DirName in a form ssl never reports: it reports the name as a Python tuple of "
            "RDNs, such as ((('commonName', 'feed.example'),),)"
        )
    if san_type == "othername" and (":" not in value or not value.split(":", 1)[0]):
        return (
            "an othername in a form ssl never reports: it reports '<form>:<value>', such as "
            "'UPN:feed@partner.example'"
        )
    return None


def cert_name_candidates(peercert: Mapping[str, Any]) -> list[str]:
    """The qualified subject/SAN names of a ``ssl.getpeercert()`` dict, in match order (#200).

    Yields ``"CN:<commonName>"`` for each subject commonName RDN and ``"SAN:<type>:<value>"`` for each
    subjectAltName entry (e.g. ``"SAN:DNS:svc.internal"``). These are the exact keys an operator lists
    under an issuer in ``[api].tls_client_cert_identities`` — qualifying the name space (CN vs SAN,
    SAN type) means a spoofed commonName can never collide with a pinned DNS SAN.

    A SAN ``ssl`` reports only as a placeholder (:data:`_SAN_PLACEHOLDERS`, such as
    ``othername:<unsupported>``), or may have cut short (:data:`_WHOLE_SAN_TYPES`), is left out, so
    no listed entry can match it (BACKLOG #4907). Such text stands for a whole class of names, so
    matching it would admit every certificate carrying any of them. Every caller shares this, the operator API and the HTTP listener included."""
    candidates: list[str] = []
    for rdn in peercert.get(
        "subject", ()
    ):  # subject = tuple of RDNs; each RDN = tuple of (attr, value)
        for pair in rdn:
            if len(pair) == 2 and pair[0] == "commonName":
                candidates.append(f"CN:{pair[1]}")
    for pair in peercert.get("subjectAltName", ()):
        if len(pair) == 2:
            san_type, value = f"{pair[0]}", f"{pair[1]}"
            if not _is_placeholder_san(san_type, value) and not _is_cut_short_san(san_type, value):
                candidates.append(f"SAN:{san_type}:{value}")
    return candidates


def client_cert_principal(
    peercert: Mapping[str, Any] | None, cert_map: Mapping[str, str]
) -> str | None:
    """The value a verified peer cert's subject maps to, or ``None`` (deny-by-default) (#200).

    Pure: given a ``ssl.getpeercert()`` dict (only ever populated by ``ssl`` AFTER the chain verified)
    and a flat allow-list keyed by qualified name, return the value of the first subject/SAN candidate
    present in the map. An empty/absent cert, an empty map, or a subject with no listed name all
    return ``None`` — an unmapped or spoofed-CN cert resolves to nothing.

    **Issuer-blind by design**, so no production caller calls it directly: the operator API and the
    inbound HTTP listener's ``intake_client_subjects`` both go through
    :func:`client_cert_principal_under_issuer`, which picks the flat map for the cert's own issuer
    first (BACKLOG #2237, #2287)."""
    if not peercert or not cert_map:
        return None
    for candidate in cert_name_candidates(peercert):
        principal = cert_map.get(candidate)
        if principal:
            return principal
    return None


# --- The verified issuer (BACKLOG #2237) -----------------------------------------------------------
#
# The operator API's cert map is keyed by the issuing CA first, so a subject is only ever trusted under
# the CA the operator named for it. With several CAs in [api].tls_client_ca_file, two of them can issue
# the same subject; without the issuer in the key both certificates reached the one account.
#
# The issuer is NOT read from the leaf's own issuer field. The issuing CA writes that field, and
# OpenSSL builds the chain by a loose name compare (case-folded, whitespace collapsed), so a second
# trusted CA named "CN=ACME   CA" can sign a leaf whose issuer field reads "CN=Acme CA" and it still
# verifies. The api shim instead finds the loaded CA whose key ACTUALLY signed the leaf and records
# its subject under VERIFIED_ISSUER_KEY (see api/tls_client_cert.py and pki.IssuerIndex). The inbound
# HTTP listener does the same for intake_client_subjects (BACKLOG #2287, transports/http_listener.py).
# This leaf only reads that string, so it stays stdlib-only.

#: The key the api shim and the inbound HTTP listener add to a copy of the ``getpeercert()`` dict,
#: holding the canonical RFC 4514 subject of the loaded CA certificate whose key directly signed the
#: leaf, or ``""`` when none qualifies. ``ssl`` never produces this key, and each overwrites it on
#: every connection, so a peer cannot supply it.
VERIFIED_ISSUER_KEY = "mf_verified_issuer"


def client_cert_principal_under_issuer(
    peercert: Mapping[str, Any] | None, issuer_map: Mapping[str, Mapping[str, str]]
) -> str | None:
    """The value a verified peer cert maps to UNDER ITS VERIFIED ISSUER, or ``None`` (deny-by-default).

    ``issuer_map`` is ``[api].tls_client_cert_identities``: canonical issuer DN -> a flat map of
    qualified subject names. Only the flat map for the cert's own verified issuer
    (:data:`VERIFIED_ISSUER_KEY`) is consulted, so the same subject from a different CA in the same
    trust bundle maps to nothing (BACKLOG #2237). A cert with no verified issuer, or an issuer not in
    the map, resolves to nothing."""
    if not peercert or not issuer_map:
        return None
    issuer = peercert.get(VERIFIED_ISSUER_KEY)
    if not isinstance(issuer, str) or not issuer:
        return None
    names = issuer_map.get(issuer)
    if not names:
        return None
    return client_cert_principal(peercert, names)
