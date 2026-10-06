# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Operator-supplied trust-anchor integrity (ASVS 6.7.1, BACKLOG #285).

With OIDC and/or AD federation enabled the engine holds operator-supplied CA anchors on the LIVE
authentication path:

* ``[auth].oidc_tls_ca_cert_file`` — trusts the OIDC IdP legs (token endpoint + JWKS); loaded into the
  one opener both legs share (:func:`messagefoundry.auth.oidc_http.build_idp_opener`). Substituting this
  PEM permits JWKS substitution and forged id_tokens.
* ``[auth].ad_tls_ca_cert_file`` — trusts the AD LDAPS bind (:mod:`messagefoundry.auth.ldap`).
  Substituting this PEM permits an LDAPS MITM. ``LdapAuthenticator`` checks it at construction and
  hands ``ldap3`` the checked bytes (BACKLOG #2034), and the central preflight below checks it again at
  start and at every reload.
* ``[api].tls_client_ca_file`` — the in-process mTLS console client-CA (:mod:`messagefoundry.api.tls`),
  which maps a verified peer cert to a principal with no bearer token. Substituting it admits a forged
  client cert.

The engine previously applied **no** integrity control to any of these. This module adds the
controls below, and is **dormant when no anchor is configured** — zero anchors set means
byte-identical behaviour (no preflight runs, no audit rows, no new settings effects):

1. A **read-only ACL preflight**: a group-/world-**writable** anchor (anyone who can write the file can
   substitute the CA and defeat authentication) is **refused** at ``[security].enforcement = enforce``
   and **warned + audited** at ``warn``. It reuses ``_secure_file``'s ``icacls`` DACL mechanism as a
   *verify-only* companion — it inspects the DACL and never changes it. Readability is deliberately not
   the threat (a CA certificate is public); tamperability is. The verdict is **tri-state**: a DACL the
   engine could not read is ``acl_indeterminate``, audited, and never reported as owner-only (BACKLOG
   #1142). Item 6 says when it refuses.
2. An **optional SHA-256 fingerprint pin** per anchor. A configured pin that the PEM's SHA-256 does not
   match **refuses** — always, independent of the enforcement dial — at construction and at reload.
3. An **anchor-changed audit event**: when a configured anchor's SHA-256 differs from the previously
   observed load's, a first-class ``auth.trust_anchor`` audit row is written (reusing
   :meth:`~messagefoundry.store.base.Store.record_audit`, mirroring the ``config_reload`` fingerprint row).
4. A **path check** (BACKLOG #1142, the directory arm): every object from the volume root down to the
   anchor, links included, read in-process by SID on Windows and by ``lstat`` on POSIX
   (:mod:`messagefoundry.auth.anchor_path`). A directory that lets an untrusted principal delete or
   rename an entry lets it replace the anchor without any right on the file itself. ``path_ok`` is
   ``False`` then, and it refuses at ``enforce`` and warns at ``warn``, as ``acl_ok`` does. A chain
   that could not be read is ``path_indeterminate`` and audited; item 6 says when it refuses. The file
   arm (1) still runs beside it, so the combined verdict is never weaker than the file arm alone.
5. **The checked bytes are the loaded bytes** (BACKLOG #1142, slice 2). :func:`evaluate_anchor` reads
   the file once and keeps the bytes it hashed. :func:`verified_anchor_cadata` hands those bytes to the
   TLS context as ``cadata=``, so no consumer that builds a context opens the file a second time.
   Before this, a file swapped between the check and the load was trusted unchecked. The AD anchor
   joined in BACKLOG #2034: ``ldap3`` used to read it by path on every bind, and now gets the checked
   bytes as ``ca_certs_data``. **Not covered:** the audit row of the central preflight, which records
   its own read rather than the consumer's.
6. **An indeterminate read refuses at ``enforce``, and a matching pin is the escape** (BACKLOG #1142,
   slice 3). When the ACL or the path could not be settled, the engine cannot say who else can
   replace the anchor, so ``enforce`` refuses to load it. A configured SHA-256 pin that matches the
   bytes read lets it load anyway, with a warning and the audit row: since item 5 those bytes are the
   bytes the context loads, so the pin already defeats a substitution. ``warn`` warns and loads.
   The refusal names both fixes: move the anchor, or set the pin.
7. **The per-connection inbound CAs** (BACKLOG #1142, slice 3). Every inbound connection whose server
   context requires a peer certificate (``tls`` and ``tls_ca_file`` set: MLLP, the HTTP listener and
   the DICOM SCP) gets the same checks. The connector loads its CA through
   :func:`inbound_ca_cadata` when it builds its context, and :func:`registry_anchor_specs` feeds the
   audited preflight each time a graph is loaded.
8. **A changed settings anchor takes a restart, and a reload says so** (BACKLOG #2185). The three
   settings anchors above are loaded once, when their consumer is built, and no reload rebuilds
   one. A reload still re-checks each file. :func:`verified_anchor_cadata` records the fingerprint
   of the bytes it hands each consumer. When the bytes on disk differ from those, the settings
   preflight logs a WARNING and audits a ``restart_required`` row. It does so on every reload whose
   anchor check passes, until the engine restarts. Item 3's ``changed`` row cannot do this job. It
   compares with the last AUDITED fingerprint, so it goes quiet after one reload while the
   consumers still trust the start-time bytes.
9. **The per-connection outbound CAs** (vault BACKLOG #2371). A connection that dials out reads its
   ``tls_ca_file`` to verify the server: every outbound that takes the key, and a ``FhirLookup``.
   :func:`registry_anchor_specs` hands each one to the same preflight, at the first load and at
   every reload, under the label ``outbound:<name>`` or ``fhir_lookup:<name>``. So the ACL and
   path checks, the optional ``tls_ca_pin`` and the change audit all apply, on the inbound dial:
   a pin mismatch always refuses, and an exposed or unjudged CA refuses at ``enforce``.
   **Not covered: the checked bytes are not the loaded bytes here.** These consumers still build
   their context from the path, with ``cafile=``, after the preflight passes. So a file swapped
   between the preflight and the build would be trusted unchecked until the next reload re-checks
   it. For that reason the spec carries ``loads_verified_bytes=False``: a matching pin is NOT the
   item 6 escape for an unjudged outbound CA, and the PEM shape checks are skipped, since
   ``cafile=`` loads what ``cadata=`` refuses. Item 5 closed the same gap for the inbound CAs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shlex
import ssl
import subprocess  # nosec B404 — used only to read a DACL via icacls (fixed tool, no shell)
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from messagefoundry.auth.anchor_path import (
    LINK,
    ChainFinding,
    PathVerdict,
    anchor_path_verdict,
)
from messagefoundry.connection_names import fhir_lookup_record_name, inbound_record_name
from messagefoundry.service_status import _system_exe

if TYPE_CHECKING:
    from messagefoundry.config.settings import ApiSettings, AuthSettings
    from messagefoundry.config.wiring import Registry
    from messagefoundry.store.base import Store

log = logging.getLogger(__name__)

#: The audit action for every trust-anchor observation. One action so an operator can filter the whole
#: family, and so :func:`_last_fingerprint` can find the prior load. The ``event`` field in the detail
#: carries which one: ``observed`` (baseline), ``changed``, ``pin_mismatch``, ``acl_insecure``,
#: ``acl_indeterminate`` (the ACL could not be determined, BACKLOG #1142), ``path_insecure`` and
#: ``path_indeterminate`` (the path check, BACKLOG #1142 directory arm), and ``pem_refused`` (the
#: file is not text the TLS library loads as trust anchors: no PEM block or a TRUSTED CERTIFICATE
#: block since BACKLOG #1142 slice 3, and anything its ``cadata=`` load refuses since #2025), and
#: ``restart_required`` (a reload found a settings anchor whose bytes differ from the ones its
#: consumer loaded, BACKLOG #2185).
AUDIT_ACTION = "auth.trust_anchor"


class TrustAnchorError(Exception):
    """An operator-supplied trust anchor failed its integrity preflight: a configured SHA-256 pin
    mismatch, a file that holds no loadable PEM block, or, under ``[security].enforcement = enforce``,
    an ACL or path that lets another principal replace it or that could not be read. Raised at
    construction and at reload so the engine refuses a tampered/exposed anchor rather than silently
    trusting it."""


@dataclass(frozen=True)
class AnchorSpec:
    """One operator-supplied trust anchor to preflight.

    ``label`` is the stable, PHI-free audit key (``"oidc"`` / ``"ad"`` / ``"api_client"`` /
    ``"inbound:<connection>"`` / ``"outbound:<connection>"`` / ``"fhir_lookup:<name>"``); ``setting`` is the human-facing config key for messages; ``path`` is
    the configured PEM; ``pin`` is the optional configured SHA-256 pin (any case, optional ``:``
    separators); ``pin_setting`` names where that pin is set, so a refusal can name the escape.

    Every consumer loads the bytes the check read (slice 2's ``cadata=``), never the file again. That
    is what lets a matching pin stand in for an unreadable ACL or path, and why every anchor takes
    the PEM shape checks of :func:`anchor_cadata`. The AD anchor was the one exception, read by path
    on every bind, until BACKLOG #2034.

    ``loads_verified_bytes`` is ``False`` for an anchor whose consumer reads the file again by path:
    the outbound and ``FhirLookup`` CAs since vault BACKLOG #2371 (item 9 of the module text). It
    restores the switch the AD anchor had before #2034. A pin cannot stand in for an unreadable ACL
    or path there, and the PEM shape checks (:func:`anchor_cadata`) do not apply, because
    ``cafile=`` reads what ``cadata=`` refuses."""

    label: str
    setting: str
    path: str
    pin: str | None = None
    pin_setting: str | None = None
    loads_verified_bytes: bool = True


@dataclass(frozen=True)
class AnchorVerdict:
    """The pure result of inspecting an anchor file (no enforcement, no I/O side effects)."""

    fingerprint: str
    acl_ok: bool | None  # None = the DACL could not be determined (refuses at enforce, unpinned)
    pin_ok: bool | None  # None = no pin configured
    # False = another principal can replace the anchor through its path; None = could not tell.
    path_ok: bool | None = None
    path_check: PathVerdict | None = None  # the findings behind path_ok, for messages and audit
    # The exact bytes ``fingerprint`` was computed over. A consumer loads THESE, never the file again
    # (BACKLOG #1142, slice 2). Kept out of repr and equality: a verdict is compared by what it found.
    data: bytes = field(default=b"", repr=False, compare=False)


# --- fingerprint --------------------------------------------------------------------------------


def anchor_fingerprint(path: str | os.PathLike[str]) -> str:
    """Lowercase-hex SHA-256 of the anchor PEM's bytes.

    A missing/unreadable anchor raises the underlying :class:`OSError` — the engine already refuses to
    start on a missing/unreadable CA (``build_idp_opener`` / ``load_verify_locations`` do), and this
    preserves that fail-closed contract rather than masking it as a softer error."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --- the verified bytes as the text a TLS context loads (BACKLOG #1142, slice 2) -----------------

_UTF8_BOM = b"\xef\xbb\xbf"
_PEM_BEGIN = b"-----BEGIN "
_PEM_END = b"-----END "
_PEM_TRUSTED = b"-----BEGIN TRUSTED CERTIFICATE-----"
#: The RFC 1421 headers of an encrypted PEM block, lower-cased (BACKLOG #2270, :func:`anchor_cadata`).
_PEM_ENCRYPTION_HEADERS = ("proc-type:", "dek-info:")
#: The source-location tail CPython appends to an ``ssl.SSLError`` message, dropped from a refusal.
_SSL_WHERE = re.compile(r"\s*\(_ssl\.c:\d+\)$")


def _has_encryption_header(text: str) -> bool:
    """Whether an RFC 1421 encryption header name appears anywhere after the first ``-----BEGIN ``
    in ``text``, the exact text the TLS load is handed (BACKLOG #2270).

    It models no block structure, on purpose. OpenSSL finds a BEGIN in 254-byte pieces of a long
    line, and ends a block where its own reader says, so a line model here disagrees with it at the
    edges. A code review measured two such bypasses of an earlier line-based check, each ending in
    a ``cadata=`` load that did not return. Every header OpenSSL could act on follows a BEGIN it
    read, and that BEGIN is in the text verbatim. So this errs wide: a header name in a comment
    between two blocks refuses too. A base64 body holds no ``:``, so no certificate line matches."""
    begin = text.find("-----BEGIN ")
    if begin < 0:
        return False
    tail = text[begin:].lower()
    return any(header in tail for header in _PEM_ENCRYPTION_HEADERS)


def anchor_cadata(data: bytes, spec: AnchorSpec) -> str:
    """The verified anchor bytes as the PEM text ``SSLContext.load_verify_locations(cadata=)`` takes.

    ``cadata=`` takes ASCII text only, while ``cafile=`` reads a file with any bytes between its PEM
    blocks. Measured on CPython 3.14.6 / OpenSSL 3.5.7: a ``cafile`` with a UTF-8 comment above the
    block (a PKCS#12 export's ``friendlyName``) or a UTF-8 byte-order mark loads, and the same bytes
    as ``cadata`` raise. So this drops every non-ASCII line OUTSIDE a block, which OpenSSL skips
    anyway, and a byte-order mark exactly where ``cafile=`` drops one: on the first line of the
    file, and on the line straight after an ``-----END`` line. Measured, a mark there loads the
    block behind it (two concatenated files), and a mark after a blank or comment line hides the
    block from ``cafile=``. Stripping it anywhere else would trust a certificate ``cafile=`` never
    loaded. ``tests/test_trust_anchor_byte_binding.py`` holds the shapes against ``cafile=``.

    Every line from ``-----BEGIN`` to ``-----END`` is kept exactly. A non-ASCII byte there refuses,
    as ``cafile=`` refuses it (``PEM lib``). The text is derived from ``data`` alone and nothing here
    opens a file, which is the point.

    **No PEM block refuses.** ``create_default_context`` tests ``cadata`` for truth, so an empty
    string loads the WHOLE OS trust store: measured, 87 anchors on one Windows host. ``cafile=``
    refused an empty file, and so does this, before an empty string can reach a context.

    **A ``TRUSTED CERTIFICATE`` block refuses.** ``cafile=`` reads one with its OpenSSL trust
    settings, and ``cadata=`` skips it without a word: measured, the lone block raises ``no start
    line``, and beside a plain block it would be dropped silently. Rewriting it as a plain block
    would drop a ``reject`` setting and so widen trust. ``openssl x509 -in <one cert> -out
    <plain.pem>`` writes a plain ``CERTIFICATE`` block, one certificate per run.

    **Text the TLS library will not load refuses here** (BACKLOG #2025). The central preflight runs
    this and builds no context of its own to verify a peer with, so before this a reload passed a
    file that only the consumer's ``load_verify_locations(cadata=)`` refused, at the next start. The
    case the item names is a CRL in the CA slot: ``cadata=`` skips every block that is not a
    certificate, and with none left it raises ``no start line: cadata does not contain a
    certificate``. Matching PEM labels here would re-implement OpenSSL's parser and disagree with it
    at the edges, such as a damaged block beside a good one, a certificate block with a bad body, or
    a control byte after a BEGIN line. So this loads the exact text into a throwaway context, and
    the verdict is OpenSSL's own. Measured on CPython 3.14.6 / OpenSSL 3.5.7: a lone ``X509 CRL``
    block refuses, and a well-formed CRL beside a certificate, in either order, loads the one
    certificate and no CRL, so that file still passes. The throwaway context is discarded. It checks
    that the text loads, not that a certificate in it is a CA; a leaf still loads here.

    **An encryption header inside a block refuses, before that load** (BACKLOG #2270). A
    ``Proc-Type: 4,ENCRYPTED`` header sends OpenSSL to its password callback, and ``cadata=`` sets
    none, so OpenSSL falls back to its default one, which reads the terminal. The POSIX TTY run the
    row asked for was NOT done: the box this was built on is Windows. What was measured there, on
    CPython 3.14.6 / OpenSSL 3.5.7 in a child process with stdin on the null device: the
    ``cadata=`` load of a certificate block carrying ``Proc-Type: 4,ENCRYPTED`` and ``DEK-Info:``
    did not return within 20 seconds and was killed, while ``cafile=`` on the same bytes refused at
    once with ``PEM lib``. So a start or a reload could hang on this file. A CA certificate never
    carries an RFC 1421 encryption header, so ``Proc-Type:`` and ``DEK-Info:`` both refuse, in any
    case, anywhere after the first BEGIN of the text the load would get, and OpenSSL is never
    handed that text (:func:`_has_encryption_header`). That is wider than the hang: an encrypted
    private-key block beside a certificate loads through ``cadata=``, and refuses here, because a
    trust anchor has no use for a key, and so does the header name in a comment between two
    blocks. The same header in a comment above the first block still passes."""
    kept: list[bytes] = []

    inside = False
    blocks = 0
    fresh = True  # the first line, or the line after an END line: where OpenSSL drops a BOM
    for raw in data.splitlines(keepends=True):
        line = raw[len(_UTF8_BOM) :] if fresh and raw.startswith(_UTF8_BOM) else raw
        fresh = False
        if line.startswith(_PEM_TRUSTED):
            raise TrustAnchorError(
                f"{spec.setting}: the trust anchor {spec.path!r} holds an OpenSSL trusted-certificate block, "
                "which the engine does not load. Re-export each certificate in it as a plain "
                "CERTIFICATE block; openssl x509 -in <one cert> -out <plain.pem> converts one "
                "certificate per run"
            )
        if line.startswith(_PEM_BEGIN):
            inside = True
            blocks += 1
        if inside or line.isascii():
            kept.append(line)
        if line.startswith(_PEM_END):
            inside = False
            fresh = True
    if not blocks:
        raise TrustAnchorError(
            f"{spec.setting}: the trust anchor {spec.path!r} holds no PEM block, so it names no "
            "certificate to trust"
        )
    try:
        text = b"".join(kept).decode("ascii")
    except UnicodeDecodeError as exc:
        raise TrustAnchorError(
            f"{spec.setting}: the trust anchor {spec.path!r} has a non-ASCII byte inside a PEM "
            "block, so it is not a readable certificate"
        ) from exc
    if _has_encryption_header(text):
        raise TrustAnchorError(
            f"{spec.setting}: the trust anchor {spec.path!r} holds a PEM block with an encryption "
            "header (Proc-Type or DEK-Info), such as an encrypted certificate or private key. A "
            "trust anchor needs only plain CERTIFICATE blocks, and loading an encrypted one can make "
            "the TLS library wait for a password. Remove the encrypted block, or export the CA "
            "certificate as a plain CERTIFICATE block"
        )
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=text)
    except ssl.SSLError as exc:
        why = _SSL_WHERE.sub("", str(exc))
        raise TrustAnchorError(
            f"{spec.setting}: the TLS library cannot load the trust anchor {spec.path!r} ({why}). "
            "Every PEM block in it must be well-formed, and at least one must be a plain "
            "CERTIFICATE block. A file holding only a CRL names no certificate to trust; a hop "
            "that checks revocation reads its CRL from its own CRL setting"
        ) from exc
    return text


def _normalize_pin(pin: str) -> str:
    """A configured pin normalized to 64 lowercase hex chars. Accepts optional ``:`` separators and any
    case. Raises :class:`TrustAnchorError` on a malformed pin (fail loud, never silently never-match)."""
    cleaned = pin.strip().lower().replace(":", "")
    if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
        raise TrustAnchorError(
            "a trust-anchor pin must be a SHA-256 hex digest (64 hex chars, optional ':'); "
            f"got {pin!r}"
        )
    return cleaned


# --- read-only DACL inspection (mirrors _secure_file's icacls mechanism, verify-only) -----------

#: Group/world principals whose members are not the file owner — a WRITE grant to any of them means a
#: non-owner can substitute the anchor. SYSTEM and Administrators are deliberately absent: they are
#: already trusted (they can rewrite any file regardless).
#:
#: The English display names, in two sets, both matched WHOLE rather than as substrings. A substring
#: match read an ordinary account such as ``DESKTOP-A\usersync`` as ``\Users``, and a false "broad"
#: refuses a secure anchor under enforce. This half is **at least** these and can never be complete:
#: ``icacls`` resolves a SID to its *localized* name by default, so a German ``Jeder`` or a Spanish
#: ``Todos`` is Everyone under a name this set does not carry. The SID half below is the
#: locale-invariant matcher; this one is a convenience for the host that speaks English.
#:
#: Whole principal tokens. ``NT AUTHORITY\`` stays on the pseudo-groups so an account named
#: ``DOMAIN\Service`` is not read as ``NT AUTHORITY\SERVICE``, and ``Local account`` is whole so
#: ``Local account and member of Administrators group`` (trusted, as Administrators) is not caught.
_BROAD_PRINCIPAL_NAMES: frozenset[str] = frozenset(
    {
        "everyone",
        "nt authority\\authenticated users",
        "nt authority\\interactive",
        "nt authority\\service",
        "nt authority\\batch",
        "nt authority\\network",
        "nt authority\\anonymous logon",
        "nt authority\\local account",
    }
)

#: Group names matched whole against the part after the LAST ``\`` of the token, under any qualifier:
#: ``BUILTIN\Users``, ``DOMAIN\Users`` and ``DOMAIN\Domain Users`` all match.
_BROAD_GROUP_LEAF_NAMES: frozenset[str] = frozenset(
    {"users", "domain users", "guests", "domain guests", "authenticated users"}
)

#: The locale-invariant half: well-known SIDs, matched **whole** against the principal token, with or
#: without a leading ``*`` (plain ``icacls`` printed an unresolvable SID with none, measured on
#: Windows 11). Whole-token matching is load-bearing rather than tidiness: as substrings,
#: ``S-1-5-3`` (BATCH) is a prefix of ``S-1-5-32-544`` (``BUILTIN\Administrators``, deliberately
#: trusted) and ``S-1-5-11`` (Authenticated Users) of ``S-1-5-114`` (local administrators), so a
#: substring set would report the administrators ACE that sits on every ordinary Windows file as a
#: broad-principal write.
_BROAD_PRINCIPAL_SIDS: frozenset[str] = frozenset(
    {
        "s-1-1-0",  # Everyone
        "s-1-5-11",  # Authenticated Users
        "s-1-5-32-545",  # BUILTIN\Users
        "s-1-5-32-546",  # BUILTIN\Guests
        "s-1-5-2",  # NT AUTHORITY\NETWORK
        "s-1-5-3",  # NT AUTHORITY\BATCH
        "s-1-5-4",  # NT AUTHORITY\INTERACTIVE
        "s-1-5-6",  # NT AUTHORITY\SERVICE
        "s-1-5-7",  # NT AUTHORITY\ANONYMOUS LOGON
        "s-1-5-113",  # NT AUTHORITY\Local account (every local user)
    }
)

#: Domain-relative RIDs that are broad in every domain: an unresolved ``S-1-5-21-<domain>-<rid>``.
_BROAD_DOMAIN_RIDS: frozenset[str] = frozenset({"513", "514"})  # Domain Users, Domain Guests

# INTERACTIVE, SERVICE and BATCH are broad here, as ``_evaluate_config_dacl``
# (``messagefoundry/config/wiring.py``) also refuses them. Commit 0adde6059 measured why on
# Windows 11: ``icacls C:\Users\Public`` lists ``NT AUTHORITY\INTERACTIVE:(OI)(CI)(IO)(M,DC)`` and
# the same for SERVICE and BATCH, which object-inherit propagates as ``(I)(M)`` onto every file
# created there. An anchor placed in that directory is modifiable by every interactive logon, and
# before BACKLOG #1142 it read as owner-only.
#
# CREATOR OWNER and OWNER RIGHTS are NOT broad, matching wiring.py's trusted set. OWNER RIGHTS
# (S-1-3-4) carries the current owner's rights. CREATOR OWNER (S-1-3-0) is a placeholder that no
# logon token ever carries, so an ACE for it on a file grants nobody anything.

#: icacls right tokens that permit modifying or replacing the file (simple + specific write masks).
#: DELETE (``D``/``DE``) is here because deleting an anchor and planting a new one replaces it, and
#: wiring.py's write mask counts DELETE too.
_WRITE_RIGHTS: frozenset[str] = frozenset(
    {"F", "M", "W", "D", "DE", "WD", "AD", "WEA", "WA", "WO", "WDAC", "GA", "GW"}
)


def _is_broad_sid(token: str) -> bool:
    """Whether a lowercased token is a broad SID, matched whole, with or without a leading ``*``."""
    sid = token.lstrip("*")
    if sid in _BROAD_PRINCIPAL_SIDS:
        return True
    return sid.startswith("s-1-5-21-") and sid.rsplit("-", 1)[-1] in _BROAD_DOMAIN_RIDS


def _is_broad_principal(principal: str) -> bool:
    """Whether an already-lowercased icacls principal token names an identity broader than the file's
    owner. Every match is whole: the SID after any leading ``*``, the display name as a whole token,
    or a group name as the part after the last ``\\``."""
    if _is_broad_sid(principal) or principal in _BROAD_PRINCIPAL_NAMES:
        return True
    return principal.rsplit("\\", 1)[-1] in _BROAD_GROUP_LEAF_NAMES


def _ends_in_broad_principal(text: str) -> bool:
    """Whether lowercased line-1 text, path echo and all, ENDS in a broad principal.

    The parser uses this on line 1 whenever the path echo was not verbatim, so it cannot be sure
    where the principal starts. The principal always comes last, after whitespace, so a broad one
    is a whole-word suffix: a SID as the last word, a display name after a space, or a group leaf
    after the last ``\\``. This keeps a line-1 broad grant visible whatever the echo looked like.

    It errs toward broad on purpose. It cannot tell ``<path> Everyone`` from ``<path> CORP\\Not
    Everyone``, and a missed broad grant is the failure to avoid. The leaf is taken after the last
    ``\\`` only, never after the last space, so ``CORP\\Power Users`` does not read as ``Users``."""
    flat = " ".join(text.split())
    if flat and _is_broad_sid(flat.rsplit(" ", 1)[-1]):
        return True
    if any(flat == name or flat.endswith(" " + name) for name in _BROAD_PRINCIPAL_NAMES):
        return True
    return flat.rsplit("\\", 1)[-1] in _BROAD_GROUP_LEAF_NAMES


def _echoed_path_pattern(anchor_path: str) -> re.Pattern[str]:
    """A fixed-width pattern for the path as ``icacls`` echoes it at the start of line 1.

    icacls writes the OEM code page, so a character outside it does not come back as itself.
    Measured on Windows 11 (OEM 437): two CJK characters echoed as ``??``, an emoji as ``??``, and
    ``l-stroke`` as a best-fit ``l``. So an ASCII character must match itself, ignoring case, and any
    other character matches one character of any kind: two outside the BMP, which icacls counts as
    two UTF-16 units. Every width in the path part is fixed. Whitespace or the end of the line must
    follow the path, and that trailing ``\\s+`` is the one repetition: nothing follows it, so a
    failed ``.match`` has nothing to backtrack into.

    The template is written inside the ``re.compile`` call on purpose: the ReDoS blind-spot pin in
    ``tests/test_security_static.py`` records the argument's source text, so an edit to how each
    character is rendered reds that pin rather than hiding behind a local name."""
    return re.compile(
        "".join(
            re.escape(ch) if ch.isascii() else (".." if ord(ch) > 0xFFFF else ".")
            for ch in anchor_path
        )
        + r"(?:\s+|$)",
        re.IGNORECASE,
    )


def _continuation_indent(lines: list[str]) -> int | None:
    """The indent of the first ACE line after line 1, or ``None`` if there is none.

    icacls pads each continuation line to the width of the path it ECHOED, plus one space. Measured
    on Windows 11: a CJK, an emoji and a best-fit path each padded to the echo, not to the path
    passed. So this column is where line 1's principal starts, whatever the echo looked like."""
    seen_first = False
    for raw in lines:
        if not raw.strip():
            continue
        if not seen_first:
            seen_first = True
            continue
        if ":(" in raw:
            return (len(raw) - len(raw.lstrip())) or None
    return None


def _path_echo_end(line: str, anchor_path: str, indent: int | None) -> tuple[int, bool] | None:
    """Where the echoed path ends on line 1, and whether the echo was verbatim.

    ``None`` when the end cannot be found reliably. A verbatim echo is trusted as it stands. A
    lenient match (:func:`_echoed_path_pattern`) must agree with the continuation indent when there
    is one, because an echo narrower than the path would let the pattern run into a principal that
    contains a space, such as ``NT AUTHORITY\\INTERACTIVE``."""
    n = len(anchor_path)
    if line[:n].lower() == anchor_path.lower() and (len(line) == n or line[n].isspace()):
        return n, True
    echo = _echoed_path_pattern(anchor_path).match(line)
    if echo is None or (indent is not None and echo.end() != indent):
        return None
    return echo.end(), False


#: Bare (unqualified) principal names that are the owner, or that grant nobody anything, so a write
#: grant to them is not a non-owner write. Matched whole against the lowercased principal token.
_OWNER_BARE_NAMES: frozenset[str] = frozenset({"owner rights", "creator owner"})


def _is_bare_name(principal: str) -> bool:
    """Whether an icacls principal token is a bare display name: no ``DOMAIN\\`` qualifier and no
    SID form. The file's owner is always an account, and icacls always prints an account
    qualified (``COMPUTER\\user``, ``DOMAIN\\user``, ``AzureAD\\user``). Bare names are the
    well-known groups icacls prints unqualified, such as ``Everyone`` -- and their localized forms,
    such as the German ``Jeder``, which no name set can list in full.

    A SID is excluded with or without the leading ``*``: measured on Windows 11, plain ``icacls``
    prints an unresolvable SID bare (``S-1-5-21-...:(I)(M)``), and the well-known broad SIDs are
    already matched whole by :data:`_BROAD_PRINCIPAL_SIDS`. The names in :data:`_OWNER_BARE_NAMES`
    are excluded too. ``OWNER RIGHTS`` is the owner: measured on Windows 11, a pytest temp file
    carries ``OWNER RIGHTS:(I)(F)`` beside SYSTEM and Administrators and nothing else. Only their
    English names are listed, so a host that localizes them reads such a file as ``None``."""
    if "\\" in principal or principal.lstrip("*").startswith("s-1-"):
        return False
    return principal not in _OWNER_BARE_NAMES


def owner_only_from_icacls(text: str, *, anchor_path: str) -> bool | None:
    """Parse ``icacls <path>`` output into a **tri-state** verdict. Pure — unit-tested with synthetic
    icacls output.

    * ``True`` — at least one ACE was read and no broad group/world principal holds a write-capable
      right (owner-only-writable).
    * ``False`` — such a principal does hold one.
    * ``None`` — the DACL could **not be determined**.

    **Determined means exactly this: at least one line parsed as an ACE, i.e. a non-empty principal
    token followed by a ``:(rights)`` blob.** Empty output, a read cut off before its first ACE, a
    banner or trailer with no ACE under it, and text that is not icacls output at all therefore all
    answer ``None``. A read cut off AFTER an ACE is not detected: the only end marker is the success
    trailer, which is localized, and :func:`dacl_is_owner_only` already answers ``None`` on the
    non-zero exit a killed ``icacls`` returns. Before
    BACKLOG #1142 this returned ``bool`` and fell through to ``True``, so "no broad principal has
    write" and "I parsed nothing" were the same answer — and the second is an affirmative assertion of
    owner-only storage the parser has no basis for. ``None`` is never read as owner-only: under
    ``enforce``, :func:`_enforce_verdict` refuses the anchor unless a configured SHA-256 pin matches
    the bytes read, and under ``warn`` it warns and loads (item 6 of the module docstring).

    Broad principals are matched by locale-invariant SID and by **at least** the English display names
    in :data:`_BROAD_PRINCIPAL_NAMES`. Because ``icacls`` resolves SIDs to localized names by default,
    that name set cannot be complete across locales. So a write-capable ACE held by a **bare** name
    the set does not recognise (no ``DOMAIN\\`` qualifier and not a SID, e.g. the German ``Jeder``
    for Everyone) answers ``None``, not ``True``: the owner never prints bare, so such a principal is
    an unrecognised group and the parser has no basis to call it harmless. A localized *qualified*
    group (e.g. ``VORDEFINIERT\\Benutzer`` for ``BUILTIN\\Users``) is still not caught by name, so a
    ``True`` from a non-English host remains weaker than one from an English host. Closing that needs
    a SID-form read (the in-process DACL walk ``config/wiring.py`` already ships) and is not done here.

    The known ``anchor_path`` is stripped from line 1, and from line 1 only, so a path that
    legitimately contains ``\\Users`` (e.g. ``C:\\Users\\svc\\anchor.pem``) is never mistaken for a
    ``BUILTIN\\Users`` ACE. icacls echoes that path in the OEM code page, so where the echo is not
    verbatim it is matched leniently and checked against the continuation indent
    (:func:`_path_echo_end`). On any line 1 that is not a verbatim echo, a broad principal at the
    end of the line answers ``False``. Where the end of the echo cannot be found at all, any other
    write grant on line 1 answers ``None``, so an unmatched echo never yields ``True`` for a write.

    Lines split on ``\\n`` only. ``str.splitlines`` also splits on U+2028 and its kin, which a path
    may contain, and that would move line 1's ACE onto a line with the path still on its front."""
    lines = text.split("\n")
    indent = _continuation_indent(lines)
    saw_ace = False
    unattributed_write = False
    first_line = True
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        is_first, first_line = first_line, False
        low = line.lower()
        if low.startswith("successfully processed") or low.startswith("failed processing"):
            continue
        # Line 1 carries the path prefix; skip it so its characters can't be read as a principal.
        # Only line 1: a short relative path such as "NT" would cut the front off "NT AUTHORITY\..."
        # on a later line.
        start = 0
        echo_verbatim = True
        path_left_on = False
        if is_first:
            found = _path_echo_end(line, anchor_path, indent)
            if found is None:
                path_left_on, echo_verbatim = True, False
            else:
                start, echo_verbatim = found
        idx = line.find(":(", start)
        if idx == -1:
            continue
        principal = line[start:idx].strip().lower()
        if not principal:
            continue  # a rights blob with nothing in front of it is attributable to nobody
        rights_blob = line[idx:]
        tokens = {t.strip().upper() for t in re.split(r"[(),]", rights_blob) if t.strip()}
        # A DENY reduces access; it never grants write.
        grants_write = "(deny)" not in rights_blob.lower() and bool(tokens & _WRITE_RIGHTS)
        if grants_write and not echo_verbatim and _ends_in_broad_principal(line[:idx].lower()):
            return False  # the echo was not verbatim, so check the line's end as well as the split
        if path_left_on:
            # Nobody knows where the echo ends. This ACE counts toward nothing determined, and a
            # write in it that is not visibly broad is unattributable.
            unattributed_write = unattributed_write or grants_write
            continue
        saw_ace = True
        if not grants_write:
            continue
        if _is_broad_principal(principal):
            return False  # a broad write settles it; the rest of the DACL cannot take it back
        if _is_bare_name(principal):
            unattributed_write = True
    if not saw_ace or unattributed_write:
        return None
    return True


def dacl_is_owner_only(path: str | os.PathLike[str]) -> bool | None:
    """Whether the anchor is writable only by its owner (+ the always-trusted SYSTEM/Administrators),
    i.e. no group/world principal can modify it. READ-ONLY: it never changes the file's ACL (unlike
    ``_secure_file``, whose ``icacls`` mechanism it mirrors). ``None`` when the DACL cannot be
    determined. An inconclusive read is not a pass: under ``enforce``, :func:`_enforce_verdict`
    refuses the anchor unless a configured SHA-256 pin matches the bytes read, and under ``warn`` it
    warns and loads.

    These make it undeterminable on Windows, and all answer ``None``: ``icacls`` could not be run,
    it exited non-zero, it returned no output, or (BACKLOG #1142) the parser answered ``None``. That
    last covers three causes the warning names together: no ACE it could attribute to a principal,
    a write grant to a bare principal name it does not recognise, or a write grant on line 1 whose
    principal could not be split from the echoed path.

    * POSIX: no group- or other-WRITE bit (``mode & 0o022 == 0``).
    * Windows: read the DACL with ``icacls <path>`` (no modifying flags) and flag any broad-group ACE
      that grants a write-capable right."""
    name = os.fspath(path)  # the one string icacls or stat checks, and every log line names
    if os.name == "nt":
        try:
            # icacls is pinned to its absolute System32 path and invoked without a shell; the path is
            # a single argv token, never a shell word (matches _secure_file's low-27/STORE-5 note).
            # No modifying flags. The pin is what makes "fixed system tool" true: CreateProcess
            # resolves an unqualified name through a search path that reaches the caller's working
            # directory, and this call's OUTPUT is what decides the verdict below, so a planted
            # icacls.exe printing a clean DACL would turn a group-writable anchor into an accepted
            # one (BACKLOG #1769).
            result = subprocess.run(  # nosec B603 B607
                [_system_exe("icacls.exe"), name],
                check=False,
                capture_output=True,
                # icacls writes the OEM code page to a pipe. Decoding it with the default ANSI code
                # page failed on a non-ASCII path (measured: "Schluessel" with u-umlaut came back as
                # byte 0x81, stdout arrived as None, and the parse raised AttributeError, which no
                # caller catches). "oem" decodes it so the echoed path matches the one passed;
                # errors="replace" keeps a stray byte from ever making the read crash.
                encoding="oem",
                errors="replace",
            )
        except OSError as exc:
            log.warning("icacls could not read the DACL of %r: %s", name, exc)
            return None
        if result.stdout is None:
            log.warning("icacls returned no readable output for %r", name)
            return None
        if result.returncode != 0:
            log.warning(
                "icacls could not read the DACL of %r (exit %s): %r",
                name,
                result.returncode,
                (result.stderr or result.stdout or "").strip(),
            )
            return None
        parsed = owner_only_from_icacls(result.stdout, anchor_path=name)
        if parsed is None:
            log.warning(
                "icacls exited 0 for %r but its output carried no readable ACE, granted write to a "
                "bare principal name it does not recognise, or granted write on a first line whose "
                "path echo did not match; the DACL could not be determined",
                name,
            )
        return parsed
    try:
        mode = Path(name).stat().st_mode
    except OSError as exc:
        log.warning("could not stat %r to check its permissions: %s", name, exc)
        return None
    return (mode & 0o022) == 0


# --- evaluation + enforcement -------------------------------------------------------------------


def evaluate_anchor(spec: AnchorSpec) -> AnchorVerdict:
    """Inspect one anchor file: compute its fingerprint, its DACL verdict, and (if pinned) whether the
    fingerprint matches the pin. Pure inspection — no enforcement, no audit. Reads the file + the DACL,
    so callers on the event loop should dispatch it via :func:`asyncio.to_thread`.

    The file is read ONCE, and the verdict carries those bytes as ``data``, so a consumer can load
    what was hashed rather than open the file again (BACKLOG #1142, slice 2)."""
    data = Path(spec.path).read_bytes()
    fingerprint = hashlib.sha256(data).hexdigest()
    pin_ok: bool | None = None
    if spec.pin is not None:
        pin_ok = fingerprint == _normalize_pin(spec.pin)
    path_check = anchor_path_verdict(spec.path)
    return AnchorVerdict(
        fingerprint=fingerprint,
        acl_ok=dacl_is_owner_only(spec.path),
        pin_ok=pin_ok,
        path_ok=path_check.ok,
        path_check=path_check,
        data=data,
    )


def _pin_mismatch_message(spec: AnchorSpec, verdict: AnchorVerdict) -> str:
    return (
        f"{spec.setting}: the trust anchor {spec.path!r} does not match its configured SHA-256 pin "
        f"(loaded {verdict.fingerprint}); refusing to load a substituted anchor"
    )


def _acl_message(spec: AnchorSpec) -> str:
    """The file arm's finding, with its fix in the message itself. It used to cite
    ``docs/security/OFF-LOOPBACK-DEPLOYMENT.md``, which ships in neither a checkout nor a wheel. The
    fix names only what :func:`dacl_is_owner_only` checks on this platform: a broad group's write
    ACE on Windows, and the group and other write bits on POSIX. Each fix takes write away and
    leaves read, so an engine account that reads the anchor through that group still can. The
    rights it names are :data:`_WRITE_RIGHTS`, so the text cannot drift from the check."""
    lines = [
        f"{spec.setting}: the trust anchor {spec.path!r} is writable by a non-owner (a group or "
        "world principal can write it). Anyone who can modify it can substitute the CA and defeat "
        "authentication. Restrict it to owner-only write."
    ]
    if os.name == "nt":
        q = _ps_quote(spec.path)
        rights = ", ".join(sorted(_WRITE_RIGHTS))
        lines += [
            "Fix, from an elevated PowerShell. List the DACL, and note each group or world "
            "principal, such as Everyone, Authenticated Users or Users, that holds a write right "
            f"({rights}):",
            f"  icacls {q}",
            "Turn inherited entries into explicit ones, so the next command reaches them:",
            f"  icacls {q} /inheritance:d",
            "Then, for each principal you noted, replace its grant with read (R), which removes "
            "write. Write a principal listed as a SID with a leading *, as '*S-1-1-0:(R)':",
            f"  icacls {q} /grant:r '<principal>:(R)'",
            f"Then run icacls {q} again. No principal you noted should hold a right from that "
            "list.",
        ]
    else:
        lines += ["Fix: drop the group and other write bits, keeping read:"]
        lines += [f"  chmod go-w {shlex.quote(spec.path)}"]
    return "\n".join(lines)


def _findings(verdict: AnchorVerdict, *, insecure: bool) -> list[ChainFinding]:
    check = verdict.path_check
    return [f for f in (check.findings if check else ()) if f.insecure is insecure]


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _path_fix(verdict: AnchorVerdict) -> list[str]:
    """The fix, as commands, for each insecure finding that a command can fix. The message must
    carry its own fix, as the file arm's (:func:`_acl_message`) does: the runbook that message once
    cited ships in neither a checkout nor a wheel.

    Every command is narrow. It removes the grants or write bits the check named, or hands
    ownership to Administrators or root, and leaves every other entry alone. A blanket reset such as
    ``/inheritance:r /grant:r`` would strip the engine's own modify grant from its data folder,
    or the user's rights from a profile folder."""
    check = verdict.path_check
    bad = _findings(verdict, insecure=True)
    objects: dict[str, str] = {}
    for f in bad:
        objects.setdefault(f.path, f.kind)
    move = "Fix: move the anchor into a folder that only administrators and the engine's account "
    if check is not None and check.platform == "windows":
        lines = [
            move + "can change, such as the engine's data folder under C:\\ProgramData. Or, "
            "from an elevated PowerShell, for each object named above:"
        ]
        for obj, kind in objects.items():
            q = _ps_quote(obj) + (" /L" if kind == LINK else "")
            here = [f for f in bad if f.path == obj]
            granted = sorted({sid for f in here if not f.owner for sid in f.sids})
            if granted:
                # /inheritance:d turns inherited entries into explicit ones, so /remove:g reaches them.
                lines.append(f"  icacls {q} /inheritance:d")
                lines.append(
                    f"  icacls {q} /remove:g " + " ".join(_ps_quote("*" + s) for s in granted)
                )
            if any(f.owner for f in here):
                lines.append(f"  icacls {q} /setowner '*S-1-5-32-544'")
        lines.append("Then read each one back with: icacls <path>")
        return lines
    # Each finding gets only its own command. A mode finding gets the chmod that drops the group and
    # other write bits, never a chown: the object may be the engine's own data folder, such as the
    # container's /config, and a chown to root would take it away from the engine.
    #
    # An owner finding gets a chown to root, the owner an anchor's folder wants: the engine only
    # reads an anchor. It names no group, because root:root would also take the group, and with it
    # any access the engine holds through that group. The finding says the account the check ran
    # as is not the owner, and the message says to run the check as the service account, so
    # handing ownership to root takes nothing from the engine.
    #
    # Always -h: on a link it re-owns the link and not its target, and on anything else it acts
    # the same. The owner the finding names can swap its entry for a link before root runs this.
    cmds: list[str] = []
    for obj in objects:
        q = shlex.quote(obj)
        here = [f for f in bad if f.path == obj]
        if any(f.owner for f in here):
            cmds.append(f"  chown -h root {q}")
        if any(f.writable for f in here):
            cmds.append(f"  chmod go-w {q}")
    lead = move + "can change, such as a root-owned 755 folder like /etc/messagefoundry/."
    return [lead + " Or, to fix it in place:", *cmds] if cmds else [lead]


def _path_message(spec: AnchorSpec, verdict: AnchorVerdict) -> str:
    lines = [
        f"{spec.setting}: the trust anchor {spec.path!r} can be replaced through its path, and "
        "anyone who replaces it can substitute the CA and defeat authentication:"
    ]
    lines += [f"  {f.kind} {f.path!r}: {f.reason}" for f in _findings(verdict, insecure=True)]
    check = verdict.path_check
    if check is not None and check.engine:
        lines.append(
            f"The check trusted the account it ran as ({check.engine}) as the engine's own. Run "
            "it as the account the service runs as, or it can answer differently."
        )
    return "\n".join(lines + _path_fix(verdict))


def _indeterminate_message(spec: AnchorSpec, verdict: AnchorVerdict) -> str:
    """What could not be read, object by object. The caller adds the outcome."""
    lines = [
        f"{spec.setting}: could not settle whether anyone else can replace the trust anchor "
        f"{spec.path!r}:"
    ]
    if verdict.acl_ok is None:
        lines.append(
            f"  file {spec.path!r}: its permissions could not be read, or they grant write to a "
            "principal the engine could not identify"
        )
    if verdict.path_ok is None:
        lines += [f"  {f.kind} {f.path!r}: {f.reason}" for f in _findings(verdict, insecure=False)]
    return "\n".join(lines)


def _indeterminate_fix(spec: AnchorSpec, verdict: AnchorVerdict) -> str:
    """The two ways out of an indeterminate read: a folder the engine can read, or a pin. The pin is
    offered with this file's own digest, and with the warning that goes with it: pinning bytes the
    engine could not vouch for is only as good as the operator's check of them."""
    check = verdict.path_check
    windows = check.platform == "windows" if check is not None else os.name == "nt"
    folder = (
        "the engine's data folder under C:\\ProgramData"
        if windows
        else "a root-owned 755 folder like /etc/messagefoundry/"
    )
    if not spec.loads_verified_bytes:
        return (
            f"Fix: move the anchor into a folder whose permissions the engine can read, such as "
            f"{folder}. A pin does not help here: this anchor is read again by path when it is "
            "used, so a pin cannot vouch for the bytes loaded."
        )
    pin = f"set {spec.pin_setting} to" if spec.pin_setting else "pin it to"
    return (
        f"Fix: move the anchor into a folder whose permissions the engine can read, such as "
        f"{folder}. Or {pin} the SHA-256 of the CA you mean to trust; this file's is "
        f"{verdict.fingerprint}. Check it against the CA first. With a matching pin the engine "
        "loads exactly those bytes, so it may load them without this check."
    )


def _enforce_verdict(spec: AnchorSpec, verdict: AnchorVerdict, *, enforcing: bool) -> None:
    """Apply the owner fork to a verdict. Raises :class:`TrustAnchorError` on a fatal violation.

    * A pin mismatch always refuses.
    * A group/world-writable DACL, or a path another principal can replace the anchor through,
      refuses at ``enforce`` and warns at ``warn``. A pin does not change this: an anchor anyone can
      replace is a finding, not an unknown.
    * An ACL or path that could not be read refuses at ``enforce`` and warns at ``warn`` (BACKLOG
      #1142, slice 3). **A configured pin that matches is the escape**: it warns and loads, at either
      dial, because the bytes it matched are the bytes the context loads. Not for an anchor whose
      consumer reads the file again (``loads_verified_bytes`` False, the outbound CAs, vault
      BACKLOG #2371): there the pin matched bytes the consumer does not load."""
    if verdict.pin_ok is False:
        raise TrustAnchorError(_pin_mismatch_message(spec, verdict))
    if verdict.acl_ok is False:
        if enforcing:
            raise TrustAnchorError(
                _acl_message(spec) + "\n[security].enforcement=enforce refuses to start"
            )
        log.warning("%s\n[security].enforcement=warn, starting anyway", _acl_message(spec))
    if verdict.path_ok is False:
        if enforcing:
            raise TrustAnchorError(
                _path_message(spec, verdict) + "\n[security].enforcement=enforce refuses to start"
            )
        log.warning(
            "%s\n[security].enforcement=warn, starting anyway", _path_message(spec, verdict)
        )
    if verdict.acl_ok is not None and verdict.path_ok is not None:
        return
    # BACKLOG #1142, slice 3. Slice 2 made the checked bytes the loaded bytes, which is what lets a
    # pin stand in for a read the file system would not give.
    unknown = _indeterminate_message(spec, verdict)
    if verdict.pin_ok is True and spec.loads_verified_bytes:
        log.warning(
            "%s\n%s matches the bytes read, and those are the bytes loaded, so it is loaded anyway",
            unknown,
            spec.pin_setting or "the configured SHA-256 pin",
        )
        return
    fix = _indeterminate_fix(spec, verdict)
    if enforcing:
        raise TrustAnchorError(f"{unknown}\n{fix}\n[security].enforcement=enforce refuses to start")
    log.warning("%s\n%s\n[security].enforcement=warn, starting anyway", unknown, fix)


def enforce_anchor(spec: AnchorSpec, *, enforcing: bool) -> str:
    """Construction-site preflight (no store/audit): evaluate + enforce one anchor, returning its
    fingerprint. It loads nothing. A consumer that loads the anchor into a context calls
    :func:`verified_anchor_cadata` instead and loads what that returns: calling this and then loading
    the file by path reopens the check-then-load gap BACKLOG #1142, slice 2 closed."""
    verdict = evaluate_anchor(spec)
    _enforce_verdict(spec, verdict, enforcing=enforcing)
    return verdict.fingerprint


def verified_anchor_cadata(spec: AnchorSpec, *, enforcing: bool) -> str:
    """Evaluate and enforce one anchor as :func:`enforce_anchor` does, then return the bytes it
    checked as ``cadata=`` text (:func:`anchor_cadata`).

    **Load the return value, never ``spec.path``.** Loading by path reads the file a second time, and
    a file swapped between the two reads would be trusted without its pin, ACL or path check. That
    was the case for both consumers until BACKLOG #1142, slice 2.

    **This is where the cadata=/cafile= measurement lives; other sites point here.** Measured on
    Windows, CPython 3.14.6 / OpenSSL 3.5.7, with a real TCP socket to a localhost server, client side
    and server side: over a valid PEM, ``cadata=`` and ``cafile=`` each verify the right CA, each
    refuse a wrong one, and each hold exactly one anchor. ``tests/test_trust_anchor_byte_binding.py``
    repeats the handshakes over memory BIOs. :func:`anchor_cadata` covers the inputs where the two
    differ.

    ``cadata=`` loads no CRL from the anchor file. A CRL file is loaded separately, by
    :func:`~messagefoundry.config.tls_policy.harden_crl_check`, which refuses a load that would add a
    certificate to the trust store (BACKLOG #1890). The CRL file carries no pin or ACL check:
    whoever can write it can change what is revoked, but not what is trusted.

    It records the fingerprint of the bytes it returns, for :func:`loaded_fingerprint`."""
    verdict = evaluate_anchor(spec)
    _enforce_verdict(spec, verdict, enforcing=enforcing)
    text = anchor_cadata(verdict.data, spec)
    _LOADED[(spec.label, spec.path)] = verdict.fingerprint
    return text


#: The fingerprint of the bytes :func:`verified_anchor_cadata` last handed a consumer in this
#: process, keyed by the anchor's label and path (BACKLOG #2185). Every consumer of a settings
#: anchor loads through that function: the API's client-CA context, the AD authenticator and the
#: OIDC opener. So this holds the bytes each one trusts, and an anchor no consumer loaded has no
#: entry. The path is in the key so two configurations in one process, such as two tests, never
#: read each other's entry.
_LOADED: dict[tuple[str, str], str] = {}


def loaded_fingerprint(spec: AnchorSpec) -> str | None:
    """The fingerprint of the bytes a consumer in this process last loaded for ``spec``, or ``None``
    when no consumer loaded it. See :data:`_LOADED`."""
    return _LOADED.get((spec.label, spec.path))


# --- spec collection ----------------------------------------------------------------------------


def api_client_anchor_spec(api: ApiSettings) -> AnchorSpec | None:
    """The ``[api].tls_client_ca_file`` anchor spec, or ``None`` when unset (dormant)."""
    if not api.tls_client_ca_file:
        return None
    return AnchorSpec(
        "api_client",
        "[api].tls_client_ca_file",
        api.tls_client_ca_file,
        api.tls_client_ca_pin,
        "[api].tls_client_ca_pin",
    )


def ad_anchor_spec(auth: AuthSettings) -> AnchorSpec | None:
    """The ``[auth].ad_tls_ca_cert_file`` anchor spec, or ``None`` when unset. One spelling for the
    central preflight and for :class:`~messagefoundry.auth.ldap.LdapAuthenticator`, which loads the
    bytes it checks (BACKLOG #2034)."""
    if not auth.ad_tls_ca_cert_file:
        return None
    return AnchorSpec(
        "ad",
        "[auth].ad_tls_ca_cert_file",
        auth.ad_tls_ca_cert_file,
        auth.ad_tls_ca_cert_pin,
        "[auth].ad_tls_ca_cert_pin",
    )


def oidc_anchor_spec(ca_cert_file: str, pin: str | None) -> AnchorSpec:
    """The ``[auth].oidc_tls_ca_cert_file`` anchor spec. One spelling for every site that builds it."""
    return AnchorSpec(
        "oidc", "[auth].oidc_tls_ca_cert_file", ca_cert_file, pin, "[auth].oidc_tls_ca_cert_pin"
    )


def connection_ca_pin(settings: Mapping[str, Any], setting: str) -> str | None:
    """A connection's ``tls_ca_pin``, or ``None`` when the key is absent or ``None``.

    **A pin that is present but blank refuses, never reads as no pin** (BACKLOG #1142). An
    ``env()`` value set to nothing, or a blank literal, used to read as no pin: the config looked
    pinned while nothing was checked. ``setting`` names the key for the message. Raises
    ``ValueError``, which a connector build reports as a config error."""
    from messagefoundry.config.settings import refuse_a_blank_anchor_pin

    pin = settings.get("tls_ca_pin")
    if pin is not None and not isinstance(pin, str):
        raise ValueError(
            f"{setting} must be text, the SHA-256 of the CA file; got a value of type "
            f"{type(pin).__name__}"
        )
    return refuse_a_blank_anchor_pin(pin, setting)


def connection_anchor_spec(name: str, settings: Mapping[str, Any]) -> AnchorSpec | None:
    """The CA of one inbound connection whose server context requires a peer certificate, or ``None``.

    The predicate is the one BACKLOG #1142 names: **every per-connection inbound CA whose server
    context requires a peer certificate**. All three inbound listeners that build a server context
    (MLLP, the HTTP listener, the DICOM SCP) set ``CERT_REQUIRED`` exactly when ``tls`` and
    ``tls_ca_file`` are both set, so that pair is the test, whatever the connector type. A predicate
    keyed on ``intake_auth`` would reach the HTTP listener alone.

    ``settings`` must already have its ``env()`` references resolved. An unresolved
    ``tls_ca_file`` is skipped here, and the connector's own build still checks the resolved value.
    On a connection that requires a peer certificate, a ``tls_ca_pin`` that is blank or not text
    raises ``ValueError`` (:func:`connection_ca_pin`). Anywhere else the pin is left to the
    connector's build, so one bad connection fails its own lane, not the whole graph."""
    ca = settings.get("tls_ca_file")
    if isinstance(ca, os.PathLike):
        ca = os.fspath(ca)
    if not settings.get("tls") or not isinstance(ca, str) or not ca:
        return None
    pin = connection_ca_pin(settings, f"inbound connection '{name}' tls_ca_pin")
    return AnchorSpec(
        inbound_record_name(name),
        f"inbound connection '{name}' tls_ca_file",
        ca,
        pin,
        f"inbound connection '{name}' tls_ca_pin",
    )


#: How an outbound connection's CA is labelled in its ``auth.trust_anchor`` rows (vault BACKLOG
#: #2371). Prefixed, unlike how a record names an outbound elsewhere (bare, see
#: :func:`~messagefoundry.connection_names.inbound_record_name`), because the label keys the
#: fingerprint baseline :func:`_last_fingerprint` reads. A connection may be named ``ad`` or
#: ``oidc``, and a bare label would then share a baseline with that settings anchor.
_OUTBOUND_LABEL = "outbound:{}"


def outbound_anchor_spec(
    name: str,
    settings: Mapping[str, Any],
    *,
    kind: str = "outbound connection",
    label: str | None = None,
) -> AnchorSpec | None:
    """The CA a dialling connection verifies its server with, or ``None`` (vault BACKLOG #2371).

    A connection that dials out reads ``tls_ca_file`` to verify the server: every outbound that
    takes the key, and a ``FhirLookup``, which passes ``kind="fhir lookup"`` and its own label. The
    test is ``tls_ca_file`` set and ``tls`` not turned off. Connectors with no ``tls`` key (the HTTP
    family, Email, Direct) read the file whenever it is set. ``MLLP``, ``DICOM`` and ``Ftp`` read
    it only with ``tls`` on. A CA a hop would not read is not checked here; ``Ftp`` refuses one at
    load, and ``tls_ca_pin`` beside one is refused by :func:`refuse_an_unread_ca_pin`.

    ``settings`` must already have its ``env()`` references resolved, as for
    :func:`connection_anchor_spec`. A ``tls_ca_pin`` that is blank or not text raises
    ``ValueError`` (:func:`connection_ca_pin`)."""
    ca = settings.get("tls_ca_file")
    if isinstance(ca, os.PathLike):
        ca = os.fspath(ca)
    if not isinstance(ca, str) or not ca:
        return None
    if "tls" in settings and not settings["tls"]:
        return None
    pin = connection_ca_pin(settings, f"{kind} '{name}' tls_ca_pin")
    return AnchorSpec(
        label or _OUTBOUND_LABEL.format(name),
        f"{kind} '{name}' tls_ca_file",
        ca,
        pin,
        f"{kind} '{name}' tls_ca_pin",
        loads_verified_bytes=False,  # the hop's context reads cafile= after the preflight
    )


def refuse_an_unread_ca_pin(settings: Mapping[str, Any], *, inbound: bool, connector: str) -> None:
    """Refuse a ``tls_ca_pin`` that nothing reads. It pins the connection's ``tls_ca_file``, so it
    means something only where that file is checked: on an inbound connection with ``tls`` and
    ``tls_ca_file`` (:func:`connection_anchor_spec`), and on an outbound one with ``tls_ca_file``
    and ``tls`` not off (:func:`outbound_anchor_spec`, vault BACKLOG #2371). Anywhere else the
    config would read as pinned while nothing checks it, which is worse than no pin. Raises
    ``ValueError``, which a connector build reports as a config error. A blank pin refuses here too,
    on every connection, whatever else it sets."""
    if connection_ca_pin(settings, f"{connector}: tls_ca_pin") is None:
        return
    if inbound and connection_anchor_spec("", settings) is not None:
        return
    if not inbound and outbound_anchor_spec("", settings) is not None:
        return
    direction = "an inbound" if inbound else "an outbound"
    raise ValueError(
        f"{connector}: tls_ca_pin is set on {direction} connection without tls=True and a "
        "tls_ca_file, so nothing would check it. It pins the connection's tls_ca_file. Remove it, "
        "or turn on tls with a tls_ca_file"
    )


def inbound_ca_cadata(name: str, settings: Mapping[str, Any], *, enforcing: bool) -> str:
    """The verified ``cadata=`` text for an inbound listener's ``tls_ca_file`` (BACKLOG #1142, slice 3).

    The listener's context builder calls this in place of ``load_verify_locations(cafile=...)``, so the
    CA it trusts is the one the pin, ACL, path and PEM checks read. ``enforcing`` is the construction
    posture's dial. Raises :class:`TrustAnchorError` if ``settings`` names no such CA, since a caller
    that reaches here has already decided to require a peer certificate.

    A CA file that cannot be read raises :class:`TrustAnchorError` too, not the ``OSError``. Its
    text names the path, and a caller that keeps anchor paths away from API callers, such as the
    connection-test route, recognises the anchor refusal by its type."""
    spec = connection_anchor_spec(name, settings)
    if spec is None:
        raise TrustAnchorError(
            f"inbound connection '{name}' names no tls_ca_file to verify peers with"
        )
    try:
        return verified_anchor_cadata(spec, enforcing=enforcing)
    except OSError as exc:
        raise TrustAnchorError(
            f"{spec.setting}: could not read the trust anchor {spec.path!r}: {exc.strerror or exc}"
        ) from exc


def connection_anchor_specs(
    inbound: Iterable[tuple[str, Mapping[str, Any]]],
) -> list[AnchorSpec]:
    """:func:`connection_anchor_spec` over ``(name, resolved settings)`` pairs, in the order given."""
    return [s for name, st in inbound if (s := connection_anchor_spec(name, st)) is not None]


#: The connection settings :func:`connection_anchor_spec` reads, and the only ones resolved for it.
_CONNECTION_ANCHOR_KEYS = ("tls", "tls_ca_file", "tls_ca_pin")


def registry_anchor_specs(registry: Registry, env_values: Mapping[str, Any]) -> list[AnchorSpec]:
    """Every per-connection CA in ``registry`` the preflight checks, with ``env()`` references
    resolved against ``env_values``: the CA of each deployed inbound that requires a peer
    certificate (:func:`connection_anchor_spec`), then, since vault BACKLOG #2371, the CA each
    deployed outbound and each ``FhirLookup`` verifies its server with (:func:`outbound_anchor_spec`).

    A connection whose anchor settings do not resolve is skipped: its own build refuses it, and
    that error names the missing value."""
    from messagefoundry.config.wiring import WiringError, resolve_env_settings

    def resolved(settings: Mapping[str, Any]) -> Mapping[str, Any] | None:
        raw = {k: settings[k] for k in _CONNECTION_ANCHOR_KEYS if k in settings}
        try:
            return resolve_env_settings(raw, env_values)
        except WiringError:
            return None

    pairs: list[tuple[str, Mapping[str, Any]]] = []
    for ic in registry.inbound.values():
        if ic.deployed and (st := resolved(ic.spec.settings)) is not None:
            pairs.append((ic.name, st))
    specs = connection_anchor_specs(pairs)
    dialling: list[tuple[str, Mapping[str, Any] | None, str, str | None]] = [
        (oc.name, resolved(oc.spec.settings) if oc.deployed else None, "outbound connection", None)
        for oc in registry.outbound.values()
    ]
    dialling += [
        (fl.name, resolved(fl.settings), "fhir lookup", fhir_lookup_record_name(fl.name))
        for fl in registry.fhir_lookups.values()
    ]
    for name, st, kind, label in dialling:
        spec = outbound_anchor_spec(name, st, kind=kind, label=label) if st is not None else None
        if spec is not None:
            specs.append(spec)
    return specs


def collect_anchor_specs(auth: AuthSettings, api: ApiSettings) -> list[AnchorSpec]:
    """Every configured operator-supplied trust anchor, in a stable order. An anchor with no path set
    is omitted, so an install with no OIDC/AD/mTLS anchor yields an empty list: the dormant,
    byte-identical path.

    The per-connection inbound CAs are not here: ``serve`` calls this before any graph is loaded.
    :func:`registry_anchor_specs` collects them each time a graph is loaded, at start and at
    reload (BACKLOG #1142, slice 3)."""
    specs: list[AnchorSpec] = []
    if auth.oidc_tls_ca_cert_file:
        specs.append(oidc_anchor_spec(auth.oidc_tls_ca_cert_file, auth.oidc_tls_ca_cert_pin))
    ad_spec = ad_anchor_spec(auth)
    if ad_spec is not None:
        specs.append(ad_spec)
    api_spec = api_client_anchor_spec(api)
    if api_spec is not None:
        specs.append(api_spec)
    return specs


# --- central preflight (store-backed: audit the load, detect changes, then enforce) -------------


#: How far back :func:`_last_fingerprint` pages. One page used to be the whole look-back, and every
#: preflight of an anchor whose path cannot be judged writes a row, so one noisy anchor could push a
#: quiet anchor's baseline out of the window. Its next swap would then read as a first observation.
_FINGERPRINT_PAGE = 200
_FINGERPRINT_PAGES = 50


async def _last_fingerprint(store: Store, label: str) -> str | None:
    """The most-recently audited fingerprint for ``label``, or ``None`` if this anchor has never been
    observed. Reads the ``auth.trust_anchor`` audit rows (most-recent-first), a page at a time, and
    returns the first matching label's fingerprint. Each page ends at the oldest timestamp of the one
    before, inclusively, so a row at that instant is read twice and never skipped."""
    until: float | None = None
    for _page in range(_FINGERPRINT_PAGES):
        rows = await store.list_audit(action=AUDIT_ACTION, limit=_FINGERPRINT_PAGE, until=until)
        for row in rows:
            detail_raw = row["detail"]
            if not detail_raw:
                continue
            try:
                detail = json.loads(detail_raw)
            except (ValueError, TypeError):
                continue
            if detail.get("label") == label:
                fp = detail.get("fingerprint")
                return fp if isinstance(fp, str) else None
        if len(rows) < _FINGERPRINT_PAGE:
            return None
        oldest = float(rows[-1]["ts"])
        if until is not None and oldest >= until:
            return None  # a whole page at one instant: nothing older can be reached this way
        until = oldest
    return None


async def _record(store: Store, spec: AnchorSpec, event: str, **extra: object) -> None:
    detail = {"label": spec.label, "setting": spec.setting, "event": event, **extra}
    await store.record_audit(AUDIT_ACTION, actor=None, detail=json.dumps(detail))


async def _preflight_one(store: Store, spec: AnchorSpec, *, enforcing: bool) -> str:
    """Preflight one anchor: audit the observation (baseline / changed) FIRST so a change is durably
    recorded even when the anchor then fails its pin/ACL, record any violation, then enforce (which may
    raise). Returns the fingerprint of the bytes it read and passed.

    **It applies every check a consumer applies**, the PEM shape of :func:`anchor_cadata` included
    (BACKLOG #1142, slice 3). The reload route runs this and builds no context to verify a peer
    with, so before this a reload accepted an anchor with no PEM block, or a ``TRUSTED
    CERTIFICATE`` block, that the next start refuses. The AD anchor takes it too since BACKLOG
    #2034, when its bind moved to the checked bytes. Since BACKLOG #2025 :func:`anchor_cadata` also
    makes the consumer's own ``cadata=`` load, so a file that load refuses, such as one holding
    only a CRL, refuses here too.

    That load is OpenSSL parsing the file, so it runs off the event loop, and it is skipped when the
    pin does not match: those bytes are refused anyway, and a consumer never parses bytes whose pin
    failed, because :func:`verified_anchor_cadata` enforces first.

    An anchor whose consumer reads ``cafile=`` (``loads_verified_bytes`` False, the outbound CAs,
    vault BACKLOG #2371) skips the shape check. ``cafile=`` loads a ``TRUSTED CERTIFICATE`` block,
    for one, so refusing it here would refuse what the build accepts."""
    verdict = await asyncio.to_thread(evaluate_anchor, spec)
    shape_error: TrustAnchorError | None = None
    if verdict.pin_ok is not False and spec.loads_verified_bytes:
        try:
            await asyncio.to_thread(anchor_cadata, verdict.data, spec)
        except TrustAnchorError as exc:
            shape_error = exc
    previous = await _last_fingerprint(store, spec.label)
    if previous is None:
        await _record(store, spec, "observed", fingerprint=verdict.fingerprint)
    elif previous != verdict.fingerprint:
        await _record(store, spec, "changed", fingerprint=verdict.fingerprint, previous=previous)
    if verdict.pin_ok is False:
        await _record(store, spec, "pin_mismatch", fingerprint=verdict.fingerprint)
    if verdict.acl_ok is False:
        await _record(
            store, spec, "acl_insecure", fingerprint=verdict.fingerprint, enforcing=enforcing
        )
    elif verdict.acl_ok is None:
        # BACKLOG #1142. This branch used to write no row at all, so an operator following the
        # runbook's "alert on auth.trust_anchor" instruction saw nothing on the one branch where the
        # engine cannot vouch for the anchor, a detective control blind on its own subject. Since
        # slice 3 it also refuses at enforce unless a matching pin lets it through, and `pinned`
        # says which of the two this row saw.
        await _record(
            store,
            spec,
            "acl_indeterminate",
            fingerprint=verdict.fingerprint,
            enforcing=enforcing,
            pinned=verdict.pin_ok is True,
        )
    if verdict.path_ok is not True:
        # Each row names every object that failed, with the principal and the right, or the cause.
        insecure = verdict.path_ok is False
        extra: dict[str, object] = {} if insecure else {"pinned": verdict.pin_ok is True}
        await _record(
            store,
            spec,
            "path_insecure" if insecure else "path_indeterminate",
            fingerprint=verdict.fingerprint,
            enforcing=enforcing,
            components=[
                {"path": f.path, "kind": f.kind, "reason": f.reason}
                for f in _findings(verdict, insecure=insecure)
            ],
            **extra,
        )
    if shape_error is not None:
        await _record(store, spec, "pem_refused", fingerprint=verdict.fingerprint)
    _enforce_verdict(spec, verdict, enforcing=enforcing)
    if shape_error is not None:
        raise shape_error
    return verdict.fingerprint


async def run_anchor_preflight(
    specs: Sequence[AnchorSpec], store: Store, *, enforcing: bool
) -> dict[str, str]:
    """The central load/reload preflight over every configured anchor. Called at serve startup (before
    any listener binds) and on a config reload (re-reading the on-disk PEMs, so a swapped anchor is
    caught). **Dormant when ``specs`` is empty** — it makes no store call and writes no audit row, so an
    install with no OIDC/AD/mTLS anchor is byte-identical.

    On a fatal violation (a pin mismatch, a file with no loadable PEM block, or under ``enforce`` an
    anchor another principal can replace or whose ACL or path could not be read, with no matching pin)
    it raises :class:`TrustAnchorError` after auditing it, so the caller refuses to start / refuses
    the reload. Otherwise it returns each anchor's fingerprint, keyed by its label."""
    return {spec.label: await _preflight_one(store, spec, enforcing=enforcing) for spec in specs}


async def _report_restart_required(
    specs: Sequence[AnchorSpec], store: Store, *, seen: Mapping[str, str]
) -> None:
    """Log and audit each settings anchor whose bytes on disk differ from the bytes its consumer
    loaded (:func:`loaded_fingerprint`). An anchor no consumer loaded is skipped: a restart would
    apply nothing there.

    The compare is never against the audit chain. The last audited fingerprint moves to the new
    bytes at the first reload that sees them, while the consumers still trust the old bytes. A
    compare with it would go quiet from the second reload on (BACKLOG #2185)."""
    for spec in specs:
        in_use = loaded_fingerprint(spec)
        now = seen[spec.label]
        if in_use is None or in_use == now:
            continue
        log.warning(
            "%s: the trust anchor %r changed on disk since the engine loaded it (sha256 %s, was "
            "%s). This reload checked the new file but does not apply it. The engine keeps "
            "trusting the CA it loaded until it restarts. Restart the engine to apply the new CA",
            spec.setting,
            spec.path,
            now,
            in_use,
        )
        await _record(store, spec, "restart_required", fingerprint=now, in_use=in_use)


def make_settings_anchor_preflight(
    specs: Sequence[AnchorSpec], store: Store, *, enforcing: bool
) -> Callable[[], Awaitable[None]] | None:
    """The engine's ``settings_preflight`` for ``serve``: :func:`run_anchor_preflight` over the
    settings anchors (:func:`collect_anchor_specs`), run by the engine on EVERY real reload. That is
    the direct ``/config/reload`` route, a held reload a second approver releases, a cluster
    convergence reload and a DR profile reload (BACKLOG #2034). Before this only the direct route ran
    it, from ``api/``, where the other three never pass.

    ``None`` when no settings anchor is configured, so the engine skips it: no store call, no audit
    row. A refusal is re-raised as ``WiringError`` caused by a :class:`TrustAnchorError`, so the reload
    route answers 422 and audits ``reason="trust_anchor"``, as it did when it ran this itself. An
    unreadable anchor (``OSError``, or ``ValueError`` from a NUL in its path) counts as a refused
    anchor, as it did there.

    **A reload that passes does not apply a changed anchor** (BACKLOG #2185). No reload rebuilds the
    consumers that loaded these files, so each keeps the bytes it read at start. When this
    preflight passes, it warns and audits ``restart_required`` for each anchor whose bytes on disk
    differ from its consumer's (:func:`loaded_fingerprint`). That repeats on every reload until a
    restart. The specs are frozen here, pins included, so a reload re-reads the paths and pins the
    engine started with."""
    if not specs:
        return None
    from messagefoundry.config.wiring import WiringError

    frozen = tuple(specs)

    async def preflight() -> None:
        try:
            seen = await run_anchor_preflight(frozen, store, enforcing=enforcing)
        except TrustAnchorError as exc:
            raise WiringError(f"a settings trust anchor was refused: {exc}") from exc
        except (OSError, ValueError) as exc:
            # An unreadable anchor is a refused anchor, as it was when the reload route ran this.
            unreadable = TrustAnchorError(f"a trust anchor could not be read: {exc}")
            unreadable.__cause__ = exc
            raise WiringError(f"a settings trust anchor was refused: {unreadable}") from unreadable
        await _report_restart_required(frozen, store, seen=seen)

    return preflight


def make_registry_anchor_preflight(
    store: Store, *, enforcing: bool
) -> Callable[[Registry, Mapping[str, Any]], Awaitable[None]]:
    """The engine's ``registry_preflight`` for ``serve``: :func:`run_anchor_preflight` over a graph's
    per-connection CAs (:func:`registry_anchor_specs`), inbound and, since vault BACKLOG #2371,
    outbound and ``FhirLookup``, at the first load and at every real reload. A refusal is re-raised
    as ``WiringError``, which the reload route answers with 422 and the first load with a refused
    start. Dormant when no connection names a CA it checks.

    The ``WiringError`` is always caused by a :class:`TrustAnchorError`, as the settings preflight's
    is (:func:`make_settings_anchor_preflight`), so the reload routes audit ``reason="trust_anchor"``
    for both. An unreadable CA (``OSError``) and a ``ValueError``, such as a blank ``tls_ca_pin``,
    are wrapped in one first, keeping their text. Before BACKLOG #2183 they were the cause
    themselves, and the routes audited ``invalid_config``."""
    from messagefoundry.config.wiring import WiringError

    async def preflight(registry: Registry, env_values: Mapping[str, Any]) -> None:
        try:
            # Inside the try: a blank tls_ca_pin raises ValueError while the specs are collected.
            specs = registry_anchor_specs(registry, env_values)
            if not specs:
                return
            await run_anchor_preflight(specs, store, enforcing=enforcing)
        except TrustAnchorError as exc:
            raise WiringError(f"a connection trust anchor was refused: {exc}") from exc
        except (OSError, ValueError) as exc:
            # ValueError too: an env()-supplied path with a NUL in it raises one from the read, and
            # a blank tls_ca_pin raises one, and each must reach the route as a refused anchor, not
            # an unaudited 500. Wrapped as the settings preflight wraps it, with the text unchanged.
            refused = TrustAnchorError(str(exc))
            refused.__cause__ = exc
            raise WiringError(f"a connection trust anchor was refused: {refused}") from refused

    return preflight
