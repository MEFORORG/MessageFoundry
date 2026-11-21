# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""In-process API / WebSocket TLS context (WP-13a, ADR 0002).

Builds the ``ssl.SSLContext`` uvicorn terminates the engine API + ``/ws/stats`` WebSocket with, from the
``[api]`` ``tls_*`` settings. Pure stdlib ``ssl`` — no FastAPI/uvicorn import — so it is unit-testable in
isolation. The ``tls_min_version`` floor (NIST SP 800-52r2: 1.2+) is enforced via
``SSLContext.minimum_version``; an encrypted key's passphrase comes from ``MEFOR_API_TLS_KEY_PASSWORD``.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import ssl
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from messagefoundry.api_tls_source import (
    GENERATED_CERT_NAME,
    ApiTlsSource,
    api_tls_source,
    dialled_host,
    unbracketed,
    wildcard_loopback,
)
from messagefoundry.audit_write import write_audit_soft
from messagefoundry.auth.trust_anchors import (
    anchor_refusal,
    api_client_anchor_spec,
    api_client_crl_spec,
    verified_anchor_cadata,
)
from messagefoundry.config.settings import _LOOPBACK_HOSTS, ApiSettings
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    apply_operator_tls_ciphers,
    harden_cipher_suites,
    harden_crl_check,
    harden_kex_groups,
    harden_verify_flags,
    narrow_to_approved_suites,
)
from messagefoundry.file_lock import lock_exclusive as _try_lock
from messagefoundry.file_lock import unlock as _unlock
from messagefoundry.keywrap import load_checked_cert_chain
from messagefoundry.redaction import log_timestamp
from messagefoundry.restricted_file import replace_generated, unlink_generated
from messagefoundry.tls_handshake_failures import HandshakeFailures

if TYPE_CHECKING:
    from messagefoundry.pki import SelfSignedFacts
    from messagefoundry.store.base import Store

__all__ = [
    "GENERATED_PAIR_REPLACED",
    "ApiHandshakeRecord",
    "ApiTlsPlan",
    "ApiTlsSource",
    "GeneratedPairReplaced",
    "api_tls_source",
    "build_api_ssl_context",
    "ensure_api_tls_material",
    "generated_state_dir",
    "off_loopback_certificate_remedy",
    "plan_api_tls_material",
    "plaintext_upstream_hop_off_loopback",
    "plaintext_upstream_hop_off_loopback_remedy",
    "plaintext_upstream_hop_unacknowledged",
    "record_generated_pair_replacements",
]

log = logging.getLogger(__name__)

# Map the validated tls_min_version floor to the SSLContext minimum (TLS < 1.2 is never allowed).
_MIN_VERSION = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}


def build_api_ssl_context(api: ApiSettings, *, enforcing: bool = True) -> ssl.SSLContext:
    """Build the server ``SSLContext`` for the API listener from ``[api].tls_*``.

    Requires ``api.tls_cert_file`` (the caller checks ``api.tls_enabled`` first). The private key may be
    embedded in the cert PEM (``tls_key_file`` optional). mTLS is **opt-in**: when ``tls_client_ca_file``
    is set, a client cert is **required** and verified against it (console mutual auth); otherwise no
    client auth (the default).

    #285 (ASVS 6.7.1): when ``tls_client_ca_file`` is set, the client-CA trust anchor is preflighted at
    this construction point — an optional SHA-256 pin (``[api].tls_client_ca_pin``) mismatch refuses
    always, and a group/world-writable DACL refuses when ``enforcing`` (``[security].enforcement``).
    When ``enforcing`` it also refuses an anchor that can be replaced through its path, even with a
    matching pin, and an anchor whose ACL or path could not be read unless its pin matches
    (:mod:`messagefoundry.auth.trust_anchors`, items 4 and 6). Under warn, a writable DACL, a
    replaceable path and an unreadable ACL or path each warn and load; a pin mismatch still refuses.
    The context loads the bytes that preflight read, never the file a second time
    (BACKLOG #1142)."""
    if not api.tls_cert_file:
        raise ValueError("build_api_ssl_context requires [api].tls_cert_file")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _MIN_VERSION[api.tls_min_version]
    # An encrypted key with no passphrase must fail deterministically, not fall back to OpenSSL's blocking
    # TTY prompt (no TTY under a service account / in a container). BACKLOG #1352 / #1171: the key's
    # wrap is checked first, so a weak wrap or a missing passphrase is refused before OpenSSL reads the
    # key; the empty-bytes callback behind the check is never invoked for an unencrypted key.
    load_checked_cert_chain(
        ctx,
        api.tls_cert_file,
        api.tls_key_file,
        api.tls_key_password,
        cert_setting="[api].tls_cert_file",
        key_setting="[api].tls_key_file",
        unlock_setting="MEFOR_API_TLS_KEY_PASSWORD",
    )
    if api.tls_ciphers:
        apply_operator_tls_ciphers(ctx, api.tls_ciphers)  # validated at settings load
    else:
        # Unset is no longer "whatever the interpreter enables": the approved AEAD names are the
        # default on every context the engine builds (BACKLOG #300, the ADR 0188 amendment).
        narrow_to_approved_suites(ctx)
    harden_kex_groups(ctx)  # pin approved ECDHE groups where the runtime supports it (ASVS 11.6.2)
    harden_cipher_suites(ctx, connector="API/UI listener")  # assert forward secrecy (ASVS 12.1.2)
    harden_verify_flags(ctx)  # strict RFC 5280 cert validation (ASVS 12.1.4)
    client_ca = api_client_anchor_spec(api)
    if client_ca is not None:
        # #285: pin + owner-only-DACL + path preflight. BACKLOG #1142, slice 2: load the bytes that
        # preflight read, as cadata=. cafile= would open the file a second time, and a swap between
        # the two reads would admit a forged client certificate past a pin that matched.
        cadata = verified_anchor_cadata(client_ca, enforcing=enforcing)
        ctx.load_verify_locations(cadata=cadata)
        ctx.verify_mode = ssl.CERT_REQUIRED
        if api.tls_client_cert_identities:
            _attach_issuer_index(ctx, cadata, api.tls_client_cert_identities)
            if api.trusted_proxies:
                # Vault BACKLOG #5628. Here rather than where the shim is built, which is before
                # serve configures logging, so the line reaches the operator's handlers.
                log.warning(
                    "[api].trusted_proxies is set beside [api].tls_client_cert_identities: a client "
                    "certificate presented by a declared proxy maps to no principal, because the "
                    "proxy forwards other callers' requests"
                )
        # Opt-in revocation (#1005). NOTE THE POSITION: harden_verify_flags runs ABOVE, before the
        # CA is loaded, and this must NOT sit beside it. The CRL goes into the trust store, so
        # loading it before the CA yields a context with the check flag set and zero CRLs -- which
        # refuses EVERY client rather than skipping the check.
        crl = api_client_crl_spec(api)
        if crl is not None:
            # Vault BACKLOG #5627: the CRL decides which client certificates are refused, so it
            # takes the client CA's owner-only ACL and path preflight. A broadly writable CRL could
            # be swapped for an older one, signed and unexpired, from before a revocation. A
            # missing file is left to harden_crl_check, which says so in its own words; a file
            # that is there and cannot be read is refused here, naming the setting.
            if Path(crl.path).is_file():
                refusal = anchor_refusal(crl, enforcing=enforcing)
                if refusal is not None:
                    raise refusal
            # And the whole chain is checked, so a revoked intermediate refuses its clients too,
            # and a loaded client CA with no CRL of its own in the file refuses the build.
            harden_crl_check(ctx, crl.path, setting=crl.setting, chain=True)
    return ctx


class ApiHandshakeRecord:
    """A throttled WARNING line for each failed TLS handshake on the API (vault BACKLOG #3302).

    uvicorn hands the context to the loop, which runs every handshake and records a failed one at
    DEBUG at most, so before #3302 nothing an operator reads showed handshakes failing again and
    again. The API has no connection to carry an event, so the record is a log line, throttled as
    ``docs/PHI.md`` section 7, row 7 states. The hook does not read the peer's address (see
    :mod:`messagefoundry.tls_handshake_failures`). The context's hook holds the counter, not
    this object. Serve keeps this object so it can call :meth:`close` once uvicorn returns, and
    what the trailing line still held is logged rather than lost with the loop.

    A client refusing the engine's own auto-minted certificate (ADR 0172) with a TLS alert, such as
    a browser before the operator trusts it, is counted and logged at WARNING too. Kept at WARNING
    by owner ruling 2026-10-26 (vault BACKLOG #3785 item 6): the throttle bounds it. A client that
    refuses by closing the socket with no alert looks like a hang-up and is not counted.
    """

    def __init__(self, ctx: ssl.SSLContext) -> None:
        # A plain emitter, so a line is logged at once and never waits on a task that uvicorn's
        # closing loop could cancel before it ran.
        self.failures = HandshakeFailures(_log_api_handshake_failures)
        self.failures.watch(ctx)

    def close(self) -> None:
        """Stop counting, and log what the trailing line still held. Needs no running loop."""
        self.failures.close()
        held = self.failures.take_held()
        if held is not None:
            _log_api_handshake_failures(*held)


def _log_api_handshake_failures(_peer_host: str | None, reason: str) -> None:
    log.warning("TLS handshake failed on the API listener: %s", reason)


def _attach_issuer_index(ctx: ssl.SSLContext, cadata: str, cert_map: Mapping[str, object]) -> None:
    """Index the loaded client CAs on ``ctx`` for the mTLS shim, and say which map keys cannot match.

    Built from the SAME ``cadata`` the context just loaded, once, rather than per connection. The shim
    reads it back off the context (:data:`~messagefoundry.api.tls_client_cert.ISSUER_INDEX_ATTR`). A
    key that names no loaded CA, or names two with one subject (typical mid-rollover), would deny
    every certificate under it with nothing in the log, so each one is warned about here (#2237),
    as is a loaded certificate that is no CA with a loaded CA's subject
    (:meth:`~messagefoundry.pki.IssuerIndex.namesake_warnings`). Raises ``ValueError``, refusing
    the start, when :class:`~messagefoundry.pki.IssuerIndex` refuses the file; what it compares
    with the context is stated there (BACKLOG #4948)."""
    from messagefoundry.api.tls_client_cert import ISSUER_INDEX_ATTR
    from messagefoundry.pki import IssuerIndex

    index = IssuerIndex(cadata, label="[api].tls_client_ca_file")
    setattr(ctx, ISSUER_INDEX_ATTR, index)
    for key, reason in index.unmatched_keys(cert_map).items():
        log.warning("[api].tls_client_cert_identities issuer %r %s", key, reason)
    for warning in index.namesake_warnings():
        log.warning("[api].tls_client_ca_file %s", warning)


#: Filenames for the first-run generated pair, written beside the store database (BACKLOG #1276).
#: **Why there, and the alternative rejected.** That directory is already the engine's own writable
#: state (the database and its WAL live there), it is already operator-controlled via ``--db`` /
#: ``[store].path``, and it is NOT operator-authored configuration -- which is what keeps the engine
#: out of the business of editing an operator's TOML. The rejected alternative was a new
#: ``[api].tls_generated_dir`` setting: a knob for a question with one sensible answer.
_GENERATED_CERT_NAME = GENERATED_CERT_NAME
_GENERATED_KEY_NAME = "api-generated-key.pem"
#: The first-run mint's lock, beside the pair. It holds no data and is never deleted: the OS lock on
#: it is the whole mechanism (see :func:`_generated_pair_lock`), so the file is only a handle.
_GENERATED_LOCK_NAME = "api-generated.lock"
#: How long a starting engine waits for ANOTHER process's mint before it gives up. A mint is one
#: P-256 key and two small writes, so this is far past any real mint; it bounds only a hung holder.
_MINT_LOCK_TIMEOUT_S = 60.0
_MINT_LOCK_POLL_S = 0.05
#: The generated pair's lifetime, inheriting the ``cert self-signed`` CLI default rather than
#: inventing a second lifetime for the same primitive.
_GENERATED_LIFETIME_DAYS = 365


#: The loopback names a generated certificate carries for a loopback bind (BACKLOG #5790), so a
#: client on this box verifies it at whichever of them it dials where the engine listens there.
#: Never the machine's own host name: the certificate goes to every peer in the handshake, before
#: any sign-in, so it names only the bind host and names from this tuple, which say nothing about
#: the machine (decision d20261119T191457909-25c3aa).
#: Built from the set ``ApiSettings.is_loopback`` reads, so the two list the same three names;
#: sorted, so the order is fixed: ``127.0.0.1``, ``::1``, ``localhost``. Which binds count as
#: loopback here is a different, wider match (:data:`_LOOPBACK_KEYS`) than ``is_loopback``'s
#: exact spelling.
_GENERATED_LOOPBACK_SANS = tuple(sorted(_LOOPBACK_HOSTS))


def _generated_sans(host: str) -> list[str]:
    """The names a generated certificate carries beside its subject, for a bind on ``host``.

    ``host`` is ``[api].host`` as written, brackets included.

    - A WILDCARD bind (``0.0.0.0``, ``::``) is not an address any client can dial, so a
      certificate naming it alone verifies against no URL at all. It carries the loopback of its
      own family (:func:`messagefoundry.api_tls_source.wildcard_loopback`), the address the tray
      and any other client on this box reach it through (BACKLOG #5973).
    - A loopback bind carries :data:`_GENERATED_LOOPBACK_SANS` (BACKLOG #5790), less a name
      that is the same SAN entry as its own subject (:func:`_san_key`). A host is loopback when
      :func:`_host_key` matches it to one of them (:data:`_LOOPBACK_KEYS`, which
      :func:`_kept_loopback_names` uses too), so ``LOCALHOST``, ``[::1]``, ``0:0:0:0:0:0:0:1`` and
      ``localhost.`` count, and a mint and a renewal for one loopback bind agree.
    - Any other DNS host, such as ``myhost``, carries its other trailing-dot spelling,
      ``myhost.`` (or ``myhost`` for ``myhost.``), so a move between the two needs no new pair:
      Python's ``ssl`` module (OpenSSL 3.5) treats the two as distinct names, though some clients,
      such as curl and browsers, strip the dot. An IP host, ``127.0.0.2`` included, carries no
      extra name, nor does a host with a ``%``.

    :func:`_replacement_due` re-mints a reused pair that lacks a name :func:`_names_missing`
    requires, and a renewal or bind re-mint adds what :func:`_kept_loopback_names` keeps.
    """
    loopback = wildcard_loopback(host)
    if loopback is not None:
        return [loopback]
    subject = unbracketed(host)
    if _host_key(subject) not in _LOOPBACK_KEYS:
        return _other_dot_spelling(subject)
    own = _san_key(subject)
    return [name for name in _GENERATED_LOOPBACK_SANS if _san_key(name) != own]


def _other_dot_spelling(subject: str) -> list[str]:
    """``[subject]`` with its trailing dot added or dropped, for a DNS subject; else ``[]``."""
    if not subject.rstrip(".") or "%" in subject:
        return []
    try:
        ipaddress.ip_address(subject)
    except ValueError:
        return [subject[:-1] if subject.endswith(".") else subject + "."]
    return []


def _names_missing(host: str, pem: bytes) -> list[str]:
    """The names a reused certificate for a bind on ``host`` must carry and the one in ``pem``
    lacks, matched by :func:`messagefoundry.pki.san_names`: the subject and
    :func:`_generated_sans`, except that a WILDCARD bind requires only its family's loopback, the
    address a client dials, since no client dials ``0.0.0.0`` or ``::``. Raises ``ValueError`` when
    ``pem`` is not a parseable certificate."""
    from messagefoundry import pki

    subject = [] if wildcard_loopback(host) is not None else [unbracketed(host)]
    wanted = [*subject, *_generated_sans(host)]
    return [name for name in wanted if not pki.san_names(pem, name)]


def _make_generated(host: str, kept: Sequence[str] = ()) -> tuple[bytes, bytes]:
    """Mint the generated pair for a bind on ``host``: ``(cert_pem, key_pem)``. Writes nothing.

    The subject is ``host`` without IPv6 brackets (:func:`messagefoundry.api_tls_source.unbracketed`),
    so a ``[::1]`` bind is named by the IP address ``::1`` a client's hostname check compares,
    not by a DNS name spelled ``[::1]`` that matches no URL (BACKLOG #5973). The extra names come
    from :func:`_generated_sans`, read on ``host`` as written. ``kept`` adds names a replacement
    of an existing pair carries over (:func:`_renew_generated_pair`). A name that is the same SAN
    entry as one before it (:func:`_san_key`) is dropped. Raises ``ValueError`` for a host the
    certificate builder refuses.
    """
    from messagefoundry import pki

    subject = unbracketed(host)
    seen = {_san_key(subject)}
    extras: list[str] = []
    for name in [*_generated_sans(host), *kept]:
        key = _san_key(name)
        if key not in seen:
            seen.add(key)
            extras.append(name)
    return pki.make_self_signed(subject, extras, _GENERATED_LIFETIME_DAYS)


def _host_key(name: str) -> object:
    """``name`` matched loosely: an IP by address without an IPv6 zone, so ``0:0:0:0:0:0:0:1`` is
    ``::1``, and a DNS name without regard to case or a trailing dot. It decides which binds count
    as loopback (:data:`_LOOPBACK_KEYS`), and in :func:`_kept_loopback_names` which loopback name
    the bind itself names, so a ``localhost.`` bind keeps no ``localhost`` there and gets it from
    :func:`_generated_sans` instead. :func:`_san_key` is the exact SAN entry."""
    try:
        return ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        return name.rstrip(".").lower()


#: The loopback names as :func:`_host_key` matches them: a bind whose subject has one of these
#: keys is a loopback bind for the generated certificate (:func:`_generated_sans`,
#: :func:`_kept_loopback_names`).
_LOOPBACK_KEYS = frozenset(_host_key(name) for name in _GENERATED_LOOPBACK_SANS)


def _san_key(name: str) -> object:
    """``name`` as the SAN entry ``make_self_signed`` writes for it: an IP literal by address
    without an IPv6 zone, which the entry cannot carry, so ``0:0:0:0:0:0:0:1``, ``::1`` and
    ``::1%1`` are one entry; anything else, ``127.0.0.1%x`` included, as a DNS name without regard
    to case, with a trailing dot significant, as Python's ``ssl`` module (OpenSSL 3.5) compares
    it."""
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return name.lower()
    return ipaddress.ip_address(str(address).split("%", 1)[0])


def _kept_loopback_names(host: str, old_pem: bytes) -> list[str]:
    """The loopback names a replacement of a loadable pair keeps (BACKLOG #5973).

    Only for a bind a client on this box dials through one of ``localhost``, ``127.0.0.1`` and
    ``::1``, matched by :func:`_host_key` (:data:`_LOOPBACK_KEYS`): of those three, every one the
    old certificate names, and the default ``[api].host``, which the CLI, the IDE and the harness
    dial by default, less the one the bind itself names. A loopback bind gets all three from
    :func:`_generated_sans` anyway, so this matters for a wildcard bind: a re-mint for a move from
    ``::`` to ``0.0.0.0`` keeps the ``::1`` the old certificate named, and a renewal at ``::`` of a
    pair minted for ``::1`` keeps its ``127.0.0.1`` and ``localhost``. A renewal keeps
    them as a bind re-mint does, or the next renewal would drop what the re-mint kept. The set is
    fixed, so repeated moves do not grow it. A bind off loopback keeps nothing. A first-run mint
    has no old certificate, so it keeps nothing.
    """
    from messagefoundry import pki

    dialled = _host_key(dialled_host(host))
    if dialled not in _LOOPBACK_KEYS:
        return []
    default = ApiSettings.model_fields["host"].default
    return [
        name
        for name in _GENERATED_LOOPBACK_SANS
        if _host_key(name) != dialled and (name == default or pki.san_names(old_pem, name))
    ]


#: Renew the generated pair at startup once less than this share of its OWN validity period is
#: left: about 122 of 365 days (ADR 0172, 2026-09-26 amendment). Early rather than at expiry, so a
#: renewal lands at an ordinary restart months before any client could see an expired certificate.
#: The expiry monitor stays the backstop for an engine that is never restarted.
_RENEW_REMAINING_FRACTION = 1 / 3
#: Suffix of the new pair while it is staged beside the live one, before the two replaces.
_STAGED_SUFFIX = ".renewing"
#: Suffix of the copy of the live certificate a replacement keeps until its key is in place, so a
#: failed key replace can put the old certificate back beside the old key (BACKLOG #5973).
_PRIOR_SUFFIX = ".prior"

#: Why a loadable generated pair is replaced at startup (:func:`_replacement_due`), and why any
#: existing pair is (:class:`GeneratedPairReplaced`).
_DueReason = Literal["renewal", "bind_changed"]
_ReplacedReason = Literal["renewal", "bind_changed", "unusable", "half_pair"]
#: Why, the old certificate's facts, and its PEM, read once.
type _Due = tuple[_DueReason, SelfSignedFacts, bytes]

#: The audit action for every replacement of a generated pair that already existed: an early
#: renewal, a re-mint of a pair that lacks a name the bind needs (BACKLOG #5973), and the recovery
#: of an unusable or half-written pair (ADR 0172 decision 6).
GENERATED_PAIR_REPLACED = "api.tls_generated_pair_replaced"


@dataclass(frozen=True)
class GeneratedPairReplaced:
    """One replacement of the generated pair, for the audit record ``serve`` writes once the store
    is open. :func:`ensure_api_tls_material` runs before the store exists, so it reports the event
    rather than recording it.

    Public facts only: SHA-256 fingerprints and expiry dates of certificates every client receives
    in the handshake. Never key material. ``old_*`` is ``None`` when the old certificate could not be
    parsed, or was the missing half of a half-written pair.
    """

    #: ``renewal``: a loadable pair near or past its expiry. ``bind_changed``: a loadable pair whose
    #: certificate lacks a name the current ``[api].host`` requires (:func:`_names_missing`),
    #: such as the ``::1`` of a bind moved to ``::`` after the mint (BACKLOG #5973, #5790).
    #: ``unusable``: a pair that would not load as one. ``half_pair``: one file of the two, left
    #: by an interrupted mint or renewal.
    reason: _ReplacedReason
    cert_file: str
    old_sha256: str | None
    old_not_after: str | None
    new_sha256: str
    new_not_after: str

    def audit_detail(self) -> str:
        return json.dumps(
            {
                "reason": self.reason,
                "cert_file": self.cert_file,
                "old_sha256": self.old_sha256,
                "old_not_after": self.old_not_after,
                "new_sha256": self.new_sha256,
                "new_not_after": self.new_not_after,
            },
            sort_keys=True,
        )


async def record_generated_pair_replacements(
    store: Store, events: Sequence[GeneratedPairReplaced]
) -> None:
    """Write one hash-chained ``api.tls_generated_pair_replaced`` audit row per event.

    Called from the serve lifespan as soon as the store is open, before any listener binds.
    **A failed write does not stop the engine**, because it cannot undo anything: the pair on disk
    is already the new one, and the next start finds it fresh and reports nothing. So the failure is
    logged at ERROR with the whole record, which keeps the replacement from being silent.
    ``defects=()`` for the same reason: nothing here may stop the start (vault BACKLOG #2260).
    """
    for event in events:
        detail = event.audit_detail()
        await write_audit_soft(
            # Awaited in this pass, so the late binding B023 warns about cannot bite. A lambda, not
            # a partial, keeps the lookup of record_audit inside the guard.
            lambda: store.record_audit(GENERATED_PAIR_REPLACED, actor=None, detail=detail),  # noqa: B023
            log=log,
            message="could not write the %s audit row; the record is: %s",
            args=(GENERATED_PAIR_REPLACED, detail),
            defects=(),
        )


def _generated_pair(state_dir: Path) -> tuple[Path, Path]:
    """The ``(cert, key)`` paths of the first-run generated pair. The only place they are spelled."""
    return state_dir / _GENERATED_CERT_NAME, state_dir / _GENERATED_KEY_NAME


def generated_state_dir(store_path: str) -> Path:
    """Where the engine keeps its own writable state: the directory holding the store database.

    Named here rather than spelled at each call site, because it is the rule a CLIENT must not have
    to know -- and it was already written twice (the serve path and the ``cert inventory`` reporter)
    before it had a name.
    """
    return Path(store_path).resolve().parent


# ApiTlsSource and api_tls_source live in messagefoundry.api_tls_source, the stdlib leaf the
# tray shares, and are re-exported from here.


def plaintext_upstream_hop_unacknowledged(api: ApiSettings) -> bool:
    """True when ``serve`` refuses to start on BACKLOG #1179: the engine serves the proxy-to-engine
    hop in plaintext (``api_tls_source`` is ``upstream``) and no operator has acknowledged it.

    One predicate for both callers, ``serve`` and the ``upstream-hop-ack`` leg of
    ``messagefoundry check``, so the refusal and the gate agree by construction.
    """
    return api.serves_plaintext_upstream_hop and not api.plaintext_upstream_hop_acknowledged


def plaintext_upstream_hop_off_loopback(api: ApiSettings) -> bool:
    """True when ``serve`` refuses to start on BACKLOG #4636: the engine serves the proxy-to-engine
    hop in plaintext and binds a host that is not loopback, so that hop would cross a network.

    The acknowledgement accepts the plaintext hop only from a proxy on the same machine, with the
    engine bound to loopback (owner ruling R1 of 2026-10-27 on BACKLOG #1179). Off loopback no
    acknowledgement covers it, so this is decided without reading one, and ``serve`` checks it
    before :func:`plaintext_upstream_hop_unacknowledged`: an operator is never told to set an
    acknowledgement that would then be refused. An operator ``tls_cert_file`` makes the hop TLS,
    so it is not refused here.

    Loopback is :attr:`ApiSettings.is_loopback`, the definition the exposed-bind gate reads: the
    exact hosts ``127.0.0.1``, ``::1`` and ``localhost``. Any other spelling, another
    ``127.0.0.0/8`` address and the empty host included, is refused. ``localhost`` is taken as a
    name, unresolved, so a hosts file that maps it off the box is not seen here.

    Shared by ``serve``'s exposed-bind gate and the ``upstream-hop-ack`` leg of
    ``messagefoundry check``.
    """
    return api.serves_plaintext_upstream_hop and not api.is_loopback


def plaintext_upstream_hop_off_loopback_remedy(loopback_lever: str) -> str:
    """The two ways out of the :func:`plaintext_upstream_hop_off_loopback` refusal, as one sentence.

    ``serve`` and the ``upstream-hop-ack`` check leg both print it. ``loopback_lever`` names how to
    bind loopback: ``serve`` adds ``serve --host``, which the check cannot see. The certificate remedy names the revocation
    attestation because off loopback that bind is in-process TLS (docs/SECURITY.md, *API revocation
    gate*)."""
    return (
        f"Either bind the engine to loopback ({loopback_lever}) behind a proxy on the same "
        "machine and set [api].plaintext_upstream_hop_acknowledged = true, or "
        f"{off_loopback_certificate_remedy()}, and point the proxy at https"
    )


def off_loopback_certificate_remedy() -> str:
    """The certificate half of an off-loopback API remedy, as one clause: an operator certificate
    AND, because off loopback that bind meets the API revocation gate, the attestation. The two
    steps are joined inside the clause so a caller's own "either ... or" list cannot split them.
    Every refusal that prescribes a certificate uses it: at least the two exposed-bind refusals,
    :func:`plaintext_upstream_hop_off_loopback_remedy`, the /ui refusal and warnings in ``serve``,
    and the PHI-read 403. Keep it free of any proxy step, since most of them have no proxy."""
    return (
        "set [api].tls_cert_file (and [api].tls_key_file unless the key is in that PEM) and set "
        f"{TLS_REVOCATION_ATTESTED_ENV}=1 in serve's environment"
    )


@dataclass(frozen=True)
class ApiTlsPlan:
    """What the API bind **will** serve with, decided without reading or writing a single file.

    This is the branch order of :func:`ensure_api_tls_material` lifted out so a caller that must not
    mint can still answer the two questions a CLIENT has: *which scheme does this engine speak*, and
    *which certificate will it present*. Both were previously derivable only by re-implementing the
    predicate, and each re-implementation got it wrong in its own way -- keying the scheme on
    ``[api].tls_cert_file`` alone reads the SHIPPED DEFAULT as cleartext (BACKLOG #1126), and a
    client with no idea where the generated pair lands cannot trust it at all (BACKLOG #1695).

    **The ordering is declared once**, in :func:`messagefoundry.api_tls_source.api_tls_source`,
    a stdlib leaf. The tray reads it from there over a raw service-TOML dict, because by ADR 0113
    it may not import this module, which pulls pydantic and the settings package in.
    """

    source: ApiTlsSource
    #: The certificate the bind will present, **whether or not it exists yet** -- for ``generated``
    #: this is the path the engine mints to on its first run. ``None`` only for ``upstream``.
    cert_file: str | None
    key_file: str | None

    @property
    def scheme(self) -> Literal["http", "https"]:
        """The scheme the engine's OWN bind serves.

        ``http`` only for a DECLARED upstream terminator: the proxy holds the protected hop and the
        engine speaks plaintext behind it. That hop is the deploying site's to secure, so ``serve``
        requires a loopback bind and ``[api].plaintext_upstream_hop_acknowledged`` for it
        (BACKLOG #4636) and ``security_loosenings()``
        lists it (BACKLOG #1179). A client that hardcodes https breaks exactly that topology, which
        is why this is reported rather than assumed.
        """
        return "http" if self.source == "upstream" else "https"

    def material(self) -> tuple[str, str | None] | None:
        """The pair in :func:`ensure_api_tls_material`'s shape, or ``None`` for an upstream proxy."""
        return None if self.cert_file is None else (self.cert_file, self.key_file)


def plan_api_tls_material(api: ApiSettings, *, state_dir: Path) -> ApiTlsPlan:
    """Decide the API bind's TLS posture **without touching the disk** -- see :class:`ApiTlsPlan`.

    Pure: it neither mints, reads, nor stats anything, so it is safe on a read-only path (the
    ``cert inventory`` reporter) and safe to call before the engine has ever run.
    :func:`ensure_api_tls_material` consumes it, so the engine's own material is decided once.
    """
    source = api_tls_source(
        cert_file=api.tls_cert_file, tls_terminated_upstream=api.tls_terminated_upstream
    )
    if source == "operator":
        # Pass tls_key_file through UNCHANGED, None included -- see ensure_api_tls_material.
        return ApiTlsPlan(source, api.tls_cert_file, api.tls_key_file)
    if source == "upstream":
        return ApiTlsPlan(source, None, None)
    cert_path, key_path = _generated_pair(state_dir)
    return ApiTlsPlan(source, str(cert_path), str(key_path))


def _discard_half_minted_pair(cert_path: Path, key_path: Path) -> None:
    """Remove a lone half of a previously generated pair, so the mint that follows can re-run.

    Called only under :func:`_generated_pair_lock`, once the reuse branch has established that BOTH
    files are not present, so at most one of these exists. The lock is what makes "a lone half" mean
    DEBRIS: without it, a lone key could be another process's mint in progress (BACKLOG #1276).

    A half-pair is unusable -- reuse needs both -- and the key half is also a TRAP: the mint falls
    through, :func:`_write_private_key`'s ``O_EXCL`` refuses the surviving key, and the engine
    fails to start. On EVERY start, permanently, naming no file to delete. ADR 0172
    makes the generated pair the default first-run path, so that is a fresh deployment that never
    comes up rather than an edge case.

    **This is the durable half of the fix, and the ``try/finally`` around the mint is not.** That
    guard unwinds an EXCEPTION. It does not run on a SIGKILL, a power loss, or an OOM kill, and each
    of those leaves exactly the same half-pair. Recovery therefore cannot hang off the failure; it
    has to sit on the path that runs next, which is this one. Attaching it here also makes the
    recovery indifferent to how the half-pair arose, which is the property that matters, since the
    causes are not enumerable.

    **Deleting a private key is safe here and only here.** An operator-supplied ``tls_cert_file``
    returned far above, so operator material never reaches this function; these are the engine's own
    fixed generated names under its own state dir, and a lone one is engine-written debris by
    construction. It is still logged at warning, because a deleted key must never be silent.
    """
    for orphan in (cert_path, key_path):
        if not orphan.exists():
            continue
        log.warning(
            "discarding a half-minted TLS pair: %s exists without its counterpart, so it is "
            "unusable and would refuse every later start. Re-minting both.",
            orphan,
        )
        unlink_generated(orphan)


def _replace_generated(staged: Path, live: Path) -> None:
    """Move a staged file over its live name, riding out a brief Windows hold on the live file.

    ``os.replace`` is atomic on one volume, and the staged file sits in the same directory, so a
    reader sees the old file or the new one, never a partial one. On NTFS the rename keeps the staged
    file's own access list, which is why the key's DACL and the cert's local-users grant are applied
    BEFORE the replace rather than after it.
    """
    replace_generated(staged, live)


def _why_generated_pair_is_unusable(cert_path: Path, key_path: Path) -> str | None:
    """``None`` when the two files load as ONE serving pair, else the TLS layer's reason why not.

    The predicate is the serving path's own: ``load_cert_chain`` is what uvicorn calls, and it
    refuses a certificate whose public key is not the key's (``KEY_VALUES_MISMATCH``), a truncated
    PEM, and an empty file. Checking presence alone is what let a mismatched pair be reused on every
    start while every start failed to serve it (BACKLOG #1276).

    **Only a CONTENT refusal is reported.** ``ssl.SSLError`` means the bytes are wrong. Any other
    ``OSError`` -- a denied read, a sharing violation -- says nothing about the bytes, so it
    propagates: a key the engine merely failed to READ must never be treated as one it may delete.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        # The empty-bytes password callback: fail deterministically rather than prompt on a TTY,
        # as build_api_ssl_context does. The engine never writes an encrypted generated key.
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path, password=lambda: b"")
    except ssl.SSLError as exc:
        return str(exc)
    return None


def _discard_unusable_pair(cert_path: Path, key_path: Path, reason: str) -> None:
    """Remove a complete but unusable generated pair, so the mint that follows can replace it.

    Reached only under :func:`_generated_pair_lock`, with both files present and
    :func:`_why_generated_pair_is_unusable` naming a content refusal. **This is not a renewal.** A
    pair that loads is never discarded here (renewal is :func:`_renew_generated_pair`); this one
    cannot serve, and reusing it failed every start until someone deleted it by hand. The mismatched
    shape is exactly what two processes minting into one state dir used to leave (BACKLOG #1276), a
    renewal interrupted between its two replaces leaves it too, and a disk fault can leave the others.

    Logged at WARNING, per ADR 0172 decision 6: replacing a key on disk is never silent. The reason
    is the TLS layer's error text, which names the refusal and carries no key material.
    """
    log.warning(
        "discarding an unusable generated TLS pair at %s and %s: they do not load as one serving "
        "pair (%s). Re-minting both.",
        cert_path,
        key_path,
        reason,
    )
    # Cert first. Should the key's unlink still fail, a lone key is left, which the next start
    # discards as a half-pair, so no ordering leaves anything a later start cannot recover.
    unlink_generated(cert_path)
    unlink_generated(key_path)


@contextmanager
def _generated_pair_lock(state_dir: Path) -> Iterator[None]:
    """Hold the ONE-WRITER lock for the generated pair in ``state_dir``, waiting a bounded time.

    **Why the pair needs one.** ``supervise`` starts N engine processes that all derive the
    same state dir, so on a first run they all find no pair at once. Unserialised, one process won
    the key's ``O_EXCL`` create and every other died with ``FileExistsError``; worse, a process
    arriving between another's key and cert writes read a lone key as debris, deleted it, and minted
    its own, and the first then overwrote that cert, leaving a mismatched pair that failed every
    later start.
    Under this lock exactly one process mints, and every other waits, then reuses that pair.

    **One shared pair for all shards** is what this keeps, and it is correct: the minted identity is
    ``[api].host`` and shards differ only by port. The lock does not choose it over one pair per
    shard; it removes the crash and the corruption from the answer the shared state dir already
    gave.

    Raises ``TimeoutError`` naming the lock file when a holder outlives
    :data:`_MINT_LOCK_TIMEOUT_S`, rather than waiting forever on a hung process.
    """
    lock_path = state_dir / _GENERATED_LOCK_NAME
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        deadline = time.monotonic() + _MINT_LOCK_TIMEOUT_S
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"{lock_path} has been held for over {_MINT_LOCK_TIMEOUT_S:g}s by another "
                    "start minting the API's TLS pair; if no other engine start is running, the "
                    "holder is hung -- stop it and start again"
                )
            time.sleep(_MINT_LOCK_POLL_S)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)


#: BUILTIN\Users, by SID so the grant does not depend on the host's display language.
_LOCAL_USERS_SID = "*S-1-5-32-545"


def _let_local_users_read_cert(cert_path: Path) -> None:
    """Grant local users READ on the minted CERTIFICATE, so a local client can pin it. Never the key.

    ``scripts/service/install-service.ps1`` locks the data directory to SYSTEM, Administrators and
    the service account, and the pair is minted there. The tray runs as the logged-on user with a
    filtered token, so without this it cannot read the file it has to pin, and it reads a running
    engine as down. The certificate is public: every client that connects receives it in the TLS
    handshake, so letting local users read it discloses nothing. The key stays restricted, as
    :func:`_write_private_key` created it.

    Windows only, because the tray is. Best-effort, like ``store._secure_file``: a failed grant is
    logged and never stops the engine. The grant is ADDITIVE and names only this file; the
    directory's ACL is untouched. It runs through ``store._grant_read``, the existing ``icacls``
    site, so this module spawns no process of its own.
    """
    from messagefoundry.store.store import _grant_read

    _grant_read(cert_path, _LOCAL_USERS_SID)


def ensure_api_tls_material(
    api: ApiSettings,
    *,
    state_dir: Path,
    replacements: list[GeneratedPairReplaced] | None = None,
    renew: bool = True,
) -> tuple[str, str | None] | None:
    """Return the ``(cert_path, key_path)`` the API should serve with, minting on first run.

    **``key_path`` is ``None`` when the operator embedded the key in the cert PEM.** That is a
    supported configuration (``[api].tls_key_file`` is optional -- see :class:`ApiSettings` and
    :func:`build_api_ssl_context`), and the ``None`` must survive all the way to
    ``ssl.load_cert_chain(keyfile=...)``, which reads a combined PEM only when keyfile is ``None``.
    Substituting ``""`` for it raises ``OSError: [Errno 22] Invalid argument`` instead, so an
    operator with a combined PEM could not start the engine at all. A minted pair is always two
    files, so that branch returns a real path.

    **The engine always serves TLS (owner ruling 2026-08-22, superseding ADR 0143's cleartext
    loopback premise).** An operator-supplied ``[api].tls_cert_file`` always wins -- this is a
    fallback BENEATH it, never a replacement -- so a site that configures its own chain sees no
    behaviour change and this function is not even consulted.

    **Returns ``None`` when a reverse proxy terminates TLS upstream.** Which of the three postures
    applies is :func:`plan_api_tls_material`'s decision, not this function's -- this one adds only
    the minting, so a read-only caller can ask the same question without writing a key.

    **Mint once, reuse while fresh, renew early (ADR 0172, 2026-09-26 amendment).** The pair is
    written with :func:`_write_private_key`'s ``O_EXCL`` + ``0o600`` + Windows-DACL sequence, which
    REFUSES to overwrite, so a start that finds a fresh pair loads it and writes nothing. A pair
    with less than a third of its lifetime left, or past it, is RENEWED at startup -- see
    :func:`_renew_generated_pair` -- but only when it is still the engine's own shape (self-signed,
    ``CA=false``). Anything else at the generated path is served as found and never replaced.
    **A pair of that shape whose certificate lacks a name the current bind requires
    (:func:`_names_missing`) is replaced the same way**, the report's reason
    ``bind_changed``: for example the loopback of a wildcard bind (:func:`_replacement_due`,
    BACKLOG #5973, #5790). Only the engine's own
    generated pair is ever checked; an operator's ``[api].tls_cert_file`` never reaches this
    branch. Nothing renews mid-run: ``CertExpiryRunner`` watches the served certificate, because
    ``serve`` hands it the path this function RETURNS, and it stays the alarm for an engine never
    restarted.

    **``renew=False`` is for an engine shard (``serve --shard``).** It skips the bind check too.
    Every process that serves the pair must start together when it is renewed, or a lone restarted shard would serve a new
    certificate while its siblings keep the old one in memory. So ``supervise`` renews before it
    spawns any shard, and a shard only reuses a pair that loads, due or not. It still mints on a
    first run and still recovers a pair that does not load, because it has nothing else to serve.
    **A file or lock failure never costs a start the old pair can still serve**: any ``OSError`` on
    the locked path -- including a lock it could not take -- falls back to that pair with a WARNING,
    and only a pair that does not load or has expired lets the error propagate. Other errors, such
    as a ``[api].host`` the certificate builder refuses on a first mint or a renewal, still stop
    the start; refused on a re-mint for a changed bind, it keeps the old pair with a WARNING.

    **EVERY REPLACEMENT IS REPORTED, never silent (ADR 0172 decision 6).** At least a renewal, a
    re-mint of a pair that lacks a name the bind needs, and the recovery of an unusable or
    half-written pair each append one :class:`GeneratedPairReplaced` to
    ``replacements`` and log a WARNING. ``serve`` passes a list and writes one audit row per entry
    once its store is open (:func:`record_generated_pair_replacements`). A first-run mint, which
    replaces nothing, reports nothing. **The row needs that start to reach its store**: a start that
    fails in between leaves the WARNING line as the only record, because the next start finds a
    fresh pair and has nothing to report.

    **ONE WRITER (BACKLOG #1276).** Every ``supervise`` shard shares this state dir, so any
    discard, mint and renewal runs under :func:`_generated_pair_lock`, after the reuse check is
    repeated there. A process that loses the race waits, then reuses the winner's pair; it neither
    crashes, nor deletes a key another process is still writing, nor renews a second time. A fresh
    pair that loads is reused before the lock is taken (:func:`_reusable_without_the_lock`).

    **REUSE MEANS THE PAIR LOADS, not that two files exist.** A pair that fails
    :func:`_why_generated_pair_is_unusable` (a cert that is not the key's, a truncated file) is
    discarded with a WARNING and re-minted -- see :func:`_discard_unusable_pair`. That is also how a
    renewal interrupted between its two replaces recovers: a new cert beside an old key does not load.

    **A HALF-PAIR IS THE OTHER EXCEPTION, and it re-mints rather than refusing** -- see
    :func:`_discard_half_minted_pair`. Reuse needs BOTH files, so one alone is unusable AND a trap:
    the O_EXCL refusal above would fire on the survivor at every later start, permanently.

    **The generated certificate is a PLACEHOLDER TO BE REPLACED, not an endorsed production
    terminator.** It is self-signed, so it carries no chain of trust: strictly better than
    cleartext, strictly worse than an operator-supplied chain. A browser reaching the console gets
    a trust interstitial until it is imported (``docs/TRAY.md`` documents that import), and that
    import must be repeated after a renewal, because the renewed certificate is a new one.
    """
    # The branch order lives in plan_api_tls_material, so the read-only reporter and the minting
    # path cannot disagree about which certificate the bind presents. Two of the three branches
    # need no disk at all: an operator's material is passed through UNCHANGED (tls_key_file's None
    # included -- see the key_path note above), and behind a DECLARED UPSTREAM TERMINATOR minting
    # would break the proxy's own plaintext hop rather than harden anything. That hop is plaintext
    # and the engine does nothing to protect it, so serve accepts it only on a loopback bind with
    # an acknowledgement (docs/SECURITY.md, Plaintext proxy hop). "Always serves TLS" means the
    # engine mints wherever no operator certificate or terminator is configured, NOT that it
    # terminates TLS in every topology. Neither branch is ever renewed.
    plan = plan_api_tls_material(api, state_dir=state_dir)
    if plan.source != "generated":
        return plan.material()

    cert_path, key_path = _generated_pair(state_dir)
    if _reusable_without_the_lock(api.host, cert_path, key_path, renew=renew):
        return str(cert_path), str(key_path)
    events = replacements if replacements is not None else []
    try:
        _make_state_dir(state_dir)
        with _generated_pair_lock(state_dir):
            _settle_under_the_lock(api, cert_path, key_path, events, renew=renew)
    except OSError as exc:
        # A RENEWAL IS EARLY, SO ITS FAILURE MUST NOT STOP A START THE OLD PAIR CAN SERVE. That
        # covers a failed stage or first replace, a state dir the engine may read but not write,
        # and a lock held past its timeout. A pair that does not load, or has expired, has
        # nothing to fall back on, so then the error propagates.
        if not _still_serves(cert_path, key_path):
            raise
        current = _cert_facts(cert_path)
        log.warning(
            "could not check or renew the generated TLS pair at %s (%s); serving the current "
            "certificate, which expires %s, and the next start tries again.",
            cert_path,
            exc,
            "at an unknown date" if current is None else log_timestamp(current.not_after_iso),
        )
    return str(cert_path), str(key_path)


def _make_state_dir(state_dir: Path) -> None:
    """Make the state dir if it is missing. On POSIX the directory this creates is ``0o755`` at
    most, whatever the umask: no group or other account may write it, because the key-file check
    refuses the generated key in a directory they may (vault BACKLOG #5636). It stays readable, so
    a client running as another account can still read the certificate it pins. A missing parent
    above it gets the umask's mode. On Windows no mode is passed, so the directory inherits its
    parent's access list, which a mode would replace with a protected one. An existing directory is
    left as it is, and the generated-key gate in ``serve`` and ``supervise`` judges it."""
    if sys.platform == "win32":
        state_dir.mkdir(parents=True, exist_ok=True)
    else:
        state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)


def _settle_under_the_lock(
    api: ApiSettings,
    cert_path: Path,
    key_path: Path,
    events: list[GeneratedPairReplaced],
    *,
    renew: bool,
) -> None:
    """Reuse, renew, recover or mint the generated pair. Call only under the lock.

    Re-decided here: a process that waited for the lock finds the pair the holder just minted or
    renewed, and reuses it. Only here may a failed check lead to a discard.
    """
    _discard_staged_leftovers(cert_path, key_path)
    if cert_path.exists() and key_path.exists():
        reason = _why_generated_pair_is_unusable(cert_path, key_path)
        if reason is None:
            due = _replacement_due(api.host, cert_path) if renew else None
            if due is not None:
                _renew_generated_pair(api, cert_path, key_path, due, events)
            return
        old = _cert_facts(cert_path)
        _discard_unusable_pair(cert_path, key_path, reason)
        recovered: Literal["unusable", "half_pair"] | None = "unusable"
    else:
        old = _cert_facts(cert_path) if cert_path.exists() else None
        recovered = "half_pair" if cert_path.exists() or key_path.exists() else None
        _discard_half_minted_pair(cert_path, key_path)
    new = _mint_generated_pair(api, cert_path, key_path)
    if recovered is not None:
        events.append(_replaced(recovered, cert_path, old, new))


def _still_serves(cert_path: Path, key_path: Path) -> bool:
    """True when the pair on disk loads as one and has not expired. Never raises."""
    try:
        if _why_generated_pair_is_unusable(cert_path, key_path) is not None:
            return False
    except OSError:
        return False
    facts = _cert_facts(cert_path)
    return facts is None or facts.not_after > time.time()


def _reusable_without_the_lock(host: str, cert_path: Path, key_path: Path, *, renew: bool) -> bool:
    """True when the pair loads and, if ``renew``, is not due for replacement, read WITHOUT the lock.

    Every other answer is ``False``, and the caller then decides again under the lock. A read that
    races a mint or renewal in progress sees a partial, vanishing or mismatched file and answers
    ``False``, so nothing here raises and nothing here deletes. The point of reading first is that
    the common start -- a fresh pair minted long ago -- needs no write access to the state dir and no
    OS lock support, which is what it needed before the lock existed.

    A certificate at the generated path that is NOT the engine's shape is never due, so a pair
    holding one is reused here as found, with the WARNING :func:`_replacement_due` logs when it is
    near or past expiry. Nothing is ever written for it, so it needs no lock.
    """
    try:
        return (
            cert_path.exists()
            and key_path.exists()
            and _why_generated_pair_is_unusable(cert_path, key_path) is None
            and (not renew or _replacement_due(host, cert_path) is None)
        )
    except OSError:
        return False


def _cert_facts(cert_path: Path) -> SelfSignedFacts | None:
    """The certificate's public facts, or ``None`` when it cannot be read or parsed."""
    from messagefoundry import pki

    try:
        return pki.read_self_signed_facts(cert_path.read_bytes())
    except (OSError, ValueError):
        return None


def _replacement_due(host: str, cert_path: Path) -> _Due | None:
    """Why the generated pair should be replaced now, with the old certificate's facts, else ``None``.

    ``renewal`` means expired, or less than :data:`_RENEW_REMAINING_FRACTION` of the certificate's
    own validity period left. ``bind_changed`` means the certificate lacks a name ``host`` requires
    (:func:`_names_missing`), among them the host a client dials for it
    (:func:`messagefoundry.api_tls_source.dialled_host`). So a bind moved after the mint, for
    example to ``::`` from ``0.0.0.0``, or to ``127.0.0.1`` from ``0.0.0.0``, gets a fresh
    certificate for the new bind at this start rather than at the next renewal (BACKLOG #5973,
    #5790). The new pair names the new bind, as a first-run mint for it would, plus the loopback
    names :func:`_kept_loopback_names` keeps, so the next start finds nothing missing and reuses
    it.

    **Only the engine's own shape is ever due**: a certificate at the generated path that is not
    self-signed with ``CA=false`` was put there by someone else, so it is served as found. That
    case is logged at WARNING when it is near or past expiry, because a certificate left to expire
    beside the store deserves a reason in the log. ``None`` too when the certificate cannot be
    parsed, since nothing here may replace what it cannot identify.
    """
    from messagefoundry import pki

    try:
        pem = cert_path.read_bytes()
        facts = pki.read_self_signed_facts(pem)
    except (OSError, ValueError):
        return None
    lifetime = facts.not_after - facts.not_before
    expiring = facts.not_after - time.time() < lifetime * _RENEW_REMAINING_FRACTION
    if not facts.engine_shaped:
        if not expiring:
            return None
        log.warning(
            "not renewing %s: it expires %s, but it is not a self-signed certificate the engine "
            "generated, so the engine leaves it alone. Replace it yourself, or set "
            "[api].tls_cert_file.",
            cert_path,
            log_timestamp(facts.not_after_iso),
        )
        return None
    if expiring:
        return "renewal", facts, pem
    if _names_missing(host, pem):
        return "bind_changed", facts, pem
    return None


def _staged_files(cert_path: Path, key_path: Path) -> tuple[Path, Path, Path]:
    """Where a renewal writes the new pair before moving it over the live one, and where it keeps a
    copy of the live certificate until the new key is in place: ``(cert, key, prior cert)``."""
    return (
        cert_path.with_name(cert_path.name + _STAGED_SUFFIX),
        key_path.with_name(key_path.name + _STAGED_SUFFIX),
        cert_path.with_name(cert_path.name + _PRIOR_SUFFIX),
    )


def _discard_staged_leftovers(cert_path: Path, key_path: Path) -> None:
    """Remove the files a renewal that died left beside the pair. Only under the lock.

    Under the lock no renewal is running, so a staged file is debris. The staged key must go before
    the next renewal, whose ``O_EXCL`` write would otherwise refuse it on every later start.
    """
    for leftover in _staged_files(cert_path, key_path):
        # A dangling link answers exists() False, and a later write would follow it.
        if leftover.is_symlink() or leftover.exists():
            log.warning("discarding %s, left by an interrupted certificate renewal", leftover)
            unlink_generated(leftover)


def _remove_quietly(*paths: Path) -> None:
    """Remove each path that exists, logging a failure rather than raising it, so a cleanup never
    masks the error that called for it. The next start's locked pass discards what is left."""
    for leftover in paths:
        try:
            if leftover.is_symlink() or leftover.exists():
                unlink_generated(leftover)
        except OSError as cleanup:
            log.warning("could not remove %s after a certificate renewal: %s", leftover, cleanup)


def _renew_generated_pair(
    api: ApiSettings,
    cert_path: Path,
    key_path: Path,
    due: _Due,
    events: list[GeneratedPairReplaced],
) -> None:
    """Replace a loadable generated pair that is due, with a new key and certificate. Lock held.

    ``due`` is :func:`_replacement_due`'s answer: why, and the old certificate's facts. A replacement
    for a changed bind takes this same path, so its key is written exactly as a renewal's is.

    **Staged, then replaced, certificate first.** The new key is written under a temporary name with
    :func:`_write_private_key` (``O_EXCL``, ``0o600``, Windows DACL) and the new certificate beside it,
    with the local-users read grant the tray needs. Only then are they moved over the live names.
    The certificate goes first because it is the file other processes hold open, so it is the replace
    most likely to be refused, and a refusal there has changed nothing.

    **A renewal that fails before the first replace has changed nothing.** The staged files are
    removed and the error propagates; :func:`ensure_api_tls_material` then keeps the old pair if it
    still serves, and the next start tries again. **A failure BETWEEN the two replaces is rolled
    back** (BACKLOG #5973): a copy of the old certificate, staged with the new pair, is moved back
    over the new one, so the old certificate is again beside the old key, which the failed replace
    never moved. The rollback is logged at ERROR and the error propagates to the same fallback. Only
    if the rollback fails too is a new certificate left beside the old key; that start fails, and
    the next one discards and re-mints it as an unusable pair, and reports that.

    A renewal and a re-mint for a changed bind both keep the loopback names
    :func:`_kept_loopback_names` gives.
    """
    from messagefoundry import pki
    from messagefoundry.__main__ import _write_private_key

    reason, old, old_pem = due
    staged_cert, staged_key, prior_cert = _staged_files(cert_path, key_path)
    try:
        cert_pem, key_pem = _make_generated(api.host, _kept_loopback_names(api.host, old_pem))
    except ValueError as exc:
        # A RE-MINT FOR A CHANGED BIND IS NEVER WORTH A START (BACKLOG #5973). The old pair still
        # loads and is fresh, so a host the certificate builder refuses (a CN over 64 characters,
        # an empty host) keeps serving it, as it did before the bind check existed. Nothing has
        # been written yet. A renewal has no such fallback here, so its refusal still propagates.
        if reason != "bind_changed":
            raise
        log.warning(
            "serving the generated TLS certificate at %s, which does not name %s, needed for the "
            "bind %r: a new certificate for that bind was refused (%s). Clients that verify those "
            "names will fail until the bind or [api].tls_cert_file is fixed.",
            cert_path,
            ", ".join(repr(name) for name in _names_missing(api.host, old_pem)),
            api.host,
            type(exc).__name__,
        )
        return
    new = pki.read_self_signed_facts(cert_pem)
    try:
        _write_private_key(staged_key, key_pem)
        staged_cert.write_bytes(cert_pem)
        _let_local_users_read_cert(staged_cert)
        # The old certificate's bytes, read under this lock, with the grant the live one carries.
        prior_cert.write_bytes(old_pem)
        _let_local_users_read_cert(prior_cert)
        _replace_generated(staged_cert, cert_path)
    except OSError:
        _remove_quietly(staged_cert, staged_key, prior_cert)
        raise
    try:
        _replace_generated(staged_key, key_path)
    except OSError as exc:
        # A failed move back keeps both files, the only halves that still match the live ones.
        if _roll_back_certificate(prior_cert, cert_path, key_path, exc):
            _remove_quietly(staged_key, prior_cert)
        raise
    _remove_quietly(prior_cert)
    event = _replaced(reason, cert_path, old, new)
    events.append(event)
    why = (
        ""
        if reason == "renewal"
        else (
            f" because it did not name {', '.join(_names_missing(api.host, old_pem))}, "
            f"needed for the bind {api.host}"
        )
    )
    log.warning(
        "%s the generated self-signed TLS certificate at %s%s: the old one (sha256 %s) expires "
        "%s, the new one (sha256 %s) expires %s. Any browser trust store or --cacert copy that "
        "holds the old certificate must import the new one.",
        "renewed" if reason == "renewal" else "re-minted",
        cert_path,
        why,
        event.old_sha256,
        "at an unknown date" if event.old_not_after is None else log_timestamp(event.old_not_after),
        event.new_sha256,
        log_timestamp(event.new_not_after),
    )


def _roll_back_certificate(prior_cert: Path, cert_path: Path, key_path: Path, exc: OSError) -> bool:
    """Put the old certificate back after the new key could not replace the old one; ``True`` once
    it is back. Never raises.

    The new certificate is already live, and the old key is still live, so until this runs the two
    do not load as a pair. Moving the staged copy of the old certificate back restores the pair the
    engine served before. Either outcome is logged at ERROR, since the caller's fallback then names
    only the original error.
    """
    try:
        _replace_generated(prior_cert, cert_path)
    except OSError as restore:
        log.error(
            "could not replace the generated TLS key at %s (%s), and could not put the previous "
            "certificate back at %s (%s): the certificate and key do not match, so this start "
            "fails and the next one discards and re-mints them.",
            key_path,
            exc,
            cert_path,
            restore,
        )
        return False
    log.error(
        "could not replace the generated TLS key at %s (%s); put the previous certificate back at "
        "%s, beside the previous key, so the pair on disk matches again; the next start tries the "
        "replacement again.",
        key_path,
        exc,
        cert_path,
    )
    return True


def _replaced(
    reason: _ReplacedReason,
    cert_path: Path,
    old: SelfSignedFacts | None,
    new: SelfSignedFacts,
) -> GeneratedPairReplaced:
    return GeneratedPairReplaced(
        reason=reason,
        cert_file=str(cert_path),
        old_sha256=None if old is None else old.sha256,
        old_not_after=None if old is None else old.not_after_iso,
        new_sha256=new.sha256,
        new_not_after=new.not_after_iso,
    )


def _mint_generated_pair(api: ApiSettings, cert_path: Path, key_path: Path) -> SelfSignedFacts:
    """Mint the pair into two ABSENT paths. Call only under :func:`_generated_pair_lock`.

    Returns the new certificate's public facts, for the report of a recovery."""
    from messagefoundry import pki
    from messagefoundry.__main__ import _write_private_key

    cert_pem, key_pem = _make_generated(api.host)
    _write_private_key(key_path, key_pem)
    paired = False
    try:
        cert_path.write_bytes(cert_pem)
        paired = True
    finally:
        # THE MINT IS ALL-OR-NOTHING. An orphaned key.pem is not merely untidy: the reuse branch
        # above needs BOTH files, so a next start finds cert_path missing, falls through, re-mints,
        # and dies on _write_private_key's O_EXCL refusal. That repeats on every start until an
        # operator deletes a file nothing told them about, so a half-written pair would brick the
        # engine rather than degrade it. `finally`, not `except`, so no failure mode is missed.
        if not paired:
            key_path.unlink(missing_ok=True)
    _let_local_users_read_cert(cert_path)
    log.warning(
        "no [api].tls_cert_file configured — minted a SELF-SIGNED certificate for %s at %s. It has "
        "no chain of trust and is a PLACEHOLDER: browsers will show a trust interstitial until it "
        "is imported, and it should be replaced with an operator-supplied chain.",
        api.host,
        cert_path,
    )
    return pki.read_self_signed_facts(cert_pem)
