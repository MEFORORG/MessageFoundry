# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared TLS hardening policy (ASVS 11.6.2 key exchange + 12.1.4 strict X.509, WP-L3-10 code half).

Pure stdlib ``ssl`` helpers, importable by ``api/`` and ``transports/`` (and the ``config`` settings
validator) without crossing the engine's one-way dependency boundaries. Three controls:

* :func:`validate_tls_ciphers` — reject an operator ``tls_ciphers`` string that would admit a
  non-forward-secret (non-ECDHE/DHE) key exchange, so a misconfiguration cannot widen the suite below
  policy. Run from the ``[api].tls_ciphers`` settings validator, so a bad value fails loud at load.
* :func:`harden_kex_groups` — pin the approved ECDHE groups on a built context where the runtime
  supports it (``SSLContext.set_groups``, Python 3.13+); on older interpreters OpenSSL already leads
  with these groups, so it is a best-effort no-op rather than a downgrade.
* :func:`harden_verify_flags` — OR ``ssl.VERIFY_X509_STRICT`` into a verifying context's
  ``verify_flags`` so a presented chain must be RFC 5280-conformant (ASVS 12.1.4 strict path
  validation). Revocation itself is delegated to the org PKI / OCSP-must-staple proxy + OS trust store
  (ADR 0002); the engine attempts no stdlib OCSP. Guarded like ``harden_kex_groups`` for old runtimes.
* :func:`in_process_tls_revocation_refused` / :func:`tls_revocation_attested` — the **ENFORCED** (not
  merely documented) half of that revocation delegation (ASVS 12.1.4, ADR 0078). Because the engine
  performs no revocation, ``serve`` must **refuse to start** an in-process, off-loopback ``[api]`` TLS
  bind unless revocation is *proven in front* — a declared TLS-terminating reverse proxy (WP-15) or an
  explicit operator attestation (``MEFOR_TLS_REVOCATION_ATTESTED``). Secure default = refuse; loopback
  and proxy-terminated binds never trip it (byte-identical start). This module owns the pure predicate
  + the env read; the ``_serve`` gate wires them.
"""

from __future__ import annotations

import enum
import ipaddress
import logging
import os
import ssl
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)

#: Env var by which an operator ATTESTS that the TLS terminator / PKI in front of an in-process,
#: off-loopback ``[api]`` TLS bind enforces certificate revocation (OCSP/CRL). Set truthy to opt out of
#: the fail-closed serve-time refusal (ADR 0078). The engine itself performs no revocation (stdlib
#: ``ssl`` exposes no OCSP/CRL fetch; on-prem offline-by-default, CLAUDE.md §2), so this is the operator
#: taking responsibility for it. Sibling of ``MEFOR_ALLOW_INSECURE_TLS`` (config.settings), kept here so
#: the pure ``tls_policy`` module owns the whole revocation-posture surface.
TLS_REVOCATION_ATTESTED_ENV = "MEFOR_TLS_REVOCATION_ATTESTED"

__all__ = [
    "APPROVED_KEX_GROUPS",
    "TLS_REVOCATION_ATTESTED_ENV",
    "HopDisposition",
    "HopPosture",
    "InsecureHopRefused",
    "RevocationHopGuard",
    "TrustAnchor",
    "TrustAnchorMode",
    "TrustAnchorPolicy",
    "active_hop_posture",
    "build_verifying_client_context",
    "current_hop_posture",
    "enforce_insecure_hop",
    "harden_kex_groups",
    "harden_verify_flags",
    "relax_verify_expiry",
    "in_process_tls_revocation_refused",
    "insecure_hop_disposition",
    "is_loopback_hop_host",
    "phi_read_hop_disposition",
    "resolve_trust_anchor",
    "revocation_hop_disposition",
    "tls_revocation_attested",
    "validate_proxy_tls_posture",
    "validate_tls_ciphers",
]

#: NIST SP 800-52r2 minimum negotiated TLS versions (shared with the in-process floor validation).
_APPROVED_TLS_MIN_VERSIONS = ("1.2", "1.3")

#: Approved forward-secret key-exchange groups in preference order (X25519 first). These are the modern
#: NIST/FIPS-permitted ECDHE curves; the string is the OpenSSL group list passed to ``set_groups``.
APPROVED_KEX_GROUPS = "X25519:secp384r1:secp256r1"


def harden_kex_groups(ctx: ssl.SSLContext) -> None:
    """Best-effort pin ``ctx`` to :data:`APPROVED_KEX_GROUPS`.

    Uses ``SSLContext.set_groups`` where available (Python 3.13+). On older interpreters there is no
    public API to pin groups and OpenSSL's defaults already lead with X25519/P-256/P-384, so this is a
    deliberate no-op rather than a weakening. A runtime that rejects the group list (an unusual OpenSSL
    build) is logged and left at its secure defaults."""
    set_groups = getattr(ctx, "set_groups", None)
    if set_groups is None:
        return
    try:
        set_groups(APPROVED_KEX_GROUPS)
    except (
        ssl.SSLError,
        ValueError,
    ) as exc:  # pragma: no cover - depends on the linked OpenSSL build
        logger.warning("Could not pin TLS key-exchange groups %r: %s", APPROVED_KEX_GROUPS, exc)


def harden_verify_flags(ctx: ssl.SSLContext) -> None:
    """Best-effort enable strict X.509 path validation on a *verifying* ``ctx`` (ASVS 12.1.4).

    ORs ``ssl.VERIFY_X509_STRICT`` into ``ctx.verify_flags`` so a presented certificate chain must be
    RFC 5280-conformant — no malformed/ambiguous fields from which revocation metadata (AIA / CRL-DP)
    would otherwise be read. This is **strict validation, not revocation checking**: live revocation is
    delegated to the deploying org's PKI — OCSP-must-staple at the WP-15 proxy plus the OS trust store —
    because stdlib ``ssl`` exposes no OCSP/CRL fetch and the engine deliberately attempts none (ADR 0002).

    Guarded like :func:`harden_kex_groups`: a runtime/OpenSSL build without ``VERIFY_X509_STRICT`` is a
    deliberate no-op, not an error. Call it **only** on a context that actually verifies the peer (skip
    the MLLP ``tls_verify=false`` / ``CERT_NONE`` path, where there is nothing to validate)."""
    strict = getattr(ssl, "VERIFY_X509_STRICT", None)
    if strict is None:  # pragma: no cover - depends on the linked OpenSSL build
        return
    ctx.verify_flags |= strict


#: OpenSSL ``X509_V_FLAG_NO_CHECK_TIME`` (``openssl/x509_vfy.h``) — a **stable public constant**
#: (``0x200000``, unchanged since OpenSSL 1.0.2 through 3.x). It disables ONLY the certificate
#: validity-period check (both ``notBefore`` AND ``notAfter``) during chain verification; the chain
#: signature, name constraints, key usage / EKU, basic constraints, and — separately — the hostname
#: match (``check_hostname``) all still apply. Python's ``ssl`` does not expose it as a named
#: ``VerifyFlags`` member, but ``SSLContext.verify_flags`` accepts a raw ``int`` OR, so the flag is
#: settable directly. See ADR 0094 for why this OpenSSL-native context-level primitive was chosen over
#: post-handshake ``cryptography.x509.verification`` (it works uniformly for every transport that funnels
#: through an ``SSLContext`` — ftplib / httpx-style urllib openers / pynetdicom — with no per-transport
#: post-handshake re-verification).
_X509_V_FLAG_NO_CHECK_TIME = 0x200000


def relax_verify_expiry(ctx: ssl.SSLContext, *, host: str) -> None:
    """Relax ONLY the certificate validity-period check on a **verifying** client context (#129, ADR 0094).

    The granular alternative to the blunt ``tls_verify=false`` (which drops chain AND hostname AND expiry
    together via ``CERT_NONE``): this ORs :data:`_X509_V_FLAG_NO_CHECK_TIME` into ``ctx.verify_flags`` so a
    peer certificate whose ``notAfter`` has passed (or whose ``notBefore`` is in the future) is accepted
    **while the chain and hostname are still fully validated**. It is a per-connection opt-in
    (``tls_allow_expired=true``) for a partner that has let its server cert lapse — a real-world
    operational reality — without opening the MITM hole ``tls_verify=false`` does.

    **Call it only on a context that actually verifies the peer** (``CERT_REQUIRED`` — the outbound
    verify path), never on the ``tls_verify=false`` / ``CERT_NONE`` path (there is nothing to relax there,
    and that path is already refused/warned separately). Guarded defensively: a ``CERT_NONE`` context is a
    no-op (a caller bug is neutralised, not amplified into a silent downgrade).

    Emits a construction-time WARNING (``host`` only — never a credential or a body) so an operator sees
    that the hop deliberately tolerates an expired certificate. The warning fires when the relaxation is
    ENABLED (once per connector build); whether an expired cert is then actually presented is an
    OpenSSL-internal handshake detail this context-level flag does not surface. It NEVER weakens the
    posture-keyed cleartext/verify-off refusals (#200, ADR 0092): those key on ``tls_verify=false`` /
    cleartext, and ``tls_allow_expired`` leaves verification ON, so it is not an insecure hop in that
    sense."""
    if ctx.verify_mode == ssl.CERT_NONE:
        # Verification is already off — there is nothing to selectively relax. Do NOT touch a
        # non-verifying context (that path is the tls_verify=false escape, refused/warned elsewhere).
        return
    ctx.verify_flags |= _X509_V_FLAG_NO_CHECK_TIME
    logger.warning(
        "TLS certificate expiry validation is RELAXED for the hop to %s (tls_allow_expired=true): an "
        "EXPIRED server certificate will be accepted, but the chain, hostname, and key-usage are still "
        "verified. Restore a valid certificate as soon as possible.",
        host or "(unspecified host)",
    )


def tls_revocation_attested() -> bool:
    """Whether the operator has attested a revocation-checking TLS terminator / PKI (ADR 0078).

    Reads :data:`TLS_REVOCATION_ATTESTED_ENV`. This is the documented **opt-out** from the fail-closed
    serve-time refusal: an org that terminates in-process ``[api]`` TLS off-loopback but runs its own
    revocation-checking PKI (short-lived / ACME-rotated certs, an OCSP-must-staple issuer, an OS trust
    store that consults CRLs) sets it truthy to accept responsibility for revocation. Secure default
    (unset) = refuse, because the engine attempts no revocation of its own (stdlib ``ssl`` has no
    OCSP/CRL fetch). Parsed exactly like ``insecure_tls_allowed`` for consistency."""
    return os.environ.get(TLS_REVOCATION_ATTESTED_ENV, "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def in_process_tls_revocation_refused(
    *, tls_enabled: bool, is_loopback: bool, proxy_terminated: bool, attested: bool
) -> bool:
    """Whether ``serve`` must REFUSE an in-process off-loopback ``[api]`` TLS bind on revocation grounds.

    The **ENFORCED** (not merely documented) delegation of certificate revocation (ASVS 12.1.4, ADR
    0078). When the engine terminates TLS itself (uvicorn, ``tls_enabled``) on a network-reachable host
    (``not is_loopback``), a **revoked-but-unexpired** certificate would still be accepted — stdlib
    ``ssl`` performs no OCSP/CRL check and the engine deliberately attempts none (on-prem, offline-by-
    default; CLAUDE.md §2 / ADR 0002). So refuse to start UNLESS revocation is *proven in front*:

    * ``proxy_terminated`` — a declared TLS-terminating reverse proxy (WP-15:
      ``[api].tls_terminated_upstream`` **+** ``[api].trusted_proxies``) that does its own revocation
      (the engine then runs plaintext behind it and terminates no TLS itself); **or**
    * ``attested`` — the operator's explicit :data:`TLS_REVOCATION_ATTESTED_ENV` claim that their
      in-process terminator's certs are backed by a revocation-checking PKI (the opt-out).

    Pure predicate so the ``_serve`` gate stays a one-liner and is unit-testable in isolation. Returns
    ``False`` (start unchanged, **byte-identical**) for the loopback default, a plaintext bind
    (``not tls_enabled``), a proxy-terminated bind, or an attested bind — ``True`` only for an otherwise
    unproven in-process off-loopback TLS bind."""
    if not (tls_enabled and not is_loopback):
        # loopback default OR no in-process TLS — path unchanged (byte-identical start)
        return False
    if proxy_terminated:
        return False  # revocation delegated to the declared upstream terminator (proven in front)
    if attested:
        return False  # operator attested their terminator/PKI enforces revocation (the opt-out)
    return True


def validate_proxy_tls_posture(min_version: str | None, ciphers: str | None) -> None:
    """Validate the operator-DECLARED reverse-proxy (Posture-B) TLS floor for coherence (#200, 11.6.2).

    In Posture-B (``[api].tls_terminated_upstream``) the reverse proxy terminates browser TLS, so the
    ENGINE never sees the negotiated protocol version or key-exchange group — it **cannot inspect** the
    proxy's TLS (11.6.2 runtime inspection is impossible here). ``[api].proxy_tls_min_version`` /
    ``proxy_tls_ciphers`` are therefore an operator **ATTESTATION** of the floor the proxy enforces, not
    runtime enforcement. This validator does the one thing the engine *can* do: reject an INCOHERENT
    declaration at config load (fail loud, not at bind) —

    * ``min_version`` (when set) must be a NIST SP 800-52r2 floor (``"1.2"`` / ``"1.3"``); and
    * ``ciphers`` (when set) must resolve to forward-secret (EC)DHE suites, reused verbatim from
      :func:`validate_tls_ciphers`, so a *declared* floor can't itself name a non-forward-secret key
      exchange.

    Presence of the declaration (the serve-time PHI-prod fail-closed refusal) is enforced separately in
    the ``serve`` gate; this is only the shape/coherence check. Raises ``ValueError`` (surfaced as a
    config-load error) on an invalid declaration; returns ``None`` when the (possibly empty) declaration
    is coherent."""
    if min_version is not None and min_version not in _APPROVED_TLS_MIN_VERSIONS:
        raise ValueError(
            "[api].proxy_tls_min_version must be '1.2' or '1.3' (NIST SP 800-52r2), "
            f"got {min_version!r}"
        )
    if ciphers is not None:
        # Reuse the forward-secrecy gate; re-raise under the proxy field name so the operator sees which
        # setting is at fault (validate_tls_ciphers's message names the generic "tls_ciphers").
        try:
            validate_tls_ciphers(ciphers)
        except ValueError as exc:
            raise ValueError(f"[api].proxy_tls_ciphers rejected: {exc}") from exc


def validate_tls_ciphers(value: str) -> str:
    """Validate an operator OpenSSL cipher string, rejecting non-forward-secret key exchange.

    Returns ``value`` unchanged when it parses and every resolved TLS 1.2 suite uses (EC)DHE (TLS 1.3
    suites are inherently ECDHE + AEAD). Raises ``ValueError`` — surfaced as a config-load error — for
    an unparseable string or one that would admit a static-RSA/DH key exchange, closing the 11.6.2 gap
    that a misconfigured ``tls_ciphers`` could widen the key exchange below policy."""
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        probe.set_ciphers(value)
    except ssl.SSLError as exc:
        raise ValueError(f"tls_ciphers is not a valid OpenSSL cipher string: {exc}") from exc
    non_fs = sorted(
        {str(c.get("name", "?")) for c in probe.get_ciphers() if not _is_forward_secret(c)}
    )
    if non_fs:
        raise ValueError(
            "tls_ciphers must resolve to forward-secret (EC)DHE suites only (ASVS 11.6.2); "
            f"these admit a non-forward-secret key exchange: {', '.join(non_fs)}"
        )
    return value


def _is_forward_secret(cipher: Mapping[str, object]) -> bool:
    """Whether a ``SSLContext.get_ciphers()`` entry uses an (EC)DHE — forward-secret — key exchange."""
    name = str(cipher.get("name", ""))
    # TLS 1.3 suite names (TLS_AES_*, TLS_CHACHA20_*) are always ECDHE and cannot be configured down.
    if name.startswith("TLS_") or cipher.get("protocol") == "TLSv1.3":
        return True
    if name.startswith(("ECDHE", "DHE")):
        return True
    # Fall back to the human description's Kx token (stable across CPython versions).
    desc = str(cipher.get("description", ""))
    return "Kx=ECDH" in desc or "Kx=DH" in desc


# --- posture-keyed transport-hop refusal (#200, ADR 0092) --------------------------------------
#
# The shared authority every insecure-egress cell consumes. Historically each cell (HTTP cleartext
# egress, engine->store TLS, credentialed FTP, MLLP verify-off) hard-coded its own refuse/warn call
# against the blunt global ``MEFOR_ALLOW_INSECURE_TLS`` escape, so an unguarded cell warned-and-crossed
# a PHI hop that a guarded cell would have refused, and the escape could silence a production refusal.
# This module centralizes the decision into one pure predicate keyed on the instance's *posture* (does
# it carry PHI? is it production?) so every cell decides identically, and a legitimately-secure hop is
# opted in per-connection (an AUDITED attestation) rather than via the blunt global escape.

#: Host tokens that name the local box (loopback) with no DNS resolution — hoisted verbatim from
#: ``transports.rest._LOOPBACK_HOST_NAMES`` so the HTTP-egress cell and this authority share ONE
#: literal set. ``""`` (empty host) is treated as loopback (an on-box bind with no host component).
_LOOPBACK_HOP_HOST_NAMES = frozenset({"localhost", ""})


class HopDisposition(enum.Enum):
    """What a cell must do with an insecure (cleartext / unverified-TLS) transport hop.

    ``ALLOW`` — cross it silently (no PHI on the hop, a proven-loopback on-box hop, or an audited
    attestation that the hop is secure by other means). ``WARN`` — cross it but log loudly + audit (a
    non-production PHI hop, or a non-prod audited opt-out via the clamped global escape). ``REFUSE`` —
    do not cross it: a production PHI hop with no attestation. Produced by
    :func:`insecure_hop_disposition`; acted on by :func:`enforce_insecure_hop`."""

    ALLOW = "allow"
    WARN = "warn"
    REFUSE = "refuse"


class InsecureHopRefused(ValueError):
    """Raised by :func:`enforce_insecure_hop` when a hop's disposition is :attr:`HopDisposition.REFUSE`.

    A ``ValueError`` subclass so it flows through the existing connector-construction error handling
    (the loader / ``build_check`` surfaces a ``ValueError`` as a ``WiringError``/422 at ``messagefoundry
    check`` / dry-run / reload) with no new except-arms needed."""


@dataclass(frozen=True, slots=True)
class HopPosture:
    """The instance security posture an insecure-hop decision is keyed on (#200).

    ``is_phi`` — the instance carries real PHI (``[ai].data_class == phi``), independent of the
    environment name. ``production`` — the instance's production flag (``[ai].production``). Both are
    the *derived* posture (built-in dev/staging/prod derivation applied); an unresolved custom-env
    posture fails closed to ``(True, True)`` via :meth:`fail_closed` — see decision 7 of ADR 0092.
    Held in a contextvar for the duration of connector construction (:func:`active_hop_posture`)."""

    is_phi: bool
    production: bool

    @classmethod
    def fail_closed(cls, *, is_phi: bool | None, production: bool | None) -> HopPosture:
        """Build a posture, defaulting an *unknown* (``None``) dimension to the strict value.

        A custom-env instance may leave ``data_class`` / ``production`` unresolved (``serve`` refuses
        such a start, but an offline build-check / embedding may still construct connectors). An unknown
        dimension defaults to the fail-closed value — ``is_phi=True`` / ``production=True`` — so an
        unproven posture never *relaxes* a hop decision. A fully-declared config passes its real values
        through unchanged (decision 7: resolve to the declared posture, not strictest-by-default)."""
        return cls(
            is_phi=True if is_phi is None else is_phi,
            production=True if production is None else production,
        )


def is_loopback_hop_host(host: str) -> bool:
    """Whether ``host`` names the local box (loopback), so a cleartext hop to it is on-box, not a
    network exposure. Hoisted verbatim from ``transports.rest._is_loopback_egress_host`` so the
    HTTP-egress cell and this authority agree on exactly one definition.

    Covers all of ``127.0.0.0/8`` and ``::1`` via :mod:`ipaddress` (not just the literal
    ``127.0.0.1``), plus the ``localhost`` name and an empty host. It **never resolves DNS**: any other
    name cannot be *proven* loopback, so it is treated as remote (fail-closed) — a name that happens to
    resolve to a loopback address is still refused, because resolution is attacker-influenceable and
    would let a hostname smuggle an off-box hop past the on-box carve-out."""
    h = host.lower()
    if h in _LOOPBACK_HOP_HOST_NAMES:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def insecure_hop_disposition(
    *,
    is_phi: bool,
    production: bool,
    is_loopback_hop: bool,
    hop_attested: bool,
    audited_opt_out: bool,
) -> HopDisposition:
    """Decide what to do with an insecure transport hop, keyed on posture (#200, ADR 0092 — PURE).

    The single authority every insecure-egress cell consumes, so all decide identically. Explicit,
    early-return precedence (the order is load-bearing — the owner-ratified gradient):

    #. ``is_loopback_hop`` → :attr:`~HopDisposition.ALLOW` — an on-box hop is not a network exposure.
    #. ``hop_attested`` → :attr:`~HopDisposition.ALLOW` — a per-connection, load-validated, audited
       attestation that this hop is legitimately secure (a proxy-terminated / trusted-segment hop).
    #. not ``is_phi`` (synthetic instance) → :attr:`~HopDisposition.ALLOW` — no PHI rides the hop.
    #. ``audited_opt_out`` → :attr:`~HopDisposition.WARN` — the global escape, **already clamped by the
       caller** to non-production (see ``settings.hop_insecure_escape_downgrades``); on production the
       caller passes ``False`` here, so this arm never fires for a prod-PHI hop.
    #. ``production`` → :attr:`~HopDisposition.REFUSE` — a production PHI hop with no attestation: do
       not put PHI on the wire in the clear.
    #. else (non-production PHI — dev/staging) → :attr:`~HopDisposition.WARN`.

    Note the escape (``audited_opt_out``) can never satisfy a prod-PHI hop: it is clamped to ``False``
    on production upstream, so the ``production`` arm always wins there (decision 2). Attestation
    (``hop_attested``) is the *only* per-hop way to cross a prod-PHI hop, and it is audited when it
    suppresses a would-be prod refusal (the cell audits at that point)."""
    if is_loopback_hop:
        return HopDisposition.ALLOW
    if hop_attested:
        return HopDisposition.ALLOW
    if not is_phi:
        return HopDisposition.ALLOW
    if audited_opt_out:
        return HopDisposition.WARN
    if production:
        return HopDisposition.REFUSE
    return HopDisposition.WARN


def enforce_insecure_hop(
    disposition: HopDisposition,
    *,
    message: str,
    cell: str,
    audit_sink: Callable[[str], None] | None = None,
) -> None:
    """Act on a :class:`HopDisposition`: raise on REFUSE, loud-log (+audit) on WARN, no-op on ALLOW.

    The thin enforcement half of the authority (the pure decision is :func:`insecure_hop_disposition`).
    ``cell`` is a short PHI-free label of the crossing (e.g. ``"REST cleartext egress"``,
    ``"engine->store TLS"``); ``message`` explains the specific hop (host/scheme — never a credential or
    a message body). On :attr:`~HopDisposition.REFUSE` it raises :class:`InsecureHopRefused` (a
    ``ValueError``, so it surfaces as a config-load/``build_check`` error). On
    :attr:`~HopDisposition.WARN` it logs at WARNING and, when an ``audit_sink`` is supplied, records the
    crossing for the audit trail (a WARN is a deliberately-crossed insecure hop — an operator should see
    it). ``audit_sink`` is a plain ``Callable`` so this stays a pure ``config``-level helper that never
    imports the engine's ``AlertSink`` (one-way dependency boundary)."""
    if disposition is HopDisposition.ALLOW:
        return
    detail = f"{cell}: {message}"
    if disposition is HopDisposition.REFUSE:
        raise InsecureHopRefused(detail)
    # WARN — crossed, but loud + audited.
    logger.warning("insecure transport hop permitted — %s", detail)
    if audit_sink is not None:
        audit_sink(detail)


#: The instance posture in force during connector construction. Stamped by the construction gate
#: (``build_check_registry`` via :func:`active_hop_posture`) so a cell built inside that scope reads the
#: LOADED config's derived posture rather than guessing. ``None`` when unstamped (an embedding/test that
#: constructs a connector outside the gate) — a cell then fail-closes (treats it as prod-PHI).
_ACTIVE_HOP_POSTURE: ContextVar[HopPosture | None] = ContextVar(
    "mf_active_hop_posture", default=None
)


@contextmanager
def active_hop_posture(posture: HopPosture | None) -> Iterator[None]:
    """Stamp ``posture`` as the active hop posture for the duration of the ``with`` block (#200).

    The construction gate wraps its connector-build loop in this so every cell built inside reads the
    same LOADED-config posture via :func:`current_hop_posture`. Reentrant/nesting-safe (contextvar
    token restore); ``None`` is a valid value (explicitly clears the posture)."""
    token = _ACTIVE_HOP_POSTURE.set(posture)
    try:
        yield
    finally:
        _ACTIVE_HOP_POSTURE.reset(token)


def current_hop_posture() -> HopPosture | None:
    """The posture stamped by the enclosing :func:`active_hop_posture`, or ``None`` when unstamped.

    A cell calls this at construction to key its :func:`insecure_hop_disposition` decision. ``None``
    means the connector is being built outside the construction gate (an embedding/test) — the cell
    fail-closes (treats the hop as prod-PHI) rather than crossing on an unknown posture."""
    return _ACTIVE_HOP_POSTURE.get()


def phi_read_hop_disposition(
    posture: HopPosture | None,
    *,
    serve_hop_secure: bool,
    audited_opt_out: bool,
) -> HopDisposition:
    """Decide whether the API may emit PHI over its own **serve hop** (#200 residual, ADR 0092 — PURE).

    The data-path analogue of :func:`insecure_hop_disposition` for the API's PHI-read RESPONSE path
    (raw view / attachment download / summary). A production-PHI instance whose API serve hop is NOT
    proven secure — not loopback, not in-process TLS, not a declared TLS-terminating proxy — REFUSES to
    put PHI on that hop rather than emitting it in the clear. Reuses the ONE authority so the API decides
    identically to the transport cells, and the production-PHI clamp (``audited_opt_out``, supplied
    already clamped by the caller) stays the single authority for the global escape.

    ``posture is None`` (an embedding / test that declared no ``[ai]`` posture, so ``is_phi`` is unknown)
    → :attr:`~HopDisposition.ALLOW` — byte-identical to the pre-residual behaviour, so the loopback/dev
    default and every non-PHI embedding are untouched. A ``serve_hop_secure`` hop is modelled as the
    authority's on-box carve-out (``is_loopback_hop``): a loopback / TLS / proxy-terminated serve hop is
    not an insecure network exposure, so PHI may cross (the serve-start exposed-gate already vetted it).
    There is no per-hop attestation for the API serve hop — the serve gate's proxy/TLS declarations are
    what prove it secure — so ``hop_attested`` is always ``False`` here."""
    if posture is None:
        return HopDisposition.ALLOW
    return insecure_hop_disposition(
        is_phi=posture.is_phi,
        production=posture.production,
        is_loopback_hop=serve_hop_secure,
        hop_attested=False,
        audited_opt_out=audited_opt_out,
    )


# --- posture-keyed OUTBOUND revocation-hop refusal (#201, ADR 0078 amendment) ------------------
#
# ADR 0078 ENFORCED the "no in-engine OCSP/CRL — refuse an unproven off-loopback in-process [api] TLS
# bind" posture for the LISTENER (in_process_tls_revocation_refused, wired in _serve). The identical
# blind spot exists on every OUTBOUND connector that VERIFIES a downstream server cert over stdlib ssl
# (MLLP-over-TLS, REST/SOAP/FHIR https, the asyncpg store hop): the chain is validated (+ strict RFC
# 5280 via harden_verify_flags) but a REVOKED-but-unexpired peer cert is still accepted — Python's ssl
# has no OCSP/CRL fetch and the engine deliberately attempts none (offline-by-default, CLAUDE.md §2).
# So a verified outbound hop that is off-loopback, PHI, and production is REFUSED at construction /
# `messagefoundry check` / dry-run unless revocation is proven in front (a revocation-checking egress
# terminator) or the operator attests a revocation-checking PKI — per-connection `tls_revocation_attested`
# or the blanket `MEFOR_TLS_REVOCATION_ATTESTED` env (the same opt-out ADR 0078 gave the listener).
#
# COMPOSES with #200 (ADR 0092): #200 refuses the CLEARTEXT / verify-off hop, so revocation only matters
# on a VERIFYING hop — the two gates key on disjoint conditions and never double-refuse the same hop.


def revocation_hop_disposition(
    *,
    is_phi: bool,
    production: bool,
    is_loopback_hop: bool,
    proxy_proven: bool,
    attested: bool,
) -> HopDisposition:
    """Decide what to do with a VERIFYING outbound TLS hop that does no revocation checking (#201 — PURE).

    The outbound sibling of :func:`in_process_tls_revocation_refused`, reusing the :class:`HopDisposition`
    gradient of :func:`insecure_hop_disposition` so the outbound connectors decide identically. Explicit
    early-return precedence:

    #. ``is_loopback_hop`` → :attr:`~HopDisposition.ALLOW` — an on-box hop is not a network exposure, and
       a revoked cert on the local box is not the threat this gate addresses.
    #. ``proxy_proven`` → :attr:`~HopDisposition.ALLOW` — revocation is *proven in front* by a declared
       revocation-checking egress terminator (the outbound analogue of ADR 0078's ``proxy_terminated``).
    #. ``attested`` → :attr:`~HopDisposition.ALLOW` — the operator attests a revocation-checking PKI backs
       this hop (per-connection ``tls_revocation_attested`` or the blanket ``MEFOR_TLS_REVOCATION_ATTESTED``).
    #. not ``is_phi`` (synthetic instance) → :attr:`~HopDisposition.ALLOW` — no PHI rides the hop.
    #. ``production`` → :attr:`~HopDisposition.REFUSE` — a production PHI hop with unchecked revocation.
    #. else (non-production PHI — dev/staging) → :attr:`~HopDisposition.WARN`.

    Unlike :func:`insecure_hop_disposition` this carries NO global-escape (``audited_opt_out``) arm — the
    ONLY relaxations are the on-box carve-out, a declared revocation-checking terminator, an operator
    attestation, or a synthetic instance. This never turns verification off (the caller has already built
    a verifying context) — it only decides whether the *unchecked-revocation* property of that verified
    hop is tolerable, so it composes with (never weakens) the #200 cleartext/verify-off refusals."""
    if is_loopback_hop:
        return HopDisposition.ALLOW
    if proxy_proven:
        return HopDisposition.ALLOW
    if attested:
        return HopDisposition.ALLOW
    if not is_phi:
        return HopDisposition.ALLOW
    if production:
        return HopDisposition.REFUSE
    return HopDisposition.WARN


@dataclass(frozen=True, slots=True)
class RevocationHopGuard:
    """A captured revocation-refusal decision for one VERIFYING outbound TLS hop (#201, ADR 0078 amend).

    The revocation twin of the transports' cleartext :class:`InsecureHopGuard`. Built once at connector
    construction via :meth:`capture`, which snapshots the active hop posture
    (:func:`current_hop_posture`) and folds the blanket ``MEFOR_TLS_REVOCATION_ATTESTED`` env into the
    per-connection attestation. :meth:`enforce_construction` is the ENFORCED gate — it fires inside
    ``build_check`` (``messagefoundry check`` / dry-run / reload / the serve pre-flight), where the derived
    posture IS stamped, and refuses a production-PHI verified-but-unrevoked hop off-loopback there. It
    **no-ops when the posture is unstamped** (``None`` — a live serve build after the pre-flight, or a
    direct test/embedding): the enforced gate has already validated the config, so re-refusing here would
    wrongly break every live serve of a legitimately-attested / non-prod lane (identical semantics to the
    cleartext :class:`InsecureHopGuard`)."""

    host: str
    cell: str
    description: str
    attested: bool
    proxy_proven: bool
    posture: HopPosture | None

    @classmethod
    def capture(
        cls,
        *,
        host: str,
        cell: str,
        description: str,
        attested: bool,
        proxy_proven: bool = False,
    ) -> RevocationHopGuard:
        """Snapshot the decision inputs + the active hop posture for a verifying outbound TLS hop.

        ``attested`` is the per-connection ``tls_revocation_attested`` flag; the blanket
        ``MEFOR_TLS_REVOCATION_ATTESTED`` env is OR'd in here so either form suppresses the refusal (the
        same opt-out ADR 0078 gave the in-process listener). ``cell`` is a short PHI-free label of the
        crossing; ``description`` explains the hop (scheme/host only — never a credential or a body)."""
        return cls(
            host=host,
            cell=cell,
            description=description,
            attested=attested or tls_revocation_attested(),
            proxy_proven=proxy_proven,
            posture=current_hop_posture(),
        )

    def _disposition(self, posture: HopPosture) -> HopDisposition:
        return revocation_hop_disposition(
            is_phi=posture.is_phi,
            production=posture.production,
            is_loopback_hop=is_loopback_hop_host(self.host),
            proxy_proven=self.proxy_proven,
            attested=self.attested,
        )

    def _detail(self) -> str:
        return (
            f"{self.description} to {self.host}: the peer certificate is verified but NO certificate "
            "revocation checking (OCSP/CRL) is performed — stdlib ssl has none (ASVS 12.1.4, ADR 0078). "
            "Terminate at a revocation-checking egress proxy, or set tls_revocation_attested=true / "
            f"{TLS_REVOCATION_ATTESTED_ENV}=1 to attest a revocation-checking PKI backs this hop."
        )

    def enforce_construction(self) -> None:
        """The ENFORCED construction gate: raise :class:`InsecureHopRefused` on a production-PHI
        verified-but-unrevoked hop off-loopback, loud-log (+audit the attestation) on a warned hop, allow
        the rest. No-op when the posture is unstamped (``None``) — the build_check gate is the authority."""
        posture = self.posture
        if posture is None:
            return
        disposition = self._disposition(posture)
        # Audit an attestation / proven terminator that SUPPRESSED a would-be production-PHI refusal: the
        # disposition is ALLOW only because tls_revocation_attested / proxy_proven fired before the REFUSE
        # arm, so an operator should see the unchecked-revocation hop was crossed on their attestation.
        if (
            disposition is HopDisposition.ALLOW
            and (self.attested or self.proxy_proven)
            and posture.is_phi
            and posture.production
            and not is_loopback_hop_host(self.host)
        ):
            logger.warning(
                "verified TLS hop crossed WITHOUT certificate revocation checking on operator "
                "attestation — %s: %s",
                self.cell,
                self._detail(),
            )
        enforce_insecure_hop(disposition, message=self._detail(), cell=self.cell)


# --- pinned internal-CA trust anchor (#190, ADR 0093) ------------------------------------------
#
# An outbound connector that verifies a downstream *server* certificate anchors trust in the OS trust
# store by default (``ssl.create_default_context()`` → ``load_default_certs``). A hospital estate whose
# internal endpoints present certs from a PRIVATE / internal CA that is NOT in the box-global OS store
# then cannot verify that hop without either installing the CA box-wide or naming a per-connection
# ``tls_ca_file``. This is the shared, opt-in ``[tls]`` fallback: a single internal CA PEM the operator
# pins once, applied to internal outbound hops so they verify against the org PKI. It is a CLIENT
# trust-anchor policy (which roots verify the peer) — it NEVER disables verification, so it composes
# with (never weakens) the existing fail-closed no-CA / verify-off / cleartext-hop refusals. The exact
# ``create_default_context(cafile=...)`` template already used for the syslog forwarder's
# ``forward_tls_ca_file`` (ADR 0080): a pinned CA loads ONLY that anchor, not the public bundle.

#: How the ``[tls].internal_ca_file`` anchor composes with the OS default roots for an internal hop.
#: ``system`` (default) — unchanged; verify against the OS trust store, byte-identical to before this
#: seam. ``augment`` — trust the OS roots AND the internal CA (a mixed public + private estate).
#: ``pinned`` — trust ONLY the internal CA, not the public bundle (a fully-private estate; the
#: strictest posture, matching ``forward_tls_ca_file``).
TrustAnchorMode = Literal["system", "augment", "pinned"]


@dataclass(frozen=True, slots=True)
class TrustAnchorPolicy:
    """The instance-wide ``[tls]`` client trust-anchor policy (#190, ADR 0093).

    ``internal_ca_file`` is a PEM path (NOT a secret) to the org's internal CA; ``mode`` selects how it
    composes with the OS default roots for an internal hop (:data:`TrustAnchorMode`). The default
    (``internal_ca_file=None``, ``mode="system"``) is a no-op — every hop verifies against the OS trust
    store exactly as before, so a config with no ``[tls]`` block is byte-identical. Threaded from
    ``[tls]`` onto each outbound :class:`~messagefoundry.config.models.Destination` so a connector's
    client-verify context resolves the same anchor at both ``build_check`` and live construction."""

    internal_ca_file: str | None = None
    mode: TrustAnchorMode = "system"


@dataclass(frozen=True, slots=True)
class TrustAnchor:
    """A resolved client-side trust anchor for verifying a peer *server* cert on one outbound hop.

    ``cafile`` is the CA PEM to load (or ``None`` to load none explicitly); ``load_system_roots`` is
    whether the OS default roots are also trusted. The two combinations the modes produce:

    * ``load_system_roots=True, cafile=None`` — the OS trust store only (``system`` mode / a loopback
      hop / no internal CA) — byte-identical to today's ``create_default_context()``.
    * ``load_system_roots=True, cafile=<path>`` — OS roots **plus** the internal CA (``augment``).
    * ``load_system_roots=False, cafile=<path>`` — **only** that CA, no public bundle (``pinned``, or a
      connection that named its own ``tls_ca_file`` — the historical ``create_default_context(cafile=…)``
      single-anchor behaviour).

    ``load_system_roots=False`` is only ever paired with a non-``None`` ``cafile`` by
    :func:`resolve_trust_anchor` (there is always something to anchor to), so a verifying context is
    never left with an empty trust store."""

    cafile: str | None
    load_system_roots: bool


def resolve_trust_anchor(
    *,
    connection_ca_file: str | None,
    host: str,
    policy: TrustAnchorPolicy,
) -> TrustAnchor:
    """Resolve the client trust anchor for an outbound hop to ``host`` (#190, ADR 0093 — PURE).

    Precedence (load-bearing):

    #. A connection that names its **own** ``connection_ca_file`` (its ``tls_ca_file``) WINS verbatim —
       trust ONLY that CA, never overridden by the instance policy (its explicit per-connection pin is
       authoritative; byte-identical to today's ``create_default_context(cafile=…)``).
    #. Else, a **loopback** hop (:func:`is_loopback_hop_host`), the ``system`` mode, or an unset
       ``internal_ca_file`` → the OS trust store only (unchanged — the internal CA is for verifying
       *internal network* peers, and an on-box hop needs no org-PKI anchor).
    #. Else (a non-loopback internal hop with an internal CA and ``augment``/``pinned``): ``pinned`` →
       ONLY the internal CA (no public bundle); ``augment`` → the OS roots plus the internal CA.

    This only chooses WHICH roots verify the peer — it never turns verification off — so it composes
    with the connectors' fail-closed no-CA / ``tls_verify=false`` / cleartext-hop refusals rather than
    weakening them."""
    if connection_ca_file is not None:
        # Per-connection pin wins verbatim (single-anchor, no OS roots — the historical behaviour).
        return TrustAnchor(cafile=connection_ca_file, load_system_roots=False)
    if policy.mode == "system" or policy.internal_ca_file is None or is_loopback_hop_host(host):
        # Unchanged: OS trust store only (byte-identical default / loopback exemption).
        return TrustAnchor(cafile=None, load_system_roots=True)
    if policy.mode == "pinned":
        # ONLY the internal CA — the forward_tls_ca_file template (no public bundle).
        return TrustAnchor(cafile=policy.internal_ca_file, load_system_roots=False)
    # augment: OS roots + the internal CA.
    return TrustAnchor(cafile=policy.internal_ca_file, load_system_roots=True)


def build_verifying_client_context(
    anchor: TrustAnchor, *, purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH
) -> ssl.SSLContext:
    """Build a **verifying** client :class:`ssl.SSLContext` whose trust store is ``anchor`` (#190).

    A drop-in replacement for the connectors' ``ssl.create_default_context(purpose, cafile=…)`` call
    that additionally supports the ``augment`` posture (OS roots + a private CA), which a single
    ``cafile=`` argument cannot express. Verification stays ON (``CERT_REQUIRED`` + ``check_hostname``,
    the ``create_default_context`` secure defaults) — the caller layers the TLS floor / KEX / strict
    flags / optional mTLS client cert exactly as before. Purpose is a parameter only so a future
    client-auth context could reuse it; every current caller verifies a *server* cert."""
    if anchor.load_system_roots:
        ctx = ssl.create_default_context(purpose)
        if anchor.cafile is not None:
            # augment: keep the OS default roots loaded above and add the internal CA on top.
            ctx.load_verify_locations(cafile=anchor.cafile)
        return ctx
    # pinned / per-connection: ONLY this CA (no load_default_certs), matching forward_tls_ca_file.
    return ssl.create_default_context(purpose, cafile=anchor.cafile)
