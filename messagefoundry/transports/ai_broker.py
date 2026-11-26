# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Engine-brokered AI-assistance HTTP client (ADR 0135, BACKLOG #95).

The broker POSTs a **code_only** assist prompt to a CUSTOMER-MANAGED / self-hosted LLM endpoint and
returns the reply text. It is the transport half of the engine-brokered AI path: the API route
(``POST /ai/chat`` in :mod:`messagefoundry.api.app`) is the SOLE policy-enforcement point — it re-resolves
the effective policy server-side, gates on ``AI_ASSIST``, and audits every use; this module only performs
the vetted network call.

**Security posture (this is the crown-jewel AI-egress surface):**

* **SSRF fail-closed.** ``[egress].allowed_http`` is opt-in *permissive-when-empty*, so the broker CANNOT
  rely on it. Instead the configured ``endpoint`` is validated at construction against the dedicated
  ``[ai].allowed_endpoints`` list — an un-listed host (**or an EMPTY list**) is REFUSED. Combined with
  rest.py's hardened **no-redirect** opener, a crafted or redirected endpoint cannot exfiltrate the prompt
  to an unintended host.
* **No new dependency.** The POST reuses rest.py's TLS-verifying, no-redirect openers +
  ``_redact_url`` (stdlib :mod:`urllib`) — exactly as smart.py does. A vendor SDK would be a separate
  DEP-1 vet, so it is intentionally avoided.
* **Trust anchor (BACKLOG #5527).** The endpoint is verified under the instance ``[tls]`` policy the
  caller hands in, resolved by ``tls_policy.resolve_trust_anchor`` as for every other HTTP-family
  hop: ``[tls].internal_ca_file`` under ``augment`` or ``pinned``, and ``[tls].crl_file``, for an
  endpoint whose host is not loopback in the reading :func:`_refuse_an_unrevoked_ai_hop`
  states. :func:`_ai_endpoint_opener` says which opener that gives.
* **Off the event loop.** :meth:`AiBroker.chat` blocks (a provider POST), and so can construction,
  which builds rest.py's shared opener on first use (BACKLOG #2484), or reads the CA and CRL files
  when it builds an anchored opener (:func:`_ai_endpoint_opener`). The API route runs the build
  and :meth:`AiBroker.chat` each through :func:`asyncio.to_thread`.
* **Revocation (BACKLOG #2193 slice (e), BACKLOG #5527).** The endpoint's certificate is verified,
  and stdlib ssl checks no OCSP. It checks no CRL unless ``[tls].crl_file`` is set, the ``[tls]``
  policy is handed in, and the endpoint host is not loopback in that reading. So an endpoint
  whose host reads as remote there, on the box or off it, is refused under an enforcing or
  unknown posture unless that CRL is checked or ``[ai].endpoint_revocation_attested`` is set
  with its reason:
  :func:`_refuse_an_unrevoked_ai_hop`.
* **Secrets / PHI.** The prompt, the reply, and the provider ``api_key`` are NEVER logged. A failure names
  only the redacted endpoint host + HTTP status — never the request or response body (either may echo
  content or the key).
* **One-way deps.** This module MUST NOT import ``api/`` (CLAUDE.md §4): the API depends on the engine,
  not the reverse.

MVP is code_only + non-streaming (ADR 0135). The Anthropic Messages wire shape is built
UNCONDITIONALLY -- nothing here dispatches on ``provider``, which is carried for addressing and for the
per-use audit only. ``claude`` is therefore the sole serviceable value, and ``[ai].provider`` is
validated at config load to refuse anything else (BACKLOG #95) rather than let it fail at request
time. The customer-managed endpoint is expected to speak that shape (a real Claude subscription, an
Azure/Bedrock-style gateway, or a self-hosted Anthropic-compatible server). If a second wire shape is
ever added here, widen ``_SERVICEABLE_AI_PROVIDERS`` in ``config/settings.py`` with it -- and only
then.
"""

from __future__ import annotations

import http.client
import json
import logging
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING

from messagefoundry.config.tls_policy import (
    PEER_NOT_VERIFIED_WAYS_ACROSS,
    CrlNoCredit,
    HopDisposition,
    HopPosture,
    RevocationHopGuard,
    TrustAnchor,
    TrustAnchorPolicy,
    hop_url_host,
    is_loopback_hop_host,
    log_attested_crossing,
)
from messagefoundry.controlchars import has_control_char, has_lone_surrogate
from messagefoundry.redaction import json_loads_or_refusal
from messagefoundry.transports.bounded_read import EgressReplyError, read_bounded_text
from messagefoundry.transports.egress import http_egress_allowed

# Reuse rest.py's hardened, TLS-verifying, no-redirect opener + URL redaction (no new HTTP plumbing) —
# exactly as smart.py / fhir.py / soap.py do. No import cycle: rest.py never imports this module.
from messagefoundry.transports.rest import (
    _no_redirect_opener,
    _redact_url,
    _shared_no_redirect_opener,
    find_outbound_length_violation,
    http_family_trust_anchor,
    opener_tls_context,
    refuse_url_credentials,
    url_host_label,
    url_scheme,
)

if TYPE_CHECKING:  # only for the from-settings factory annotation
    from messagefoundry.config.settings import AiSettings

__all__ = [
    "AiBroker",
    "AiBrokerError",
    "AiOpenerSlot",
    "ai_broker_from_settings",
    "endpoint_host_allowed",
]

logger = logging.getLogger(__name__)

# Anthropic Messages API wire constants (the MVP provider shape). The customer-managed endpoint speaks
# this; the version header is the stable public value.
_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MAX_OUTPUT_TOKENS = 4096
_DEFAULT_TIMEOUT = 60.0


#: The cell the AI hop's revocation refusal and its log lines name where the guard's reason is
#: that the context consults no CRL. PHI-free.
_AI_HOP_CELL = "[ai] engine AI broker (verified TLS, no revocation check)"

#: The cell for any other reason, written through the guard's ``stated_cell``, which drops
#: "verified" on a context that does not verify the peer. It does not say "no revocation check",
#: as REST's and remotefile's cells do not on a relaxed hop (vault BACKLOG #4912).
_AI_HOP_CELL_OTHER = "[ai] engine AI broker (verified TLS)"

#: The ways across that refusal under an enforcing posture where no CRL can reach the hop: the
#: attestation pair, or an endpoint the refusal reads as on the box, in the reading
#: :func:`_refuse_an_unrevoked_ai_hop` states. So the remedy names spellings that read as on the
#: box rather than "this machine". Each remedy is written out in full, with no text made from
#: another, so a grep for its opening words finds it (BACKLOG #5527 item 13).
_AI_ATTESTATION_LEVER = (
    "Set [ai].endpoint_revocation_attested = true with an "
    "[ai].endpoint_revocation_attested_reason that says what covers revocation of the AI "
    "endpoint's certificate, or use an endpoint URL whose host reads as loopback here, such as "
    "localhost, 127.0.0.1 or [::1], and list that host in [ai].allowed_endpoints. Such an "
    "endpoint is verified against the OS trust store alone, with neither [tls] file. The host "
    "is read as spelled, apart from case and IPv6 brackets: at least a spelling with a "
    "trailing dot, or a shortened IPv4 address such as 127.1, reads as remote."
)

#: The ways across that refusal under an enforcing posture, on the terms below:
#: ``[tls].crl_file``, the attestation pair, or an endpoint whose host reads as loopback.
#: ``[tls].crl_file`` reaches this hop since BACKLOG #5527, the later CRL lever ADR 0173 section 12
#: foresaw when the owner ruling of 2026-10-27 built the attestation pair alone. It is offered only
#: to a broker that was handed a ``[tls]`` policy, on a context whose only reason for no CRL
#: credit is that it consults none: on a build with none, such as a direct ``create_app`` whose
#: embedder passed no ``tls_settings`` and set no ``app.state.tls_settings``, setting it would
#: change nothing. No connection's attestation is offered either: the endpoint is not a
#: connection. Naming either would be a remedy the operator cannot perform.
_AI_CRL_LEVER = (
    "Set [tls].crl_file to a CRL file that covers the issuer of the AI endpoint's certificate (it "
    "is instance-wide: every non-loopback hop it reaches then needs its issuer's CRL in that file, "
    "or its handshake fails), or set [ai].endpoint_revocation_attested = true with an "
    "[ai].endpoint_revocation_attested_reason that says what covers revocation of the AI "
    "endpoint's certificate, or use an endpoint URL whose host reads as loopback here, such as "
    "localhost, 127.0.0.1 or [::1], and list that host in [ai].allowed_endpoints. Such an "
    "endpoint is verified against the OS trust store alone, with neither [tls] file. The host "
    "is read as spelled, apart from case and IPv6 brackets: at least a spelling with a "
    "trailing dot, or a shortened IPv4 address such as 127.1, reads as remote."
)


def _revocation_lever(*, crl_reachable: bool, no_credit: CrlNoCredit | None) -> str:
    """The refusal's remedy text: :data:`_AI_CRL_LEVER` only where a CRL can reach the hop and
    could be credited there, else :data:`_AI_ATTESTATION_LEVER`. On a context that does not verify
    the peer it is the guard's default for such a context,
    :data:`~messagefoundry.config.tls_policy.PEER_NOT_VERIFIED_WAYS_ACROSS` (vault BACKLOG #4912)."""
    if no_credit is CrlNoCredit.PEER_NOT_VERIFIED:
        return PEER_NOT_VERIFIED_WAYS_ACROSS
    if crl_reachable and no_credit is CrlNoCredit.NO_CRL:
        return _AI_CRL_LEVER
    return _AI_ATTESTATION_LEVER


#: Each crossing line already logged, keyed by its kind and the endpoint host, so each is written
#: once per process for each hop, as the Vault hop's are. The broker is built for every request, so
#: without this an attested or warned hop would log a WARNING on every assist call.
_LOGGED_CROSSINGS: set[tuple[str, str]] = set()
_LOGGED_CROSSINGS_LOCK = threading.Lock()


def _first_crossing(kind: str, host: str) -> bool:
    """``True`` the first time ``(kind, host)`` is seen in this process, and ``False`` after."""
    with _LOGGED_CROSSINGS_LOCK:
        if (kind, host) in _LOGGED_CROSSINGS:
            return False
        _LOGGED_CROSSINGS.add((kind, host))
        return True


class AiBrokerError(ValueError):
    """The engine broker is mis-configured (at least: missing endpoint/key, an endpoint outside the SSRF
    allowlist, a cleartext-http endpoint, which always carries the key, or an endpoint the
    revocation guard refuses; :func:`_refuse_an_unrevoked_ai_hop` says when, and that one on this
    machine can be among them) or the provider call failed. Raised with a PHI-/secret-safe
    message (redacted host + status only) so it can surface as a clean API error without leaking the
    prompt, the response, or the key."""


def endpoint_host_allowed(url: str, allowed: list[str]) -> bool:
    """True if ``url``'s host (and port, when an allow entry pins one) is on ``allowed``, through the
    egress gate's own HTTP matcher, so ``[v6]`` and ``[v6]:port`` entries read as they do there
    (BACKLOG #5915). Applied FAIL-CLOSED by the caller: an empty ``allowed`` matches nothing, and
    so does a URL with no host, or one whose port or authority ``urlsplit`` cannot read; this never
    raises, as the egress matcher never does (BACKLOG #1793)."""
    return http_egress_allowed(url, allowed)


class AiOpenerSlot:
    """Where one app holds the AI endpoint's anchored opener, with the anchor it was built for
    (BACKLOG #5527 items 3 to 5). ``create_app`` puts one on ``app.state.ai_opener_slot`` and the
    ``POST /ai/chat`` route hands it to the broker, so no process-wide holder keeps the opener.
    Beyond the app's state, at least the broker of an assist call in flight holds it too, and an
    opener no longer held lasts until a collection frees it. Two apps in one
    process each hold their own. Only :func:`_ai_endpoint_opener` fills and clears it."""

    __slots__ = ("_held", "_lock")

    def __init__(self) -> None:
        # Replaced whole, never mutated, so a read without the lock sees one consistent pair.
        self._held: tuple[TrustAnchor, urllib.request.OpenerDirector] | None = None
        self._lock = threading.Lock()


def _ai_endpoint_opener(
    endpoint: str, policy: TrustAnchorPolicy | None, slot: AiOpenerSlot | None = None
) -> urllib.request.OpenerDirector:
    """The opener the broker dials ``endpoint`` through, under the instance ``[tls]`` ``policy``
    (BACKLOG #5527). ``None``, no policy reached the broker, resolves as the empty policy does:
    the OS trust store and no CRL. The two differ only in the remedy the refusal and the warn
    line name: each offers ``[tls].crl_file`` only where a policy reached the broker
    (``crl_reachable``).

    The anchor is resolved by ``rest.http_family_trust_anchor``, as for every HTTP-family hop, here
    with no ``tls_ca_file`` of its own: ``[tls].internal_ca_file`` under ``augment`` or ``pinned``,
    and ``[tls].crl_file`` in any mode, each only for an endpoint whose host does not read as
    loopback in the reading :func:`_refuse_an_unrevoked_ai_hop` states, so an endpoint URL holding
    ``[::1]`` takes neither. So this is where a CRL reaches this hop. An anchor that narrows gets an anchored opener. One that narrows
    nothing gets rest.py's shared opener, which is never mutated: callers compare an opener to it
    by identity to learn that.

    **The anchored opener is held in ``slot``**, though the broker is built for each request: the
    slot holds one, keyed on the resolved anchor. A call whose anchor differs from the one held
    empties the slot first, then builds and holds the new one if its anchor narrows; so a build
    that raises leaves the slot empty, and a call whose anchor narrows nothing leaves it empty.
    Only such a call empties it: an assist call refused before it reaches the opener, or no call
    at all, leaves the slot as it was. Held, its context is a live hop as every connection's is,
    so ``loaded_crls`` records the CRL it holds, the expiry monitor judges that copy, and
    ``crl_reload`` brings it current when the file is replaced. An opener that is no longer held
    keeps its ``loaded_crls`` record until it is garbage-collected. An opener and its handlers form
    a reference cycle, so only the cyclic collector frees it. The engine's expiry monitor, and
    ``crl_reload`` on a newly changed file, run a full collection before they read
    ``loaded_crls``, so neither judges a dropped opener's copy; a ``crl_reload`` pass whose changes
    are all retries reads without collecting and can still see it. With no slot, as for a broker
    built directly, a call whose anchor narrows nothing returns the shared opener and builds no
    opener of its own. A call whose anchor narrows builds an opener of its own, held only by that
    broker: it reads and judges the CA and CRL files every time, and records a copy in
    ``loaded_crls`` for each such context until that is collected.

    Raises ``ValueError`` or ``OSError`` for a file that cannot be loaded or a CRL that
    ``harden_crl_check`` refuses."""
    anchor = http_family_trust_anchor(
        {}, url=endpoint, trust_anchor_policy=policy, cell="[ai].endpoint"
    )
    # A slot made for this call alone, held nowhere, so a broker with none takes the one build
    # path below.
    held_by = slot if slot is not None else AiOpenerSlot()
    if anchor.narrows:
        # Read without the lock first, as the shared opener's getter does: a hit, every request
        # after the first, takes no lock.
        held = held_by._held
        if held is not None and held[0] == anchor:
            return held[1]
    with held_by._lock:
        held = held_by._held
        if anchor.narrows and held is not None and held[0] == anchor:
            return held[1]
        # BACKLOG #5527 item 3: an opener held for an anchor this call no longer resolves would
        # keep its context, and its loaded_crls record, live for nothing. Emptied under the lock,
        # before any build, so neither a racing build nor one that raises leaves it held.
        held_by._held = None
        if not anchor.narrows:
            return _shared_no_redirect_opener()
        # The hop's own label, so a refusal raised while the context is built or asserted does not
        # name the HTTP-family destinations (BACKLOG #5527 item 9).
        opener = _no_redirect_opener(trust_anchor=anchor, connector="AI endpoint")
        held_by._held = (anchor, opener)
        return opener


def _refuse_an_unrevoked_ai_hop(
    endpoint: str,
    *,
    opener: urllib.request.OpenerDirector,
    posture: HopPosture | None,
    revocation_attested: bool,
    revocation_reason: str | None,
    crl_reachable: bool = False,
) -> None:
    """Refuse a verifying AI endpoint hop that checks no revocation and carries no attestation
    (BACKLOG #2193 slice (e), owner ruling 2026-10-27, on the ADR 0173 section 12 pattern).

    Every call sends ``[ai].api_key`` and the code sent for assistance over https. The openers
    the broker builds verify the endpoint's certificate; on a context handed in that does not
    verify the peer, the record says so instead of calling the hop verified, and its remedy is
    the guard's (vault BACKLOG #4912). Stdlib ssl checks no OCSP, and no CRL unless one is loaded on the
    context, so without one a revoked but unexpired certificate would be accepted with no refusal
    and no record. ``crl_reachable`` says whether a ``[tls]`` policy reached the broker, and so
    whether the refusal and the warning may offer ``[tls].crl_file``; they offer it only where
    the guard's reason is that the context consults no CRL.

    The decision is ``tls_policy.revocation_hop_disposition``, the authority every revocation
    guard uses, asked through ``RevocationHopGuard.capture(...).disposition()``, with these inputs:

    * **On the box** is :func:`~messagefoundry.config.tls_policy.is_loopback_hop_host` on the
      host :func:`~messagefoundry.config.tls_policy.hop_url_host` takes from the endpoint URL,
      and the refusal and its remedies use this reading. It reads the host as spelled, apart
      from case and the brackets of an IPv6 host, not where the endpoint runs. So "not on the
      box" means the host does not read as loopback, not that the endpoint is off this machine:
      at least a spelling with a trailing dot, such as ``localhost.``, or a shortened IPv4
      address such as ``127.1`` reads as remote, though it may name this machine. An endpoint
      URL holding ``[::1]`` reads as on the box, because the host arrives without its brackets.
      Every opener dials a loopback host direct, whatever proxy it has (vault
      BACKLOG #2579), so a proxy does not move a loopback endpoint off the box.
    * ``revocation_attested`` goes in the per-hop ``attested`` slot. It is
      ``[ai].endpoint_revocation_attested``, which load refuses without a reason. Only the value
      ``True`` counts, so a truthy string cannot cross.
    * ``tls_revocation_attested()``, the process-wide variable, goes in ``blanket_attested``
      only. The authority ranks it below the enforcing refusal (BACKLOG #299), so it does not
      cross this hop under an enforcing or unknown posture.
    * ``crl_checked`` is read off ``opener``'s https context, the opener the broker will dial
      through, never off a setting. It is ``True`` only when
      :func:`~messagefoundry.config.tls_policy.crl_no_credit` gives no reason against that
      context (vault BACKLOG #5086, #4912). That function's docstring is the source of record
      for the conditions. It can be ``True`` when
      ``[tls].crl_file`` reached the hop through :func:`_ai_endpoint_opener` (BACKLOG #5527).
      Otherwise the opener is rest.py's shared one, which loads no CRL, or one carrying only
      ``[tls].internal_ca_file``, so it is ``False``.
    * An attestation with no reason or a blank one, and a reason holding a control character or a
      lone surrogate, are refused here as at settings load, so a broker built directly cannot
      cross with no recorded reason or forge a log line through it.
    * ``posture`` is the instance posture the caller holds, or ``None``. **An unknown posture
      counts as enforcing**, as on the Vault hops: the broker is built per request, outside the
      construction gate, so there is no ambient posture to read.

    **The three answers.** REFUSE raises :class:`AiBrokerError`, which the route answers 503.
    WARN crosses and logs a WARNING that names the pair; that is a hop not on the box, as read
    above, with no credited CRL and no attestation, on an instance whose
    ``[security].enforcement`` is ``warn``. ALLOW crosses; a hop that crossed an enforcing or
    unknown posture on its attestation logs a WARNING through
    ``tls_policy.log_attested_crossing``, with the reason. A hop on the box logs nothing, and
    neither does a hop the process-wide variable crossed on a warn instance. Each line is written
    once per process for each host. Any other answer refuses, so a new one fails closed.

    It acts on the answer itself rather than through ``RevocationHopGuard.enforce_construction``,
    for two reasons: it logs on every build, and the broker is built per request; and it raises
    ``InsecureHopRefused``, which the route does not map, so a refusal would surface as an
    unhandled 500. :class:`AiBrokerError` is answered 503."""
    # Each ValueError below is re-raised as this module's single error type OUTSIDE its handler,
    # so neither __cause__ nor __context__ carries the original; its text names no URL part.
    refusal: str | None = None
    try:
        host = hop_url_host(endpoint, cell="[ai].endpoint")
    except ValueError as exc:
        refusal = str(exc)
    if refusal is not None:
        raise AiBrokerError(refusal)
    attested = revocation_attested is True
    if attested and not (revocation_reason and revocation_reason.strip()):
        raise AiBrokerError(
            "[ai].endpoint_revocation_attested=true requires an "
            "[ai].endpoint_revocation_attested_reason that says what covers revocation of the AI "
            "endpoint's certificate"
        )
    # The settings load refuses these too; the reason is written into a WARNING below, where a
    # CR or LF could forge a log line.
    if revocation_reason is not None and (
        has_control_char(revocation_reason) or has_lone_surrogate(revocation_reason)
    ):
        raise AiBrokerError(
            "[ai].endpoint_revocation_attested_reason must not contain control characters or "
            "lone surrogates"
        )
    held = HopPosture.fail_closed(enforcing=None) if posture is None else posture
    on_box = is_loopback_hop_host(host)
    # urllib_handler_context fails closed when it cannot read the handler's context; carried as
    # this module's error type so the route answers 503, not an unhandled 500.
    try:
        context = opener_tls_context(opener, connector="AI endpoint")
    except ValueError as exc:
        context = None
        refusal = str(exc)
    if refusal is not None:
        raise AiBrokerError(refusal)
    # capture() reads the process-wide variable into its own field and the context through
    # crl_no_credit, the same reads every RevocationHopGuard hop makes; disposition() asks
    # revocation_hop_disposition, logging and raising nothing. The texts below are this hop's own,
    # worded from the guard's reason (guard.no_credit) and its stated_cell (vault BACKLOG #4912).
    # disposition() is never None, since a posture is held.
    guard = RevocationHopGuard.capture(
        host=host,
        cell=_AI_HOP_CELL_OTHER,
        description="sends [ai].api_key over verified https",
        attested=attested,
        context=context,
        posture=held,
        connection=None,  # the [ai] endpoint, not a connection
        declaration="[ai].endpoint_revocation_attested",
    )
    disposition = guard.disposition()
    enforcing = held.enforcing
    no_credit = guard.no_credit
    # On NO_CRL the verify_mode is not CERT_NONE, or there is no context, so stated_cell would keep
    # "verified" as well.
    cell = _AI_HOP_CELL if no_credit is CrlNoCredit.NO_CRL else guard.stated_cell
    sent = f"the AI endpoint {host!r} is sent [ai].api_key over https"
    if no_credit is CrlNoCredit.PEER_NOT_VERIFIED:
        detail = (
            f"{sent} whose TLS context does not verify the peer (verify_mode is CERT_NONE), and "
            "the guard credits no revocation check on such a context"
        )
    elif no_credit is CrlNoCredit.EXPIRY_RELAXED:
        # A CRL on such a context still refuses a leaf it lists, so "NO revocation checking"
        # would say less was checked than was; what the hop lacks is a check the guard credits.
        detail = (
            f"{sent} whose TLS context skips validity-period checks, and the guard credits no "
            "revocation check on such a context"
        )
    else:
        detail = (
            f"{sent} that verifies its certificate, but NO certificate revocation checking "
            "(OCSP/CRL) is performed"
        )
    if disposition is HopDisposition.ALLOW:
        # Not when the context's CRL is a real check: that hop crossed on it, not on the
        # attestation, and the line would be a false record. `crl_checked` is the same one field
        # the disposition read, False for a CRL on a context that skips time validity (vault
        # BACKLOG #5086).
        crossed_on_attestation = attested and enforcing and not on_box and not guard.crl_checked
        if crossed_on_attestation and _first_crossing("attested", host):
            log_attested_crossing(
                logger,
                crossing=guard.crossing_lead,
                connection=None,
                detail=f"{cell}: {detail}",
                reason=revocation_reason,
                declaration=guard.declaration,
            )
        return
    if disposition is HopDisposition.WARN:
        if _first_crossing("warn", host):
            logger.warning(
                "insecure transport hop permitted -- %s: %s; under [security].enforcement = "
                "enforce this hop is refused unless %s[ai].endpoint_revocation_attested is true "
                "with its reason",
                cell,
                detail,
                "a [tls].crl_file covering its issuer is set or "
                if crl_reachable and no_credit is CrlNoCredit.NO_CRL
                else "",
            )
        return
    raise AiBrokerError(
        f"{cell}: {detail}. {_revocation_lever(crl_reachable=crl_reachable, no_credit=no_credit)}"
    )


class AiBroker:
    """Broker one code_only assist prompt to a customer-managed / self-hosted LLM (ADR 0135).

    Built from the loaded ``[ai]`` settings (:func:`ai_broker_from_settings`), once for each
    ``POST /ai/chat`` request. Construction validates at least the endpoint scheme, the
    credential, that the endpoint host is on ``allowed_endpoints`` (the SSRF gate, fail-closed),
    and, last, the revocation guard (:func:`_refuse_an_unrevoked_ai_hop`). :meth:`chat` performs
    the blocking POST; the API route awaits :meth:`chat_async`."""

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        allowed_endpoints: list[str],
        provider: str = "claude",
        model: str = "claude-opus-4-8",
        max_output_tokens: int = _DEFAULT_MAX_OUTPUT_TOKENS,
        timeout_seconds: float = _DEFAULT_TIMEOUT,
        posture: HopPosture | None = None,
        revocation_attested: bool = False,
        revocation_attested_reason: str | None = None,
        trust_anchor_policy: TrustAnchorPolicy | None = None,
        opener_slot: AiOpenerSlot | None = None,
    ) -> None:
        if not endpoint:
            raise AiBrokerError(
                "engine-brokered AI requires an '[ai].endpoint' (the customer-managed LLM's URL)"
            )
        # Read through url_scheme, never a bare urlsplit: a URL it cannot parse raises urlsplit's own
        # ValueError, which quotes the netloc. The full credential screen stays after the http
        # refusal below, so that order is unchanged (BACKLOG #2686).
        scheme = url_scheme(endpoint, "[ai].endpoint", use="[ai].api_key", error=AiBrokerError)
        # The api_key is a credential, and every call sends it (an empty key is refused below), so a
        # cleartext http endpoint is refused with no escape and in every posture: vault BACKLOG #3533
        # item 5, which applies docs/SECURITY-LOOSENING.md, *No escape sends a credential to an
        # unverified peer*. The insecure-TLS escape released it at warn until then. Refused first,
        # so an http endpoint is never sent to fix an allowlist entry it cannot use.
        if scheme == "http":
            raise AiBrokerError(
                "[ai].endpoint over cleartext http would send the api_key in clear; refused, with "
                "no escape. Use an https endpoint."
            )
        if scheme != "https":
            raise AiBrokerError(f"[ai].endpoint must be https, got scheme {scheme!r}")
        refuse_url_credentials(endpoint, "[ai].endpoint", use="[ai].api_key", error=AiBrokerError)
        if not api_key:
            raise AiBrokerError(
                "engine-brokered AI requires an '[ai].api_key' (the LLM credential, via MEFOR_AI_API_KEY)"
            )
        # SSRF fail-closed (ADR 0135): the endpoint host MUST be explicitly allow-listed. This is stricter
        # than — and independent of — the permissive-when-empty [egress].allowed_http, so the engine can
        # never be pointed at an un-allowlisted LLM host. An EMPTY allowlist permits NOTHING.
        if not endpoint_host_allowed(endpoint, allowed_endpoints):
            host = url_host_label(endpoint)
            raise AiBrokerError(
                f"[ai].endpoint host {host!r} is not in the [ai].allowed_endpoints allowlist; "
                "list it explicitly to permit engine-brokered AI egress (SSRF fail-closed)"
            )
        # ASVS 4.2.5. Both values are operator-supplied via env() and both ship on every provider call
        # -- the endpoint as the request line, the key as the ``x-api-key`` header. Bounded here rather
        # than per call because neither varies per prompt. Raised as AiBrokerError (a ValueError
        # subclass) so the API surface keeps its single error type, and the key is NEVER echoed.
        violation = find_outbound_length_violation(endpoint, {"x-api-key": api_key})
        if violation is not None:
            raise AiBrokerError(
                f"[ai] {violation.kind} is {violation.length} chars, over the "
                f"{violation.limit}-char limit; check [ai].endpoint / the api_key env() value"
            )
        # The opener is chosen before the guard and handed to it, so the guard judges the context
        # this broker really dials with (BACKLOG #5527).
        # BACKLOG #2484: the shared opener is built on first use, so a build refusal, such as an
        # OpenSSL that refuses the engine's list (EngineTlsListRefused, a ValueError), lands here, as
        # does an OSError from the default context's trust-store load (ssl.SSLError is one), and a
        # [tls] file _ai_endpoint_opener cannot load. Re-raised as AiBrokerError, the API surface's
        # one error type.
        try:
            opener = _ai_endpoint_opener(endpoint, trust_anchor_policy, opener_slot)
        except (ValueError, OSError) as exc:
            raise AiBrokerError(f"[ai] endpoint opener refused: {exc}") from exc
        # Last, so an endpoint refused for any reason above never logs a revocation crossing, and
        # the operator is never sent to attest a hop that is refused anyway (BACKLOG #2193 (e)).
        _refuse_an_unrevoked_ai_hop(
            endpoint,
            opener=opener,
            posture=posture,
            revocation_attested=revocation_attested,
            revocation_reason=revocation_attested_reason,
            crl_reachable=trust_anchor_policy is not None,
        )
        self.endpoint = endpoint
        self.api_key = api_key
        self.provider = provider or "claude"
        self.model = model or "claude-opus-4-8"
        self.max_output_tokens = max(1, int(max_output_tokens))
        self.timeout_seconds = timeout_seconds
        self._opener: urllib.request.OpenerDirector = opener

    @property
    def endpoint_host(self) -> str:
        """The endpoint host (no scheme/path/query) — PHI-safe metadata for the audit ``detail``."""
        return urllib.parse.urlsplit(self.endpoint).hostname or ""

    def chat(self, prompt: str) -> str:
        """POST the code_only ``prompt`` to the endpoint and return the reply text. BLOCKING (a provider
        POST over urllib); the API route calls :meth:`chat_async`. Raises :class:`AiBrokerError` (PHI-/
        secret-safe: redacted host + status only) on any failure."""
        data = json.dumps(
            {
                "model": self.model,
                "max_tokens": self.max_output_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
        ).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to https in __init__
            self.endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": _ANTHROPIC_VERSION,
            },
            method="POST",
        )
        # Vault BACKLOG #5356: an arm whose exception can quote the api_key or hold the provider's
        # bytes sets `refusal`, raised after the try so neither __cause__ nor __context__ keeps it.
        refusal: str | None = None
        try:
            with self._opener.open(req, timeout=self.timeout_seconds) as resp:
                # ASVS 15.2.2: bounded on the socket read. The AI endpoint is operator-configured but
                # off-premises, so its reply is the least-trusted body the engine buffers on egress.
                body = read_bounded_text(
                    resp,
                    connector="AI endpoint",
                    encoding="utf-8",
                )
        except EgressReplyError as exc:
            # Mapped onto this module's single error type: the API route handles AiBrokerError, and a
            # DeliveryError escaping here would be unmapped. The message already names only the
            # fixed label "AI endpoint" and the refusal, never the URL (BACKLOG #2060).
            #
            # Caught as the FAMILY, not as ResponseTooLargeError: a refusal added beside it later
            # shares this reason exactly, and catching the member is how #1575's first cut let
            # TruncatedResponseError escape this arm as an unhandled 500.
            raise AiBrokerError(str(exc)) from exc
        except urllib.error.HTTPError as exc:
            # Never echo exc.read() — the error body may carry provider detail; redacted host + status only.
            refusal = f"AI endpoint {_redact_url(self.endpoint)} returned HTTP {exc.code}"
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} unreachable: {exc.reason}"
            ) from exc
        except (ValueError, http.client.InvalidURL):
            # BACKLOG #2113, closing the arm #1793 left open here: urllib refused a request value. Its
            # text can quote that value, and the x-api-key header is one, so it is never echoed.
            refusal = f"AI endpoint {_redact_url(self.endpoint)} rejected an invalid request value"
        except (TimeoutError, OSError) as exc:
            raise AiBrokerError(f"AI endpoint {_redact_url(self.endpoint)} failed: {exc}") from exc
        except http.client.HTTPException as exc:
            # BACKLOG #2113: a malformed status or header line (BadStatusLine, LineTooLong) is
            # neither an OSError nor a URLError, so it escaped the route's AiBrokerError mapping as
            # an unhandled 500. Named by class only: its text can echo the provider's bytes. Last,
            # so InvalidURL and RemoteDisconnected keep the arms above.
            refusal = (
                f"AI endpoint {_redact_url(self.endpoint)} sent a malformed HTTP reply "
                f"({type(exc).__name__})"
            )
        else:
            return self._extract_text(body)
        # The fallback text keeps an arm that forgot to set `refusal` on this module's error.
        raise AiBrokerError(refusal or f"AI endpoint {_redact_url(self.endpoint)} request failed")

    async def chat_async(self, prompt: str) -> str:
        """Awaitable wrapper: run the blocking :meth:`chat` OFF the event loop (CLAUDE.md §6) so the
        engine's asyncio loop never blocks on the provider round-trip."""
        import asyncio

        return await asyncio.to_thread(self.chat, prompt)

    def _extract_text(self, body: str) -> str:
        """Pull the reply text from an Anthropic Messages response. Defensive: a refusal or an
        unparseable/empty body raises :class:`AiBrokerError` (never echoing ``body`` — it may carry
        content). Concatenates every ``text`` content block."""
        # Raised with no chain, so the decode error holding the whole reply stays off it (#2085).
        payload, refused = json_loads_or_refusal(body)
        if refused is not None:
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} returned an unparseable response"
            )
        if isinstance(payload, dict) and payload.get("stop_reason") == "refusal":
            raise AiBrokerError("the AI provider declined the request (refusal)")
        blocks = payload.get("content") if isinstance(payload, dict) else None
        if not isinstance(blocks, list):
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} returned an unexpected response shape"
            )
        text = "".join(
            str(b.get("text", ""))
            for b in blocks
            if isinstance(b, dict) and b.get("type") == "text"
        )
        if not text:
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} returned an empty completion"
            )
        return text


def ai_broker_from_settings(
    ai: AiSettings,
    *,
    posture: HopPosture | None = None,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
    opener_slot: AiOpenerSlot | None = None,
) -> AiBroker:
    """Build the :class:`AiBroker` from the loaded ``[ai]`` settings, or raise :class:`AiBrokerError`
    when the engine broker is not fully configured. Settings arrive already ``env()``-resolved (the API
    lifespan stashes the resolved :class:`AiSettings` on ``app.state.ai``).

    ``posture`` keys the revocation refusal (BACKLOG #2193 slice (e)), and ``None`` counts as
    enforcing there: :func:`_refuse_an_unrevoked_ai_hop` says why. It no longer reaches the
    cleartext-http refusal, which takes no escape in any posture since vault BACKLOG #3533 item 5.

    ``trust_anchor_policy`` is the instance ``[tls]`` policy (BACKLOG #5527), or ``None`` where
    none reached the caller, and ``opener_slot`` the calling app's :class:`AiOpenerSlot`, or
    ``None``. :func:`_ai_endpoint_opener` says what each reaches."""
    return AiBroker(
        endpoint=ai.endpoint or "",
        api_key=ai.api_key or "",
        allowed_endpoints=list(ai.allowed_endpoints),
        provider=ai.provider,
        model=ai.model,
        posture=posture,
        revocation_attested=ai.endpoint_revocation_attested,
        revocation_attested_reason=ai.endpoint_revocation_attested_reason,
        trust_anchor_policy=trust_anchor_policy,
        opener_slot=opener_slot,
    )
