# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""OIDC authorization-code + PKCE flow state (ADR 0142): PKCE generation, the browser-binding flow
cache, the authorization-URL builder, and the token-endpoint code exchange.

**Why a flow cache and not just ``state``.** A server-side ``state`` is a CSRF/mix-up defence, not a
*browser* binding: whoever presents a valid ``(state, code)`` pair would get a session in *their*
browser. The start leg therefore issues a random ``flow_id`` in a ``__Host-``-prefixed cookie and
stores the flow keyed on ``sha256(flow_id)``; the callback must present both the cookie ``flow_id``
and the matching ``state``. The cache is process-local — like the WebAuthn ceremony cache, single API
process is structural (ADR 0068), and a start-on-A/callback-on-B flow behind a non-sticky balancer
fails *legibly* as ``state_unknown``.

The cache **rejects when full** rather than evicting oldest: eviction would let a start-leg flood drop
legitimate pending flows — a login denial-of-service. A per-client-IP sub-cap contains one source.

No socket is opened except in :func:`exchange_code`, which takes an injected ``opener`` so tests stay
hermetic; nothing here logs the client secret, the ``code``, or a token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from messagefoundry.redaction import json_loads_or_refusal

if TYPE_CHECKING:  # the annotation only; this module takes no module-scope transports import
    from messagefoundry.auth.oidc.client_auth import ClientAuthentication

_VERIFIER_BYTES = 48  # 64 base64url chars — within RFC 7636's 43..128
_STATE_BYTES = 32
_NONCE_BYTES = 32
_FLOW_ID_BYTES = 32

DEFAULT_FLOW_TTL_SECONDS = 300.0
DEFAULT_FLOW_CACHE_MAX = 512
DEFAULT_PER_IP_CAP = 16
# The token-endpoint response is small; a larger body is refused unread.
_MAX_TOKEN_RESPONSE_BYTES = 256 * 1024


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class FlowError(ValueError):
    """A flow could not be started, bound, or exchanged (cache full, token-endpoint failure)."""


class FlowCacheFullError(FlowError):
    """The global or per-IP pending-flow bound is full — a start-leg flood, refused not evicted."""


class TokenRefusedError(FlowError):
    """The token endpoint ANSWERED, and gave no usable token: the IdP is up (BACKLOG #1948).

    RFC 6749 section 5.2 answers a bad, used or expired ``code`` with a 4xx, usually 400
    ``invalid_grant``, and a signed-out caller chooses the ``code``. So an answer must not read as an
    IdP outage, or any caller could hide the federated sign-in link.

    **Every received status lands here, and that is on purpose.** The engine's own configuration
    faults are 4xx too: a wrong client secret (401, or 400 under ``client_secret_post``), a redirect
    mismatch, an unsupported grant type. Telling them apart means reading the error body, which may
    echo the request, client secret included, and ``invalid_grant`` itself arrives as 400 from one
    IdP and 403 from another. A faulty IdP may answer a bad ``code`` with a 5xx, and a 3xx is a
    redirect the no-redirect opener refuses. A 2xx whose body is not a readable token response is an
    answer too. Any split a caller's code can reach is a switch for the link, so the line is drawn
    at whether the endpoint answered at all (ADR 0142 Amendment E, the source of record). The
    operator tells a fault from a junk-code spray by :attr:`status` on the audit row, which is a
    number and never IdP text. It is None when a reply arrived but its header block did not parse,
    so no status could be read from it.
    """

    # `status` has a default so copy and pickle, which rebuild from the message alone and then
    # restore the instance dict, can rebuild this error.
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class TokenEndpointUnreachableError(FlowError):
    """No answer arrived from the token endpoint, or it was cut short: a TRANSPORT failure (BACKLOG
    #1948). The only token-endpoint outcome that may mark the IdP unavailable; ADR 0142 Amendment E
    says why, and which residual it leaves."""


def pkce_challenge(verifier: str) -> str:
    """The PKCE S256 challenge for ``verifier`` — ``base64url(sha256(verifier))`` (RFC 7636).

    Split out so the challenge can be re-derived from a STAGED verifier when the authorization URL is
    built, without the caller reimplementing the transform (a second, drifting copy of a cryptographic
    binding is exactly the failure mode worth avoiding).
    """
    return _b64u(hashlib.sha256(verifier.encode("ascii")).digest())


def generate_pkce() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` for PKCE S256 (RFC 7636).

    The verifier is high-entropy base64url; the challenge is ``base64url(sha256(verifier))``. Only the
    challenge crosses to the IdP; the verifier stays in the flow cache and is replayed at the token
    endpoint, proving the callback came from the browser that started the flow.
    """
    verifier = _b64u(secrets.token_bytes(_VERIFIER_BYTES))
    return verifier, pkce_challenge(verifier)


@dataclass(frozen=True, slots=True)
class PendingFlow:
    """One in-flight authorization request, staged at start and consumed at callback."""

    state: str
    nonce: str
    code_verifier: str
    return_to: str
    client_ip: str
    deadline: float
    #: The hash of the session the browser presented at the START leg, if any (ASVS 7.2.4). The
    #: callback cannot read it for itself: the session cookie is SameSite=Strict and the IdP's
    #: redirect back is a cross-site navigation, so the browser withholds it there. Staged as a hash,
    #: never the token, so a cache dump yields nothing that authenticates.
    prior_session_hash: str | None = None
    #: STEP-UP flows only (ADR 0142 Amendment B, BACKLOG #296). The hash of the live session that
    #: asked to step up at the IdP; ``None`` marks an ordinary sign-in flow. Staged here for the
    #: reason ``prior_session_hash`` is: the callback cannot see the SameSite=Strict cookie. A flow
    #: with this set elevates THAT session and never mints a new one, and a sign-in flow never
    #: elevates anything, so each completion refuses the other kind.
    step_up_session_hash: str | None = None
    #: The ADR 0077 action the step-up is for, if any, so the single-use grant is minted for the
    #: action the operator started from. ``None`` refreshes only the session window.
    step_up_purpose: str | None = None
    #: Wall-clock (``time.time``) when the flow was staged. A step-up proof must show an IdP sign-in
    #: at or after this instant, less the clock skew; ``max_age=0`` asks the IdP for that, and this
    #: is how the engine checks it was honoured. ``0.0`` on a flow that predates the field.
    issued_at: float = 0.0
    #: Stamped by :meth:`FlowCache.put` on the cache's own clock, so :meth:`FlowCache.age` reads the
    #: same clock (BACKLOG #2301). ``0.0`` on a flow never staged, which reads as staged long ago.
    started: float = 0.0


class FlowCache:
    """Bounded, TTL'd, process-local staging for in-flight OIDC flows (ADR 0142).

    Keyed on ``sha256(flow_id)`` — the raw ``flow_id`` lives only in the browser cookie, so a cache
    dump never yields a usable flow id. ``put`` **rejects** at the global or per-IP cap rather than
    evicting (eviction = a login DoS); ``pop`` is single-use and TTL-checked on ``time.monotonic``.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_FLOW_TTL_SECONDS,
        global_cap: int = DEFAULT_FLOW_CACHE_MAX,
        per_ip_cap: int = DEFAULT_PER_IP_CAP,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._global_cap = global_cap
        self._per_ip_cap = per_ip_cap
        self._clock = clock
        self._entries: dict[str, PendingFlow] = {}

    @staticmethod
    def _key(flow_id: str) -> str:
        return hashlib.sha256(flow_id.encode("ascii")).hexdigest()

    def _prune(self, now: float) -> None:
        for k in [k for k, e in self._entries.items() if e.deadline <= now]:
            del self._entries[k]

    def put(self, flow_id: str, flow: PendingFlow) -> PendingFlow:
        """Stage ``flow`` under ``sha256(flow_id)``, enforcing the global and per-IP caps, and return
        the staged copy, stamped with the instant it was staged."""
        now = self._clock()
        self._prune(now)
        if len(self._entries) >= self._global_cap:
            raise FlowCacheFullError(
                f"OIDC login refused: the engine-wide pending-flow bound ({self._global_cap}) is "
                "full. Retry shortly; if this persists, investigate mass login-start traffic."
            )
        mine = sum(1 for e in self._entries.values() if e.client_ip == flow.client_ip)
        if mine >= self._per_ip_cap:
            raise FlowCacheFullError(
                f"OIDC login refused: too many pending flows from {flow.client_ip} "
                f"({self._per_ip_cap})."
            )
        staged = replace(flow, started=now)
        self._entries[self._key(flow_id)] = staged
        return staged

    def age(self, flow: PendingFlow) -> float:
        """Seconds since ``flow`` was staged, on this cache's clock (BACKLOG #2301)."""
        return self._clock() - flow.started

    def peek(self, flow_id: str) -> PendingFlow | None:
        """The live flow for ``flow_id`` WITHOUT consuming it; None if absent or expired.

        Used only to decide which completion runs (sign-in or step-up). The completion itself still
        ``pop``s, so single use is unchanged, and it re-checks the kind of flow it popped.
        """
        entry = self._entries.get(self._key(flow_id))
        if entry is None or entry.deadline <= self._clock():
            return None
        return entry

    def pop(self, flow_id: str) -> PendingFlow | None:
        """Consume the flow for ``flow_id`` (single-use); None if absent or expired."""
        entry = self._entries.pop(self._key(flow_id), None)
        if entry is None or entry.deadline <= self._clock():
            return None
        return entry


def new_flow_id() -> str:
    """A fresh opaque flow id for the ``__Host-`` cookie."""
    return _b64u(secrets.token_bytes(_FLOW_ID_BYTES))


def start_flow(
    cache: FlowCache,
    *,
    return_to: str,
    client_ip: str,
    ttl_seconds: float = DEFAULT_FLOW_TTL_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    prior_session_hash: str | None = None,
    step_up_session_hash: str | None = None,
    step_up_purpose: str | None = None,
    wall_clock: Callable[[], float] = time.time,
) -> tuple[str, PendingFlow]:
    """Mint a flow (state/nonce/PKCE), stage it, and return ``(flow_id, flow)``.

    ``flow_id`` goes in the browser cookie; ``flow`` carries the values the callback re-checks.
    """
    flow_id = new_flow_id()
    verifier, _challenge = generate_pkce()
    flow = PendingFlow(
        state=_b64u(secrets.token_bytes(_STATE_BYTES)),
        nonce=_b64u(secrets.token_bytes(_NONCE_BYTES)),
        code_verifier=verifier,
        return_to=return_to,
        client_ip=client_ip,
        deadline=clock() + ttl_seconds,
        prior_session_hash=prior_session_hash,
        step_up_session_hash=step_up_session_hash,
        step_up_purpose=step_up_purpose,
        issued_at=wall_clock(),
    )
    return flow_id, cache.put(flow_id, flow)


def state_matches(expected: str, received: str) -> bool:
    """Constant-time ``state`` comparison — never ``==`` on an attacker-supplied token.

    ``received`` is raw query-string input. ``hmac.compare_digest`` RAISES ``TypeError`` on a ``str``
    containing non-ASCII, so comparing directly would turn ``?state=café`` into an unhandled 500 on an
    unauthenticated route — skipping the audited ``state_mismatch`` branch entirely and letting a
    prober evade the closed-set audit trail. A non-ASCII state cannot match anyway: the value we
    minted is base64url, so this is a plain non-match, not a special case.
    """
    try:
        received_ascii = received.encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(expected.encode("ascii"), received_ascii)


def build_authorization_url(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str,
    scopes: Sequence[str],
    max_age: int,
    acr_values: str | None = None,
    prompt: str | None = None,
    step_up: bool = False,
) -> str:
    """Build the front-channel authorization-code + PKCE (S256) redirect URL (``response_mode=query``).

    ``max_age`` is REQUIRED, with no default, so a caller cannot build a URL that forgets it (ASVS
    6.8.4 / 7.6.1, BACKLOG #1150). OIDC Core's authentication-request rules make the IdP
    re-authenticate only IF its own authentication is older than ``max_age``, and make
    ``auth_time`` REQUIRED in the ``id_token`` whenever ``max_age`` was sent. That second half is
    what the claims ladder then verifies. A value of 0 or less is refused: 0 forces a fresh IdP
    login every time, which is ``prompt=login`` under another name and throws away the single
    sign-on federation exists to deliver.

    ``step_up=True`` is the one exception, and it is the whole of the federated step-up leg's request
    (ADR 0142 Amendment B, BACKLOG #296): the URL carries ``max_age=0`` and ``prompt=login``, so
    the IdP must authenticate the user afresh rather than answer from its own session. That is
    exactly the single sign-on a step-up must NOT reuse. ``max_age`` is still validated as the
    configured value, and a caller ``prompt`` is refused rather than silently overridden.
    """
    if max_age <= 0:
        raise ValueError("max_age must be a positive number of seconds")
    if step_up and prompt:
        raise ValueError("a step-up request sends prompt=login; do not pass another prompt")
    params: dict[str, str] = {
        "response_type": "code",
        "response_mode": "query",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "max_age": "0" if step_up else str(max_age),
    }
    # BACKLOG #2325: a whitespace-only request names no class, so it is not sent. Settings load
    # already turns one into None; this covers any other caller.
    requested_acr = " ".join((acr_values or "").split())
    if requested_acr:
        params["acr_values"] = requested_acr
    if step_up:
        params["prompt"] = "login"
    elif prompt:
        params["prompt"] = prompt
    # urlsplit is the repo's ONE URL parser (enforced by tests/test_security_static.py), so a value
    # validated at config load cannot be re-read differently at use — the classic parser-confusion
    # gap. config/settings.py validates this endpoint with urlsplit too.
    sep = "&" if urllib.parse.urlsplit(authorization_endpoint).query else "?"
    return f"{authorization_endpoint}{sep}{urllib.parse.urlencode(params)}"


def exchange_code(
    *,
    token_endpoint: str,
    client_id: str,
    client_auth: ClientAuthentication | None,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    opener: urllib.request.OpenerDirector,
    timeout: float = 10.0,
) -> Mapping[str, object]:
    """POST the authorization ``code`` (+ the PKCE verifier) to the token endpoint; return the JSON.

    ``opener`` is injected (production supplies a hardened, CA-pinned, no-redirect opener).
    ``client_auth`` supplies the client's credential fields: the secret under
    ``client_secret_post``, or under ``private_key_jwt`` an assertion minted for this one request and
    no secret (BACKLOG #296). One value carries one credential, so the two can never ride together.
    ``None`` sends no client credential, a public client relying on PKCE alone.
    Raises — PHI/secret-safe: the secret, the ``code``, and the tokens never enter an exception
    message. At least these (BACKLOG #1948): :class:`TokenRefusedError` when the endpoint answered,
    with any status other than a usable 2xx, or with a reply the engine cannot read as a token
    response; :class:`TokenEndpointUnreachableError` on a transport failure, where no answer arrived
    or it was cut short; a plain :class:`FlowError` when the request itself is over the length
    bound below, before anything is sent. An ``http.client`` exception raised while the reply's
    status line is read, such as ``BadStatusLine``, is not wrapped and propagates as itself.

    The request line and header block are **measured before the POST** (ASVS 4.2.5, BACKLOG #1048).
    ``token_endpoint`` is operator-static config (validated https at load), so this is the weaker of
    the two 4.2.5 limbs and not attacker-influenced; it earns the bound because an ``env()`` value
    that resolved to an unexpected blob then surfaces as a clear refusal here instead of a
    wire-level surprise on the first federated login.
    """
    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if client_auth is not None:
        # Built here, per request, so a private_key_jwt POST carries a fresh `jti` and `exp`.
        form.update(client_auth.form_fields())
    data = urllib.parse.urlencode(form).encode("ascii")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    # Reuse the ONE outbound length measurement rather than declaring a third copy of the bound
    # (transports/rest.py owns it; apiclient's duplicate is pinned equal by a test, and that
    # duplication is only tolerated because ADR 0088 makes that package engine-free). Imported
    # lazily so the pure, socket-free ``auth.oidc`` package takes no module-scope transports import
    # — the same containment ``store/keyprovider_vault.py`` uses for the same helper. The raise is
    # this module's own FlowError, not a transport exception: the caller maps FlowError to the
    # audited login-failure path, and a DeliveryError there would escape unmapped. Only the class
    # and the length are disclosed; the endpoint and every credential stay out of the message.
    from messagefoundry.transports.rest import (  # noqa: PLC0415  (lazy — see above)
        find_outbound_length_violation,
    )

    violation = find_outbound_length_violation(token_endpoint, headers)
    if violation is not None:
        raise FlowError(
            f"the token-endpoint request {violation.kind} is {violation.length} chars, over the "
            f"{violation.limit}-char limit — check [auth].oidc_token_endpoint / its env() value"
        )
    req = urllib.request.Request(  # noqa: S310 — scheme is validated https at config load
        token_endpoint,
        data=data,
        headers=headers,
        method="POST",
    )
    # BACKLOG #1125 (ASVS 4.2.1) and #1979: the reply is read by the same bounded reader as every
    # connector reply, so misframed headers, a malformed chunked body, an over-cap body and a body
    # cut short are all refused. Imported here to match the length helper's import above; FlowError
    # keeps each refusal on the audited login-failure path.
    from messagefoundry.transports.bounded_read import (  # noqa: PLC0415  (matches the import above)
        AmbiguousFramingError,
        EgressReplyError,
        ResponseTooLargeError,
        TruncatedResponseError,
        read_bounded,
    )

    # Every raise sits OUTSIDE its handler on purpose. `raise ... from None` clears `__cause__`
    # but leaves `__context__` populated, so the HTTPError — a readable response object whose body
    # may echo the request params, this POST's client secret among them — would still be reachable
    # by a chain-walking handler. See `encode_wire_body` in transports/base.py.
    refusal: str | None = None
    unreachable = False
    # The status the endpoint answered with, None until one is read. Only the arms that set
    # `unreachable` are transport failures; every other refusal is the endpoint answering, with
    # its status or, for a header block that did not parse, with none.
    status: int | None = None
    body = b""
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 — see above
            # The production opener refuses a redirect, so anything that reaches here is a 2xx.
            # A stand-in response with no status still counts as one.
            answered = getattr(resp, "status", None)
            status = answered if isinstance(answered, int) else 200
            body = read_bounded(
                resp, limit=_MAX_TOKEN_RESPONSE_BYTES, connector="OIDC token endpoint"
            )
    except urllib.error.HTTPError as exc:
        # Read the RFC 6749 error code only; never the body verbatim (may echo request params).
        # HTTPError is an OSError, so this arm must stay above the transport arm.
        status = exc.code
        refusal = f"token endpoint returned HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        unreachable = True
        refusal = f"token endpoint unreachable: {type(exc).__name__}"
    except AmbiguousFramingError:
        refusal = "token endpoint response framed its body length ambiguously"
    except ResponseTooLargeError:
        refusal = "token endpoint response exceeds the size bound"
    except TruncatedResponseError:
        # The connection closed before the body ended: a reset, so a transport failure.
        unreachable = True
        refusal = "token endpoint closed the connection part-way through its response"
    except EgressReplyError:
        # The family, so a refusal added to bounded_read later still lands on FlowError.
        refusal = "token endpoint response could not be read"
    if refusal is not None:
        if unreachable:
            raise TokenEndpointUnreachableError(refusal)
        raise TokenRefusedError(refusal, status=status)
    # No handler here, for the same reason (BACKLOG #2048): the decode error holds the WHOLE reply,
    # tokens included. The helper also catches json's depth-limit RecursionError, which used to
    # escape this function as a non-FlowError.
    payload, refusal = json_loads_or_refusal(body)
    if refusal is not None:
        raise TokenRefusedError(
            f"token endpoint response is not valid JSON ({refusal})", status=status
        )
    if not isinstance(payload, dict):
        raise TokenRefusedError("token endpoint response is not a JSON object", status=status)
    if "id_token" not in payload:
        raise TokenRefusedError("token endpoint response carries no id_token", status=status)
    if not isinstance(payload["id_token"], str):
        raise TokenRefusedError("token endpoint returned a non-string id_token", status=status)
    return payload
