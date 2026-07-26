# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
import json
import secrets
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

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

    def put(self, flow_id: str, flow: PendingFlow) -> None:
        """Stage ``flow`` under ``sha256(flow_id)``, enforcing the global and per-IP caps."""
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
        self._entries[self._key(flow_id)] = flow

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
    )
    cache.put(flow_id, flow)
    return flow_id, flow


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
    acr_values: str | None = None,
    prompt: str | None = None,
) -> str:
    """Build the front-channel authorization-code + PKCE (S256) redirect URL (``response_mode=query``)."""
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
    }
    if acr_values:
        params["acr_values"] = acr_values
    if prompt:
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
    client_secret: str | None,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    opener: urllib.request.OpenerDirector,
    timeout: float = 10.0,
) -> Mapping[str, object]:
    """POST the authorization ``code`` (+ the PKCE verifier) to the token endpoint; return the JSON.

    ``opener`` is injected (production supplies a hardened, CA-pinned, no-redirect opener). A
    confidential client sends ``client_secret_post``; a public client omits it and relies on PKCE.
    Raises :class:`FlowError` on any non-2xx, oversized, or non-JSON response — PHI/secret-safe: the
    secret, the ``code``, and the tokens never enter an exception message.
    """
    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if client_secret is not None:
        form["client_secret"] = client_secret
    data = urllib.parse.urlencode(form).encode("ascii")
    req = urllib.request.Request(  # noqa: S310 — scheme is validated https at config load
        token_endpoint,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 — see above
            body = resp.read(_MAX_TOKEN_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        # Read the RFC 6749 error code only; never the body verbatim (may echo request params).
        raise FlowError(f"token endpoint returned HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FlowError(f"token endpoint unreachable: {type(exc).__name__}") from None
    if len(body) > _MAX_TOKEN_RESPONSE_BYTES:
        raise FlowError("token endpoint response exceeds the size bound")
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise FlowError("token endpoint response is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise FlowError("token endpoint response is not a JSON object")
    if "id_token" not in payload:
        raise FlowError("token endpoint response carries no id_token")
    return payload
