# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tokenless engine probes for the tray (ADR 0113 §2/§5).

Two credential-free HTTP reads against the engine, with **pure** classifiers so the
status-vs-foreign-vs-down and console-enabled logic is unit-tested without a network:

- :func:`probe_health` — ``GET /health`` with **no** ``Authorization`` header. A bare-``Health``-model
  decode cannot tell a foreign ``{}`` responder from the real thing (both default to
  ``status="ok"``), so :func:`classify_health` inspects the raw body for the whole of
  :data:`ENGINE_HEALTH_KEYS`.
- :func:`probe_ui` — ``GET /ui`` with redirects **not** followed: ``404`` ⇒ ``serve_ui`` off,
  ``303``→``/ui/login`` (or any non-404 answer) ⇒ the console is mounted.

No bearer token is ever sent (that would defeat the engine's idle-timeout — CWE-613 — and cross the
not-a-console boundary). Uses ``httpx`` directly (a base dependency, shared with the apiclient),
never the authenticating apiclient session.

**TLS.** The engine serves https by default (ADR 0172), so the probe client must be able to
*verify* that server certificate. It trusts one of two things, and never neither:

- **A pinned PEM** (``cacert``) when the config carries one. That is the certificate the engine
  minted for itself, which no trust store holds, found by
  :func:`messagefoundry.tray.config.generated_cert_path` or set as ``engine_cacert`` in
  ``tray.toml``. It becomes the context's ONLY trust anchor, the same way ``cacert`` works in
  :mod:`messagefoundry.apiclient.client`.
- **The OS trust store** (``truststore``, a base dependency) otherwise, mirroring the engine
  client's default posture. On a domain-joined box an internal-CA/AD-CS operator chain then
  verifies with no per-machine wrangling.

Verification is **never** disabled: there is no ``verify=False`` path here, by
design, because a probe that trusts anything cannot distinguish the real engine from a
man-in-the-middle and the tray's whole job is to report which one answered.

**Why ``truststore`` is safe here but not in** :mod:`messagefoundry.auth.oidc_http`. That module
rejects ``truststore`` for a real reason: its ``SSLContext`` flips a *shared inner* context to
``check_hostname=False`` / ``verify_mode=CERT_NONE`` for the duration of a handshake, and
``_verify_peercerts`` reads those attributes back afterwards — so two **concurrent** handshakes on
one context can let a peer through unverified. The tray never creates that condition: a context is
built per :func:`make_probe_client` (never shared between clients), each poller owns exactly one
client, and that client is driven only by the single ``mefor-tray-poller`` thread, which runs
``/health`` then ``/ui`` **sequentially**. Keeping ``truststore`` here means the tray and the web
console/`apiclient` trust the *same* engine certificate by the *same* rules — an operator who got
the console working does not then have to debug the tray. If a second concurrent probe is ever
added, this analysis must be redone (or the client moved to ``ssl.create_default_context()``,
which on Windows also reads the machine CA/ROOT stores; see ``auth/oidc_http``).
"""

from __future__ import annotations

import json
import logging
import ssl

import httpx

from messagefoundry.tray.config import is_tls_url
from messagefoundry.tray.state import HealthProbe, UiProbe

log = logging.getLogger("messagefoundry.tray.probe")

DEFAULT_TIMEOUT_S = 2.0

#: ASVS 15.2.2 (BACKLOG #1577): the ceiling on a reply body either probe will buffer.
#:
#: The tray reads exactly two things. ``/health`` is a small JSON object -- a status word, a version,
#: a little metadata. ``/ui`` is read for its STATUS CODE alone and its body is thrown away. 1 MiB is
#: generous for the first and irrelevant to the second, and it is the same shape of number, chosen
#: the same way, as the 256 KiB ceiling the engine applies to a token endpoint
#: (``transports.bounded_read.MAX_TOKEN_RESPONSE_BYTES``).
#:
#: It is deliberately far below the ``apiclient``'s 128 MiB. That client has to be able to receive a
#: whole HL7 message back inside a JSON envelope; the tray never asks for one, so a ceiling sized for
#: the apiclient's job would be dead headroom on this hop.
#:
#: The bound matters here more than its size suggests: the poller calls both probes on a repeating
#: schedule, and :func:`classify_health` explicitly models a NON-ENGINE server answering that port. A
#: local process squatting it would otherwise drive the tray's memory one poll at a time. Nothing
#: raises -- see :func:`_get_bounded` for what a probe does instead.
#:
#: The number is NOT imported from ``transports/``: ADR 0113 keeps ``tray/`` to stdlib plus httpx,
#: which is the same layering reason ``apiclient`` duplicates its own bounds.
MAX_PROBE_RESPONSE_BYTES = 1024 * 1024


#: Every key the engine's tokenless ``GET /health`` carries (BACKLOG #1715).
#:
#: The route answers through ``api/models.Health``, which declares ``status``, ``version`` and
#: ``observed_client`` and is serialized WITHOUT ``exclude_none``, so all three names are present on
#: every reply.
#:
#: **The NAMES are the contract; the VALUES are not, and must never be keyed on.** ``version`` is
#: ``null`` to an unauthenticated caller under ASVS 13.4.6, but is the real build string on an engine
#: with ``[auth] enabled = false`` -- ``allow_no_auth`` hands even a tokenless caller the system
#: identity. ``observed_client`` is ``null`` unless ``[security].allowed_client_networks`` is in use.
#: The key SET is the one thing steady across all of those, which is why :func:`classify_health`
#: keys on it.
#:
#: This set must stay a SUBSET of what the route actually sends, and
#: ``tests/test_client_network_allowlist.py`` pins that against the real app in-process. **That pin
#: is a SAME-TREE check and its limit matters:** it catches a ``Health`` change landing beside this
#: file, and it CANNOT catch an older tray probing a newer engine, which is the only way a key goes
#: missing at runtime. Nothing here gates that skew; containment (below) is what keeps it survivable.
ENGINE_HEALTH_KEYS = frozenset({"status", "version", "observed_client"})


def classify_health(status_code: int | None, body: object) -> HealthProbe:
    """Pure: map an HTTP status + parsed body to a :class:`HealthProbe`.

    ``None`` status ⇒ the socket did not answer ⇒ :data:`DOWN`. A ``200`` whose body is a JSON
    object carrying every one of :data:`ENGINE_HEALTH_KEYS` is our ``/health`` ⇒ :data:`OK`.
    Anything else that answered is some other server ⇒ :data:`FOREIGN`.

    Keying on the key set rather than on the ``status`` key alone is BACKLOG #1715: ``{"status":
    "ok"}`` is the commonest health body in the industry, so the old single-key test called every
    such responder our engine and left :data:`FOREIGN` reachable only for a non-JSON answer. See
    :data:`ENGINE_HEALTH_KEYS` for why the names and not the values.

    **Containment, not equality, and that is deliberate.** A body carrying the three names plus
    others still reads :data:`OK`, so a newer engine that added a ``Health`` field is still our
    engine. Under equality that engine would render as "another program answers on this port" -- a
    loud, wrong alarm from the one component whose job is naming that case. Containment cannot make
    that error: it fails only toward :data:`FOREIGN`, and only when a key goes away.
    """
    if status_code is None:
        return HealthProbe.DOWN
    if status_code == 200 and isinstance(body, dict) and ENGINE_HEALTH_KEYS.issubset(body):
        return HealthProbe.OK
    return HealthProbe.FOREIGN


def classify_ui(status_code: int | None) -> UiProbe:
    """Pure: map the ``/ui`` probe status to a :class:`UiProbe`.

    ``404`` ⇒ ``serve_ui`` off ⇒ :data:`DISABLED`. No answer ⇒ :data:`UNKNOWN` (engine down; the
    status icon already says so). Any other answer (``303``→login, ``2xx``, ``401``) ⇒ the console
    is mounted ⇒ :data:`ENABLED`.
    """
    if status_code is None:
        return UiProbe.UNKNOWN
    if status_code == 404:
        return UiProbe.DISABLED
    return UiProbe.ENABLED


def _safe_json(body: bytes | None) -> object:
    """Parse ``body`` as JSON, or return ``None`` when it is absent or not JSON.

    ``None`` in means the reply was over :data:`MAX_PROBE_RESPONSE_BYTES` and was discarded unread.
    ``None`` out is what :func:`classify_health` already reads as "not our ``/health``", so an
    oversized reply classifies :data:`~messagefoundry.tray.state.HealthProbe.FOREIGN` with no extra
    branch -- which is the correct answer, not a fallback: the engine's ``/health`` is a few hundred
    bytes, so whatever sent a megabyte is some other server.
    """
    if body is None:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def _get_bounded(client: httpx.Client, path: str) -> tuple[int, bytes | None]:
    """``GET path`` and return its status plus at most :data:`MAX_PROBE_RESPONSE_BYTES` of body.

    ASVS 15.2.2 (BACKLOG #1577). The request is dispatched with ``stream=True`` so the body is read
    a chunk at a time and abandoned the moment it passes the ceiling -- the peak allocation is the
    ceiling plus one chunk, not whatever answered the port. Over the ceiling, the body comes back
    ``None``; the STATUS is still returned, because it arrived before any of the body did and both
    classifiers are keyed on it.

    Nothing raises for being too large. A tray probe reports a state, and an oversized reply has a
    correct state to report on both paths (``FOREIGN`` for ``/health``, the status's own verdict for
    ``/ui``). A transport failure still raises ``httpx.HTTPError`` for the callers to map to
    ``DOWN``/``UNKNOWN``, and it can now surface mid-body rather than only at connect.

    The body is drained rather than dropped unread so the connection returns to the pool: the poller
    runs ``/health`` then ``/ui`` sequentially on one client, and abandoning a socket per probe would
    force a fresh connect on every tick.

    ``follow_redirects`` is passed explicitly rather than left to the client default. ``/ui`` answers
    ``303``; a followed redirect would turn it into the ``200`` login page and destroy the only
    signal :func:`classify_ui` reads.
    """
    request = client.build_request("GET", path)
    response = client.send(request, stream=True, follow_redirects=False)
    try:
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > MAX_PROBE_RESPONSE_BYTES:
                return response.status_code, None
            chunks.append(chunk)
        return response.status_code, b"".join(chunks)
    finally:
        response.close()


def probe_health(client: httpx.Client) -> HealthProbe:
    """Probe ``GET /health`` tokenlessly via ``client`` (its ``base_url`` is the engine URL)."""
    try:
        status_code, body = _get_bounded(client, "/health")
    except httpx.HTTPError:
        return HealthProbe.DOWN
    return classify_health(status_code, _safe_json(body))


def probe_ui(client: httpx.Client) -> UiProbe:
    """Probe ``GET /ui`` tokenlessly, without following the login redirect.

    The body is read only to keep the connection reusable and is never looked at --
    :func:`classify_ui` decides on the status code alone. A ``/ui`` page past the bound therefore
    cannot change this verdict, it just does not get buffered.
    """
    try:
        status_code, _ = _get_bounded(client, "/ui")
    except httpx.HTTPError:
        return UiProbe.UNKNOWN
    return classify_ui(status_code)


def build_verify(engine_url: str, cacert: str | None = None) -> ssl.SSLContext | bool:
    """The ``verify=`` httpx should use for ``engine_url`` — pinned TLS, OS-trust-store TLS, or ``True``.

    Only an https URL gets a context: httpx ignores ``verify`` for plaintext http, and building
    one there would make an http-only tray import ``truststore`` for nothing. The ``True`` returned
    for http is httpx's own default, not a relaxation — there is no code path that yields ``False``.

    ``cacert`` pins trust to exactly that PEM. **A pin that cannot be loaded falls back to the OS
    trust store, which still verifies.** The common cause is a tray started before the engine's
    first run, when the pair is not minted yet. The poller rebuilds its client once the file
    appears; until then the engine reads as down, and the warning names the path.
    """
    if not is_tls_url(engine_url):
        return True
    if cacert is not None:
        try:
            return ssl.create_default_context(cafile=cacert)
        except (OSError, ssl.SSLError) as exc:
            log.warning(
                "cannot load the engine certificate %s (%s); verifying against the OS trust store "
                "until it can be loaded.",
                cacert,
                exc,
            )
    # Lazily imported so the http path never pays for it, matching apiclient's convention.
    import truststore

    # A FRESH context per call, never a module-level singleton: truststore mutates a shared inner
    # context mid-handshake, so two clients sharing one context could race into CERT_NONE (the
    # hazard auth/oidc_http.py documents). One context per client keeps that unreachable.
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def make_probe_client(
    engine_url: str, timeout: float = DEFAULT_TIMEOUT_S, *, cacert: str | None = None
) -> httpx.Client:
    """A tokenless httpx client for probing: short timeout, no redirect-follow by default.

    Never carries an ``Authorization`` header — the whole point of the tray's boundary. An https
    engine URL gets a verifying TLS context (see :func:`build_verify`); a failed verification
    surfaces as an ``httpx.HTTPError`` and therefore as ``DOWN``/``UNKNOWN``, never as a silent
    downgrade to an unverified connection.

    **ASVS 4.2.5 — a NAMED residual, not an oversight.** ``engine_url`` is not length-bounded the way
    the outbound transports and ``apiclient`` are. Three facts make that proportionate rather than a
    gap, and all three must stay true or this needs revisiting: the client is **tokenless** (no
    credential can overflow), the URL is **local operator config** pointing at this host's own engine
    (not attacker-influenceable and not message-derived), and ``tray/`` is deliberately stdlib+httpx
    only (ADR 0113) — importing ``transports/`` to share the constant would breach the same layering
    ADR 0088 protects for ``apiclient``, and a third copy of an 8192 that nothing pins is worse than
    a documented absence. If the tray ever carries a token or takes a remote URL, close it.
    """
    return httpx.Client(
        base_url=engine_url.rstrip("/"),
        timeout=timeout,
        follow_redirects=False,
        verify=build_verify(engine_url, cacert),
    )
