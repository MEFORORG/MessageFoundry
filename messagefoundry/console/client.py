# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Synchronous API client for the console.

A small typed wrapper over the localhost REST API. It is deliberately **synchronous** —
Qt has its own event loop and localhost calls are sub-millisecond, so blocking briefly on
the GUI thread is simpler and safe enough for Phase 1 (a short timeout guards against a
hung/dead server). It returns the API's pydantic models so callers get typed, validated
data rather than raw dicts.

Kept free of any Qt import so it can be unit-tested on its own against a real server.
"""

from __future__ import annotations

import logging
import ssl
from collections.abc import Callable, Sequence
from json import JSONDecodeError
from types import TracebackType
from typing import TypeVar
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ValidationError

from messagefoundry.api.auth_models import (
    AdGroupMap,
    AdGroupMapEntry,
    AuditList,
    ChannelScope,
    CurrentUser,
    LoginResponse,
    MfaConfirmResponse,
    MfaEnrollResponse,
    MfaStatusResponse,
    ProvidersInfo,
    RoleInfo,
    SessionInfo,
    SessionList,
    SimpleMessage,
    UserSummary,
)
from messagefoundry.api.models import (
    AlertsConfig,
    ChannelInfo,
    ClusterNodeList,
    ClusterStatus,
    ConnectionEventInfo,
    ConnectionRow,
    DeadLetterList,
    DeadLetterReplayResult,
    Health,
    IntegrityResult,
    MessageDetail,
    MessageList,
    PurgeResult,
    ReloadResult,
    ReplayResult,
    StatsResetResult,
    StatsResponse,
    SystemStatus,
)

__all__ = ["EngineClient", "ApiError"]

_log = logging.getLogger(__name__)
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class ApiError(RuntimeError):
    """An API call failed (transport error, a non-2xx response, or an undecodable 2xx body)."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


_Model = TypeVar("_Model", bound=BaseModel)


def _decode(response: httpx.Response, model: type[_Model]) -> _Model:
    """Validate a 2xx JSON body into ``model``, mapping schema/JSON errors to :class:`ApiError`.

    Preserves the client's contract that every call raises only ``ApiError``: a malformed or
    schema-mismatched success body (e.g. an engine version skew) would otherwise raise pydantic's
    ``ValidationError`` straight out of a Qt slot into the event loop (H2/L2)."""
    try:
        return model.model_validate(response.json())
    except (ValidationError, JSONDecodeError) as exc:
        raise ApiError(f"invalid response from engine: {exc}") from exc


def _decode_list(response: httpx.Response, model: type[_Model]) -> list[_Model]:
    """List form of :func:`_decode` (the body must be a JSON array of ``model`` objects)."""
    try:
        return [model.model_validate(item) for item in response.json()]
    except (ValidationError, JSONDecodeError, TypeError) as exc:
        raise ApiError(f"invalid response from engine: {exc}") from exc


def _assert_safe_transport(base_url: str, *, allow_insecure: bool) -> None:
    """Refuse plaintext ``http`` to a non-loopback host (CONSOLE-3).

    A remote ``http://`` URL would put the bearer token and PHI on the wire in cleartext, so a
    remote engine must be reached over the engine's built-in TLS (``https://``, WP-13a). Loopback
    http and any https are fine; a non-loopback http URL requires an explicit ``allow_insecure``
    opt-in (trusted-network dev only), which is then loudly warned."""
    parts = urlsplit(base_url)
    if parts.scheme == "https":
        return
    host = (parts.hostname or "").lower()
    if host in _LOOPBACK_HOSTS or host == "":
        return
    if allow_insecure:
        _log.warning(
            "sending credentials over plaintext http to non-loopback host %r (allow_insecure)", host
        )
        return
    raise ApiError(
        f"refusing to use plaintext http to non-loopback host {host!r}: the bearer token and PHI "
        "would cross the network in cleartext. Use an https URL, or pass --insecure for a "
        "trusted-network dev setup."
    )


def _build_verify_context(
    cacert: str | None,
    client_cert: str | None,
    client_key: str | None,
) -> ssl.SSLContext:
    """Build the TLS verification context the console uses to reach an ``https`` engine (CONSOLE-3).

    Trust model designed to keep a *remote* console low-burden:

    * **No ``cacert`` (default)** — verify the engine cert against the **operating-system trust store**
      (``truststore``). On a domain-joined PC an enterprise/AD-CS-issued cert is then trusted with no
      per-machine configuration, and public-CA certs still verify (the OS store ships the public roots).
      This replaces httpx's certifi-only default, which trusted neither an internal CA nor a self-signed
      cert and offered no override.
    * **``cacert`` set** — pin trust to exactly that PEM (a CA bundle *or* a self-signed engine cert).
      The escape hatch for a self-signed / non-domain deployment: the OS verifier won't treat a
      ``load_verify_locations`` cert as a trust anchor (verified on Windows), so we build a stdlib
      context whose only anchors are the supplied file.

    An opt-in **client** certificate (mTLS, ASVS 12.3.5) is loaded onto whichever context is built — this
    is also what replaces httpx 0.28's deprecated ``cert=`` keyword. Plaintext ``http`` never reaches
    this context (the ``_assert_safe_transport`` gate runs first and httpx ignores TLS settings for http).
    """
    if cacert is not None:
        ctx: ssl.SSLContext = ssl.create_default_context(cafile=cacert)
    else:
        # Function-local: truststore is a [console]-extra dep. Importing it at module top made
        # `import messagefoundry.console.client` hard-require it, which broke every non-console
        # install that imports EngineClient (e.g. the CI store/load test jobs that install only
        # [dev,sqlserver]) — matching the lazy-import convention used for every other extra dep.
        import truststore

        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if client_cert is not None:
        # keyfile=None is valid: the private key may be bundled in the client cert PEM.
        ctx.load_cert_chain(client_cert, client_key)
    return ctx


class EngineClient:
    """Blocking client for the MessageFoundry localhost API.

    Use as a context manager (or call :meth:`close`) to release the connection pool.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8765",
        *,
        timeout: float = 5.0,
        allow_insecure: bool = False,
        cacert: str | None = None,
        tls_client_cert: str | None = None,
        tls_client_key: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._allow_insecure = allow_insecure
        # Retained so for_polling() can build its background client with the SAME TLS posture (a CA
        # pin / client cert that the main client trusted must not silently drop on the poll client).
        self._cacert = cacert
        self._tls_client_cert = tls_client_cert
        self._tls_client_key = tls_client_key
        _assert_safe_transport(self.base_url, allow_insecure=allow_insecure)
        # How the engine's server cert is trusted (OS store by default; `cacert` to pin a self-signed /
        # internal-CA PEM) plus an optional client cert for mutual TLS (ASVS 12.3.5) when the engine
        # requires one (api.tls_client_ca_file → CERT_REQUIRED). See _build_verify_context.
        # Built ONLY for an https engine: httpx ignores `verify` for http (the gate above already ran),
        # and building the default context imports the [console]-extra `truststore` — so an http client
        # (the load harness, any non-[console] install) must NOT need it just to construct a client.
        verify: ssl.SSLContext | bool = True
        if self.base_url.lower().startswith("https"):
            verify = _build_verify_context(cacert, tls_client_cert, tls_client_key)
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout, verify=verify)
        self._token: str | None = None
        self._user: CurrentUser | None = None
        #: Invoked when the engine demands step-up re-verification (403 + X-Step-Up-Required); the GUI
        #: prompts, calls reauth(), and returns True iff re-verified — then the request is retried.
        self._step_up_handler: Callable[[], bool] | None = None
        #: Invoked when the engine demands a second factor (403 + X-MFA-Required, WP-14); the GUI
        #: prompts for a TOTP / recovery code, calls verify_mfa(), and returns True iff verified.
        self._mfa_handler: Callable[[], bool] | None = None

    def __enter__(self) -> "EngineClient":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def for_polling(self) -> "EngineClient":
        """A second client dedicated to **background (off-thread) reads** — the nav health poll, the
        Engine Status refresh, and the per-page auto-refresh.

        It shares this client's bearer token but has its **own** ``httpx.Client`` connection pool and
        **no step-up/MFA handlers**, so background reader threads never contend on the main-thread
        client's pool or its mutable auth state. That separation is what makes the console
        concurrency-safe: the handler-bearing, token-mutating primary client stays **main-thread
        only** (it serves the modal sign-in/step-up/MFA flows and user actions), while this read-only
        client is the only one shared across worker threads — and sharing *it* is safe because its
        token is never mutated, its 403→prompt retry branches are inert (no handlers), and
        ``httpx.Client`` is itself thread-safe for concurrent requests.

        The token is copied at creation. A mid-session credential change relaunches the console
        (sign-out/expiry quits the app), so this snapshot can't drift out from under a live window.
        """
        poll = EngineClient(
            self.base_url,
            timeout=self._timeout,
            allow_insecure=self._allow_insecure,
            cacert=self._cacert,
            tls_client_cert=self._tls_client_cert,
            tls_client_key=self._tls_client_key,
        )
        poll._token = self._token
        poll._user = self._user
        return poll

    # --- requests ------------------------------------------------------------

    def _get(self, path: str, **params: object) -> httpx.Response:
        return self._request("GET", path, params={k: v for k, v in params.items() if v is not None})

    def _request(
        self,
        method: str,
        path: str,
        *,
        _allow_step_up: bool = True,
        _allow_mfa: bool = True,
        **kw: object,
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else None
        try:
            response = self._http.request(method, path, headers=headers, **kw)  # type: ignore[arg-type]
        except httpx.HTTPError as exc:
            raise ApiError(f"could not reach engine at {self.base_url}: {exc}") from exc
        # Second factor (WP-14, ASVS 6.3.3): the engine refuses a sensitive op with 403 +
        # X-MFA-Required when this session hasn't satisfied MFA. Prompt for a code (the handler calls
        # verify_mfa()) and retry once — transparently, like step-up. Checked first because the engine
        # gates MFA before step-up.
        if (
            _allow_mfa
            and response.status_code == 403
            and response.headers.get("X-MFA-Required")
            and self._mfa_handler is not None
            and self._mfa_handler()
        ):
            return self._request(
                method, path, _allow_step_up=_allow_step_up, _allow_mfa=False, **kw
            )
        # Step-up re-verification (ASVS 7.5.3): the engine refuses a sensitive op with 403 +
        # X-Step-Up-Required when this session hasn't re-proved its credential recently. Prompt the
        # user (the handler re-authenticates via reauth()) and retry once, so the action goes through
        # transparently instead of surfacing a raw 403.
        if (
            _allow_step_up
            and response.status_code == 403
            and response.headers.get("X-Step-Up-Required")
            and self._step_up_handler is not None
            and self._step_up_handler()
        ):
            return self._request(method, path, _allow_step_up=False, _allow_mfa=_allow_mfa, **kw)
        if response.status_code >= 400:
            raise ApiError(_error_detail(response), status=response.status_code)
        return response

    def set_step_up_handler(self, handler: Callable[[], bool] | None) -> None:
        """Register the callback invoked when the engine demands step-up re-verification (403 +
        ``X-Step-Up-Required``). It must prompt the user, call :meth:`reauth`, and return ``True`` iff
        re-verified — the original request is then retried once. Runs on the calling thread (the
        console's sensitive actions run on the Qt main thread, so a modal dialog is safe)."""
        self._step_up_handler = handler

    def reauth(self, password: str) -> None:
        """Step-up re-verification (ASVS 7.5.3): re-prove the current credential to refresh this
        session's step-up window. Raises :class:`ApiError` (status 403) on a wrong password. Does not
        itself trigger the step-up handler (``/me/reauth`` is not a step-up-gated route)."""
        self._request("POST", "/me/reauth", json={"password": password}, _allow_step_up=False)

    def set_mfa_handler(self, handler: Callable[[], bool] | None) -> None:
        """Register the callback invoked when the engine demands a second factor (403 +
        ``X-MFA-Required``, WP-14). It must prompt for a TOTP / recovery code, call :meth:`verify_mfa`,
        and return ``True`` iff verified — the original request is then retried once."""
        self._mfa_handler = handler

    # --- MFA (WP-14, ASVS 6.3.3) ---------------------------------------------

    def mfa_status(self) -> MfaStatusResponse:
        """The signed-in user's MFA posture (enabled, enrolled-at, recovery codes left, required)."""
        return _decode(self._get("/me/mfa"), MfaStatusResponse)

    def enroll_mfa(self) -> MfaEnrollResponse:
        """Begin TOTP enrollment: stage a secret and return it + the ``otpauth://`` URI. Step-up gated,
        so the step-up handler may prompt for the password before this returns."""
        return _decode(self._request("POST", "/me/mfa/enroll"), MfaEnrollResponse)

    def confirm_mfa(self, code: str) -> list[str]:
        """Confirm enrollment with a live TOTP code; activates MFA and returns the one-time recovery
        codes (shown **once**). Raises :class:`ApiError` (400) on a wrong code."""
        return _decode(
            self._request("POST", "/me/mfa/confirm", json={"code": code}), MfaConfirmResponse
        ).recovery_codes

    def verify_mfa(self, code: str) -> None:
        """Satisfy the current session's second factor with a TOTP or single-use recovery code. Raises
        :class:`ApiError` (401) on a wrong code. Does not itself trigger the MFA handler."""
        self._request("POST", "/auth/mfa-verify", json={"code": code}, _allow_mfa=False)

    def disable_mfa(self) -> None:
        """Turn off the signed-in user's TOTP MFA (step-up gated)."""
        self._request("DELETE", "/me/mfa")

    def reset_user_mfa(self, user_id: str) -> None:
        """Admin: clear a user's MFA enrollment and revoke their sessions (step-up gated)."""
        self._request("POST", f"/users/{user_id}/reset-mfa")

    # --- endpoints -----------------------------------------------------------

    def health(self) -> Health:
        return _decode(self._get("/health"), Health)

    def list_channels(self) -> list[ChannelInfo]:
        """Inbound connections (id = connection name) — used by the Log Search filter."""
        return _decode_list(self._get("/channels"), ChannelInfo)

    def connections(self) -> list[ConnectionRow]:
        return _decode_list(self._get("/connections"), ConnectionRow)

    # --- code-first connection operations ------------------------------------

    def start_connection(self, name: str) -> None:
        self._request("POST", f"/connections/{name}/start")

    def stop_connection(self, name: str) -> None:
        self._request("POST", f"/connections/{name}/stop")

    def restart_connection(self, name: str) -> None:
        self._request("POST", f"/connections/{name}/restart")

    def purge_connection(self, name: str, scope: str = "all") -> PurgeResult:
        return _decode(
            self._request("POST", f"/connections/{name}/purge", params={"scope": scope}),
            PurgeResult,
        )

    def reset_stats(
        self,
        *,
        all_connections: bool = False,
        targets: Sequence[tuple[str, str, str | None]] = (),
    ) -> StatsResetResult:
        """Reset the connections-dashboard counters for ``targets`` (each ``(role, channel_id,
        destination)``), or for every connection when ``all_connections`` is set."""
        body = {
            "all": all_connections,
            "targets": [
                {"role": role, "channel_id": channel_id, "destination": destination}
                for (role, channel_id, destination) in targets
            ],
        }
        return _decode(self._request("POST", "/statistics/reset", json=body), StatsResetResult)

    def list_messages(
        self,
        *,
        channel_id: str | None = None,
        status: str | None = None,
        message_type: str | None = None,
        control_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
        audit_summary: bool = False,
    ) -> MessageList:
        response = self._get(
            "/messages",
            channel_id=channel_id,
            status=status,
            message_type=message_type,
            control_id=control_id,
            limit=limit,
            offset=offset,
            audit_summary=audit_summary or None,
        )
        return _decode(response, MessageList)

    def get_message(self, message_id: str) -> MessageDetail:
        return _decode(self._get(f"/messages/{message_id}"), MessageDetail)

    def replay(self, message_id: str) -> ReplayResult:
        return _decode(self._request("POST", f"/messages/{message_id}/replay"), ReplayResult)

    # --- dead letters --------------------------------------------------------

    def list_dead_letters(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
        audit_summary: bool = False,
    ) -> DeadLetterList:
        """Dead-lettered deliveries (newest first), optionally scoped to an inbound/outbound."""
        response = self._get(
            "/dead-letters",
            channel_id=channel_id,
            destination_name=destination_name,
            limit=limit,
            offset=offset,
            audit_summary=audit_summary or None,
        )
        return DeadLetterList.model_validate(response.json())

    def list_connection_events(
        self,
        *,
        connection: str | None = None,
        kind: str | None = None,
        limit: int = 200,
    ) -> list[ConnectionEventInfo]:
        """The Corepoint-style connection/transport event log (#46), newest first — metadata only (no
        PHI), so it needs only ``monitoring:read``."""
        response = self._get("/events", connection=connection, kind=kind, limit=limit)
        return [ConnectionEventInfo.model_validate(e) for e in response.json()]

    def replay_dead_letters(
        self, *, channel_id: str | None = None, destination_name: str | None = None
    ) -> DeadLetterReplayResult:
        """Re-queue dead-lettered deliveries (``None`` scope = all; a channel-scoped user must
        name their channel — an unscoped replay-all is denied server-side)."""
        return DeadLetterReplayResult.model_validate(
            self._request(
                "POST",
                "/dead-letters/replay",
                json={"channel_id": channel_id, "destination_name": destination_name},
            ).json()
        )

    # --- config --------------------------------------------------------------

    def reload_config(self, config_dir: str | None = None) -> ReloadResult:
        """Apply code-first config atomically (``None`` = the server's startup --config dir)."""
        return ReloadResult.model_validate(
            self._request("POST", "/config/reload", json={"config_dir": config_dir}).json()
        )

    def stats(self) -> StatsResponse:
        return _decode(self._get("/stats"), StatsResponse)

    def alerts_rules(self) -> AlertsConfig:
        """Read-only view of the loaded ``[alerts]`` transports + rule set (ADR 0014, BACKLOG #22b).
        No secrets/recipients are returned. Gated by ``monitoring:read`` like :meth:`stats`."""
        return _decode(self._get("/alerts/rules"), AlertsConfig)

    def status(self) -> SystemStatus:
        return _decode(self._get("/status"), SystemStatus)

    def cluster_status(self) -> ClusterStatus:
        """This node's active-passive role / leadership (cheap in-memory read; MONITORING_READ)."""
        return _decode(self._get("/cluster/status"), ClusterStatus)

    def cluster_nodes(self) -> ClusterNodeList:
        """Cluster membership + the derived live leader + lease state (MONITORING_READ)."""
        return _decode(self._get("/cluster/nodes"), ClusterNodeList)

    def integrity_check(self) -> IntegrityResult:
        # The DB integrity scan (PRAGMA quick_check) is exactly the call that runs long on a large
        # store — the blanket short timeout would spuriously report it as "could not reach engine".
        # Give this one request a generous timeout (review M-27).
        return _decode(
            self._request("POST", "/status/integrity-check", timeout=httpx.Timeout(300.0)),
            IntegrityResult,
        )

    # --- authentication ------------------------------------------------------

    @property
    def token(self) -> str | None:
        return self._token

    @property
    def current_user(self) -> CurrentUser | None:
        return self._user

    def can(self, permission: str) -> bool:
        """True if the signed-in user holds ``permission`` (False when not signed in)."""
        return self._user is not None and permission in self._user.permissions

    def set_token(self, token: str) -> None:
        """Adopt an existing token (e.g. from the OS keyring) and refresh the cached user."""
        self._token = token
        self._user = self.me()

    def clear_auth(self) -> None:
        self._token = None
        self._user = None

    def providers(self) -> ProvidersInfo:
        """Which login methods the engine offers (callable before authenticating)."""
        return _decode(self._get("/auth/providers"), ProvidersInfo)

    def login(self, username: str, password: str, *, provider: str = "local") -> LoginResponse:
        result = _decode(
            self._request(
                "POST",
                "/auth/login",
                json={"username": username, "password": password, "provider": provider},
            ),
            LoginResponse,
        )
        self._token = result.token
        self._user = result.user
        return result

    def me(self) -> CurrentUser:
        return _decode(self._get("/auth/me"), CurrentUser)

    def logout(self) -> None:
        try:
            self._request("POST", "/auth/logout")
        finally:
            self.clear_auth()

    def change_password(self, current_password: str, new_password: str) -> None:
        self._request(
            "POST",
            "/me/password",
            json={"current_password": current_password, "new_password": new_password},
        )
        self.clear_auth()  # the server revokes sessions on change; sign in again

    # --- sessions (WP-10) ----------------------------------------------------

    def list_sessions(self) -> list[SessionInfo]:
        """The signed-in user's active sessions; the entry with ``current=True`` is this one."""
        return _decode(self._get("/me/sessions"), SessionList).sessions

    def revoke_session(self, session_id: str) -> None:
        """Revoke one of the user's own sessions by its ``id`` (the session's ``token_hash``)."""
        self._request("DELETE", f"/me/sessions/{session_id}")

    def revoke_other_sessions(self) -> str:
        """Revoke every session except this one ("sign out everywhere else"); returns the summary."""
        return _decode(self._request("DELETE", "/me/sessions"), SimpleMessage).detail

    def revoke_user_sessions(self, user_id: str) -> str:
        """Admin force-sign-out: revoke all of ``user_id``'s sessions; returns the summary."""
        return _decode(self._request("DELETE", f"/users/{user_id}/sessions"), SimpleMessage).detail

    # --- user administration -------------------------------------------------

    def list_roles(self) -> list[RoleInfo]:
        return _decode_list(self._get("/roles"), RoleInfo)

    def list_users(self) -> list[UserSummary]:
        return _decode_list(self._get("/users"), UserSummary)

    def create_user(
        self,
        username: str,
        password: str,
        *,
        display_name: str | None = None,
        email: str | None = None,
        roles: list[str] | None = None,
    ) -> UserSummary:
        body = {
            "username": username,
            "password": password,
            "display_name": display_name,
            "email": email,
            "roles": roles or [],
        }
        return _decode(self._request("POST", "/users", json=body), UserSummary)

    def set_user_roles(self, user_id: str, roles: list[str]) -> None:
        self._request("PUT", f"/users/{user_id}/roles", json={"roles": roles})

    def get_channel_scope(self, user_id: str) -> list[str] | None:
        """A user's per-channel RBAC scope (``None`` = all channels)."""
        return _decode(self._get(f"/users/{user_id}/channel-scope"), ChannelScope).channels

    def set_channel_scope(self, user_id: str, channels: list[str] | None) -> None:
        """Set a user's per-channel RBAC scope (``None`` = all channels)."""
        self._request("PUT", f"/users/{user_id}/channel-scope", json={"channels": channels})

    def delete_user(self, user_id: str) -> None:
        self._request("DELETE", f"/users/{user_id}")

    def audit(self, *, limit: int = 100) -> AuditList:
        return _decode(self._get("/audit", limit=limit), AuditList)

    def ad_group_map(self) -> AdGroupMap:
        return _decode(self._get("/ad-group-map"), AdGroupMap)

    def set_ad_group_map(self, entries: list[tuple[str, str]]) -> None:
        payload = {
            "entries": [AdGroupMapEntry(ad_group=g, role=r).model_dump() for g, r in entries]
        }
        self._request("PUT", "/ad-group-map", json=payload)


def _error_detail(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail")
    except Exception:
        detail = None
    return f"{response.status_code}: {detail or response.text or response.reason_phrase}"
