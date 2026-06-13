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
    ProvidersInfo,
    RoleInfo,
    SessionInfo,
    SessionList,
    SimpleMessage,
    UserSummary,
)
from messagefoundry.api.models import (
    ChannelInfo,
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

    There is no transport TLS yet, so a remote ``http://`` URL would put the bearer token and PHI on
    the wire in cleartext. Loopback http and any https are fine; a non-loopback http URL requires an
    explicit ``allow_insecure`` opt-in (trusted-network dev only), which is then loudly warned."""
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
    ) -> None:
        self.base_url = base_url.rstrip("/")
        _assert_safe_transport(self.base_url, allow_insecure=allow_insecure)
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout)
        self._token: str | None = None
        self._user: CurrentUser | None = None

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

    # --- requests ------------------------------------------------------------

    def _get(self, path: str, **params: object) -> httpx.Response:
        return self._request("GET", path, params={k: v for k, v in params.items() if v is not None})

    def _request(self, method: str, path: str, **kw: object) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else None
        try:
            response = self._http.request(method, path, headers=headers, **kw)  # type: ignore[arg-type]
        except httpx.HTTPError as exc:
            raise ApiError(f"could not reach engine at {self.base_url}: {exc}") from exc
        if response.status_code >= 400:
            raise ApiError(_error_detail(response), status=response.status_code)
        return response

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

    def status(self) -> SystemStatus:
        return _decode(self._get("/status"), SystemStatus)

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
