# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Console entrypoint:  python -m messagefoundry.console [--url URL]

Connects to a running engine API (default http://127.0.0.1:8765 — start one with
``python -m messagefoundry serve``), opens the admin window, and auto-refreshes channel and
message state on a timer. The interval is user-selectable from the window (link → dialog) and
remembered across runs (QSettings); ``--poll`` is just the default for a first run.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable
from importlib.resources import files

from PySide6.QtCore import QSettings
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import QApplication, QDialog

from messagefoundry.console import theme
from messagefoundry.console.change_password import ChangePasswordDialog
from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.console.login import LoginDialog
from messagefoundry.console.mfa import MfaVerifyDialog, make_mfa_handler
from messagefoundry.console.reauth import make_step_up_handler
from messagefoundry.console.shards import ShardRegistry
from messagefoundry.console.shell import AppWindow

log = logging.getLogger(__name__)

_SETTINGS_KEY = "autorefresh/seconds"
_DEFAULT_SIZE = (2560, 1440)
# The cached token is a PHI-scoped bearer credential (the user's full RBAC, incl. messages:view_raw)
# valid for the server-side session lifetime. It lives in the OS keyring (Windows Credential
# Manager) and is re-validated against /auth/me on startup, so a stale/revoked one is discarded.
_KEYRING_SERVICE = "MessageFoundry"


def _app_icon() -> QIcon:
    """The MessageFoundry badge for the window title bar / Windows taskbar.

    Ships in the wheel at ``messagefoundry/console/resources/app.ico`` (a multi-resolution
    icon) and is the same artwork the Desktop/Start-Menu shortcut uses. A missing or unreadable
    icon must never stop the console from opening, so every failure degrades to a null QIcon.
    """
    try:
        resource = files("messagefoundry.console") / "resources" / "app.ico"
        # A normal pip install exposes the resource as a real on-disk path, so QIcon reads the
        # .ico directly and keeps every embedded size (Qt picks the best per request).
        icon = QIcon(str(resource))
        if not icon.isNull():
            return icon
        # Zip/odd install where the path isn't real: fall back to the bytes (single best frame).
        pixmap = QPixmap()
        pixmap.loadFromData(resource.read_bytes(), b"ICO")
        return QIcon(pixmap)
    except (OSError, ModuleNotFoundError):
        return QIcon()


def _load_token(base_url: str) -> str | None:
    try:
        import keyring
        from keyring.errors import KeyringError
    except ImportError:
        return None
    try:
        return keyring.get_password(_KEYRING_SERVICE, base_url)
    except KeyringError as exc:  # keyring present but locked/unavailable — fall back to sign-in
        log.warning("could not read stored credential: %s", exc)
        return None


def _save_token(base_url: str, token: str) -> None:
    try:
        import keyring
        from keyring.errors import KeyringError
    except ImportError:
        return  # no keyring backend — the session simply isn't remembered across launches
    try:
        keyring.set_password(_KEYRING_SERVICE, base_url, token)
    except KeyringError as exc:
        log.warning("could not store credential (will re-prompt next launch): %s", exc)


def _delete_token(base_url: str) -> bool:
    """Clear the stored token. Returns False if it may still be present (CONSOLE-2)."""
    try:
        import keyring
        from keyring.errors import KeyringError, PasswordDeleteError
    except ImportError:
        return True  # nothing was persisted to begin with
    try:
        keyring.delete_password(_KEYRING_SERVICE, base_url)
        return True
    except PasswordDeleteError:
        return True  # no such entry — already absent, effectively cleared
    except KeyringError as exc:
        log.warning("could not clear stored credential — it may still be present: %s", exc)
        return False


def _authenticate(client: EngineClient) -> bool:
    """Ensure the client is authenticated when the engine requires it.

    Returns True to proceed (authenticated, or auth disabled, or unreachable so the window can show
    the connection error), or False if the user cancelled the sign-in dialog.
    """
    try:
        client.providers()  # 200 when auth is on; 503 when disabled
    except ApiError as exc:
        if exc.status == 503 or exc.status is None:
            return True  # auth disabled, or unreachable (the window surfaces the error)
    stored = _load_token(client.base_url)
    if stored:
        try:
            client.set_token(stored)
            return True
        except ApiError:
            client.clear_auth()
            _delete_token(client.base_url)
    while True:
        login = LoginDialog(client)
        if login.exec() != QDialog.DialogCode.Accepted:
            return False
        if not login.must_change_password:
            # A second factor is required (WP-14): prompt for the TOTP / recovery code now. If the
            # user cancels, REVOKE the un-MFA'd session server-side (not just locally) — the login
            # already minted a durable session row, so a bare clear_auth() would leave it alive until
            # expiry. logout() hits /auth/logout to revoke it (mirrors _sign_out); no keyring entry was
            # saved yet on this branch, so a local clear is the only fallback if the revoke call fails.
            if login.mfa_required and not _verify_mfa(client):
                try:
                    client.logout()
                except ApiError as exc:
                    log.warning("server-side logout after MFA cancel failed: %s", exc)
                    client.clear_auth()
                continue
            break
        # Forced change: the session is must-change-restricted (403 on protected routes). Let the
        # user set a new password, prefilling the current one they just typed and the server
        # accepted.
        change = ChangePasswordDialog(client, current_password=login.entered_password)
        login.entered_password = ""  # nosec B105 (clears the plaintext seam, not a credential; M4)
        if change.exec() != QDialog.DialogCode.Accepted:
            client.clear_auth()  # drop the restricted token; the user bailed out
            continue  # back to sign-in (still blocked until they change it)
        # change_password() already revoked + cleared the session server-side, so the loop falls
        # through to a fresh sign-in with the new password rather than admitting the dead token.
    if client.token is not None:
        _save_token(client.base_url, client.token)
    return True


def _verify_mfa(client: EngineClient) -> bool:
    """Prompt for a second factor after a login that reported ``mfa_required`` (WP-14). Returns True
    iff the TOTP / recovery code verified."""
    return MfaVerifyDialog(client).exec() == QDialog.DialogCode.Accepted


def _sign_out(client: EngineClient, app: QApplication) -> None:
    base_url = client.base_url
    try:
        client.logout()  # revoke the session server-side
    except ApiError as exc:
        log.warning("server-side logout failed: %s", exc)
    if not _delete_token(base_url):
        log.warning("local credential may not have been cleared; remove it from the OS keyring")
    app.quit()  # re-launch the console to sign in again


def _password_changed(client: EngineClient, app: QApplication) -> None:
    """Route back to sign-in after an in-app password change.

    The dialog already called ``change_password`` (server revoked the session, client cleared its
    token), so this only clears the cached keyring credential and quits — relaunch lands on the
    sign-in dialog where the user authenticates with the new password.
    """
    if not _delete_token(client.base_url):
        log.warning("local credential may not have been cleared; remove it from the OS keyring")
    app.quit()  # re-launch the console to sign in with the new password


def _session_expired(client: EngineClient, app: QApplication) -> None:
    """The session expired/was revoked mid-session (a 401 on the health poll). The token is already
    dead, so just clear the cached credential and quit — re-launch lands on the sign-in dialog (M-26)."""
    if not _delete_token(client.base_url):
        log.warning("local credential may not have been cleared; remove it from the OS keyring")
    app.quit()


def _open_window(window: AppWindow, app: QApplication) -> None:
    """Open at the default size, or maximized if the screen can't fit it.

    ``_DEFAULT_SIZE`` is in physical pixels (what the user sees on a monitor), but Qt's
    geometry and ``resize()`` are in device-independent (logical) pixels. On a HiDPI display
    (e.g. a 5K2K monitor at 200% scaling) the two differ by ``devicePixelRatio``, so we compare
    against the *physical* work area and convert the target back to logical pixels for resize().
    """
    target_w, target_h = _DEFAULT_SIZE
    screen = app.primaryScreen()
    if screen is None:
        window.resize(target_w, target_h)
        window.show()
        return
    dpr = screen.devicePixelRatio() or 1.0
    available = screen.availableGeometry()  # logical pixels
    if available.width() * dpr < target_w or available.height() * dpr < target_h:
        window.showMaximized()  # default size is too big for this display
    else:
        window.resize(round(target_w / dpr), round(target_h / dpr))
        window.show()


def _make_shard_factory(
    registry: ShardRegistry, args: argparse.Namespace
) -> Callable[[str], tuple[EngineClient, EngineClient]]:
    """Build the per-shard client factory the window calls when the operator selects a new shard.

    Each shard gets its own freshly authenticated :class:`EngineClient` (action) + a read-only
    polling copy, built with the same TLS posture as the launch client (``--insecure``/``--cacert``/
    ``--client-cert``/``--client-key``). The per-shard bearer token already works for free: the
    keyring is keyed by ``base_url`` (``_load_token``/``_save_token``), so ``_authenticate`` reuses a
    remembered token or prompts sign-in for that endpoint. A cancelled sign-in raises so the window
    keeps the previously active shard. The window owns/closes the returned clients (it caches them per
    shard and stops them on switch/teardown)."""

    def factory(shard_id: str) -> tuple[EngineClient, EngineClient]:
        shard = registry.get(shard_id)
        if shard is None:
            raise ValueError(f"unknown shard {shard_id!r}")
        client = EngineClient(
            shard.base_url,
            allow_insecure=args.insecure,
            cacert=args.cacert,
            tls_client_cert=args.client_cert,
            tls_client_key=args.client_key,
        )
        client.set_step_up_handler(make_step_up_handler(client))
        client.set_mfa_handler(make_mfa_handler(client))
        if not _authenticate(client):
            client.close()
            raise RuntimeError(f"sign-in cancelled for {shard.name}")
        return client, client.for_polling()

    return factory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="messagefoundry.console")
    parser.add_argument("--url", default="http://127.0.0.1:8765", help="engine API base URL")
    parser.add_argument("--poll", type=float, default=2.0, help="default auto-refresh seconds")
    parser.add_argument(
        "--service-name", default="MessageFoundry", help="Windows service name for the Status page"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="allow plaintext http to a non-loopback engine (trusted-network dev only; no TLS yet)",
    )
    parser.add_argument(
        "--cacert",
        default=None,
        help="PEM CA bundle (or the engine's self-signed cert) to trust for https. Omit to verify "
        "against the OS trust store (an enterprise/AD-CS-issued cert then needs no flag on a "
        "domain-joined PC); set this only for a self-signed or non-domain engine.",
    )
    parser.add_argument(
        "--client-cert",
        default=None,
        help="PEM client certificate to present for mutual TLS (ASVS 12.3.5; opt-in, https only)",
    )
    parser.add_argument(
        "--client-key",
        default=None,
        help="private key for --client-cert, when it is not bundled in the cert PEM",
    )
    args = parser.parse_args(argv)

    app = QApplication(sys.argv[:1])
    app.setOrganizationName("MessageFoundry")
    app.setApplicationName("Console")
    app.setWindowIcon(_app_icon())  # title bar + Windows taskbar branding
    # Apply the console's light theme before any window/dialog is built so sign-in inherits it too.
    theme.apply_theme(app)

    try:
        client = EngineClient(
            args.url,
            allow_insecure=args.insecure,
            cacert=args.cacert,
            tls_client_cert=args.client_cert,
            tls_client_key=args.client_key,
        )
    except ApiError as exc:
        print(f"error: {exc}", file=sys.stderr)  # e.g. refusing plaintext http to a remote host
        return 2

    # When the engine demands step-up re-verification on a sensitive action (ASVS 7.5.3), prompt the
    # operator and retry — instead of surfacing a raw 403 (WP-L3-16, console side).
    client.set_step_up_handler(make_step_up_handler(client))
    # And prompt for a second factor when a sensitive op needs one (403 + X-MFA-Required, WP-14).
    client.set_mfa_handler(make_mfa_handler(client))

    if not _authenticate(client):
        client.close()
        return 0

    # A second, read-only client dedicated to background (off-thread) reads — the health poll, the
    # Engine Status refresh, and the per-page auto-refresh. Keeping those off the primary client
    # means the handler-bearing, token-mutating primary client is only ever used on the Qt main
    # thread (sign-in / step-up / MFA / user actions), so no single client is shared across threads.
    poll_client = client.for_polling()

    # Multi-shard registry (QSettings-backed). Seed a single default shard from --url when nothing is
    # configured, so a legacy single-engine launch is unchanged: exactly one shard, already active,
    # bound to the client we just authenticated.
    settings = QSettings()
    registry = ShardRegistry(settings)
    active = registry.ensure_default(client.base_url)
    # The launch-time clients ARE the active shard's clients; the window seeds its cache with them so
    # a re-select of the active shard never rebuilds. Selecting a *different* shard calls the factory.
    factory = _make_shard_factory(registry, args)

    # Remembered interval wins; fall back to --poll on first run. QSettings returns the value
    # as a str (registry) or float (in-memory), so normalise via str() before parsing.
    poll_seconds = float(str(settings.value(_SETTINGS_KEY, args.poll)))
    window = AppWindow(
        client,
        poll_client=poll_client,
        poll_seconds=poll_seconds,
        service_name=args.service_name,
        registry=registry,
        client_factory=factory,
    )
    _ = active  # ensured above; the window reads the active shard from the registry
    window.interval_changed.connect(lambda seconds: settings.setValue(_SETTINGS_KEY, seconds))
    window.logout_requested.connect(lambda: _sign_out(client, app))
    window.change_password_requested.connect(lambda: _password_changed(client, app))
    window.session_expired.connect(lambda: _session_expired(client, app))

    # Confirm the engine is reachable before showing a blank window.
    try:
        client.health()
    except ApiError as exc:
        window._show_error(f"Cannot reach engine: {exc}")  # noqa: SLF001 (entrypoint glue)

    window.refresh_all()
    _open_window(window, app)

    exit_code = app.exec()
    client.close()
    poll_client.close()
    return int(exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
