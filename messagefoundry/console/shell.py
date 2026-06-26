# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""App shell: a persistent left nav over stacked pages, with the auto-refresh timer driving
whichever page is active. Pages: Connections, Alerts, Dead Letters, Log Search, Engine Status.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, cast

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QCloseEvent, QIcon, QKeySequence, QShortcut
from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMenu,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.console import service_control
from messagefoundry.console._async import AsyncRunner
from messagefoundry.console.alerts_page import AlertsPage
from messagefoundry.console.change_password import ChangePasswordDialog
from messagefoundry.console.mfa import manage_mfa
from messagefoundry.console.sessions import SessionsDialog
from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.console.connections import ConnectionsPage
from messagefoundry.console.search import LogSearchPage
from messagefoundry.console.status import EngineStatusPage
from messagefoundry.console.dead_letters_page import DeadLettersPage
from messagefoundry.console.event_log_page import EventLogPage
from messagefoundry.console.users_page import UsersPage
from messagefoundry.console.widgets import ERROR_COLOR, RefreshSettingsDialog

_NAV = ["Connections", "Alerts", "Dead Letters", "Event Log", "Log Search", "Engine Status"]
_HEALTH_INTERVAL_MS = 5000  # heart polls health on its own timer (independent of auto-refresh)
_LOW_DISK_BYTES = 1024**3  # < 1 GiB free on the DB drive => "running out of space"

# Bundled line icons for the left nav, keyed by nav label (Users is permission-gated). A missing
# file simply yields a null icon — the nav still works text-only.
_ICONS_DIR = Path(__file__).resolve().parent / "icons"
_NAV_ICONS = {
    "Connections": "connections.svg",
    "Alerts": "alerts.svg",
    "Dead Letters": "dead-letters.svg",
    "Log Search": "log-search.svg",
    "Engine Status": "engine-status.svg",
    "Users": "users.svg",
}

_LOGO_LOCKUP = _ICONS_DIR / "logo-lockup.svg"
_WORDMARK_HEIGHT = 30  # header lockup height in logical px (width follows the SVG aspect ratio)


def _make_wordmark() -> QWidget:
    """The brand lockup shown at the top-left of the header.

    Renders the bundled SVG lockup at a fixed header height — vector, so it stays crisp at any
    DPI/zoom and keeps its aspect ratio. Falls back to a styled text label if the asset is absent
    (e.g. a stripped install), so the header is never empty."""
    if _LOGO_LOCKUP.exists():
        logo = QSvgWidget(str(_LOGO_LOCKUP))
        logo.setObjectName("wordmark")
        size = logo.renderer().defaultSize()
        width = round(_WORDMARK_HEIGHT * size.width() / max(1, size.height()))
        logo.setFixedSize(width, _WORDMARK_HEIGHT)
        logo.setToolTip("MessageFoundry")
        return logo
    label = QLabel("MessageFoundry")
    label.setObjectName("wordmark")  # styled bold + accent by the theme
    return label


class HeartIndicator(QLabel):
    """A heart glyph that conveys overall health: green steady (healthy), orange pulsing
    100%↔50% (low space), red pulsing 100%↔75% (engine/DB stopped)."""

    _COLORS = {"green": "#2e7d32", "orange": "#ef6c00", "red": ERROR_COLOR}
    _PULSE = {"orange": (0.5, 2000), "red": (0.75, 1400)}  # (low opacity, cycle ms)

    def __init__(self) -> None:
        super().__init__("♥")  # ♥
        self._state = ""
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._anim = QPropertyAnimation(self._effect, b"opacity", self)
        self._anim.setLoopCount(-1)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutSine)
        self.set_state("green")

    def set_state(self, state: str) -> None:
        if state == self._state:
            return
        self._state = state
        self.setStyleSheet(f"color: {self._COLORS.get(state, '#2e7d32')}; font-size: 44px;")
        self._anim.stop()
        if state not in self._PULSE:  # green / unknown: steady, fully opaque
            self._effect.setOpacity(1.0)
            return
        low, duration = self._PULSE[state]
        self._anim.setDuration(duration)
        self._anim.setKeyValueAt(0.0, 1.0)
        self._anim.setKeyValueAt(0.5, low)
        self._anim.setKeyValueAt(1.0, 1.0)
        self._anim.start()


class _Refreshable(Protocol):
    def refresh(self) -> None: ...  # silent (auto-refresh timer)
    def reload(self) -> None: ...  # user-initiated (nav/open): may audit / autosize


class PlaceholderPage(QWidget):
    """A nav destination that isn't built yet."""

    def __init__(self, title: str) -> None:
        super().__init__()
        label = QLabel(f"{title} — coming soon")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout = QVBoxLayout(self)
        layout.addWidget(label)

    def refresh(self) -> None:  # uniform page interface; nothing to refresh
        return

    def reload(self) -> None:
        return


class AppWindow(QWidget):
    """Top-level window: left nav + stacked pages + an auto-refresh control.

    The timer refreshes whichever page is active. ``interval_changed`` fires (seconds) when
    the user picks a new interval so the entrypoint can persist it."""

    interval_changed = Signal(float)
    logout_requested = Signal()
    # Emitted only after a successful in-app password change; the entrypoint re-prompts sign-in
    # because the server revokes the session on change.
    change_password_requested = Signal()
    # Emitted when the health poll sees a 401 (the session expired/was revoked mid-session) so the
    # entrypoint can re-prompt sign-in instead of leaving the user stuck (review M-26).
    session_expired = Signal()

    def __init__(
        self,
        client: EngineClient,
        *,
        poll_client: EngineClient | None = None,
        poll_seconds: float = 2.0,
        service_name: str = "MessageFoundry",
    ) -> None:
        super().__init__()
        self.setWindowTitle("MessageFoundry Console")
        self._client = client  # user actions + modal auth flows — main thread only
        # All BACKGROUND (off-thread) reads — the nav health poll, Engine Status, and the per-page
        # auto-refresh — go through this read-only client, so the handler-bearing primary client is
        # never touched from a worker thread (the cross-thread-shared-client hazard). Defaults to the
        # primary client when not supplied (tests / embedding), which keeps single-client behaviour.
        self._poll_client = poll_client or client
        self._service_name = service_name
        self._interval = max(0.0, poll_seconds)

        self.connections = ConnectionsPage(client, poll_client=self._poll_client)
        self.alerts = AlertsPage(client, poll_client=self._poll_client)
        self.dead_letters = DeadLettersPage(client, poll_client=self._poll_client)
        self.event_log = EventLogPage(client, poll_client=self._poll_client)
        self.log_search = LogSearchPage(client, poll_client=self._poll_client)
        self.engine_status = EngineStatusPage(self._poll_client, service_name=service_name)
        nav_items = list(_NAV)
        self._pages: list[QWidget] = [
            self.connections,
            self.alerts,
            self.dead_letters,
            self.event_log,
            self.log_search,
            self.engine_status,
        ]
        if client.can("users:manage"):  # user administration is permission-gated
            self.users = UsersPage(client, poll_client=self._poll_client)
            self.users.error.connect(self._show_error)
            nav_items.append("Users")
            self._pages.append(self.users)
        self._stack = QStackedWidget()
        for page in self._pages:
            self._stack.addWidget(page)

        self._nav = QListWidget()
        self._nav.setObjectName("nav")  # styled by the theme (active-item accent bar, hover)
        self._nav.addItems(nav_items)
        self._nav.setFixedWidth(190)
        self._nav.setIconSize(QSize(18, 18))
        for i, label in enumerate(nav_items):
            icon_file = _NAV_ICONS.get(label)
            if icon_file:
                self._nav.item(i).setIcon(QIcon(str(_ICONS_DIR / icon_file)))
        self._nav.currentRowChanged.connect(self._on_nav)

        self.connections.open_logs.connect(self._open_logs)
        self.connections.error.connect(self._show_error)
        self.alerts.error.connect(self._show_error)
        self.dead_letters.error.connect(self._show_error)
        self.event_log.error.connect(self._show_error)
        self.log_search.error.connect(self._show_error)
        self.engine_status.error.connect(self._show_error)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

        self._refresh_link = QLabel()
        self._refresh_link.setTextFormat(Qt.TextFormat.RichText)
        self._refresh_link.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse)
        self._refresh_link.linkActivated.connect(self._edit_interval)

        self._user_label: QLabel | None = None  # header username label (None if signed out)
        self._user_menu: QMenu | None = None  # account overflow menu (Change password / Sign out)
        topbar = QHBoxLayout()
        topbar.setContentsMargins(12, 8, 12, 8)
        topbar.addWidget(_make_wordmark())
        topbar.addStretch(1)
        signed_in = client.current_user
        if signed_in is not None:
            roles = ", ".join(signed_in.roles) or "no roles"
            user_label = QLabel(f"{signed_in.username} ({roles})")
            self._user_label = user_label
            topbar.addWidget(user_label)

            # Account actions live in a compact "⋯" overflow menu to keep the header uncluttered.
            menu = QMenu(self)
            # Local accounts can rotate their password in-app; AD passwords are managed in Active
            # Directory (the server rejects /me/password for them), so omit it for AD users.
            if signed_in.auth_provider != "ad":
                menu.addAction("Change password…", lambda *_: self._change_password())
                # Native TOTP MFA is for local accounts; AD users get MFA from the directory.
                menu.addAction("Two-factor authentication…", lambda *_: self._manage_mfa())
            # All users (incl. AD) have server-side sessions they can inventory and revoke.
            menu.addAction("Active sessions…", lambda *_: self._active_sessions())
            menu.addAction("Sign out", lambda *_: self.logout_requested.emit())
            self._user_menu = menu

            menu_btn = QToolButton()
            menu_btn.setText("⋯")
            menu_btn.setToolTip("Account")
            menu_btn.setAutoRaise(True)
            menu_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
            menu_btn.setStyleSheet("QToolButton::menu-indicator { image: none; }")  # just the dots
            menu_btn.setMenu(menu)
            topbar.addWidget(menu_btn)
            # Plain-text separator: a bare QLabel has no leading HTML tag, so Qt treats it as plain
            # text and would render an "&nbsp;" entity literally — so use real spaces, not entities.
            topbar.addWidget(QLabel(" | "))
        topbar.addWidget(self._refresh_link)

        # The top bar lives in a styled #header container (background + bottom border) that spans the
        # window width; WA_StyledBackground lets the QSS background paint on a plain QWidget.
        header = QWidget()
        header.setObjectName("header")
        header.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        header.setLayout(topbar)

        self._heart = HeartIndicator()
        heart_row = QHBoxLayout()
        heart_row.setContentsMargins(14, 8, 14, 8)
        heart_row.addWidget(self._heart)
        heart_row.addWidget(QLabel("Engine"))
        heart_row.addStretch(1)
        # The heart + label sit in a styled #footer strip under the nav (top border, surface fill).
        footer = QWidget()
        footer.setObjectName("footer")
        footer.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        footer.setLayout(heart_row)

        left = QVBoxLayout()
        left.setContentsMargins(0, 0, 0, 0)
        left.setSpacing(0)
        left.addWidget(self._nav, stretch=1)
        left.addWidget(footer)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addLayout(left)
        body.addWidget(self._stack, stretch=1)

        self._status = QLabel("")
        self._status.setObjectName("statusline")  # themed (danger-coloured error text)
        self._health_error = ""  # the reachability error the poll currently owns (low-14)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(header)
        layout.addLayout(body)
        layout.addWidget(self._status)

        self._nav.setCurrentRow(0)
        self._apply_interval()

        # Zoom the whole UI with Ctrl +/- (and Ctrl+= for keyboards needing shift), Ctrl+0 reset.
        self._base_point_size = max(1.0, self._app().font().pointSizeF())
        for seq, step in (("Ctrl++", 1), ("Ctrl+=", 1), ("Ctrl+-", -1), ("Ctrl+0", 0)):
            shortcut = QShortcut(QKeySequence(seq), self)
            shortcut.activated.connect(lambda s=step: self._zoom(s))

        # The nav heart polls health on its own timer so it updates even when auto-refresh is off.
        # The poll reads the engine off the main thread (a /status read can stall for seconds during
        # a failover) and applies the heart on the main thread.
        self._health_runner = AsyncRunner(self)
        self._health_loading = False  # in-flight guard — one poll at a time
        self._health_timer = QTimer(self)
        self._health_timer.timeout.connect(self._poll_health)
        self._health_timer.start(_HEALTH_INTERVAL_MS)
        self._poll_health()

    def refresh_all(self) -> None:
        self._refresh_current()

    def closeEvent(self, event: QCloseEvent) -> None:
        # Stop the timers before teardown so a queued tick/health-poll can't touch widgets while
        # the window is being destroyed (M3). Then stop the off-thread runners so a late in-flight
        # result (engine read) is dropped rather than delivered to a torn-down widget.
        self._timer.stop()
        self._health_timer.stop()
        self._health_runner.stop()
        # Stop every page that runs a background runner (Connections, Alerts, Dead Letters, Log
        # Search, Engine Status, Users); a page without a stop() (e.g. a PlaceholderPage) is skipped.
        for page in self._pages:
            stop = getattr(page, "stop", None)
            if callable(stop):
                stop()
        super().closeEvent(event)

    def _app(self) -> QApplication:
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        return app

    def _zoom(self, step: int) -> None:
        """Grow/shrink the application font (step ±1), or reset to the launch size (step 0)."""
        app = self._app()
        font = app.font()
        if step == 0:
            size = self._base_point_size
        else:
            current = font.pointSizeF() if font.pointSizeF() > 0 else self._base_point_size
            size = max(6.0, min(40.0, current + step))
        font.setPointSizeF(size)
        app.setFont(font)

    def set_interval(self, seconds: float) -> None:
        """Change the auto-refresh interval (seconds; 0 = off) and notify listeners."""
        self._interval = max(0.0, seconds)
        self._apply_interval()
        self.interval_changed.emit(self._interval)

    # --- internals -----------------------------------------------------------

    def _refresh_current(self) -> None:
        cast(_Refreshable, self._pages[self._stack.currentIndex()]).refresh()

    def _on_nav(self, row: int) -> None:
        if 0 <= row < len(self._pages):
            self._stack.setCurrentIndex(row)
            # Nav is user-initiated -> reload (audits PHI / autosizes); the timer uses refresh().
            cast(_Refreshable, self._pages[row]).reload()

    def _open_logs(self, channel_id: str) -> None:
        # Switch to Log Search without firing _on_nav; set_channel does the single audited load.
        idx = _NAV.index("Log Search")
        self._nav.blockSignals(True)
        self._nav.setCurrentRow(idx)
        self._nav.blockSignals(False)
        self._stack.setCurrentIndex(idx)
        self.log_search.set_channel(channel_id)

    def _tick(self) -> None:
        self._refresh_current()

    def _poll_health(self) -> None:
        """Kick off a health poll off the main thread (the apply runs on the main thread)."""
        if self._health_loading:
            return  # a poll is already in flight — don't pile up while the engine is slow/down
        self._health_loading = True
        self._health_runner.submit(self._fetch_health, on_done=self._apply_health)

    def _fetch_health(self) -> tuple[str, float | None, ApiError | None]:
        """Runs on a worker thread — only blocking I/O. Returns (service_state, free_disk, error)."""
        svc = service_control.service_state(self._service_name)
        try:
            status = self._poll_client.status()  # read-only poll client (never the main-thread one)
        except ApiError as exc:
            return svc, None, exc
        return svc, float(status.db.disk_free_bytes), None

    def _apply_health(self, data: tuple[str, float | None, ApiError | None]) -> None:
        """Drive the nav heart and own the engine-reachability status line (main thread).

        Service-aware: if the Windows service is installed it is the source of truth — a stopped
        service is red even if a terminal happens to answer the API. With no service installed
        (dev), fall back to API reachability + disk. Reachability also governs the status line:
        when the engine answers we clear any stale 'could not reach engine' error; while it's
        down we show it."""
        self._health_loading = False
        svc, free_disk, exc = data
        reachable = False
        low_disk = False
        if exc is not None:
            if exc.status == 401:
                # Session expired/revoked mid-session — distinct from "engine down". Tell the user and
                # let the entrypoint re-prompt sign-in, not a misleading "Engine unreachable" (M-26).
                self._heart.set_state("red")
                self._heart.setToolTip("Session expired — sign in again")
                self.session_expired.emit()
                return
            self._set_health_error(str(exc))
        else:
            reachable = True
            low_disk = free_disk is not None and free_disk < _LOW_DISK_BYTES
        if reachable:
            self._clear_health_error()  # engine answered -> clear our reachability error only

        if svc == "stopped":
            self._heart.set_state("red")
            self._heart.setToolTip(f"Service '{self._service_name}' is installed but stopped")
        elif not reachable:
            self._heart.set_state("red")
            self._heart.setToolTip("Engine unreachable")
        elif low_disk:
            self._heart.set_state("orange")
            self._heart.setToolTip("Low disk space on the database drive")
        else:
            self._heart.set_state("green")
            self._heart.setToolTip("Engine and database healthy")

    def _apply_interval(self) -> None:
        if self._interval > 0:
            self._timer.setInterval(int(self._interval * 1000))
            self._timer.start()
            shown = f"<b>{self._interval:g}s</b>"
        else:
            self._timer.stop()
            shown = "<b>off</b>"
        self._refresh_link.setText(f'Auto-refresh: {shown} &nbsp; <a href="#change">change</a>')

    def _edit_interval(self, _href: str = "") -> None:
        dialog = RefreshSettingsDialog(self._interval, self)
        if dialog.exec():
            self.set_interval(dialog.selected_seconds())

    def _change_password(self) -> None:
        """Open the change-password dialog; on success route back to sign-in (session is revoked)."""
        dialog = ChangePasswordDialog(self._client, parent=self)
        if dialog.exec():
            self.change_password_requested.emit()

    def _manage_mfa(self) -> None:
        """Open the two-factor flow: enroll a TOTP authenticator if off, or turn it off if on."""
        manage_mfa(self._client, parent=self)

    def _active_sessions(self) -> None:
        """Open the self-service active-sessions dialog (it never revokes the current session)."""
        SessionsDialog(self._client, parent=self).exec()

    def _show_error(self, message: str) -> None:
        self._status.setText(message)

    def _set_health_error(self, message: str) -> None:
        self._health_error = message
        self._show_error(message)

    def _clear_health_error(self) -> None:
        # Only clear the status line if it still shows OUR reachability error — a page slot may have
        # set its own error since, and the 5s poll must not wipe it (review low-14).
        if self._health_error and self._status.text() == self._health_error:
            self._show_error("")
        self._health_error = ""
