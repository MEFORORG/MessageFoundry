# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""App shell: a persistent left nav over stacked pages, with the auto-refresh timer driving
whichever page is active. Pages: Connections, Alerts, Dead Letters, Log Search, Engine Status.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QCloseEvent, QIcon, QKeySequence, QShortcut
from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMenu,
    QPushButton,
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
from messagefoundry.console.shards import ShardRegistry
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


class _UpdateBanner(QWidget):
    """A thin, non-blocking, dismissible strip announcing that a newer MessageFoundry version is
    available (#30, ADR 0026). It is purely a view over the engine's no-network ``/status`` signal —
    the console NEVER calls PyPI. ``dismissed`` fires with ``(current, pinned)`` when the operator
    closes it so the shell can suppress re-showing the same update."""

    dismissed = Signal(str, str)  # (current_version, pinned_version)

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("updateBanner")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        # A muted amber strip (brand "Foundry" amber lives in the wordmark only; this is an advisory
        # info tone, not the accent), readable on the light theme.
        self.setStyleSheet(
            "#updateBanner { background: #fff7e6; border-bottom: 1px solid #f0c674; }"
        )
        self._current = ""
        self._pinned = ""
        self._label = QLabel("")
        dismiss = QPushButton("Dismiss")
        dismiss.setFlat(True)
        dismiss.setCursor(Qt.CursorShape.PointingHandCursor)
        dismiss.clicked.connect(lambda: self.dismissed.emit(self._current, self._pinned))
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 6, 12, 6)
        row.addWidget(self._label, stretch=1)
        row.addWidget(dismiss)
        self.setVisible(False)

    def set_versions(self, current: str, pinned: str) -> None:
        self._current = current
        self._pinned = pinned
        self._label.setText(
            f"A newer MessageFoundry version is available: running {current}, {pinned} is installed/"
            f"pinned. Update the engine to pick it up."
        )


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

    # Emitted when the operator picks a different shard in the selector, carrying the new shard id.
    # The entrypoint uses it to (re)authenticate the per-shard client before pages talk to it.
    shard_changed = Signal(str)

    def __init__(
        self,
        client: EngineClient,
        *,
        poll_client: EngineClient | None = None,
        poll_seconds: float = 2.0,
        service_name: str = "MessageFoundry",
        registry: ShardRegistry | None = None,
        client_factory: Callable[[str], tuple[EngineClient, EngineClient]] | None = None,
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

        # Multi-shard wiring (opt-in). `registry` lists the configured engine endpoints; the active
        # shard's clients are the ones above. `client_factory(shard_id)` lazily builds (and caches)
        # an (action, poll) client pair for a shard the first time it is selected — the entrypoint
        # supplies it so per-shard authentication/keyring lives there, not in the GUI. With neither,
        # the window is single-shard (exactly the legacy behaviour) and the selector is hidden.
        self._registry = registry
        self._client_factory = client_factory
        #: shard_id -> (action_client, poll_client); seeded with the active shard so a re-select of it
        #: is free and the launch-time authenticated clients are reused, never rebuilt.
        self._shard_clients: dict[str, tuple[EngineClient, EngineClient]] = {}
        active_id = registry.active_id if registry is not None else None
        if active_id is not None:
            self._shard_clients[active_id] = (self._client, self._poll_client)
        self._active_shard_id = active_id
        #: The launch-time client pair is owned/closed by the entrypoint; every OTHER pair the window
        #: lazily built is owned by the window and closed on teardown. Track the launch ids to skip.
        self._entrypoint_clients = {id(self._client), id(self._poll_client)}

        self._pages: list[QWidget] = []
        self._stack = QStackedWidget()
        self._build_pages(client, self._poll_client)

        self._nav = QListWidget()
        self._nav.setObjectName("nav")  # styled by the theme (active-item accent bar, hover)
        self._nav.addItems(self._nav_items)
        self._nav.setFixedWidth(190)
        self._nav.setIconSize(QSize(18, 18))
        for i, label in enumerate(self._nav_items):
            icon_file = _NAV_ICONS.get(label)
            if icon_file:
                self._nav.item(i).setIcon(QIcon(str(_ICONS_DIR / icon_file)))
        self._nav.currentRowChanged.connect(self._on_nav)

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

        # Shard selector: a combobox listing the configured engine endpoints, switching the active
        # one. Shown only when more than one shard is configured (a single-shard / legacy launch keeps
        # the footer exactly as before). It carries the shard id as item data so reordering can't
        # mis-target a switch.
        self._shard_combo = QComboBox()
        self._shard_combo.setObjectName("shardSelector")
        self._shard_combo.setToolTip("Engine endpoint (shard)")
        self._populate_shard_combo()
        self._shard_combo.activated.connect(self._on_shard_selected)

        # The heart + label sit in a styled #footer strip under the nav (top border, surface fill).
        footer_col = QVBoxLayout()
        footer_col.setContentsMargins(0, 0, 0, 0)
        footer_col.setSpacing(0)
        if self._shard_combo.count() > 1:
            shard_row = QHBoxLayout()
            shard_row.setContentsMargins(14, 8, 14, 0)
            shard_row.addWidget(self._shard_combo, stretch=1)
            footer_col.addLayout(shard_row)
        footer_col.addLayout(heart_row)
        footer = QWidget()
        footer.setObjectName("footer")
        footer.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        footer.setLayout(footer_col)

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

        # Non-blocking, dismissible "update available" banner (#30, ADR 0026). Hidden until the engine's
        # no-network /status diff reports a newer pinned/installed version; the console never calls PyPI.
        # Dismissal is per-(current,pinned) so a NEW update re-shows after the operator dismissed an
        # older one.
        self._update_banner = _UpdateBanner()
        self._update_banner.dismissed.connect(self._on_update_banner_dismissed)
        self._dismissed_update: tuple[str, str] | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(header)
        layout.addWidget(self._update_banner)
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

    def _build_pages(self, client: EngineClient, poll_client: EngineClient) -> None:
        """Construct the page set against ``client``/``poll_client`` and register them in the stack.

        Called once at construction and again on each shard switch (after the old pages are torn
        down). It owns the page list, the nav-item labels, and the per-page error/open-logs wiring so
        a shard switch rebuilds a consistent set without duplicating that wiring at the call site."""
        self.connections = ConnectionsPage(client, poll_client=poll_client)
        self.alerts = AlertsPage(client, poll_client=poll_client)
        self.dead_letters = DeadLettersPage(client, poll_client=poll_client)
        self.event_log = EventLogPage(client, poll_client=poll_client)
        self.log_search = LogSearchPage(client, poll_client=poll_client)
        self.engine_status = EngineStatusPage(poll_client, service_name=self._service_name)
        self._nav_items = list(_NAV)
        self._pages = [
            self.connections,
            self.alerts,
            self.dead_letters,
            self.event_log,
            self.log_search,
            self.engine_status,
        ]
        if client.can("users:manage"):  # user administration is permission-gated
            self.users = UsersPage(client, poll_client=poll_client)
            self.users.error.connect(self._show_error)
            self._nav_items.append("Users")
            self._pages.append(self.users)
        for page in self._pages:
            self._stack.addWidget(page)

        self.connections.open_logs.connect(self._open_logs)
        self.connections.error.connect(self._show_error)
        self.alerts.error.connect(self._show_error)
        self.dead_letters.error.connect(self._show_error)
        self.event_log.error.connect(self._show_error)
        self.log_search.error.connect(self._show_error)
        self.engine_status.error.connect(self._show_error)

    def _populate_shard_combo(self) -> None:
        """Fill the selector from the registry and select the active shard. Hidden for 0/1 shard."""
        combo = self._shard_combo
        combo.blockSignals(True)  # programmatic fill must not fire activated/currentIndexChanged
        combo.clear()
        shards = self._registry.list() if self._registry is not None else []
        for shard in shards:
            combo.addItem(shard.name, shard.id)
        if self._active_shard_id is not None:
            idx = combo.findData(self._active_shard_id)
            if idx >= 0:
                combo.setCurrentIndex(idx)
        combo.blockSignals(False)
        # Only meaningful with a choice to make; a single-shard / legacy launch hides it entirely.
        combo.setVisible(len(shards) > 1)

    def _on_shard_selected(self, index: int) -> None:
        """Selector activated by the user: switch to the chosen shard (no-op if it's already active)."""
        shard_id = self._shard_combo.itemData(index)
        if isinstance(shard_id, str) and shard_id != self._active_shard_id:
            self.set_active_shard(shard_id)

    def set_active_shard(self, shard_id: str) -> bool:
        """Re-point every page at ``shard_id``'s engine client and refresh the current page.

        Lazily builds (and caches) the shard's (action, poll) client pair via ``client_factory`` the
        first time it is selected, rebuilds the page set against it, persists the active shard in the
        registry, and emits :attr:`shard_changed`. Returns ``False`` (no-op) when multi-shard wiring
        isn't configured, the id is unknown, the factory is missing, or it is already active."""
        if self._registry is None or self._client_factory is None:
            return False
        if shard_id == self._active_shard_id:
            return True  # already there
        if self._registry.get(shard_id) is None:
            return False
        clients = self._shard_clients.get(shard_id)
        if clients is None:
            try:
                clients = self._client_factory(shard_id)
            except Exception as exc:  # noqa: BLE001 — a factory failure must not crash the window
                self._show_error(f"could not connect to shard: {exc}")
                self._populate_shard_combo()  # snap the selector back to the still-active shard
                return False
            self._shard_clients[shard_id] = clients
        action_client, poll_client = clients

        # Tear down the current pages (stop their background runners) and clear the stack before
        # rebuilding against the new clients, so no torn-down page is left receiving queued results.
        current_row = self._nav.currentRow()
        for page in self._pages:
            stop = getattr(page, "stop", None)
            if callable(stop):
                stop()
            self._stack.removeWidget(page)
            page.deleteLater()

        self._client = action_client
        self._poll_client = poll_client
        self._active_shard_id = shard_id
        self._registry.set_active(shard_id)
        self._build_pages(action_client, poll_client)

        # Re-point the nav at the same row (the page set is identical unless the users:manage gate
        # differs across shards; clamp to a valid row in that case).
        row = min(max(0, current_row), len(self._pages) - 1)
        self._nav.blockSignals(True)
        self._nav.setCurrentRow(row)
        self._nav.blockSignals(False)
        self._stack.setCurrentIndex(row)
        self._populate_shard_combo()  # reflect the new active selection
        self.shard_changed.emit(shard_id)
        cast(_Refreshable, self._pages[row]).reload()  # user-initiated switch -> reload (audited)
        self._poll_health()  # update the heart for the new engine right away
        return True

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
        # Close every per-shard client the window built itself (the launch pair belongs to the
        # entrypoint, which closes it after the event loop exits — skip those).
        for action_client, poll_client in self._shard_clients.values():
            for c in (action_client, poll_client):
                close = getattr(c, "close", None)
                if id(c) not in self._entrypoint_clients and callable(close):
                    close()
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

    def _fetch_health(
        self,
    ) -> tuple[str, float | None, ApiError | None, tuple[str, str] | None]:
        """Runs on a worker thread — only blocking I/O. Returns
        (service_state, free_disk, error, update). ``update`` is ``(current, pinned)`` when the engine
        reports a newer version is available (#30, ADR 0026), else ``None``. The console NEVER calls
        PyPI — this is purely the engine's no-network /status signal, rendered as a banner."""
        svc = service_control.service_state(self._service_name)
        try:
            status = self._poll_client.status()  # read-only poll client (never the main-thread one)
        except ApiError as exc:
            return svc, None, exc, None
        update = status.update
        avail = (
            (update.current_version, update.pinned_version or "?")
            if update is not None and update.update_available
            else None
        )
        return svc, float(status.db.disk_free_bytes), None, avail

    def _apply_health(
        self, data: tuple[str, float | None, ApiError | None, tuple[str, str] | None]
    ) -> None:
        """Drive the nav heart and own the engine-reachability status line (main thread).

        Service-aware: if the Windows service is installed it is the source of truth — a stopped
        service is red even if a terminal happens to answer the API. With no service installed
        (dev), fall back to API reachability + disk. Reachability also governs the status line:
        when the engine answers we clear any stale 'could not reach engine' error; while it's
        down we show it."""
        self._health_loading = False
        svc, free_disk, exc, update = data
        # Surface the engine's no-network update signal (#30) as a dismissible banner. The console
        # never calls PyPI; this only reflects /status.
        self._apply_update_banner(update)
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

    def _apply_update_banner(self, update: tuple[str, str] | None) -> None:
        """Show/hide the dismissible update banner from the engine's /status signal (#30).

        ``update`` is ``(current, pinned)`` when a newer version is available, else ``None``. The
        banner stays hidden once the operator dismisses a given (current, pinned) pair, but a DIFFERENT
        pair (a genuinely newer pinned version) re-shows it."""
        if update is None or update == self._dismissed_update:
            self._update_banner.setVisible(False)
            return
        current, pinned = update
        self._update_banner.set_versions(current, pinned)
        self._update_banner.setVisible(True)

    def _on_update_banner_dismissed(self, current: str, pinned: str) -> None:
        """Remember this (current, pinned) as dismissed so the banner doesn't re-show for the same
        update; a later, different pinned version re-shows it."""
        self._dismissed_update = (current, pinned)
        self._update_banner.setVisible(False)

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
