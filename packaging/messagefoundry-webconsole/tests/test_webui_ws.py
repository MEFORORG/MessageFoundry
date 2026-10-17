# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""/ui WebSocket channel (/ws/stats), the parse-tree endpoint, WS payload enrichment, and the
[api].public_origin same-origin checks (ADR 0065 / BACKLOG #75)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from _webui_support import (
    _GIB,
    PW,
    XSS_RAW,
    _add,
    _client,
    _cookie_login,
    _seed,
    _service,
    _sysinfo,
)
from starlette.datastructures import Headers

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine

# --- M-ws: /ws/stats browser channel — cookie-on-handshake auth + CSWSH gate --


class _FakeWS:
    """Minimal duck-typed WebSocket for unit-testing authorize_ui_ws (headers/cookies/app.state/url)."""

    def __init__(
        self,
        origin: str | None,
        host: str | None,
        cookie: str | None,
        app: object,
        peer: tuple[str, int] = ("127.0.0.1", 123),
    ) -> None:
        self.headers = Headers(  # has getlist (BACKLOG #2454)
            {k: v for k, v in (("origin", origin), ("host", host)) if v is not None}
        )
        self.app = app
        # ``scope["client"]`` is what ``client_ip`` reads for the denial rows (ADR 0150, BACKLOG
        # #1644, #2289). A real address by default, never None, so a client assertion cannot pass
        # as None == None.
        self.scope = {"client": peer}
        # A real Starlette WebSocket carries ``.url``; the #192 cookie-name resolver
        # (session_cookie_name → effective_https) reads ``.url.scheme`` to key the cookie name off the
        # effective scheme. Model the handshake scheme from the page origin — a cleartext http page
        # opens ws://, an https page wss:// — and store the session token under the SAME name a real
        # browser on that origin would hold: plain ``mf_session`` over cleartext (byte-identity), the
        # ``__Host-mf_session`` prefix over https (#192, ASVS 3.4.3), so the resolver reads it back.
        # ``.url.path`` is read by the denial audit (the row records the path, never the full URL);
        # /ws/stats is the console's only socket.
        scheme = "wss" if (origin or "").startswith("https") else "ws"
        self.url = SimpleNamespace(scheme=scheme, path="/ws/stats")
        cookie_name = "__Host-mf_session" if scheme == "wss" else "mf_session"
        self.cookies = {cookie_name: cookie} if cookie is not None else {}


#: A named, non-loopback handshake peer (TEST-NET-3), so a client assertion compares a value this file
#: chose rather than a default that also matches a loopback login row.
_WS_PEER = ("203.0.113.9", 55123)


async def _token(engine: Engine, service: AuthService, user: str) -> tuple[object, str]:
    from messagefoundry.api import create_app

    app = create_app(engine, auth=service, serve_ui=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        token = (await c.post("/auth/login", json={"username": user, "password": PW})).json()[
            "token"
        ]
    return app, token


async def test_ws_cookie_auth_same_origin_ok(engine: Engine) -> None:
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import authorize_ui_ws

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    app, token = await _token(engine, service, "op")
    ws = _FakeWS(origin="http://t", host="t", cookie=token, app=app)
    identity, tok = await authorize_ui_ws(ws, Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert identity is not None and tok == token


async def test_ws_cookie_auth_rejects_cross_origin(engine: Engine) -> None:
    # CSWSH gate: a cross-origin handshake is rejected even with a valid cookie value.
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import authorize_ui_ws

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    app, token = await _token(engine, service, "op")
    ws = _FakeWS(origin="http://evil.example", host="t", cookie=token, app=app)
    identity, _ = await authorize_ui_ws(ws, Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert identity is None


async def test_ws_cookie_auth_requires_cookie_and_origin(engine: Engine) -> None:
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import authorize_ui_ws

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    app, token = await _token(engine, service, "op")
    # No cookie → rejected (falls back to the native header path in the handler).
    no_cookie = _FakeWS(origin="http://t", host="t", cookie=None, app=app)
    assert (await authorize_ui_ws(no_cookie, Permission.MONITORING_READ))[0] is None  # type: ignore[arg-type]
    # No Origin (a native client) → rejected here so the handler uses the header path.
    no_origin = _FakeWS(origin=None, host="t", cookie=token, app=app)
    assert (await authorize_ui_ws(no_origin, Permission.MONITORING_READ))[0] is None  # type: ignore[arg-type]
    # A bad/expired cookie value → rejected.
    bad = _FakeWS(origin="http://t", host="t", cookie="not-a-real-token", app=app)
    assert (await authorize_ui_ws(bad, Permission.MONITORING_READ))[0] is None  # type: ignore[arg-type]


async def test_ws_cookie_auth_permission_denial_is_audited(engine: Engine) -> None:
    """BACKLOG #1197 (ASVS 16.3.2): a refused console WebSocket authorization writes a denial row.

    This gate is a browser handshake's only credential path, and the engine's header-path fallback
    cannot cover it — that path reads the token from the Authorization header only, and its Origin
    check refuses every browser Origin against the shipped empty allowlist before its permission loop
    runs. Nor does any setting reach it. Without the call inside the loop a deploying site would have
    no record of the failed attempt anywhere, so pin it here.

    The exact-equality assertion on ``detail`` is the second half of the test and is deliberate: the
    row must carry the permission and the path and NOTHING else. Widening it to the full URL would put
    an operator's query string — where a clinician's search terms live — into the hash chain.
    """
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import authorize_ui_ws

    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    app, token = await _token(engine, service, "vw")

    async def _denials() -> list[dict[str, object]]:
        return [
            a for a in await engine.store.list_audit() if a["action"] == "auth.permission_denied"
        ]

    # Negative control: the sign-in above audits, but it audits nothing of this action.
    assert await _denials() == []

    # VIEWER holds monitoring:read but not config:deploy, so the permission loop is what refuses.
    ws = _FakeWS(origin="http://t", host="t", cookie=token, app=app, peer=_WS_PEER)
    identity, tok = await authorize_ui_ws(ws, Permission.CONFIG_DEPLOY)  # type: ignore[arg-type]
    assert identity is None and tok is None  # behaviour unchanged: the caller still falls through

    rows = await _denials()
    assert len(rows) == 1, "the refused handshake left no denial row"
    assert rows[0]["actor"] == "vw"
    # ADR 0150, BACKLOG #1644: the row names the handshake's host. RED when client= is dropped.
    assert rows[0]["client"] == _WS_PEER[0]
    assert json.loads(str(rows[0]["detail"])) == {
        "permission": "config:deploy",
        "path": "/ws/stats",
    }


async def test_ws_cookie_auth_mfa_pending_refusal_is_audited(engine: Engine) -> None:
    """BACKLOG #1197 (ASVS 16.3.2, the BASE failed-attempt limb): the MFA-pending refusal leaves a row.

    This refusal sits ABOVE the permission loop, so the denial call inside that loop cannot reach it,
    and nothing downstream records it either — the caller falls back to the engine's ``authorize_ws``,
    which never sees a browser handshake (header-only token, and its Origin check refuses every browser
    Origin against the shipped empty allowlist). Without this call a stolen password-only cookie could
    probe the socket and leave the chain completely silent, which is the exact scenario
    ``audit_mfa_denied`` was added to the engine's gates for.

    RED when the ``audit_mfa_denied`` call is removed from ``authorize_ui_ws``. Measured at HEAD before
    it existed: the console wrote ZERO rows here while the engine's header path wrote
    ``auth.mfa_denied`` for the same session in the same run.

    The permission asserted is one this OPERATOR does NOT hold, which makes this an ordering guard too:
    only ``auth.mfa_denied`` may appear. A ``auth.permission_denied`` row would mean the MFA gate had
    slipped below the permission loop, and refusing there tells an unverified caller whether it holds
    the permission — a free authorization oracle.
    """
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import authorize_ui_ws

    service = AuthService(engine.store, AuthSettings(require_mfa=True))
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    app, token = await _token(engine, service, "op")

    # Controls: the arm really is MFA-pending, and the identity resolves — so the gate reaches the MFA
    # branch rather than returning at an earlier one. Without these a broken sign-in would produce the
    # same silent shape as a working one, and the assertion below would be measuring nothing.
    assert await service.mfa_satisfied(token) is False
    resolved = await service.identity_for_token(token)
    assert resolved is not None and not resolved.must_change_password

    async def _rows(action: str) -> list[dict[str, object]]:
        return [a for a in await engine.store.list_audit() if a["action"] == action]

    # Negative control: the sign-in above audits, but it audits nothing of this action.
    assert await _rows("auth.mfa_denied") == []

    ws = _FakeWS(origin="http://t", host="t", cookie=token, app=app, peer=_WS_PEER)
    identity, tok = await authorize_ui_ws(ws, Permission.CONFIG_DEPLOY)  # type: ignore[arg-type]
    assert identity is None and tok is None  # behaviour unchanged: the caller still falls through

    rows = await _rows("auth.mfa_denied")
    assert len(rows) == 1, "the MFA-pending handshake left no record"
    assert rows[0]["actor"] == "op"
    # ADR 0150, BACKLOG #1644: the row names the handshake's host. RED when client= is dropped.
    assert rows[0]["client"] == _WS_PEER[0]
    # Exact equality, for the same reason the permission-denial row asserts it: the row carries the
    # PATH and nothing else. Widening it to the full URL would put an operator's query string — where
    # a clinician's search terms live — into the hash chain.
    assert json.loads(str(rows[0]["detail"])) == {"path": "/ws/stats"}
    assert await _rows("auth.permission_denied") == [], (
        "the MFA gate must stay ABOVE the permission loop — a denial row here would mean an "
        "unverified caller was told whether it holds the permission"
    )


async def test_ws_cookie_auth_mfa_satisfied_writes_no_mfa_row(engine: Engine) -> None:
    """The MFA audit fires on the refusal branch only — a session that satisfies MFA stays quiet.

    Pairs with the test above the way the grant guard pairs with the permission denial: without it, a
    change that audited every handshake would still pass that test while multiplying the trail.
    """
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import authorize_ui_ws

    service = await _service(engine)  # require_mfa=False → mfa_satisfied is True for this session
    await _add(service, "op", Role.OPERATOR)
    app, token = await _token(engine, service, "op")
    assert await service.mfa_satisfied(token) is True  # control: this is the SATISFIED arm
    ws = _FakeWS(origin="http://t", host="t", cookie=token, app=app)
    identity, _ = await authorize_ui_ws(ws, Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert identity is not None
    assert "auth.mfa_denied" not in {a["action"] for a in await engine.store.list_audit()}


async def test_ws_cookie_auth_grant_writes_no_denial_row(engine: Engine) -> None:
    """The denial audit fires on the denial branch only — an authorized handshake stays quiet here.

    BACKLOG #1197 keeps grant parity for the console OUT of scope (it is ruling- and measurement-gated
    on audit volume), so this is also the guard against a later change quietly mirroring grants in.
    """
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import authorize_ui_ws

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    app, token = await _token(engine, service, "op")
    ws = _FakeWS(origin="http://t", host="t", cookie=token, app=app)
    identity, _ = await authorize_ui_ws(ws, Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert identity is not None
    actions = {a["action"] for a in await engine.store.list_audit()}
    assert "auth.permission_denied" not in actions
    assert "auth.permission_granted" not in actions


def test_rows_table_marks_adjustable() -> None:
    """Every grid table is marked ``data-mf-table`` so ``app.js`` enhances it with click-to-sort +
    drag-to-resize columns. Losing the marker silently disables the enhancement (no error, just an
    inert table), so lock the seam here. The enhancement is presentation-only — cells, header labels,
    and escaping are unchanged."""
    from messagefoundry_webconsole._html import rows_table

    html = str(rows_table(["Name", "Count"], [["a", "2"]]))
    assert 'class="grid" data-mf-table' in html
    assert "<thead>" in html and "<th>Name</th>" in html and "<td>a</td>" in html


def test_rows_table_info_is_not_adjustable() -> None:
    """A key/value readout table (adjustable=False) is a plain wrapping table (class ``grid info``) with
    NO ``data-mf-table`` marker — so app.js leaves it alone (no fixed-layout/explicit-width grid) and CSS
    wraps long values instead of showing a horizontal scrollbar. Used for the status + connection-detail
    readouts. Cells/headers/escaping are otherwise identical to the grid form."""
    from messagefoundry_webconsole._html import rows_table

    html = str(rows_table(["Field", "Value"], [["Path", "C:/x/y"]], adjustable=False))
    assert 'class="grid info"' in html and "data-mf-table" not in html
    assert "<th>Field</th>" in html and "<td>Path</td>" in html


def test_status_and_detail_tables_are_non_adjustable() -> None:
    """The status page + connection-detail key/value tables render as non-adjustable ``info`` tables (no
    horizontal scrollbar); the connection-detail card is widened. Locks the fix so a future rows_table
    refactor can't silently reintroduce the scroll."""
    from messagefoundry_webconsole.pages.connections import connection_details

    row = _ux_conn_row(name="IB_ORDERS ▸ in", channel_id="IB_ORDERS")
    html = str(connection_details(row, []))
    assert "detail-card" in html  # widened container
    assert 'class="grid info"' in html  # the Connection + Statistics readouts wrap, not scroll
    assert "data-mf-table" not in html  # nothing on this page is an adjustable (scrolling) grid


def test_default_nav_renders_dropdown_groups() -> None:
    """The top nav groups its links into CSS-only dropdowns (a <button> toggle + a <div class=navmenu>
    of links), opening on :hover/:focus-within with no JS (CSP 'self'). Every member link stays in the
    DOM (CSS hides the menu), so text/hrefs remain assertable. The group whose page is active is marked
    active on its toggle button — NOT via an attribute on the wrapper div (locks a past regression)."""
    from messagefoundry_webconsole._html import _default_nav

    html = str(_default_nav("dashboard"))
    # Dropdown scaffolding: one toggle button + one menu per group, labelled by area.
    assert 'class="navtop active">Traffic ▾</button>' in html  # active group (dashboard is in it)
    assert 'class="navtop">Monitoring ▾</button>' in html  # an inactive group
    assert html.count('aria-haspopup="menu"') == 4  # each toggle marks itself a menu opener (a11y)
    assert html.count('class="navmenu"') == 4
    # Member links are present (menu is CSS-hidden, not removed) and none leaked as a top-level <a>.
    assert '<a href="/ui/messages">Messages</a>' in html
    assert '<a href="/ui/config">Configuration</a>' in html
    assert "<div active=" not in html  # active drives a button class, never a wrapper attribute
    # Active highlight follows the current page to a different group.
    assert 'class="navtop active">Monitoring ▾</button>' in str(_default_nav("alerts"))


def test_default_nav_renders_status_icons() -> None:
    """The nav pins two live status glyphs to the right (left of Sign out): the alerts bell then the
    engine-health heart, in that order. Each is a LINK to its detail page (bell → /ui/alerts, heart →
    /ui/status). They render NEUTRAL (gray) with app.js data hooks; app.js polls /ui/nav-status and
    recolors them. Monochrome inline SVG (fill=currentColor) so CSS `color` tints them — not an emoji."""
    from messagefoundry_webconsole._html import _default_nav

    html = str(_default_nav("dashboard"))
    assert "data-mf-nav-status" in html  # the always-on app.js poller hook (present on every page)
    assert "data-mf-nav-alerts" in html and "alerts-unknown" in html
    assert "data-mf-nav-health" in html and "health-unknown" in html
    # Each glyph is an anchor to its detail page (the app.js hook rides the same <a>).
    assert '<a href="/ui/alerts"' in html and "data-mf-nav-alerts" in html  # bell → alerts
    assert '<a href="/ui/status"' in html and "data-mf-nav-health" in html  # heart → status
    assert 'role="status"' not in html  # a link, not a live-region that re-announces every poll
    # alerts left of heart, both left of Sign out
    assert (
        html.index("data-mf-nav-alerts") < html.index("data-mf-nav-health") < html.index("Sign out")
    )
    assert 'fill="currentColor"' in html  # colorable monochrome glyph, not an emoji


def test_derive_health_ok_when_healthy() -> None:
    from messagefoundry_webconsole.routes.status import _derive_health

    assert _derive_health(_sysinfo(50 * _GIB), None, None, None) == ("ok", None)


def test_derive_health_warns_on_low_disk() -> None:
    from messagefoundry_webconsole.routes.status import _derive_health

    health, reason = _derive_health(_sysinfo(3 * _GIB), None, None, None)
    assert health == "warn" and reason is not None and "low disk" in reason


def test_derive_health_down_on_a_pooled_stage_that_is_not_draining() -> None:
    """BACKLOG #1609: a dead pooled claimer stops its whole stage while intake keeps acknowledging
    and every connection reads healthy, so the heart must say DOWN and name the stage -- and it must
    outrank a coexisting warn (low disk here) for the tooltip."""
    from messagefoundry_webconsole.routes.status import _derive_health

    sysinfo = _sysinfo(3 * _GIB)
    sysinfo.engine.stages_degraded = {"ingress": "claimer-0 exited unexpectedly (RuntimeError)"}
    health, reason = _derive_health(sysinfo, None, None, None)
    assert health == "down"
    assert reason == "pipeline stage not draining: ingress"


def test_derive_health_critical_on_very_low_disk() -> None:
    from messagefoundry_webconsole.routes.status import _derive_health

    health, _ = _derive_health(_sysinfo(512 * 1024**2), None, None, None)  # 0.5 GiB free
    assert health == "down"


@pytest.mark.parametrize(
    ("kwargs", "label"),
    [
        ({"disk_free": 0}, "db"),
        ({"disk_free": 0, "journal_mode": "postgres"}, "db"),
        ({"disk_free": 50 * _GIB, "logs_free": 0}, "logs"),
    ],
    ids=["db", "db-server-backend", "logs"],
)
def test_derive_health_still_critical_on_a_measured_zero_drive(
    kwargs: dict[str, object], label: str
) -> None:
    """BACKLOG #1563's guard rail, and the reason the fix is not just "ignore falsy".

    A drive the engine MEASURED at 0 bytes free is the real emergency this rule exists for, and it
    must keep firing after unmeasurable values stop doing so. It holds because the rule tests
    ``free is None`` — an identity check, never ``not free``. If any case here goes green, the fix
    has silenced the alarm rather than narrowing it. The reason names WHICH drive, so the operator
    knows which one to go and clear.

    The ``db-server-backend`` arm is a REGRESSION guard, not a live path, and says so because the
    id alone reads like end-to-end coverage of the server stores. No server store can emit a 0 any
    more — both hardcode ``disk_free_bytes=None`` — so the only defect it can catch is the
    discriminator being widened to skip server backends BEFORE the null check instead of inside it.
    That would silence a measured figure on the strength of which store reported it, and the check
    is cheap enough to keep for that one shape."""
    from messagefoundry_webconsole.routes.status import _derive_health

    health, reason = _derive_health(_sysinfo(**kwargs), None, None, None)  # type: ignore[arg-type]
    assert health == "down"
    assert reason == f"low disk ({label}): 0.0 GiB free"


@pytest.mark.parametrize("journal_mode", ["postgres", "FULL", "SIMPLE", "BULK_LOGGED", "Full"])
def test_derive_health_ignores_an_unmeasurable_db_disk_on_a_server_backend(
    journal_mode: str,
) -> None:
    """BACKLOG #1563: both server stores hardcoded ``disk_free_bytes=0`` to mean "I cannot see this
    disk", and every threshold here read that as a full drive — so a healthy Postgres or SQL Server
    deployment WOULD come up with the engine-health heart pinned critical and a tooltip reading
    "low disk (db): 0.0 GiB free". The value is now ``None``, and on a SERVER backend it is skipped,
    claiming nothing — the engine was never meant to stat that disk.

    Parametrized over both server spellings of ``journal_mode``, including SQL Server's three
    recovery models and a lowercase one: the discriminator case-folds, because SQLite reports its
    journal mode lowercase and SQL Server reports its recovery model uppercase."""
    from messagefoundry_webconsole.routes.status import _derive_health

    assert _derive_health(_sysinfo(None, journal_mode=journal_mode), None, None, None) == (
        "ok",
        None,
    )


@pytest.mark.parametrize(
    "journal_mode", ["wal", "delete", "truncate", "persist", "memory", "off", "", "mysql"]
)
def test_derive_health_warns_on_an_unmeasurable_db_disk_on_a_local_backend(
    journal_mode: str,
) -> None:
    """The other half of the rule, and the regression it was written against.

    On the DEFAULT SQLite backend there is no not-applicable reading: ``_disk_free_bytes`` returns
    ``None`` ONLY when a local ``shutil.disk_usage`` raised, so a null is a probe that FAILED on a
    drive that should have been readable. Skipping it for every backend alike turned a real
    emergency into a silent ``ok`` — SQLite holds its file handle open, so queries keep succeeding
    while the parent directory's ACL or mount goes bad, and nothing else in the rollup would notice.

    The five SQLite journal modes pin the module's claim that the two vocabularies cannot collide:
    none of them may ever fall into ``_SERVER_DB_JOURNAL_MODES``.

    ``"mysql"`` and ``""`` are the unrecognised arms. An unknown ``journal_mode`` counts as a LOCAL
    disk and alarms, because silence is the failure this rule exists to prevent: a backend nobody
    listed should read louder than it deserves, never quieter. ``""`` is the one arm that is a
    judgement rather than a reading — it names no backend, and a SQL Server whose recovery-model
    read came back empty reaches it too. Pinned here so that flipping it is a deliberate act with a
    failing test behind it, not a quiet edit; see ``_SERVER_DB_JOURNAL_MODES`` for the reasoning."""
    from messagefoundry_webconsole.routes.status import _derive_health

    health, reason = _derive_health(_sysinfo(None, journal_mode=journal_mode), None, None, None)
    assert health == "warn"
    assert reason == "db directory missing or unreadable"


@pytest.mark.parametrize("journal_mode", ["wal", "postgres"], ids=["sqlite", "server"])
def test_derive_health_unmeasurable_disk_skips_only_itself(journal_mode: str) -> None:
    """The skip is a ``continue``, not an early exit: an unmeasurable disk must not take the rest of
    the rollup down with it. An engine with a failed inbound still warns and still names the inbound
    — otherwise #1563's fix would have blinded the heart to everything else.

    Both backends are covered, because they reach this line by different routes: the server one
    appends no disk issue at all, the SQLite one appends its own warn and must still lose the
    tooltip to the connection failure. Insertion order IS that tie-break, so this pins it."""
    from messagefoundry_webconsole.routes.status import _derive_health

    health, reason = _derive_health(
        _sysinfo(None, failed_names=["IB_ACME_ADT"], journal_mode=journal_mode), None, None, None
    )
    assert health == "warn"
    assert reason == "inbound IB_ACME_ADT failed to start"


def test_derive_health_warns_on_an_unmeasurable_log_drive() -> None:
    """A configured log directory the engine could not measure is a WARN, not a skip.

    A log directory has no not-applicable case: the operator configured that path, so a null there
    is always a failed probe. Skipping it would have traded #1563's loud wrong answer for a silent
    one, leaving a vanished log directory reading green forever. The DB drive reaches the same
    answer on the default SQLite backend for the same reason; only a server backend's DB null is
    genuinely not-applicable, and ``journal_mode`` is what tells those apart."""
    from messagefoundry_webconsole.routes.status import _derive_health

    health, reason = _derive_health(_sysinfo(50 * _GIB, logs_free="unmeasured"), None, None, None)
    assert health == "warn"
    assert reason == "log directory missing or unreadable"


def test_derive_health_ok_when_no_log_dir_is_configured() -> None:
    """The control for the warn above: stdout-only (``logs is None``) is a deliberate configuration,
    not a failed probe, and must stay silent. If this ever warns, the fix has started treating "the
    operator wanted no log directory" as "the log directory is broken"."""
    from messagefoundry_webconsole.routes.status import _derive_health

    assert _derive_health(_sysinfo(50 * _GIB, logs_free=None), None, None, None) == ("ok", None)


def test_bytes_renders_an_unmeasured_value_as_words_not_a_quantity() -> None:
    """BACKLOG #1563, the on-screen half. The Engine Status page prints "Disk free" straight from
    ``DbInfo``, so a server backend's unmeasurable figure must not fall through to "0 B" — an
    operator reading that sees a disk emergency, when in fact nobody looked. A real zero still
    renders as a quantity, because that one IS a measurement."""
    from messagefoundry_webconsole.pages.monitoring import _bytes

    assert _bytes(None) == "nothing measured"
    assert _bytes(0) == "0 B"
    assert _bytes(10 * 1024**3) == "10.0 GiB"


def test_derive_health_down_when_store_unreachable() -> None:
    from messagefoundry_webconsole.routes.status import _derive_health

    assert _derive_health(None, None, None, None) == ("down", "store unreachable")


def test_derive_health_warns_on_saturated_pool() -> None:
    from messagefoundry_webconsole.routes.status import _derive_health

    health, reason = _derive_health(_sysinfo(50 * _GIB, pool_idle=0), None, None, None)
    assert health == "warn" and reason == "DB connection pool saturated"


def test_derive_health_warns_on_dr_active() -> None:
    from messagefoundry.api.models import DrStatus
    from messagefoundry_webconsole.routes.status import _derive_health

    dr = DrStatus(enabled=True, active=True, threshold="P1", activation_mode="manual")
    health, reason = _derive_health(_sysinfo(50 * _GIB), dr, None, None)
    assert health == "warn" and reason is not None and "failover" in reason


def test_derive_health_down_when_cluster_leaderless() -> None:
    from messagefoundry.api.models import ClusterNodeList, ClusterStatus
    from messagefoundry_webconsole.routes.status import _derive_health

    cluster = ClusterStatus(
        node_id="n1", clustered=True, is_leader=False, role="standby", config_version=1
    )
    nodes = ClusterNodeList(nodes=[], leader_node_id=None, lease_owner=None, lease_expires_at=None)
    health, reason = _derive_health(_sysinfo(50 * _GIB), None, cluster, nodes)
    assert health == "down" and reason == "cluster has no leader"


def test_derive_health_worst_issue_wins_not_composite() -> None:
    """Owner spec: the color is the WORST single issue, not a composite. A critical disk + warn signals
    (saturated pool, DR-active) still resolves to down, and the reason is the critical one."""
    from messagefoundry.api.models import DrStatus
    from messagefoundry_webconsole.routes.status import _derive_health

    dr = DrStatus(enabled=True, active=True, threshold="P1", activation_mode="manual")
    health, reason = _derive_health(_sysinfo(512 * 1024**2, pool_idle=0), dr, None, None)
    assert health == "down" and reason is not None and "low disk" in reason


def test_derive_health_warns_on_a_failed_inbound_and_names_it() -> None:
    """BACKLOG #1741 act 1: a deployed inbound that failed to start is at least warn, naming it.

    The heart used to read ok over exactly this — an MLLP inbound on an occupied port — while the
    dashboard row beside it already said "failed"."""
    from messagefoundry_webconsole.routes.status import _derive_health

    health, reason = _derive_health(
        _sysinfo(50 * _GIB, failed_names=["IB_ACME_ADT"]), None, None, None
    )
    assert health == "warn"
    assert reason == "inbound IB_ACME_ADT failed to start"


def test_derive_health_failed_inbound_reason_lists_several_then_truncates() -> None:
    from messagefoundry_webconsole.routes.status import _derive_health

    _, two = _derive_health(
        _sysinfo(50 * _GIB, channels=5, failed_names=["A", "B"]), None, None, None
    )
    assert two == "2 inbound connections failed to start: A, B"
    # The reason renders into a title= attribute, so a wide outage truncates rather than listing all.
    _, many = _derive_health(
        _sysinfo(50 * _GIB, channels=9, failed_names=["A", "B", "C", "D", "E"]), None, None, None
    )
    assert many == "5 inbound connections failed to start: A, B, C, and 2 more"


def test_derive_health_failed_inbound_warns_without_a_name_for_a_scoped_caller() -> None:
    """A channel-scoped operator gets the COUNT but no name (/connections hides an out-of-scope
    inbound's name, and the heart must not be a side channel around that) — and still gets the warn,
    which is the whole point of surfacing the count separately."""
    from messagefoundry_webconsole.routes.status import _derive_health

    health, reason = _derive_health(
        _sysinfo(50 * _GIB, channels=4, failed_names=[], failed_count=2), None, None, None
    )
    assert health == "warn"
    assert reason == "2 inbound connections failed to start"
    # A SINGLE hidden failure must not read "1 inbound connections" — the plural head is shared, so
    # the singular case needs its own text on the no-name branch too.
    _, one = _derive_health(
        _sysinfo(50 * _GIB, channels=4, failed_names=[], failed_count=1), None, None, None
    )
    assert one == "1 inbound connection failed to start"


def test_derive_health_warns_when_no_inbound_is_deployed() -> None:
    """BACKLOG #1741 act 2: zero deployed inbounds on a started engine is warn — the heart used to
    read ok over an engine listening on nothing ("0/0 running")."""
    from messagefoundry_webconsole.routes.status import _derive_health

    health, reason = _derive_health(_sysinfo(50 * _GIB, channels=0), None, None, None)
    assert health == "warn"
    assert reason == "no inbound connections deployed"


def test_derive_health_no_inbound_warn_keys_on_total_not_running() -> None:
    """A cluster standby binds no listeners BY DESIGN, so channels_running == 0 is correct there.
    Keying act 2 on running would paint every standby permanently warn; it keys on channels_total."""
    from messagefoundry_webconsole.routes.status import _derive_health

    standby = _sysinfo(50 * _GIB, channels=3, channels_running=0)
    assert standby.engine.channels_running == 0 and standby.engine.channels_total == 3
    assert _derive_health(standby, None, None, None) == ("ok", None)


def test_derive_health_no_inbound_warn_waits_for_a_started_engine() -> None:
    """uptime_seconds == 0 means /status has no engine.started_at yet. An engine still coming up is
    not "listening on nothing", so act 2 holds its warn rather than flashing one on every restart."""
    from messagefoundry_webconsole.routes.status import _derive_health

    assert _derive_health(_sysinfo(50 * _GIB, channels=0, uptime=0.0), None, None, None) == (
        "ok",
        None,
    )


def test_derive_health_connection_issues_lose_to_a_worse_one() -> None:
    """Both #1741 rules are warn, so a critical disk still wins the heart — worst issue wins,
    unchanged. Run for each rule: a failed inbound, then a graph with no inbound at all."""
    from messagefoundry_webconsole.routes.status import _derive_health

    crit = 512 * 1024**2  # 0.5 GiB free
    for sysinfo in (
        _sysinfo(crit, channels=1, failed_names=["IB_A"]),
        _sysinfo(crit, channels=0),
    ):
        health, reason = _derive_health(sysinfo, None, None, None)
        assert health == "down" and reason is not None and "low disk" in reason


def test_derive_health_connection_issue_wins_the_tie_against_another_warn() -> None:
    """At EQUAL severity the reason is the first issue appended, and the connection rules are
    appended first on purpose — a feed that is not listening is more actionable than "on the DR
    box". Pins the tie-break, which is encoded only in list order inside _derive_health."""
    from messagefoundry.api.models import DrStatus
    from messagefoundry_webconsole.routes.status import _derive_health

    dr = DrStatus(enabled=True, active=True, threshold="P1", activation_mode="manual")
    # 3 GiB free is a warn, DR-active is a warn, a failed inbound is a warn — all three fire.
    health, reason = _derive_health(
        _sysinfo(3 * _GIB, channels=2, failed_names=["IB_A"], pool_idle=0), dr, None, None
    )
    assert health == "warn"
    assert reason == "inbound IB_A failed to start"


def test_dashboard_has_connections_filter_box() -> None:
    """The connections dashboard renders a client-side filter-as-you-type box (app.js hides rows that
    don't match). It's an <input type=search> outside the polled table so its value survives the swap."""
    from messagefoundry_webconsole.pages.connections import dashboard

    html = str(dashboard([]))
    assert "data-mf-conns-filter" in html and 'type="search"' in html


def _ux_conn_row(name: str = "IB_ADT", channel_id: str = "c1"):
    from messagefoundry.api.models import ConnectionRow

    return ConnectionRow(
        role="source",
        channel_id=channel_id,
        channel_name="IB",
        destination=None,
        name=name,
        status="running",
        direction="in",
        method="MLLP",
        peer="h",
        port=1,
        queue_depth=None,
        idle_seconds=None,
        alerts_active=0,
        errored=0,
        read=5,
        written=None,
        backlog_seconds=None,
        delivered_age_seconds=None,
    )


def test_connection_name_cell_links() -> None:
    """The connections table name cell (#4a/#4b): the name links to that connection's pre-filled message
    search, and a 'details' link points at its detail page."""
    from messagefoundry_webconsole.pages.connections import connections_fragment

    html = str(connections_fragment([_ux_conn_row()]))
    assert "/ui/messages?channel_id=c1&amp;defer=1" in html  # name → pre-filled search (# escaped)
    assert "/ui/connection/IB_ADT" in html  # details link


def test_connection_details_page_renders() -> None:
    """The connection details page (#4a) composes info + stats + a recent-events table + a link to the
    connection's pre-filled message search."""
    from messagefoundry.api.models import ConnectionEventInfo
    from messagefoundry_webconsole.pages.connections import connection_details

    ev = ConnectionEventInfo(
        id=1,
        ts=1783431967.0,
        connection="IB_ADT",
        transport="MLLP",
        direction="inbound",
        kind="listen_start",
        peer_host="h",
        reason=None,
    )
    html = str(connection_details(_ux_conn_row(), [ev]))
    assert "<h1>IB_ADT</h1>" in html and "listen_start" in html
    assert "channel_id=c1&amp;defer=1" in html  # View messages → pre-filled search


def test_messages_deferred_renders_form_only() -> None:
    """The message log in deferred mode (#4b) renders the pre-filled form + a Search prompt, no results —
    "open a connection's messages, adjust, then Search"."""
    from messagefoundry_webconsole.pages.messages import messages

    html = str(messages(None, deferred=True, channel_id="c1", received_from="2026-07-06T00:00"))
    assert "Adjust the filters and click Search" in html
    assert 'name="received_from"' in html and 'type="datetime-local"' in html
    assert "<tbody>" not in html  # no results table when deferred


def test_connection_name_strips_direction_suffix() -> None:
    """#1: the connection display name drops the redundant ' ▸ in'/' ▸ out' suffix (the Dir column shows
    direction), but the details link keeps the FULL composite name as the row identity; a destination's
    'chan ▸ dest' name has no such suffix and is kept."""
    from messagefoundry_webconsole.pages.connections import _display_name, connections_fragment

    assert _display_name("IB_ADT_FEED ▸ in") == "IB_ADT_FEED"
    assert _display_name("D ▸ out") == "D"
    assert _display_name("chan ▸ dest") == "chan ▸ dest"  # destination composite kept
    html = str(
        connections_fragment([_ux_conn_row(name="IB_ADT_FEED ▸ in", channel_id="IB_ADT_FEED")])
    )
    assert ">IB_ADT_FEED</a>" in html  # stripped display
    assert (
        "/ui/connection/IB_ADT_FEED%20%E2%96%B8%20in" in html
    )  # full name kept as the detail identity


# --- PR A: parse-tree endpoint + per-destination dead-letter replay ----------


async def test_parse_tree_renders_escaped(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine, raw=XSS_RAW, control_id="X1")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get(f"/ui/messages/{mid}/parse-tree")
        assert r.status_code == 200
        assert "MSH" in r.text and "PID" in r.text  # HL7 segment labels rendered
        # The attacker-influenced field value is escaped, never live markup.
        assert "<script>alert(1)</script>" not in r.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


async def test_parse_tree_non_hl7_is_unavailable(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine, raw="this is not an hl7 message", control_id="NOPE")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get(f"/ui/messages/{mid}/parse-tree")
        assert r.status_code == 200
        assert "No HL7 parse tree" in r.text


async def test_parse_tree_requires_view_raw(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "auditor", Role.AUDITOR)  # MONITORING_READ only, no MESSAGES_VIEW_RAW
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "auditor")
        assert (await c.get(f"/ui/messages/{mid}/parse-tree")).status_code == 403


def test_is_safe_ui_action_per_destination() -> None:
    from messagefoundry_webconsole import is_safe_ui_action

    assert is_safe_ui_action("/ui/dead-letters/CH/OB_DEST/replay")
    assert is_safe_ui_action("/ui/dead-letters/CH/replay")
    assert not is_safe_ui_action("/ui/dead-letters/CH/OB/extra/replay")  # 3 segments rejected
    assert not is_safe_ui_action("/ui/dead-letters/CH/../replay")


async def test_dl_replay_per_destination_reaches_handler(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/dead-letters/ch1/OB_DEST/replay", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code not in (401, 403)
        assert "reauth" not in r.headers.get("location", "")


async def test_dl_replay_per_destination_rejects_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/dead-letters/ch1/OB_DEST/replay", headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert r.status_code == 403


# --- PR B: WS payload enrichment (connections fragment pushed over /ws/stats) --


def test_ws_stats_payload_is_enriched(tmp_path: Path) -> None:
    # Sync TestClient drives the lifespan (engine on its own loop), like tests/test_api.py's WS test.
    # No auth → the native allow_no_auth path authorizes the socket; with serve_ui on the web console
    # installs the app.state.ui_connections_render hook, so the payload carries the server-rendered
    # connections fragment alongside the queue-by-status counts (Option B Phase 0 seam 3).
    from starlette.testclient import TestClient

    from messagefoundry.api import create_managed_app

    app = create_managed_app(
        db_path=tmp_path / "wsx.db",
        poll_interval=0.05,
        serve_ui=True,
        allow_no_auth=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    with TestClient(app) as tc, tc.websocket_connect("/ws/stats") as ws:
        data = ws.receive_json()
        assert "outbox_by_status" in data and isinstance(data["outbox_by_status"], dict)
        assert "connections_html" in data and isinstance(data["connections_html"], str)
        assert 'id="conns"' in data["connections_html"]  # the server-rendered table fragment


def test_ws_stats_payload_is_counts_only_without_serve_ui(tmp_path: Path) -> None:
    # JSON-only fallback (Option B Phase 0 seam 3): with serve_ui off the ui_connections_render hook is
    # unset, so /ws/stats pushes a COUNTS-ONLY frame (no server-rendered connections_html) over the
    # native Authorization-header WS auth path. The counts key is always present; a native client that
    # only reads outbox_by_status is unaffected.
    from starlette.testclient import TestClient

    from messagefoundry.api import create_managed_app

    app = create_managed_app(
        db_path=tmp_path / "wsx.db",
        poll_interval=0.05,
        allow_no_auth=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    with TestClient(app) as tc, tc.websocket_connect("/ws/stats") as ws:
        data = ws.receive_json()
        assert "outbox_by_status" in data and isinstance(data["outbox_by_status"], dict)
        assert "connections_html" not in data


# --- PR C: off-loopback exposure — [api].public_origin same-origin checks ------


def _client_po(engine: Engine, service: AuthService, public_origin: str) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, serve_ui=True, public_origin=public_origin)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


def test_public_origin_is_validated_and_normalized() -> None:
    from messagefoundry.config.settings import ApiSettings

    assert (
        ApiSettings(public_origin="https://ops.example.com/").public_origin
        == "https://ops.example.com"
    )
    assert ApiSettings(public_origin=None).public_origin is None
    with pytest.raises(ValueError):
        ApiSettings(public_origin="https://ops.example.com/path")  # path not allowed
    with pytest.raises(ValueError):
        ApiSettings(public_origin="ops.example.com")  # missing scheme


async def test_csrf_honors_public_origin(engine: Engine) -> None:
    # Behind a proxy (public_origin set), the Origin is matched against public_origin, not Host — so a
    # same-origin POST with a mismatching Host still passes, and a cross-origin one is still rejected.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client_po(engine, service, "http://ops.example.com") as c:
        await _cookie_login(c, "op")
        ok = await c.post("/ui/connections/nope/stop", headers={"Origin": "http://ops.example.com"})
        assert ok.status_code != 403  # Origin matches public_origin → CSRF passes (reaches handler)
        bad = await c.post("/ui/connections/nope/stop", headers={"Origin": "http://evil.example"})
        assert bad.status_code == 403  # cross-origin → rejected


async def test_ws_cookie_auth_honors_public_origin(engine: Engine) -> None:
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import authorize_ui_ws

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    app = create_app(engine, auth=service, serve_ui=True, public_origin="https://ops.example.com")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://ops.example.com"
    ) as c:
        token = (await c.post("/auth/login", json={"username": "op", "password": PW})).json()[
            "token"
        ]
    # Public origin matches despite a mismatching Host (the proxy case); a wrong origin is rejected.
    good = _FakeWS(origin="https://ops.example.com", host="internal", cookie=token, app=app)
    assert (await authorize_ui_ws(good, Permission.MONITORING_READ))[0] is not None  # type: ignore[arg-type]
    bad = _FakeWS(origin="https://evil.example", host="internal", cookie=token, app=app)
    assert (await authorize_ui_ws(bad, Permission.MONITORING_READ))[0] is None  # type: ignore[arg-type]


def test_public_origin_matching_is_case_insensitive() -> None:
    # Scheme + host are case-insensitive (RFC 3986 §3.2.2): the validator lowercases the configured
    # origin, and _origin_matches canonicalizes the incoming Origin — so a case variant is not a false
    # reject (and can never be a bypass; it fails closed).
    from messagefoundry.config.settings import ApiSettings
    from messagefoundry_webconsole._auth import _origin_matches

    assert (
        ApiSettings(public_origin="https://OPS.Example.COM").public_origin
        == "https://ops.example.com"
    )

    class _WithPO:
        public_origin = "https://ops.example.com"

    assert _origin_matches(_WithPO(), "https://OPS.EXAMPLE.COM", "internal")
    assert _origin_matches(_WithPO(), "https://ops.example.com", "internal")
    assert not _origin_matches(_WithPO(), "https://evil.example", "internal")

    class _NoPO:
        public_origin = None

    assert _origin_matches(_NoPO(), "http://T", "t")  # Host fallback is case-insensitive too
    assert not _origin_matches(_NoPO(), "http://evil", "t")
