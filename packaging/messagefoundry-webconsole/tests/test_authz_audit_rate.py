# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 16.3.2 (BACKLOG #1197) -- the audit-row RATE a polling console produces under audit_all.

WHY. The all-decisions clause was traded against a "flooding the audit log" cost that ADR 0118
section 5 and the ``audit_all_authz`` field comment both ASSERT and neither MEASURES. The default
has since flipped ON (BACKLOG #1277) on the reasoning that the console "never traverses
``require()``", so no console page view can write a grant row. That reasoning is now load-bearing
under a shipped default, and it was reached by reading the code rather than by running it. This
module runs it.

THE METHOD is deterministic, not statistical: rows-per-minute is a quotient of two exactly-known
integers, so no number here depends on wall-clock timing or machine speed. The NUMERATOR is rows per
request, measured against the real ASGI app -- real ``AuthService``, real store, real hash-chained
``audit_log``. The DENOMINATOR is the poll interval the console ships, held in
:data:`_SHIPPED_POLL_INTERVALS_MS` and re-derived from the console's own source by
:func:`test_shipped_poll_intervals_match_the_console_source`, so a cadence change fails loudly
instead of silently rescaling a published rate.

THE COMMAND::

    pytest packaging/messagefoundry-webconsole/tests/test_authz_audit_rate.py -q -s

``-s`` prints one rate table at the end of the session; without it the assertions still hold every
number in that table.

THREE ARMS:

* ARM A -- HEAD, unmodified. What one open console tab costs today.
* ARM B -- the end state BACKLOG #1197 proposes: ``audit_permission_granted`` mirrored into
  ``require_ui``. Applied as a probe over the real factory, so rows go down the real audit path.
* ARM C -- the JSON API, which is the surface the flipped default actually changed.

WHAT THIS DOES NOT MEASURE, so nobody reads the numbers as wider than they are. One tab in steady
state: page NAVIGATIONS are excluded (a human action, not a rate), as is the ``/ws/stats`` socket
(``authorize_ws`` fires once per CONNECTION, not per message). ARM B patches the bare ``require_ui``
factory, which is what all four polled endpoints use; it does NOT reach the step-up and reauth
derivatives, which call ``require_ui`` as a module global inside ``_auth`` where this patch cannot
see it. And nothing here measures the point at which a row rate "degrades security monitoring" --
that half of the question has no shipped threshold to measure against, since ``[retention]``'s
``audit_days`` is reserved and unenforced and ``max_db_mb`` ships at 0.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import Request

from messagefoundry.api import create_app
from messagefoundry.api.security import _grant_audit_permission, get_auth
from messagefoundry.auth import Identity, Permission, Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, DiagnosticsSettings, SecuritySettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # matches the /ui suite's own fixture password (WP-3 policy)
GRANT = "auth.permission_granted"

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONSOLE_ROOT = _REPO_ROOT / "messagefoundry_webconsole"
_HARNESS_MONITOR = _REPO_ROOT / "harness" / "monitor.py"

# The shipped steady-state poll cadence, in milliseconds, keyed by the endpoint the client fetches.
# Each value is checked against the console's own source by the test named in the module docstring.
_SHIPPED_POLL_INTERVALS_MS: dict[str, int] = {
    "/ui/nav-status": 15_000,  # static/app.js -- runs on EVERY page (nav heart + alerts bell)
    "/ui/session-status": 30_000,  # static/app.js PROBE_MS -- the watchdog heartbeat, every page
    "/ui/connections": 5_000,  # pages/connections.py data_poll_ms -- connections dashboard only
    "/ui/monitoring/live": 5_000,  # pages/monitoring.py data_fragment_ms -- flow page only
}

# What one tab polls, by the page it is parked on. Every page carries the nav poll and the session
# watchdog; the two live pages add their own fragment.
_TAB_PROFILES: dict[str, tuple[str, ...]] = {
    "any page (nav + watchdog)": ("/ui/nav-status", "/ui/session-status"),
    "connections dashboard": ("/ui/nav-status", "/ui/session-status", "/ui/connections"),
    "flow / monitoring page": ("/ui/nav-status", "/ui/session-status", "/ui/monitoring/live"),
}


def _per_minute(interval_ms: int, what: str) -> int:
    """Exact count in one minute. Divisibility keeps every published number off a rounding."""
    assert 60_000 % interval_ms == 0, f"{what}: {interval_ms}ms does not divide a minute evenly"
    return 60_000 // interval_ms


def _requests_per_minute(endpoint: str) -> int:
    return _per_minute(_SHIPPED_POLL_INTERVALS_MS[endpoint], endpoint)


def _find(pattern: str, text: str, what: str) -> str:
    """First capture group, or a loud failure. A regex that matches nothing must never read as a
    zero-valued measurement, so the absence is an error rather than a default."""
    match = re.search(pattern, text)
    assert match is not None, f"{what}: /{pattern}/ matched nothing -- the source moved"
    return match.group(1)


async def _service(engine: Engine) -> AuthService:
    # require_mfa=False for the reason the /ui suite pins it: this measures authorization auditing,
    # not enrolment, and an unenrolled session otherwise diverts to the enrol page.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _operator(service: AuthService) -> None:
    user_id = await service.create_local_user(
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _app(engine: Engine) -> Any:
    """An engine + console app with one operator signed up, at the SHIPPED audit posture."""
    service = await _service(engine)
    await _operator(service)
    app = create_app(engine, auth=service, serve_ui=True)
    assert app.state.audit_all_authz is True, "the factory did not thread the shipped default"
    return app


async def _count(engine: Engine, action: str | None = None) -> int:
    """Rows in ``audit_log``; ``action=None`` counts every row, which is what flooding means."""
    rows = await engine.store.list_audit(action=action, limit=100_000)
    assert len(rows) < 100_000, "audit read hit its limit -- the count would be a truncation"
    return len(rows)


@asynccontextmanager
async def _signed_in_tab(app: Any) -> AsyncIterator[httpx.AsyncClient]:
    """A browser tab: an ASGI client holding a real session cookie from the real /ui login flow.

    THE LOGIN STATUS IS NOT THE PROOF, and reading it as one would make every zero in ARM A vacuous.
    Measured on this app: ``POST /ui/login`` answers **303 on a correct password and 303 on a wrong
    one** -- the redirect target differs, the status does not. An unauthenticated client would then
    be redirected away from every polled endpoint, write no audit rows, and report a tidy zero that
    is a fact about the failed sign-in rather than about the console. So the proof is a REQUEST:
    fetch a gated endpoint and require a 200, which separates the two cases as the status cannot.
    """
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as client:
        await client.post("/ui/login", data={"username": "op", "password": PW})
        proof = await client.get("/ui/nav-status")
        assert proof.status_code == 200, (
            f"the tab is not signed in: /ui/nav-status returned {proof.status_code}, not 200 "
            "-- every row count taken from this client would be vacuous"
        )
        yield client


async def _bearer(client: httpx.AsyncClient) -> dict[str, str]:
    """A JSON-API Authorization header for the same operator -- the engine gate, not the /ui one."""
    login = await client.post("/auth/login", json={"username": "op", "password": PW})
    assert login.status_code == 200, f"JSON login failed: {login.status_code}"
    return {"Authorization": f"Bearer {login.json()['token']}"}


async def _drive_one_minute(client: httpx.AsyncClient, endpoints: tuple[str, ...]) -> None:
    """Issue exactly the requests one tab makes in a minute.

    Issued back-to-back rather than on a timer: the gate writes its row per request, so the ROW
    COUNT is a function of how many requests are made, never of how far apart they are.
    """
    for endpoint in endpoints:
        for _ in range(_requests_per_minute(endpoint)):
            resp = await client.get(endpoint)
            assert resp.status_code == 200, f"{endpoint} returned {resp.status_code}, not 200"


def _mirror_grant_into_require_ui(monkeypatch: pytest.MonkeyPatch, app_state: Any) -> None:
    """ARM B: apply BACKLOG #1197's proposed console grant parity as a probe.

    Route modules do ``from .._auth import require_ui`` at import time, so patching ``_auth`` alone
    would reach nothing -- each module's own namespace has to be patched. The module list comes from
    ``mount._REGISTRARS``, which is mount's authoritative, order-pinned tuple, rather than from a
    scan of whatever happens to be imported.

    Patching the FACTORY rather than the dependency is what makes this faithful: a gate application
    naming no permission (``/ui/session-status``) then has nothing to record and correctly writes
    nothing, which is why ARM B lands below the request count instead of equal to it.

    NOTE FOR WHOEVER IMPLEMENTS THIS: the probe calls ``_grant_audit_permission``, a PRIVATE symbol
    in ``messagefoundry.api.security``, from the separately-versioned console package. The real
    change would live in the console and could not make that call, so step one of the build is
    promoting that seam -- not writing this line into ``_auth``.
    """
    from messagefoundry_webconsole._auth import require_ui as real_require_ui
    from messagefoundry_webconsole.mount import _REGISTRARS

    audit_all = bool(getattr(app_state, "audit_all_authz", False))

    def factory(*permissions: Permission, **kwargs: Any) -> Callable[[Request], Any]:
        inner = real_require_ui(*permissions, **kwargs)

        async def dependency(request: Request) -> Identity:
            identity = await inner(request)
            auth = get_auth(request)
            audited = _grant_audit_permission(permissions, audit_all=audit_all)
            if auth is not None and audited is not None:
                await auth.audit_permission_granted(identity, audited, request.url.path)
            return identity

        return dependency

    patched = 0
    for module in _REGISTRARS:
        if getattr(module, "require_ui", None) is real_require_ui:
            monkeypatch.setattr(module, "require_ui", factory)
            patched += 1
    assert patched > 0, "no registrar exposed require_ui -- the probe would measure nothing"


@pytest.fixture(scope="session")
def rate_table() -> Iterator[list[str]]:
    """Collects one line per measured case and prints the table once, at the end of the session."""
    lines: list[str] = []
    yield lines
    if lines:
        print("\n\nASVS 16.3.2 / BACKLOG #1197 -- measured audit-row rates\n" + "\n".join(lines))


# --------------------------------------------------------------------------------------------
# The premise: what actually ships
# --------------------------------------------------------------------------------------------


def test_shipped_default_audits_every_authorization_grant() -> None:
    """BACKLOG #1197's row records this default as False. It is TRUE at HEAD (BACKLOG #1277).

    This pins the SETTINGS value. The behaviour it produces -- a plain authenticated GET leaving a
    grant row -- is pinned separately in ``tests/test_auth_hardening.py``.
    """
    assert SecuritySettings().audit_all_authorization_decisions is True
    assert DiagnosticsSettings().audit_all_authz is True


def test_shipped_poll_intervals_match_the_console_source() -> None:
    """The rate's DENOMINATOR, derived from the console's own source and compared to the dict.

    Derived rather than restated: a regex pulls each integer out and checks it against
    :data:`_SHIPPED_POLL_INTERVALS_MS`, so editing the dict alone cannot silently rescale a
    published rate. :func:`_find` turns a non-matching pattern into a loud failure, not a zero.
    """
    app_js = (_CONSOLE_ROOT / "static" / "app.js").read_text(encoding="utf-8")
    connections = (_CONSOLE_ROOT / "pages" / "connections.py").read_text(encoding="utf-8")
    monitoring = (_CONSOLE_ROOT / "pages" / "monitoring.py").read_text(encoding="utf-8")

    derived = {
        "/ui/nav-status": _find(r"setInterval\(poll,\s*(\d+)\)", app_js, "nav-status poll"),
        "/ui/session-status": _find(r"PROBE_MS\s*=\s*(\d+)", app_js, "session-status probe"),
        "/ui/connections": _find(r'data_poll_ms="(\d+)"', connections, "connections fragment"),
        "/ui/monitoring/live": _find(r'data_fragment_ms="(\d+)"', monitoring, "flow fragment"),
    }
    assert {k: int(v) for k, v in derived.items()} == _SHIPPED_POLL_INTERVALS_MS

    # The endpoints themselves are named in the same rendered attributes; a renamed route would
    # otherwise leave the interval right and the target wrong.
    assert 'data_poll="/ui/connections"' in connections
    assert 'data_fragment_url="/ui/monitoring/live"' in monitoring


def test_console_has_no_grant_audit_call_anywhere() -> None:
    """The structural reason ARM A is what it is, held against a positive control in the same walk.

    A search for an absent symbol returns zero whether the symbol is absent or the walk is broken,
    so the denial twin is counted in the same pass over the same files and must be found.
    """
    grants = denials = 0
    for path in _CONSOLE_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        grants += text.count("audit_permission_granted")
        denials += text.count("audit_permission_denied")
    assert denials > 0, "positive control: the console must call audit_permission_denied"
    assert grants == 0, "the console now writes grant rows -- the measured ARM A rate is stale"


# --------------------------------------------------------------------------------------------
# ARM A -- HEAD, unmodified
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", sorted(_TAB_PROFILES))
async def test_arm_a_console_tab_writes_no_audit_rows_at_head(
    engine: Engine, profile: str, rate_table: list[str]
) -> None:
    """One console tab, one minute of the shipped poll schedule, ``audit_all_authz`` at its default.

    The positive control stays INSIDE this test deliberately, rather than being split out: it has to
    run on the same store, in the same run, through the same counter as the zero it validates. A
    separate test could pass while this test's store was broken, which is the failure the control
    exists to exclude.
    """
    app = await _app(engine)
    endpoints = _TAB_PROFILES[profile]
    async with _signed_in_tab(app) as client:
        before_grants = await _count(engine, GRANT)
        before_all = await _count(engine)
        await _drive_one_minute(client, endpoints)
        grants = await _count(engine, GRANT) - before_grants
        total = await _count(engine) - before_all

        # Positive control: the engine's own gate, same app, same store, same counter.
        control = await client.get("/stats", headers=await _bearer(client))
        assert control.status_code == 200, f"control request failed: {control.status_code}"
        controlled = await _count(engine, GRANT) - before_grants

    assert controlled > grants, "positive control did not fire -- this measurement proves nothing"
    assert grants == 0, f"{profile}: console polling wrote {grants} grant rows in a minute"
    # The flooding question is about the LOG, not only its grant rows: a poll cycle writing any
    # other row would still be a cost. Measured so the zero is a zero about the whole table.
    assert total == 0, (
        f"{profile}: console polling wrote {total} audit rows of some kind in a minute"
    )

    issued = sum(_requests_per_minute(e) for e in endpoints)
    rate_table.append(
        f"  ARM A  {profile:<26} {issued:>3} requests/min -> {total:>3} audit rows/min"
    )


# --------------------------------------------------------------------------------------------
# ARM B -- the proposed end state
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", sorted(_TAB_PROFILES))
async def test_arm_b_console_tab_under_proposed_grant_parity(
    engine: Engine, profile: str, monkeypatch: pytest.MonkeyPatch, rate_table: list[str]
) -> None:
    """The same minute with ``audit_permission_granted`` mirrored into ``require_ui``.

    This is the cost BACKLOG #1197 says must be measured BEFORE console grant parity lands. Rows go
    down the real audit path, so the number includes the chained INSERT the proposal would pay for.
    """
    service = await _service(engine)
    await _operator(service)
    # The patch must be installed BEFORE create_app, which is when the route modules bind their
    # dependencies -- so this arm cannot reuse _app().
    probe_state = type("_S", (), {"audit_all_authz": True})()
    _mirror_grant_into_require_ui(monkeypatch, probe_state)
    app = create_app(engine, auth=service, serve_ui=True)
    assert app.state.audit_all_authz is probe_state.audit_all_authz, (
        "arms are on different postures"
    )

    endpoints = _TAB_PROFILES[profile]
    async with _signed_in_tab(app) as client:
        before = await _count(engine, GRANT)
        await _drive_one_minute(client, endpoints)
        rows = await _count(engine, GRANT) - before

    # One row per gate application naming at least one non-PHI-view permission. The watchdog probe
    # gates on a live session and NO permission, so it is polled and still records nothing.
    expected = sum(_requests_per_minute(e) for e in endpoints if e != "/ui/session-status")
    assert rows == expected, f"{profile}: expected {expected} rows/min, measured {rows}"

    issued = sum(_requests_per_minute(e) for e in endpoints)
    rate_table.append(
        f"  ARM B  {profile:<26} {issued:>3} requests/min -> {rows:>3} audit rows/min"
        f"  ({rows * 60 * 24:,}/day)"
    )


# --------------------------------------------------------------------------------------------
# ARM C -- the JSON API, which is the surface the flipped default actually changed
# --------------------------------------------------------------------------------------------


def _harness_poll_cycle() -> tuple[int, tuple[str, ...]]:
    """The shipped harness monitor's poll interval and the API calls one cycle makes.

    BOTH halves are read from ``harness/monitor.py`` rather than transcribed. Reading the interval
    while hand-copying the call list would leave the arm blind to the one drift it exists to
    catch -- a fourth call per cycle would raise the real rate and fail nothing. Read as TEXT,
    not by import, so this console-suite test never pulls PySide6 in behind the harness package.
    """
    source = _HARNESS_MONITOR.read_text(encoding="utf-8")
    interval_ms = int(_find(r"_POLL_INTERVAL_MS\s*=\s*(\d+)", source, "harness poll interval"))

    start = source.index("    def _poll(self)")
    body = source[start:]
    end = body.find("\n\nclass ")
    poll_src = body[:end] if end != -1 else body
    methods = tuple(sorted(set(re.findall(r"\bclient\.(\w+)\(", poll_src))))
    assert methods, "positive control: _poll must make at least one API client call"
    return interval_ms, methods


async def test_arm_c_json_api_client_rate_on_the_shipped_default(
    engine: Engine, rate_table: list[str]
) -> None:
    """ARM A being zero does not mean the flipped default is free -- the cost is on another surface.

    The ``audit_all_authz`` field comment bounds the growth by "JSON-API client polling cadence (the
    harness polls /stats)" and stops at a ROUTE COUNT. This measures the RATE, against a polling
    JSON-API client this repository ships: ``harness/monitor.py``'s ``MonitorPoller``.
    """
    interval_ms, methods = _harness_poll_cycle()
    paths = {"stats": "/stats", "connections": "/connections", "list_dead_letters": "/dead-letters"}
    assert set(methods) == set(paths), (
        f"the harness poll cycle changed: {methods} -- the endpoint map below is now wrong"
    )
    cycle = tuple(paths[m] for m in methods)

    app = await _app(engine)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as client:
        headers = await _bearer(client)
        before = await _count(engine, GRANT)
        for path in cycle:
            resp = await client.get(path, headers=headers)
            assert resp.status_code == 200, f"{path} returned {resp.status_code}"
        per_cycle = await _count(engine, GRANT) - before

    assert per_cycle == len(cycle), f"expected one row per gated call, measured {per_cycle}"
    per_minute = per_cycle * _per_minute(interval_ms, "harness poll cycle")
    rate_table.append(
        f"  ARM C  harness monitor ({interval_ms}ms)   {len(cycle)} calls/cycle"
        f" -> {per_minute:>3} audit rows/min  ({per_minute * 60 * 24:,}/day)"
    )
