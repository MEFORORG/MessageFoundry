# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 8.1.1 (BACKLOG #1151) — the monitoring plane's DATA-scoping rule, executed and documented.

THE DEFECT THIS EXISTS FOR. ``docs/SECURITY.md``'s per-channel-scoping blockquote — the public
statement of the engine's data-specific access rule — asserted "Monitoring dashboards stay global."
The code outgrew that sentence: a channel-scoped caller's channel, connection, event, alert and graph
reads are ALL narrowed, and every shared-outbound row is suppressed. The doc claimed a caller sees
MORE than the code gives them, and no gate could tell, because the route-map drift guard reads only
the permission and gate columns.

HOW THIS GUARD DIFFERS FROM PROSE-PINNING. The narrowed and global route sets are module constants,
and BOTH halves are checked against BOTH the code and the doc in the same run:

* :func:`test_monitoring_plane_scope_is_measured_against_a_live_app` EXECUTES every route in both
  sets against a channel-scoped operator, with an ALL-CHANNELS operator in the same run as the
  positive control, and asserts the constants describe what the app does.
* :func:`test_security_doc_states_the_measured_monitoring_scope` asserts the doc's blockquote names
  those same routes on the correct side.

So the constants cannot drift from the code without the first test reddening, and the doc cannot
drift from the constants without the second. A name-presence scan was rejected as the instrument
after measurement: over the live app it MISSES ``_control_guard`` (the three ``connections:control``
routes enforce the scope through a helper, so their bodies name no primitive) and it misses the
per-property rule inside ``/ws/stats``. A scan that cannot see a rule it is checking for is not an
instrument, so the executed request is the measurement here.

NOT-DEPLOYED beta: ``GET /metrics`` is recorded below as the one monitoring read that is NOT
narrowed. That is a gap a first deployment would carry, tracked as BACKLOG #1152 (the
metrics-exposition scoping), not a live exposure.
"""

from __future__ import annotations

import re
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AuthSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "SECURITY.md"

#: The blockquote that IS the public statement of the per-channel data rule. Pinned to the rule's
#: NAME and its bold open, NOT to the punctuation that follows: an earlier form ended the literal at
#: ``).**`` and a doc edit that appended to the same heading broke the locator, which silently took
#: every check below with it. The bold open is load-bearing -- without it this also matches the
#: italic cross-reference earlier in the document and anchors the scan on the pointer, not the rule.
_SCOPE_MARKER = "**Per-channel scoping (DLQ-SCOPE)"

#: The retired falsehood. It was inherited verbatim from an internal design document, where it was a
#: decision the code later outgrew. It must never come back.
_RETIRED_FALSEHOOD = "Monitoring dashboards stay global."

#: Monitoring reads a channel-scoped caller sees NARROWED. Written as the doc writes them, so the
#: doc check is an exact token comparison rather than a substring test (``GET /metrics`` is a prefix
#: of ``GET /metrics/history``, and a substring test would confuse the two).
_NARROWED_READS = (
    "GET /channels",
    "GET /connections",
    "GET /events",
    "GET /graph/edges",
    "GET /alerts/active",
)

#: Monitoring reads that stay GLOBAL because they carry no connection identity at all — aggregate
#: queue counters. These are the "both halves" the rule has to state: narrowing the topology reads
#: while leaving these global is the actual shipped behaviour.
_GLOBAL_AGGREGATES = ("GET /stats", "GET /metrics/history")

#: The one monitoring read that is per-connection AND not narrowed. Stating it is what keeps the
#: correction from trading one false sentence for another.
_UNSCOPED_PER_CONNECTION = "GET /metrics"

PW = "Sup3rSecret!!"

#: Synthetic HL7 — MSH only, no PID segment, so no field can be mistaken for patient data.
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r"


# =====================================================================================================
# The measurement — executed against a live app, scoped caller vs all-channels positive control
# =====================================================================================================


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "monscope.db", poll_interval=0.02)
    reg = Registry()
    reg.add_inbound(
        InboundConnection("IB_A", ConnectionSpec(ConnectorType.MLLP, {"port": 25850}), router="r")
    )
    reg.add_inbound(
        InboundConnection("IB_B", ConnectionSpec(ConnectorType.MLLP, {"port": 25851}), router="r")
    )
    reg.add_outbound(
        OutboundConnection("OB_X", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_X", m))
    eng.add_registry(reg)
    # Traffic on BOTH inbounds, so the Prometheus exposition actually carries a per-connection
    # series to measure. Synthetic MSH-only HL7, no PID, no PHI.
    for channel in ("IB_A", "IB_B"):
        await eng.store.enqueue_message(
            channel_id=channel, raw=ADT, deliveries=[("OB_X", ADT)], now=time.time()
        )
    for name, direction in (("IB_A", "inbound"), ("IB_B", "inbound"), ("OB_X", "outbound")):
        await eng.store.record_connection_event(
            connection=name,
            transport="mllp",
            direction=direction,
            kind="established",
            peer_host="10.0.0.1",
            now=100.0,
        )
        # One open alert per connection, so /alerts/active discriminates instead of being empty on
        # both sides (an empty-vs-empty comparison would assert nothing).
        await eng.store.upsert_alert_instance(
            event_type="connection_lost", connection=name, severity="warning", now=100.0
        )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _operator(service: AuthService, username: str) -> str:
    user_id = await service.create_local_user(
        username=username,
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
    return user_id


async def _login(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def test_monitoring_plane_scope_is_measured_against_a_live_app(engine: Engine) -> None:
    """Every route in ``_NARROWED_READS`` narrows for a scoped caller; every route in
    ``_GLOBAL_AGGREGATES`` does not; ``_UNSCOPED_PER_CONNECTION`` is per-connection and not narrowed.

    The all-channels operator is the positive control, in the SAME run: if the fixture were
    mis-seeded, or a route 500'd, the control's assertions fail too rather than the scoped side
    passing vacuously.
    """
    service = await _service(engine)
    scoped_id = await _operator(service, "scoped")
    await service.set_channel_scope(scoped_id, ["IB_A"], actor="admin")
    # Deny-by-default (BACKLOG #1152): an absent scope now resolves to NO channel, so the control
    # has to be granted the estate rather than left unset. It is still a genuinely wide caller --
    # "*" resolves to every channel -- which is what makes it a control and not a second scoped user.
    wide_id = await _operator(service, "allchannels")
    await service.set_channel_scope(wide_id, [ALL_CHANNELS], actor="admin")

    async with _client(engine, service) as c:
        s = await _login(c, "scoped")
        u = await _login(c, "allchannels")

        # --- positive control: the all-channels caller sees the whole estate on every read ---------
        assert {ch["id"] for ch in (await c.get("/channels", headers=u)).json()} == {"IB_A", "IB_B"}
        assert {r["channel_id"] for r in (await c.get("/connections", headers=u)).json()} == {
            "IB_A",
            "IB_B",
        }
        assert {e["connection"] for e in (await c.get("/events", headers=u)).json()} == {
            "IB_A",
            "IB_B",
            "OB_X",
        }
        ugraph = (await c.get("/graph/edges", headers=u)).json()
        assert any(n["kind"] == "outbound" for n in ugraph["nodes"])
        ualerts = (await c.get("/alerts/active", headers=u)).json()
        assert {a["connection"] for a in ualerts["alerts"]} == {"IB_A", "IB_B", "OB_X"}

        # --- GET /channels, GET /connections, GET /events, GET /graph/edges: NARROWED --------------
        assert {ch["id"] for ch in (await c.get("/channels", headers=s)).json()} == {"IB_A"}
        conns = (await c.get("/connections", headers=s)).json()
        assert {r["channel_id"] for r in conns} == {"IB_A"}
        # A destination row only materialises once an (inbound -> outbound) edge has carried traffic,
        # so this alone would not discriminate on a quiet fixture. The shared-outbound suppression is
        # measured non-vacuously by /events and /graph/edges below, where the all-channels control
        # DOES see OB_X and the scoped caller does not.
        assert all(r["destination"] is None for r in conns)
        assert {e["connection"] for e in (await c.get("/events", headers=s)).json()} == {"IB_A"}
        sgraph = (await c.get("/graph/edges", headers=s)).json()
        assert not any(n["kind"] == "outbound" for n in sgraph["nodes"]), (
            "a scoped caller must never traverse into a shared outbound"
        )
        assert {n["name"] for n in sgraph["nodes"] if n["kind"] == "inbound"} == {"IB_A"}

        # --- GET /alerts/active: NARROWED ---------------------------------------------------------
        salerts = (await c.get("/alerts/active", headers=s)).json()
        assert {a["connection"] for a in salerts["alerts"]} == {"IB_A"}

        # --- GET /stats, GET /metrics/history: GLOBAL ---------------------------------------------
        # These carry aggregate queue counters and NO connection identity, so there is nothing to
        # narrow. Asserted as "no connection name reaches the payload" rather than as byte equality:
        # /stats also exposes live cost counters (committed_txns) that tick between two requests, and
        # an equality assertion on those would be flaky for a reason unrelated to scoping.
        for path in ("/stats", "/metrics/history"):
            scoped_body, control_body = (
                (await c.get(path, headers=s)).json(),
                (await c.get(path, headers=u)).json(),
            )
            assert scoped_body.keys() == control_body.keys()
            for name in ("IB_A", "IB_B", "OB_X"):
                assert name not in str(scoped_body), f"{path} named {name} — it is not an aggregate"

        # --- GET /metrics: per-connection AND NOT narrowed ----------------------------------------
        smetrics = (await c.get("/metrics", headers=s)).text
        umetrics = (await c.get("/metrics", headers=u)).text
        # It is per-connection: the out-of-scope connection name appears in the exposition...
        assert 'connection="IB_B"' in smetrics, (
            "the exposition is keyed by connection name, so a scoped caller reads a connection "
            "outside their scope — BACKLOG #1152 (metrics-exposition scoping)"
        )
        # ...and it is identical to what the all-channels caller reads, i.e. not narrowed at all.
        assert _strip_volatile(smetrics) == _strip_volatile(umetrics)


def _strip_volatile(exposition: str) -> list[str]:
    """Metric LINES with the sampled values dropped, so a process gauge moving between two requests
    cannot make an equality assertion flaky. The label sets — which is what scoping would change —
    survive."""
    return sorted(
        line.split(" ")[0] for line in exposition.splitlines() if line and not line.startswith("#")
    )


# =====================================================================================================
# The doc binding — the same constants, read out of docs/SECURITY.md
# =====================================================================================================


def _doc_text() -> str:
    return _DOC.read_text(encoding="utf-8")


def _scope_blockquote_lines(text: str) -> list[str]:
    """The RAW lines of the DLQ-SCOPE blockquote: from its marker to the first non-blockquote line."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if _SCOPE_MARKER in line), None)
    assert start is not None, f"docs/SECURITY.md no longer contains {_SCOPE_MARKER!r}"
    out: list[str] = []
    for line in lines[start:]:
        if not line.startswith(">"):
            break
        out.append(line)
    return out


def _scope_blockquote(text: str) -> str:
    """The DLQ-SCOPE blockquote as one unwrapped string, so a claim split across a line break still
    reads as one sentence."""
    return " ".join(line.lstrip("> ").rstrip() for line in _scope_blockquote_lines(text))


def _plant_in_blockquote(text: str, old: str, new: str) -> str:
    """Substitute INSIDE the DLQ-SCOPE blockquote only.

    A whole-document ``replace`` was the first attempt and it graded the wrong thing: several of
    these route tokens are backticked elsewhere in ``docs/SECURITY.md``, so the mutation landed in
    an unrelated section, the document changed, and the planted-omission test passed without ever
    touching the block under grade.
    """
    block = "\n".join(_scope_blockquote_lines(text))
    assert old in block, f"the DLQ-SCOPE blockquote does not contain {old!r}"
    return text.replace(block, block.replace(old, new, 1), 1)


def _route_tokens(block: str) -> set[str]:
    """Backticked ``METHOD /path`` tokens in the block, matched EXACTLY. Substring matching would
    read ``GET /metrics`` out of ``GET /metrics/history`` and grade the wrong sentence."""
    return set(re.findall(r"`([A-Z]+ /[^`]*)`", block))


def _monitoring_scope_problems(text: str) -> list[str]:
    """Every way the monitoring-scope statement fails to say what the app does. Empty list = sound."""
    problems: list[str] = []
    block = _scope_blockquote(text)
    # BOTH readings, because each misses what the other catches. The raw document finds the sentence
    # anywhere, including outside this blockquote; the unwrapped block finds it when a reflow has
    # split it across a line break, which is exactly how it survived one merge unnoticed.
    if _RETIRED_FALSEHOOD in text or _RETIRED_FALSEHOOD in block:
        problems.append(f"the retired falsehood is back: {_RETIRED_FALSEHOOD!r}")
    tokens = _route_tokens(block)
    for route in _NARROWED_READS:
        if route not in tokens:
            problems.append(f"{route} is narrowed for a scoped caller and the blockquote omits it")
    for route in _GLOBAL_AGGREGATES:
        if route not in tokens:
            problems.append(f"{route} stays global and the blockquote omits it")
    if _UNSCOPED_PER_CONNECTION not in tokens:
        problems.append(
            f"{_UNSCOPED_PER_CONNECTION} is per-connection and NOT narrowed; omitting it would "
            "trade one false sentence for a quieter one"
        )
    if "shared outbound" not in block.lower():
        problems.append("the shared-outbound suppression is the sharpest half and must be stated")
    return problems


def test_security_doc_states_the_measured_monitoring_scope() -> None:
    """For a documentation requirement the DOCUMENTATION is the control; this guard only keeps it
    true. Every route the measurement above classifies must appear on the right side of the rule."""
    assert _monitoring_scope_problems(_doc_text()) == []


def test_scope_guard_detects_the_retired_falsehood() -> None:
    """A planted mutation, in the house pattern: re-assert the retired sentence and the guard must
    catch it. Without this, a guard that silently stopped locating the blockquote would stay green."""
    # Same rule as _SCOPE_MARKER: pin the claim, not the punctuation the surrounding prose owns.
    # The closing ``.**`` was in the literal once and a rewrite to "**...all-channels**, by role,"
    # broke it, which cost this planted mutation its anchor while every other assertion still read
    # green. Where the falsehood lands inside the plant does not matter -- the planted string is
    # graded, never written -- only that it lands inside THIS blockquote.
    anchor = "**Administrators are always all-channels"
    planted = _plant_in_blockquote(_doc_text(), anchor, f"{anchor} {_RETIRED_FALSEHOOD}")
    assert planted != _doc_text(), "the planted-mutation anchor no longer exists in the blockquote"
    assert any("retired falsehood" in p for p in _monitoring_scope_problems(planted))


@pytest.mark.parametrize("route", (*_NARROWED_READS, *_GLOBAL_AGGREGATES, _UNSCOPED_PER_CONNECTION))
def test_scope_guard_detects_a_planted_omission(route: str) -> None:
    """Deleting any single classified route from the blockquote must red the guard — the row-count
    floor in its per-row form. The walk's own docstring prescribes flooring because a refactor once
    made every route read as ungated while the guard stayed green."""
    planted = _plant_in_blockquote(_doc_text(), f"`{route}`", "`GET /nowhere`")
    assert planted != _doc_text(), f"the blockquote does not backtick {route!r} to begin with"
    assert _monitoring_scope_problems(planted), f"deleting {route} did not red the guard"
