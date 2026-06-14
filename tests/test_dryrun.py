"""Dry-run harness: pure routing/handling, no store/connectors/network."""

from __future__ import annotations

import pytest

from messagefoundry.config.models import ConnectorType, Validation
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import (
    DeliveryPreview,
    dry_run,
    route_message,
    route_only,
    select_inbound,
    split_messages,
    transform_one,
)
from messagefoundry.store import MessageStatus

ADT_A01 = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def _registry(route, handlers, *, strict: bool = False) -> Registry:  # type: ignore[no-untyped-def]
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
            router="r",
            validation=Validation(strict=strict, hl7_version="2.5.1"),
        )
    )
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", route)
    for name, fn in handlers.items():
        reg.add_handler(name, fn)
    return reg


def test_routed_and_transformed() -> None:
    def handle(msg: Message) -> Send:
        msg["MSH-3"] = "FOUNDRY"
        return Send("out", msg)

    result = dry_run(_registry(lambda m: ["h"], {"h": handle}), ADT_A01)
    assert result.disposition is MessageStatus.RECEIVED
    assert result.inbound == "in"
    assert result.message_type == "ADT^A01" and result.control_id == "MSG1"
    assert result.handlers == ["h"]
    assert len(result.deliveries) == 1
    assert result.deliveries[0].to == "out"
    assert "FOUNDRY" in result.deliveries[0].payload
    assert "DOE" in (result.summary or "")  # PHI summary computed from the peek


def test_router_routes_nowhere_is_unrouted() -> None:
    result = dry_run(_registry(lambda m: [], {}), ADT_A01)
    assert result.disposition is MessageStatus.UNROUTED
    assert result.handlers == [] and result.deliveries == []


def test_handler_filters_is_filtered() -> None:
    result = dry_run(_registry(lambda m: ["h"], {"h": lambda m: None}), ADT_A01)
    assert result.disposition is MessageStatus.FILTERED
    assert result.handlers == ["h"] and result.deliveries == []


def test_router_to_unknown_handler_is_error() -> None:
    # Router names a handler that isn't registered (typo / renamed / removed handler). This must FAIL
    # CLOSED — ERROR (+ NAK on the live path), never a silent FILTERED accept-and-drop (review M-7).
    result = dry_run(_registry(lambda m: ["ghost"], {}), ADT_A01)
    assert result.disposition is MessageStatus.ERROR
    assert result.error and "ghost" in result.error


def test_parse_error_is_error() -> None:
    result = dry_run(
        _registry(lambda m: ["h"], {"h": lambda m: Send("out", m)}), "not an hl7 message"
    )
    assert result.disposition is MessageStatus.ERROR
    assert result.error and "parse" in result.error


def test_router_exception_is_error() -> None:
    def boom(msg: Message) -> list[str]:
        raise RuntimeError("kaboom")

    result = dry_run(_registry(boom, {}), ADT_A01)
    assert result.disposition is MessageStatus.ERROR
    assert result.error and "router/handler error" in result.error


def test_strict_validation_error() -> None:
    bad = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|N1|P|2.5.1\rEVN|A01|20260101\r"  # no PID
    result = dry_run(_registry(lambda m: ["h"], {"h": lambda m: Send("out", m)}, strict=True), bad)
    assert result.disposition is MessageStatus.ERROR
    assert result.error


def test_route_message_is_pure_routing() -> None:
    reg = _registry(lambda m: ["h"], {"h": lambda m: Send("out", m)})
    outcome = route_message(reg, reg.inbound["in"], ADT_A01)
    assert outcome.routed is True
    assert [d.to for d in outcome.deliveries] == ["out"]


# --- split routing core: route_only + transform_one (ADR 0001 Step B) --------


def test_route_only_returns_handler_names() -> None:
    reg = _registry(lambda m: ["h1", "h2"], {"h1": lambda m: None, "h2": lambda m: None})
    assert route_only(reg, reg.inbound["in"], ADT_A01) == ["h1", "h2"]


def test_route_only_routes_nowhere() -> None:
    reg = _registry(lambda m: [], {})
    assert route_only(reg, reg.inbound["in"], ADT_A01) == []


def test_route_only_unknown_handler_raises() -> None:
    # The router-stage fail-closed: a router naming a missing handler raises BEFORE any routed-stage
    # row is produced (no transform worker could run it). Same ValueError the combined path raised.
    reg = _registry(lambda m: ["ghost"], {})
    with pytest.raises(ValueError, match="unknown handler 'ghost'"):
        route_only(reg, reg.inbound["in"], ADT_A01)


def test_transform_one_returns_deliveries() -> None:
    def handle(msg: Message) -> Send:
        msg["MSH-3"] = "FOUNDRY"
        return Send("out", msg)

    reg = _registry(lambda m: ["h"], {"h": handle})
    deliveries, state_ops = transform_one(reg, "h", ADT_A01)
    assert [d.to for d in deliveries] == ["out"]
    assert isinstance(deliveries[0], DeliveryPreview) and "FOUNDRY" in deliveries[0].payload
    assert state_ops == []  # no SetState declared (ADR 0005)


def test_transform_one_filtering_handler_returns_no_deliveries() -> None:
    reg = _registry(lambda m: ["h"], {"h": lambda m: None})
    assert transform_one(reg, "h", ADT_A01) == ([], [])


def test_transform_one_unknown_outbound_raises() -> None:
    # The transform-stage fail-closed: a handler sending to an unregistered outbound raises here.
    reg = _registry(lambda m: ["h"], {"h": lambda m: Send("ghost_out", m)})
    with pytest.raises(ValueError, match="unknown outbound connection 'ghost_out'"):
        transform_one(reg, "h", ADT_A01)


def test_transform_one_handlers_get_independent_message() -> None:
    # Each handler must parse its OWN Message from raw — one handler's transform can't leak into
    # another's. h1 rewrites MSH-3 to MUTATED; h2 returns its (fresh) message untouched, which must
    # therefore NOT carry h1's mutation.
    def h1(msg: Message) -> Send:
        msg["MSH-3"] = "MUTATED"
        return Send("out", msg)

    def h2(msg: Message) -> Send:
        return Send("out", msg)  # fresh parse — must not see h1's mutation

    reg = _registry(lambda m: ["h1", "h2"], {"h1": h1, "h2": h2})
    outcome = route_message(reg, reg.inbound["in"], ADT_A01)
    assert outcome.handlers == ["h1", "h2"]
    assert "MUTATED" in outcome.deliveries[0].payload  # h1's own copy was mutated
    assert "MUTATED" not in outcome.deliveries[1].payload  # h2's copy is isolated from h1's


def test_route_message_recomposes_identically() -> None:
    # route_message must equal the manual route_only + per-handler transform_one composition
    # (value-equal RouteOutcome) — the contract that keeps dry-run and the live split path identical.
    def h1(msg: Message) -> Send:
        msg["MSH-3"] = "X1"
        return Send("out", msg)

    def h2(msg: Message) -> Send:
        msg["MSH-3"] = "X2"
        return Send("out", msg)

    reg = _registry(lambda m: ["h1", "h2"], {"h1": h1, "h2": h2})
    ic = reg.inbound["in"]
    combined = route_message(reg, ic, ADT_A01)
    names = route_only(reg, ic, ADT_A01)
    manual_deliveries = [d for hname in names for d in transform_one(reg, hname, ADT_A01)[0]]
    assert combined.handlers == names
    assert [(d.to, d.payload) for d in combined.deliveries] == [
        (d.to, d.payload) for d in manual_deliveries
    ]


def test_split_messages_separator_agnostic() -> None:
    # A batch whose MSH-1 isn't `|` must still split per-message (low-4), not parse as one.
    batch = (
        "MSH^~|\\&^A^B^C^D^20260101^^ADT~A01^M1^P^2.5.1\r"
        "MSH^~|\\&^A^B^C^D^20260101^^ADT~A02^M2^P^2.5.1\r"
    ).encode("utf-8")
    msgs = split_messages(batch)
    assert len(msgs) == 2
    assert msgs[0].startswith("MSH^~|\\&^A^B^C^D^20260101^^ADT~A01")
    assert msgs[1].startswith("MSH^~|\\&^A^B^C^D^20260101^^ADT~A02")


def test_split_messages_pipe_batch_and_single() -> None:
    two = (ADT_A01 + ADT_A01.replace("MSG1", "MSG2")).encode("utf-8")
    assert len(split_messages(two)) == 2
    assert len(split_messages(ADT_A01.encode("utf-8"))) == 1


def test_select_inbound_requires_name_when_ambiguous() -> None:
    reg = _registry(lambda m: ["h"], {"h": lambda m: Send("out", m)})
    reg.add_inbound(
        InboundConnection("in2", ConnectionSpec(ConnectorType.MLLP, {"port": 2576}), router="r")
    )
    with pytest.raises(ValueError):
        select_inbound(reg)
    assert select_inbound(reg, "in2").name == "in2"
