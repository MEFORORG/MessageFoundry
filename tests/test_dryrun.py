# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Dry-run harness: pure routing/handling, no store/connectors/network."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Validation
from messagefoundry.config.wiring import (
    HANDLER_ITEM_TYPES,
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    SetMeta,
    SetState,
    handler_item_fault,
)
from messagefoundry.parsing.message import Message, RawMessage
from messagefoundry.pipeline.dryrun import (
    DeliveryPreview,
    _partition,
    disposition_for,
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
    #
    # BACKLOG #1688: the assertion has to name the ROUTER stage, because ERROR-plus-"ghost" is not
    # unique to it. With `route_only`'s fail-closed deleted, this message reaches `transform_one`,
    # whose `registry.handlers[hname]` raises `KeyError('ghost')` a stage later; `dry_run`'s catch-all
    # renders that as "router/handler error: 'ghost'" — still ERROR, still carrying "ghost". So the
    # weaker pin stayed green with the guard gone and reported only that SOMETHING failed.
    result = dry_run(_registry(lambda m: ["ghost"], {}), ADT_A01)
    assert result.disposition is MessageStatus.ERROR
    assert result.error and "returned unknown handler 'ghost'" in result.error


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
    deliveries, state_ops, meta_ops, declined = transform_one(reg, "h", ADT_A01)
    assert [d.to for d in deliveries] == ["out"]
    assert isinstance(deliveries[0], DeliveryPreview) and "FOUNDRY" in deliveries[0].payload
    assert state_ops == []  # no SetState declared (ADR 0005)
    assert meta_ops == []  # no SetMeta declared (ADR 0081)
    assert declined == []  # every target deployed (#233) — nothing declined


def test_transform_one_filtering_handler_returns_no_deliveries() -> None:
    reg = _registry(lambda m: ["h"], {"h": lambda m: None})
    assert transform_one(reg, "h", ADT_A01) == ([], [], [], [])


def test_transform_one_unknown_outbound_raises() -> None:
    # The transform-stage fail-closed: a handler sending to an unregistered outbound (or pass-through)
    # target raises here (the message names both since a Send.to may now name a PT inbound, ADR 0013).
    reg = _registry(lambda m: ["h"], {"h": lambda m: Send("ghost_out", m)})
    with pytest.raises(ValueError, match="unknown outbound/pass-through connection 'ghost_out'"):
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
        b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A01^M1^P^2.5.1\r"
        b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A02^M2^P^2.5.1\r"
    )
    # Bytes in, bytes out since BACKLOG #1689 — the decode belongs to the inbound, in `dry_run`.
    msgs = split_messages(batch)
    assert len(msgs) == 2
    assert msgs[0].startswith(b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A01")
    assert msgs[1].startswith(b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A02")


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


# --- parse-once on the per-message fan-out (hotpath) --------------------------


def _raw_registry(route, handlers, *, content_type: ContentType):  # type: ignore[no-untyped-def]
    """A non-HL7 inbound: Router/Handlers receive a RawMessage (ADR 0004)."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in",
            ConnectionSpec(ConnectorType.FILE, {}),
            router="r",
            content_type=content_type,
        )
    )
    reg.add_outbound(OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {})))
    reg.add_router("r", route)
    for name, fn in handlers.items():
        reg.add_handler(name, fn)
    return reg


def test_route_message_hl7_parses_once_per_consumer() -> None:
    # HL7 payloads are MUTABLE (Handlers transform in place), so each consumer (router + every handler)
    # must get its OWN parse — never a shared object. Hold a reference to each Message (NOT id(), whose
    # value CPython recycles for ephemeral objects) and assert all three are distinct instances.
    seen: list[Message] = []

    def route(msg: Message) -> list[str]:
        seen.append(msg)
        return ["h1", "h2"]

    def make_handler() -> Any:
        def handle(msg: Message) -> Send:
            seen.append(msg)
            return Send("out", msg)

        return handle

    reg = _registry(route, {"h1": make_handler(), "h2": make_handler()})
    route_message(reg, reg.inbound["in"], ADT_A01)
    assert len(seen) == 3  # router + h1 + h2
    # All THREE are distinct objects — each consumer parsed its own (no shared mutable Message).
    assert seen[0] is not seen[1] and seen[1] is not seen[2] and seen[0] is not seen[2]


def test_route_message_nonhl7_shares_one_rawmessage() -> None:
    # A RawMessage is READ-ONLY, so the parse-once win: build it ONCE and reuse the SAME instance for
    # the router and every handler (instead of re-decoding/re-constructing it N+1 times on a high-fan-out
    # non-HL7 feed). Hold a reference to each object and assert they are all the one same instance.
    seen: list[RawMessage] = []

    def route(msg: RawMessage) -> list[str]:
        seen.append(msg)
        return ["h1", "h2"]

    def make_handler() -> Any:
        def handle(msg: RawMessage) -> Send:
            seen.append(msg)
            return Send("out", msg.raw)

        return handle

    reg = _raw_registry(
        route, {"h1": make_handler(), "h2": make_handler()}, content_type=ContentType.JSON
    )
    outcome = route_message(reg, reg.inbound["in"], '{"a": 1}')
    assert len(seen) == 3  # router + h1 + h2
    assert all(isinstance(m, RawMessage) for m in seen)
    # All THREE are the one shared RawMessage (read-only → safe to reuse across the fan-out).
    assert seen[0] is seen[1] and seen[1] is seen[2]
    assert [d.to for d in outcome.deliveries] == ["out", "out"]  # both handlers still delivered


# --- BACKLOG #1692: DryRunResult.meta_ops ---------------------------------------------------------


def test_dry_run_surfaces_declared_metadata_writes_on_the_hl7_path() -> None:
    """A Handler's ``SetMeta`` reaches ``DryRunResult.meta_ops`` (ADR 0081).

    ``dry_run`` built its result without ``meta_ops=outcome.meta_ops`` from the day ``MetaOpPreview``
    arrived, so the field was empty whatever a Handler declared and a ``SetMeta`` was invisible to the
    CLI and the Test Bench. The ``SetState`` beside it is asserted on the SAME run: without it, an
    outcome that produced nothing at all would satisfy the metadata assertion by being empty too.
    """

    def handle(msg: Message) -> list[Any]:
        return [Send("out", msg), SetState("ns", "sk", "sv"), SetMeta("mk", "mv")]

    result = dry_run(_registry(lambda m: ["h"], {"h": handle}), ADT_A01)
    assert [(s.namespace, s.key, s.value) for s in result.state_ops] == [("ns", "sk", "sv")]
    assert [(m.key, m.value) for m in result.meta_ops] == [("mk", "mv")]


def test_dry_run_surfaces_declared_metadata_writes_on_the_raw_path() -> None:
    """The same, through ``_dry_run_raw`` — the non-HL7 construction is a SECOND call site.

    Both sites omitted ``meta_ops`` and each has to be pinned: fixing one leaves a JSON/X12 feed's
    ``SetMeta`` as invisible as before, with the HL7 test green over it.
    """

    def handle(msg: RawMessage) -> list[Any]:
        return [Send("out", msg.raw), SetState("ns", "sk", "sv"), SetMeta("mk", "mv")]

    reg = _raw_registry(lambda m: ["h"], {"h": handle}, content_type=ContentType.JSON)
    result = dry_run(reg, '{"a": 1}')
    assert [(s.namespace, s.key, s.value) for s in result.state_ops] == [("ns", "sk", "sv")]
    assert [(m.key, m.value) for m in result.meta_ops] == [("mk", "mv")]


def test_transform_one_honors_prebuilt_payload() -> None:
    # The optional pre-parsed `payload` is used as-is instead of parsing `raw`. Pass a payload built
    # from DIFFERENT content than `raw` to prove the payload (not the raw) drove the transform.
    def handle(msg: Message) -> Send:
        return Send("out", msg)

    reg = _registry(lambda m: ["h"], {"h": handle})
    other = Message.parse(ADT_A01.replace("MSG1", "FROMPAYLOAD"))
    deliveries, _, _, _ = transform_one(reg, "h", ADT_A01, payload=other)
    assert "FROMPAYLOAD" in deliveries[0].payload  # the prebuilt payload won, not the raw arg


def test_route_only_honors_prebuilt_payload() -> None:
    # route_only uses the prebuilt payload as-is (no re-parse of raw).
    seen: list[int] = []

    def route(msg: Message) -> list[str]:
        seen.append(id(msg))
        return []

    reg = _registry(route, {})
    prebuilt = Message.parse(ADT_A01)
    assert route_only(reg, reg.inbound["in"], ADT_A01, payload=prebuilt) == []
    assert seen == [id(prebuilt)]  # the router received the exact prebuilt object


# --- a Handler may return ANY non-str iterable of Sends (BACKLOG #341) --------


def _fanout_registry(handle: Any) -> Registry:
    """One inbound → one handler → TWO outbounds, so a fan-out has somewhere to go."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection("OB_A", ConnectionSpec(ConnectorType.FILE, {"directory": "./a"}))
    )
    reg.add_outbound(
        OutboundConnection("OB_B", ConnectionSpec(ConnectorType.FILE, {"directory": "./b"}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", handle)
    return reg


def test_handler_returning_a_tuple_of_sends_delivers_both() -> None:
    """The headline defect (#341). ``_partition`` narrowed with ``isinstance(result, list)``, so a
    returned TUPLE became the single item, matched none of the three isinstance filters, and the
    message finalized FILTERED — delivering nothing and erroring nothing, indistinguishable from a
    handler deliberately declining it. That is the accept-and-drop CLAUDE.md §12 forbids outright."""

    def handle(msg: Message) -> tuple[Send, Send]:
        return (Send("OB_A", msg), Send("OB_B", msg))

    deliveries, _, _, _ = transform_one(_fanout_registry(handle), "h", ADT_A01)
    assert [d.to for d in deliveries] == ["OB_A", "OB_B"]  # both delivered, order preserved


def test_handler_returning_a_set_of_sends_delivers_all() -> None:
    """A ``set`` fans out too. Asserted as a SET: set iteration order is unspecified, so pinning a
    list here would be a flake rather than a contract."""

    def handle(msg: Message) -> set[Send]:
        return {Send("OB_A", msg), Send("OB_B", msg)}

    deliveries, _, _, _ = transform_one(_fanout_registry(handle), "h", ADT_A01)
    assert {d.to for d in deliveries} == {"OB_A", "OB_B"}


def test_handler_returning_a_generator_of_sends_delivers_all() -> None:
    """A generator Handler fans out — the Router half (``_handler_names``) has always accepted one, so
    this closes the internal inconsistency rather than inventing a new contract."""

    def handle(msg: Message) -> Iterator[Send]:
        yield Send("OB_A", msg)
        yield Send("OB_B", msg)

    deliveries, _, _, _ = transform_one(_fanout_registry(handle), "h", ADT_A01)
    assert [d.to for d in deliveries] == ["OB_A", "OB_B"]


@pytest.mark.parametrize("empty", [[], (), set(), None], ids=["list", "tuple", "set", "none"])
def test_empty_container_returns_still_filter(empty: Any) -> None:
    """THE acceptance criterion for #341. ``return []`` and ``return ()`` are the documented filter
    idiom (recognized by the Steps lens, SHALL'd at ADR 0108 §6). Widening must turn neither into a
    delivery NOR into an error: every empty container delivers nothing, raises nothing, and keeps the
    honest FILTERED disposition."""
    reg = _fanout_registry(lambda msg: empty)
    outcome = route_message(reg, reg.inbound["in"], ADT_A01)
    assert outcome.deliveries == []
    assert outcome.routed  # a handler DID run — so this is FILTERED, not UNROUTED
    assert disposition_for(outcome) is MessageStatus.FILTERED


def test_a_mixed_tuple_partitions_exactly_like_the_equivalent_list() -> None:
    """A tuple is partitioned by the SAME rule as a list — ``Send``\\ s, ``SetState``\\ s and
    ``SetMeta``\\ s each land in their own bucket. The outcomes are compared to each other so the test
    cannot drift from ``_partition``'s own definition of the buckets, and the counts are pinned so the
    comparison cannot pass by both sides being empty."""

    def _items(msg: Message) -> list[Any]:
        return [Send("OB_A", msg), SetState("ns", "k", 1), SetMeta("mk", "mv")]

    tup = transform_one(_fanout_registry(lambda m: tuple(_items(m))), "h", ADT_A01)
    lst = transform_one(_fanout_registry(_items), "h", ADT_A01)
    assert tup == lst
    assert (len(tup.deliveries), len(tup.state_ops), len(tup.meta_ops)) == (1, 1, 1)


@pytest.mark.parametrize(
    ("build", "offender"),
    [
        (lambda msg: msg, "Message"),
        (lambda msg: [Send("OB_A", msg), object()], "object"),
    ],
    ids=["bare_return", "stray_element"],
)
def test_an_unrecognised_return_raises_and_names_the_handler(build: Any, offender: str) -> None:
    """BACKLOG #1687, through the ``transform_one`` seam. The slip used to partition to nothing and
    finalize ``FILTERED`` — see
    :func:`~messagefoundry.config.wiring.handler_item_fault` for what that cost.

    Two rows, because the two positions are different code paths: a bare return is the value the
    materialization rule declined to treat as a container, a stray element is one it DID materialize.
    The remaining measured shapes (``msg.encode()``, a ``dict``, a ``(name, message)`` tuple) are
    pinned in ``tests/test_sandbox_codec.py::test_partition_parity_table_rejects``, which asserts them
    against both ``[sandbox]`` modes rather than only this one.

    The handler NAME is asserted, not just the raise: a message that says only "unsupported dict"
    leaves an operator with a dead-lettered message and no way to find the Handler that produced it."""

    def handle(msg: Message) -> Any:
        return build(msg)

    with pytest.raises(ValueError, match=f"handler 'h' returned an unsupported {offender}"):
        transform_one(_fanout_registry(handle), "h", ADT_A01)


def test_an_unrecognised_return_is_an_error_disposition_not_filtered() -> None:
    """The disposition the finding actually measured, at the surface an author sees. ``dry_run``
    reported ``FILTERED`` with ``error`` unset — the shape of a deliberate decline — so ``messagefoundry
    check`` passed a broken feed. Asserting the raise alone would not have caught that: the raise could
    be swallowed anywhere between here and the report and every other test would stay green."""
    result = dry_run(_registry(lambda m: ["h"], {"h": lambda m: m}), ADT_A01)
    assert result.disposition is MessageStatus.ERROR
    assert result.error and "'h'" in result.error and "unsupported" in result.error


def test_every_admissible_item_type_has_a_partition_bucket() -> None:
    """The two halves of the rule cannot drift apart. ``handler_item_fault`` decides what is
    ADMISSIBLE and ``_partition``'s three filters decide where each one GOES, and a type added to the
    first without a filter in the second would be accepted and then dropped from all three lists —
    re-opening the accept-and-drop #1687 closes, silently.

    The table is keyed on ``HANDLER_ITEM_TYPES`` itself rather than listing the types, so widening
    that tuple fails HERE, on the set comparison, with the reason in the assertion."""
    samples: dict[type, object] = {
        Send: Send("OB_A", "x"),
        SetState: SetState("ns", "k", 1),
        SetMeta: SetMeta("mk", "mv"),
    }
    assert set(samples) == set(HANDLER_ITEM_TYPES), (
        "a new admissible item type needs a bucket below"
    )
    for kind, sample in samples.items():
        assert handler_item_fault(sample) is None
        buckets = _partition([sample], "h")  # type: ignore[arg-type]
        assert [len(b) for b in buckets].count(1) == 1, f"{kind.__name__} landed in no bucket"


def test_a_bare_message_return_is_not_iterated_to_reach_that_raise() -> None:
    """The ``isinstance(..., Iterable)`` GATE, pinned apart from the outcome above.

    A :class:`Message` declares ``__getitem__(path: str)`` and no ``__iter__``, so a duck-typed
    ``list(result)`` would drive the legacy sequence protocol with an *int* index and raise
    ``TypeError`` from inside the handler's own frame — naming neither the handler nor what it should
    have returned. The row above would still be "it raises" and would not notice the difference, so
    the exception TYPE and the absence of any ``__getitem__`` traffic are what make the gate
    falsifiable."""
    seen: list[object] = []

    class _Watched(Message):
        def __getitem__(self, path: Any) -> Any:
            seen.append(path)
            return super().__getitem__(path)

    watched = _Watched.parse(ADT_A01)
    reg = _fanout_registry(lambda msg: watched)
    with pytest.raises(ValueError, match="unsupported _Watched"):
        transform_one(reg, "h", ADT_A01)
    assert seen == [], f"the return value was iterated, not classified: {seen}"
