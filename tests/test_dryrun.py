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
from messagefoundry.parsing.split import split_batch_bytes
from messagefoundry.pipeline.dryrun import (
    AmbiguousInboundError,
    DeliveryPreview,
    NoInboundError,
    UnknownInboundError,
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


def _registry(route, handlers, *, strict: bool = False) -> Registry:
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


@pytest.mark.parametrize(
    ("code", "named"),
    [(0, " with code 0"), (3, " with code 3"), (None, ""), ("bad MRN 12345", "")],
    ids=["zero", "three", "none", "text"],
)
@pytest.mark.parametrize("where", ["router", "handler"])
def test_sys_exit_in_user_code_is_an_error_not_an_exit(
    where: str, code: object, named: str
) -> None:
    """``SystemExit`` is not an ``Exception``, so a Router or Handler calling ``sys.exit()`` left
    ``dry_run`` and ended ``messagefoundry check`` with the script's own code, 0 included, which reads
    as a pass. It is an ERROR naming only an integer exit code: ``sys.exit("...")`` carries the
    author's text, which could quote a field."""

    def exits(msg: Message) -> Any:
        raise SystemExit(code)

    if where == "router":
        registry = _registry(exits, {})
    else:
        registry = _registry(lambda m: ["h"], {"h": exits})

    result = dry_run(registry, ADT_A01)

    assert result.disposition is MessageStatus.ERROR
    assert result.error == (
        f"router/handler error: Router or Handler code raised SystemExit{named} "
        "(sys.exit() at run time)"
    )


@pytest.mark.parametrize("where", ["router", "handler"])
def test_a_converted_sys_exit_does_not_chain_the_authors_text(where: str) -> None:
    """``raise ... from None`` still leaves the caught exit on ``__context__``, and with it the text
    ``sys.exit("...")`` carried; the conversion must chain nothing a traceback printer could read."""
    from messagefoundry.pipeline.dryrun import UserCodeCalledSysExit

    def exits(msg: Message) -> Any:
        raise SystemExit("bad MRN 12345")

    registry = (
        _registry(exits, {}) if where == "router" else _registry(lambda m: ["h"], {"h": exits})
    )

    with pytest.raises(UserCodeCalledSysExit) as caught:
        route_message(registry, registry.inbound["in"], ADT_A01)

    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert "12345" not in str(caught.value)


def test_keyboard_interrupt_in_user_code_still_stops_the_dry_run() -> None:
    """An interrupt is the operator's, not a fault in the message, so it is not converted."""

    def interrupted(msg: Message) -> list[str]:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        dry_run(_registry(interrupted, {}), ADT_A01)


def test_strict_validation_error() -> None:
    bad = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|N1|P|2.5.1\rEVN|A01|20260101\r"  # no PID
    result = dry_run(_registry(lambda m: ["h"], {"h": lambda m: Send("out", m)}, strict=True), bad)
    assert result.disposition is MessageStatus.ERROR
    assert result.error
    # On time, the validator's verdict is the run's error itself (BACKLOG #5107).
    assert result.strict_refusal == result.error and result.strict_timed_out is False


def test_strict_validation_timing_starts_after_the_warm_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #5107: a verdict must not count the cold hl7apy import, the choice-group probe or
    the reference load. The warm-up is made to "take" 10 000 s on a fake clock and the validate
    none, so the run is a timeout only if the clock starts before the warm-up. No wall clock."""
    import time
    from types import SimpleNamespace

    from messagefoundry.parsing.validate import ValidationResult
    from messagefoundry.pipeline import dryrun

    now = [0.0]
    warmed: list[str] = []

    def cold_warm_up(text: str) -> None:
        warmed.append("warm")
        now[0] += 10_000.0

    def fast_validate(*args: Any, **kwargs: Any) -> ValidationResult:
        warmed.append("validate")
        return ValidationResult(True, "2.5.1", [])

    monkeypatch.setattr(dryrun, "time", SimpleNamespace(time=time.time, monotonic=lambda: now[0]))
    monkeypatch.setattr(dryrun, "warm_validation", cold_warm_up)
    monkeypatch.setattr(dryrun, "validate", fast_validate)

    result = dry_run(
        _registry(lambda m: ["h"], {"h": lambda m: Send("out", m)}, strict=True), ADT_A01
    )

    assert warmed == ["warm", "validate"], "the warm-up must run, and before the validate"
    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert result.strict_timed_out is False


@pytest.mark.parametrize(
    ("outcome", "late"),
    [("refuse", "missing PV1"), ("pass", None), ("raise", None)],
)
def test_strict_timeout_keeps_a_late_content_refusal(
    monkeypatch: pytest.MonkeyPatch, outcome: str, late: str | None
) -> None:
    """BACKLOG #5107: past the timeout ``error`` is the listener's timeout text whatever the
    validate did, and ``strict_refusal`` keeps only a content refusal it returned. Fake clock:
    every read advances 31 s past the timeout."""
    import itertools
    import time
    from types import SimpleNamespace

    from messagefoundry.parsing.validate import ValidationResult
    from messagefoundry.pipeline import dryrun

    def slow_validate(*args: Any, **kwargs: Any) -> ValidationResult:
        if outcome == "raise":
            raise RuntimeError("validator fault")
        return ValidationResult(outcome == "pass", "2.5.1", [late] if late else [])

    ticks = itertools.count()
    monkeypatch.setattr(
        dryrun, "time", SimpleNamespace(time=time.time, monotonic=lambda: next(ticks) * 31.0)
    )
    monkeypatch.setattr(dryrun, "warm_validation", lambda text: None)
    monkeypatch.setattr(dryrun, "validate", slow_validate)

    result = dry_run(
        _registry(lambda m: ["h"], {"h": lambda m: Send("out", m)}, strict=True), ADT_A01
    )

    assert result.disposition is MessageStatus.ERROR
    assert result.strict_timed_out is True
    assert result.error is not None and result.error.startswith("strict-validation timed out")
    assert result.strict_refusal == late


def test_warm_validation_fills_what_a_first_validate_loads_lazily() -> None:
    """The warm-up leaves the probe and the structure's reference table cached, so the timed
    validate after it loads neither. Cleared first, so a cache another test filled proves nothing."""
    import importlib

    # By module path: the package re-exports the function under the module's own name.
    validate_module = importlib.import_module("messagefoundry.parsing.validate")

    validate_module._choice_fix_needed.cache_clear()
    validate_module._references.cache_clear()

    validate_module.warm_validation(ADT_A01)

    assert validate_module._choice_fix_needed.cache_info().currsize == 1
    expected = 1 if validate_module._choice_fix_needed() else 0
    assert validate_module._references.cache_info().currsize == expected


@pytest.mark.parametrize("lead", ["", " \n", "\r\n\t"])
def test_warm_validation_parses_the_msh_segment_only(
    monkeypatch: pytest.MonkeyPatch, lead: str
) -> None:
    """The warm-up's parse does not grow with the body: it is handed the MSH segment alone, after
    leading whitespace as hl7apy strips it, and that segment still fills the reference table."""
    import importlib

    validate_module = importlib.import_module("messagefoundry.parsing.validate")
    parsed: list[str] = []
    real = validate_module._tolerant_parse

    def recording(norm: str) -> Any:
        parsed.append(norm)
        return real(norm)

    monkeypatch.setattr(validate_module, "_tolerant_parse", recording)
    validate_module._references.cache_clear()

    validate_module.warm_validation(lead + ADT_A01 + "NTE|1\r" * 50)

    assert len(parsed) == 1
    assert parsed[0].startswith("MSH|") and "\r" not in parsed[0], parsed[0][:40]
    expected = 1 if validate_module._choice_fix_needed() else 0
    assert validate_module._references.cache_info().currsize == expected


def test_warm_validation_never_raises_on_a_body_it_cannot_parse() -> None:
    from messagefoundry.parsing.validate import warm_validation

    warm_validation("not an HL7 message")
    warm_validation("")


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


@pytest.mark.parametrize("marks", [1, 2], ids=["one-mark", "two-marks"])
@pytest.mark.parametrize("brk", [b"\r", b"\n", b"\r\n"], ids=["cr", "lf", "crlf"])
def test_split_messages_splits_where_byte_order_marks_lead_a_later_msh(
    marks: int, brk: bytes
) -> None:
    """BACKLOG #5918 step 1: the live File source decodes, then splits past marks between a line
    break and a later MSH. The dry run's latin-1 view spelled each mark as three characters, so it
    read such a file as one message. Mutation: drop the ``view.replace(_LATIN1_BOM, _BOM)``
    spelling. Red: one message."""
    first = ADT_A01.encode("utf-8").rstrip(b"\r")
    second = ADT_A01.replace("MSG1", "MSG2").encode("utf-8")
    raw = first + brk + b"\xef\xbb\xbf" * marks + second
    live = split_batch_bytes(raw, "utf-8")
    assert len(live) == 2
    assert split_messages(raw) == live


@pytest.mark.parametrize(
    "lead",
    [b"\xef\xbb\xbf\r\n\xef\xbb\xbf", b"\xef\xbb\xbf\xef\xbb\xbf", b"\r\n\xef\xbb\xbf\xef\xbb\xbf"],
    ids=["mark-break-mark", "two-marks", "break-two-marks"],
)
@pytest.mark.parametrize("count", [1, 2], ids=["one-message", "two-messages"])
def test_split_messages_reads_a_leading_run_of_marks_as_the_live_split(
    lead: bytes, count: int
) -> None:
    """Round-one review of BACKLOG #5918: the dry run stripped one leading mark before its view, so
    a second mark, or a mark after a leading line break, stayed three characters and the first
    member was refused where the live UTF-8 split reads past it. Mutation: strip one leading mark
    and spell only marks after a line break. Red: a member led by the mark's bytes."""
    body = ADT_A01 + ADT_A01.replace("MSG1", "MSG2") if count == 2 else ADT_A01
    raw = lead + body.encode("utf-8")
    assert split_messages(raw) == split_batch_bytes(raw, "utf-8")


@pytest.mark.parametrize(
    "noise",
    [b"", b"\xc2\xa0", b"\xc2\x85", b"\xe2\x80\x83", b"\x1c", b"\x0b", b"\xef\xbb\xbf"],
    ids=["none", "nbsp", "nel", "em-space", "fs", "vt", "mark"],
)
@pytest.mark.parametrize("count", [1, 2], ids=["one-message", "two-messages"])
def test_split_messages_drops_a_trailer_as_the_live_split(noise: bytes, count: int) -> None:
    """BACKLOG #5806: the dry run's latin-1 view drops the trailer lines the live UTF-8 split drops,
    and keeps the lines it keeps, a line of non-ASCII or other noise among them included."""
    body = ADT_A01 + ADT_A01.replace("MSG1", "MSG2") if count == 2 else ADT_A01
    raw = body.encode("utf-8") + b"BTS|1\r" + noise + b"\rFTS|1\r"
    assert split_messages(raw) == split_batch_bytes(raw, "utf-8")


def test_split_messages_reads_a_non_ascii_field_separator_as_the_live_split() -> None:
    """A field separator outside ASCII is one character to the live UTF-8 split and its first byte
    to the dry run's latin-1 view, so neither drops a trailer under one. Mutation: drop the ASCII
    test in ``_trailer_start``. Red: the dry run drops the ``BTS`` line the live split keeps."""
    raw = "MSHé^~\\&éA\rPIDé1\rBTSè1\r".encode()
    assert split_batch_bytes(raw, "utf-8") == [raw]
    assert split_messages(raw) == [raw]


def test_split_messages_keeps_a_mark_that_leads_no_msh() -> None:
    """Control: marks after a line break that no MSH follows are data, kept byte for byte."""
    raw = ADT_A01.encode("utf-8") + b"NTE|1||\xef\xbb\xbfnote\r\xef\xbb\xbfNTE|2\r"
    assert split_messages(raw) == [raw]


def test_select_inbound_requires_name_when_ambiguous() -> None:
    reg = _registry(lambda m: ["h"], {"h": lambda m: Send("out", m)})
    reg.add_inbound(
        InboundConnection("in2", ConnectionSpec(ConnectorType.MLLP, {"port": 2576}), router="r")
    )
    with pytest.raises(AmbiguousInboundError, match="choose one: in, in2"):
        select_inbound(reg)
    assert select_inbound(reg, "in2").name == "in2"


def test_select_inbound_names_its_three_failures_apart() -> None:
    """BACKLOG #1707: a caller must be able to tell an open choice from a defect.

    Each is still a ``ValueError``, which is what ``dryrun`` and ``dryrun --trace`` catch.
    """
    reg = _registry(lambda m: ["h"], {"h": lambda m: Send("out", m)})
    with pytest.raises(UnknownInboundError) as unknown:
        select_inbound(reg, "IB_TYPO")
    assert "'IB_TYPO'" in str(unknown.value) and "the config has: in" in str(unknown.value)

    # Zero inbounds, with and without a name. The wording is pinned because the old text printed
    # "multiple inbound connections; choose one:" over an empty list.
    for name in (None, "in"):
        with pytest.raises(NoInboundError) as empty:
            select_inbound(Registry(), name)
        assert "no inbound connection" in str(empty.value)
        assert "multiple" not in str(empty.value)

    for exc_type in (AmbiguousInboundError, UnknownInboundError, NoInboundError):
        assert issubclass(exc_type, ValueError), exc_type


def test_select_inbound_caps_the_names_it_lists() -> None:
    """A large config must not turn one selection error into a wall of names.

    Both errors list the config's inbounds, and at scale that list would bury the one name that
    matters. Twenty are shown and the rest are counted.
    """
    reg = Registry()
    for i in range(25):
        spec = ConnectionSpec(ConnectorType.MLLP, {"port": 3000 + i})
        reg.add_inbound(InboundConnection(f"IB_{i:02d}", spec, router="r"))
    with pytest.raises(UnknownInboundError) as unknown:
        select_inbound(reg, "IB_TYPO")
    with pytest.raises(AmbiguousInboundError) as ambiguous:
        select_inbound(reg)
    for text in (str(unknown.value), str(ambiguous.value)):
        assert "IB_19 (+5 more)" in text, text  # the 20th name, then the count
        assert "IB_20" not in text, text


# --- parse-once on the per-message fan-out (hotpath) --------------------------


def _raw_registry(route, handlers, *, content_type: ContentType):
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
    samples: dict[type, Send | SetState | SetMeta] = {
        Send: Send("OB_A", "x"),
        SetState: SetState("ns", "k", 1),
        SetMeta: SetMeta("mk", "mv"),
    }
    assert set(samples) == set(HANDLER_ITEM_TYPES), (
        "a new admissible item type needs a bucket below"
    )
    for kind, sample in samples.items():
        assert handler_item_fault(sample) is None
        buckets = _partition([sample], "h")
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


# --- BACKLOG #6819: the shared payload is build_payload's, not a copy of its branch -------------


def test_shareable_payload_delegates_to_build_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """The non-HL7 shared payload is built by ``build_payload``, the one definition the sandbox
    child also uses, so the fan-out's shared object cannot drift from the per-consumer one
    (BACKLOG #6819). It used to repeat that branch inline."""
    from messagefoundry.pipeline import dryrun

    built = RawMessage("{}", "json")
    calls: list[tuple[str | bytes, str]] = []

    def spy(raw: str | bytes, content_type: str) -> Message | RawMessage:
        calls.append((raw, content_type))
        return built

    monkeypatch.setattr(dryrun, "build_payload", spy)
    assert dryrun._shareable_payload(b"{}", "json") is built
    assert calls == [(b"{}", "json")]
    assert dryrun._shareable_payload(ADT_A01, ContentType.HL7V2.value) is None
    assert len(calls) == 1  # HL7 is never shared, so never built here


# --- BACKLOG #6819: a bytes body reaches the public entry points in the listener's form ---------

#: Not valid UTF-8 (0xFF never is), and a NUL besides, as a DICOM preamble holds.
_BINARY_NOT_UTF8 = b"\x00" * 8 + b"DICM\xff\xfe\x80"
#: Valid UTF-8, so a text decode "succeeds" and hands the Handler an uncarried body.
_BINARY_UTF8 = b"DICM-plain"


def _bytes_registry(seen: list[Any], *, content_type: ContentType, encoding: str | None = None):
    """A non-HL7 inbound whose Router and Handler record what they were handed."""

    def route(msg: RawMessage) -> list[str]:
        seen.append(("router", msg))
        return ["h"]

    def handle(msg: RawMessage) -> Send:
        seen.append(("handler", msg))
        return Send("out", msg.raw)

    reg = _raw_registry(route, {"h": handle}, content_type=content_type)
    if encoding is not None:
        reg.inbound["in"].spec.settings["encoding"] = encoding
    return reg


def _run_entry(entry: str, reg: Registry, raw: bytes) -> None:
    ic = reg.inbound["in"]
    if entry == "route_message":
        route_message(reg, ic, raw)
    elif entry == "route_only":
        route_only(reg, ic, raw)
    else:
        transform_one(reg, "h", raw, ic.content_type.value)


@pytest.mark.parametrize("entry", ["route_message", "route_only", "transform_one"])
@pytest.mark.parametrize("content_type", [ContentType.DICOM, ContentType.BINARY])
@pytest.mark.parametrize("data", [_BINARY_NOT_UTF8, _BINARY_UTF8], ids=["not-utf8", "utf8"])
def test_binary_bytes_are_carried_at_each_public_entry_point(
    entry: str, content_type: ContentType, data: bytes
) -> None:
    """Bytes for a binary inbound reach the Router and Handler base64-carried (ADR 0028), as
    ``_dry_run_raw`` carries them, so ``raw_bytes`` gives the bytes back (BACKLOG #6819). The
    DICOM bodies hold no preamble, so the listener's declared-type sniff would refuse them; the
    entry points do not run it.
    They used to be decoded as UTF-8: a body that is not UTF-8 raised ``UnicodeDecodeError``, and
    one that is reached the Handler uncarried, so ``raw_bytes`` raised ``BinaryCarriageError``."""
    seen: list[Any] = []
    _run_entry(entry, _bytes_registry(seen, content_type=content_type), data)
    assert seen, "no Router or Handler ran"
    for _, msg in seen:
        assert isinstance(msg, RawMessage)
        assert msg.raw_bytes == data


@pytest.mark.parametrize("entry", ["route_message", "route_only"])
def test_text_bytes_decode_with_the_inbound_charset(entry: str) -> None:
    """Bytes for a text inbound are decoded with the charset it declares, as the listener does
    (BACKLOG #6819). A latin-1 body used to be decoded as UTF-8 and raise ``UnicodeDecodeError``."""
    seen: list[Any] = []
    reg = _bytes_registry(seen, content_type=ContentType.JSON, encoding="latin-1")
    _run_entry(entry, reg, '{"n": "café"}'.encode("latin-1"))
    assert seen, "no Router or Handler ran"
    assert [msg.json() for _, msg in seen] == [{"n": "café"}] * len(seen)


@pytest.mark.parametrize("entry", ["route_message", "route_only"])
def test_undecodable_text_bytes_are_a_typed_decode_refusal(entry: str) -> None:
    """Bytes a text inbound's charset refuses are the listener's ``decode``-phase
    :class:`IngressGuardError`, quoting no byte of the body, and no Router or Handler runs
    (BACKLOG #6819). They used to escape as a bare ``UnicodeDecodeError``, whose ``.object`` is the
    whole body."""
    from messagefoundry.pipeline.ingress_guards import IngressGuardError

    seen: list[Any] = []
    with pytest.raises(IngressGuardError) as info:
        _run_entry(entry, _bytes_registry(seen, content_type=ContentType.JSON), b'{"n": "MRN\xff"}')
    assert info.value.phase == "decode"
    assert "MRN" not in info.value.reason
    assert info.value.__cause__ is None and info.value.__context__ is None
    assert seen == []


@pytest.mark.parametrize("data", [b'{"n": "MRN\xff"}', b'{"n": "MRN"}'], ids=["not-utf8", "utf8"])
def test_transform_one_refuses_text_bytes(data: bytes) -> None:
    """``transform_one`` has no inbound to name a text body's charset or run its post-decode
    guards, so bytes for a text type are a ``TypeError``, the caller's fault, quoting no byte of
    the body, and no Handler runs (BACKLOG #6819). It used to decode them as UTF-8, raising a bare
    ``UnicodeDecodeError`` on any other charset."""
    seen: list[Any] = []
    with pytest.raises(TypeError, match="takes a 'json' body as str") as info:
        _run_entry("transform_one", _bytes_registry(seen, content_type=ContentType.JSON), data)
    assert "MRN" not in str(info.value)
    assert info.value.__cause__ is None and info.value.__context__ is None
    assert seen == []


def test_an_undecodable_body_reads_no_reference_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """``route_message`` refuses an undecodable body before it builds the reference view, so the
    refusal costs no reference-file read (BACKLOG #6819)."""
    from messagefoundry.pipeline import dryrun
    from messagefoundry.pipeline.ingress_guards import IngressGuardError

    built: list[object] = []

    def counting(reg: Registry) -> dict[str, Any]:
        built.append(reg)
        return {}

    monkeypatch.setattr(dryrun, "dry_run_reference_view", counting)
    reg = _bytes_registry([], content_type=ContentType.JSON)
    with pytest.raises(IngressGuardError):
        route_message(reg, reg.inbound["in"], b"\xff")
    assert built == []


@pytest.mark.parametrize("entry", ["route_only", "transform_one"])
def test_the_sandbox_child_rebuilds_from_the_carried_body(
    monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    """On the sandboxed branch the child rebuilds the payload from ``origin``, so ``origin``
    holds the carried ``str``, never the bytes ``build_payload`` would decode as UTF-8
    (BACKLOG #6819)."""
    from messagefoundry.pipeline import dryrun
    from messagefoundry.pipeline.sandbox import SandboxMode

    origins: list[Any] = []

    def fake_run(fn: Any, payload: Any, **kw: Any) -> Any:
        origins.append(kw["origin"])
        assert payload.raw_bytes == _BINARY_NOT_UTF8
        return ["h"] if kw["phase"] == "router" else Send("out", payload.raw)

    class _Session:
        mode = SandboxMode.SUBPROCESS

    monkeypatch.setattr(dryrun, "run_sandboxed", fake_run)
    reg = _bytes_registry([], content_type=ContentType.DICOM)
    ic = reg.inbound["in"]
    session: Any = _Session()
    if entry == "route_only":
        route_only(reg, ic, _BINARY_NOT_UTF8, sandbox=session)
    else:
        transform_one(reg, "h", _BINARY_NOT_UTF8, ic.content_type.value, sandbox=session)
    [(raw, ct)] = origins
    assert isinstance(raw, str) and ct == "dicom"
    assert RawMessage(raw, ct).raw_bytes == _BINARY_NOT_UTF8


def test_an_oversize_binary_body_is_the_size_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """A binary body over the engine ceiling is the ``size``-phase refusal at each entry point
    that carries it, as the listener's is (BACKLOG #6819)."""
    from messagefoundry.pipeline import ingress_guards
    from messagefoundry.pipeline.ingress_guards import IngressTooLarge

    monkeypatch.setattr(ingress_guards, "ingress_size_error", lambda size: "too large")
    for entry in ("route_message", "route_only", "transform_one"):
        seen: list[Any] = []
        with pytest.raises(IngressTooLarge):
            _run_entry(entry, _bytes_registry(seen, content_type=ContentType.BINARY), b"\x00")
        assert seen == [], entry


# --- BACKLOG #6821: a fault in a peek read is a recorded ERROR, as on the listener --------------


@pytest.mark.parametrize("fault", [IndexError, KeyError, TypeError, ValueError])
@pytest.mark.parametrize("site", ["summarize", "doc_ref_marker_refusal"])
def test_a_peek_read_fault_is_an_error_result(
    monkeypatch: pytest.MonkeyPatch, fault: type[Exception], site: str
) -> None:
    """A field read on an accepted peek that faults is ``ERROR`` naming the fault's type alone,
    the listener's ``parse error: peek read failed (<type>)`` (BACKLOG #6821, #1594). It used to
    raise straight out of ``dry_run``, since only ``HL7PeekError`` was caught around the parse."""
    from messagefoundry.pipeline import dryrun

    def boom(*_a: object, **_k: object) -> object:
        raise fault("MRN999SECRET")

    monkeypatch.setattr(dryrun, site, boom)
    result = dry_run(_registry(lambda m: ["h"], {"h": lambda m: Send("out", m)}), ADT_A01)
    assert result.disposition is MessageStatus.ERROR
    assert result.error == f"parse error: peek read failed ({fault.__name__})"
    assert result.handlers == [] and result.deliveries == []
