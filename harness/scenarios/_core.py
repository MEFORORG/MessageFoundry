# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Scenario types, the runner, and the API verifiers every scenario family shares.

A scenario injects traffic through a DRIVER (``harness/drivers/``), then asserts what the engine
did: the disposition the API reports for each control id it sent, or that those messages were
dead-lettered for a named outbound -- and, when it names a SINK (``harness/sinks/``), what the
outbound actually delivered, byte for byte.

Each scenario declares the (connector kind, direction) pairs it covers. ``python -m harness
--coverage`` joins those declarations against the engine's live connector registries. A scenario
claims an INBOUND kind by injecting through it and an OUTBOUND kind only by asserting on what a
sink of that kind received; a disposition alone does not say what left the engine.

Qt-free: plain sockets, threads and the synchronous :class:`~messagefoundry.apiclient.EngineClient`.
"""

from __future__ import annotations

import abc
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from uuid import uuid4

from harness import drivers, sinks
from harness.endpoints import Endpoints
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.generators import (
    _core,
    all_types,  # noqa: F401  (registers the built-in message types)
)
from messagefoundry.parsing import HL7PeekError, Peek
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import PEEK_READ_FAULTS

INBOUND = "inbound"
OUTBOUND = "outbound"
DIRECTIONS = (INBOUND, OUTBOUND)

#: A (connector kind, direction) pair, the kind spelled as the engine's registry spells it.
Coverage = tuple[str, str]

_TERMINAL = {"processed", "unrouted", "filtered", "error"}


@dataclass(frozen=True)
class ScenarioContext:
    """What a scenario run is given: the engine API, where things are, and how long to wait."""

    client: EngineClient
    endpoints: Endpoints = field(default_factory=Endpoints)
    timeout: float = 30.0


@dataclass(frozen=True)
class ScenarioResult:
    """``skipped`` marks a run whose precondition is missing here (a family that needs an external
    server, say). A skipped result is never ``ok``: it is reported as SKIPPED, not as a pass."""

    scenario: BaseScenario
    ok: bool
    detail: str
    skipped: bool = False

    def __post_init__(self) -> None:
        if self.skipped and self.ok:
            raise ValueError("a skipped scenario result cannot also be ok")


class BaseScenario(abc.ABC):
    """What the registry, the CLI and the coverage report need from any scenario."""

    name: str
    description: str

    @property
    @abc.abstractmethod
    def covers(self) -> frozenset[Coverage]:
        """The (kind, direction) pairs this scenario exercises."""

    @abc.abstractmethod
    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        """Run end to end and report pass or fail with a one-line detail."""

    def unavailable(self) -> str | None:
        """Why this scenario cannot run in this install (an optional extra it needs is missing), or
        None. A test reports that as a skip; :meth:`run` still fails rather than passing."""
        return None


@dataclass(frozen=True)
class Scenario(BaseScenario):
    """Generate ``count`` messages of ``code^trigger``, inject them through the ``driver`` kind at
    the ``inbound`` endpoint, and expect each to reach ``expect`` -- one of the dispositions
    ``processed`` / ``unrouted`` / ``filtered`` / ``error``, or ``dead_letter`` for
    ``dead_letter_destination``. With ``sink`` set, a sink of that kind listens at
    ``sink_endpoint`` for the whole run and every control id sent must arrive there."""

    name: str
    description: str
    code: str
    trigger: str
    count: int = 5
    expect: str = "processed"  # processed | unrouted | filtered | error | dead_letter
    driver: str = "mllp"
    inbound: str = "mllp_in"
    dead_letter_destination: str | None = None  # required when expect == "dead_letter"
    sink: str | None = None
    sink_endpoint: str | None = None

    def __post_init__(self) -> None:
        if self.count < 1:
            raise ValueError(f"scenario {self.name!r} must send at least one message")
        if self.expect == "dead_letter" and not self.dead_letter_destination:
            raise ValueError(f"scenario {self.name!r} expects dead_letter but names no destination")
        if (self.sink is None) != (self.sink_endpoint is None):
            raise ValueError(f"scenario {self.name!r} must set sink and sink_endpoint together")

    @property
    def covers(self) -> frozenset[Coverage]:
        pairs = {(self.driver, INBOUND)}
        if self.sink is not None:
            pairs.add((self.sink, OUTBOUND))
        return frozenset(pairs)

    def payloads(self) -> tuple[list[bytes], list[str]]:
        """Fresh payloads and their control ids. The corpus is deterministic; only the control ids
        are fresh, so a run can never match rows a previous run left in a long-lived store."""
        payloads: list[bytes] = []
        control_ids: list[str] = []
        for i in range(1, self.count + 1):
            message = Message.parse(_core.generate_message(self.code, self.trigger, i))
            control_id = uuid4().hex[:20]
            message.set("MSH-10", control_id)
            payloads.append(str(message).encode("utf-8"))
            control_ids.append(control_id)
        return payloads, control_ids

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        payloads, control_ids = self.payloads()
        if self.sink is None:
            return self._inject_and_verify(ctx, payloads, control_ids)
        assert self.sink_endpoint is not None
        with sinks.build(self.sink, ctx.endpoints, self.sink_endpoint) as sink:
            result = self._inject_and_verify(ctx, payloads, control_ids)
            if not result.ok:
                return result
            return _verify_sink(self, sink, control_ids, ctx.timeout, result.detail)

    def _inject_and_verify(
        self, ctx: ScenarioContext, payloads: list[bytes], control_ids: list[str]
    ) -> ScenarioResult:
        driver = drivers.build(self.driver, ctx.endpoints, self.inbound)
        send_errors = [i.error for i in driver.inject(payloads) if i.error]
        if len(send_errors) == self.count:
            target = ctx.endpoints.value(self.inbound)
            return ScenarioResult(
                self,
                False,
                f"could not send to {self.driver} endpoint {self.inbound!r} ({target}): "
                f"{send_errors[0]}",
            )
        if self.expect == "dead_letter":
            return _verify_dead_letter(self, ctx.client, control_ids, ctx.timeout, send_errors)
        return _verify_disposition(self, ctx.client, control_ids, ctx.timeout, send_errors)


def run_scenario(
    scenario: BaseScenario,
    client: EngineClient,
    *,
    timeout: float = 30.0,
    endpoints: Endpoints | None = None,
) -> ScenarioResult:
    """Run one scenario end to end against the engine ``client`` talks to."""
    ctx = ScenarioContext(client, endpoints if endpoints is not None else Endpoints(), timeout)
    return scenario.run(ctx)


def control_id_of(payload: bytes) -> str | None:
    """MSH-10 of an HL7 payload, or None when it does not parse as HL7."""
    try:
        return Peek.parse(payload.decode("utf-8", errors="replace")).control_id or None
    except HL7PeekError:
        return None
    except PEEK_READ_FAULTS:
        return None


def _send_error_suffix(send_errors: Sequence[str]) -> str:
    return f"; {len(send_errors)} send error(s): {send_errors[0]}" if send_errors else ""


def _verify_disposition(
    scenario: Scenario,
    client: EngineClient,
    control_ids: list[str],
    timeout: float,
    send_errors: list[str],
) -> ScenarioResult:
    # Query per control_id (not a newest-500 page): under concurrent traffic this run's messages can
    # be pushed past the page boundary, false-FAILing the scenario (review low-23).
    by_id: dict[str, str] = {}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            by_id = {}
            for cid in control_ids:
                listing = client.list_messages(control_id=cid, limit=1)
                if listing.messages:
                    by_id[cid] = listing.messages[0].status
        except ApiError as exc:
            return ScenarioResult(scenario, False, f"API error: {exc}")
        if len(by_id) == len(control_ids) and all(s in _TERMINAL for s in by_id.values()):
            break
        time.sleep(0.2)

    matched = sum(1 for cid in control_ids if by_id.get(cid) == scenario.expect)
    ok = matched == scenario.count
    detail = f"{matched}/{scenario.count} reached {scenario.expect!r}" + _send_error_suffix(
        send_errors
    )
    if not ok:
        missing = len(set(control_ids) - set(by_id))
        if missing:
            detail += f"; {missing} not found within {timeout:g}s"
        seen = sorted(set(by_id.values()))
        if seen:
            detail += f"; statuses seen: {seen}"
    return ScenarioResult(scenario, ok, detail)


def _verify_dead_letter(
    scenario: Scenario,
    client: EngineClient,
    control_ids: list[str],
    timeout: float,
    send_errors: list[str],
) -> ScenarioResult:
    # Match THIS run's control_ids, not a raw total: `total >= count` false-PASSes immediately against
    # a long-lived DB that already holds dead letters for the destination (review M-32).
    wanted = set(control_ids)
    matched: set[str] = set()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            dead = client.list_dead_letters(
                destination_name=scenario.dead_letter_destination, limit=500
            )
        except ApiError as exc:
            return ScenarioResult(scenario, False, f"API error: {exc}")
        matched = {d.control_id for d in dead.dead_letters if d.control_id in wanted}
        if len(matched) >= scenario.count:
            break
        time.sleep(0.5)
    ok = len(matched) >= scenario.count
    detail = (
        f"{len(matched)}/{scenario.count} of this run's messages dead-lettered for "
        f"{scenario.dead_letter_destination}" + _send_error_suffix(send_errors)
    )
    return ScenarioResult(scenario, ok, detail)


def _verify_sink(
    scenario: Scenario,
    sink: sinks.Sink,
    control_ids: Iterable[str],
    timeout: float,
    prior: str,
) -> ScenarioResult:
    """Every control id sent must have been delivered to the sink. The disposition said the engine
    delivered; this says the delivery reached the peer and still carries the same control id."""
    wanted = set(control_ids)

    def arrived(records: list[sinks.Record]) -> set[str]:
        return {cid for r in records if (cid := control_id_of(r.payload)) in wanted}

    records = sink.wait_for(lambda rs: arrived(rs) >= wanted, timeout)
    got = arrived(records)
    detail = f"{prior}; {len(got)}/{len(wanted)} delivered to the {scenario.sink} sink"
    return ScenarioResult(scenario, got >= wanted, detail)
