"""Scenario runner: send generated traffic, then assert the engine's resulting disposition (or
dead-lettering) over the API. Pass/fail, scriptable, and **Qt-free** so it runs headless in CI.

A scenario names a message (type + trigger + count), an MLLP inbound to send it to, and the
outcome to expect — one of the dispositions ``processed`` / ``unrouted`` / ``filtered`` / ``error``
(verified by polling ``/messages`` for the control ids it sent), or ``dead_letter`` for a named
outbound (verified by polling ``/dead-letters``). The built-in :data:`SCENARIOS` target the
``harness/config`` graph; serve it first, then ``python -m harness --scenario <name>``.

This module deliberately imports no PySide6 — it uses plain sockets and the synchronous
:class:`~messagefoundry.console.client.EngineClient`, so it works on a headless runner.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.generators import _core
from messagefoundry.generators import all_types  # noqa: F401  (registers the built-in message types)
from messagefoundry.transports.mllp import MLLPDecoder, frame

_TERMINAL = {"processed", "unrouted", "filtered", "error"}


@dataclass(frozen=True)
class Scenario:
    """A self-describing test case: what to send, where, and the engine outcome to expect."""

    name: str
    description: str
    code: str
    trigger: str
    count: int = 5
    expect: str = "processed"  # processed | unrouted | filtered | error | dead_letter
    inbound_host: str = "127.0.0.1"
    inbound_port: int = 2575
    dead_letter_destination: str | None = None  # required when expect == "dead_letter"


@dataclass(frozen=True)
class ScenarioResult:
    scenario: Scenario
    ok: bool
    detail: str


# Presets for the harness/config graph (serve it, then run by name).
SCENARIOS: dict[str, Scenario] = {
    "processed": Scenario(
        "processed", "ADT^A05 archived to a file → PROCESSED", "ADT", "A05", 5, "processed"
    ),
    "filtered": Scenario(
        "filtered", "ADT^A02 dropped by the handler → FILTERED", "ADT", "A02", 5, "filtered"
    ),
    "unrouted": Scenario("unrouted", "ORU routed nowhere → UNROUTED", "ORU", "R01", 5, "unrouted"),
    "error": Scenario("error", "ADT^A03 handler raises → ERROR", "ADT", "A03", 5, "error"),
    "dead_letter": Scenario(
        "dead_letter",
        "ADT^A01 echo to a downed listener → dead-lettered (run with nothing on 2576)",
        "ADT",
        "A01",
        2,
        "dead_letter",
        dead_letter_destination="OB_Coverage_Echo",
    ),
}


def _send_mllp(host: str, port: int, payloads: list[str], *, timeout: float = 10.0) -> list[str]:
    """Send each payload on its own MLLP connection (draining any ACK). Returns one entry per
    message: ``""`` on success, else the error text — so an unreachable inbound is reported, not
    raised."""
    outcomes: list[str] = []
    for payload in payloads:
        try:
            with socket.create_connection((host, port), timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(frame(payload))
                decoder = MLLPDecoder()
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk or any(True for _ in decoder.feed(chunk)):
                            break
                except (TimeoutError, OSError):
                    pass  # NONE-ack inbound or the peer closed — the send itself still happened
            outcomes.append("")
        except OSError as exc:
            outcomes.append(str(exc))
    return outcomes


def run_scenario(
    scenario: Scenario, client: EngineClient, *, timeout: float = 30.0
) -> ScenarioResult:
    """Run one scenario end-to-end: generate + send, then poll the API until the outcome settles."""
    payloads = [
        _core.generate_message(scenario.code, scenario.trigger, i)
        for i in range(1, scenario.count + 1)
    ]
    control_ids = [
        _core.control_id(scenario.code, scenario.trigger, i) for i in range(1, scenario.count + 1)
    ]
    send_errors = [
        e for e in _send_mllp(scenario.inbound_host, scenario.inbound_port, payloads) if e
    ]
    if len(send_errors) == scenario.count:
        return ScenarioResult(
            scenario,
            False,
            f"could not send to {scenario.inbound_host}:{scenario.inbound_port}: {send_errors[0]}",
        )

    if scenario.expect == "dead_letter":
        return _verify_dead_letter(scenario, client, control_ids, timeout, send_errors)
    return _verify_disposition(scenario, client, control_ids, timeout, send_errors)


def _send_error_suffix(send_errors: list[str]) -> str:
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
