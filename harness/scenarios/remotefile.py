# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Remote-file (SFTP) scenarios against ``harness/config/remotefile/``: upload into the share's
``/inbox`` the engine polls, and observe the file its outbound writes to the share's ``/outbox``.

The share is up for the whole of every run, because the engine's inbound polls it and its outbound
writes to it: a scenario hosts it through the remotefile sink even when, like ``remotefile_poll_in``, it
asserts nothing about the outbound and so claims only the inbound kind.

``remotefile_write_out`` goes further than the generic sink check: every file the outbound wrote must
equal the uploaded payload BYTE FOR BYTE (the graph forwards each message unchanged) and must sit
directly in ``/outbox``, not below or outside it.

These scenarios need the graph served on its own (``graph = "remotefile"``), the ``[sftp]`` extra, and
``MEFOR_VALUE_REMOTEFILE_HARNESS_PASSWORD`` set for both the engine and the harness. A missing extra or
password is a SETUP error from the CLI (exit 2), never a pass.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import ClassVar

from harness import sinks
from harness.scenarios._core import (
    Scenario,
    ScenarioContext,
    ScenarioResult,
    _verify_sink,
    control_id_of,
)


@dataclass(frozen=True)
class RemoteFileScenario(Scenario):
    """A :class:`Scenario` driven through the remotefile driver, with the share hosted at ``share``
    for the whole run. With ``sink`` set, what the outbound wrote is also checked byte for byte."""

    graph: ClassVar[str] = "remotefile"

    driver: str = "remotefile"
    inbound: str = "remotefile_sftp"
    share: str = "remotefile_sftp"

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.inbound != self.share:
            raise ValueError(
                f"scenario {self.name!r}: the driver uploads into the share, so inbound must be "
                f"{self.share!r}, not {self.inbound!r}"
            )
        if self.sink not in (None, "remotefile") or self.sink_endpoint not in (None, self.share):
            raise ValueError(
                f"scenario {self.name!r}: the remotefile sink IS the share, so it must be "
                f"sink='remotefile' at sink_endpoint={self.share!r}"
            )

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        payloads, control_ids = self.payloads()
        with sinks.build("remotefile", ctx.endpoints, self.share) as share:
            result = self._inject_and_verify(ctx, payloads, control_ids)
            if not result.ok:
                if "not found within" in result.detail:
                    # Nothing arrived. The share's side of that is in its docstring; the engine's
                    # side is usually one of these.
                    hint = (
                        f"; check the engine serves harness/config/{self.graph} with the same "
                        "password and known_hosts path (harness/sinks/_sftp_server.py)"
                    )
                    return ScenarioResult(self, False, result.detail + hint)
                return result
            if self.sink is None:
                return result
            result = _verify_sink(self, share, control_ids, ctx.timeout, result.detail)
            if not result.ok:
                return result
            return verify_written(
                self, share.records(), dict(zip(control_ids, payloads, strict=True)), result.detail
            )


def verify_written(
    scenario: Scenario,
    records: list[sinks.Record],
    sent: Mapping[str, bytes],
    prior: str,
) -> ScenarioResult:
    """Every file written for a sent control id equals what was sent, byte for byte, and was
    published directly inside the outbox."""
    problems: list[str] = []
    for record in records:
        cid = control_id_of(record.payload)
        if cid is None or cid not in sent:
            continue
        where = record.meta.get("relpath", "?")
        if record.meta.get("inside") != "true" or "/" in where:
            problems.append(f"{cid} written outside the outbox top level ({where})")
        elif record.payload != sent[cid]:
            problems.append(
                f"{cid} differs from the upload ({len(record.payload)} vs {len(sent[cid])} bytes)"
            )
    if problems:
        return ScenarioResult(scenario, False, f"{prior}; {problems[0]}")
    return ScenarioResult(scenario, True, f"{prior}; bytes match and stay inside the outbox")


SCENARIOS = (
    RemoteFileScenario(
        "remotefile_poll_in",
        "ADT^A04 uploaded over SFTP into the share's /inbox -> polled -> PROCESSED",
        "ADT",
        "A04",
        3,
        "processed",
    ),
    RemoteFileScenario(
        "remotefile_write_out",
        "ADT^A05 polled from /inbox -> written by the SFTP outbound to /outbox, bytes unchanged",
        "ADT",
        "A05",
        3,
        "processed",
        sink="remotefile",
        sink_endpoint="remotefile_sftp",
    ),
)
