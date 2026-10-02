# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DICOM DIMSE scenarios against ``harness/config/dimse.py``: C-STORE into the engine's SCP inbound,
forwarded by its SCU outbound to a harness DIMSE sink.

**How a row is matched to the object that made it.** The engine records a DICOM object with no
control id (there is no MSH-10, and the SCP does not lift the SOPInstanceUID into one), so the
per-control-id lookup the HL7 scenarios use has nothing to look up. Instead a run:

1. snapshots the ids of the inbound's newest rows BEFORE it sends anything;
2. sends objects whose SOPInstanceUIDs are freshly generated;
3. pages through the inbound's rows, newest first, down to the first snapshot row, and reads the
   body of each row it has not read yet through the audited raw-body route (``surface="harness"``,
   so every read leaves a ``message_body_view`` audit row), peeking the SOPInstanceUID out of the
   stored carriage. It stops reading bodies once every sent UID is matched.

A row counts only when its SOPInstanceUID is one this run sent, so concurrent traffic on the same
inbound, or a previous run's rows, can never satisfy a scenario. The snapshot keeps the reads to rows
that arrived after it; another sender's object arriving on this inbound during a run IS read, and
that is accepted because the inbound belongs to the harness's own synthetic graph. Reading bodies
needs the ``messages:view_raw`` permission as well as ``messages:read``.

Every scenario also asserts what reached the sink: each SOPInstanceUID, and how many C-STOREs the
sink saw for it. That count is what tells "retried, then dead-lettered" from "dead-lettered at
once", measured at the peer rather than taken from the engine's own report.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field

from harness import drivers
from harness.drivers.dimse import KIND, dicom_extra_missing, status_of
from harness.scenarios._core import (
    _TERMINAL,
    INBOUND,
    OUTBOUND,
    BaseScenario,
    Coverage,
    ScenarioContext,
    ScenarioResult,
    _send_error_suffix,
)
from harness.scenarios._dimse_dataset import make_datasets, sop_instance_uid
from harness.sinks import LOOPBACK, Record
from harness.sinks.dimse import CANNOT_UNDERSTAND, OUT_OF_RESOURCES, SUCCESS, DimseSink
from messagefoundry.api.models import MessageSummary
from messagefoundry.apiclient import ApiError, EngineClient

#: Connection names in ``harness/config/dimse.py``.
INBOUND_CONNECTION = "IB_Harness_DIMSE"
OUTBOUND_CONNECTION = "OB_Harness_DIMSE"

#: Rows per page when snapshotting and polling the inbound, and the most pages one poll reads.
_PAGE = 200
_MAX_PAGES = 50
_POLL_SECONDS = 0.5
#: Final dispositions that are not a failure; a row in one of these will never dead-letter.
_SETTLED = frozenset({"processed", "filtered", "unrouted"})
#: The least a sink wait gets once the API leg is done. The engine reports a delivery or a dead
#: letter only after the C-STORE answer came back, so the sink normally already holds the records.
_SINK_FLOOR_SECONDS = 2.0


@dataclass(frozen=True)
class DimseScenario(BaseScenario):
    """C-STORE ``count`` fresh synthetic objects into the ``inbound`` endpoint while a DIMSE sink
    answering ``sink_status`` listens on ``sink_endpoint``. Each object must be committed (the SCP
    answers Success), its row on ``inbound_connection`` must reach ``expect`` (``processed``, or
    ``dead_letter`` for ``outbound_connection``), and the sink must have seen exactly ``attempts``
    C-STOREs carrying its SOPInstanceUID."""

    name: str
    description: str
    count: int = 3
    expect: str = "processed"  # processed | dead_letter
    sink_status: int = SUCCESS
    attempts: int = 1
    inbound: str = "dimse_in"
    sink_endpoint: str = "dimse_out"
    inbound_connection: str = INBOUND_CONNECTION
    outbound_connection: str = OUTBOUND_CONNECTION

    def __post_init__(self) -> None:
        if self.count < 1:
            raise ValueError(f"scenario {self.name!r} must send at least one object")
        if self.expect not in ("processed", "dead_letter"):
            raise ValueError(f"scenario {self.name!r}: expect must be processed or dead_letter")
        if self.attempts < 1:
            raise ValueError(f"scenario {self.name!r}: attempts must be at least 1")
        if not 0 <= self.sink_status <= 0xFFFF:
            raise ValueError(f"scenario {self.name!r}: sink_status must be a 16-bit DIMSE status")
        # Success and the Warning family (0xBxxx) are both a stored object to the engine's SCU.
        stores = self.sink_status == SUCCESS or 0xB000 <= self.sink_status <= 0xBFFF
        if (self.expect == "processed") != stores:
            raise ValueError(
                f"scenario {self.name!r}: a sink answering {self.sink_status:04X} cannot lead to "
                f"{self.expect!r}"
            )
        if stores and self.attempts != 1:
            raise ValueError(f"scenario {self.name!r}: a stored object is sent exactly once")

    @property
    def covers(self) -> frozenset[Coverage]:
        return frozenset({(KIND, INBOUND), (KIND, OUTBOUND)})

    def unavailable(self) -> str | None:
        return dicom_extra_missing()

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        missing = self.unavailable()
        if missing:
            return ScenarioResult(self, False, f"cannot run: {missing}")
        payloads, uids = make_datasets(self.count)
        port = ctx.endpoints.port(self.sink_endpoint)
        with DimseSink(LOOPBACK, port, status=self.sink_status) as sink:
            try:
                before = {row.id for row in _rows(ctx.client, self.inbound_connection, pages=1)}
            except ApiError as exc:
                return ScenarioResult(self, False, f"API error: {exc}")
            injections = drivers.build(KIND, ctx.endpoints, self.inbound).inject(payloads)
            answered = [status_of(i) for i in injections]
            committed = answered.count(SUCCESS)
            if committed != self.count:
                return ScenarioResult(
                    self, False, _send_detail(self.count, committed, injections, answered)
                )
            # Like the HL7 verifiers, the clock for the outcome starts once the sends are done.
            deadline = time.monotonic() + ctx.timeout
            try:
                found = _correlate(self, ctx.client, before, uids, deadline)
            except ApiError as exc:
                return ScenarioResult(self, False, f"API error: {exc}")
            sink_wait = max(deadline - time.monotonic(), _SINK_FLOOR_SECONDS)
            return self._judge(found, sink, uids, sink_wait)

    def _judge(
        self, found: _Found, sink: DimseSink, uids: list[str], sink_wait: float
    ) -> ScenarioResult:
        detail = f"{self.count}/{self.count} committed (C-STORE 0000)"
        matched = "rows (matched by SOPInstanceUID)"
        if self.expect == "dead_letter":
            attempts = {uid: found.dead_attempts.get(found.message_id.get(uid, "")) for uid in uids}
            dead = [uid for uid, n in attempts.items() if n is not None]
            wrong = sorted({n for n in attempts.values() if n is not None and n != self.attempts})
            detail += (
                f"; {len(dead)}/{self.count} {matched} dead-lettered for {self.outbound_connection}"
            )
            if wrong:
                detail += f"; dead-letter attempts {wrong}, expected {self.attempts}"
            ok = len(dead) == self.count and not wrong
        else:
            reached = [uid for uid in uids if found.status_of(uid) == self.expect]
            detail += f"; {len(reached)}/{self.count} {matched} reached {self.expect!r}"
            ok = len(reached) == self.count
        if not ok:
            unmatched = self.count - len(found.message_id)
            if unmatched:
                detail += f"; {unmatched} row(s) not found"
            seen = sorted({s for uid in uids if (s := found.status_of(uid)) is not None})
            if seen:
                detail += f"; statuses seen: {seen}"
            return ScenarioResult(self, False, detail)

        wanted = set(uids)
        records = sink.wait_for(
            lambda rs: _all_seen(
                Counter(r.meta.get("sop_instance_uid") for r in rs), wanted, self.attempts
            ),
            sink_wait,
        )
        # The verdict counts the UID inside each delivered object, not the sink's own note of it.
        counts = _delivered(records, wanted)
        exact = sum(1 for uid in wanted if counts[uid] == self.attempts)
        detail += (
            f"; {exact}/{self.count} reached the dimse sink with their SOPInstanceUID "
            f"exactly {self.attempts} time(s)"
        )
        if exact != self.count:
            detail += f" (C-STOREs per object: {sorted(counts[uid] for uid in wanted)})"
        return ScenarioResult(self, exact == self.count, detail)


def _all_seen(counts: Counter[str | None], wanted: set[str], attempts: int) -> bool:
    return all(counts[uid] >= attempts for uid in wanted)


def _delivered(records: list[Record], wanted: set[str]) -> Counter[str]:
    found: Counter[str] = Counter()
    for record in records:
        uid = sop_instance_uid(record.payload)
        if uid is not None and uid in wanted:
            found[uid] += 1
    return found


@dataclass
class _Found:
    """What the API said about this run's objects: their row ids by SOPInstanceUID, those rows'
    statuses, and the dead-letter attempt count for each of those rows that dead-lettered."""

    message_id: dict[str, str] = field(default_factory=dict)
    status: dict[str, str] = field(default_factory=dict)
    dead_attempts: dict[str, int] = field(default_factory=dict)

    def status_of(self, uid: str) -> str | None:
        mid = self.message_id.get(uid)
        return None if mid is None else self.status.get(mid)


def _rows(
    client: EngineClient, channel: str, *, pages: int, stop_at: set[str] | None = None
) -> Iterator[MessageSummary]:
    """The inbound's rows, newest first, a page at a time. With ``stop_at`` it stops after the first
    page holding one of those ids: everything older than a snapshot row is older than this run."""
    for page in range(pages):
        rows = client.list_messages(channel_id=channel, limit=_PAGE, offset=page * _PAGE).messages
        yield from rows
        if len(rows) < _PAGE or (stop_at and any(row.id in stop_at for row in rows)):
            return


def _correlate(
    scenario: DimseScenario,
    client: EngineClient,
    before: set[str],
    uids: list[str],
    deadline: float,
) -> _Found:
    """Poll until every sent SOPInstanceUID has a new row in its final state, or the deadline."""
    wanted = set(uids)
    found = _Found()
    read: set[str] = set()  # row ids whose body was already read; each read is audited
    while True:
        for row in _rows(client, scenario.inbound_connection, pages=_MAX_PAGES, stop_at=before):
            if row.id in before:
                continue
            if row.id not in read and len(found.message_id) < len(wanted):
                read.add(row.id)
                uid = sop_instance_uid(client.get_message_body(row.id, surface="harness").raw)
                if uid is not None and uid in wanted:
                    found.message_id[uid] = row.id
            found.status[row.id] = row.status
        mine = set(found.message_id.values())
        found.status = {mid: s for mid, s in found.status.items() if mid in mine}
        done = False
        if len(mine) == len(wanted):
            if scenario.expect == "dead_letter":
                dead = client.list_dead_letters(
                    channel_id=scenario.inbound_connection,
                    destination_name=scenario.outbound_connection,
                    limit=500,
                )
                found.dead_attempts = {
                    d.message_id: d.attempts for d in dead.dead_letters if d.message_id in mine
                }
                # Done when all dead-lettered, or when every row settled without failing, which
                # can no longer dead-letter: the verdict is then already decidable.
                done = mine <= set(found.dead_attempts) or all(
                    found.status.get(mid) in _SETTLED for mid in mine
                )
            else:
                done = all(found.status.get(mid) in _TERMINAL for mid in mine)
        if done or time.monotonic() >= deadline:
            return found
        time.sleep(_POLL_SECONDS)


def _send_detail(
    count: int, committed: int, injections: list[drivers.Injection], answered: list[int | None]
) -> str:
    detail = f"{committed}/{count} committed by the inbound SCP (C-STORE 0000)"
    refused = sorted({f"{s:04X}" for s in answered if s is not None and s != SUCCESS})
    if refused:
        detail += f"; it answered {refused}"
    return detail + _send_error_suffix([i.error for i in injections if i.error])


SCENARIOS = (
    DimseScenario(
        "dimse_delivered",
        "C-STORE into IB_Harness_DIMSE -> PROCESSED, forwarded once to the dimse sink",
        count=3,
        expect="processed",
    ),
    DimseScenario(
        "dimse_retry_dead_letter",
        "dimse sink answers Out of Resources (A700) -> retried to the graph's limit, dead-lettered",
        count=2,
        expect="dead_letter",
        sink_status=OUT_OF_RESOURCES,
        attempts=3,  # OB_Harness_DIMSE's RetryPolicy.max_attempts
    ),
    DimseScenario(
        "dimse_refused_dead_letter",
        "dimse sink answers Cannot Understand (C000) -> dead-lettered after one attempt",
        count=2,
        expect="dead_letter",
        sink_status=CANNOT_UNDERSTAND,
        attempts=1,
    ),
)
