# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A passive DR standby delivers nothing until it is activated (vault BACKLOG #3262).

A DR box is seeded by restoring a backup of the primary's store, and that backup can hold rows
the primary had not delivered yet. A box that started passive over such a store used to build
every outbound and deliver those rows at once, possibly while the primary was alive and
delivering the same rows. Each test here starts the engine the way ``serve`` does, over a store
that already holds undelivered rows, and records every payload a connector is handed.

The store holds rows at two stages: three messages already at the ``outbound`` stage, and one
still at ``ingress``. The router and transform stages run on a passive box, so the ingress row
moves to the ``outbound`` stage and waits there with the others.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path

import pytest

from messagefoundry.config.settings import DrSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.wiring_runner import DrParkedError
from messagefoundry.store import MessageStore, Store
from messagefoundry.transports.file import FileDestination
from tests.test_dr_passive_bind import _DB, _served
from tests.test_dr_running_config_dir import _free_ports, _until

_IB = "IB_CRIT_ADT"
_OB_CRIT = "OB_CRIT_ADT"
_OB_NORM = "OB_NORM_ADT"
# Six poll intervals, for a worker that is free to deliver to do so.
_SETTLE_SECONDS = 0.3

Sent = list[tuple[str, str]]


@pytest.fixture(params=["pooled", "per_lane"])
def claim_mode(request: pytest.FixtureRequest) -> str:
    """Both delivery consumers: the pooled dispatcher pauses a lane, a lane's own worker waits at
    its gate. A park has to hold in each."""
    return str(request.param)


def _adt(control_id: str) -> str:
    return (
        f"MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|{control_id}|P|2.5.1\r"
        "EVN|A01|20260604\r"
        "PID|1||100^^^H^MR||DOE^JANE\r"
    )


def _write_graph(cfg: Path, tmp_path: Path, *, hold: bool) -> None:
    """One critical inbound whose handler sends to a critical and a normal File outbound. With
    ``hold`` both outbounds are ``auto_start = false``, which is how the seeding engine leaves
    their rows undelivered."""
    cfg.mkdir(parents=True, exist_ok=True)
    (port,) = _free_ports(1)
    flag = ", auto_start=False" if hold else ""
    lines = [
        "from messagefoundry import inbound, outbound, router, handler, Send, File, MLLP",
        "from messagefoundry.config.models import Priority",
        f"inbound({_IB!r}, MLLP(port={port}), router='r', priority=Priority.CRITICAL)",
    ]
    for name, tier in ((_OB_CRIT, "CRITICAL"), (_OB_NORM, "NORMAL")):
        out = tmp_path / name
        out.mkdir(exist_ok=True)
        lines.append(
            f"outbound({name!r}, File(directory={str(out)!r}), priority=Priority.{tier}{flag})"
        )
    lines += [
        "@router('r')",
        "def route(msg):",
        "    return ['h']",
        "@handler('h')",
        "def handle(msg):",
        f"    return [Send({_OB_CRIT!r}, msg), Send({_OB_NORM!r}, msg)]",
    ]
    (cfg / "cfg.py").write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> Sent:
    """Every payload a File outbound is handed, as ``(outbound, control id)``, in order."""
    record: Sent = []
    real_send = FileDestination.send

    async def recording_send(
        self: FileDestination, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> None:
        record.append((self.directory.name, payload.split("|")[9]))
        await real_send(self, payload, metadata=metadata)

    monkeypatch.setattr(FileDestination, "send", recording_send)
    return record


async def _until_sent(sent: Sent, count: int) -> None:
    """Wait until the connectors have been handed ``count`` payloads."""

    async def handed() -> bool:
        return len(sent) >= count

    await _until(handed)


async def _held(engine: Engine, outbound: str) -> int:
    """How many rows wait PENDING at the outbound stage for ``outbound``."""
    count, _oldest = await engine.store.pending_depth(outbound)
    return count


async def _enqueue(store: Store, control_id: str) -> None:
    await store.enqueue_ingress(
        channel_id=_IB, raw=_adt(control_id), control_id=control_id, message_type="ADT^A01"
    )


async def _seeded(tmp_path: Path, sent: Sent) -> Path:
    """Leave the store as a restored seed would be, and return the config dir the box under test
    starts from. A first engine routes S1 to S3 to both outbounds and holds them there. S4 is
    then written at the ingress stage with no engine running."""
    hold = tmp_path / "cfg-hold"
    _write_graph(hold, tmp_path, hold=True)
    async with _served(tmp_path, hold, DrSettings()) as engine:
        for control_id in ("S1", "S2", "S3"):
            await _enqueue(engine.store, control_id)
        rr = engine.registry_runner
        assert rr is not None
        rr.notify_work()

        async def routed() -> bool:
            return await _held(engine, _OB_CRIT) == 3 and await _held(engine, _OB_NORM) == 3

        await _until(routed)
    assert sent == []  # the seeding engine delivered nothing, so the rows are still owed
    store = await MessageStore.open(tmp_path / _DB)
    try:
        await _enqueue(store, "S4")
    finally:
        await store.close()
    live = tmp_path / "cfg"
    _write_graph(live, tmp_path, hold=False)
    return live


async def _all_at_outbound(engine: Engine, crit: int, norm: int) -> None:
    async def there() -> bool:
        return await _held(engine, _OB_CRIT) == crit and await _held(engine, _OB_NORM) == norm

    await _until(there)


async def test_a_passive_standby_delivers_nothing_until_it_is_activated(
    tmp_path: Path, sent: Sent, claim_mode: str
) -> None:
    """Red before #3262: the passive box delivered every restored row as soon as it started."""
    cfg = await _seeded(tmp_path, sent)
    passive = DrSettings(enabled=True, activate=False)
    async with _served(tmp_path, cfg, passive, claim_mode) as engine:
        rr = engine.registry_runner
        assert rr is not None
        # The ingress row is routed and transformed, and then waits with the rest.
        await _all_at_outbound(engine, crit=4, norm=4)
        await asyncio.sleep(_SETTLE_SECONDS)
        assert sent == []
        assert await _held(engine, _OB_CRIT) == 4 and await _held(engine, _OB_NORM) == 4
        assert set(rr.filtered_outbound()) == {_OB_CRIT, _OB_NORM}
        assert not rr.outbound_running(_OB_CRIT)
        # No door starts a parked lane, and the refusal names the way out.
        with pytest.raises(DrParkedError, match="POST /dr/activate"):
            await rr.start_outbound(_OB_CRIT)
        # A reload's CA gate reads the outbounds an activation would build, and no other.
        gated = rr._reload_anchor_lanes(rr.registry, rr.registry, [])
        assert [name for _kind, name, _settings in gated] == [_OB_CRIT]
        # A reload while passive keeps every lane parked.
        await engine.reload_detail(cfg)
        await asyncio.sleep(_SETTLE_SECONDS)
        assert sent == []
        assert set(rr.filtered_outbound()) == {_OB_CRIT, _OB_NORM}

        await engine._dr_activate_profile()  # what POST /dr/activate runs once its gates pass
        await _until_sent(sent, 4)
        await asyncio.sleep(_SETTLE_SECONDS)
        # Each parked row once, in the order it was queued. The normal lane stays parked.
        assert sent == [(_OB_CRIT, "S1"), (_OB_CRIT, "S2"), (_OB_CRIT, "S3"), (_OB_CRIT, "S4")]
        assert await _held(engine, _OB_CRIT) == 0 and await _held(engine, _OB_NORM) == 4
        assert set(rr.filtered_outbound()) == {_OB_NORM}


async def test_a_release_stops_delivery_again_until_the_next_activation(
    tmp_path: Path, sent: Sent, claim_mode: str
) -> None:
    """After ``POST /dr/release`` the box is passive again, so a row that reaches the outbound
    stage waits, across a reload too, and the next activation delivers it once."""
    cfg = await _seeded(tmp_path, sent)
    passive = DrSettings(enabled=True, activate=False)
    async with _served(tmp_path, cfg, passive, claim_mode) as engine:
        rr = engine.registry_runner
        assert rr is not None
        await engine._dr_activate_profile()
        await _until_sent(sent, 4)
        outcome = await engine._dr_release_drain()  # what POST /dr/release runs
        assert outcome["drained"] is True and outcome["held_on_parked_outbounds"] == 4
        # Parked at once, before any reload: the release returns with nothing delivering.
        assert set(rr.filtered_outbound()) == {_OB_CRIT, _OB_NORM}
        assert not rr.outbound_running(_OB_CRIT)
        del sent[:]

        await _enqueue(engine.store, "S5")
        rr.notify_work()
        await _all_at_outbound(engine, crit=1, norm=5)
        await asyncio.sleep(_SETTLE_SECONDS)
        assert sent == []
        await engine.reload_detail(cfg)
        await asyncio.sleep(_SETTLE_SECONDS)
        assert sent == []
        assert set(rr.filtered_outbound()) == {_OB_CRIT, _OB_NORM}

        await engine._dr_activate_profile()
        await _until_sent(sent, 1)
        await asyncio.sleep(_SETTLE_SECONDS)
        assert sent == [(_OB_CRIT, "S5")]
        assert await _held(engine, _OB_NORM) == 5


async def test_an_active_dr_box_over_the_same_store_delivers_its_critical_rows(
    tmp_path: Path, sent: Sent
) -> None:
    """The control arm: the recorder sees a delivery, so the empty lists above are not a dead
    probe, and the park is the passive state's and not the seed's."""
    cfg = await _seeded(tmp_path, sent)
    async with _served(tmp_path, cfg, DrSettings(enabled=True, activate=True)) as engine:
        await _until_sent(sent, 4)
        await asyncio.sleep(_SETTLE_SECONDS)
        assert sent == [(_OB_CRIT, "S1"), (_OB_CRIT, "S2"), (_OB_CRIT, "S3"), (_OB_CRIT, "S4")]
        assert await _held(engine, _OB_NORM) == 4


async def test_a_box_that_is_not_a_dr_standby_delivers_every_restored_row(
    tmp_path: Path, sent: Sent
) -> None:
    """With ``[dr].enabled`` off nothing is parked: both lanes drain."""
    cfg = await _seeded(tmp_path, sent)
    async with _served(tmp_path, cfg, DrSettings()) as engine:
        await _until_sent(sent, 8)
        assert sorted(sent) == sorted(
            (ob, cid) for ob in (_OB_CRIT, _OB_NORM) for cid in ("S1", "S2", "S3", "S4")
        )
        assert await _held(engine, _OB_CRIT) == 0 and await _held(engine, _OB_NORM) == 0
