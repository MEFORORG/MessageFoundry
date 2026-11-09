# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0217 slice 1b-iii: a ``vault_transit`` cipher gets the Transit row sealer on every backend,
and the engine runs its start probe and refuses to start, failing closed, when it fails.
Synthetic data only, with an in-memory Transit stand-in."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings, StoreSettings
from messagefoundry.pipeline.engine import Engine
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.crypto_transit import TransitCipher
from messagefoundry.store.row_seal import (
    RowSealer,
    RowSealStartRefused,
    TransitRowSealer,
    probe_row_sealer_at_start,
    row_sealer_for_cipher,
    transit_seal_key_id,
)
from messagefoundry.store.store import MessageStore
from tests._transit_seal_fake import ACTIVE, FakeBackend


def test_a_transit_cipher_gets_the_transit_sealer() -> None:
    sealer = row_sealer_for_cipher(TransitCipher(None, "mefor-data", audit_key="mefor-audit"))
    assert isinstance(sealer, TransitRowSealer)
    assert sealer.key_id == transit_seal_key_id("transit", "mefor-audit")
    # Controls: a local key gets the local sealer, and a keyless cipher none.
    assert type(row_sealer_for_cipher(make_cipher(generate_key()))) is RowSealer
    assert row_sealer_for_cipher(make_cipher(None)) is None


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
def test_a_server_store_on_a_transit_cipher_holds_the_transit_sealer(backend: str) -> None:
    """Each server backend builds its sealer through ``for_cipher`` in its constructor, which
    touches no database, so no server is needed to see it."""
    import importlib

    module = importlib.import_module(f"messagefoundry.store.{backend}")
    Store: Any = getattr(module, "PostgresStore" if backend == "postgres" else "SqlServerStore")
    store: Any = Store(None, StoreSettings(), cipher=TransitCipher(None, "mefor-data"))
    assert isinstance(store.row_sealer(), TransitRowSealer)
    local: Any = Store(None, StoreSettings(), cipher=make_cipher(generate_key()))
    assert type(local.row_sealer()) is RowSealer


async def test_the_start_probe_passes_and_refuses(caplog: pytest.LogCaptureFixture) -> None:
    fake = FakeBackend()
    await probe_row_sealer_at_start(TransitRowSealer(fake))  # Transit up: no raise
    assert fake.verify_calls == 1 and fake.probe_calls == 1
    await probe_row_sealer_at_start(None)  # keyless: nothing to probe
    await probe_row_sealer_at_start(RowSealer.for_cipher(make_cipher(generate_key())))
    for broken in ("down", "verify_forbidden"):
        fake = FakeBackend()
        if broken == "down":
            fake.down = True
        else:
            fake.forbid = {ACTIVE}  # a token without transit/verify on the audit key
        caplog.clear()
        with (
            caplog.at_level(logging.ERROR, logger="messagefoundry.store.row_seal"),
            pytest.raises(RowSealStartRefused),
        ):
            await probe_row_sealer_at_start(TransitRowSealer(fake))
        assert any("startup refused" in r.getMessage() for r in caplog.records), broken


async def test_the_engine_refuses_to_start_when_the_probe_fails(tmp_path: Path) -> None:
    """The probe runs in ``Engine.start``, before recovery or any listener, for whatever backend
    the store is. Control: the same store and engine start with Transit up."""
    store = await MessageStore.open(tmp_path / "start.db", cipher=make_cipher(generate_key()))
    fake = FakeBackend()
    try:
        store._row_sealer = TransitRowSealer(fake)
        fake.down = True
        engine = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
        with pytest.raises(RowSealStartRefused):
            await engine.start()
        fake.down = False
        engine = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
        try:
            await engine.start()
        finally:
            await engine.stop()
        assert fake.verify_calls >= 1
    finally:
        await store.close()
