# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The keyless-then-keyed on-open contract on SQLite, plus what keeps it honest (BACKLOG #1723).

The contract is ``tests/_keyed_reopen_contract.py``. The server legs run it from
``tests/test_postgres_store.py`` and ``tests/test_sqlserver_store.py``. This file runs it on the plain
leg, where its negative control is cheap enough to cover every cell: a contract that cannot go red
proves nothing on any backend, and all three backends share its whole body.

**Why the controls are few.** One run with every pass removed reaches every cell's at-rest check, and
one control per cell would buy little beyond that for its store opens. It proves less for the read
half: a read can refuse on a sibling column it opens first. Measured once per cell when this file was
written: with any one pass removed, the at-rest check named that cell alone on 16 of SQLite's 18
cells, the read path reported it too, and the keyed open refused on the other two, the warmed cells.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store import store as store_module
from messagefoundry.store.crypto import CipherError, generate_key, make_cipher
from tests._keyed_reopen_contract import (
    CONTROL_CELL,
    READERS,
    WARMED_AT_OPEN,
    Cell,
    KeyedReopenReport,
    assert_names_the_control_cell_alone,
    cells_in_scope,
    keyed_reopen_report,
    remove_seal_passes,
)
from tests.test_store_cipher_sweep_parity import _BACKENDS


@pytest.fixture(autouse=True)
def _no_store_file_acls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each open restricts three files, a process launch apiece on Windows, and that is most of the
    open's cost there. ACLs are not this contract's question, and this file opens stores often."""
    monkeypatch.setattr(store_module, "_secure_store_file", lambda path, *, dir_grants: None)


async def _fetch(store: Any, sql: str) -> Sequence[Mapping[str, Any]]:
    cursor = await store._db.execute(sql)
    rows: Sequence[Mapping[str, Any]] = await cursor.fetchall()
    return rows


async def _report(db: Path) -> KeyedReopenReport:
    key = generate_key()
    return await keyed_reopen_report(
        MessageStore,
        open_keyless=lambda: MessageStore.open(db),
        open_keyed=lambda: MessageStore.open(db, cipher=make_cipher(key, write_v2=True)),
        fetch=_fetch,
    )


@pytest.mark.parametrize("backend", _BACKENDS)
def test_the_contract_reads_exactly_each_backends_written_cells(backend: str) -> None:
    """Per backend, because a union would stay equal while one backend's scope narrowed. A new
    written cell reds here on the plain leg with no database, and so does a cell that stopped being
    written. Only SQLite writes ``shared_body``; tests/test_phi_at_rest_inventory.py pins why."""
    expected = set(READERS)
    if backend != "store.py":
        expected.discard(("shared_body", "body"))
    assert set(cells_in_scope(backend)) == expected


async def test_every_written_cell_is_sealed_and_reads_back(tmp_path: Path) -> None:
    assert await _report(tmp_path / "msg.db") == KeyedReopenReport()


async def test_removing_every_pass_reds_every_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The negative control over the whole scope. The read half may name a cell for a sibling's
    refusal, as the module docstring says, so only the at-rest half proves that cell's own check."""
    cells = [cell for cell in cells_in_scope("store.py") if cell not in WARMED_AT_OPEN]
    remove_seal_passes(monkeypatch, MessageStore, cells)
    report = await _report(tmp_path / "msg.db")
    assert report.unsealed == cells
    assert sorted(report.unreadable) == cells


async def test_removing_one_pass_names_that_cell_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remove_seal_passes(monkeypatch, MessageStore, {CONTROL_CELL})
    assert_names_the_control_cell_alone(await _report(tmp_path / "msg.db"))


@pytest.mark.parametrize("cell", WARMED_AT_OPEN, ids=lambda cell: f"{cell[0]}.{cell[1]}")
async def test_removing_a_warmed_cells_pass_fails_the_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cell: Cell
) -> None:
    """The same control for the two cells the open itself decrypts: the keyed open refuses."""
    remove_seal_passes(monkeypatch, MessageStore, {cell})
    with pytest.raises(CipherError, match=rf"{cell[0]}\.{cell[1]}"):
        await _report(tmp_path / "msg.db")
