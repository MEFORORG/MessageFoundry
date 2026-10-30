# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The keyless-then-keyed on-open contract on SQLite, plus what keeps it honest (BACKLOG #1723).

The contract is ``tests/_keyed_reopen_contract.py``. The server legs run it from
``tests/test_postgres_store.py`` and ``tests/test_sqlserver_store.py``. This file runs it on the plain
leg, where its negative control is cheap enough to cover every cell: a contract that cannot go red
proves nothing on any backend, and all three backends share its whole body.

**Why the controls are few.** One run with every unwarmed pass removed reaches each of those cells'
at-rest checks, and one control per cell would buy little beyond that for its store opens. It proves
less for the read half: a read can refuse on a sibling column it opens first. The warmed cells never
reach the at-rest check, because with their pass removed the keyed open raises first. Measured once
per cell when this file was written: with any one pass removed, the at-rest check named that cell
alone on 16 of SQLite's 18 cells, the read path reported it too, and the keyed open refused on the
other two.

**A removed pass is refused as an unmarked value, so it says nothing about a pass that ran and got it
wrong.** The two damaged-seal controls cover that: one reaches the equality check and one the AAD.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store import store as store_module
from messagefoundry.store.crypto import AesGcmCipher, CipherError, generate_key, make_cipher
from tests._keyed_reopen_contract import (
    CONTROL_CELL,
    READERS,
    WARMED_AT_OPEN,
    Cell,
    KeyedReopenReport,
    assert_names_the_control_cell_alone,
    cells_in_scope,
    keyed_reopen_report,
    plain,
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


async def test_removing_every_unwarmed_pass_reds_every_unwarmed_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The negative control over every cell but the warmed two. The read half may name a cell for a
    sibling's refusal, as the module docstring says, so only the at-rest half proves its own check."""
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


def _damage_the_control_cells_seal(
    monkeypatch: pytest.MonkeyPatch, *, suffix: str = "", wrong_aad: bytes | None = None
) -> None:
    """Seal :data:`CONTROL_CELL`'s value with ``suffix`` added, or under ``wrong_aad``, and every
    other value as usual. Picked out by its text, because ``encrypt`` is not told the cell."""
    real = AesGcmCipher.encrypt

    def encrypt(self: AesGcmCipher, plaintext: str, *, aad: bytes | None = None) -> str:
        if plaintext == plain(CONTROL_CELL):
            return real(self, plaintext + suffix, aad=wrong_aad or aad)
        return real(self, plaintext, aad=aad)

    monkeypatch.setattr(AesGcmCipher, "encrypt", encrypt)


async def test_a_seal_that_damages_a_value_reds_that_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cell is sealed, the read succeeds, and only the equality check can see the difference."""
    _damage_the_control_cells_seal(monkeypatch, suffix="-DAMAGED")
    report = await _report(tmp_path / "msg.db")
    assert report.unsealed == []
    assert list(report.unreadable) == [CONTROL_CELL]
    assert report.unreadable[CONTROL_CELL].startswith("read back")


async def test_a_seal_under_the_wrong_tag_reds_that_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cell is sealed and marked, and only the read path's own tag refuses it. This is the check
    the v1 default format could not make, which binds no tag."""
    _damage_the_control_cells_seal(monkeypatch, wrong_aad=b"not this cell's tag")
    report = await _report(tmp_path / "msg.db")
    assert report.unsealed == []
    assert list(report.unreadable) == [CONTROL_CELL]
    assert "CipherError" in report.unreadable[CONTROL_CELL]


@pytest.mark.parametrize("cell", WARMED_AT_OPEN, ids=lambda cell: f"{cell[0]}.{cell[1]}")
async def test_removing_a_warmed_cells_pass_fails_the_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cell: Cell
) -> None:
    """The same control for the two cells the open itself decrypts: the keyed open refuses."""
    remove_seal_passes(monkeypatch, MessageStore, {cell})
    with pytest.raises(CipherError, match=rf"{cell[0]}\.{cell[1]}"):
        await _report(tmp_path / "msg.db")
