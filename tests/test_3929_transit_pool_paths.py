# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3929: the store's bulk cipher work that leaves the loop under every cipher runs on the
Transit pool when the cipher blocks on I/O.

``get_message``, an attachment's seal, and SQL Server's ``reload_state_cache`` each hand a whole
batch of cipher calls to a worker thread, under the in-process cipher too, because the batch is CPU
work in proportion to its size. Before this fix they used asyncio's default executor, so under
``vault_transit`` a slow Vault could fill it. They now go through
:func:`~messagefoundry.store.row_seal.cipher_offload`: the Transit pool when the cipher blocks on
I/O, the default executor otherwise. The content search's scan stays on the default executor on
purpose (see :func:`cipher_offload`), and a test here pins that too.

The check reads each Transit call's thread NAME, so it tells the Transit pool
(:data:`~messagefoundry.store.row_seal.TRANSIT_THREAD_PREFIX`) from the default executor, which a
thread-id check against the loop's thread cannot. Synthetic data only.
"""

from __future__ import annotations

import ast
import pathlib
import threading
from typing import Any

import pytest

pytest.importorskip("hvac", reason="the Transit cipher tests need the [vault] extra")

from messagefoundry.store import row_seal  # noqa: E402
from messagefoundry.store.content_search import make_spec  # noqa: E402
from messagefoundry.store.crypto import generate_key, make_cipher  # noqa: E402
from messagefoundry.store.crypto_transit import TransitCipher  # noqa: E402
from messagefoundry.store.row_seal import TRANSIT_THREAD_PREFIX  # noqa: E402
from messagefoundry.store.sqlserver import SqlServerStore  # noqa: E402
from messagefoundry.store.store import MessageStatus, MessageStore  # noqa: E402
from tests.test_crypto_transit import _FakeClient, _FakeTransit  # noqa: E402
from tests.test_store_transit_off_loop import _RecordingTransit  # noqa: E402
from tests.test_store_transit_off_loop_servers import _bare_store, _state_rows  # noqa: E402

_KEY = "mefor-store"
_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M3929|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
_STORES = ("store.py", "postgres.py", "sqlserver.py")
#: The batch callables routed through cipher_offload; none may go to ``asyncio.to_thread`` itself.
_BATCHES = frozenset({"open_message_record", "_seal", "_decode_state_rows"})


class _NamingTransit(_RecordingTransit):
    """A fake Transit that also records the name of the thread each call ran on."""

    def __init__(self) -> None:
        super().__init__()
        self.names: list[str] = []

    def _note(self) -> None:
        self.names.append(threading.current_thread().name)
        super()._note()


def _on_pool(names: list[str]) -> bool:
    return bool(names) and all(n.startswith(TRANSIT_THREAD_PREFIX) for n in names)


async def test_cipher_offload_picks_the_pool_only_for_a_blocking_cipher() -> None:
    loop_name = threading.current_thread().name
    transit = TransitCipher(_FakeClient(_FakeTransit()), _KEY)

    def name() -> str:
        return threading.current_thread().name

    assert (await row_seal.cipher_offload(transit, name)).startswith(TRANSIT_THREAD_PREFIX)
    # An in-process cipher's batch still leaves the loop, on the default executor.
    for local in (make_cipher(generate_key()), make_cipher(None)):
        off = await row_seal.cipher_offload(local, name)
        assert off != loop_name and not off.startswith(TRANSIT_THREAD_PREFIX), off


async def test_a_sqlite_stores_bulk_paths_run_their_transit_calls_on_the_pool(
    tmp_path: pathlib.Path,
) -> None:
    transit = _NamingTransit()
    store = await MessageStore.open(
        tmp_path / "t.db", cipher=TransitCipher(_FakeClient(transit), _KEY)
    )
    try:
        mid = await store.record_received(
            channel_id="IB_TEST",
            raw=_RAW,
            status=MessageStatus.FILTERED,
            summary="synthetic",
            metadata="{}",
        )
        transit.names.clear()
        message = await store.get_message(mid)
        assert message is not None and message["raw"] == _RAW
        assert _on_pool(transit.names), ("get_message", transit.names)

        transit.names.clear()
        await store.put_attachment(iter(["chunk-one", "chunk-two"]), "application/pdf")
        assert _on_pool(transit.names), ("put_attachment", transit.names)

        # CONTROL, and the scan's own pin: the search scan stays on the default executor.
        transit.names.clear()
        spec = make_spec(content="JANE", field_path=None, field_value=None)
        result = await store.search_messages(spec, allowed_channels=None)
        assert result.matched == 1
        assert transit.names and not any(
            n.startswith(TRANSIT_THREAD_PREFIX) for n in transit.names
        ), ("search", transit.names)
    finally:
        await store.close()


async def test_a_sql_server_promotion_reload_decrypts_on_the_pool() -> None:
    transit = _NamingTransit()
    cipher = TransitCipher(_FakeClient(transit), _KEY)
    rows = _state_rows(cipher)
    store = _bare_store(SqlServerStore, cipher)

    async def fetchall(*_: Any, **__: Any) -> list[dict[str, Any]]:
        return rows

    store._fetchall = fetchall
    transit.names.clear()
    await store.reload_state_cache()
    assert dict(store._state_cache) == {("ns", key): {"n": key} for key in ("k1", "k2")}
    assert _on_pool(transit.names), transit.names


def _to_thread_batches(source: str) -> list[str]:
    """The names of the store's batch callables handed straight to ``asyncio.to_thread``."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and node.args):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "to_thread"):
            continue
        first = node.args[0]
        name = first.attr if isinstance(first, ast.Attribute) else getattr(first, "id", None)
        if name in _BATCHES:
            found.append(name)
    return found


@pytest.mark.parametrize("module", _STORES)
def test_no_backend_hands_a_cipher_batch_to_the_default_executor(module: str) -> None:
    """The Postgres and SQL Server twins of the paths above, which need a live server to drive,
    are held to the same routing statically."""
    root = pathlib.Path(row_seal.__file__).parent
    assert _to_thread_batches((root / module).read_text(encoding="utf-8")) == []


def test_the_static_check_sees_a_batch_handed_to_the_default_executor() -> None:
    """Negative control for the static check: it finds each shape the stores used before."""
    planted = (
        "async def f(self):\n"
        "    await asyncio.to_thread(open_message_record, self._cipher, record)\n"
        "    await asyncio.to_thread(_seal, ref, chunks)\n"
        "    await asyncio.to_thread(self._decode_state_rows, rows)\n"
    )
    assert _to_thread_batches(planted) == ["open_message_record", "_seal", "_decode_state_rows"]
