# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1624 item 2 -- one connection-event vocabulary, :mod:`messagefoundry.connection_events`,
read by the connectors, the store and the web console's event-log filter.

``tests/test_phi_logging_inventory.py`` pins that the set equals the kinds the emit sites write, and
``tests/test_connection_event_burst.py`` that the drainer loses only an undeclared row.
"""

from __future__ import annotations

import ast
import re
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry import connection_events
from messagefoundry.connection_events import (
    CONNECTION_EVENT_KIND_ORDER,
    CONNECTION_EVENT_KINDS,
    check_connection_event_kind,
)
from messagefoundry.store import MessageStore
from messagefoundry.store.store import ConnectionEventWrite
from tests._ast_sites import code_strings, parse_source

_ROOT = Path(__file__).resolve().parents[1]
UNDECLARED = "not_a_connection_event_kind"


def _event(kind: str, peer: str = "10.0.0.1") -> ConnectionEventWrite:
    return ConnectionEventWrite(
        connection="IB_VOCAB",
        transport="mllp",
        direction="inbound",
        kind=kind,
        peer_host=peer,
        message_id=None,
        reason=None,
    )


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "vocab.db")
    try:
        yield s
    finally:
        await s.close()


# --- one set, three readers ---------------------------------------------------------------------


def test_transports_base_re_exports_the_one_set() -> None:
    from messagefoundry.transports import base

    assert base.CONNECTION_EVENT_KINDS is CONNECTION_EVENT_KINDS
    assert "CONNECTION_EVENT_KINDS" in base.__all__


def test_the_leaf_imports_nothing_from_the_engine() -> None:
    # The console may import it only because it pulls in no engine package. A leaf that grew an
    # import of transports/ or store/ would smuggle that package into the client.
    tree = ast.parse(Path(connection_events.__file__).read_text(encoding="utf-8"))
    imported = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }
    assert imported == {"__future__", "typing"}, imported


def test_the_ordered_vocabulary_names_each_kind_once() -> None:
    assert len(CONNECTION_EVENT_KIND_ORDER) == len(CONNECTION_EVENT_KINDS)


def test_the_console_filter_offers_the_shared_vocabulary_in_order() -> None:
    monitoring = pytest.importorskip("messagefoundry_webconsole.pages.monitoring")

    rendered = str(monitoring._event_filter(""))
    offered = re.findall(r'<option value="([a-z_]+)"', rendered)
    assert offered == list(CONNECTION_EVENT_KIND_ORDER)


def _kind_collections(source: str) -> list[int]:
    """Line numbers of literal tuples, lists and sets in CODE holding two or more kinds."""
    hits = []
    for node in ast.walk(parse_source(source)):
        if isinstance(node, ast.Tuple | ast.List | ast.Set):
            kinds = set(code_strings(node)) & CONNECTION_EVENT_KINDS
            if len(kinds) >= 2:
                hits.append(node.lineno)
    return hits


def test_the_console_holds_no_copy_of_its_own() -> None:
    # Equality above would also pass for a hand-kept copy that happens to match today. No console
    # module may hold a literal collection of kinds, so the only way a kind list reaches the console
    # is the shared vocabulary. One word such as "closed" alone is not a copy, so it is not flagged.
    # The control shows the probe fires on a planted copy, so an empty answer is a reading.
    assert _kind_collections('_EVENT_KINDS = (\n    "established",\n    "closed",\n)\n') == [1]
    assert _kind_collections('state = "closed"\n') == []
    console = _ROOT / "messagefoundry_webconsole"
    paths = sorted(console.rglob("*.py"))
    assert len(paths) > 20, "the console walk found too few files to mean anything"
    copies = {
        str(path.relative_to(_ROOT)): lines
        for path in paths
        if (lines := _kind_collections(path.read_text(encoding="utf-8")))
    }
    assert not copies, copies


# --- the store refuses an undeclared kind -------------------------------------------------------


def test_the_check_refuses_an_undeclared_kind_and_passes_every_declared_one() -> None:
    for kind in CONNECTION_EVENT_KINDS:
        check_connection_event_kind(kind)
    with pytest.raises(ValueError, match=UNDECLARED):
        check_connection_event_kind(UNDECLARED)


async def test_sqlite_store_writes_every_declared_kind(store: MessageStore) -> None:
    await store.record_connection_events(
        [_event(kind, peer=f"10.0.0.{i}") for i, kind in enumerate(sorted(CONNECTION_EVENT_KINDS))]
    )
    rows = await store.list_connection_events(limit=1000, allowed_channels=None)
    assert {r.kind for r in rows} == CONNECTION_EVENT_KINDS


async def test_sqlite_store_refuses_an_undeclared_kind_on_both_writers(
    store: MessageStore,
) -> None:
    with pytest.raises(ValueError, match=UNDECLARED):
        await store.record_connection_event(
            connection="IB_VOCAB", transport="mllp", direction="inbound", kind=UNDECLARED
        )
    # The declared row beside the undeclared one is not written either. That is because the refusal
    # comes while the parameters are built, before any row is stepped; the burst's rollback is
    # pinned in tests/test_connection_event_burst.py, not here.
    with pytest.raises(ValueError, match=UNDECLARED):
        await store.record_connection_events([_event("established"), _event(UNDECLARED)])
    assert await store.list_connection_events(allowed_channels=None) == []


@pytest.mark.parametrize(
    ("module", "cls"),
    [
        ("messagefoundry.store.postgres", "PostgresStore"),
        ("messagefoundry.store.sqlserver", "SqlServerStore"),
    ],
)
def test_server_backends_refuse_an_undeclared_kind(module: str, cls: str) -> None:
    # The server backends' writers need a live database, which these suites gate. The refusal sits
    # in the shared parameter builder before any cipher or connection use, so it is reachable on a
    # bare instance.
    store_cls = getattr(pytest.importorskip(module), cls)
    bare = object.__new__(store_cls)
    with pytest.raises(ValueError, match=UNDECLARED):
        bare._connection_event_params(_event(UNDECLARED))
