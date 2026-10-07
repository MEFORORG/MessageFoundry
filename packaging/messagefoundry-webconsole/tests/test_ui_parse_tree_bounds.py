# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2762: the parse-tree page is capped and built off the event loop.

``/ui/messages/{id}/parse-tree`` builds a node for every field, component and subcomponent, and the
console shares the engine's event loop. One field made of component separators is a few bytes per
node, so a body under the 16 MiB cap would build millions of nodes there. The page now says the
tree is too large and links the raw view past ``MAX_TREE_NODES``, and the build and render run in a
worker thread. An ordinary message still renders its tree, which is the control arm for both.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from _ui_clients import ADT, auth_service, cookie_login, provision, ui_client

from messagefoundry.auth import Role
from messagefoundry.parsing.tree import MAX_TREE_NODES
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole import pages
from messagefoundry_webconsole.routes import core

#: One PID field of component separators, a node per separator: past the cap with room to spare.
_TOO_LARGE = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|BIG1|P|2.5.1\rPID|1||" + "^" * (
    MAX_TREE_NODES + 10
)


async def _seed(engine: Engine, raw: str) -> str:
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=raw,
        deliveries=[("archive", raw)],
        control_id=None,
        message_type="ADT^A01",
        source_type="file",
    )


async def _get_trees(engine: Engine, *raws: str) -> list[tuple[str, str]]:
    """Each body's message id and parse-tree page, fetched by one signed-in operator."""
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    ids = [await _seed(engine, raw) for raw in raws]
    out = []
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        for mid in ids:
            r = await c.get(f"/ui/messages/{mid}/parse-tree")
            assert r.status_code == 200
            out.append((mid, r.text))
    return out


async def test_a_tree_past_the_cap_says_so_and_links_the_raw_view(engine: Engine) -> None:
    (big_id, big), (_ok_id, ok) = await _get_trees(engine, _TOO_LARGE, ADT)
    assert "too large to render" in big
    assert f'href="/ui/messages/{big_id}/body"' in big
    assert "PID-3.1" not in big  # no partial tree
    # Control: an ordinary message renders its tree on the same route.
    assert "too large to render" not in ok
    assert "PID-5" in ok and "DOE" in ok


async def test_the_tree_is_built_and_rendered_off_the_event_loop(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    on_loop: dict[str, bool] = {}

    def _running_loop() -> bool:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return False
        return True

    real_parse, real_page = core.parse_tree, pages.parse_tree_page

    def spy_parse(raw: str) -> Any:
        on_loop["parse"] = _running_loop()
        return real_parse(raw)

    def spy_page(message_id: str, nodes: Any) -> Any:
        on_loop["render"] = _running_loop()
        return real_page(message_id, nodes)

    monkeypatch.setattr(core, "parse_tree", spy_parse)
    monkeypatch.setattr(pages, "parse_tree_page", spy_page)
    ((_mid, page),) = await _get_trees(engine, ADT)
    assert "PID-5" in page  # the spies ran the real thing
    # Both ran, and neither on a thread with a running event loop.
    assert on_loop == {"parse": False, "render": False}
