# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How ``GET /search/layered`` finds and validates the one content needle across its presets
(BACKLOG #6700 items 10, 11 and 17). Synthetic data only."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from messagefoundry.api import app as app_module
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry.store.content_search import make_spec
from tests.test_search_presets_api import (  # noqa: F401
    ADT,
    _login,
    _store_criteria,
    _user,
    engine,
)


async def _presets(c: httpx.AsyncClient, h: dict[str, str], *criterias: dict[str, Any]) -> str:
    """Save each criteria as a preset, then return their ids joined for ``presets=``."""
    ids = []
    for i, criteria in enumerate(criterias):
        r = await c.post("/search/presets", json={"name": f"p{i}", "criteria": criteria}, headers=h)
        assert r.status_code == 200, r.text
        ids.append(r.json()["id"])
    return ",".join(ids)


@pytest.mark.parametrize("falsy", [0, False])
async def test_a_falsy_non_text_field_value_on_the_needle_is_refused(
    engine: Engine,  # noqa: F811
    falsy: object,
) -> None:
    """Item 10: ``needle.get("field_value") or None`` dropped a falsy non-text value, so 0 or false
    searched the bare field path, while a truthy one was refused. Both are refused now. The
    control: the same preset with a text value answers 200."""
    pytest.importorskip("psutil")
    service = await _user(engine, Role.OPERATOR, "op")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        pid = await _presets(c, h, {"field_path": "PID-3", "field_value": "MRN999"})
        ok = await c.get("/search/layered", params={"presets": pid}, headers=h)
        assert ok.status_code == 200, ok.text
        await _store_criteria(engine, pid, {"field_path": "PID-3", "field_value": falsy})
        r = await c.get("/search/layered", params={"presets": pid}, headers=h)
        assert r.status_code == 400, r.text
        assert "field_value must be text" in r.json()["detail"]


@pytest.mark.parametrize("falsy", [0, False, []])
async def test_a_falsy_non_text_target_on_the_needle_is_refused(
    engine: Engine,  # noqa: F811
    falsy: object,
) -> None:
    """Item 10, the same rule for ``target``: ``crit.get("target") or "both"`` searched both
    columns for a falsy non-text target, while a truthy one was refused. The control: an absent
    target still reads as ``"both"``."""
    pytest.importorskip("psutil")
    service = await _user(engine, Role.OPERATOR, "op")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        pid = await _presets(c, h, {"content": "MRN999"})
        ok = await c.get("/search/layered", params={"presets": pid}, headers=h)
        assert ok.status_code == 200, ok.text
        await _store_criteria(engine, pid, {"content": "MRN999", "target": falsy})
        r = await c.get("/search/layered", params={"presets": pid}, headers=h)
        assert r.status_code == 400, r.text
        assert "target must be raw, summary or both" in r.json()["detail"]


@pytest.mark.parametrize(
    ("second", "cause"),
    [
        ({"channel_id": "ch1", "field_value": "MRN999"}, "field_value needs an HL7 field path"),
        ({"channel_id": "ch1", "content": 5}, "content must be text"),
        ({"channel_id": "ch1", "field_path": 7}, "field_path must be text"),
        ({"content": "DOE"}, "at most one content predicate"),
    ],
    ids=["lone-field-value", "non-text-content", "non-text-path", "control-second-needle"],
)
async def test_a_malformed_second_needle_is_refused_with_its_own_cause(
    engine: Engine,  # noqa: F811
    second: dict[str, Any],
    cause: str,
) -> None:
    """Item 11: a lone ``field_value``, or a non-text content or path, on a preset beside the
    needle counted as a second needle, so the 400 said "at most one content predicate" rather than
    what was wrong. Each needle is validated as it is found now. The control: a real second needle
    still gets the at-most-one refusal."""
    pytest.importorskip("psutil")
    service = await _user(engine, Role.OPERATOR, "op")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        ids = await _presets(c, h, {"content": "MRN999"}, {"channel_id": "ch1"})
        await _store_criteria(engine, ids.split(",")[1], second)
        r = await c.get("/search/layered", params={"presets": ids}, headers=h)
        assert r.status_code == 400, r.text
        assert cause in r.json()["detail"]


async def test_layered_search_builds_its_spec_once_at_the_requested_scan_limit(
    engine: Engine,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Item 17: the route built the needle's spec at the default scan limit, then built it again
    at the requested one. It builds it once now, and the audit records the requested limit."""
    pytest.importorskip("psutil")
    await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("o", ADT)], control_id="MSG1"
    )
    service = await _user(engine, Role.OPERATOR, "op")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    calls: list[dict[str, Any]] = []

    def counting(**kwargs: Any) -> Any:
        calls.append(kwargs)
        return make_spec(**kwargs)

    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        ids = await _presets(c, h, {"content": "MRN999"}, {"channel_id": "ch1"})
        monkeypatch.setattr(app_module, "make_spec", counting)
        r = await c.get("/search/layered", params={"presets": ids, "scan_limit": 17}, headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["matched"] == 1
    assert len(calls) == 1, calls
    [row] = await engine.store.list_audit(action="preset.layered_search")
    assert json.loads(str(row["detail"]))["scan_limit"] == 17
