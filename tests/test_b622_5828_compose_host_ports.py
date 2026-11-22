# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No two co-running compose services publish one host port (BACKLOG #5828).

A service with no ``profiles`` key runs under every profile, so the default ``engine`` runs beside
the ``ha`` pair under ``docker compose --profile ha up``. Both it and ``engine-ha`` published host
port 2575, so that documented command would fail on the second bind. Each profile's co-running
set is checked, with a negative control that the check sees a collision.
"""

from __future__ import annotations

import copy
from collections import Counter
from typing import Any

import pytest

from tests.test_compose_revocation_attestation import _compose_doc

#: The profile sets a reader would run: the default ``up`` and ``--profile ha up``.
_PROFILE_SETS: tuple[frozenset[str], ...] = (frozenset(), frozenset({"ha"}))


def _profiles(doc: dict[str, Any]) -> set[str]:
    return {p for svc in doc["services"].values() for p in svc.get("profiles") or []}


def _host_port(entry: object) -> str:
    """The host side of a short-syntax ``[ip:]host:container`` entry, or a long-syntax mapping's."""
    if isinstance(entry, dict):
        return f"{entry.get('host_ip', '')}:{entry['published']}"
    parts = str(entry).split(":")
    assert len(parts) in (2, 3), f"no host port in {entry!r}"
    return f"{parts[0] if len(parts) == 3 else ''}:{parts[-2]}"


def _duplicates(doc: dict[str, Any], active: frozenset[str]) -> dict[str, int]:
    ports: Counter[str] = Counter()
    for svc in doc["services"].values():
        profiles = set(svc.get("profiles") or [])
        if profiles and not profiles & active:
            continue
        ports.update(_host_port(p) for p in svc.get("ports") or [])
    return {port: n for port, n in ports.items() if n > 1}


def test_every_profile_is_covered() -> None:
    assert _profiles(_compose_doc()) <= set().union(*_PROFILE_SETS)


@pytest.mark.parametrize("active", _PROFILE_SETS, ids=lambda s: ",".join(sorted(s)) or "default")
def test_no_two_co_running_services_publish_one_host_port(active: frozenset[str]) -> None:
    dup = _duplicates(_compose_doc(), active)
    assert not dup, f"host ports published twice under profiles {sorted(active)}: {dup}"


def test_the_check_sees_a_collision() -> None:
    """Negative control: engine-ha publishing the default engine's MLLP host port again is found."""
    doc = copy.deepcopy(_compose_doc())
    doc["services"]["engine-ha"]["ports"] = [*doc["services"]["engine-ha"]["ports"], "2575:2575"]
    assert _duplicates(doc, frozenset({"ha"})) == {":2575": 2}
    assert not _duplicates(doc, frozenset())
