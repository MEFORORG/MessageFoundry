# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No two co-running compose services publish one host port (BACKLOG #5828).

A service with no ``profiles`` key runs under every profile, so the default ``engine`` runs beside
the ``ha`` pair under ``docker compose --profile ha up``. Both it and ``engine-ha`` published host
port 2575, so that documented command would fail on the second bind. Each profile's co-running
set is checked, with a negative control that the check sees a collision.

Ports are keyed on number and protocol, not host address: a wildcard bind conflicts with any
address on the same port, so comparing addresses would miss a real collision.
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


def _host_port(entry: object) -> str | None:
    """``<port>/<protocol>`` on the host for a ``ports`` entry, or None when it publishes none."""
    if isinstance(entry, dict):
        published = entry.get("published")
        return f"{published}/{entry.get('protocol', 'tcp')}" if published else None
    spec, _, proto = str(entry).partition("/")
    parts = spec.split(":")
    return f"{parts[-2]}/{proto or 'tcp'}" if len(parts) > 1 and parts[-2] else None


def _duplicates(doc: dict[str, Any], active: frozenset[str]) -> dict[str, int]:
    ports: Counter[str] = Counter()
    for svc in doc["services"].values():
        profiles = set(svc.get("profiles") or [])
        if profiles and not profiles & active:
            continue
        ports.update(p for p in map(_host_port, svc.get("ports") or []) if p)
    return {port: n for port, n in ports.items() if n > 1}


def test_every_profile_is_covered() -> None:
    assert _profiles(_compose_doc()) <= set().union(*_PROFILE_SETS)


@pytest.mark.parametrize("active", _PROFILE_SETS, ids=lambda s: ",".join(sorted(s)) or "default")
def test_no_two_co_running_services_publish_one_host_port(active: frozenset[str]) -> None:
    dup = _duplicates(_compose_doc(), active)
    assert not dup, f"host ports published twice under profiles {sorted(active)}: {dup}"


@pytest.mark.parametrize(
    "planted",
    ("2575:2575", "127.0.0.1:2575:2575", {"target": 2575, "published": 2575}),
    ids=("short", "host-address", "long"),
)
def test_the_check_sees_a_collision(planted: object) -> None:
    """Negative control: engine-ha publishing the default engine's MLLP host port is found."""
    doc = copy.deepcopy(_compose_doc())
    svc = doc["services"]["engine-ha"]
    svc["ports"] = [*svc["ports"], planted]
    assert _duplicates(doc, frozenset({"ha"})) == {"2575/tcp": 2}
    assert not _duplicates(doc, frozenset())


@pytest.mark.parametrize("entry", ("2575", "2575:2575/udp", {"target": 2575}))
def test_a_container_only_or_other_protocol_entry_is_no_collision(entry: object) -> None:
    doc = copy.deepcopy(_compose_doc())
    svc = doc["services"]["engine-ha"]
    svc["ports"] = [*svc["ports"], entry]
    assert not _duplicates(doc, frozenset({"ha"}))
