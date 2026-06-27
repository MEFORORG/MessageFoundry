# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shard registry: the console's list of engine endpoints ("shards") it can manage.

The console historically talked to exactly one engine (the ``--url`` value). A larger
deployment runs several engines (shards) — e.g. one per partner site, or a sharded
high-throughput cluster — and an operator wants one console that switches between them
rather than relaunching with a different ``--url`` each time.

This module owns the *data* side of that: a small, well-typed registry of
``Shard{id, name, base_url}`` records persisted in **QSettings** (the same store the
console already uses for the auto-refresh interval), plus the id of the currently active
shard. It deliberately holds **no** ``EngineClient`` and does **no** networking — the shell
owns the per-shard clients and refresh wiring (keep widgets/clients out of here so the
registry stays unit-testable without Qt widgets or a live server).

Backward compatibility: when nothing has been configured, :meth:`ShardRegistry.ensure_default`
seeds a single shard from the launch ``--url``, so an existing single-engine launch (and every
existing console test) behaves exactly as before — one shard, already active.

Persistence layout (under the console's existing ``MessageFoundry``/``Console`` QSettings):

* ``shards/registry`` — a JSON array of ``{"id", "name", "base_url"}`` objects.
* ``shards/active`` — the id string of the active shard.

JSON (rather than QSettings' array API) keeps the value a single portable blob that round-trips
identically across the registry (Windows) and the in-memory/INI backends the tests use.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass

from PySide6.QtCore import QSettings

__all__ = ["Shard", "ShardRegistry", "REGISTRY_KEY", "ACTIVE_KEY"]

_log = logging.getLogger(__name__)

REGISTRY_KEY = "shards/registry"
ACTIVE_KEY = "shards/active"


@dataclass(frozen=True)
class Shard:
    """One managed engine endpoint.

    ``id`` is a stable, opaque handle (the keyring tokens are keyed by ``base_url``, not this id,
    so the id is purely the registry's own primary key). ``name`` is the human label shown in the
    selector; ``base_url`` is what an :class:`~messagefoundry.console.client.EngineClient` connects
    to.
    """

    id: str
    name: str
    base_url: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "base_url": self.base_url}

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "Shard":
        """Build a Shard from a persisted JSON object, coercing each field to ``str``.

        Raises ``ValueError`` if the required keys are missing/empty so a corrupt blob is rejected
        by the caller rather than silently producing a half-formed shard."""
        shard_id = str(data.get("id", "")).strip()
        base_url = str(data.get("base_url", "")).strip()
        if not shard_id or not base_url:
            raise ValueError("shard entry missing 'id' or 'base_url'")
        # A missing/blank name falls back to the URL so the selector always has something to show.
        name = str(data.get("name", "")).strip() or base_url
        return cls(id=shard_id, name=name, base_url=base_url)


def new_shard_id() -> str:
    """A fresh opaque shard id."""
    return uuid.uuid4().hex


class ShardRegistry:
    """Load/save/list the configured shards and track which one is active.

    Thin wrapper over :class:`QSettings`; all logic (defaulting, dedup, active tracking) lives here
    so the shell can stay a thin view. Construct with the console's :class:`QSettings` (org
    ``MessageFoundry`` / app ``Console``); pass an in-memory ``QSettings`` in tests.
    """

    def __init__(self, settings: QSettings) -> None:
        self._settings = settings
        self._shards: list[Shard] = self._load()
        self._active_id: str | None = self._load_active()

    # --- persistence ---------------------------------------------------------

    def _load(self) -> list[Shard]:
        raw = self._settings.value(REGISTRY_KEY)
        if not raw:
            return []
        try:
            data = json.loads(str(raw))
        except (ValueError, TypeError) as exc:
            # A corrupt blob must never wedge the console — log and start empty (the launch URL then
            # re-seeds a default shard, the same as a first run).
            _log.warning("ignoring unreadable shard registry: %s", exc)
            return []
        if not isinstance(data, list):
            _log.warning(
                "ignoring shard registry: expected a JSON array, got %s", type(data).__name__
            )
            return []
        shards: list[Shard] = []
        seen: set[str] = set()
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                shard = Shard.from_dict(item)
            except ValueError as exc:
                _log.warning("skipping malformed shard entry: %s", exc)
                continue
            if shard.id in seen:  # ids are the primary key — drop a duplicate rather than carry two
                continue
            seen.add(shard.id)
            shards.append(shard)
        return shards

    def _load_active(self) -> str | None:
        raw = self._settings.value(ACTIVE_KEY)
        active = str(raw).strip() if raw else ""
        if active and any(s.id == active for s in self._shards):
            return active
        # No stored active (or it points at a now-deleted shard): fall back to the first shard.
        return self._shards[0].id if self._shards else None

    def _save(self) -> None:
        blob = json.dumps([s.to_dict() for s in self._shards])
        self._settings.setValue(REGISTRY_KEY, blob)
        self._settings.setValue(ACTIVE_KEY, self._active_id or "")
        self._settings.sync()

    # --- queries -------------------------------------------------------------

    def list(self) -> list[Shard]:
        """All configured shards, in registry order."""
        return list(self._shards)

    def get(self, shard_id: str) -> Shard | None:
        return next((s for s in self._shards if s.id == shard_id), None)

    def active(self) -> Shard | None:
        """The active shard (``None`` only when the registry is empty)."""
        if self._active_id is None:
            return None
        return self.get(self._active_id)

    @property
    def active_id(self) -> str | None:
        return self._active_id

    def is_empty(self) -> bool:
        return not self._shards

    # --- mutations -----------------------------------------------------------

    def ensure_default(self, base_url: str, *, name: str = "Default") -> Shard:
        """Seed a single default shard from ``base_url`` when the registry is empty, then return the
        active shard.

        This is the backward-compatibility seam: an existing single-engine launch (``--url`` only,
        no configured shards) gets exactly one shard, already active — so the console behaves as it
        always has. If a shard with this ``base_url`` already exists it is reused (and made active if
        nothing else is) rather than duplicated; if the registry already has shards but none active,
        the first becomes active."""
        existing = next((s for s in self._shards if s.base_url == base_url.rstrip("/")), None)
        if existing is not None:
            if self._active_id is None:
                self.set_active(existing.id)
            return existing
        if self._shards:
            # Already configured (different URL): don't inject the launch URL; just guarantee an
            # active selection and return it.
            if self._active_id is None:
                self.set_active(self._shards[0].id)
            active = self.active()
            assert active is not None  # _shards is non-empty here
            return active
        shard = self.add(name=name, base_url=base_url, make_active=True)
        return shard

    def add(self, *, name: str, base_url: str, make_active: bool = False) -> Shard:
        """Append a new shard and persist. Becomes active if it is the first shard or ``make_active``."""
        shard = Shard(
            id=new_shard_id(), name=name.strip() or base_url, base_url=base_url.rstrip("/")
        )
        self._shards.append(shard)
        if make_active or self._active_id is None:
            self._active_id = shard.id
        self._save()
        return shard

    def set_active(self, shard_id: str) -> bool:
        """Make ``shard_id`` the active shard. Returns ``False`` (no-op) if it isn't registered."""
        if not any(s.id == shard_id for s in self._shards):
            return False
        if shard_id != self._active_id:
            self._active_id = shard_id
            self._save()
        return True

    def remove(self, shard_id: str) -> bool:
        """Remove a shard. If it was active, the active selection moves to the first remaining shard
        (or ``None`` when the registry empties). Returns ``False`` if it wasn't registered."""
        before = len(self._shards)
        self._shards = [s for s in self._shards if s.id != shard_id]
        if len(self._shards) == before:
            return False
        if self._active_id == shard_id:
            self._active_id = self._shards[0].id if self._shards else None
        self._save()
        return True
