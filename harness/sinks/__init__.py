# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Sinks: stand up the peer an engine OUTBOUND connection delivers to, and record what it sent.

A sink is the observing half of a scenario. The API says what the engine decided about a message;
a sink says what actually left the engine, byte for byte. Each transport family is one module here
that sets ``KIND`` (the connector kind it receives from, as the registry spells it) and a
``build(endpoints, key)`` returning a :class:`Sink`. Modules are discovered, so a new family is a
new file.

Every sink binds 127.0.0.1 (:data:`LOOPBACK`) and nothing else, whatever the ``host`` endpoint
says -- that key is the address drivers and engine outbounds DIAL -- so a sink never accepts traffic
from another machine. A family's ``build()`` must keep it that way. A sink records payloads in
memory for the scenario to assert on and never logs them: the harness sends synthetic data, but a
sink must not become the place where a full message body reaches a log.
"""

from __future__ import annotations

import abc
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import cache
from types import MappingProxyType, TracebackType
from typing import ClassVar, Self

from harness._discover import family_modules
from harness.endpoints import Endpoints

#: The only address a sink binds.
LOOPBACK = "127.0.0.1"


@dataclass(frozen=True)
class Record:
    """One thing an outbound delivered: the payload bytes, plus transport detail in ``meta``
    (a peer address, a file path, a method and URL path, a header)."""

    payload: bytes
    meta: Mapping[str, str] = field(default_factory=dict)


class Sink(abc.ABC):
    """A peer for one outbound connection. Use as a context manager: started on enter, stopped
    on exit, even when the scenario fails."""

    kind: ClassVar[str]

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[Record] = []

    def start(self) -> None:  # noqa: B027  (an optional hook: not every sink needs one)
        """Begin accepting deliveries."""

    def stop(self) -> None:  # noqa: B027
        """Stop accepting deliveries and release the port or handle."""

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    def _add(self, record: Record) -> None:
        with self._lock:
            self._records.append(record)

    def records(self) -> list[Record]:
        """A snapshot of everything received so far, in arrival order."""
        with self._lock:
            return list(self._records)

    def wait_for(
        self, done: Callable[[list[Record]], bool], timeout: float, *, interval: float = 0.1
    ) -> list[Record]:
        """Poll :meth:`records` until ``done`` holds or ``timeout`` passes; return the last
        snapshot either way, so the caller reports what did arrive."""
        deadline = time.monotonic() + timeout
        while True:
            snapshot = self.records()
            if done(snapshot) or time.monotonic() >= deadline:
                return snapshot
            time.sleep(interval)


SinkFactory = Callable[[Endpoints, str], Sink]


@cache
def registry() -> Mapping[str, SinkFactory]:
    """Sink factories by connector kind, discovered from this package's family modules."""
    found: dict[str, SinkFactory] = {}
    for module in family_modules(__name__):
        kind = module.KIND
        if kind in found:
            raise ValueError(f"two harness sinks claim connector kind {kind!r}")
        found[kind] = module.build
    return MappingProxyType(found)


def build(kind: str, endpoints: Endpoints, key: str) -> Sink:
    """A sink for connector ``kind`` at endpoint ``key``."""
    try:
        factory = registry()[kind]
    except KeyError:
        raise KeyError(f"no harness sink for connector kind {kind!r}") from None
    return factory(endpoints, key)
