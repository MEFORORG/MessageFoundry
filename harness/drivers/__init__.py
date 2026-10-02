# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Drivers: inject payloads into one kind of engine INBOUND connection.

A driver is the sending half of a scenario. Each transport family is one module here that sets
``KIND`` (the engine's connector kind it feeds, spelled as the registry spells it: ``"mllp"``,
``"file"``, ``"tcp"`` ...) and a ``build(endpoints, key)`` that returns a :class:`Driver` aimed at
the named endpoint. Modules are discovered, so a new family is a new file.

Qt-free and synchronous: a scenario runs on a plain thread or a headless CI runner. A driver
reports a failed send in its :class:`Injection` rather than raising, so a scenario can say how
many of its sends reached the engine.
"""

from __future__ import annotations

import abc
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from types import MappingProxyType
from typing import ClassVar

from harness._discover import family_modules
from harness.endpoints import Endpoints


@dataclass(frozen=True)
class Injection:
    """The outcome of one injected payload: ``error`` is empty on success, and ``reply`` holds
    whatever the inbound answered with (an MLLP ACK, an HTTP body), when it answers at all."""

    error: str = ""
    reply: bytes | None = None


class Driver(abc.ABC):
    """Sends payloads into one inbound connection."""

    kind: ClassVar[str]

    @abc.abstractmethod
    def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
        """Inject each payload, one :class:`Injection` per payload, in order."""


DriverFactory = Callable[[Endpoints, str], Driver]


@cache
def registry() -> Mapping[str, DriverFactory]:
    """Driver factories by connector kind, discovered from this package's family modules."""
    found: dict[str, DriverFactory] = {}
    for module in family_modules(__name__):
        kind = module.KIND
        if kind in found:
            raise ValueError(f"two harness drivers claim connector kind {kind!r}")
        found[kind] = module.build
    return MappingProxyType(found)


def build(kind: str, endpoints: Endpoints, key: str) -> Driver:
    """A driver for connector ``kind`` aimed at endpoint ``key``."""
    try:
        factory = registry()[kind]
    except KeyError:
        raise KeyError(f"no harness driver for connector kind {kind!r}") from None
    return factory(endpoints, key)
