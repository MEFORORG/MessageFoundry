# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Synthetic PEM-shaped fixtures, assembled at run time (BACKLOG #5550).

The secret scanner the commit hooks run reads a literal PEM marker or a long base64 run in the
source as a leaked key. These fixtures hold no key, so they are built here, in code, rather than
written out: the markers from their parts, and the base64 runs from a seeded generator, so every
run reads the same values. Nothing here is real key material.
"""

from __future__ import annotations

import random
import string

#: The base64 alphabet a key body line is drawn from.
_B64 = string.ascii_letters + string.digits + "+/"


def pem_marker(edge: str, kind: str) -> str:
    """The ``edge`` (``BEGIN`` or ``END``) marker line of a ``kind`` block, such as
    ``RSA PRIVATE KEY``."""
    return "-" * 5 + edge + " " + kind + "-" * 5


def pem_block(kind: str, sep: str, *lines: str, end: bool = True) -> str:
    """A ``kind`` block holding ``lines``, joined by ``sep``, with its END marker unless ``end`` is
    False."""
    parts = [pem_marker("BEGIN", kind), *lines]
    if end:
        parts.append(pem_marker("END", kind))
    return sep.join(parts)


def b64_run(seed: int, length: int) -> str:
    """``length`` base64 characters, drawn from a generator seeded with ``seed``."""
    rng = random.Random(seed)
    return "".join(rng.choice(_B64) for _ in range(length))
