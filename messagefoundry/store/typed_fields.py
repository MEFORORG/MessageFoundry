# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One injective byte encoding for a list of named, typed fields.

A MAC is only as strong as the bytes it covers are unambiguous. This encoder writes each field as
its name, a one-byte type tag and its value, each length-prefixed, so:

* two different field lists never produce the same bytes -- no value can run into its neighbour,
  and no crafted string can imitate a field boundary;
* ``None``, the empty string and the text ``"None"`` are three different encodings;
* an integer and a float of the same magnitude differ, and a float is written with
  :meth:`float.hex`, which round-trips every finite value exactly and does not depend on a
  locale or a ``repr`` rule.

The audit chain's row MAC is its first user (vault BACKLOG #2594). It imports nothing from the
engine and holds no key, so any later integrity tag can share it.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable

__all__ = ["TypedValue", "encode_typed_fields"]

#: What a field may hold. These are the Python types the three store drivers return for a text,
#: integer or floating-point column, plus ``bytes`` for a SQLite cell written as a blob.
TypedValue = str | int | float | bytes | None

_NONE = b"N"
_INT = b"I"
_FLOAT = b"F"
_STR = b"S"
_BYTES = b"B"


def _prefixed(data: bytes) -> bytes:
    """``data`` behind its own 4-byte big-endian length."""
    return struct.pack(">I", len(data)) + data


def encode_typed_fields(fields: Iterable[tuple[str, TypedValue]]) -> bytes:
    """Encode ``fields`` -- ``(name, value)`` pairs, in the caller's order -- to canonical bytes.

    Raises ``TypeError`` for a value outside :data:`TypedValue`, ``bool`` included: a caller that
    means an integer passes an integer, so ``True`` can never be read back as ``1``. A lone
    surrogate in a string encodes rather than raising (``surrogatepass``), so the mapping is total
    over every ``str`` CPython can hold."""
    out = bytearray()
    for name, value in fields:
        if value is None:
            tag, body = _NONE, b""
        elif isinstance(value, bool):
            raise TypeError(f"field {name!r}: bool is not an encodable type")
        elif isinstance(value, int):
            tag, body = _INT, str(value).encode("ascii")
        elif isinstance(value, float):
            tag, body = _FLOAT, value.hex().encode("ascii")
        elif isinstance(value, str):
            tag, body = _STR, value.encode("utf-8", "surrogatepass")
        elif isinstance(value, bytes):
            tag, body = _BYTES, value
        else:
            raise TypeError(f"field {name!r}: {type(value).__name__} is not an encodable type")
        out += _prefixed(name.encode("utf-8"))
        out += tag
        out += _prefixed(body)
    return bytes(out)
