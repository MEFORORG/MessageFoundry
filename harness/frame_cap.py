# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How the harness's MLLP receivers read a ``max_frame_bytes`` setting.

It matches the engine's MLLP source: ``0`` (or ``None``) turns the cap off. A negative value is
refused here, when the setting is read. A live negative cap would refuse every frame, so a typo would
turn the receiver off while its owner thinks it is capped. Qt-free, so the asyncio sinks and the Qt
Receive tab share it (BACKLOG #1127 follow-up).
"""

from __future__ import annotations

import argparse


def resolve_max_frame_bytes(value: int | None) -> int | None:
    """``value`` as a decoder cap: ``None`` for off (``0`` or ``None``), else the byte count.

    Raises ``ValueError`` for a negative value or a fraction, which would otherwise truncate to a
    live cap of zero."""
    if value is None or value == 0:
        return None
    if value < 0 or value != int(value):
        raise ValueError(
            f"max_frame_bytes must be zero or more whole bytes (0 turns the cap off), got {value!r}"
        )
    return int(value)


def max_frame_bytes_arg(text: str) -> int:
    """``argparse`` type for ``--max-frame-bytes``: a whole number, zero or more."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be zero or more (0 turns the cap off), got {value}")
    return value
