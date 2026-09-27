# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Configurable delimiter framing, re-exported from its leaf home :mod:`messagefoundry.framing`.

The codec moved out of ``transports/`` so a client can import it without registering every
connector (BACKLOG #1697). Engine callers keep importing it from here.
"""

from __future__ import annotations

from messagefoundry.framing import (
    MLLP_CODEC,
    PRESETS,
    STX_ETX_CODEC,
    FrameCodec,
    FrameDecoder,
    FrameError,
    codec_for,
)

__all__ = [
    "FrameError",
    "FrameCodec",
    "FrameDecoder",
    "MLLP_CODEC",
    "STX_ETX_CODEC",
    "PRESETS",
    "codec_for",
]
