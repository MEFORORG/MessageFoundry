#!/usr/bin/env python
"""Generate the tray's status ``.ico`` assets — pure stdlib, no Pillow (ADR 0113 §8).

Emits one multi-resolution ``.ico`` per (TrayState, taskbar Theme) into ``messagefoundry/tray/assets/``.
Each is a
status-coloured disc with a thin theme-coloured ring so it reads against either taskbar and encodes
the engine state by colour at a glance. This is functional v1 art — a later pass can render richer
glyphs (with Pillow, in the ``[dev]`` extra) without touching the runtime, which only *loads* these
files. The output is checked in; re-run this script only to regenerate.

    python scripts/tray/make_icons.py
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

# The sys.path insert above lets these resolve when run from a bare checkout.
from messagefoundry.tray.state import TrayState  # noqa: E402
from messagefoundry.tray.theme import Theme  # noqa: E402

_SIZES = (16, 24, 32, 48)

# Status colour per state (RGB). Green=healthy, amber=in-transition, gray=down, red=wedged,
# violet=foreign, slate=unknown.
_GREEN = (46, 160, 67)
_AMBER = (219, 154, 4)
_GRAY = (130, 130, 130)
_RED = (218, 54, 51)
_VIOLET = (137, 87, 229)
_SLATE = (110, 118, 129)

_STATUS_RGB = {
    TrayState.RUNNING: _GREEN,
    TrayState.RUNNING_UNMANAGED: _GREEN,
    TrayState.STARTING: _AMBER,
    TrayState.STOPPING: _AMBER,
    TrayState.STOPPED: _GRAY,
    TrayState.NOT_INSTALLED: _GRAY,
    TrayState.WEDGED: _RED,
    TrayState.FOREIGN: _VIOLET,
    TrayState.UNKNOWN: _SLATE,
}

# Ring / glyph colour per taskbar theme (contrasts against the bar).
_RING_RGB = {Theme.LIGHT: (33, 37, 41), Theme.DARK: (233, 236, 239)}


def _bgra_topdown(size: int, status: tuple[int, int, int], ring: tuple[int, int, int]) -> bytes:
    """A top-down BGRA raster: a filled status disc inside a thin ring, transparent elsewhere."""
    px = bytearray(size * size * 4)
    center = (size - 1) / 2.0
    r_disc = size * 0.40
    r_ring = size * 0.46
    for y in range(size):
        for x in range(size):
            dist = ((x - center) ** 2 + (y - center) ** 2) ** 0.5
            if dist <= r_disc:
                col, alpha = status, 255
            elif dist <= r_ring:
                col, alpha = ring, 255
            else:
                col, alpha = (0, 0, 0), 0
            i = (y * size + x) * 4
            px[i], px[i + 1], px[i + 2], px[i + 3] = col[2], col[1], col[0], alpha
    return bytes(px)


def _ico_image(size: int, bgra_topdown: bytes) -> bytes:
    """A single ICO image blob: BITMAPINFOHEADER (32bpp) + bottom-up XOR BGRA + zero AND mask."""
    rows = [bgra_topdown[y * size * 4 : (y + 1) * size * 4] for y in range(size)]
    xor = b"".join(reversed(rows))  # ICO/BMP rasters are bottom-up
    and_stride = ((size + 31) // 32) * 4  # 1bpp mask rows padded to 32-bit boundaries
    and_mask = b"\x00" * (and_stride * size)  # fully opaque; the alpha channel does the shaping
    header = struct.pack(
        "<IiiHHIIiiII",
        40,  # biSize
        size,  # biWidth
        size * 2,  # biHeight = XOR + AND
        1,  # biPlanes
        32,  # biBitCount
        0,  # biCompression (BI_RGB)
        len(xor) + len(and_mask),  # biSizeImage
        0,
        0,
        0,
        0,
    )
    return header + xor + and_mask


def _write_ico(path: Path, status: tuple[int, int, int], ring: tuple[int, int, int]) -> None:
    images = [(s, _ico_image(s, _bgra_topdown(s, status, ring))) for s in _SIZES]
    out = struct.pack("<HHH", 0, 1, len(images))  # ICONDIR: reserved, type=1 (icon), count
    offset = 6 + 16 * len(images)
    entries = b""
    data = b""
    for size, blob in images:
        wh = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", wh, wh, 0, 0, 1, 32, len(blob), offset)
        data += blob
        offset += len(blob)
    path.write_bytes(out + entries + data)


def main() -> None:
    assets = _REPO_ROOT / "messagefoundry" / "tray" / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    count = 0
    for state in TrayState:
        for theme in Theme:
            _write_ico(
                assets / f"{state.value}_{theme.value}.ico", _STATUS_RGB[state], _RING_RGB[theme]
            )
            count += 1
    print(f"wrote {count} .ico files to {assets}")


if __name__ == "__main__":
    main()
