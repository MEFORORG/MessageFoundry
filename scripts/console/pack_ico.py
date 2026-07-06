# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pack PNG frames into a multi-resolution Windows .ico (stdlib only — no imaging deps).

Build step for the console badge: rasterize the source SVG to PNG frames with Inkscape, then run
this to assemble them into ``messagefoundry/console/resources/app.ico``. PNG-embedded frames are
used, which Windows Vista+ reads at every size.

Usage:
    python scripts/console/pack_ico.py <frames_dir> [out.ico]

<frames_dir> must contain frame-<size>.png for each size below; out.ico defaults to
<frames_dir>/app.ico. See messagefoundry/console/resources/README.md for the full recipe.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

SIZES = [16, 24, 32, 48, 64, 128, 256]


def pack(frames_dir: Path, out: Path) -> None:
    frames = [(s, (frames_dir / f"frame-{s}.png").read_bytes()) for s in SIZES]

    # ICONDIR: reserved=0, type=1 (icon), image count.
    header = struct.pack("<HHH", 0, 1, len(frames))
    entries = b""
    blobs = b""
    offset = 6 + 16 * len(frames)  # past the header + one 16-byte ICONDIRENTRY per frame
    for size, data in frames:
        dim = 0 if size >= 256 else size  # the ICO spec encodes 256 as 0
        # width, height, palette colors (0), reserved (0), planes (1), bpp (32), bytes, offset
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
        blobs += data

    out.write_bytes(header + entries + blobs)
    print(f"wrote {out} ({out.stat().st_size} bytes, {len(frames)} frames)")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    frames_dir = Path(argv[1])
    out = Path(argv[2]) if len(argv) > 2 else frames_dir / "app.ico"
    pack(frames_dir, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
