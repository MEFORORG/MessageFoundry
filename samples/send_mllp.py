# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Send an HL7 file to a running MLLP listener and print the ACK it returns.

A tiny manual-testing helper for a running engine. With the sample channel
(``adt_mllp_to_file.py``) the engine listens on port 2575, so:

    python samples/send_mllp.py samples/messages/adt_a01.hl7
    python samples/send_mllp.py samples/messages/adt_a01.hl7 --host 127.0.0.1 --port 2575

It reuses the engine's own (tested) MLLP framing, so it frames the message correctly
(``0x0B … 0x1C 0x0D``) and decodes the framed ACK before printing it.

It frames with ``frame_checked``, so it refuses a file by the rule the engine's own MLLP delivery
refuses a payload by (ADR 0205 rule 1, stated once at ``FrameCodec.find_frame_byte``), before it
connects. That includes a file saved with its own MLLP framing around it: strip that first. The
reason goes to stderr and the exit status is 3. The position it names is a 0-based byte offset in
the message as it would be sent, not in the file as saved: line endings are collapsed to CR first,
and a byte that is not valid UTF-8 becomes U+FFFD, three bytes.

It sends the whole file as ONE frame. A listener takes one message per frame and answers ``AR``
(MSA-3 ``more than one MSH in body``) to a frame holding several (ADR 0206), so
``samples/messages/adt_batch.hl7``, five messages with no envelope, is refused here. Drop a batch
file in a ``File(...)`` inbox instead, which splits it into one message each.

The ACK is the peer's text, printed to a terminal, so it is printed as printable ASCII, newline and
tab only (ASVS 1.1.2). CR becomes a newline. Every other character -- a C0 control such as ESC or
DEL as ``\\xNN``, and every code point past ASCII, a C1 control, a bidirectional override or an
accented letter alike, as ``\\uNNNN`` or ``\\UNNNNNNNN`` -- is printed as a visible escape, and a
byte that is not UTF-8 as ``\\ufffd``. A backslash is doubled only where it would otherwise read as
the start of one of those escapes, so an ordinary ACK, ``MSH|^~\\&|`` included, prints unchanged.
A peer could otherwise move the cursor, retitle the window, rewrite what was printed above it or
reorder what it shows, and a character a Windows console cannot encode would stop the print. The
reply is read under the engine's frame cap and one overall deadline, so a peer that never ends its
frame, or trickles it, cannot hold the helper.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import re
import sys
from pathlib import Path

from messagefoundry.mllpcodec import (
    DEFAULT_MAX_FRAME_BYTES,
    FramePayloadError,
    MLLPDecoder,
    MLLPFrameError,
    frame_checked,
)
from messagefoundry.parsing import normalize

#: The exit status for a refused file. Not 2, which argparse uses for a usage error.
_REFUSED = 3


class _Escapes(dict[int, str]):
    """A ``str.translate`` table that computes each code point's printed form once, on first use:
    itself when printable ASCII, newline or tab, else ``\\xNN`` (ASCII) or ``\\uNNNN``/``\\UNNNNNNNN``."""

    def __missing__(self, code: int) -> str:
        if code in (0x09, 0x0A) or 0x20 <= code <= 0x7E:
            shown = chr(code)
        elif code < 0x80:
            shown = f"\\x{code:02x}"
        else:
            shown = f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"
        self[code] = shown
        return shown


_ESCAPES = _Escapes()

#: A backslash that would read as the start of an escape: one before x, u, U or another backslash,
#: or before a character that is itself about to be escaped. Only that one is doubled.
_AMBIGUOUS_BACKSLASH = re.compile(r"\\(?=[\\xuU]|[^\t\n -~])")


def _printable(ack: bytes) -> str:
    """The ACK as text that is safe to print to any terminal: see the module docstring."""
    text = ack.decode("utf-8", errors="replace").replace("\r", "\n")
    return _AMBIGUOUS_BACKSLASH.sub(r"\\\\", text).translate(_ESCAPES)


async def _send(host: str, port: int, wire: bytes, timeout: float) -> bytes:
    """Send one already-framed message and return the body of the first framed reply."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(wire)
        await writer.drain()
        decoder = MLLPDecoder(max_frame_bytes=DEFAULT_MAX_FRAME_BYTES)
        # One deadline for the whole reply, not one per read, so a peer that trickles bytes cannot
        # keep the helper waiting.
        async with asyncio.timeout(timeout):
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    raise RuntimeError("peer closed before sending an ACK")
                for message in decoder.feed(chunk):
                    return message
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="path to an HL7 v2 message file")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2575)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    payload = normalize(Path(args.file).read_bytes())
    # Framed BEFORE dialling, so a refused file never opens a connection. normalize() decodes with
    # errors="replace", so re-encoding as UTF-8 cannot fail and FrameEncodeError cannot arise here.
    try:
        wire = frame_checked(payload)
    except FramePayloadError as exc:
        print(f"send_mllp: {exc}", file=sys.stderr)
        return _REFUSED
    try:
        ack = asyncio.run(_send(args.host, args.port, wire, args.timeout))
    except MLLPFrameError as exc:  # the cap, named by size only: the reply's content is not quoted
        print(f"send_mllp: reply refused: {exc}", file=sys.stderr)
        return 1
    print("--- ACK ---")
    print(_printable(ack))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
