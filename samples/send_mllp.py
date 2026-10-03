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

The ACK is the peer's text, printed to a terminal, so every control character in it except newline
and tab -- C0, DEL and C1, after CR becomes a newline -- is printed as a visible ``\\xNN`` escape. A
peer could otherwise move the cursor, retitle the window or rewrite what was printed above it with
an escape sequence (ASVS 1.1.2).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys
from pathlib import Path

from messagefoundry.mllpcodec import FramePayloadError, MLLPDecoder, frame_checked
from messagefoundry.parsing import normalize

#: The exit status for a refused file. Not 2, which argparse uses for a usage error.
_REFUSED = 3

#: Each C0 control but newline and tab, DEL, and each C1 control, mapped to a visible escape.
_CONTROL_ESCAPES = {
    code: f"\\x{code:02x}"
    for code in (*range(0x20), 0x7F, *range(0x80, 0xA0))
    if chr(code) not in "\n\t"
}


def _printable(ack: bytes) -> str:
    """The ACK as text that is safe to print to a terminal: CR as a newline, every other control
    character but tab as ``\\xNN``."""
    return ack.decode("utf-8", errors="replace").replace("\r", "\n").translate(_CONTROL_ESCAPES)


async def _send(host: str, port: int, wire: bytes, timeout: float) -> bytes:
    """Send one already-framed message and return the body of the first framed reply."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(wire)
        await writer.drain()
        decoder = MLLPDecoder()
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout)
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
    ack = asyncio.run(_send(args.host, args.port, wire, args.timeout))
    print("--- ACK ---")
    print(_printable(ack))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
