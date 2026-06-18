# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Send an HL7 file to a running MLLP listener and print the ACK it returns.

A tiny manual-testing helper for a running engine. With the sample channel
(``adt_mllp_to_file.py``) the engine listens on port 2575, so:

    python samples/send_mllp.py samples/messages/adt_a01.hl7
    python samples/send_mllp.py samples/messages/adt_a01.hl7 --host 127.0.0.1 --port 2575

It reuses the engine's own (tested) MLLP framing, so it frames the message correctly
(``0x0B … 0x1C 0x0D``) and decodes the framed ACK before printing it.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from messagefoundry.parsing import normalize
from messagefoundry.transports.mllp import MLLPDecoder, frame


async def _send(host: str, port: int, payload: str, timeout: float) -> bytes:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(frame(payload))
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
        try:
            await writer.wait_closed()
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="path to an HL7 v2 message file")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2575)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    payload = normalize(Path(args.file).read_bytes())
    ack = asyncio.run(_send(args.host, args.port, payload, args.timeout))
    print("--- ACK ---")
    print(ack.decode("utf-8", errors="replace").replace("\r", "\n"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
