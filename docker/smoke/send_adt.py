# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Self-contained MLLP sender for the container smoke: frame one SYNTHETIC ADT^A01 and assert AA.

Uses only the installed engine package (no samples/ mount needed) and a hard-coded synthetic message
(no PHI). Exits 0 on a positive ACK (MSA-1 starts with 'A'), non-zero otherwise — so the CI smoke can
gate on delivery before it polls the message disposition.
"""

from __future__ import annotations

import asyncio
import sys

from messagefoundry.transports.mllp import MLLPDecoder, frame

# Synthetic ADT^A01 (no PHI). \r segment terminators, as HL7 requires.
ADT_A01 = (
    "MSH|^~\\&|SMOKE_APP|SMOKE_FAC|MEFOR|MEFOR|20260101000000||ADT^A01|SMOKE0001|P|2.5.1\r"
    "EVN|A01|20260101000000\r"
    "PID|1||SMOKE1^^^SMOKE^MR||SYNTHETIC^PATIENT||20000101|U\r"
    "PV1|1|I|WARD^1^A\r"
)


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


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2575
    ack = asyncio.run(_send(host, port, ADT_A01, timeout=10.0)).decode("utf-8", errors="replace")
    print("--- ACK ---")
    print(ack.replace("\r", "\n"))
    # A positive HL7 ACK has MSA-1 in the AA/CA family. Fail loudly on AE/AR or a missing MSA.
    for seg in ack.split("\r"):
        if seg.startswith("MSA|"):
            code = seg.split("|")[1] if len(seg.split("|")) > 1 else ""
            return 0 if code.startswith("A") else 1
    print("no MSA segment in ACK", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
