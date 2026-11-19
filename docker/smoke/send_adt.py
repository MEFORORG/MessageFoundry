# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Self-contained MLLP sender for the container smoke: frame one SYNTHETIC ADT^A01 and assert AA or CA.

Uses only the installed engine package (no samples/ mount needed) and a hard-coded synthetic message
(no PHI). Exits 0 on a positive ACK (MSA-1 exactly AA or CA), non-zero otherwise — so the CI smoke can
gate on delivery before it polls the message disposition.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys

from messagefoundry.mllpcodec import MLLPDecoder, frame
from messagefoundry.parsing.peek import HL7PeekError, Peek

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
        with contextlib.suppress(OSError):
            await writer.wait_closed()


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2575
    ack = asyncio.run(_send(host, port, ADT_A01, timeout=10.0)).decode("utf-8", errors="replace")
    print("--- ACK ---")
    print(ack.replace("\r", "\n"))
    return ack_exit_code(ack)


#: The only MSA-1 codes that mean the message was accepted: original-mode AA and enhanced-mode
#: commit accept CA. A prefix test on 'A' would pass AE and AR and refuse CA.
_POSITIVE_ACK_CODES = frozenset({"AA", "CA"})


def ack_exit_code(ack: str) -> int:
    """0 when the ACK's MSA-1 is exactly AA or CA, 1 for anything else.

    Read through the engine's own separator-aware Peek, as its MLLP client reads an ACK. Fails
    closed: AE, AR, CE, CR, an empty or unknown code, a missing MSA-1 and an unparseable ACK all
    exit 1.
    """
    try:
        code = Peek.parse(ack).field("MSA-1")
    except HL7PeekError as exc:
        print(f"unparseable ACK: {exc}", file=sys.stderr)
        return 1
    if code in _POSITIVE_ACK_CODES:
        return 0
    if code is None:
        print("no MSA-1 in ACK", file=sys.stderr)
        return 1
    print(f"MSA-1 {code!r} is not AA or CA", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
