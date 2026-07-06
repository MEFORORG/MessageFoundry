# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Minimal self-contained smoke config for the container CI leg: receive ADT over MLLP, archive to file.

Deliberately tiny and dependency-free — no code sets, no env() refs, no optional extras (fhir/dicom) —
so the slim engine image can serve it with nothing mounted but this directory. The container CI smoke
(.github/workflows/ci.yml) sends one synthetic ADT^A01 over MLLP and asserts it finalizes to PROCESSED.

The File output goes under /var/lib/mefor (the writable store volume in the image), so it works on a
read-only root filesystem. Every ADT is archived (no event filter) so the smoke's message always
reaches a terminal PROCESSED disposition; a non-ADT message would be logged UNROUTED.
"""

from messagefoundry import File, MLLP, Send, handler, inbound, outbound, router

inbound("IB_Test_ADT", MLLP(port=2575), router="adt_router")
outbound("FILE-OUT_Test_ADT", File(directory="/var/lib/mefor/out/adt", filename="{MSH-10}.hl7"))


@router("adt_router")
def route(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.1"] != "ADT":
        return []  # not ADT — routed nowhere (logged UNROUTED)
    return ["archive"]


@handler("archive")
def archive(msg):  # type: ignore[no-untyped-def]
    return Send("FILE-OUT_Test_ADT", msg)
