# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Worked example — a Wave-1 *porting template* for an ORU results relay.

This is the canonical shape almost every migrated feed follows: an inbound MLLP listener → a
**Router** (which feeds care about) → a **Handler** (filter → transform → fan-out) → outbound
connections, with reference data in a **code set** and per-environment endpoints via **`env()`**.

It is **fully synthetic** (no real partners/sites) and exists to (1) document the authoring pattern
end-to-end and (2) exercise the mutable-``Message`` repetition/segment API in CI — it is gated by
``messagefoundry check`` (validate + dryrun over ``messages/``) via ``tests/test_checks.py``.

Scenario: a lab (LABCO) sends an ``ORU^R01`` over MLLP. We relay it to the EHR and archive a copy,
after:
  - collapsing PID-3's identifier repetition list to the single **MR** identifier the EHR wants,
  - dropping **cancelled** results (OBX-11 = ``X``), and
  - remapping each local test code (OBX-3.1) to the EHR's code via a code set,
  - rebuilding the OBX block in place (renumbered) — the *repeating-segment rebuild* that the
    mutable-``Message`` API makes first-class (``count_segments`` / ``field(occurrence=…)`` /
    ``repetitions`` / ``delete_segments`` / ``add_segment``).

Run it locally::

    python -m messagefoundry serve --config samples/results_relay --env dev --db ./mf.db
    python -m messagefoundry dryrun --config samples/results_relay \\
        --messages samples/results_relay/messages --show-phi
"""

from messagefoundry import File, MLLP, Send, code_set, env, handler, inbound, outbound, router
from messagefoundry.parsing.message import Message

OB_EHR = "OB_EHR_ORU"
FILE_ARCHIVE = "FILE-OUT_LABCO_ORU"

# Inbound takes only a port (binds the service-wide [inbound].bind_host). The downstream EHR peer and
# the archive directory differ by environment, so they're env()-driven; the defaults keep the example
# runnable locally and let `check`/dryrun resolve without an env file:
#     environments/prod.toml     ->  ehr_host = "ehr.prod.example", ehr_port = 2999, archive_dir = "D:/hl7/labco"
#     environments/staging.toml  ->  ehr_host = "ehr.test.example", ...
inbound("IB_LABCO_ORU", MLLP(port=env("labco_port", cast=int, default=2576)), router="oru_router")
outbound(
    OB_EHR,
    MLLP(host=env("ehr_host", default="127.0.0.1"), port=env("ehr_port", cast=int, default=2999)),
)
outbound(
    FILE_ARCHIVE,
    File(directory=env("archive_dir", default="./out/labco_oru"), filename="{MSH-10}.hl7"),
)

# Local lab test code (OBX-3.1) -> the EHR's code. Edit codesets/test_codes.csv + reload; no code
# change. A code not in the table blanks through unchanged (.get(code, code)).
TEST_CODES = code_set("test_codes")


@router("oru_router")
def route(msg):  # type: ignore[no-untyped-def]
    # Every received message is seen; only ORU goes to the handler (anything else -> UNROUTED).
    return ["relay_results"] if msg["MSH-9.1"] == "ORU" else []


@handler("relay_results")
def relay_results(msg):  # type: ignore[no-untyped-def]
    fsep, csep = _separators(msg)

    # 1) Collapse PID-3's identifier repetition list to the MR identifier the EHR expects.
    #    repetitions() iterates the ~-list; a whole-field write replaces the whole list.
    identifiers = msg.repetitions("PID-3")
    if len(identifiers) > 1:
        mr = next(
            (
                ident
                for k, ident in enumerate(identifiers, start=1)
                if msg.field("PID-3.5", repetition=k) == "MR"
            ),
            identifiers[0],
        )
        msg.set("PID-3", mr)

    # 2) Walk every OBX (occurrence=), drop cancelled results, remap the test code; collect what
    #    to keep, then rebuild the OBX block in place — renumbering OBX-1.
    kept: list[tuple[str, ...]] = []
    for i in range(1, msg.count_segments("OBX") + 1):
        if msg.field("OBX-11", occurrence=i) == "X":  # cancelled / not done -> drop
            continue
        local_code = msg.field("OBX-3.1", occurrence=i) or ""
        observation = csep.join(
            [
                TEST_CODES.get(local_code, local_code),  # remapped code (blank-through on a miss)
                msg.field("OBX-3.2", occurrence=i) or "",  # text
                msg.field("OBX-3.3", occurrence=i) or "",  # coding system
            ]
        )
        kept.append(
            (
                msg.field("OBX-2", occurrence=i) or "",  # value type
                observation,  # OBX-3
                msg.field("OBX-5", occurrence=i) or "",  # value
                msg.field("OBX-6", occurrence=i) or "",  # units
                msg.field("OBX-7", occurrence=i) or "",  # reference range
                msg.field("OBX-8", occurrence=i) or "",  # abnormal flag
                msg.field("OBX-11", occurrence=i) or "",  # result status
            )
        )
    if not kept:
        return None  # every result cancelled -> nothing to relay (logged FILTERED)

    insert_at = msg.segments().index(
        "OBX"
    )  # rebuild where the block began (OBX present: kept non-empty)
    msg.delete_segments("OBX")
    for n, (vtype, obs, value, units, ref, abnormal, status) in enumerate(kept, start=1):
        msg.add_segment(
            fsep.join(["OBX", str(n), vtype, obs, "", value, units, ref, abnormal, "", "", status]),
            index=insert_at + n - 1,
        )

    # 3) Fan out: relay to the EHR and archive a copy to file.
    return [Send(OB_EHR, msg), Send(FILE_ARCHIVE, msg)]


def _separators(msg: Message) -> tuple[str, str]:
    # (field sep, component sep) read from MSH-1/MSH-2 — never hardcoded (CLAUDE.md §8).
    enc = msg.field("MSH-2") or "^~\\&"
    return (msg.field("MSH-1") or "|"), enc[0]
