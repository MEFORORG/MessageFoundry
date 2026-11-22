# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
  - renumbering OBX-1 within each order — the *repeating-segment edit* that the mutable-``Message``
    API makes first-class (``count_segments`` / ``field(occurrence=…)`` / ``repetitions`` /
    ``delete_segments(occurrence=…)`` / ``groups``).

Every OBX edit goes through the parsed model, never a re-joined line, so the template keeps every
OBX field and component it does not touch, the message's escaping, and each OBX under its own OBR.

Run it locally::

    python -P -X disable-remote-debug -m messagefoundry serve --config samples/results_relay --env dev --db ./mf.db
    python -m messagefoundry dryrun --config samples/results_relay \\
        --messages samples/results_relay/messages --show-phi
"""

from messagefoundry import MLLP, File, Send, code_set, env, handler, inbound, outbound, router

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
# change. A code not in the table passes through unchanged.
TEST_CODES = code_set("test_codes")


@router("oru_router")
def route(msg):  # type: ignore[no-untyped-def]
    # Every received message is seen; only ORU goes to the handler (anything else -> UNROUTED).
    return ["relay_results"] if msg["MSH-9.1"] == "ORU" else []


@handler("relay_results")
def relay_results(msg):  # type: ignore[no-untyped-def]
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

    # 2) Walk every OBX back to front (occurrence=), so deleting one never shifts an occurrence
    #    still to visit: drop each cancelled result and remap each kept test code in place. Editing
    #    the parsed segment, rather than re-joining its text, keeps every other OBX field and
    #    component, the message's own escaping, and each OBX under the OBR it arrived with.
    for i in range(msg.count_segments("OBX"), 0, -1):
        if msg.field("OBX-11", occurrence=i) == "X":  # cancelled / not done -> drop
            _drop_result(msg, i)
            continue
        local_code = msg.field("OBX-3.1", occurrence=i)
        if local_code in TEST_CODES:  # an unmapped code is left exactly as it arrived
            # A component write escapes the new code and leaves OBX-3.2 onward as they were.
            msg.set("OBX-3.1", TEST_CODES[local_code], occurrence=i)
    if not msg.count_segments("OBX"):
        return None  # every result cancelled -> nothing to relay (logged FILTERED)

    # 3) Renumber OBX-1 (Set ID) from 1 within each order, closing the gaps the drops left.
    for order in msg.groups("OBR"):
        for n in range(1, order.count("OBX") + 1):
            order.set("OBX-1", str(n), occurrence=n)

    # 4) Fan out: relay to the EHR and archive a copy to file.
    return [Send(OB_EHR, msg), Send(FILE_ARCHIVE, msg)]


#: Segments that belong to the OBX they follow; a Z-segment does too (see _is_child).
_CHILD_SEGMENTS = {"NTE", "PRT"}


def _is_child(segment_id: str) -> bool:
    # An allowlist, not a stop list: any other segment after the OBX (the next patient's PID and
    # PV1, a DSC, FT1 or CTI, a batch trailer, the next MSH) is not this result's and must survive.
    return segment_id in _CHILD_SEGMENTS or segment_id.startswith("Z")


def _drop_result(msg, i):  # type: ignore[no-untyped-def]
    # Delete the i-th OBX and the rows that belong to it (its NTE comments, PRT participants and
    # any Z-segment), so none of them ends up attached to the result before it.
    ids = msg.segments()
    at = [pos for pos, seg in enumerate(ids) if seg == "OBX"][i - 1]
    end = at + 1
    while end < len(ids) and _is_child(ids[end]):
        end += 1
    children = ids[at + 1 : end]
    # segments() lists a fieldless bare line (e.g. "NTE" alone); occurrences skip it. Where one is
    # present the positions above and the occurrences below disagree, so refuse the message (it
    # takes the ERROR path) rather than delete another result's rows.
    if any(ids.count(seg) != msg.count_segments(seg) for seg in {"OBX", *children}):
        raise ValueError("a fieldless segment line makes the OBX rows ambiguous")
    # Each deleted child's next sibling takes its occurrence number. A delete that removes nothing
    # means the numbering disagreed after all, so refuse rather than relay a cancelled result.
    deletes = [(seg, ids[:at].count(seg) + 1) for seg in children] + [("OBX", i)]
    for seg, occurrence in deletes:
        if msg.delete_segments(seg, occurrence=occurrence) != 1:
            raise ValueError(f"{seg} occurrence {occurrence} is missing; refusing a partial drop")
