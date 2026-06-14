"""Example config (code-first): receive ADT over MLLP, archive A01/A04/A08 to a file.

Connection names follow the project convention ``[TYPE]_[PARTNER]_[MESSAGE]`` (see
docs/CONNECTIONS.md): ``IB_Test_ADT`` is an inbound MLLP listener; ``FILE-OUT_Test_ADT`` is an
outbound file writer. Run it with::

    python -m messagefoundry serve --config samples/config --db ./messagefoundry.db --env dev

Pass ``--env dev`` for local work: the active environment defaults to ``prod``, which is what
resolves any ``env()`` value lookups (this sample uses none, so it runs in any environment). The
engine logs the active environment at startup.

The Router sees every received message (non-ADT is routed nowhere → logged UNROUTED); the
Handler archives admit/register/update events and drops the rest (→ logged FILTERED). Nothing is
silently lost — every receipt is counted and logged.

It also demonstrates **code sets** (``codesets/`` next to this config): ``event_labels.csv`` (the
admit/register/update event codes → a label) and ``facility_mnemonics.toml`` (a sending-facility →
downstream mnemonic), captured once at module top level. Both reload with the graph (POST
/config/reload) — edit the CSV/TOML, no code change. (A call-time ``code_set("facility_mnemonics")``
inside the handler works just as well — the engine/dry-run keeps the set active while a handler runs.)
"""

from messagefoundry import File, MLLP, Send, code_set, handler, inbound, outbound, router

inbound("IB_Test_ADT", MLLP(port=2575), router="adt_router")
outbound("FILE-OUT_Test_ADT", File(directory="./out/adt", filename="{MSH-10}.hl7"))

# Module-top-level capture: the archived event codes are exactly the keys of the event_labels table,
# so a new archivable event is added by editing the CSV — not this script. facility_mnemonics maps a
# sending facility (MSH-4) to the downstream mnemonic to stamp.
EVENT_LABELS = code_set("event_labels")
FACILITY_MNEMONICS = code_set("facility_mnemonics")


@router("adt_router")
def route(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.1"] != "ADT":
        return []  # not ADT — routed nowhere (logged UNROUTED)
    return ["archive"]


@handler("archive")
def archive(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.2"] not in EVENT_LABELS:
        return None  # only events in the code set (admit/register/update) are archived (others FILTERED)
    # Stamp the downstream mnemonic for this sending facility (MSH-4), if the code set maps it.
    mnemonic = FACILITY_MNEMONICS.get(msg["MSH-4"])
    if mnemonic:
        msg["MSH-4"] = mnemonic
    return Send("FILE-OUT_Test_ADT", msg)
