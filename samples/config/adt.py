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
"""

from messagefoundry import File, MLLP, Send, handler, inbound, outbound, router

inbound("IB_Test_ADT", MLLP(port=2575), router="adt_router")
outbound("FILE-OUT_Test_ADT", File(directory="./out/adt", filename="{MSH-10}.hl7"))


@router("adt_router")
def route(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.1"] != "ADT":
        return []  # not ADT — routed nowhere (logged UNROUTED)
    return ["archive"]


@handler("archive")
def archive(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.2"] not in ("A01", "A04", "A08"):
        return None  # only admit / register / update are archived (others FILTERED)
    return Send("FILE-OUT_Test_ADT", msg)
