"""The shipped sample config loads/routes, and the Engine runs a loaded Registry end-to-end."""

from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path

from messagefoundry.config.wiring import load_config
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline import Engine

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def test_sample_config_loads_and_routes() -> None:
    cfg = Path(__file__).resolve().parents[1] / "samples" / "config"
    reg = load_config(cfg)

    assert reg.inbound["IB_Test_ADT"].router == "adt_router"
    assert reg.inbound["IB_Test_ADT"].spec.settings["port"] == 2575
    assert (
        reg.inbound["IB_Test_ADT"].spec.settings.get("host") is None
    )  # bind interface is service-set
    assert "FILE-OUT_Test_ADT" in reg.outbound
    # samples/config ships two modules: the ADT archive route and the ACME env()-driven route.
    assert set(reg.routers) == {"adt_router", "acme_adt_router"}
    assert set(reg.handlers) == {"archive", "acme_adt_handler"}

    a01 = Message.parse("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\r")
    a99 = Message.parse("MSH|^~\\&|A|B|C|D|20260101||ADT^A99|M2|P|2.5.1\r")
    oru = Message.parse("MSH|^~\\&|A|B|C|D|20260101||ORU^R01|M3|P|2.5.1\r")

    assert reg.routers["adt_router"](a01) == ["archive"]
    assert reg.routers["adt_router"](oru) == []  # non-ADT routed nowhere (UNROUTED)
    send = reg.handlers["archive"](a01)
    assert send is not None and send.to == "FILE-OUT_Test_ADT"
    assert reg.handlers["archive"](a99) is None  # non-A01/04/08 ADT filtered


async def test_engine_runs_loaded_registry(tmp_path: Path) -> None:
    inbox, outdir, cfgdir = tmp_path / "in", tmp_path / "out", tmp_path / "cfg"
    inbox.mkdir()
    cfgdir.mkdir()
    (cfgdir / "c.py").write_text(
        textwrap.dedent(
            f"""
            from messagefoundry import inbound, outbound, router, handler, Send, File
            inbound("in", File(directory={str(inbox)!r}, pattern="*.hl7", poll_seconds=0.02),
                    router="r")
            outbound("out", File(directory={str(outdir)!r}, filename="{{MSH-10}}.hl7"))

            @router("r")
            def route(msg):
                return ["h"]

            @handler("h")
            def handle(msg):
                return Send("out", msg)
            """
        ),
        encoding="utf-8",
    )
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    engine = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    engine.add_registry(load_config(cfgdir))
    await engine.start()
    try:
        delivered = outdir / "MSG1.hl7"
        elapsed = 0.0
        while not delivered.exists() and elapsed < 3.0:
            await asyncio.sleep(0.02)
            elapsed += 0.02
        assert delivered.exists()
        assert delivered.read_bytes() == ADT.encode("utf-8")
    finally:
        await engine.stop()
