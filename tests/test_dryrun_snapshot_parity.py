# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""CLI ``dryrun`` / ``dryrun --trace`` preview the engine's copy-on-Send posture (#230 P4, ADR 0104).

The engine default for ``[pipeline].snapshot_on_send`` is ON (ADR 0104 §8.1) while the ``dry_run`` /
``route_message`` / ``trace_dry_run`` *library* defaults stay ``False``. The CLI closes that gap: it
resolves the setting from the service settings best-effort (fallback = the Settings-model default, ON —
never a silent OFF) and threads it into BOTH preview paths, so a divergent fan-out (mutate the same
message between two ``Send``\\ s — the ADR 0104 §2.1 shape) previews per-destination bytes exactly as
the default engine delivers them, and ``dryrun --trace`` stays byte-identical to plain ``dryrun`` under
either setting value.

The config's handler doubles as a *posture probe*: it writes the active copy-on-Send flag into MSH-6,
so the plain preview reveals the posture in payload bytes and the traced preview reveals the SAME
posture in its captured writes — a direct proof the two paths ran under one posture.

PHI: every fixture here is synthetic (CLAUDE.md §9); ``--show-phi`` is used only on that synthetic data.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.send_snapshot import snapshot_on_send_active
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun_trace import trace_dry_run
from messagefoundry.store import MessageStatus

ADT_A01 = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)

# A divergent fan-out (ADR 0104 §2.1: mutate the same message between two Sends) + the MSH-6 posture
# probe. Under copy-on-Send the OB_A delivery keeps MSH-5=SYS_A (snapshotted at Send construction);
# with the setting off, both deliveries collapse to the last write (SYS_B).
_DIVERGENT_CONFIG = """\
# SPDX-License-Identifier: AGPL-3.0-or-later
from messagefoundry import File, Send, handler, inbound, outbound, router
from messagefoundry.config.send_snapshot import snapshot_on_send_active

inbound("IB_TEST", File(directory="in"), router="r")
outbound("OB_A", File(directory="outa"))
outbound("OB_B", File(directory="outb"))


@router("r")
def route(msg):
    return ["fanout"]


@handler("fanout")
def fanout(msg):
    msg["MSH-6"] = "SNAP" if snapshot_on_send_active() else "NOSNAP"
    msg["MSH-5"] = "SYS_A"
    first = Send("OB_A", msg)
    msg["MSH-5"] = "SYS_B"
    return [first, Send("OB_B", msg)]
"""

_TOML_OFF = "[pipeline]\nsnapshot_on_send = false\n"


def _write_config(tmp_path: Path) -> tuple[str, str]:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "IB_TEST.py").write_text(_DIVERGENT_CONFIG, encoding="utf-8")
    msg = tmp_path / "adt.hl7"
    msg.write_text(ADT_A01, encoding="utf-8")
    return str(cfg), str(msg)


def _delivered(entry: dict) -> dict[str, Message]:  # type: ignore[type-arg]
    return {d["to"]: Message.parse(d["payload"]) for d in entry["deliveries"]}


def _handler_writes(entry: dict) -> dict[str, str]:  # type: ignore[type-arg]
    inv = next(i for i in entry["invocations"] if i["kind"] == "handler")
    return {w["path"]: w["value"] for ev in inv["events"] for w in ev.get("writes", [])}


# --- plain CLI dryrun: engine-posture parity ----------------------------------------------------


def test_cli_dryrun_default_previews_per_destination_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # No service settings anywhere (CWD pinned to tmp_path) -> the Settings-model default (ON) — the
    # preview must show the per-destination bytes the DEFAULT engine delivers, not a silent OFF.
    cfg, msg = _write_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    rc = main(["dryrun", "--config", cfg, "--messages", msg, "--json", "--show-phi"])
    assert rc == 0
    (entry,) = json.loads(capsys.readouterr().out)
    assert entry["disposition"] == MessageStatus.RECEIVED.value
    by_dest = _delivered(entry)
    assert by_dest["OB_A"].field("MSH-5") == "SYS_A"  # snapshotted at the first Send (copy-on-Send)
    assert by_dest["OB_B"].field("MSH-5") == "SYS_B"
    assert by_dest["OB_A"].field("MSH-6") == "SNAP"  # the probe agrees the flag was active


def test_cli_dryrun_explicit_false_restores_last_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # [pipeline].snapshot_on_send = false in the resolved service settings -> the pre-ADR-0104
    # last-write-collapse preview (both deliveries carry the final mutation).
    cfg, msg = _write_config(tmp_path)
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(_TOML_OFF, encoding="utf-8")
    rc = main(
        [
            "dryrun",
            "--config",
            cfg,
            "--messages",
            msg,
            "--service-config",
            str(toml),
            "--json",
            "--show-phi",
        ]
    )
    assert rc == 0
    (entry,) = json.loads(capsys.readouterr().out)
    assert entry["disposition"] == MessageStatus.RECEIVED.value
    by_dest = _delivered(entry)
    assert by_dest["OB_A"].field("MSH-5") == "SYS_B"  # last-write collapse
    assert by_dest["OB_B"].field("MSH-5") == "SYS_B"
    assert by_dest["OB_A"].field("MSH-6") == "NOSNAP"  # the probe agrees the flag was off


# --- dryrun --trace: byte-identical to plain dryrun under BOTH setting values --------------------


@pytest.mark.parametrize("configured_off", [False, True])
def test_cli_trace_byte_identical_to_plain_dryrun_under_both_postures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    configured_off: bool,
) -> None:
    # The ADR 0072 contract the snapshot passthrough preserves: `dryrun --trace` matches plain
    # `dryrun` in disposition / routed-to / would-send outbounds — under the default-ON posture AND
    # with the setting explicitly configured off.
    cfg, msg = _write_config(tmp_path)
    monkeypatch.chdir(tmp_path)  # no stray messagefoundry.toml can leak into the default-ON leg
    args = ["--config", cfg, "--messages", msg, "--json", "--show-phi"]
    if configured_off:
        toml = tmp_path / "messagefoundry.toml"
        toml.write_text(_TOML_OFF, encoding="utf-8")
        args += ["--service-config", str(toml)]

    assert main(["dryrun", *args]) == 0
    (plain,) = json.loads(capsys.readouterr().out)
    assert main(["dryrun", *args, "--trace"]) == 0
    (traced,) = json.loads(capsys.readouterr().out)

    assert traced["disposition"] == plain["disposition"]
    assert traced["handlers"] == plain["handlers"] == ["fanout"]
    assert [s["outbound"] for s in traced["sends"]] == [d["to"] for d in plain["deliveries"]]

    # ...and both ran under the SAME posture: the probe value the plain preview delivered equals the
    # probe write the traced run captured (SNAP under the default-ON engine, NOSNAP when configured
    # off). Without the trace_dry_run passthrough the traced leg would report SNAP != NOSNAP here.
    expected = "NOSNAP" if configured_off else "SNAP"
    assert Message.parse(plain["deliveries"][0]["payload"]).field("MSH-6") == expected
    assert _handler_writes(traced)["MSH-6"] == expected


# --- library surface: trace_dry_run threads the flag; its own default stays False ----------------


def probe_handler(msg: Message) -> Send:
    verdict = "SNAP" if snapshot_on_send_active() else "NOSNAP"
    msg["MSH-6"] = verdict
    return Send("OB_A", msg)


def _probe_registry() -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection("in", ConnectionSpec(ConnectorType.FILE, {"directory": "in"}), router="r")
    )
    reg.add_outbound(
        OutboundConnection("OB_A", ConnectionSpec(ConnectorType.FILE, {"directory": "out"}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", probe_handler)
    return reg


def test_trace_dry_run_passes_snapshot_on_send_through() -> None:
    # snapshot_on_send=True must reach the run context the traced dry_run activates (the same
    # ContextVar the engine's copy-on-Send keys on) — and the library default must stay False
    # (ADR 0104 §8.1: a preview that doesn't opt in does not snapshot).
    reg = _probe_registry()
    on = trace_dry_run(reg, ADT_A01, show_phi=True, snapshot_on_send=True)
    off = trace_dry_run(reg, ADT_A01, show_phi=True)
    assert _handler_writes(on)["MSH-6"] == "SNAP"
    assert _handler_writes(off)["MSH-6"] == "NOSNAP"
