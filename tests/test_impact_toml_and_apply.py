# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rename paths that wrote a wrong result while reporting success (BACKLOG #5980, #5966).

* A ``connections.toml`` rename rewrote every ``name = "old"`` / ``router = "old"`` line in the file,
  whatever table it sat in, and silently skipped a binding spelled another way.
* Renaming a Loopback inbound left an outbound's ``reingress_to`` naming it, and renaming an outbound
  left an ``Http`` inbound's ``reply_from`` naming it, with neither reported.
* ``codeset rename`` moved the table when the config did not load, leaving every reference to it.
* ``apply_rename`` skipped an edit whose file had changed since the plan, wrote the rest, and the
  CLI reported the rename as applied.

Each test loads a real config, and none was green before the fix."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.config import codeset_edit, impact
from messagefoundry.config.code_sets import load_code_set
from messagefoundry.config.graph import build_wiring_graph
from messagefoundry.config.impact import RenamePlan, apply_rename, plan_rename
from messagefoundry.config.reachability import Reference
from messagefoundry.config.wiring import WiringError, load_config
from messagefoundry_toolkit.__main__ import main

LOGIC = """\
from messagefoundry import Send, handler, router


@router("route_req")
def route_req(msg):
    return "to_partner"


@router("route_loop")
def route_loop(msg):
    return "to_result"


@handler("to_partner")
def to_partner(msg):
    return Send("OB_PARTNER", msg)


@handler("to_result")
def to_result(msg):
    return Send("OB_RESULT", msg)
"""

# connections.toml has no loopback transport, so the Loopback inbound stays in a .py module.
LOOPBACK = 'from messagefoundry import Loopback, inbound\n\ninbound("IB_LOOP", Loopback(), router="route_loop")\n'

REQ = """\
[[inbound]]
name = "IB_REQ"
transport = "file"
router = "route_req"
[inbound.settings]
directory = "in_req"
"""

OUTBOUNDS = """\
[[outbound]]
name = "OB_PARTNER"
transport = "file"
[outbound.settings]
directory = "out_partner"

[[outbound]]
name = "OB_RESULT"
transport = "file"
[outbound.settings]
directory = "out_result"
"""


def _config(tmp_path: Path, files: dict[str, str]) -> Path:
    d = tmp_path / "config"
    d.mkdir()
    for name, text in files.items():
        path = d / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="")
    return d


def _toml_config(tmp_path: Path, toml: str, logic: str = LOGIC) -> Path:
    return _config(tmp_path, {"connections.toml": toml, "logic.py": logic, "loopback.py": LOOPBACK})


def _validate(path: Path) -> None:
    """The post-write check codeset_edit injects: prove the written file loads."""
    load_code_set(path)


def _toml(config_dir: Path) -> str:
    return (config_dir / "connections.toml").read_text(encoding="utf-8")


# --- step 1: a TOML name rename rewrites only the entry's own name ------------------------------


def test_a_toml_inbound_rename_leaves_a_metadata_value_equal_to_its_name(tmp_path: Path) -> None:
    config_dir = _toml_config(tmp_path, REQ + '[inbound.metadata]\nname = "IB_REQ"\n\n' + OUTBOUNDS)
    plan = plan_rename(load_config(config_dir), config_dir, "inbound", "IB_REQ", "IB_ORDERS")
    assert plan.unresolved == ()
    apply_rename(plan)
    registry = load_config(config_dir)
    assert set(registry.inbound) == {"IB_ORDERS", "IB_LOOP"}
    assert registry.inbound["IB_ORDERS"].metadata == {"name": "IB_REQ"}


def test_a_toml_inbound_rename_leaves_an_outbound_of_the_same_name(tmp_path: Path) -> None:
    # Inbounds and outbounds are separate tables, so one name may denote one of each.
    toml = REQ + "\n" + OUTBOUNDS.replace("OB_RESULT", "IB_REQ")
    config_dir = _toml_config(tmp_path, toml, LOGIC.replace('Send("OB_RESULT"', 'Send("IB_REQ"'))
    plan = plan_rename(load_config(config_dir), config_dir, "inbound", "IB_REQ", "IB_ORDERS")
    apply_rename(plan)
    registry = load_config(config_dir)
    assert "IB_ORDERS" in registry.inbound
    assert set(registry.outbound) == {"OB_PARTNER", "IB_REQ"}


# --- step 2: a TOML router rename rewrites only an inbound's router binding --------------------


def test_a_router_rename_leaves_a_toml_metadata_value_equal_to_it(tmp_path: Path) -> None:
    toml = REQ + '[inbound.metadata]\nrouter = "route_req"\n\n' + OUTBOUNDS
    config_dir = _toml_config(tmp_path, toml)
    plan = plan_rename(load_config(config_dir), config_dir, "router", "route_req", "route_orders")
    assert plan.unresolved == ()
    apply_rename(plan)
    registry = load_config(config_dir)
    assert registry.inbound["IB_REQ"].router == "route_orders"
    assert registry.inbound["IB_REQ"].metadata == {"router": "route_req"}


@pytest.mark.parametrize(
    "binding",
    [
        'inbound = [{ name = "IB_REQ", transport = "file", router = "route_req", '
        'settings = { directory = "in_req" } }]\n',
        '[[inbound]]\nname = "IB_REQ"\ntransport = "file"\n"router" = "route_req"\n'
        '[inbound.settings]\ndirectory = "in_req"\n',
    ],
    ids=["inline-table", "quoted-key"],
)
def test_a_toml_router_binding_spelled_another_way_is_reported_and_apply_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], binding: str
) -> None:
    config_dir = _toml_config(tmp_path, binding + "\n" + OUTBOUNDS)
    before = _toml(config_dir)
    plan = plan_rename(load_config(config_dir), config_dir, "router", "route_req", "route_orders")
    assert plan.unresolved == (Reference("inbound", "IB_REQ", "router", "route_req"),)
    argv = ["impact", "--config", str(config_dir), "router", "route_req"]
    rc = main([*argv, "--rename-to", "route_orders", "--apply", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc != 0 and "--apply refused" in out["error"], out
    assert _toml(config_dir) == before


# --- BACKLOG #5966: a loopback rename rewrites reingress_to, an outbound rename reply_from ------

PY_REINGRESS = """\
from messagefoundry import MLLP, File, Loopback, inbound, outbound

inbound("IB_REQ", File(directory="in_req"), router="route_req")
inbound("IB_LOOP", Loopback(), router="route_loop")
outbound("OB_PARTNER", MLLP(host="127.0.0.1", port=2575, reingress_to="IB_LOOP"))
outbound("OB_RESULT", File(directory="out_result"))
"""

TOML_REINGRESS = (
    REQ
    + "\n"
    + OUTBOUNDS.replace(
        'transport = "file"\n[outbound.settings]\ndirectory = "out_partner"',
        'transport = "mllp"\n[outbound.settings]\nhost = "127.0.0.1"\nport = 2575\n'
        'reingress_to = "IB_LOOP"',
    )
)


@pytest.mark.parametrize("surface", ["py", "toml"])
def test_a_loopback_rename_rewrites_the_reingress_to_naming_it(
    tmp_path: Path, surface: str
) -> None:
    if surface == "py":
        config_dir = _config(tmp_path, {"connections.py": PY_REINGRESS, "logic.py": LOGIC})
    else:
        config_dir = _toml_config(tmp_path, TOML_REINGRESS)
    plan = plan_rename(load_config(config_dir), config_dir, "inbound", "IB_LOOP", "IB_REPLIES")
    assert plan.unresolved == ()
    apply_rename(plan)
    registry = load_config(config_dir)
    assert registry.outbound["OB_PARTNER"].spec.settings["reingress_to"] == "IB_REPLIES"
    assert not build_wiring_graph(registry).dangling


def test_a_reingress_to_the_plan_cannot_read_is_reported(tmp_path: Path) -> None:
    body = PY_REINGRESS.replace('reingress_to="IB_LOOP"', 'reingress_to="IB_" "LOOP"')
    config_dir = _config(tmp_path, {"connections.py": body, "logic.py": LOGIC})
    plan = plan_rename(load_config(config_dir), config_dir, "inbound", "IB_LOOP", "IB_REPLIES")
    assert plan.unresolved == (Reference("outbound", "OB_PARTNER", "inbound", "IB_LOOP"),)


PY_REPLY = """\
from messagefoundry import Http, Rest, Send, handler, inbound, outbound, router
from messagefoundry.config.models import ContentType

inbound("IB_HTTP", Http(port=18080, reply_from="OB_PARTNER"), router="r", content_type=ContentType.JSON)
outbound("OB_PARTNER", Rest(url="https://partner.example/ingest", capture_response=True))


@router("r")
def r(msg):
    return "h"


@handler("h")
def h(msg):
    return Send("OB_PARTNER", msg)
"""


def test_an_outbound_rename_rewrites_the_reply_from_naming_it(tmp_path: Path) -> None:
    config_dir = _config(tmp_path, {"conn.py": PY_REPLY})
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_PARTNER", "OB_UPSTREAM")
    assert plan.unresolved == ()
    apply_rename(plan)
    registry = load_config(config_dir)
    assert registry.inbound["IB_HTTP"].spec.settings["reply_from"] == "OB_UPSTREAM"


def test_an_outbound_rename_rewrites_a_toml_reply_from(tmp_path: Path) -> None:
    toml = """\
[[inbound]]
name = "IB_HTTP"
transport = "http"
router = "r"
content_type = "json"
[inbound.settings]
port = 18080
reply_from = "OB_PARTNER"
"""
    logic = PY_REPLY.split("\n\n\n", 1)[1]
    head = "from messagefoundry import Rest, Send, handler, outbound, router\n\n"
    ob = 'outbound("OB_PARTNER", Rest(url="https://partner.example/ingest", capture_response=True))\n'
    config_dir = _config(tmp_path, {"connections.toml": toml, "logic.py": head + ob + logic})
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_PARTNER", "OB_UPSTREAM")
    assert plan.unresolved == ()
    apply_rename(plan)
    registry = load_config(config_dir)
    assert registry.inbound["IB_HTTP"].spec.settings["reply_from"] == "OB_UPSTREAM"


# --- step 12: `codeset rename` with no plan -------------------------------------------------------

CODESET_MOD = """\
from messagefoundry import MLLP, Send, code_set, handler, inbound, outbound, router

inbound("IB_CS", MLLP(port=2731), router="r_cs_misspelled")
outbound("OB_CS", MLLP(host="127.0.0.1", port=6400))


@router("r_cs")
def r_cs(msg):
    return ["h_cs"]


@handler("h_cs")
def h_cs(msg):
    label = code_set("diets").get("A")
    return Send("OB_CS", msg)
"""


def test_codeset_rename_refuses_and_moves_nothing_when_the_config_does_not_load(
    tmp_path: Path,
) -> None:
    config_dir = _config(
        tmp_path, {"mod.py": CODESET_MOD, "codesets/diets.csv": "code,value\nA,Apple\n"}
    )
    with pytest.raises(WiringError, match="references could not be checked"):
        codeset_edit.rename_code_set(config_dir, "diets", "meals", validate=_validate)
    assert sorted(p.name for p in (config_dir / "codesets").iterdir()) == ["diets.csv"]
    assert 'code_set("diets")' in (config_dir / "mod.py").read_text(encoding="utf-8")


# --- step 13: an edit apply_rename cannot make fails the whole apply ------------------------------

SPLIT = {
    "a.py": "from messagefoundry import MLLP, inbound, outbound\n\n"
    'inbound("IB_X", MLLP(port=2900), router="rx")\n'
    'outbound("OB_X", MLLP(host="127.0.0.1", port=6900))\n',
    "b.py": "from messagefoundry import Send, handler, router\n\n\n"
    '@router("rx")\ndef rx(msg):\n    return "hx"\n\n\n'
    '@handler("hx")\ndef hx(msg):\n    return Send("OB_X", msg)\n',
}


def _drift(path: Path, old: str = 'Send("OB_X"', new: str = 'Send( "OB_X"') -> None:
    """Change ``path`` after the plan so an edit's span no longer holds the old literal."""
    path.write_text(path.read_text(encoding="utf-8").replace(old, new), "utf-8")


def _drift_after_planning(monkeypatch: pytest.MonkeyPatch, path: Path, *replace: str) -> None:
    """Make every plan_rename call change ``path`` once it has planned, as a concurrent edit would."""
    real = impact.plan_rename

    def plan_then_drift(*args: object, **kwargs: object) -> RenamePlan:
        plan = real(*args, **kwargs)  # type: ignore[arg-type]
        _drift(path, *replace)
        return plan

    monkeypatch.setattr(impact, "plan_rename", plan_then_drift)


def test_apply_writes_nothing_when_a_file_changed_after_the_plan(tmp_path: Path) -> None:
    config_dir = _config(tmp_path, SPLIT)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_Y")
    assert {Path(e.file).name for e in plan.edits} == {"a.py", "b.py"}
    _drift(config_dir / "b.py")
    before = {name: (config_dir / name).read_bytes() for name in SPLIT}
    with pytest.raises(WiringError, match="changed after the plan"):
        apply_rename(plan)
    assert {name: (config_dir / name).read_bytes() for name in SPLIT} == before


def test_the_cli_does_not_report_success_when_an_edit_could_not_be_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_dir = _config(tmp_path, SPLIT)
    _drift_after_planning(monkeypatch, config_dir / "b.py")
    argv = ["impact", "--config", str(config_dir), "outbound", "OB_X", "--rename-to", "OB_Y"]
    rc = main([*argv, "--apply", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc != 0 and "changed after the plan" in out["error"], out
    assert 'outbound("OB_X"' in (config_dir / "a.py").read_text(encoding="utf-8")


def test_codeset_rename_moves_the_table_back_when_the_rewrite_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = CODESET_MOD.replace("r_cs_misspelled", "r_cs")
    config_dir = _config(tmp_path, {"mod.py": mod, "codesets/diets.csv": "code,value\nA,Apple\n"})
    _drift_after_planning(
        monkeypatch, config_dir / "mod.py", 'code_set("diets")', 'code_set( "diets")'
    )
    with pytest.raises(WiringError, match="changed after the plan"):
        codeset_edit.rename_code_set(config_dir, "diets", "meals", validate=_validate)
    assert sorted(p.name for p in (config_dir / "codesets").iterdir()) == ["diets.csv"]


def test_reapplying_a_plan_with_two_edits_on_one_line_is_a_no_op(tmp_path: Path) -> None:
    """The already-renamed check maps each span through the edits before it: a second edit on the
    same line sits where the first one's change in length moved it."""
    body = SPLIT["b.py"].replace(
        '    return Send("OB_X", msg)\n', '    return [Send("OB_X", msg), Send("OB_X", msg)]\n'
    )
    config_dir = _config(tmp_path, {**SPLIT, "b.py": body})
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_LONGER")
    assert len(apply_rename(plan)) == 3
    after = (config_dir / "b.py").read_bytes()
    assert apply_rename(plan) == []
    assert (config_dir / "b.py").read_bytes() == after
