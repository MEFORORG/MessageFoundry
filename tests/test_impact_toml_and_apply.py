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

import contextlib
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config import atomic_edit, codeset_edit, impact
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
    assert plan.unresolved == ()
    apply_rename(plan)
    registry = load_config(config_dir)
    assert "IB_ORDERS" in registry.inbound
    assert set(registry.outbound) == {"OB_PARTNER", "IB_REQ"}
    # The handler's Send goes to the outbound, so it keeps naming it.
    logic = (config_dir / "logic.py").read_text(encoding="utf-8")
    assert 'Send("IB_REQ"' in logic and "IB_ORDERS" not in logic


def test_a_toml_rename_beside_a_nan_value_still_applies(tmp_path: Path) -> None:
    """A nan never equals itself, so it must not make the re-parse proof refuse a rename."""
    toml = REQ + "[inbound.metadata]\nratio = nan\n\n" + OUTBOUNDS
    config_dir = _toml_config(tmp_path, toml)
    plan = plan_rename(load_config(config_dir), config_dir, "router", "route_req", "route_orders")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert load_config(config_dir).inbound["IB_REQ"].router == "route_orders"


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


PY_REINGRESS_WRAPPED = """\
from messagefoundry import MLLP, File, Loopback, inbound, outbound


def _keep(spec):
    return spec


def _note(reingress_to=None):
    return None


inbound("IB_REQ", File(directory="in_req"), router="route_req")
inbound("IB_LOOP", Loopback(), router="route_loop")
outbound(
    "OB_PARTNER",
    _keep(MLLP(host="127.0.0.1", port=2575, reingress_to="IB_LOOP")),
    buildup=_note(reingress_to="IB_LOOP"),
)
outbound("OB_RESULT", File(directory="out_result"))
"""


def test_a_reingress_to_is_read_from_the_spec_argument_only(tmp_path: Path) -> None:
    """The setting is the keyword inside the outbound's ``spec`` argument, through a wrapper; the
    same keyword on a call in a sibling argument is another call's, and is left (BACKLOG #5966,
    #5980 step 6)."""
    config_dir = _config(tmp_path, {"connections.py": PY_REINGRESS_WRAPPED, "logic.py": LOGIC})
    plan = plan_rename(load_config(config_dir), config_dir, "inbound", "IB_LOOP", "IB_REPLIES")
    assert plan.unresolved == ()
    apply_rename(plan)
    registry = load_config(config_dir)
    assert registry.outbound["OB_PARTNER"].spec.settings["reingress_to"] == "IB_REPLIES"
    assert '_note(reingress_to="IB_LOOP")' in (config_dir / "connections.py").read_text()


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


def test_apply_refuses_a_file_that_still_holds_the_old_literal_at_the_span(tmp_path: Path) -> None:
    """A line inserted above an edit can put an equal literal at the planned span; the span check
    alone would rewrite that one and leave the real reference reading the old name."""
    config_dir = _config(tmp_path, SPLIT)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_Y")
    b = config_dir / "b.py"
    text = b.read_text(encoding="utf-8")
    b.write_text(
        text.replace("    return Send(", '    _ =    Send("OB_X", msg)\n    return Send('), "utf-8"
    )
    before = b.read_bytes()
    with pytest.raises(WiringError, match="changed after the plan"):
        apply_rename(plan)
    assert b.read_bytes() == before


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


def test_an_interrupted_codeset_rename_moves_the_table_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C while the references are written: they are restored to the old name, so the table
    must go back to it too, leaving the config consistent and loadable."""
    mod = CODESET_MOD.replace("r_cs_misspelled", "r_cs")
    config_dir = _config(tmp_path, {"mod.py": mod, "codesets/diets.csv": "code,value\nA,Apple\n"})
    before = (config_dir / "mod.py").read_bytes()

    def interrupted(*_args: Any, **_kwargs: Any) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(atomic_edit, "replace_validated", interrupted)
    with pytest.raises(KeyboardInterrupt):
        codeset_edit.rename_code_set(config_dir, "diets", "meals", validate=_validate)
    monkeypatch.undo()
    assert sorted(p.name for p in (config_dir / "codesets").iterdir()) == ["diets.csv"]
    assert (config_dir / "mod.py").read_bytes() == before
    load_config(config_dir)


def test_a_codeset_rename_interrupted_after_a_write_keeps_table_and_references_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Ctrl-C after the reference write returned, as the locks are released: nothing restores
    the reference, so moving the table back would leave it named by a reference that reads the
    new name. The table stays under the new name and the log names the file left rewritten."""
    mod = CODESET_MOD.replace("r_cs_misspelled", "r_cs")
    config_dir = _config(tmp_path, {"mod.py": mod, "codesets/diets.csv": "code,value\nA,Apple\n"})
    real_locks = impact._rename_locks

    @contextlib.contextmanager
    def interrupted_on_release(files: Any) -> Iterator[None]:
        with real_locks(files):
            yield
        raise KeyboardInterrupt

    monkeypatch.setattr(impact, "_rename_locks", interrupted_on_release)
    with caplog.at_level("ERROR"), pytest.raises(KeyboardInterrupt):
        codeset_edit.rename_code_set(config_dir, "diets", "meals", validate=_validate)
    monkeypatch.undo()
    assert sorted(p.name for p in (config_dir / "codesets").iterdir()) == ["meals.csv"]
    text = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert 'code_set("meals")' in text and 'code_set("diets")' not in text
    load_config(config_dir)
    assert "mod.py" in caplog.text and "stays as meals.csv" in caplog.text


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


def test_a_write_that_fails_restores_the_files_already_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_dir = _config(tmp_path, SPLIT)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_Y")
    before = {name: (config_dir / name).read_bytes() for name in SPLIT}
    real_replace = atomic_edit.replace_validated
    writes: list[str] = []

    def second_write_fails(path: Path, data: bytes, *args: Any, **kwargs: Any) -> None:
        writes.append(path.name)
        if len(writes) == 2:
            raise PermissionError("held open")
        real_replace(path, data, *args, **kwargs)

    monkeypatch.setattr(atomic_edit, "replace_validated", second_write_fails)
    with pytest.raises(WiringError, match="already written were restored"):
        apply_rename(plan)
    monkeypatch.undo()
    assert {name: (config_dir / name).read_bytes() for name in SPLIT} == before


def test_a_write_interrupted_part_way_leaves_each_file_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rename killed while it writes a file must not leave that file truncated: each file is
    written to a candidate and renamed over the live one, so the live file holds its old bytes,
    never part of its new ones (BACKLOG #5980). The kill is simulated where either write path
    passes: an in-place write half done, and the candidate's flush to disk."""
    config_dir = _config(tmp_path, SPLIT)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_Y")
    before = {name: (config_dir / name).read_bytes() for name in SPLIT}
    real_write = Path.write_bytes

    def half_then_killed(self: Path, data: bytes) -> int:
        real_write(self, data[: len(data) // 2])
        raise KeyboardInterrupt

    def killed(_fd: int) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(Path, "write_bytes", half_then_killed)
    monkeypatch.setattr(os, "fsync", killed)
    with pytest.raises(KeyboardInterrupt):
        apply_rename(plan)
    monkeypatch.undo()
    assert {name: (config_dir / name).read_bytes() for name in SPLIT} == before


def test_an_interrupt_between_two_files_restores_the_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C after one file is written and before the next must not leave the rename half
    applied: the written file is restored before the interrupt propagates."""
    config_dir = _config(tmp_path, SPLIT)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_Y")
    before = {name: (config_dir / name).read_bytes() for name in SPLIT}
    real_replace = atomic_edit.replace_validated
    writes: list[str] = []

    def second_write_interrupted(path: Path, data: bytes, *args: Any, **kwargs: Any) -> None:
        writes.append(path.name)
        if len(writes) == 2:
            raise KeyboardInterrupt
        real_replace(path, data, *args, **kwargs)

    monkeypatch.setattr(atomic_edit, "replace_validated", second_write_interrupted)
    with pytest.raises(KeyboardInterrupt):
        apply_rename(plan)
    monkeypatch.undo()
    assert len(writes) >= 2
    assert {name: (config_dir / name).read_bytes() for name in SPLIT} == before


def test_write_rename_holds_the_config_edit_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The writes run under the lock the other config editors take, so a connections.toml or code
    set edit in another process cannot interleave with them (BACKLOG #5980)."""
    config_dir = _config(tmp_path, SPLIT)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_Y")
    held: list[Path] = []
    locked: list[Path] = []
    real_lock = atomic_edit.edit_lock
    real_replace = atomic_edit.replace_validated

    @contextlib.contextmanager
    def recording_lock(path: Path, **kwargs: object) -> Iterator[None]:
        with real_lock(path, **kwargs):  # type: ignore[arg-type]
            held.append(path.parent)
            try:
                yield
            finally:
                held.remove(path.parent)

    def write_under_lock(path: Path, data: bytes, *args: Any, **kwargs: Any) -> None:
        locked.extend(d for d in held if d == path.parent)
        real_replace(path, data, *args, **kwargs)

    monkeypatch.setattr(atomic_edit, "edit_lock", recording_lock)
    monkeypatch.setattr(atomic_edit, "replace_validated", write_under_lock)
    assert len(apply_rename(plan)) == 2
    monkeypatch.undo()
    assert [p.resolve() for p in locked] == [config_dir.resolve()] * 2


def test_write_rename_writes_nothing_when_a_file_changed_after_it_was_prepared(
    tmp_path: Path,
) -> None:
    """An edit landing between prepare_rename and write_rename would be overwritten by the
    prepared bytes; under the lock the file is read again, and the write refuses."""
    config_dir = _config(tmp_path, SPLIT)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_Y")
    prepared = impact.prepare_rename(plan)
    a = config_dir / "a.py"
    a.write_text(a.read_text(encoding="utf-8") + "# edited by another editor\n", "utf-8")
    before = {name: (config_dir / name).read_bytes() for name in SPLIT}
    with pytest.raises(impact.RenameWriteError, match="Nothing was written") as caught:
        impact.write_rename(prepared)
    assert caught.value.unrestored == []
    assert {name: (config_dir / name).read_bytes() for name in SPLIT} == before


def test_codeset_rename_moves_the_table_back_when_the_rename_lock_is_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A referent directory's edit lock held past its timeout refuses the rewrite after the table
    moved; the table moves back rather than leave every reference naming a table that is gone."""
    mod = CODESET_MOD.replace("r_cs_misspelled", "r_cs")
    config_dir = _config(tmp_path, {"mod.py": mod, "codesets/diets.csv": "code,value\nA,Apple\n"})
    real_lock = atomic_edit.edit_lock
    codesets = (config_dir / "codesets").resolve()

    def busy_but_the_codeset_lock(
        path: Path, **kwargs: object
    ) -> contextlib.AbstractContextManager[None]:
        if Path(path).resolve() != codesets:  # the codeset editor locks the folder itself
            raise WiringError("another edit holds the lock")
        return real_lock(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(atomic_edit, "edit_lock", busy_but_the_codeset_lock)
    with pytest.raises(WiringError, match="moved back"):
        codeset_edit.rename_code_set(config_dir, "diets", "meals", validate=_validate)
    monkeypatch.undo()
    assert sorted(p.name for p in (config_dir / "codesets").iterdir()) == ["diets.csv"]
    assert 'code_set("diets")' in (config_dir / "mod.py").read_text(encoding="utf-8")


def test_a_reply_from_env_default_naming_the_outbound_is_reported(tmp_path: Path) -> None:
    """An env() default is no keyword literal the plan rewrites, so it is reported, not passed."""
    body = PY_REPLY.replace(
        'reply_from="OB_PARTNER"', 'reply_from=env("REPLY_OB", default="OB_PARTNER")'
    ).replace("import Http,", "import Http, env,")
    config_dir = _config(tmp_path, {"conn.py": body})
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_PARTNER", "OB_UPSTREAM")
    assert plan.unresolved == (Reference("inbound", "IB_HTTP", "outbound", "OB_PARTNER"),)


# --- review round 1 (round-97e5c019) -------------------------------------------------------------


def test_a_toml_reply_from_env_table_beside_a_literal_is_reported(tmp_path: Path) -> None:
    """An env() table naming the outbound is reported per entry: a sibling entry's literal edit no
    longer hides it (BACKLOG #5966)."""
    toml = """\
[[inbound]]
name = "IB_HTTP"
transport = "http"
router = "r"
content_type = "json"
[inbound.settings]
port = 18080
reply_from = "OB_PARTNER"

[[inbound]]
name = "IB_HTTP2"
transport = "http"
router = "r"
content_type = "json"
[inbound.settings]
port = 18081
reply_from = { env = "REPLY_OB", default = "OB_PARTNER" }
"""
    logic = PY_REPLY.split("\n\n\n", 1)[1]
    head = "from messagefoundry import Rest, Send, handler, outbound, router\n\n"
    ob = 'outbound("OB_PARTNER", Rest(url="https://partner.example/ingest", capture_response=True))\n'
    config_dir = _config(tmp_path, {"connections.toml": toml, "logic.py": head + ob + logic})
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_PARTNER", "OB_UPSTREAM")
    assert Reference("inbound", "IB_HTTP2", "outbound", "OB_PARTNER") in plan.unresolved


def test_a_multi_line_literal_in_a_crlf_file_applies(tmp_path: Path) -> None:
    """The plan reads a backslash-continued literal with universal newlines; apply compares it with
    the same line ends, so an untouched CRLF file is not taken as changed."""
    body = SPLIT["b.py"].replace('Send("OB_X", msg)', 'Send("OB_\\\nX", msg)')
    config_dir = _config(tmp_path, {**SPLIT, "b.py": body})
    b = config_dir / "b.py"
    b.write_bytes(b.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_Y")
    assert plan.unresolved == ()
    assert len(apply_rename(plan)) == 2
    assert b'Send("OB_Y", msg)\r\n' in b.read_bytes()


def test_the_snapshot_holds_the_bytes_the_plan_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A save landing after the plan read a file and before it took the snapshot is refused at
    apply: the snapshot is the bytes the edits were computed from, not a later read."""
    config_dir = _config(tmp_path, SPLIT)
    real = impact._file_bytes

    def save_then_snapshot(*args: object) -> object:
        # Appended below every edit, so each planned span still holds its literal.
        b = config_dir / "b.py"
        b.write_text(b.read_text(encoding="utf-8") + '\nLATE = "OB_X"\n', "utf-8")
        return real(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(impact, "_file_bytes", save_then_snapshot)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_Y")
    monkeypatch.undo()
    with pytest.raises(WiringError, match="changed after the plan"):
        apply_rename(plan)


def test_a_file_the_snapshot_does_not_hold_is_refused(tmp_path: Path) -> None:
    config_dir = _config(tmp_path, SPLIT)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_X", "OB_Y")
    partial = RenamePlan(
        plan.target_kind,
        plan.old,
        plan.new,
        edits=plan.edits,
        sources=tuple(s for s in plan.sources if Path(s[0]).name != "b.py"),
    )
    before = {name: (config_dir / name).read_bytes() for name in SPLIT}
    with pytest.raises(WiringError, match="changed after the plan"):
        apply_rename(partial)
    assert {name: (config_dir / name).read_bytes() for name in SPLIT} == before


def test_a_rename_write_error_survives_pickling() -> None:
    import pickle

    exc = impact.RenameWriteError("writing a.py failed", ["a.py"])
    back = pickle.loads(pickle.dumps(exc))
    assert (str(back), back.unrestored) == ("writing a.py failed", ["a.py"])


def test_codeset_rename_says_so_when_the_table_cannot_be_moved_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rewrite fails, and so does the move back: the message keeps the rewrite's own text,
    then says where the table was left and that its references still name the old table."""
    from messagefoundry import restricted_file

    mod = CODESET_MOD.replace("r_cs_misspelled", "r_cs")
    config_dir = _config(tmp_path, {"mod.py": mod, "codesets/diets.csv": "code,value\nA,Apple\n"})
    real_move = restricted_file.replace_generated
    moves: list[str] = []

    def second_move_fails(src: Path, dest: Path) -> None:
        moves.append(Path(dest).name)
        if len(moves) == 2:
            raise PermissionError("held open")
        real_move(src, dest)

    def write_fails(prepared: impact.PreparedRename) -> list[impact.LiteralEdit]:
        raise impact.RenameWriteError("writing mod.py failed. Nothing was written", [])

    monkeypatch.setattr(restricted_file, "replace_generated", second_move_fails)
    monkeypatch.setattr(impact, "write_rename", write_fails)
    with pytest.raises(WiringError) as caught:
        codeset_edit.rename_code_set(config_dir, "diets", "meals", validate=_validate)
    message = str(caught.value)
    assert message.startswith("writing mod.py failed. Nothing was written. The code set was then")
    assert "left as meals.csv" in message and "still name 'diets'" in message


def test_the_codeset_rename_row_spells_its_steps_in_words() -> None:
    """CLAUDE.md section 11: the rename row of docs/CODESETS.md says its steps in words, with no
    arrow glyph standing in for "then" or "to"."""
    docs = Path(__file__).resolve().parents[1] / "docs" / "CODESETS.md"
    row = next(
        line
        for line in docs.read_text(encoding="utf-8").splitlines()
        if line.startswith("| `messagefoundry codeset rename")
    )
    assert not any(ord(ch) > 0x7F for ch in row), row
