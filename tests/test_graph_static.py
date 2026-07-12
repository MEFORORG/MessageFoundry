# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The authoritative static wiring graph (ADR 0091 D1): ``config.graph`` extraction tiers +
provenance, the ``graph --json`` v2 CLI shape, and the ``send-target`` advisory (AC-1/2/3/5/7)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry import checks
from messagefoundry.__main__ import main
from messagefoundry.config.graph import WiringGraph, build_wiring_graph
from messagefoundry.config.wiring import load_config

CONFIG = """\
from messagefoundry import File, PassThrough, Send, handler, inbound, outbound, router

OB_CONST = "OB_Const_Target"

inbound("IB_A", File(directory="in_a"), router="route_shared")
inbound("IB_B", File(directory="in_b"), router="route_shared")
inbound("PT_Internal", PassThrough(), router="route_pt")
outbound("OB_Main", File(directory="out_main"))
outbound("OB_Const_Target", File(directory="out_const"))


@router("route_shared")
def route_shared(msg):
    return ["xform_main", "relay_const"]


@router("route_pt")
def route_pt(msg):
    return "xform_main"


@router("route_dynamic")
def route_dynamic(msg):
    name = "xform" + str(msg.field("MSH-9"))
    return [name]


@handler("xform_main")
def xform_main(msg):
    return [Send("OB_Main", msg), Send("PT_Internal", msg)]


@handler("relay_const")
def relay_const(msg):
    # The module-level constant target — the co_consts tier is blind to it (the constant lives in
    # the MODULE's code object), so only the AST tier can prove this edge.
    return Send(OB_CONST, msg)


@handler("xform_local")
def xform_local(msg):
    ob = "OB_Main"
    return Send(ob, msg)


@handler("xform_dynamic")
def xform_dynamic(msg):
    return Send(_pick(msg), msg)


def _pick(msg):
    return "OB_Elsewhere"
"""


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    d = tmp_path / "config"
    d.mkdir()
    (d / "estate.py").write_text(CONFIG, encoding="utf-8")
    return d


def _edges(graph, kind: str, name: str) -> dict[tuple[str, str], str]:
    return {(e.target_kind, e.target): e.provenance for e in graph.targets(kind, name)}


def test_elements_once_with_forward_and_reverse_edges(cfg: Path) -> None:
    # AC-1 / AC-5: one graph, every edge directed + provenanced, fan-in resolvable for every element.
    g = build_wiring_graph(load_config(cfg))
    # Declared inbound -> router; the shared router's fan-in lists BOTH inbounds.
    assert {(e.source, e.provenance) for e in g.referrers("router", "route_shared")} == {
        ("IB_A", "declared"),
        ("IB_B", "declared"),
    }
    # Router -> handler edges are AST-proven from the return statements.
    assert _edges(g, "router", "route_shared") == {
        ("handler", "xform_main"): "literal",
        ("handler", "relay_const"): "literal",
    }
    # A bare-string return ("xform_main", no list) resolves the same way.
    assert _edges(g, "router", "route_pt") == {("handler", "xform_main"): "literal"}
    # Handler fan-in: xform_main is fed by both routers (AC-5).
    assert {e.source for e in g.referrers("handler", "xform_main")} == {"route_shared", "route_pt"}


def test_module_constant_send_target_is_literal(cfg: Path) -> None:
    # The truncated-chain defect: Send(OB_CONST) with OB_CONST = "..." at module level. The old
    # co_consts scan missed it; the AST tier proves it.
    g = build_wiring_graph(load_config(cfg))
    assert _edges(g, "handler", "relay_const") == {("outbound", "OB_Const_Target"): "literal"}
    assert not g.is_dynamic("handler", "relay_const")


def test_pass_through_send_target_is_an_inbound_edge_not_dangling(cfg: Path) -> None:
    g = build_wiring_graph(load_config(cfg))
    assert _edges(g, "handler", "xform_main") == {
        ("outbound", "OB_Main"): "literal",
        ("inbound", "PT_Internal"): "literal",
    }
    assert not any(d.source == "xform_main" for d in g.dangling)


def test_local_variable_target_resolves_via_dataflow(cfg: Path) -> None:
    # `ob = "OB_Main"; Send(ob, ...)` — the conservative function-local dataflow tier proves the
    # local, so the edge is LITERAL and the element is NOT dynamic (previously heuristic+dynamic).
    g = build_wiring_graph(load_config(cfg))
    assert _edges(g, "handler", "xform_local") == {("outbound", "OB_Main"): "literal"}
    assert not g.is_dynamic("handler", "xform_local")


def test_computed_targets_mark_dynamic_never_silently_empty(cfg: Path) -> None:
    # AC-3: a genuinely computed name yields NO edge but a dynamic marker — never a silent stop.
    g = build_wiring_graph(load_config(cfg))
    assert g.is_dynamic("handler", "xform_dynamic")
    assert g.is_dynamic("router", "route_dynamic")


def test_graph_cli_v2_shape_and_backward_compat(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # AC-1 (CLI) + AC-7: v2 adds version/edges/fed_by/receives_from/dynamic; v1 fields intact.
    assert main(["graph", "--config", str(cfg), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == 2
    by_name = {r["name"]: r for r in data["routers"]}
    shared = by_name["route_shared"]
    # v1 fields survive unchanged in meaning.
    assert shared["handlers"] == ["relay_const", "xform_main"]
    assert shared["file"] and shared["line"]
    # v2: reverse adjacency + provenanced edges.
    assert shared["fed_by"] == ["IB_A", "IB_B"]
    assert {(e["target"], e["provenance"]) for e in shared["edges"]} == {
        ("relay_const", "literal"),
        ("xform_main", "literal"),
    }
    handlers = {h["name"]: h for h in data["handlers"]}
    assert handlers["relay_const"]["sends"] == ["OB_Const_Target"]  # v1 field, AST-completed
    assert handlers["xform_main"]["fed_by"] == ["route_pt", "route_shared"]
    assert handlers["xform_dynamic"]["dynamic"] is True
    outbound = {o["name"]: o for o in data["outbound"]}
    assert outbound["OB_Main"]["receives_from"] == ["xform_local", "xform_main"]
    inbound = {i["name"]: i for i in data["inbound"]}
    assert inbound["PT_Internal"]["receives_from"] == ["xform_main"]
    assert inbound["IB_A"]["router"] == "route_shared"  # v1 field


def test_send_target_advisory_flags_dangling_literals_never_blocks(tmp_path: Path) -> None:
    # AC-2: a literal Send/return target that names nothing registered — advisory, required=False.
    d = tmp_path / "config"
    d.mkdir()
    (d / "feed.py").write_text(
        "from messagefoundry import File, Send, handler, inbound, outbound, router\n"
        "inbound('IB_X', File(directory='in_x'), router='route_x')\n"
        "outbound('OB_Real', File(directory='out_x'))\n"
        "@router('route_x')\n"
        "def route_x(msg):\n"
        "    return ['no_such_handler', 'xform_x']\n"
        "@handler('xform_x')\n"
        "def xform_x(msg):\n"
        "    return Send('OB_Typo', msg)\n",
        encoding="utf-8",
    )
    res = checks._check_send_target(d)
    assert res.required is False and res.ok is False and res.skipped is False
    assert "'xform_x'" in res.detail and "'OB_Typo'" in res.detail
    assert "'route_x'" in res.detail and "'no_such_handler'" in res.detail


def test_send_target_advisory_skips_clean_config(cfg: Path) -> None:
    res = checks._check_send_target(cfg)
    assert res.ok is True and res.required is False and res.skipped is True


# ---------------------------------------------------------------------------
# Function-local dataflow (conservative may-route union) — resolves the common accumulation
# idioms as LITERAL, and poisons anything it cannot replay back to dynamic.
# ---------------------------------------------------------------------------

DATAFLOW_CONFIG = """\
from messagefoundry import File, Send, handler, inbound, outbound, router
from messagefoundry import Send as _S

inbound("IB_X", File(directory="in_x"), router="route_append")
outbound("OB_Main", File(directory="out_main"))
outbound("OB_Alt", File(directory="out_alt"))

H2 = "h_two"
H3 = "h_three"
OB_FD = "OB_Main"
OB_CF = "OB_Alt"


@router("route_append")
def route_append(msg):
    targets = ["h_one"]
    if msg.field("MSH-9") == "ADT":
        targets.append("h_two")
    return targets


@router("route_branch")
def route_branch(msg):
    if msg.field("MSH-9") == "ADT":
        t = ["h_one"]
    else:
        t = ["h_two"]
    return t


@router("route_extend")
def route_extend(msg):
    targets = ["h_one"]
    targets.extend(["h_two", "h_three"])
    targets += ["h_four"]
    return targets


@router("route_multi_return")
def route_multi_return(msg):
    if msg.field("MSH-9") == "SIU":
        return []
    if msg.field("MSH-9") == "ORM":
        return ["h_one"]
    targets = ["h_two"]
    return targets


@router("route_alias_mutation")
def route_alias_mutation(msg):
    targets = ["h_one"]
    alias = targets
    alias.append(_pick(msg))
    return targets


@router("route_alias_call")
def route_alias_call(msg):
    targets = ["h_one"]
    _mangle(targets)
    return targets


@router("route_computed_append")
def route_computed_append(msg):
    targets = ["h_one"]
    targets.append(_pick(msg))
    return targets


@router("route_nested_mutation")
def route_nested_mutation(msg):
    targets = ["h_one"]

    def _grow():
        targets.append("h_two")

    _grow()
    return targets


@router("route_for_shadow")
def route_for_shadow(msg):
    for targets in _groups(msg):
        return targets
    return []


@router("route_copy_concat")
def route_copy_concat(msg):
    base = ["h_one"]
    if msg.field("MSH-9") == "SIU":
        return list(base)
    if msg.field("MSH-9") == "ORM":
        return base + ["h_two"]
    zero_all = ["h_three"]
    targets: list[str] = list(zero_all)
    targets.append("h_four")
    targets += ["h_one"]
    return base + targets


@router("route_loop_carried")
def route_loop_carried(msg):
    x = "h_one"
    t = []
    for seg in _groups(msg):
        t += [x]
        x = H2
    return t


@router("route_str_concat")
def route_str_concat(msg):
    t = "h_one"
    t += "x"
    return t


@router("route_list_plus_str")
def route_list_plus_str(msg):
    t = ["h_two"]
    t += "ab"
    return t


@router("route_ann_alias")
def route_ann_alias(msg):
    targets = ["h_one"]
    alias: list = targets
    alias.append(_pick(msg))
    return targets


@router("route_walrus_alias")
def route_walrus_alias(msg):
    targets = ["h_one"]
    (alias := targets)
    alias.append(_pick(msg))
    return targets


@router("route_or_alias")
def route_or_alias(msg):
    targets = ["h_one"]
    alias = targets or []
    alias.append(_pick(msg))
    return targets


@router("route_ifexp_alias")
def route_ifexp_alias(msg):
    targets = ["h_one"]
    alias = targets if msg else []
    alias.append(_pick(msg))
    return targets


@router("route_box_alias")
def route_box_alias(msg):
    targets = ["h_one"]
    box = [targets]
    box[0].append(_pick(msg))
    return targets


@router("route_dict_alias")
def route_dict_alias(msg):
    targets = ["h_one"]
    d = {"k": targets}
    d["k"].append(_pick(msg))
    return targets


@router("route_star_call")
def route_star_call(msg):
    targets = ["h_one"]
    _mangle(*[targets])
    return targets


@router("route_match_subject")
def route_match_subject(msg):
    targets = ["h_one"]
    match targets:
        case whole:
            whole.append(H2)
    return targets


@router("route_for_display")
def route_for_display(msg):
    adt = ["h_one"]
    oru = ["h_two"]
    for lst in (adt, oru):
        lst.append(H3)
    return adt if msg.field("MSH-9") == "ADT" else oru


@router("route_display_subscript")
def route_display_subscript(msg):
    targets = ["h_one"]
    x = [targets][0]
    x.append(H2)
    return targets


@router("route_assert_msg")
def route_assert_msg(msg):
    targets = ["h_one"]
    try:
        assert msg.field("MSH-9"), targets
    except AssertionError as e:
        e.args[0].append(H2)
    return targets


@router("route_copy_rebind")
def route_copy_rebind(msg):
    t = sorted(["h_one"])
    return t


@router("route_yield")
def route_yield(msg):
    yield H2


def _evil(x):
    return [H2]


sorted = _evil


def _mk(m):
    return Send(OB_FD, m)


@handler("relay_helper")
def relay_helper(msg):
    return _mk(msg)


@handler("relay_helper_var")
def relay_helper_var(msg):
    s = _mk(msg)
    return s


@handler("relay_alias")
def relay_alias(msg):
    return _S(OB_CF, msg)


@handler("relay_ifexp")
def relay_ifexp(msg):
    flag = msg.field("ZRX-1") or ""
    dest = OB_FD if flag == "N" else OB_CF
    return Send(dest, msg)


@handler("ab")
def ab(msg):
    return Send("OB_Alt", msg)


@handler("h_one")
def h_one(msg):
    ob = "OB_Main"
    return Send(ob, msg)


@handler("h_two")
def h_two(msg):
    return Send("OB_Alt", msg)


@handler("h_three")
def h_three(msg):
    return Send("OB_Alt", msg)


@handler("h_four")
def h_four(msg):
    return Send("OB_Alt", msg)


def _pick(msg):
    return "h_two"


def _mangle(targets):
    targets.append("h_two")


def _groups(msg):
    return [["h_one"]]
"""


@pytest.fixture
def dataflow_graph(tmp_path: Path) -> WiringGraph:
    d = tmp_path / "config"
    d.mkdir()
    (d / "estate.py").write_text(DATAFLOW_CONFIG, encoding="utf-8")
    return build_wiring_graph(load_config(d))


def test_dataflow_assign_then_conditional_append_is_literal(dataflow_graph: WiringGraph) -> None:
    # (a) targets = ["h1"]; if cond: targets.append("h2"); return targets — both edges proven.
    assert _edges(dataflow_graph, "router", "route_append") == {
        ("handler", "h_one"): "literal",
        ("handler", "h_two"): "literal",
    }
    assert not dataflow_graph.is_dynamic("router", "route_append")


def test_dataflow_branch_reassignment_unions_both_arms(dataflow_graph: WiringGraph) -> None:
    # (b) if x: t = ["a"] else: t = ["b"] — may-route union of both branches.
    assert _edges(dataflow_graph, "router", "route_branch") == {
        ("handler", "h_one"): "literal",
        ("handler", "h_two"): "literal",
    }
    assert not dataflow_graph.is_dynamic("router", "route_branch")


def test_dataflow_extend_and_augassign_accumulate(dataflow_graph: WiringGraph) -> None:
    # (d) targets.extend([...]) and targets += [...] union in like append.
    assert _edges(dataflow_graph, "router", "route_extend") == {
        ("handler", "h_one"): "literal",
        ("handler", "h_two"): "literal",
        ("handler", "h_three"): "literal",
        ("handler", "h_four"): "literal",
    }
    assert not dataflow_graph.is_dynamic("router", "route_extend")


def test_dataflow_multi_return_unions_and_empty_contributes_nothing(
    dataflow_graph: WiringGraph,
) -> None:
    # (e) several returns: [] adds nothing, a literal list and a tracked local both union in.
    assert _edges(dataflow_graph, "router", "route_multi_return") == {
        ("handler", "h_one"): "literal",
        ("handler", "h_two"): "literal",
    }
    assert not dataflow_graph.is_dynamic("router", "route_multi_return")


def test_dataflow_local_send_target_is_literal(dataflow_graph: WiringGraph) -> None:
    # (c) ob = "OB_X"; return Send(ob, msg) — the Send target reference is not an escape.
    assert _edges(dataflow_graph, "handler", "h_one") == {("outbound", "OB_Main"): "literal"}
    assert not dataflow_graph.is_dynamic("handler", "h_one")


def test_dataflow_alias_mutation_poisons_both_names(dataflow_graph: WiringGraph) -> None:
    # alias = targets; alias.append(computed) — mutation through the alias is invisible to
    # `targets`' env entry, so BOTH names are poisoned: dynamic, edge only heuristic.
    assert _edges(dataflow_graph, "router", "route_alias_mutation") == {
        ("handler", "h_one"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_alias_mutation")


def test_dataflow_call_argument_aliasing_poisons(dataflow_graph: WiringGraph) -> None:
    # _mangle(targets) — the list escapes as a bare-Name call argument: dynamic, heuristic only.
    assert _edges(dataflow_graph, "router", "route_alias_call") == {
        ("handler", "h_one"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_alias_call")


def test_dataflow_computed_append_poisons(dataflow_graph: WiringGraph) -> None:
    # targets.append(f(msg)) — an unresolvable appended value poisons the whole local.
    assert _edges(dataflow_graph, "router", "route_computed_append") == {
        ("handler", "h_one"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_computed_append")


def test_dataflow_nested_def_mutation_poisons(dataflow_graph: WiringGraph) -> None:
    # A nested helper appending to the outer list mutates outside the forward scan — dynamic;
    # the co_consts heuristic (which recurses into nested code) still recovers both names.
    assert _edges(dataflow_graph, "router", "route_nested_mutation") == {
        ("handler", "h_one"): "heuristic",
        ("handler", "h_two"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_nested_mutation")


def test_dataflow_for_target_shadowing_poisons(dataflow_graph: WiringGraph) -> None:
    # `for targets in ...: return targets` — a loop binding is caller-data, never a literal.
    assert _edges(dataflow_graph, "router", "route_for_shadow") == {}
    assert dataflow_graph.is_dynamic("router", "route_for_shadow")


def test_dataflow_copy_calls_and_list_concat_resolve(dataflow_graph: WiringGraph) -> None:
    # A ported-estate ADT-hub idiom: `return list(base)`, `base + [...]`,
    # `targets: list[str] = list(zero_all)` — copies and list concatenation are proven literal.
    assert _edges(dataflow_graph, "router", "route_copy_concat") == {
        ("handler", "h_one"): "literal",
        ("handler", "h_two"): "literal",
        ("handler", "h_three"): "literal",
        ("handler", "h_four"): "literal",
    }
    assert not dataflow_graph.is_dynamic("router", "route_copy_concat")


def test_dataflow_loop_carried_value_reaches_fixpoint(dataflow_graph: WiringGraph) -> None:
    # `t += [x]` inside a for loop where x is reassigned to a module constant AFTER the append:
    # the value scan iterates to a fixpoint, so iteration 2's value (h_two) is in the union —
    # previously the single forward pass missed it while still claiming dynamic=False.
    assert _edges(dataflow_graph, "router", "route_loop_carried") == {
        ("handler", "h_one"): "literal",
        ("handler", "h_two"): "literal",
    }
    assert not dataflow_graph.is_dynamic("router", "route_loop_carried")


def test_dataflow_str_augassign_is_concatenation_not_union(dataflow_graph: WiringGraph) -> None:
    # `t = "h_one"; t += "x"` routes to "h_onex" at runtime — NEVER a literal edge to h_one
    # (that edge can never fire); the element is dynamic, the heuristic tier still surfaces it.
    assert _edges(dataflow_graph, "router", "route_str_concat") == {
        ("handler", "h_one"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_str_concat")


def test_dataflow_list_plus_str_extends_characters_not_names(dataflow_graph: WiringGraph) -> None:
    # `t = ["h_two"]; t += "ab"` extends with the CHARACTERS "a","b" — no literal edge to the
    # registered handler "ab" may be claimed; both surviving edges are heuristic-only.
    assert _edges(dataflow_graph, "router", "route_list_plus_str") == {
        ("handler", "h_two"): "heuristic",
        ("handler", "ab"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_list_plus_str")


@pytest.mark.parametrize(
    "router_name",
    [
        "route_ann_alias",  # alias: list = targets   (AnnAssign aliasing)
        "route_walrus_alias",  # (alias := targets)   (walrus captures the reference)
        "route_or_alias",  # alias = targets or []    (BoolOp yields the operand itself)
        "route_ifexp_alias",  # alias = targets if msg else []
        "route_box_alias",  # box = [targets]; box[0].append(...)  (container capture)
        "route_dict_alias",  # d = {"k": targets}; d["k"].append(...)
        "route_star_call",  # _mangle(*[targets])     (starred call-argument escape)
    ],
)
def test_dataflow_aliasing_escapes_poison(dataflow_graph: WiringGraph, router_name: str) -> None:
    # Every aliasing escape of the tracked list poisons it: a helper-computed name appended
    # through the alias would otherwise be a missing edge on a dynamic=False element.
    assert _edges(dataflow_graph, "router", router_name) == {
        ("handler", "h_one"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", router_name)


def test_dataflow_ifexp_of_module_constants_send_target(dataflow_graph: WiringGraph) -> None:
    # The pharmacy-cabinet-style handler: dest = OB_A if flag == "N" else OB_B; Send(dest, msg) —
    # an exhaustive if/else union of module constants is fully proven: both edges literal.
    assert _edges(dataflow_graph, "handler", "relay_ifexp") == {
        ("outbound", "OB_Main"): "literal",
        ("outbound", "OB_Alt"): "literal",
    }
    assert not dataflow_graph.is_dynamic("handler", "relay_ifexp")


def test_dataflow_match_subject_capture_poisons(dataflow_graph: WiringGraph) -> None:
    # `match targets: case whole:` — a bare capture pattern binds the SUBJECT itself; the mutation
    # through the binding-poisoned alias must poison the subject too (dynamic, heuristic only).
    assert _edges(dataflow_graph, "router", "route_match_subject") == {
        ("handler", "h_one"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_match_subject")


def test_dataflow_for_over_display_hands_out_element_refs(dataflow_graph: WiringGraph) -> None:
    # `for lst in (adt, oru): lst.append(H3)` — iterating a display yields the element REFERENCES;
    # both lists must be poisoned (dynamic; the runtime routes h_three too, invisible here).
    assert _edges(dataflow_graph, "router", "route_for_display") == {
        ("handler", "h_one"): "heuristic",
        ("handler", "h_two"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_for_display")


def test_dataflow_subscripted_display_hands_out_element_ref(dataflow_graph: WiringGraph) -> None:
    # `x = [targets][0]; x.append(H2)` — a read-position display still hands out the element.
    assert _edges(dataflow_graph, "router", "route_display_subscript") == {
        ("handler", "h_one"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_display_subscript")


def test_dataflow_assert_message_is_a_capture(dataflow_graph: WiringGraph) -> None:
    # `assert cond, targets` — a failing assert captures targets into AssertionError.args, which
    # the enclosing `except AssertionError as e:` mutates (`e.args[0].append(H2)`).
    assert _edges(dataflow_graph, "router", "route_assert_msg") == {
        ("handler", "h_one"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_assert_msg")


def test_dataflow_module_rebound_copy_call_is_not_trusted(dataflow_graph: WiringGraph) -> None:
    # `sorted = _evil` at module scope (a non-str, non-def rebind): `t = sorted(["h_one"])` may
    # return anything, so NO literal edge to h_one may be claimed (it would be a phantom on every
    # execution — the runtime routes h_two) and the element is dynamic.
    assert _edges(dataflow_graph, "router", "route_copy_rebind") == {
        ("handler", "h_one"): "heuristic",
    }
    assert dataflow_graph.is_dynamic("router", "route_copy_rebind")


def test_generator_router_is_dynamic_never_silently_static(dataflow_graph: WiringGraph) -> None:
    # `yield H2` — route_only routes the YIELDED values of a generator router; the return union
    # sees none of them, so the element must be dynamic (previously 0 edges + dynamic=False).
    assert _edges(dataflow_graph, "router", "route_yield") == {}
    assert dataflow_graph.is_dynamic("router", "route_yield")


def test_handler_helper_built_send_marks_dynamic(dataflow_graph: WiringGraph) -> None:
    # `return _mk(msg)` / `s = _mk(msg); return s` — transform_one partitions by isinstance, so a
    # helper-built Send DELIVERS at runtime while the call-site walk sees nothing: the handler
    # must carry the dynamic marker (AC-3), never render as a Send-free static element.
    for hname in ("relay_helper", "relay_helper_var"):
        assert _edges(dataflow_graph, "handler", hname) == {}, hname
        assert dataflow_graph.is_dynamic("handler", hname), hname


def test_handler_send_import_alias_resolves_literal(dataflow_graph: WiringGraph) -> None:
    # `from messagefoundry import Send as _S; return _S(OB_CF, msg)` — the alias builds real
    # Sends, so the target is extracted (literal) and the element is NOT dynamic.
    assert _edges(dataflow_graph, "handler", "relay_alias") == {("outbound", "OB_Alt"): "literal"}
    assert not dataflow_graph.is_dynamic("handler", "relay_alias")


# ---------------------------------------------------------------------------
# Module-constant validation — a "constant" any code can rebind is not a constant.
# ---------------------------------------------------------------------------

CONST_REBIND_CONFIG = """\
from messagefoundry import File, Send, handler, inbound, outbound, router

inbound("IB_C", File(directory="in_c"), router="route_global_rebind")
outbound("OB_Main", File(directory="out_main"))

HB = "h_one"
OBA = "OB_Main"
OBA += "x"
OBF = "OB_Main"
for OBF in ("OB_Alt",):
    pass


def _rebind():
    global HB
    HB = "h_" + "computed"


@router("route_global_rebind")
def route_global_rebind(msg):
    return HB


@handler("h_one")
def h_one(msg):
    return Send(OBA, msg)


@handler("h_for")
def h_for(msg):
    return Send(OBF, msg)
"""


def test_module_constant_rebinds_demote_to_heuristic(tmp_path: Path) -> None:
    # (a) `global HB` + rebind in ANY function, (b) module-level `OBA += "x"`, (c) module-level
    # `for OBF in ...` — each makes the top-level value stale, so no certain-looking LITERAL edge
    # may be emitted (the element is dynamic). But the once-literal value is DEMOTED to the
    # heuristic tier, not dropped: it lives in the MODULE's code object (invisible to the
    # function's co_consts scan), and dropping it would SHRINK the graph vs the pre-ADR-0091
    # extractor — a false dead-config report on h_one/OB_Main, which the runtime still routes to.
    d = tmp_path / "config"
    d.mkdir()
    (d / "estate.py").write_text(CONST_REBIND_CONFIG, encoding="utf-8")
    g = build_wiring_graph(load_config(d))
    for kind, name, expected in [
        ("router", "route_global_rebind", {("handler", "h_one"): "heuristic"}),
        ("handler", "h_one", {("outbound", "OB_Main"): "heuristic"}),
        ("handler", "h_for", {("outbound", "OB_Main"): "heuristic"}),
    ]:
        assert g.is_dynamic(kind, name), (kind, name)
        assert _edges(g, kind, name) == expected, (kind, name)
    assert not g.dangling  # a demoted value is uncertain — never reported as a dangling literal


# ---------------------------------------------------------------------------
# Round-3 regressions: the IfExp-test escape hole + send-plumbing locals
# (the two unresolved must-fixes from the adversarial verification pass)
# ---------------------------------------------------------------------------


def _graph_of(tmp_path: Path, body: str) -> WiringGraph:
    d = tmp_path / "config"
    d.mkdir()
    (d / "feed.py").write_text(body, encoding="utf-8")
    return build_wiring_graph(load_config(d))


_IFEXP_PRELUDE = """\
from messagefoundry import File, Send, handler, inbound, outbound, router

HIDDEN = "h_two"

inbound("IB_I", File(directory="in_i"), router="route_mut")
outbound("OB_I", File(directory="out_i"))


@handler("h_one")
def h_one(msg):
    return Send("OB_I", msg)


@handler("h_two")
def h_two(msg):
    return Send("OB_I", msg)
"""


def test_ifexp_test_mutation_marks_dynamic_never_silent(tmp_path: Path) -> None:
    # Verifier counterexample A: the append hides h_two from every tier (module-const arg), so the
    # element MUST carry the dynamic flag and MUST NOT claim its visible edges are literal.
    g = _graph_of(
        tmp_path,
        _IFEXP_PRELUDE
        + '@router("route_mut")\n'
        + "def route_mut(msg):\n"
        + '    targets = ["h_one"]\n'
        + "    return targets if targets.append(HIDDEN) else targets\n",
    )
    assert g.is_dynamic("router", "route_mut")
    assert all(e.provenance != "literal" for e in g.targets("router", "route_mut"))


def test_ifexp_test_mutation_no_phantom_literal(tmp_path: Path) -> None:
    # Verifier counterexample B: `targets.remove("h_two")` in test position — h_two never routes
    # at runtime, so a LITERAL h_two edge would be a phantom; heuristic + dynamic is the honest tier.
    g = _graph_of(
        tmp_path,
        _IFEXP_PRELUDE
        + '@router("route_mut")\n'
        + "def route_mut(msg):\n"
        + '    targets = ["h_one", "h_two"]\n'
        + '    return targets if targets.remove("h_two") else targets\n',
    )
    assert g.is_dynamic("router", "route_mut")
    assert all(e.provenance != "literal" for e in g.targets("router", "route_mut"))


def test_ifexp_call_over_untracked_names_still_resolves(tmp_path: Path) -> None:
    # `msg.field(...)` in the test cannot alias a fresh local list — the common conditional-return
    # idiom must stay statically proven (no over-conservative dynamic flag).
    g = _graph_of(
        tmp_path,
        _IFEXP_PRELUDE
        + '@router("route_mut")\n'
        + "def route_mut(msg):\n"
        + '    return ["h_one"] if msg.field("MSH-9") == "ADT" else ["h_two"]\n',
    )
    assert not g.is_dynamic("router", "route_mut")
    assert _edges(g, "router", "route_mut") == {
        ("handler", "h_one"): "literal",
        ("handler", "h_two"): "literal",
    }


_PLUMBING_PRELUDE = """\
from messagefoundry import File, Send, handler, inbound, outbound, router

inbound("IB_P", File(directory="in_p"), router="route_p")
outbound("OB_A", File(directory="out_a"))
outbound("OB_B", File(directory="out_b"))


@router("route_p")
def route_p(msg):
    return ["x_append", "x_firstvar"]
"""


def test_send_list_plumbing_locals_are_not_dynamic(tmp_path: Path) -> None:
    # The estate idioms that false-flagged (three Send-list-building transform handlers):
    # a local list built ONLY from this function's own Send(...) calls, then returned. Every Send
    # target was already extracted by the walk, so the handler is fully static.
    g = _graph_of(
        tmp_path,
        _PLUMBING_PRELUDE
        + '@handler("x_append")\n'
        + "def x_append(msg):\n"
        + '    sends = [Send("OB_A", msg)]\n'
        + '    if msg.field("PID-3"):\n'
        + '        sends.append(Send("OB_B", msg))\n'
        + "    return sends\n\n"
        + '@handler("x_firstvar")\n'
        + "def x_firstvar(msg):\n"
        + '    first = Send("OB_A", msg)\n'
        + '    return [first, Send("OB_B", msg)]\n',
    )
    for name in ("x_append", "x_firstvar"):
        assert not g.is_dynamic("handler", name), name
        assert _edges(g, "handler", name) == {
            ("outbound", "OB_A"): "literal",
            ("outbound", "OB_B"): "literal",
        }, name


def test_foreign_send_return_stays_dynamic(tmp_path: Path) -> None:
    # The blind spot the return check exists for: a helper-built Send is invisible to the call-site
    # walk, so the handler MUST stay dynamic (empty edges would otherwise read as complete).
    g = _graph_of(
        tmp_path,
        _PLUMBING_PRELUDE
        + '@handler("x_append")\n'
        + "def x_append(msg):\n"
        + "    return _mk(msg)\n\n"
        + '@handler("x_firstvar")\n'
        + "def x_firstvar(msg):\n"
        + '    return Send("OB_A", msg)\n\n'
        + "def _mk(msg):\n"
        + '    return Send("OB_B", msg)\n',
    )
    assert g.is_dynamic("handler", "x_append")


def test_module_global_accumulator_is_not_plumbing(tmp_path: Path) -> None:
    # Round-4 verifier counterexample: a module-level list seeded with a FOREIGN Send, appended-to
    # and returned by the handler. Append-receiver-only names must never qualify as plumbing — the
    # runtime delivers the foreign Send too, so the handler MUST be dynamic (its edge list is
    # incomplete: only the own-body Send is extractable).
    g = _graph_of(
        tmp_path,
        "from messagefoundry import File, Send, handler, inbound, outbound, router\n"
        'inbound("IB_G", File(directory="in_g"), router="route_g")\n'
        'outbound("OB_A", File(directory="out_a"))\n'
        'outbound("OB_FOREIGN", File(directory="out_f"))\n'
        'SENDS = [Send("OB_FOREIGN", None)]\n'
        '@router("route_g")\n'
        "def route_g(msg):\n"
        '    return "x_global"\n'
        '@handler("x_global")\n'
        "def x_global(msg):\n"
        '    SENDS.append(Send("OB_A", msg))\n'
        "    return SENDS\n",
    )
    assert g.is_dynamic("handler", "x_global")


def test_escaped_plumbing_local_stays_dynamic(tmp_path: Path) -> None:
    # Passing the list to ANY function disqualifies it — the callee could inject a foreign Send.
    g = _graph_of(
        tmp_path,
        _PLUMBING_PRELUDE
        + '@handler("x_append")\n'
        + "def x_append(msg):\n"
        + '    sends = [Send("OB_A", msg)]\n'
        + "    _audit(sends)\n"
        + "    return sends\n\n"
        + '@handler("x_firstvar")\n'
        + "def x_firstvar(msg):\n"
        + '    return Send("OB_B", msg)\n\n'
        + "def _audit(x):\n"
        + "    return None\n",
    )
    assert g.is_dynamic("handler", "x_append")
