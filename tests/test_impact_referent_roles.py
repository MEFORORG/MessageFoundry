# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A rename rewrites a literal only in its referent role (BACKLOG #5980).

Before this, every plain literal equal to the old name inside a referrer's body or the definition
statement was rewritten, whatever it did there: a field comparison, a lookup key, or a sibling
argument naming a different object would have changed with it, and the applied config would load
with altered logic. These load real config modules and check that only the name-bearing literal
moves, that a name carried through a local variable still moves, and that a referrer still reading
the old name in another role is reported unresolved rather than passed as clean."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.impact import apply_rename, plan_rename
from messagefoundry.config.reachability import Reference
from messagefoundry.config.wiring import load_config

_HEAD = "from messagefoundry import MLLP, Send, code_set, handler, inbound, outbound, router\n\n"


def _write_config(tmp_path: Path, body: str, codesets: tuple[str, ...] = ()) -> Path:
    d = tmp_path / "config"
    d.mkdir()
    (d / "mod.py").write_text(_HEAD + body, encoding="utf-8", newline="")
    if codesets:
        (d / "codesets").mkdir()
        for name in codesets:
            (d / "codesets" / f"{name}.csv").write_text(
                "code,value\nA,Apple\n", encoding="utf-8", newline=""
            )
    return d


def _mod(config_dir: Path) -> str:
    return (config_dir / "mod.py").read_text(encoding="utf-8")


def test_a_field_comparison_equal_to_the_outbound_name_is_left_and_reported(
    tmp_path: Path,
) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_C", MLLP(port=2801), router="r_c")\n'
        'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6951))\n'
        "\n"
        '@router("r_c")\n'
        "def r_c(msg):\n"
        '    return ["h_c"]\n'
        "\n"
        '@handler("h_c")\n'
        "def h_c(msg):\n"
        '    if str(msg) == "OB_OLD":\n'
        "        return None\n"
        '    return Send("OB_OLD", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    apply_rename(plan)
    text = _mod(config_dir)
    assert 'outbound("OB_NEW"' in text
    assert 'return Send("OB_NEW", msg)' in text
    assert 'if str(msg) == "OB_OLD":' in text
    # The handler still reads the old name, so the plan must not pass it as fully rewritten.
    assert plan.unresolved == (Reference("handler", "h_c", "outbound", "OB_OLD"),)


def test_a_send_target_carried_by_a_local_variable_is_rewritten(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_V", MLLP(port=2802), router="r_v")\n'
        'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6952))\n'
        'outbound("OB_ALT", MLLP(host="127.0.0.1", port=6953))\n'
        "\n"
        '@router("r_v")\n'
        "def r_v(msg):\n"
        '    return ["h_v"]\n'
        "\n"
        '@handler("h_v")\n'
        "def h_v(msg):\n"
        '    dest = "OB_OLD" if msg else "OB_ALT"\n'
        "    return Send(dest, msg)\n",
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert 'dest = "OB_NEW" if msg else "OB_ALT"' in _mod(config_dir)
    load_config(config_dir)


def test_a_router_rename_leaves_an_inbound_of_the_same_name(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("adt", MLLP(port=2803), router="adt")\n'
        'outbound("OB_A", MLLP(host="127.0.0.1", port=6954))\n'
        "\n"
        '@router("adt")\n'
        "def adt(msg):\n"
        '    return ["h_a"]\n'
        "\n"
        '@handler("h_a")\n'
        "def h_a(msg):\n"
        '    return Send("OB_A", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "router", "adt", "adt_router")
    assert plan.unresolved == ()
    apply_rename(plan)
    text = _mod(config_dir)
    assert 'inbound("adt", MLLP(port=2803), router="adt_router")' in text
    assert '@router("adt_router")' in text
    registry = load_config(config_dir)
    assert set(registry.inbound) == {"adt"}


def test_an_inbound_rename_leaves_a_router_of_the_same_name(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("adt", MLLP(port=2804), router="adt")\n'
        'outbound("OB_B", MLLP(host="127.0.0.1", port=6955))\n'
        "\n"
        '@router("adt")\n'
        "def adt(msg):\n"
        '    return ["h_b"]\n'
        "\n"
        '@handler("h_b")\n'
        "def h_b(msg):\n"
        '    return Send("OB_B", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "inbound", "adt", "IB_ADT")
    apply_rename(plan)
    text = _mod(config_dir)
    assert 'inbound("IB_ADT", MLLP(port=2804), router="adt")' in text
    assert '@router("adt")' in text
    load_config(config_dir)


def test_a_definition_sibling_argument_equal_to_the_name_is_left(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_S", MLLP(port=2805), router="r_s")\n'
        'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6956), metadata={"feed": "OB_OLD"})\n'
        "\n"
        '@router("r_s")\n'
        "def r_s(msg):\n"
        '    return ["h_s"]\n'
        "\n"
        '@handler("h_s")\n'
        "def h_s(msg):\n"
        '    return Send("OB_OLD", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    apply_rename(plan)
    assert (
        'outbound("OB_NEW", MLLP(host="127.0.0.1", port=6956), metadata={"feed": "OB_OLD"})'
        in _mod(config_dir)
    )
    load_config(config_dir)


def test_a_handler_rename_leaves_a_router_comparison_and_follows_a_collected_list(
    tmp_path: Path,
) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_H", MLLP(port=2806), router="r_h")\n'
        'outbound("OB_H", MLLP(host="127.0.0.1", port=6957))\n'
        "\n"
        '@router("r_h")\n'
        "def r_h(msg):\n"
        "    out = []\n"
        '    if str(msg) == "h_old":\n'
        '        out.append("h_old")\n'
        "    return out\n"
        "\n"
        '@handler("h_old")\n'
        "def h_old(msg):\n"
        '    return Send("OB_H", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "handler", "h_old", "h_new")
    apply_rename(plan)
    text = _mod(config_dir)
    assert '@handler("h_new")' in text
    assert 'out.append("h_new")' in text
    assert 'if str(msg) == "h_old":' in text
    assert plan.unresolved == (Reference("router", "r_h", "handler", "h_old"),)
    load_config(config_dir)


def test_a_code_set_lookup_key_equal_to_the_table_name_is_left_and_reported(
    tmp_path: Path,
) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_K", MLLP(port=2807), router="r_k")\n'
        'outbound("OB_K", MLLP(host="127.0.0.1", port=6958))\n'
        "\n"
        '@router("r_k")\n'
        "def r_k(msg):\n"
        '    return ["h_k"]\n'
        "\n"
        '@handler("h_k")\n'
        "def h_k(msg):\n"
        '    label = code_set("diets").get("diets")\n'
        '    return Send("OB_K", msg)\n',
        codesets=("diets",),
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    assert [e.new_literal for e in plan.edits] == ['"meals"']
    assert plan.edits[0].start_col == len("    label = code_set(")
    assert plan.unresolved == (Reference("handler", "h_k", "code_set", "diets"),)


_FANOUT_HEAD = (
    'inbound("IB_F", MLLP(port=2808), router="r_f")\n'
    'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6959))\n'
    'outbound("OB_ALT", MLLP(host="127.0.0.1", port=6960))\n'
    "\n"
    "def _out(dest, msg):\n"
    "    return Send(dest, msg)\n"
    "\n"
    '@router("r_f")\n'
    "def r_f(msg):\n"
    '    return ["h_f"]\n'
    "\n"
    '@handler("h_f")\n'
    "def h_f(msg):\n"
)


@pytest.mark.parametrize(
    "body",
    [
        '    return [Send(d, msg) for d in ("OB_OLD", "OB_ALT")]\n',
        '    out = []\n    for d in ["OB_OLD", "OB_ALT"]:\n        out.append(Send(d, msg))\n'
        "    return out\n",
        '    a, b = "OB_OLD", "OB_ALT"\n    return [Send(a, msg), Send(b, msg)]\n',
        '    return _out("OB_OLD", msg)\n',
        '    return _out(dest="OB_OLD", msg=msg)\n',
    ],
)
def test_fan_out_send_forms_are_rewritten(tmp_path: Path, body: str) -> None:
    config_dir = _write_config(tmp_path, _FANOUT_HEAD + body)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    text = _mod(config_dir)
    assert '"OB_OLD"' not in text
    assert '"OB_ALT"' in text
    load_config(config_dir)


_ROUTER_FORMS_HEAD = (
    'inbound("IB_RF", MLLP(port=2809), router="r_rf")\n'
    'outbound("OB_RF", MLLP(host="127.0.0.1", port=6961))\n'
    "\n"
    '@handler("h_old")\n'
    "def h_old(msg):\n"
    '    return Send("OB_RF", msg)\n'
    "\n"
    '@handler("h_x")\n'
    "def h_x(msg):\n"
    '    return Send("OB_RF", msg)\n'
    "\n"
    '@router("r_rf")\n'
    "def r_rf(msg):\n"
)


@pytest.mark.parametrize(
    "body",
    [
        '    yield "h_old"\n',
        '    routes = {"ADT": "h_old"}\n    return [routes.get(str(msg), "h_x")]\n',
        '    return list({"h_old"})\n',
        '    base = ["h_x"]\n    return base + ["h_old"]\n',
    ],
)
def test_router_return_forms_are_rewritten(tmp_path: Path, body: str) -> None:
    config_dir = _write_config(tmp_path, _ROUTER_FORMS_HEAD + body)
    plan = plan_rename(load_config(config_dir), config_dir, "handler", "h_old", "h_new")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert '"h_old"' not in _mod(config_dir)
    load_config(config_dir)


def test_a_wrapped_outbound_definition_is_renamed(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        "def _keep(conn):\n"
        "    return conn\n"
        "\n"
        'inbound("IB_W", MLLP(port=2810), router="r_w")\n'
        '_keep(outbound("OB_OLD", MLLP(host="127.0.0.1", port=6962)))\n'
        "\n"
        '@router("r_w")\n'
        "def r_w(msg):\n"
        '    return ["h_w"]\n'
        "\n"
        '@handler("h_w")\n'
        "def h_w(msg):\n"
        '    return Send("OB_OLD", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    apply_rename(plan)
    assert '_keep(outbound("OB_NEW"' in _mod(config_dir)
    load_config(config_dir)


def test_a_wrapped_declaration_is_renamed(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        "from messagefoundry import DatabaseLookup, db_lookup\n"
        "\n"
        "def _keep(spec):\n"
        "    return spec\n"
        "\n"
        'inbound("IB_L", MLLP(port=2814), router="r_l")\n'
        'outbound("OB_L", MLLP(host="127.0.0.1", port=6966))\n'
        '_keep(DatabaseLookup("clarity", server="db", database="C", username="u", password="p"))\n'
        "\n"
        '@router("r_l")\n'
        "def r_l(msg):\n"
        '    return ["h_l"]\n'
        "\n"
        '@handler("h_l")\n'
        "def h_l(msg):\n"
        '    row = db_lookup("clarity", "SELECT 1", ())\n'
        '    return Send("OB_L", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "lookup", "clarity", "clarity2")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert '"clarity"' not in _mod(config_dir)
    load_config(config_dir)


def test_a_table_name_passed_to_a_helper_parameter_is_rewritten(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_T", MLLP(port=2811), router="r_t")\n'
        'outbound("OB_T", MLLP(host="127.0.0.1", port=6963))\n'
        "\n"
        "def _lookup(code, table):\n"
        "    return code_set(table).get(code)\n"
        "\n"
        '@router("r_t")\n'
        "def r_t(msg):\n"
        '    return ["h_t"]\n'
        "\n"
        '@handler("h_t")\n'
        "def h_t(msg):\n"
        '    label = _lookup("A", "diets")\n'
        '    return Send("OB_T", msg)\n',
        codesets=("diets",),
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    assert plan.unresolved == ()
    assert [e.new_literal for e in plan.edits] == ['"meals"']


def test_a_name_read_only_in_a_comparison_is_left_outside_the_body(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_M", MLLP(port=2812), router="r_m")\n'
        'outbound("OB_M", MLLP(host="127.0.0.1", port=6964))\n'
        'SKIP = "h_old"\n'
        "\n"
        "def _tag():\n"
        '    return "h_old"\n'
        "\n"
        '@router("r_m")\n'
        "def r_m(msg):\n"
        "    if str(msg) == SKIP or str(msg) == _tag():\n"
        "        return []\n"
        '    return ["h_old"]\n'
        "\n"
        '@handler("h_old")\n'
        "def h_old(msg):\n"
        '    return Send("OB_M", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "handler", "h_old", "h_new")
    apply_rename(plan)
    text = _mod(config_dir)
    assert 'SKIP = "h_old"' in text
    assert '    return "h_old"\n' in text
    assert 'return ["h_new"]' in text
    assert plan.unresolved == (Reference("router", "r_m", "handler", "h_old"),)


def test_a_stacked_decorator_argument_equal_to_the_name_is_left(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        "def tag(_label):\n"
        "    return lambda fn: fn\n"
        "\n"
        'inbound("IB_D", MLLP(port=2813), router="r_d")\n'
        'outbound("OB_D", MLLP(host="127.0.0.1", port=6965))\n'
        "\n"
        '@router("r_d")\n'
        "def r_d(msg):\n"
        '    return ["h_old"]\n'
        "\n"
        '@handler("h_old")\n'
        '@tag("h_old")\n'
        "def h_old(msg):\n"
        '    return Send("OB_D", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "handler", "h_old", "h_new")
    apply_rename(plan)
    assert '@handler("h_new")\n@tag("h_old")' in _mod(config_dir)
    load_config(config_dir)
