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

import json
from pathlib import Path

import pytest

from messagefoundry.config.impact import apply_rename, plan_rename
from messagefoundry.config.reachability import Reference
from messagefoundry.config.wiring import load_config
from messagefoundry_toolkit.__main__ import main

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
    "def _or_alt(dest, msg):\n"
    '    dest = dest or "OB_ALT"\n'
    "    return Send(dest, msg)\n"
    "\n"
    "def _b(x):\n"
    "    return x\n"
    "\n"
    "def _a(x):\n"
    "    return _b(x)\n"
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
        '    return _or_alt("OB_OLD", msg)\n',
        '    return Send(_a("OB_OLD"), msg)\n',
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
        '    return [h for h in ("h_old", "h_x") if msg]\n',
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


_LEFT_HEAD = (
    'inbound("IB_N", MLLP(port=2815), router="r_n")\n'
    'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6967))\n'
    'outbound("TEST_OB_OLD", MLLP(host="127.0.0.1", port=6968))\n'
    'LABELS = {"OB_OLD": "x"}\n'
    "\n"
    "def get(dest, msg):\n"
    "    return Send(dest, msg)\n"
    "\n"
    '@router("r_n")\n'
    "def r_n(msg):\n"
    '    return ["h_n"]\n'
    "\n"
    '@handler("h_n")\n'
    "def h_n(msg):\n"
)


@pytest.mark.parametrize(
    ("body", "kept"),
    [
        # A method named like a config helper is not that helper.
        ('    tag = LABELS.get("OB_OLD")\n    return get("OB_OLD", msg)\n', 'LABELS.get("OB_OLD")'),
        # A fragment of a target being built is not the target.
        (
            '    env = "TEST_"\n    dest = "OB_OLD"\n    return Send(env + dest, msg)\n',
            'dest = "OB_OLD"',
        ),
    ],
)
def test_a_literal_that_only_resembles_a_role_is_left(tmp_path: Path, body: str, kept: str) -> None:
    config_dir = _write_config(tmp_path, _LEFT_HEAD + body)
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    apply_rename(plan)
    assert kept in _mod(config_dir)
    assert plan.unresolved == (Reference("handler", "h_n", "outbound", "OB_OLD"),)


def test_an_aliased_send_and_a_same_named_handler_are_handled(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        "from messagefoundry import Send as S\n"
        "\n"
        'inbound("IB_E", MLLP(port=2816), router="r_e")\n'
        'outbound("EPIC", MLLP(host="127.0.0.1", port=6969))\n'
        "\n"
        '@router("r_e")\n'
        "def r_e(msg):\n"
        '    return ["EPIC"]\n'
        "\n"
        '@handler("EPIC")\n'
        "def epic(msg):\n"
        '    return S("EPIC", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "EPIC", "OB_EPIC")
    # The handler's own decorator names the handler; it is neither rewritten nor counted.
    assert plan.unresolved == ()
    apply_rename(plan)
    text = _mod(config_dir)
    assert 'return S("OB_EPIC", msg)' in text
    assert '@handler("EPIC")' in text
    load_config(config_dir)


def test_an_accepts_lambda_is_scanned_not_a_lambda_in_the_body(tmp_path: Path) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_P", MLLP(port=2817), router="r_p")\n'
        'outbound("OB_P", MLLP(host="127.0.0.1", port=6970))\n'
        "\n"
        '@router("r_p")\n'
        "def r_p(msg):\n"
        '    return ["h_p"]\n'
        "\n"
        '@handler("h_p", accepts=lambda m: code_set("diets").get("A") is not None)\n'
        "def h_p(msg):\n"
        "    key = lambda m: m\n"
        '    return Send("OB_P", key(msg))\n',
        codesets=("diets",),
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    assert plan.unresolved == ()
    assert [e.new_literal for e in plan.edits] == ['"meals"']


@pytest.mark.parametrize("factory", ["handler", "hd"], ids=["plain", "aliased_factory"])
def test_a_stacked_decorator_literal_on_a_referrer_is_never_silently_left(
    tmp_path: Path, factory: str
) -> None:
    """A referrer's stacked decorator is part of its definition: an equal literal there is either
    rewritten or reports the referrer unresolved, never left behind while the plan passes clean.
    Only the registering ``@handler(...)`` name argument is the referrer's own and is skipped, and
    under an aliased factory a stacked decorator is still not taken for it."""
    config_dir = _write_config(
        tmp_path,
        "import functools\n"
        "from messagefoundry import handler as hd\n"
        "\n"
        "def uses(table):\n"
        "    def deco(fn):\n"
        "        @functools.wraps(fn)\n"
        "        def wrapper(msg):\n"
        "            code_set(table)\n"
        "            return fn(msg)\n"
        "        return wrapper\n"
        "    return deco\n"
        "\n"
        'inbound("IB_K", MLLP(port=2818), router="r_k")\n'
        'outbound("OB_K", MLLP(host="127.0.0.1", port=6971))\n'
        "\n"
        '@router("r_k")\n'
        "def r_k(msg):\n"
        '    return ["h_k"]\n'
        "\n"
        f'@{factory}("h_k")\n'
        '@uses("diets")\n'
        "def h_k(msg):\n"
        '    code_set("diets")\n'
        '    return Send("OB_K", msg)\n',
        codesets=("diets",),
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    apply_rename(plan)
    assert '@uses("diets")' not in _mod(config_dir) or plan.unresolved, plan


@pytest.mark.parametrize(
    "head",
    [
        "from messagefoundry import code_set as cs\n",
        "",
    ],
    ids=["aliased", "keyword"],
)
def test_an_aliased_or_keyword_code_set_call_in_the_body_is_rewritten(
    tmp_path: Path, head: str
) -> None:
    call = 'cs("diets")' if head else 'code_set(name="diets")'
    config_dir = _write_config(
        tmp_path,
        head + 'inbound("IB_Q", MLLP(port=2819), router="r_q")\n'
        'outbound("OB_Q", MLLP(host="127.0.0.1", port=6972))\n'
        "\n"
        '@router("r_q")\n'
        "def r_q(msg):\n"
        '    return ["h_q"]\n'
        "\n"
        '@handler("h_q")\n'
        "def h_q(msg):\n"
        f'    tag = {call}.get("A")\n'
        '    return Send("OB_Q", msg)\n',
        codesets=("diets",),
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert '"diets"' not in _mod(config_dir)


def test_an_accepts_lambda_does_not_count_the_handlers_own_name(tmp_path: Path) -> None:
    """An accepts= lambda's site spans the registering decorator, whose name argument is the
    handler's own name, not a referent to an outbound named the same."""
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_E", MLLP(port=2822), router="r_e")\n'
        'outbound("EPIC", MLLP(host="127.0.0.1", port=6975))\n'
        "\n"
        '@router("r_e")\n'
        "def r_e(msg):\n"
        '    return ["EPIC"]\n'
        "\n"
        '@handler("EPIC", accepts=lambda m: m is not None)\n'
        "def epic(msg):\n"
        '    return Send("EPIC", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "EPIC", "OB_EPIC")
    assert plan.unresolved == ()
    apply_rename(plan)
    text = _mod(config_dir)
    assert 'return Send("OB_EPIC", msg)' in text
    assert '@handler("EPIC", accepts=' in text


def test_a_nested_lambda_default_is_not_the_functions_own(tmp_path: Path) -> None:
    """A nested lambda's parameter is another parameter, even when it shares a role parameter's
    name, so its default is left and counted."""
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_L", MLLP(port=2823), router="r_l")\n'
        'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6976))\n'
        "\n"
        '@router("r_l")\n'
        "def r_l(msg):\n"
        '    return ["h_l"]\n'
        "\n"
        '@handler("h_l")\n'
        "def h_l(msg, dest=None):\n"
        '    if (lambda dest="OB_OLD": str(msg) == dest)():\n'
        "        return None\n"
        '    return Send(dest or "OB_OLD", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    apply_rename(plan)
    text = _mod(config_dir)
    assert 'lambda dest="OB_OLD"' in text
    assert 'Send(dest or "OB_NEW", msg)' in text
    assert plan.unresolved == (Reference("handler", "h_l", "outbound", "OB_OLD"),)


_DEFAULTS = {
    "handler_default": (
        "outbound",
        "OB_OLD",
        "OB_NEW",
        '@router("r_f")\n'
        "def r_f(msg):\n"
        '    return ["h_f"]\n'
        "\n"
        '@handler("h_f")\n'
        'def h_f(msg, dest="OB_OLD"):\n'
        "    if msg is None:\n"
        '        return Send("OB_OLD", msg)\n'
        "    return Send(dest, msg)\n",
    ),
    "helper_default": (
        "outbound",
        "OB_OLD",
        "OB_NEW",
        'def _send(msg, dest="OB_OLD"):\n'
        "    return Send(dest, msg)\n"
        "\n"
        '@router("r_f")\n'
        "def r_f(msg):\n"
        '    return ["h_f"]\n'
        "\n"
        '@handler("h_f")\n'
        "def h_f(msg):\n"
        "    if msg is None:\n"
        '        return Send("OB_OLD", msg)\n'
        "    return _send(msg)\n",
    ),
    "router_default": (
        "handler",
        "h_f",
        "h_g",
        '@router("r_f")\n'
        'def r_f(msg, name="h_f"):\n'
        '    return [name] if msg is None else ["h_f"]\n'
        "\n"
        '@handler("h_f")\n'
        "def h_f(msg):\n"
        '    return Send("OB_OLD", msg)\n',
    ),
}


@pytest.mark.parametrize("case", sorted(_DEFAULTS))
def test_a_parameter_default_carrying_a_referent_is_rewritten(tmp_path: Path, case: str) -> None:
    kind, old, new, body = _DEFAULTS[case]
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_F", MLLP(port=2820), router="r_f")\n'
        'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6973))\n'
        "\n" + body,
    )
    plan = plan_rename(load_config(config_dir), config_dir, kind, old, new)
    assert plan.unresolved == ()
    apply_rename(plan)
    assert f'"{old}"' not in _mod(config_dir)
    load_config(config_dir)


def test_a_parameter_default_read_only_in_a_comparison_is_left_and_reported(
    tmp_path: Path,
) -> None:
    config_dir = _write_config(
        tmp_path,
        'inbound("IB_G", MLLP(port=2821), router="r_g")\n'
        'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6974))\n'
        "\n"
        '@router("r_g")\n'
        "def r_g(msg):\n"
        '    return ["h_g"]\n'
        "\n"
        '@handler("h_g")\n'
        'def h_g(msg, skip="OB_OLD"):\n'
        "    if str(msg) == skip:\n"
        "        return None\n"
        '    return Send("OB_OLD", msg)\n',
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    apply_rename(plan)
    text = _mod(config_dir)
    assert 'skip="OB_OLD"' in text
    assert 'return Send("OB_NEW", msg)' in text
    assert plan.unresolved == (Reference("handler", "h_g", "outbound", "OB_OLD"),)


_UNRESOLVABLE = {
    "field_comparison": (
        "outbound",
        "OB_OLD",
        "OB_NEW",
        'inbound("IB_U", MLLP(port=2851), router="r_u")\n'
        'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6991))\n'
        "\n"
        '@router("r_u")\n'
        "def r_u(msg):\n"
        '    return ["h_u"]\n'
        "\n"
        '@handler("h_u")\n'
        "def h_u(msg):\n"
        '    if str(msg) == "OB_OLD":\n'
        "        return None\n"
        '    return Send("OB_OLD", msg)\n',
    ),
    "router_splat": (
        "router",
        "r_old",
        "r_new",
        'inbound("IB_S", MLLP(port=2852), **{"router": "r_old"})\n'
        'outbound("OB_S", MLLP(host="127.0.0.1", port=6992))\n'
        "\n"
        '@router("r_old")\n'
        "def r_old(msg):\n"
        '    return ["h_s"]\n'
        "\n"
        '@handler("h_s")\n'
        "def h_s(msg):\n"
        '    return Send("OB_S", msg)\n',
    ),
}


@pytest.mark.parametrize("case", sorted(_UNRESOLVABLE))
def test_apply_refuses_and_writes_nothing_when_a_reference_is_unresolved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], case: str
) -> None:
    """A plan with an unresolved referrer would leave a half-renamed config, so `--apply` must
    refuse before any write, name the referrer, and exit non-zero; the dry run still shows it."""
    kind, old, new, body = _UNRESOLVABLE[case]
    config_dir = _write_config(tmp_path, body)
    before = (config_dir / "mod.py").read_bytes()
    argv = ["impact", "--config", str(config_dir), kind, old, "--rename-to", new, "--json"]

    assert main(argv) == 0
    dry = json.loads(capsys.readouterr().out)
    assert dry["dry_run"] is True and dry["unresolved"], dry

    rc = main([*argv, "--apply"])
    out = json.loads(capsys.readouterr().out)
    assert rc != 0, out
    assert "--apply refused" in out["error"], out
    for ref in dry["unresolved"]:
        assert repr(ref["referrer"]) in out["error"], out
    assert (config_dir / "mod.py").read_bytes() == before


def test_a_helper_referent_at_the_decorators_coordinates_in_another_file_is_counted(
    tmp_path: Path,
) -> None:
    """The registering ``@handler("EPIC")`` argument is skipped by its (line, col), and only in the
    handler's own file. A helper in another file whose ``Send("EPIC", ...)`` sits at the same line
    and column is a referent there, so it must be rewritten or reported, never silently left."""
    d = tmp_path / "config"
    d.mkdir()
    (d / "mod.py").write_text(
        "from _epic import send_epic\n"
        "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
        "\n"
        'inbound("IB_EH", MLLP(port=2831), router="r_eh")\n'
        'outbound("EPIC", MLLP(host="127.0.0.1", port=6981))\n'
        "\n"
        "\n"
        '@router("r_eh")\n'
        "def r_eh(msg):\n"
        '    return ["EPIC"]\n'
        "\n"
        "\n"
        '@handler("EPIC")\n'
        "def epic(msg):\n"
        # The body's own Send is what makes the handler a referrer of the outbound, so its helper
        # becomes one of the rename's sites.
        '    return [Send("EPIC", msg), *send_epic(msg)]\n',
        encoding="utf-8",
        newline="",
    )
    # Padded so the Send target sits at line 13, column 9: the coordinates of "EPIC" in mod.py's
    # @handler("EPIC") above.
    (d / "_epic.py").write_text(
        "from messagefoundry import Send\n"
        + "\n" * 9
        + "def send_epic(msg):\n"
        + "    return [\n"
        + '    Send("EPIC", msg)]\n',
        encoding="utf-8",
        newline="",
    )
    helper_line = (d / "_epic.py").read_text(encoding="utf-8").splitlines()[12]
    mod_line = _mod(d).splitlines()[12]
    assert helper_line.index('"EPIC"') == mod_line.index('"EPIC"'), "the fixture lost its overlap"

    plan = plan_rename(load_config(d), d, "outbound", "EPIC", "OB_EPIC")
    rewritten = any(e.file.endswith("_epic.py") for e in plan.edits)
    reported = Reference("handler", "EPIC", "outbound", "EPIC") in plan.unresolved
    assert rewritten or reported, (plan.edits, plan.unresolved)
    if rewritten:
        apply_rename(plan)
        assert 'Send("OB_EPIC", msg)' in (d / "_epic.py").read_text(encoding="utf-8")
        assert '@handler("EPIC")' in _mod(d)
