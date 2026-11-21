# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rename paths the role scan got wrong while reporting success (BACKLOG #5980, closing steps 3-11).

Each test loads a real config, plans a rename, and checks that the plan either rewrites exactly the
name-bearing literals or reports the referrer unresolved, so ``impact --apply`` refuses instead of
writing a config whose logic has silently changed."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from messagefoundry.config.impact import apply_rename, plan_rename
from messagefoundry.config.reachability import Reference
from messagefoundry.config.wiring import load_config

_HEAD = "from messagefoundry import MLLP, Send, code_set, handler, inbound, outbound, router\n\n"

#: An inbound, two outbounds and a router routing to the handler ``h_p``.
_WIRE = (
    'inbound("IB_P", MLLP(port=2901), router="r_p")\n'
    'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6901))\n'
    'outbound("OB_A", MLLP(host="127.0.0.1", port=6902))\n'
    "\n"
    '@router("r_p")\n'
    "def r_p(msg):\n"
    '    return ["h_p"]\n'
    "\n"
)


@pytest.fixture(autouse=True)
def _forget_helper_modules(tmp_path: Path) -> object:
    """Config helper modules are imported by name, so one test's ``_ha`` must not serve the next.
    Only the modules this test's config dir supplied are forgotten."""
    before = set(sys.modules)
    yield None
    root = tmp_path.resolve()
    for name in set(sys.modules) - before:
        file = getattr(sys.modules[name], "__file__", None)
        if file and Path(file).resolve().is_relative_to(root):
            del sys.modules[name]


def _write(tmp_path: Path, files: dict[str, str]) -> Path:
    d = tmp_path / "config"
    d.mkdir()
    for name, body in files.items():
        path = d / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8", newline="")
    return d


def _text(config_dir: Path, name: str = "mod.py") -> str:
    return (config_dir / name).read_text(encoding="utf-8")


def test_a_router_keyword_inside_a_sibling_argument_is_left(tmp_path: Path) -> None:
    """Step 6: only the inbound call's own ``router=`` is the binding."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + "def _t(port, router):\n"
            "    return MLLP(port=port)\n"
            "\n"
            'inbound("IB_Q", _t(2902, router="r_old"), router="r_old")\n'
            'outbound("OB_A", MLLP(host="127.0.0.1", port=6902))\n'
            "\n"
            '@router("r_old")\n'
            "def r_old(msg):\n"
            '    return ["h_p"]\n'
            "\n"
            '@handler("h_p")\n'
            "def h_p(msg):\n"
            '    return Send("OB_A", msg)\n'
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "router", "r_old", "r_new")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert 'inbound("IB_Q", _t(2902, router="r_old"), router="r_new")' in _text(config_dir)
    load_config(config_dir)


@pytest.mark.parametrize(
    ("prelude", "body"),
    [
        ("", '    labels = {"OB_A": "OB_OLD"}\n    return [Send(dest, msg) for dest in labels]\n'),
        ('LABELS = {"OB_A": "OB_OLD"}\n', "    return [Send(d, msg) for d in list(LABELS)]\n"),
        ('LABELS = {"OB_A": "OB_OLD"}\n', "    return [Send(d, msg) for d in LABELS.keys()]\n"),
        (
            "def _fan(dests, msg):\n    return [Send(d, msg) for d in dests]\n",
            '    return _fan({"OB_A": "OB_OLD"}, msg)\n',
        ),
        ('LABELS = {"OB_A": "OB_OLD"}\n', "    return [Send(d, msg) for d in LABELS.copy()]\n"),
        (
            'def _fan(msg, dests={"OB_A": "OB_OLD"}):\n    return [Send(d, msg) for d in dests]\n',
            "    return _fan(msg)\n",
        ),
    ],
)
def test_iterating_a_dict_reads_its_keys_not_its_values(
    tmp_path: Path, prelude: str, body: str
) -> None:
    """Step 5: a dict value equal to the name is a label when the dict is iterated."""
    config_dir = _write(
        tmp_path,
        {"mod.py": _HEAD + _WIRE + prelude + '\n@handler("h_p")\ndef h_p(msg):\n' + body},
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    # Where the index has an edge from h_p but no role reads the name, the referrer is still
    # reported (the planner cannot see the read the index saw); the claim here is only that the
    # label is never rewritten.
    assert plan.unresolved in ((), (_H_P,))
    apply_rename(plan)
    text = _text(config_dir)
    assert 'outbound("OB_NEW"' in text
    assert '{"OB_A": "OB_OLD"}' in text
    load_config(config_dir)


@pytest.mark.parametrize(
    "body",
    [
        '    return [Send(dest, msg) for dest in {"OB_OLD": "primary"}]\n',
        '    for dest in {**{"OB_OLD": 1}}:\n        return Send(dest, msg)\n',
        '    return [Send(d, msg) for d, n in {"OB_OLD": 1}.items()]\n',
    ],
)
def test_iterating_a_dict_rewrites_a_key_that_is_sent(tmp_path: Path, body: str) -> None:
    """Step 5: the keys a dict is iterated for are the referents."""
    config_dir = _write(
        tmp_path, {"mod.py": _HEAD + _WIRE + '@handler("h_p")\ndef h_p(msg):\n' + body}
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert '"OB_OLD"' not in _text(config_dir)


def test_two_helpers_sharing_a_bare_name_report_the_referrer(tmp_path: Path) -> None:
    """Step 4: the scan's role maps are keyed by a helper's bare name, so ``_hb.pick`` (read in a
    comparison) would take ``_ha.pick``'s role and have its literal rewritten."""
    config_dir = _write(
        tmp_path,
        {
            "_ha.py": 'def pick():\n    return "OB_OLD"\n',
            "_hb.py": 'def pick():\n    return "OB_OLD"\n',
            "mod.py": _HEAD + "import _ha\nimport _hb\n\n" + _WIRE + '@handler("h_p")\n'
            "def h_p(msg):\n"
            "    if str(msg) == _hb.pick():\n"
            '        return Send("OB_OLD", msg)\n'
            "    return Send(_ha.pick(), msg)\n",
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == (Reference("handler", "h_p", "outbound", "OB_OLD"),)


def test_a_router_returning_a_dict_routes_to_its_keys(tmp_path: Path) -> None:
    """Step 5: the engine iterates a router's return, so a dict value is not a handler name."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + 'inbound("IB_P", MLLP(port=2901), router="r_p")\n'
            'outbound("OB_A", MLLP(host="127.0.0.1", port=6902))\n'
            "\n"
            '@router("r_p")\n'
            "def r_p(msg):\n"
            '    return {"h_a": "h_old"}\n'
            "\n"
            '@handler("h_a")\n'
            "def h_a(msg):\n"
            '    return Send("OB_A", msg)\n'
            "\n"
            '@handler("h_old")\n'
            "def h_old(msg):\n"
            '    return Send("OB_A", msg)\n'
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "handler", "h_old", "h_new")
    apply_rename(plan)
    text = _text(config_dir)
    assert '@handler("h_new")' in text
    assert 'return {"h_a": "h_old"}' in text


_H_P = Reference("handler", "h_p", "outbound", "OB_OLD")


@pytest.mark.parametrize(
    ("prelude", "body"),
    [
        # Step 7: a local read as the Send target and in a comparison.
        (
            "",
            '    dest = "OB_OLD"\n    if str(msg) == dest:\n        return None\n'
            "    return Send(dest, msg)\n",
        ),
        # Step 7: a module constant read the same two ways.
        (
            'DEST = "OB_OLD"\n',
            "    if str(msg) == DEST:\n        return None\n    return Send(DEST, msg)\n",
        ),
        # Step 7: a helper parameter read the same two ways.
        (
            "def _send(dest, msg):\n    if str(msg) == dest:\n        return None\n"
            "    return Send(dest, msg)\n",
            '    return _send("OB_OLD", msg)\n',
        ),
        # Step 7: a string's length depends on which name it holds.
        (
            "",
            '    dest = "OB_OLD"\n    if len(dest) == 6:\n        return None\n'
            "    return Send(dest, msg)\n",
        ),
        # Step 9: flow-insensitive values: a later value never reaches the Send, only the comparison.
        (
            "",
            '    dest = "OB_A"\n    out = Send(dest, msg)\n    dest = "OB_OLD"\n'
            "    if str(msg) == dest:\n        return None\n    return out\n",
        ),
        # Step 9: a local copy of a parameter, a module constant or a helper's return, compared.
        (
            "def _send(dest, msg):\n    label = dest\n    if str(msg) == label:\n"
            "        return None\n    return Send(dest, msg)\n",
            '    return _send("OB_OLD", msg)\n',
        ),
        (
            'DEST = "OB_OLD"\n',
            "    label = DEST\n    if str(msg) == label:\n        return None\n"
            "    return Send(DEST, msg)\n",
        ),
        (
            'def _pick():\n    return "OB_OLD"\n',
            "    label = _pick()\n    if str(msg) == label:\n        return None\n"
            "    return Send(_pick(), msg)\n",
        ),
        # Step 3: a helper passing its default through, compared by the caller.
        (
            'def _pick(d="OB_OLD"):\n    return d\n',
            "    if str(msg) == _pick():\n        return None\n    return Send(_pick(), msg)\n",
        ),
        # Step 9: a copy taken before the Send keeps reading the old value.
        (
            "",
            '    dest = "OB_OLD"\n    label = dest\n    if str(msg) == label:\n        return None\n'
            "    return Send(dest, msg)\n",
        ),
    ],
)
def test_a_name_read_outside_its_role_reports_the_referrer(
    tmp_path: Path, prelude: str, body: str
) -> None:
    """Steps 7 and 9: rewriting a name's value would change every other read of it."""
    config_dir = _write(
        tmp_path,
        {"mod.py": _HEAD + _WIRE + prelude + '\n@handler("h_p")\ndef h_p(msg):\n' + body},
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == (_H_P,)


@pytest.mark.parametrize(
    "body",
    [
        '    dests = []\n    if msg:\n        dests.append("OB_OLD")\n    if not dests:\n'
        "        return None\n    return [Send(d, msg) for d in dests if d]\n",
        '    dest = "OB_OLD"\n    if dest is None or not dest:\n        return None\n'
        "    return Send(dest, msg)\n",
    ],
)
def test_a_value_agnostic_read_keeps_the_rename_resolved(tmp_path: Path, body: str) -> None:
    """Steps 7 and 9: a truth test, an ``is None`` check and a collector do not read the string,
    so they do not stop the rewrite."""
    config_dir = _write(
        tmp_path, {"mod.py": _HEAD + _WIRE + '@handler("h_p")\ndef h_p(msg):\n' + body}
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert '"OB_OLD"' not in _text(config_dir)
    load_config(config_dir)


@pytest.mark.parametrize(
    "prelude",
    [
        'TARGETS = {"ADT": "OB_OLD"}\n\n\ndef _route(kind):\n    return TARGETS[kind]\n',
        'def _route(kind):\n    return "OB_OLD"\n',
    ],
)
def test_a_referrer_the_index_has_no_edge_from_is_rewritten(tmp_path: Path, prelude: str) -> None:
    """Step 8: a name that reaches Send through a helper or a module table gives the wiring graph
    no edge, so the plan renamed the outbound and left the handler sending to the old name."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + _WIRE + prelude + '\n@handler("h_p")\n'
            "def h_p(msg):\n"
            '    return Send(_route("ADT"), msg)\n'
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert '"OB_OLD"' not in _text(config_dir)
    load_config(config_dir)


def test_a_router_the_index_has_no_edge_from_is_rewritten(tmp_path: Path) -> None:
    """Step 8: the same for a handler name a router reads out of a module table."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + 'inbound("IB_P", MLLP(port=2901), router="r_p")\n'
            'outbound("OB_A", MLLP(host="127.0.0.1", port=6902))\n'
            "\n"
            'ROUTES = {"ADT": ["h_old"]}\n'
            "\n"
            '@router("r_p")\n'
            "def r_p(msg):\n"
            '    return ROUTES.get("ADT", [])\n'
            "\n"
            '@handler("h_old")\n'
            "def h_old(msg):\n"
            '    return Send("OB_A", msg)\n'
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "handler", "h_old", "h_new")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert 'ROUTES = {"ADT": ["h_new"]}' in _text(config_dir)
    load_config(config_dir)


@pytest.mark.parametrize(
    ("reader", "routes"),
    [
        # Another handler compares with the same helper's return.
        (
            '@handler("h_q")\ndef h_q(msg):\n    if str(msg) == _dest():\n        return None\n'
            '    return Send("OB_A", msg)\n',
            '["h_p", "h_q"]',
        ),
        # Module-level code reads it.
        ("DEFAULT = _dest()\n", '["h_p"]'),
    ],
)
def test_a_shared_helper_return_read_outside_a_role_reports_the_referrer(
    tmp_path: Path, reader: str, routes: str
) -> None:
    """Step 3: rewriting a helper's returned name changes every caller's value, so a caller that
    reads it in no role would change silently."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + _WIRE.replace('["h_p"]', routes) + "def _dest():\n"
            '    return "OB_OLD"\n'
            "\n"
            '@handler("h_p")\n'
            "def h_p(msg):\n"
            "    return Send(_dest(), msg)\n"
            "\n" + reader
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert _H_P in plan.unresolved
    apply_rename(plan)
    assert 'return "OB_OLD"' in _text(config_dir)


def test_a_shared_helper_return_every_referrer_sends_is_rewritten(tmp_path: Path) -> None:
    """Step 3: two handlers that both send a helper's return rename together."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + _WIRE.replace('["h_p"]', '["h_p", "h_q"]') + "def _dest():\n"
            '    return "OB_OLD"\n'
            "\n"
            '@handler("h_p")\n'
            "def h_p(msg):\n"
            "    return Send(_dest(), msg)\n"
            "\n"
            '@handler("h_q")\n'
            "def h_q(msg):\n"
            '    return [Send(_dest(), msg), Send("OB_A", msg)]\n'
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert '"OB_OLD"' not in _text(config_dir)
    load_config(config_dir)


_TABLES_HEAD = (
    "from messagefoundry import FileRef, MLLP, Reference, Send, code_set, handler, inbound, "
    "outbound, reference, router\n\n"
    'Reference("diets", source=FileRef(path="diets.csv"))\n'
)
_CSV = "code,value\nA,Apple\n"
_H_DIETS = Reference("handler", "h_p", "code_set", "diets")


@pytest.mark.parametrize(
    "body",
    [
        # One module constant read by the code set's accessor and the reference's.
        'NAME = "diets"\n\n\n@handler("h_p")\ndef h_p(msg):\n    a = code_set(NAME)\n'
        '    b = reference(NAME)\n    return Send("OB_A", msg)\n',
        # The reference's read sits in a helper the handler reaches.
        'NAME = "diets"\n\n\ndef _ref():\n    return reference(NAME)\n\n\n'
        '@handler("h_p")\ndef h_p(msg):\n    _ref()\n'
        '    return Send("OB_A", code_set(NAME).get("A"))\n',
    ],
)
def test_a_constant_two_table_kinds_read_is_not_rewritten(tmp_path: Path, body: str) -> None:
    """Step 10: a code set and a reference share the name, so rewriting the constant would move
    the reference's read to a table that does not exist."""
    config_dir = _write(
        tmp_path,
        {"mod.py": _TABLES_HEAD + _WIRE + body, "codesets/diets.csv": _CSV, "diets.csv": _CSV},
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    assert plan.unresolved == (_H_DIETS,)
    apply_rename(plan)
    assert 'NAME = "diets"' in _text(config_dir)


@pytest.mark.parametrize(
    "helper",
    [
        # The helper compares its table parameter with the name its caller passes.
        'def _lookup(table, code):\n    if table == "diets":\n        code = code.upper()\n'
        "    return code_set(table).get(code)\n",
        # A table default whose parameter is also read in a comparison.
        'def _lookup(code, table="diets"):\n    if table == "x":\n        return None\n'
        "    return code_set(table).get(code)\n",
    ],
)
def test_a_table_value_a_helper_also_compares_reports_the_referrer(
    tmp_path: Path, helper: str
) -> None:
    """Step 11: the helper's other read of the table name was neither rewritten nor counted."""
    call = '_lookup("diets", "A")' if helper.startswith("def _lookup(table") else '_lookup("A")'
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + _WIRE + helper + '\n\n@handler("h_p")\ndef h_p(msg):\n'
            f"    {call}\n"
            '    return Send("OB_A", msg)\n',
            "codesets/diets.csv": _CSV,
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    assert plan.unresolved == (_H_DIETS,)


@pytest.mark.parametrize(
    "direct", ["", '    if msg is None:\n        return Send("OB_OLD", msg)\n']
)
def test_a_container_built_from_a_constant_reports_the_referrer(
    tmp_path: Path, direct: str
) -> None:
    """Step 11: ``ALL = [DEST, "OB_A"]`` holds the name with no literal of its own, so neither
    binding was a counted occurrence and the handler kept sending to the old name."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + _WIRE + 'DEST = "OB_OLD"\nALL = [DEST, "OB_A"]\n\n\n'
            '@handler("h_p")\ndef h_p(msg):\n' + direct + "    return [Send(d, msg) for d in ALL]\n"
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == (_H_P,)


def test_a_container_holding_the_literal_is_rewritten(tmp_path: Path) -> None:
    """Step 11: the container's own literal is located, so the rename completes."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + _WIRE + 'ALL = ["OB_OLD", "OB_A"]\n\n\n'
            '@handler("h_p")\ndef h_p(msg):\n    return [Send(d, msg) for d in ALL]\n'
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert 'ALL = ["OB_NEW", "OB_A"]' in _text(config_dir)
    load_config(config_dir)


def test_two_helpers_sharing_an_unused_bare_name_keep_the_rename_resolved(tmp_path: Path) -> None:
    """Step 4: a bare-name collision between helpers no role reads cannot mislead the scan."""
    config_dir = _write(
        tmp_path,
        {
            "_ha.py": "def fmt(x):\n    return x\n",
            "_hb.py": "def fmt(x):\n    return x\n",
            "mod.py": _HEAD + "import _ha\nimport _hb\n\n" + _WIRE + '@handler("h_p")\n'
            "def h_p(msg):\n"
            "    _ha.fmt(1)\n"
            "    _hb.fmt(2)\n"
            '    return Send("OB_OLD", msg)\n',
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert '"OB_OLD"' not in _text(config_dir)


def test_a_helper_module_constant_a_helper_returns_is_rewritten(tmp_path: Path) -> None:
    """Steps 3 and 11: the constant behind an imported helper's return is the sent name."""
    config_dir = _write(
        tmp_path,
        {
            "_hc.py": 'DEST = "OB_OLD"\n\n\ndef dest():\n    return DEST\n',
            "mod.py": _HEAD + "import _hc\n\n" + _WIRE + '@handler("h_p")\n'
            "def h_p(msg):\n"
            "    return Send(_hc.dest(), msg)\n",
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert _text(config_dir, "_hc.py").startswith('DEST = "OB_NEW"')


# --- review round 1 (round-97e5c019) -------------------------------------------------------------


def test_a_table_a_handler_reads_out_of_a_module_dict_reports_the_referrer(tmp_path: Path) -> None:
    """Step 8 for a table: the index has no edge from ``code_set(TABLES["x"])``, so the referrer was
    never scanned and the rename reported success with the handler still reading the old table."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + 'TABLES = {"x": "diets"}\n\n' + _WIRE + '@handler("h_p")\n'
            "def h_p(msg):\n"
            '    label = code_set(TABLES["x"]).get("A")\n'
            '    return Send("OB_A", msg)\n',
            "codesets/diets.csv": "code,value\nA,Apple\n",
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    assert plan.unresolved == (Reference("handler", "h_p", "code_set", "diets"),)


def _sends_through_a_helper(spec: str, extra: str = "") -> str:
    """A config whose handler ``h_a`` sends to ``IB_OLD`` only through a helper's module table,
    with ``IB_OLD`` declared as ``spec``."""
    return (
        "from messagefoundry import MLLP, Loopback, PassThrough, Send, handler, inbound, outbound, "
        "router\n\n"
        'TARGETS = {"ADT": "IB_OLD"}\n\n\n'
        "def _route(k):\n"
        "    return TARGETS[k]\n\n\n"
        'inbound("IB_A", MLLP(port=2932), router="r_a")\n'
        f'inbound("IB_OLD", {spec}, router="r_b")\n'
        f"{extra}"
        'outbound("OB_B", MLLP(host="127.0.0.1", port=6931))\n\n\n'
        '@router("r_a")\ndef r_a(msg):\n    return ["h_a"]\n\n\n'
        '@router("r_b")\ndef r_b(msg):\n    return ["h_b"]\n\n\n'
        '@handler("h_a")\ndef h_a(msg):\n    return Send(_route("ADT"), msg)\n\n\n'
        '@handler("h_b")\ndef h_b(msg):\n    return Send("OB_B", msg)\n'
    )


def test_a_pass_through_a_handler_sends_to_through_a_helper_is_rewritten(tmp_path: Path) -> None:
    """Step 8 for an inbound: a pass-through inbound a handler reaches only through a helper's
    table."""
    config_dir = _write(tmp_path, {"mod.py": _sends_through_a_helper("PassThrough()")})
    plan = plan_rename(load_config(config_dir), config_dir, "inbound", "IB_OLD", "IB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert 'TARGETS = {"ADT": "IB_NEW"}' in _text(config_dir)
    load_config(config_dir)


@pytest.mark.parametrize(
    "spec",
    [
        "Loopback()",
        # An MLLP inbound beside an outbound of the same name: the Send goes to the outbound.
        "MLLP(port=2933)",
    ],
    ids=["loopback", "same_named_outbound"],
)
def test_a_send_literal_naming_an_inbound_that_is_no_send_target_is_left(
    tmp_path: Path, spec: str
) -> None:
    """Only a pass-through inbound is a Send target; a Send naming any other inbound's name goes
    to an outbound of that name, so renaming the inbound must not rewrite it."""
    extra = 'outbound("IB_OLD", MLLP(host="127.0.0.1", port=6932))\n' if "MLLP" in spec else ""
    config_dir = _write(tmp_path, {"mod.py": _sends_through_a_helper(spec, extra)})
    plan = plan_rename(load_config(config_dir), config_dir, "inbound", "IB_OLD", "IB_NEW")
    apply_rename(plan)
    assert 'TARGETS = {"ADT": "IB_OLD"}' in _text(config_dir)


def test_an_outbound_shadowed_by_a_pass_through_of_its_name_leaves_the_send(
    tmp_path: Path,
) -> None:
    """The mirror: a Send names the pass-through inbound when one shares the name, so renaming the
    outbound of that name must not rewrite it."""
    extra = 'outbound("IB_OLD", MLLP(host="127.0.0.1", port=6932))\n'
    config_dir = _write(tmp_path, {"mod.py": _sends_through_a_helper("PassThrough()", extra)})
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "IB_OLD", "IB_NEW")
    apply_rename(plan)
    assert 'TARGETS = {"ADT": "IB_OLD"}' in _text(config_dir)


def test_a_literal_send_to_a_pass_through_shadowing_an_outbound_is_left(tmp_path: Path) -> None:
    """The index's own edge follows the runtime: a literal ``Send("X")`` with a pass-through and
    an outbound both named X reaches the pass-through, so renaming the outbound leaves it."""
    body = (
        "from messagefoundry import MLLP, PassThrough, Send, handler, inbound, outbound, router\n\n"
        'inbound("IB_A", MLLP(port=2936), router="r_a")\n'
        'inbound("X", PassThrough(), router="r_a")\n'
        'outbound("X", MLLP(host="127.0.0.1", port=6934))\n\n\n'
        '@router("r_a")\ndef r_a(msg):\n    return ["h_a"]\n\n\n'
        '@handler("h_a")\ndef h_a(msg):\n    return Send("X", msg)\n'
    )
    config_dir = _write(tmp_path, {"mod.py": body})
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "X", "X2")
    apply_rename(plan)
    assert 'return Send("X", msg)' in _text(config_dir)


def test_a_router_that_filters_with_a_bare_return_keeps_a_label_dict_rename_resolved(
    tmp_path: Path,
) -> None:
    """A router's ``return None`` reads no value, so it is no unfollowed role read: a label dict
    holding the handler's name beside it is not a referent, and the rename completes."""
    body = (
        "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n\n"
        'LABELS = {"h_old": "ADT handler"}\n\n'
        'inbound("IB_A", MLLP(port=2934), router="r_a")\n'
        'inbound("IB_B", MLLP(port=2935), router="r_b")\n'
        'outbound("OB_B", MLLP(host="127.0.0.1", port=6933))\n\n\n'
        '@router("r_a")\ndef r_a(msg):\n    return ["h_old"]\n\n\n'
        '@router("r_b")\ndef r_b(msg):\n'
        "    if msg is None:\n        return None\n"
        "    note = LABELS.get(str(msg))\n"
        '    return ["h_b"]\n\n\n'
        '@handler("h_old")\ndef h_old(msg):\n    return Send("OB_B", msg)\n\n\n'
        '@handler("h_b")\ndef h_b(msg):\n    return Send("OB_B", msg)\n'
    )
    config_dir = _write(tmp_path, {"mod.py": body})
    plan = plan_rename(load_config(config_dir), config_dir, "handler", "h_old", "h_new")
    assert plan.unresolved == ()


def test_a_read_at_a_role_reads_coordinates_in_another_file_reports_the_referrer(
    tmp_path: Path,
) -> None:
    """A role read is keyed by its file as well as its position: a comparison in ``b.py`` at the
    same line and columns as ``a.py``'s Send is not that Send."""
    head = "from messagefoundry import Send, handler\n\nimport _consts\n\n"
    config_dir = _write(
        tmp_path,
        {
            "_consts.py": 'TARGET = "OB_OLD"\n',
            "wire.py": _HEAD + _WIRE.replace('["h_p"]', '["h_a", "h_b"]'),
            "a.py": head + '@handler("h_a")\ndef h_a(msg):\n    return Send(_consts.TARGET, msg)\n',
            "b.py": head + '@handler("h_b")\ndef h_b(msg):\n'
            "    if msg.xx ==_consts.TARGET: return None\n"
            "    return Send(_consts.TARGET, msg)\n",
        },
    )
    a_line = _text(config_dir, "a.py").splitlines()[6]
    b_line = _text(config_dir, "b.py").splitlines()[6]
    assert a_line.index("_consts.TARGET") == b_line.index("_consts.TARGET")
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved != ()
    assert not any(Path(e.file).name == "_consts.py" for e in plan.edits)


# --- review round 2 (round-f12b8401) -------------------------------------------------------------


def test_a_table_only_an_accepts_predicate_reads_reports_the_referrer(tmp_path: Path) -> None:
    """The cheap gate reads the handler's ``accepts=`` predicate as the scan does, so a handler
    whose predicate is its only reader of the table is scanned, not skipped."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD
            + 'TABLES = {"k": "diets"}\n\n'
            + _WIRE
            + '@handler("h_p", accepts=lambda m: code_set(TABLES["k"]).get("x") is not None)\n'
            "def h_p(msg):\n"
            '    return Send("OB_A", msg)\n',
            "codesets/diets.csv": "code,value\nA,Apple\n",
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    assert plan.unresolved == (Reference("handler", "h_p", "code_set", "diets"),)


def test_a_module_helper_called_with_no_arguments_is_read_for_its_elements(
    tmp_path: Path,
) -> None:
    """``_routes.all()`` is a helper call, not a dict method: a dict it returns is iterated for its
    keys, which are the names sent."""
    config_dir = _write(
        tmp_path,
        {
            "_routes.py": 'def all():\n    return {"OB_OLD": 1}\n',
            "mod.py": _HEAD + "import _routes\n\n" + _WIRE + '@handler("h_p")\n'
            "def h_p(msg):\n"
            "    return [Send(d, msg) for d in _routes.all()]\n",
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    assert any(Path(e.file).name == "_routes.py" for e in plan.edits)


@pytest.mark.parametrize(
    "body",
    [
        'DESTS = ["OB_A", "OB_OLD"]\n\n\n|    return [Send(d, msg) for _i, d in enumerate(DESTS)]\n',
        'ROUTES = {"ADT": "OB_OLD"}\n\n\n|    return [Send(p[1], msg) for p in ROUTES.items()]\n',
    ],
    ids=["enumerate", "items_index"],
)
def test_a_captured_container_the_scan_cannot_follow_reports_the_referrer(
    tmp_path: Path, body: str
) -> None:
    prelude, send = body.split("|")
    config_dir = _write(
        tmp_path,
        {"mod.py": _HEAD + prelude + _WIRE + '@handler("h_p")\ndef h_p(msg):\n' + send},
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert Reference("handler", "h_p", "outbound", "OB_OLD") in plan.unresolved


# --- r3 repairs (findings 1 and 3 of b617r-5980-r2) ----------------------------------------------

_LOGGED_LOOKUP = (
    "def _lookup(table, code):\n    print(table)\n    return code_set(table).get(code)\n"
)


@pytest.mark.parametrize(
    ("prelude", "call", "extra"),
    [
        ('TABLES = {"x": "diets"}\n' + _LOGGED_LOOKUP, '_lookup(TABLES["x"], "A")', {}),
        ("import _t\n" + _LOGGED_LOOKUP, '_lookup(_t.NAME, "A")', {"_t.py": 'NAME = "diets"\n'}),
        ('def _name():\n    return "diets"\n\n\n' + _LOGGED_LOOKUP, '_lookup(_name(), "A")', {}),
        (
            'TABLES = {"x": "diets"}\n'
            + _LOGGED_LOOKUP
            + '\n\ndef _via(table):\n    return _lookup(table, "A")\n',
            '_via(TABLES["x"])',
            {},
        ),
    ],
    ids=["module_dict", "module_attribute", "helper_return", "handed_on"],
)
def test_a_table_value_passed_to_a_logged_helper_parameter_reports_the_referrer(
    tmp_path: Path, prelude: str, call: str, extra: dict[str, str]
) -> None:
    """A helper parameter that reaches the accessor and is also logged gives no role slot, so the
    caller's argument is never rewritten. Reached through a module name, a module attribute or a
    helper's return it was not counted either, so the rename reported success while the handler
    kept reading the old table. The handler's own direct read gives the index an edge from it."""
    config_dir = _write(
        tmp_path,
        {
            **extra,
            "mod.py": _HEAD + _WIRE + prelude + '\n\n@handler("h_p")\ndef h_p(msg):\n'
            f"    {call}\n"
            '    code_set("diets").get("A")\n'
            '    return Send("OB_A", msg)\n',
            "codesets/diets.csv": _CSV,
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    assert plan.unresolved == (_H_DIETS,)


def test_a_table_value_passed_to_a_helper_parameter_only_the_accessor_reads_is_rewritten(
    tmp_path: Path,
) -> None:
    """The control: with no other read of the parameter, the module constant is the table."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + _WIRE + 'NAME = "diets"\n'
            "def _lookup(table, code):\n    return code_set(table).get(code)\n"
            '\n\n@handler("h_p")\ndef h_p(msg):\n'
            '    _lookup(NAME, "A")\n'
            '    code_set("diets").get("A")\n'
            '    return Send("OB_A", msg)\n',
            "codesets/diets.csv": _CSV,
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "meals")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert '"diets"' not in _text(config_dir)


@pytest.mark.parametrize(
    "body",
    [
        '    note = LABELS.get("OB_A")\n    return Send("OB_A", msg)\n',
        '    return Send("OB_A", msg) if LABELS else None\n',
        '    return [Send(d, msg) for d in ["OB_A"] if d in LABELS]\n',
    ],
    ids=["get", "truthiness", "membership"],
)
def test_a_label_dict_holding_the_name_beside_a_followed_send_is_not_refused(
    tmp_path: Path, body: str
) -> None:
    """A handler the index has no edge from holds a label dict whose value is the name, and sends
    only to values the scan follows: no role reads the dict, so the rename completes and the label
    is left. A label written in the handler's own lines is still counted, by design."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD
            + 'LABELS = {"OB_A": "OB_OLD"}\n\n'
            + _WIRE
            + '@handler("h_p")\ndef h_p(msg):\n'
            + body
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert 'LABELS = {"OB_A": "OB_OLD"}' in _text(config_dir)


# --- r3 final round: nested routing tables (round-8e41ea17 finding 2) ---------------------------


@pytest.mark.parametrize(
    ("prelude", "body"),
    [
        # The inner dict's key is the name sent: missed, and the rename reported success.
        (
            'ROUTES = {"adt": {"OB_OLD": 1}}\n',
            "    return [Send(d, msg) for d in ROUTES[str(msg)]]\n",
        ),
        # The inner dict's value is a label: rewritten, and the key that is sent missed.
        (
            'ROUTES = {"adt": {"OB_A": "OB_OLD"}, "oru": {"OB_OLD": 1}}\n',
            "    return [Send(d, msg) for d in ROUTES.get(str(msg), {})]\n",
        ),
        # The same, read out of a local table.
        (
            "",
            '    routes = {"adt": {"OB_OLD": 1}}\n'
            "    return [Send(d, msg) for d in routes[str(msg)]]\n",
        ),
    ],
    ids=["module_subscript", "module_get", "local"],
)
def test_a_nested_routing_table_reports_the_referrer(
    tmp_path: Path, prelude: str, body: str
) -> None:
    """A role iterating a value read out of a table takes the inner dict's keys, which the scan
    carried as values: the plan never rewrites the keys, so it must report the handler."""
    config_dir = _write(
        tmp_path,
        {"mod.py": _HEAD + prelude + _WIRE + '@handler("h_p")\ndef h_p(msg):\n' + body},
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert _H_P in plan.unresolved


def test_a_nested_routing_table_a_router_returns_reports_the_router(tmp_path: Path) -> None:
    """The router variant: the engine iterates ``list(TABLE[kind])``, an inner dict's keys."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + 'TABLE = {"adt": {"h_p": 1}}\n\n'
            'inbound("IB_P", MLLP(port=2937), router="r_t")\n'
            'outbound("OB_A", MLLP(host="127.0.0.1", port=6935))\n\n\n'
            '@router("r_t")\ndef r_t(msg):\n    return list(TABLE[str(msg)])\n\n\n'
            '@handler("h_p")\ndef h_p(msg):\n    return Send("OB_A", msg)\n'
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "handler", "h_p", "h_new")
    assert Reference("router", "r_t", "handler", "h_p") in plan.unresolved


def test_a_table_of_lists_iterated_by_key_is_rewritten(tmp_path: Path) -> None:
    """The control: a table whose values are lists yields their elements, which are rewritten."""
    config_dir = _write(
        tmp_path,
        {
            "mod.py": _HEAD + 'ROUTES = {"adt": ["OB_OLD", "OB_A"]}\n' + _WIRE + '@handler("h_p")\n'
            "def h_p(msg):\n    return [Send(d, msg) for d in ROUTES[str(msg)]]\n"
        },
    )
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert 'ROUTES = {"adt": ["OB_NEW", "OB_A"]}' in _text(config_dir)
