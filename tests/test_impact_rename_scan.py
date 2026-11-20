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
def _forget_helper_modules() -> object:
    """Config helper modules are imported by name, so one test's ``_ha`` must not serve the next."""
    before = set(sys.modules)
    yield None
    for name in set(sys.modules) - before:
        if name.startswith("_h"):
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
