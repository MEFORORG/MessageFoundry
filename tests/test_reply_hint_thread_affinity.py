# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The reply rendezvous is only ever touched from the event loop thread (ADR 0154 D3).

**Static, because the failure is not reliably reproducible.** ``asyncio.Event.set()`` is not
thread-safe, and neither is the ``call_soon`` that schedules a waiter's wakeup. Called from a worker
thread it *usually appears to work* and intermittently drops the wakeup — so the turn hangs to its
full ``reply_timeout`` instead of returning in milliseconds, under load, occasionally. A functional
test cannot be relied on to catch that.

Worse, the tempting hook sites are exactly the unsafe ones. ``_run_fused_route`` and
``_run_fused_transform`` contain a disposition line that reads like the obvious place to signal from,
and both are dispatched onto a ``ThreadPoolExecutor``. They are also **SQL-Server-only** and gated
behind ``fuse_thread_hops``, which defaults off — so the normal PR leg would never execute them even
if a hint were added. This guard is what stands between that and a silent production defect.
"""

from __future__ import annotations

import ast
from pathlib import Path

from _ast_sites import find_funcs, named_func

_RUNNER = Path(__file__).resolve().parents[1] / "messagefoundry" / "pipeline" / "wiring_runner.py"

#: Function bodies that run OFF the event loop, in a ThreadPoolExecutor.
_OFF_LOOP_FUNCTIONS = ("_run_fused_route", "_run_fused_transform")

#: Any reference to the rendezvous. Deliberately broad — the point is that the object must not be
#: reachable from these frames at all, not that one particular method is avoided.
_FORBIDDEN_NAMES = ("_reply_rendezvous", "ReplyRendezvous", "reply_rendezvous")


def test_the_off_loop_functions_exist() -> None:
    """Liveness receipt: a rename would otherwise turn this module into green over nothing."""
    tree = ast.parse(_RUNNER.read_text(encoding="utf-8"))
    missing = [name for name in _OFF_LOOP_FUNCTIONS if not find_funcs(tree, name)]
    assert not missing, (
        f"{missing} no longer exist in wiring_runner.py. If the fused route/transform bodies were "
        "renamed or removed, update _OFF_LOOP_FUNCTIONS — do not delete this guard, the thread-safety "
        "constraint outlives any particular function name."
    )


def test_no_rendezvous_reference_in_an_off_loop_function() -> None:
    """The guard. Mutation: add ``self._reply_rendezvous.signal(...)`` to either body. Red: named."""
    tree = ast.parse(_RUNNER.read_text(encoding="utf-8"))

    violations: list[str] = []
    for func_name in _OFF_LOOP_FUNCTIONS:
        for func in find_funcs(tree, func_name):
            for node in ast.walk(func):
                name = (
                    node.attr
                    if isinstance(node, ast.Attribute)
                    else node.id
                    if isinstance(node, ast.Name)
                    else None
                )
                if name in _FORBIDDEN_NAMES:
                    line = getattr(node, "lineno", "?")  # Attribute and Name both carry it
                    violations.append(f"{func_name} references {name!r} at line {line}")

    assert not violations, (
        "the reply rendezvous is reachable from a function that runs OFF the event loop: "
        f"{violations}. asyncio.Event.set() and call_soon are NOT thread-safe — this usually appears "
        "to work and intermittently drops the wakeup, hanging the HTTP turn to its full "
        "reply_timeout under load. Hook the loop-side marshalling instead (the _Fused*Result path)."
    )


def test_the_guard_catches_a_planted_violation() -> None:
    """The guard must actually fire, or it is decoration (mirrors test_scanner_flags_a_planted_*)."""
    planted = ast.parse(
        "def _run_fused_route(self, item):\n"
        "    self._reply_rendezvous.signal(item.message_id, item.destination_name)\n"
        "    return None\n"
    )
    func = named_func(planted, "_run_fused_route")
    found = [
        n.attr
        for n in ast.walk(func)
        if isinstance(n, ast.Attribute) and n.attr in _FORBIDDEN_NAMES
    ]
    assert found == ["_reply_rendezvous"], "the walk would not have seen a real violation"


def test_the_loop_side_signal_is_present() -> None:
    """The other half: the hint must exist SOMEWHERE, or the poll silently carries every turn.

    Not a style check — a missing hint costs a poll interval on every reply and would never fail a
    functional test, since the loop is correct without it.
    """
    source = _RUNNER.read_text(encoding="utf-8")
    assert "self._reply_rendezvous.signal(" in source, (
        "no delivery-side reply hint found — every sync-reply turn would wait a full poll period "
        "for a reply that had already committed"
    )
