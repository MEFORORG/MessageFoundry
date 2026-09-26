# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CRIT-2 (P7 disposition) — the ADR 0057 inline Step-A `handoff` fast-path is WIRED but ships
permanently DEFAULT-OFF (DO-NOT-PROMOTE per the ADR 0057 banner + ADR 0107 measured dead-end).

Two tripwires, no perf:

1. **Config-default gate** — `InboundConnection.inline` and the `inbound()` factory both default
   to `False`. This is the single knob that keeps the fast-path dormant on every default deployment
   (`_recompute_inline_ok` ANDs it in, `wiring_runner.py:1111`). A silent flip to `True` would
   promote a withdrawn lever; these pin it OFF. (The runtime split-path assertion already lives in
   `tests/test_inline_fast_path.py::test_inline_off_uses_split_path_and_processes`.)

2. **Doc-drift** — the earlier plan/ADR claim that `handoff` is "wired into nothing / only tests
   call `.handoff(`" was STALE: the live `_router_worker` calls `store.handoff(` at
   `wiring_runner.py:4084`. This guards the corrected docs against reverting to the false framing
   AND guards the live wiring against silently becoming dead code again.

Synthetic only; no store, no I/O beyond reading the shipped source/doc files.
"""

from __future__ import annotations

import ast
import inspect
import os
import warnings
from pathlib import Path

import pytest
from _ast_sites import calls_to, find_funcs

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, inbound

_REPO = Path(__file__).resolve().parents[1]

#: The coverage plan moved out of this repository under ADR 0160 D1 on 2026-08-31 (maintainer QA
#: planning: a draft that says on its face it awaits owner approval). Custody is in the vault. Only
#: ONE test below reads it; the other three assert about CODE and about ADR 0057, which stays.
_PLAN = _REPO / "docs" / "testing" / "FEATURE-COVERAGE-PLAN.md"
_DOC_ENV = "MEFOR_COVERAGE_PLAN_DOC"
_REQUIRE_ENV = "MEFOR_REQUIRE_COVERAGE_PLAN_DOC"


class CoveragePlanUnenforced(UserWarning):
    """The coverage plan is absent from this checkout, so its doc-drift assertion is inert.

    A warning rather than a bare skip, for the reason
    ``tests/test_threat_model_doc_drift.py::ThreatModelDocUnenforced`` gives and this module adopts
    verbatim: a skip prints as one ``s`` among thousands and the run still reads as clean. A warning
    lands in pytest's warnings summary, which is printed even under ``-q``.
    """


def _plan_path() -> Path:
    override = os.environ.get(_DOC_ENV, "").strip()
    return Path(override) if override else _PLAN


def _plan_text() -> str:
    """The coverage-plan text, or an ANNOUNCED skip where the document is not published here.

    The skip sits at this accessor rather than at module level on purpose. A module-level skip would
    take the three CODE assertions down with the doc one -- including the config-default gate that is
    the single knob keeping the ADR 0057 fast-path dormant on every default deployment. Those assert
    about shipped code and are exactly as valid in a checkout that does not carry the plan.
    """
    path = _plan_path()
    if not path.exists():
        if os.environ.get(_REQUIRE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
            pytest.fail(
                f"{_REQUIRE_ENV} is set, so this run is expected to enforce the coverage plan's "
                f"content — but {path} does not exist. Point {_DOC_ENV} at the document, or unset "
                f"{_REQUIRE_ENV} to run in the announced, non-enforcing posture."
            )
        warnings.warn(
            CoveragePlanUnenforced(
                f"{path} is absent from this checkout (docs/testing/** is withheld under ADR 0160 "
                "D1 and vaulted), so the CRIT-2 doc-drift assertion in "
                "tests/test_crit2_inline_doc_drift.py is INERT in this run: nothing here stops the "
                'plan reverting to the stale "wired into nothing" framing. Still enforced: the '
                "config-default gate on `InboundConnection.inline` and the `inbound()` factory, the "
                "live-wiring check that `_router_worker` really calls `store.handoff(`, and the ADR "
                f"0057 text. Set {_DOC_ENV}=<path to the plan> to enforce the doc half from this "
                f"checkout, or {_REQUIRE_ENV}=1 to make its absence a hard failure."
            ),
            stacklevel=3,
        )
        pytest.skip(
            f"{path} is absent — the coverage-plan drift half is NOT enforced in this run; see the "
            "CoveragePlanUnenforced entry in the warnings summary for what that costs"
        )
    return path.read_text(encoding="utf-8")


def test_inline_config_default_is_off() -> None:
    """The `InboundConnection.inline` field AND the `inbound()` factory default MUST stay `False` —
    the gate that keeps the ADR 0057 fast-path dormant. Flipping either to `True` would silently
    enable a wired-but-DO-NOT-PROMOTE lever (ADR 0057 banner, ADR 0107 measured dead end)."""
    ic = InboundConnection(
        "file_in",
        ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/in", "pattern": "*.hl7"}),
        router="r",
    )
    assert ic.inline is False  # dataclass default: fast-path off unless explicitly opted in

    factory_default = inspect.signature(inbound).parameters["inline"].default
    assert factory_default is False  # the connections-authoring factory default matches


def _awaits_store_handoff(node: ast.AST) -> bool:
    """Whether ``node`` contains ``await <x>.store.handoff(...)``."""
    return any(
        isinstance(sub, ast.Await)
        and isinstance(sub.value, ast.Call)
        and isinstance(sub.value.func, ast.Attribute)
        and sub.value.func.attr == "handoff"
        and isinstance(sub.value.func.value, ast.Attribute)
        and sub.value.func.value.attr == "store"
        for sub in ast.walk(node)
    )


def _wiring(source: str) -> dict[str, bool]:
    """The four links that keep the inline fast-path reachable, each read from CODE.

    An AST walk, not a substring scan (BACKLOG #1818). ``wiring_runner.py`` also names ``ic.inline``
    in a comment, so deleting the real read inside ``_recompute_inline_ok`` left the old scan green.
    The old scan also never asked whether the gate runs or whether its cache is read, so deleting
    either call site left the path dead with the guard green.
    """
    tree = ast.parse(source)
    gates = find_funcs(tree, "_recompute_inline_ok")
    readers = [
        func
        for func in ast.walk(tree)
        if isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
        and func.name != "_recompute_inline_ok"
        and any(
            isinstance(sub, ast.Attribute)
            and sub.attr == "_inline_ok"
            and isinstance(sub.ctx, ast.Load)
            for sub in ast.walk(func)
        )
    ]
    return {
        "gate reads ic.inline": len(gates) == 1
        and any(
            isinstance(sub, ast.Attribute)
            and sub.attr == "inline"
            and isinstance(sub.value, ast.Name)
            and sub.value.id == "ic"
            for sub in ast.walk(gates[0])
        ),
        "gate is called": bool(calls_to(tree, {"_recompute_inline_ok"})),
        "cache is read": bool(readers),
        "cache reader awaits store.handoff": any(_awaits_store_handoff(f) for f in readers),
    }


def test_inline_fast_path_is_wired_not_dead_code() -> None:
    """Doc-drift / dead-code tripwire: the inline fast-path IS reached from the live pipeline. The
    eligibility gate `_recompute_inline_ok` ANDs in `ic.inline` and is called; the function that
    reads its cache (`_process_ingress_item` today) awaits `self.store.handoff(...)`. If any link is
    removed the fast-path becomes dead code and the corrected docs go stale again."""
    src = (_REPO / "messagefoundry" / "pipeline" / "wiring_runner.py").read_text(encoding="utf-8")
    broken = sorted(link for link, held in _wiring(src).items() if not held)
    assert not broken, f"the inline fast-path is no longer wired; these links are gone: {broken}"


def test_wiring_probe_ignores_mentions() -> None:
    """The probe above reads code only: mentions are ABSENT, the real constructs PRESENT."""
    mention = (
        '"""The worker reads self._inline_ok, awaits self.store.handoff( and ANDs in ic.inline."""\n'
        "class Runner:\n"
        "    def _recompute_inline_ok(self):\n"
        "        # inline_ok = ic.inline and ...; self._recompute_inline_ok()\n"
        '        return "await self.store.handoff("\n'
    )
    assert not any(_wiring(mention).values())
    real = (
        "class Runner:\n"
        "    def _recompute_inline_ok(self):\n"
        "        self._inline_ok = {n: ic.inline for n, ic in self.inbounds}\n"
        "    def start(self):\n"
        "        self._recompute_inline_ok()\n"
        "    async def process(self, name):\n"
        "        if self._inline_ok.get(name, False):\n"
        "            await self.store.handoff(row)\n"
    )
    assert all(_wiring(real).values())


def test_adr_0057_does_not_claim_unwired() -> None:
    """ADR 0057 §1 must NOT carry the stale "nothing in the live pipeline calls `.handoff(`" claim,
    and the permanent-OFF posture (DO-NOT-PROMOTE banner + the wired-but-default-OFF correction)
    must be present. Regression tripwire on the ADR text itself."""
    adr = (_REPO / "docs" / "adr" / "0057-inline-step-a-fast-path.md").read_text(encoding="utf-8")
    assert "Grep confirms nothing in the live pipeline calls" not in adr  # the struck false claim
    assert "DO NOT PROMOTE" in adr  # the shipping-OFF banner still stands
    assert "wired-but-permanently-default-OFF" in adr  # the corrected framing
    assert "wiring_runner.py:4084" in adr  # anchored to the real call site


def test_coverage_plan_reflects_wired_default_off() -> None:
    """The FEATURE-COVERAGE-PLAN CRIT-2 rows must reflect WIRED-but-DEFAULT-OFF, not the stale
    "unwired / wired into nothing" framing. Guards the plan against reverting to the false claim."""
    plan = _plan_text()
    # The stale claims as they stood (bold feature cell / disposition cell) must be gone. The
    # corrected narrative may still QUOTE the old phrase when explaining the fix, so match the exact
    # struck forms rather than a bare substring.
    assert "**wired into nothing**" not in plan  # struck bold row-509 feature claim
    assert "built+tested but unwired" not in plan  # struck row-349 disposition claim
    # ...replaced by the WIRED-but-DEFAULT-OFF framing anchored to live code.
    assert "**WIRED into `_router_worker`**" in plan  # the corrected row-509 feature cell
    assert "wiring_runner.py:4084" in plan  # the corrected rows cite the real call site
    assert "`[transform].inline=False`" in plan  # and the config-default gate that keeps it off
