# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The reported outcome of a config reload matches what the engine actually did (BACKLOG #1111).

``Engine.reload`` swaps the live graph, and until this landed three steps that could raise ran
AFTER the swap. A raise in any of them would surface to ``POST /config/reload`` as a FAILED reload
while the NEW graph was already live -- and, on the propagate step, possibly after other nodes had
been told to converge onto it. An operator reading that failure would go on believing the old graph
was still serving.

The fix is two-sided, and both sides need holding down:

* the fingerprint step MOVED to before the swap, where a raise is honest (nothing was applied);
* the two steps that cannot move -- reference-set reconciliation reads its specs off the LIVE
  registry, and the cluster version bump announces a config this node has already taken -- report a
  PARTIAL outcome (``applied`` True with a named failure) instead of a failed reload.

The negative controls below are the load-bearing half. A change that simply reported success for
everything would satisfy every "degraded" assertion here; only the pre-swap arms, which still demand
an outright raise and the OLD graph still delivering, can tell that apart.

This fixes ONE named reporting defect. It does not move ASVS cell 2.3.3, whose row covers other
subjects entirely.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.wiring import WiringError, load_config
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.cluster import NullCoordinator

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


# --- helpers -----------------------------------------------------------------


def _write_config(cfg: Path, *, inbound_name: str, outbound_name: str, inbox: Path, outdir: Path):
    """A minimal valid graph: one file inbound -> one router -> one handler -> one file outbound.

    The inbound/outbound NAMES differ between the two configs a test loads, so "which graph is live"
    is answered by a name that exists in exactly one of them rather than by counting."""
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    outdir.mkdir(parents=True, exist_ok=True)
    (cfg / "cfg.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        f"inbound({inbound_name!r}, File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=0.02), router='r')\n"
        f"outbound({outbound_name!r}, File(directory={str(outdir)!r}, filename='{{MSH-10}}.hl7'))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        f"    return Send({outbound_name!r}, msg)\n",
        encoding="utf-8",
    )


def _write_bad_connector_config(cfg: Path, inbox: Path) -> None:
    """Valid wiring (the router resolves) but an outbound connector that cannot build (no directory).

    This is the PRE-swap failure the runner's own ``build_check`` raises on, before it touches the
    running graph -- the negative control's failure mode."""
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    (cfg / "cfg.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        "from messagefoundry.config.wiring import ConnectionSpec\n"
        "from messagefoundry.config.models import ConnectorType\n"
        f"inbound('IB_BAD', File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=0.02), router='r')\n"
        "outbound('OUT_BAD', ConnectionSpec(ConnectorType.FILE, {}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OUT_BAD', msg)\n",
        encoding="utf-8",
    )


async def _delivers(inbox: Path, outdir: Path, *, name: str, timeout: float = 5.0) -> bool:
    """True once a message dropped in ``inbox`` lands in ``outdir`` -- the graph is really RUNNING.

    Asserting on ``registry_runner.registry`` alone would pass against an engine that swapped the
    object and left the listeners bound to the old one, so every "which graph is live" claim here is
    settled by an end-to-end delivery."""
    (inbox / f"{name}.hl7").write_bytes(ADT.replace("MSG1", name).encode("utf-8"))
    deadline = asyncio.get_running_loop().time() + timeout
    target = outdir / f"{name}.hl7"
    while asyncio.get_running_loop().time() < deadline:
        if target.exists():
            return True
        await asyncio.sleep(0.02)
    return False


class _BumpFailsCoordinator(NullCoordinator):
    """A clustered stand-in whose cluster-wide config-version bump fails.

    ``is_clustered`` True is what puts the propagate step on the reload path at all; the bump then
    raises, which is the post-swap failure this arm needs."""

    def is_clustered(self) -> bool:
        return True

    async def bump_config_version(self) -> int:
        raise RuntimeError("cluster_config table is unreachable")


# --- the post-swap arms: applied, with the failed step named ------------------


async def test_post_swap_reference_sync_failure_reports_degraded_and_new_graph_is_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reference-sync failure AFTER the swap reports applied-with-a-named-failure, and the NEW
    graph is delivering.

    Falsified by reverting the ``try``/``except`` around ``_reconcile_reference_sync`` to the bare
    ``await``: the call raises out of ``reload_detail``, ``pytest.raises`` would be needed instead,
    and the reload reports total failure while the new feed below is demonstrably serving. Falsified
    separately by dropping the ``_delivers`` assertion: the test would then pass on a change that
    reports a degraded outcome without the swap ever having happened."""
    old_in, old_out = tmp_path / "old-in", tmp_path / "old-out"
    new_in, new_out = tmp_path / "new-in", tmp_path / "new-out"
    old_cfg, new_cfg = tmp_path / "old", tmp_path / "new"
    _write_config(
        old_cfg, inbound_name="IB_OLD", outbound_name="OUT_OLD", inbox=old_in, outdir=old_out
    )
    _write_config(
        new_cfg, inbound_name="IB_NEW", outbound_name="OUT_NEW", inbox=new_in, outdir=new_out
    )

    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(old_cfg))
    await eng.start()
    try:

        async def _boom(self: Engine, *, startup: bool) -> None:
            raise RuntimeError("reference source refused the connection")

        monkeypatch.setattr(Engine, "_reconcile_reference_sync", _boom)

        outcome = await eng.reload_detail(new_cfg)

        assert outcome.applied is True
        assert outcome.degraded is True
        assert [f.step for f in outcome.failures] == ["reference_sync"]
        # safe_exc keeps the type and redacts the message -- no body, and no bare "an error occurred".
        assert outcome.failures[0].detail.startswith("RuntimeError")

        # The reported outcome is only honest if the new graph really is live. Prove it end to end.
        assert eng.registry_runner is not None
        assert "IB_NEW" in eng.registry_runner.registry.inbound
        assert "IB_OLD" not in eng.registry_runner.registry.inbound
        assert await _delivers(new_in, new_out, name="AFTERSWAP")
    finally:
        await eng.stop()


async def test_post_swap_cluster_propagate_failure_reports_degraded_and_new_graph_is_live(
    tmp_path: Path,
) -> None:
    """A failed cluster config-version bump AFTER the swap reports applied-with-a-named-failure, and
    the NEW graph is delivering.

    This is the worst arm of the defect: the bump is what tells sibling nodes to converge, so a raise
    here used to report a failed reload from the one node that had definitely applied the config.

    Falsified by reverting the ``try``/``except`` around ``bump_config_version`` to the bare
    ``await``: ``RuntimeError`` escapes and no outcome is returned at all."""
    old_in, old_out = tmp_path / "old-in", tmp_path / "old-out"
    new_in, new_out = tmp_path / "new-in", tmp_path / "new-out"
    old_cfg, new_cfg = tmp_path / "old", tmp_path / "new"
    _write_config(
        old_cfg, inbound_name="IB_OLD", outbound_name="OUT_OLD", inbox=old_in, outdir=old_out
    )
    _write_config(
        new_cfg, inbound_name="IB_NEW", outbound_name="OUT_NEW", inbox=new_in, outdir=new_out
    )

    eng = await Engine.create(
        tmp_path / "e.db", poll_interval=0.02, coordinator=_BumpFailsCoordinator()
    )
    eng.add_registry(load_config(old_cfg))
    await eng.start()
    try:
        outcome = await eng.reload_detail(new_cfg, propagate=True)

        assert outcome.applied is True
        assert outcome.degraded is True
        assert [f.step for f in outcome.failures] == ["cluster_propagate"]

        assert eng.registry_runner is not None
        assert "IB_NEW" in eng.registry_runner.registry.inbound
        assert await _delivers(new_in, new_out, name="BUMPFAIL")
    finally:
        await eng.stop()


async def test_unreadable_bundle_applies_and_names_the_fingerprint_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreadable config bundle still applies (provenance is best-effort) but is NOT reported as a
    clean reload -- the caller is told which step left ``GET /config/provenance`` with nothing.

    Falsified by dropping the ``failures.append`` in the ``OSError`` branch: ``degraded`` goes False
    and the reload reports plain success while provenance is blank."""
    old_in, old_out = tmp_path / "old-in", tmp_path / "old-out"
    new_in, new_out = tmp_path / "new-in", tmp_path / "new-out"
    old_cfg, new_cfg = tmp_path / "old", tmp_path / "new"
    _write_config(
        old_cfg, inbound_name="IB_OLD", outbound_name="OUT_OLD", inbox=old_in, outdir=old_out
    )
    _write_config(
        new_cfg, inbound_name="IB_NEW", outbound_name="OUT_NEW", inbox=new_in, outdir=new_out
    )

    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(old_cfg))
    await eng.start()
    try:

        def _unreadable(directory: Any) -> dict[str, object]:
            raise OSError("config dir vanished mid-reload")

        monkeypatch.setattr(
            "messagefoundry.config.fingerprint.config_fingerprint_detail", _unreadable
        )

        outcome = await eng.reload_detail(new_cfg)

        assert outcome.applied is True
        assert [f.step for f in outcome.failures] == ["config_fingerprint"]
        assert eng.loaded_config_fingerprint is None  # provenance unknown, and the caller was told
        assert eng.registry_runner is not None
        assert "IB_NEW" in eng.registry_runner.registry.inbound
    finally:
        await eng.stop()


async def test_fingerprint_is_taken_before_the_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The provenance fingerprint is computed BEFORE the graph swap, not after.

    Order is the whole point: taken after the swap, a raise the ``OSError`` guard does not cover (an
    ``ImportError`` on the local import, say) reports a failed reload with the new graph already
    live. Taken before, the same raise aborts while the old graph still serves.

    Falsified by moving the fingerprint block back below ``runner.reload``: ``order`` becomes
    ``['swap', 'fingerprint']``."""
    old_in, old_out = tmp_path / "old-in", tmp_path / "old-out"
    new_in, new_out = tmp_path / "new-in", tmp_path / "new-out"
    old_cfg, new_cfg = tmp_path / "old", tmp_path / "new"
    _write_config(
        old_cfg, inbound_name="IB_OLD", outbound_name="OUT_OLD", inbox=old_in, outdir=old_out
    )
    _write_config(
        new_cfg, inbound_name="IB_NEW", outbound_name="OUT_NEW", inbox=new_in, outdir=new_out
    )

    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(old_cfg))
    await eng.start()
    try:
        order: list[str] = []
        runner = eng.registry_runner
        assert runner is not None
        original_reload = runner.reload

        def _recording_fingerprint(directory: Any) -> dict[str, object]:
            order.append("fingerprint")
            return {"fingerprint": "deadbeef", "files": 1}

        async def _recording_swap(new_registry: Any) -> None:
            order.append("swap")
            await original_reload(new_registry)

        monkeypatch.setattr(
            "messagefoundry.config.fingerprint.config_fingerprint_detail", _recording_fingerprint
        )
        monkeypatch.setattr(runner, "reload", _recording_swap)

        outcome = await eng.reload_detail(new_cfg)

        assert order == ["fingerprint", "swap"]
        assert outcome.failures == ()
        assert eng.loaded_config_fingerprint == {"fingerprint": "deadbeef", "files": 1}
    finally:
        await eng.stop()


# --- the negative controls: a PRE-swap failure still fails outright -----------


async def test_pre_swap_wiring_error_still_fails_and_leaves_the_old_graph_live(
    tmp_path: Path,
) -> None:
    """A config the loader rejects raises out of the reload and leaves the OLD graph delivering.

    THE control for the arms above. A change that reported a degraded success for everything would
    keep every "degraded" assertion in this file green; only this one goes red, because the reload
    genuinely did not happen and saying otherwise would send an operator looking at a graph that
    never loaded.

    Falsified by catching ``WiringError`` and returning an applied outcome: ``pytest.raises`` goes
    red. Falsified separately by dropping the ``_delivers`` assertion: the test would pass against a
    reload that raised AFTER wrecking the running graph."""
    old_in, old_out = tmp_path / "old-in", tmp_path / "old-out"
    old_cfg = tmp_path / "old"
    _write_config(
        old_cfg, inbound_name="IB_OLD", outbound_name="OUT_OLD", inbox=old_in, outdir=old_out
    )

    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(old_cfg))
    await eng.start()
    try:
        bad = tmp_path / "bad"
        bad.mkdir()
        (bad / "bad.py").write_text(
            "from messagefoundry import inbound, File\n"
            "inbound('IB_NEW', File(directory='.', pattern='*.hl7'), router='missing')\n",
            encoding="utf-8",
        )
        with pytest.raises(WiringError):
            await eng.reload_detail(bad)

        assert eng.registry_runner is not None
        assert "IB_OLD" in eng.registry_runner.registry.inbound
        assert "IB_NEW" not in eng.registry_runner.registry.inbound
        assert await _delivers(old_in, old_out, name="OLDSTILLRUNS")
    finally:
        await eng.stop()


async def test_pre_swap_connector_build_failure_still_fails_and_leaves_the_old_graph_live(
    tmp_path: Path,
) -> None:
    """A config that loads but whose connector cannot BUILD raises out of the reload, with the OLD
    graph still delivering.

    The second control, one step later than the loader: this failure comes from the runner's own
    ``build_check`` at the top of its quiesce-and-swap, so it exercises the boundary the partial
    outcome must never creep across.

    Falsified by widening the post-swap ``except Exception`` to cover the swap call itself: this
    would report an applied outcome for a graph that never went live."""
    old_in, old_out = tmp_path / "old-in", tmp_path / "old-out"
    old_cfg = tmp_path / "old"
    _write_config(
        old_cfg, inbound_name="IB_OLD", outbound_name="OUT_OLD", inbox=old_in, outdir=old_out
    )

    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(old_cfg))
    await eng.start()
    try:
        bad = tmp_path / "badconn"
        _write_bad_connector_config(bad, tmp_path / "bad-in")
        with pytest.raises(ValueError):
            await eng.reload_detail(bad)

        assert eng.registry_runner is not None
        assert "IB_OLD" in eng.registry_runner.registry.inbound
        assert "IB_BAD" not in eng.registry_runner.registry.inbound
        assert await _delivers(old_in, old_out, name="BUILDFAILOLD")
    finally:
        await eng.stop()


# --- the clean paths: unchanged behaviour ------------------------------------


async def test_clean_reload_reports_plain_success(tmp_path: Path) -> None:
    """A reload with nothing wrong reports applied with NO failures, and the new graph delivers.

    Falsified by appending an unconditional entry to ``failures``: ``degraded`` goes True and a
    healthy reload would start reading as partial, which is the same defect pointed the other way."""
    old_in, old_out = tmp_path / "old-in", tmp_path / "old-out"
    new_in, new_out = tmp_path / "new-in", tmp_path / "new-out"
    old_cfg, new_cfg = tmp_path / "old", tmp_path / "new"
    _write_config(
        old_cfg, inbound_name="IB_OLD", outbound_name="OUT_OLD", inbox=old_in, outdir=old_out
    )
    _write_config(
        new_cfg, inbound_name="IB_NEW", outbound_name="OUT_NEW", inbox=new_in, outdir=new_out
    )

    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(old_cfg))
    await eng.start()
    try:
        outcome = await eng.reload_detail(new_cfg)

        assert outcome.applied is True
        assert outcome.failures == ()
        assert outcome.degraded is False
        assert outcome.registry.inbound.keys() == {"IB_NEW"}
        # Provenance was still recorded, from the digest taken before the swap.
        assert eng.loaded_config_fingerprint is not None
        assert eng.loaded_config_fingerprint["files"] == 1
        assert await _delivers(new_in, new_out, name="CLEAN")
    finally:
        await eng.stop()


async def test_reload_wrapper_still_returns_the_registry(tmp_path: Path) -> None:
    """``reload()`` keeps its Registry return, so every existing caller is untouched by the outcome
    type -- including ``POST /config/reload``, which counts the returned graph.

    Falsified by changing ``reload`` to return the ``ReloadOutcome``: the ``.inbound`` lookup below
    raises ``AttributeError``."""
    old_in, old_out = tmp_path / "old-in", tmp_path / "old-out"
    new_in, new_out = tmp_path / "new-in", tmp_path / "new-out"
    old_cfg, new_cfg = tmp_path / "old", tmp_path / "new"
    _write_config(
        old_cfg, inbound_name="IB_OLD", outbound_name="OUT_OLD", inbox=old_in, outdir=old_out
    )
    _write_config(
        new_cfg, inbound_name="IB_NEW", outbound_name="OUT_NEW", inbox=new_in, outdir=new_out
    )

    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(old_cfg))
    await eng.start()
    try:
        registry = await eng.reload(new_cfg)
        assert registry.inbound.keys() == {"IB_NEW"}
        assert registry.outbound.keys() == {"OUT_NEW"}
    finally:
        await eng.stop()


async def test_dry_run_reports_not_applied_and_swaps_nothing(tmp_path: Path) -> None:
    """A dry run reports ``applied`` False with no failures, and the OLD graph is still live.

    ``applied`` False here is what keeps "validated" separate from "applied cleanly" -- both return
    an empty ``failures``, so a caller reading only ``failures`` could not tell them apart.

    Falsified by returning ``applied=True`` from the dry-run branch: the assertion below goes red
    while the old graph, correctly, keeps running."""
    old_in, old_out = tmp_path / "old-in", tmp_path / "old-out"
    new_in, new_out = tmp_path / "new-in", tmp_path / "new-out"
    old_cfg, new_cfg = tmp_path / "old", tmp_path / "new"
    _write_config(
        old_cfg, inbound_name="IB_OLD", outbound_name="OUT_OLD", inbox=old_in, outdir=old_out
    )
    _write_config(
        new_cfg, inbound_name="IB_NEW", outbound_name="OUT_NEW", inbox=new_in, outdir=new_out
    )

    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(old_cfg))
    await eng.start()
    try:
        outcome = await eng.reload_detail(new_cfg, dry_run=True)

        assert outcome.applied is False
        assert outcome.failures == ()
        assert outcome.degraded is False
        assert outcome.registry.inbound.keys() == {"IB_NEW"}  # the graph that WOULD go live
        assert eng.registry_runner is not None
        assert "IB_OLD" in eng.registry_runner.registry.inbound  # still the running one
    finally:
        await eng.stop()
