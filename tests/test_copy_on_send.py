# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Copy-on-Send (ADR 0104) — the flag-gated snapshot-at-Send-construction behaviour and its propagation.

Verifies AC-1 (a divergent fan-out — mutate the same message between two Sends — delivers per-destination
bytes, on the shape every transform path funnels through), AC-11 (flag OFF is byte-identical: Sends share
the caller's reference and a divergent fan-out collapses to last-write, exactly as before), and the
propagation guards: the run-context provider activates only in the transform phase, all three
transform-phase ``RunContext`` builders thread the flag (the fused silent-miss backstop), the sandbox
marshalling carries the scalar, and a snapshotted ``Send.message`` is picklable on both backends.
"""

from __future__ import annotations

import pickle
from pathlib import Path

import pytest

from messagefoundry.config.run_context import (
    RunContext,
    registered_providers,
    run_contexts,
)
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.send_snapshot import snapshot_on_send_active
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing._backend import backend
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import dry_run, transform_one
from messagefoundry.pipeline.sandbox import _picklable_run_context

_ADT = (
    "MSH|^~\\&|SENDA|SENDF|RECV|RFAC|20200101||ADT^A01^ADT_A01|MSG1|P|2.5\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def _fanout_registry() -> Registry:
    """A registry with two outbounds and one handler that mutates MSH-5 BETWEEN two Sends."""
    reg = Registry()
    for name in ("OB_A", "OB_B"):
        reg.add_outbound(
            OutboundConnection(
                name,
                ConnectionSpec(ConnectorType.FILE, {"directory": ".", "filename": "{MSH-10}.hl7"}),
            )
        )

    def _divergent(msg):  # type: ignore[no-untyped-def]
        msg.set("MSH-5", "SYS_A")
        a = Send("OB_A", msg)
        msg.set("MSH-5", "SYS_B")
        b = Send("OB_B", msg)
        return [a, b]

    reg.add_handler("fanout", _divergent)
    return reg


def _delivered_msh5(deliveries) -> dict[str, str | None]:  # type: ignore[no-untyped-def]
    return {d.to: Message.parse(d.payload).field("MSH-5") for d in deliveries}


def test_divergent_fanout_snapshots_per_send_fused_shape() -> None:
    """AC-1 (fused-path backstop): reproduce exactly what ``_run_fused_transform`` does — enter
    ``run_contexts(rc, phase="transform")`` with the flag ON, then call ``transform_one`` with **no**
    ``run_context=`` argument (the fused path reads the flag only from the provider-set ContextVar).
    The two deliveries must diverge; this FAILS if the fused ``RunContext`` literal omits the flag or if
    ``Send`` ever read the flag from an argument instead of the ContextVar."""
    reg = _fanout_registry()
    with run_contexts(RunContext(snapshot_on_send=True), phase="transform"):
        deliveries, _, _ = transform_one(reg, "fanout", _ADT, "hl7v2")
    assert _delivered_msh5(deliveries) == {"OB_A": "SYS_A", "OB_B": "SYS_B"}


def test_divergent_fanout_snapshots_per_send_split_shape() -> None:
    """AC-1 (split/inline shape): ``transform_one`` invoked with ``run_context=rc`` inside the same
    ``run_contexts`` scope (the split/inline workers pass the rc through ``to_thread``)."""
    reg = _fanout_registry()
    rc = RunContext(snapshot_on_send=True)
    with run_contexts(rc, phase="transform"):
        deliveries, _, _ = transform_one(reg, "fanout", _ADT, "hl7v2", run_context=rc)
    assert _delivered_msh5(deliveries) == {"OB_A": "SYS_A", "OB_B": "SYS_B"}


def _fanout_registry_with_inbound() -> Registry:
    reg = _fanout_registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(ConnectorType.FILE, {"directory": ".", "pattern": "*.hl7"}),
            router="r",
        )
    )
    reg.add_router("r", lambda msg: ["fanout"])
    return reg


def test_dry_run_previews_copy_on_send_only_when_opted_in() -> None:
    """Preview fidelity (adversarial-review fix): ``dry_run``/Test Bench previews the copy-on-Send
    divergence when ``snapshot_on_send=True`` and collapses to last-write by default (the default engine
    posture) — closing the preview/live gap where the shared ``RunContext`` had pinned the flag OFF."""
    reg = _fanout_registry_with_inbound()
    off = dry_run(reg, _ADT, inbound="IB")
    assert {d.to: Message.parse(d.payload).field("MSH-5") for d in off.deliveries} == {
        "OB_A": "SYS_B",
        "OB_B": "SYS_B",
    }
    on = dry_run(reg, _ADT, inbound="IB", snapshot_on_send=True)
    assert {d.to: Message.parse(d.payload).field("MSH-5") for d in on.deliveries} == {
        "OB_A": "SYS_A",
        "OB_B": "SYS_B",
    }


def test_flag_off_collapses_to_last_write() -> None:
    """AC-11: with no active run-context (flag OFF, the default) a divergent fan-out collapses to the
    final write for BOTH destinations — byte-identical to the pre-ADR-0104 deferred-encode behaviour."""
    reg = _fanout_registry()
    deliveries, _, _ = transform_one(reg, "fanout", _ADT, "hl7v2")
    assert _delivered_msh5(deliveries) == {"OB_A": "SYS_B", "OB_B": "SYS_B"}


def test_flag_off_send_stores_caller_reference() -> None:
    """AC-11: outside a transform run, ``Send`` stores the caller's exact object (zero snapshot)."""
    msg = Message.parse(_ADT)
    a = Send("OB_A", msg)
    msg.set("MSH-5", "LATER")
    b = Send("OB_B", msg)
    assert a.message is msg and b.message is msg
    assert Send("OB_A", "literal").message == "literal"


def test_flag_off_never_enters_snapshot_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-11: the OFF path must not even call the snapshot helper — monkeypatch it to explode and prove
    a normal Send still constructs."""
    import messagefoundry.config.wiring as wiring

    def _boom(_payload):  # type: ignore[no-untyped-def]
        raise AssertionError("snapshot_payload must not run when copy-on-Send is off")

    monkeypatch.setattr(wiring, "snapshot_payload", _boom)
    msg = Message.parse(_ADT)
    assert Send("OB_A", msg).message is msg  # constructs, no snapshot call


def test_provider_activates_only_in_transform_phase() -> None:
    """The ``snapshot_on_send`` provider activates the flag in the transform phase (where Sends are
    built) and NOT in the router phase; it defaults inactive with no scope at all."""
    assert snapshot_on_send_active() is False
    with run_contexts(RunContext(snapshot_on_send=True), phase="router"):
        assert snapshot_on_send_active() is False  # router phase does not construct Sends
    with run_contexts(RunContext(snapshot_on_send=True), phase="transform"):
        assert snapshot_on_send_active() is True
    with run_contexts(RunContext(snapshot_on_send=False), phase="transform"):
        assert snapshot_on_send_active() is False
    assert snapshot_on_send_active() is False  # restored on exit


def test_all_three_transform_builders_thread_the_flag() -> None:
    """Fused silent-miss structural backstop: every transform-phase ``RunContext`` literal in the runner
    threads ``snapshot_on_send=self._snapshot_on_send``. Exactly three today (split, inline, fused); a
    fourth transform-phase builder added without the kwarg (the exact silent-miss regression) trips this."""
    src = (
        Path(__file__).resolve().parents[1] / "messagefoundry" / "pipeline" / "wiring_runner.py"
    ).read_text(encoding="utf-8")
    assert src.count("snapshot_on_send=self._snapshot_on_send") == 3


def test_picklable_run_context_carries_flag() -> None:
    """AC-4: the sandbox marshalling copy carries the scalar ``snapshot_on_send`` to the child unchanged
    (no ``sandbox.py`` edit needed — it rides ``dataclasses.replace``)."""
    assert _picklable_run_context(RunContext(snapshot_on_send=True)).snapshot_on_send is True
    assert _picklable_run_context(RunContext()).snapshot_on_send is False


@pytest.mark.parametrize("builtin", [True, False], ids=["builtin", "python_hl7"])
def test_snapshotted_send_message_is_picklable(builtin: bool) -> None:
    """AC-4: a snapshotted ``Send.message`` survives the child→parent pickle round-trip on both backends
    and still encodes identically (so ``send.message.encode()`` succeeds in the parent)."""
    with backend(builtin=builtin):
        msg = Message.parse(_ADT)
        with run_contexts(RunContext(snapshot_on_send=True), phase="transform"):
            send = Send("OB_A", msg)
        assert send.message is not msg
        restored = pickle.loads(pickle.dumps(send, protocol=pickle.HIGHEST_PROTOCOL))
        assert restored.message.encode() == msg.encode()


def test_provider_registered_before_unmapped_capture() -> None:
    """The provider slots in AFTER the built-in five (their order unchanged) and BEFORE unmapped_capture,
    so the capture drain stays inside it."""
    provs = registered_providers()
    assert provs[:5] == ["code_sets", "reference", "state", "response", "environment"]
    assert "snapshot_on_send" in provs
    assert provs.index("snapshot_on_send") < provs.index("unmapped_capture")
