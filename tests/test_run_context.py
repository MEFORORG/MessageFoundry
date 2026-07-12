# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the run-scoped context provider registry (ADR 0009).

The four built-in providers (code_sets/reference/state/environment) are exercised end-to-end by the
rest of the suite (the staged-pipeline + dry-run tests prove the seam is byte-identical). These tests
cover the registry contract itself: built-in order, phase filtering, registration-order == nesting,
idempotency, and input validation.
"""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
from typing import Any, Iterator

import pytest

from messagefoundry.config import run_context
from messagefoundry.config.run_context import (
    ROUTER,
    TRANSFORM,
    RunContext,
    register_run_context,
    registered_providers,
    run_contexts,
)


@pytest.fixture(autouse=True)
def _isolate_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give each test its own copy of the module-global provider list so a test registration can't leak
    into the engine's real runs in the same process (there is no unregister; the built-ins are kept)."""
    monkeypatch.setattr(run_context, "_providers", list(run_context._providers))


def test_builtins_registered_first_in_nesting_order() -> None:
    # The built-ins are pre-registered at import in the order that reproduces the old `with`-tuple
    # nesting; they always lead the list (they register before any feature module imports run_context).
    # `response` (ADR 0013) nests AFTER state and BEFORE environment (transform phase only).
    assert registered_providers()[:5] == [
        "code_sets",
        "reference",
        "state",
        "response",
        "environment",
    ]


def _order_probe(label: str, log: list[str]) -> Any:
    @contextmanager
    def cm(_context: RunContext) -> Iterator[None]:
        log.append(f"enter:{label}")
        try:
            yield
        finally:
            log.append(f"exit:{label}")

    return lambda _context: cm(_context)


def test_phase_filtering_and_registration_order_is_nesting() -> None:
    log: list[str] = []
    register_run_context("probe_both", _order_probe("both", log), phases={ROUTER, TRANSFORM})
    register_run_context("probe_tx", _order_probe("tx", log), phases={TRANSFORM})

    # Router phase: the transform-only provider is skipped.
    with run_contexts(RunContext(), phase=ROUTER):
        pass
    assert "enter:both" in log
    assert "enter:tx" not in log

    # Transform phase: both run; registration order == nesting (both is outer, so it exits last).
    log.clear()
    with run_contexts(RunContext(), phase=TRANSFORM):
        pass
    assert log == ["enter:both", "enter:tx", "exit:tx", "exit:both"]


def test_register_is_idempotent_by_name() -> None:
    before = registered_providers()
    # Re-registering an existing name replaces in place — no duplicate, order preserved.
    register_run_context("code_sets", lambda _c: nullcontext(), phases={ROUTER})
    assert registered_providers() == before


def test_unknown_phase_rejected() -> None:
    with pytest.raises(ValueError, match="unknown phase"):
        register_run_context("bad", lambda _c: nullcontext(), phases={"bogus"})


def test_empty_phases_rejected() -> None:
    with pytest.raises(ValueError, match="phases must not be empty"):
        register_run_context("empty", lambda _c: nullcontext(), phases=set())


def test_unmapped_capture_provider_keys_by_message_id() -> None:
    """#162: the built-in ``unmapped_capture`` provider must thread ``RunContext.message_id`` to the
    capture scope, so the drained sink is keyed per message. Guards the pipeline wiring (every runner
    RunContext sets message_id=item.message_id) against silently collapsing to None."""
    from messagefoundry.config.code_sets import (
        CodeSet,
        UnmappedKind,
        UnmappedMiss,
        UnmappedPolicy,
        set_unmapped_sink,
    )

    cs = CodeSet("diet", {}, UnmappedPolicy(UnmappedKind.PASSTHROUGH))
    seen: list[tuple[str | None, str, str]] = []

    def sink(misses: list[UnmappedMiss], message_id: str | None) -> None:
        seen.extend((message_id, m.code_set, m.key) for m in misses)

    set_unmapped_sink(sink)
    try:
        with run_contexts(RunContext(message_id="msg-42"), phase=TRANSFORM):
            cs.translate("ZZ")
    finally:
        set_unmapped_sink(None)
    assert seen == [("msg-42", "diet", "ZZ")]


def test_providers_unwind_on_exception() -> None:
    log: list[str] = []
    register_run_context("probe", _order_probe("p", log), phases={TRANSFORM})
    with pytest.raises(RuntimeError):
        with run_contexts(RunContext(), phase=TRANSFORM):
            raise RuntimeError("boom")
    # The ExitStack still unwound the provider despite the body raising.
    assert log == ["enter:p", "exit:p"]
