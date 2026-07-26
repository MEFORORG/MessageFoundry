"""Tray service-control wrapper (ADR 0113 §4) — pure helpers + the delegating perform()."""

from __future__ import annotations

import pytest

import messagefoundry.tray.control as control
from messagefoundry.service import ServiceControlOutcome
from messagefoundry.tray.control import confirm_text, needs_confirm, outcome_toast, perform


def test_needs_confirm() -> None:
    assert needs_confirm("stop") is True
    assert needs_confirm("restart") is True
    assert needs_confirm("start") is False


def test_confirm_text_names_service_and_verb() -> None:
    text = confirm_text("stop", "MessageFoundry")
    assert "Stop" in text
    assert "MessageFoundry" in text
    assert "halts message flow" in text


@pytest.mark.parametrize(
    ("outcome", "expect_body"),
    [
        (ServiceControlOutcome.CANCELLED, "cancelled"),
        (ServiceControlOutcome.FAILED, "failed"),
        (ServiceControlOutcome.UNSUPPORTED, "Windows-only"),
    ],
)
def test_outcome_toast_messages(outcome: ServiceControlOutcome, expect_body: str) -> None:
    toast = outcome_toast("stop", outcome)
    assert toast is not None
    assert expect_body.lower() in toast.body.lower()


def test_outcome_toast_dispatched_is_silent() -> None:
    # A successful dispatch is announced by the poller's transition toast, not here.
    assert outcome_toast("start", ServiceControlOutcome.DISPATCHED) is None


def test_perform_delegates_to_control_service_ex(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake(action: str, name: str) -> ServiceControlOutcome:
        calls.append((action, name))
        return ServiceControlOutcome.DISPATCHED

    monkeypatch.setattr(control, "control_service_ex", fake)
    assert perform("restart", "MessageFoundry") is ServiceControlOutcome.DISPATCHED
    assert calls == [("restart", "MessageFoundry")]
