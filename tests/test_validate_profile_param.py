# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The deleted conformance ``profile`` affordance stays deleted, and validation still works.

``messagefoundry.parsing.validate.validate`` used to take ``profile: object | None = None`` and
``messagefoundry.config.models.Validation`` used to carry a matching ``profile`` field. Both were
accepted, documented and read nowhere -- a control-shaped surface that was not a control. They were
removed on 2026-09-06 (BACKLOG #1109, ASVS 2.2.1).

This file lives apart from ``tests/test_parsing.py``, which owns the pure ``validate()`` surface,
because the deletion spans three layers: the function signature, the config model, and the pipeline
call path that joins them. Each half of that needs a different fixture, and only the join proves the
deletion broke no caller.

Every assertion here is paired with a NEGATIVE CONTROL that would fail if the deletion had broken
validation outright rather than merely removed a no-op. A test that only checks "profile is gone"
passes just as happily on a ``validate()`` that has stopped validating anything.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Validation
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing import validate
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import dry_run
from messagefoundry.store import MessageStatus

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "messages"
ADT = (SAMPLES / "adt_a01.hl7").read_text(encoding="utf-8")

# ADT_A01 requires a PID segment; this one has none, so hl7apy rejects it.
NON_CONFORMANT = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|N1|P|2.5.1\rEVN|A01|20260101\r"


# --- the parameter is gone, and stays gone -----------------------------------


def test_validate_signature_has_no_profile_keyword() -> None:
    params = inspect.signature(validate).parameters
    assert "profile" not in params
    # Positive control on the instrument: the sibling keyword the pipeline really passes IS
    # here, so an empty/rebound `params` cannot make the assertion above pass vacuously.
    assert "expected_version" in params
    # No ``**kwargs`` either -- one would swallow ``profile=`` and re-create the silent no-op.
    assert not any(p.kind is p.VAR_KEYWORD for p in params.values())


def test_passing_profile_now_raises_instead_of_being_silently_ignored() -> None:
    """The whole point of the deletion: a caller who passes one is told, not ignored."""
    with pytest.raises(TypeError, match="profile"):
        validate(ADT, profile="some/conformance/profile.xml")  # type: ignore[call-arg]


def test_validation_config_model_has_no_profile_field() -> None:
    assert "profile" not in Validation.model_fields
    # Positive control: the fields that ARE read by the pipeline are still declared.
    assert {"strict", "hl7_version", "strict_timeout_s"} <= set(Validation.model_fields)


def test_removing_the_config_field_changed_no_construction() -> None:
    """``Validation`` takes Pydantic's default ``extra='ignore'``, as it did before.

    So a caller that passed ``profile=`` got a silently-ignored value before the deletion and
    gets a silently-ignored value after it. Nothing that used to construct stopped constructing.
    """
    cfg = Validation(strict=True, hl7_version="2.5.1", profile="ignored")  # type: ignore[call-arg]
    assert cfg.strict is True
    assert cfg.hl7_version == "2.5.1"
    assert not hasattr(cfg, "profile")


# --- negative controls: validation itself is unchanged -----------------------


def test_conformant_message_still_validates_ok() -> None:
    result = validate(ADT)
    assert result.ok
    assert result.version == "2.5.1"
    assert result.errors == []


def test_non_conformant_message_still_reports_errors() -> None:
    result = validate(NON_CONFORMANT)
    assert not result.ok
    assert result.errors


def test_expected_version_cross_check_still_fires() -> None:
    result = validate(ADT, expected_version="2.3")
    assert not result.ok
    assert any("version mismatch" in e for e in result.errors)


def test_tolerant_default_is_untouched_by_the_deletion() -> None:
    """A non-conformant message must still be VALIDATED as bad, not rejected earlier.

    Guards the constraint that mattered most: nothing here may make the engine refuse traffic it
    exists to tolerate. ``validation.strict`` ships False, so this message only reaches ``validate``
    at all because this test calls it directly -- and when it does, it comes back as a result
    object, never an exception.
    """
    assert validate(NON_CONFORMANT).errors  # a result, not a raise
    assert validate("   ").errors  # empty input is a result too


# --- the real pipeline strict-validation call path still works ---------------


def _registry(*, strict: bool, handler: Callable[[Message], Send] | None = None) -> Registry:
    """The shipped strict path: ``dryrun`` reads ``ic.validation`` and calls ``validate``."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 2575}),
            router="r",
            validation=Validation(strict=strict, hl7_version="2.5.1"),
        )
    )
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", handler or (lambda m: Send("out", m)))
    return reg


def test_strict_pipeline_path_still_passes_a_conformant_message() -> None:
    result = dry_run(_registry(strict=True), ADT)
    assert result.disposition is not MessageStatus.ERROR
    assert result.error is None
    assert result.handlers == ["h"]


def test_strict_pipeline_path_still_rejects_a_non_conformant_message() -> None:
    result = dry_run(_registry(strict=True), NON_CONFORMANT)
    assert result.disposition is MessageStatus.ERROR
    assert result.error


def test_tolerant_pipeline_path_still_accepts_a_non_conformant_message() -> None:
    """The default posture: ``strict=False`` routes an off-spec message rather than erroring."""
    result = dry_run(_registry(strict=False), NON_CONFORMANT)
    assert result.disposition is not MessageStatus.ERROR
    assert result.handlers == ["h"]


def test_handler_receives_a_parsed_message_on_the_strict_path() -> None:
    """End to end, not just a disposition: the strict path really produced a delivery."""
    seen: list[str] = []

    def handle(msg: Message) -> Send:
        seen.append(msg["MSH-10"] or "")
        return Send("out", msg)

    result = dry_run(_registry(strict=True, handler=handle), ADT)
    assert seen and seen[0]
    assert [d.to for d in result.deliveries] == ["out"]
