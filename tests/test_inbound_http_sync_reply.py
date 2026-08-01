# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Synchronous captured-downstream reply on the inbound HTTP listener (ADR 0154 increment B).

Starts with the **factory-local** half of D4: everything decidable from one ``Http()`` call with no
store, no posture and no registry, so it fires identically in ``messagefoundry check``, in dry-run,
and through the ``connections.toml`` desugar (which routes through this same factory).

The cross-registry half — ``reply_from`` naming a deployed outbound, that outbound capturing
responses, the ``passthrough`` content-type requirement, and the effective ``ordering`` /
``max_attempts`` refusals — is not knowable here and is tested against ``build_check_registry``.
"""

from __future__ import annotations

import inspect

import pytest

from messagefoundry.config.wiring import Http, WiringError


def test_valid_configurations_build() -> None:
    Http(port=8080)  # no reply_from: the shipped 202 path, byte-identical
    Http(port=8080, reply_from="OB_PARTNER")
    Http(
        port=8080,
        reply_from="OB_PARTNER",
        reply_timeout=5.0,
        reply_on_timeout="202",
        reply_content_type="application/json",
        reply_on_empty="200",
        reply_write_timeout=10.0,
    )


def test_settings_are_carried_onto_the_spec() -> None:
    spec = Http(port=8080, reply_from="OB_PARTNER", reply_timeout=7.5)
    assert spec.settings["reply_from"] == "OB_PARTNER"
    assert spec.settings["reply_timeout"] == 7.5
    assert spec.settings["reply_on_timeout"] == "504"  # default
    assert spec.settings["reply_content_type"] == "passthrough"  # default
    assert spec.settings["reply_on_empty"] == "204"  # default
    assert spec.settings["reply_write_timeout"] == 30.0  # default

    # An inbound with no reply_from still carries the key, so the listener reads one shape.
    assert Http(port=8080).settings["reply_from"] is None


def test_knobs_without_reply_from_are_refused() -> None:
    # Same defect class as a credential configured with intake_auth="none": every one of these is
    # inert without reply_from, so the config would silently do nothing while reading as if it did.
    with pytest.raises(WiringError, match="no reply_from"):
        Http(port=8080, reply_timeout=5.0)
    with pytest.raises(WiringError, match="no reply_from"):
        Http(port=8080, reply_on_timeout="202")
    with pytest.raises(WiringError, match="no reply_from"):
        Http(port=8080, reply_content_type="application/json")
    with pytest.raises(WiringError, match="no reply_from"):
        Http(port=8080, reply_on_empty="200")
    with pytest.raises(WiringError, match="no reply_from"):
        Http(port=8080, reply_write_timeout=10.0)

    # ... and the message names the offending knob, so the fix is obvious from the error alone.
    with pytest.raises(WiringError, match="reply_timeout"):
        Http(port=8080, reply_timeout=5.0)


def test_the_default_table_is_derived_from_the_signature_not_copied() -> None:
    # Drift guard on the guard. If the defaults were hand-copied, changing one in the signature would
    # silently stop the "configured but never read" refusal from firing for that knob.
    from messagefoundry.config.wiring import _SYNC_REPLY_KNOBS, _sync_reply_defaults

    params = inspect.signature(Http).parameters
    assert _sync_reply_defaults() == {name: params[name].default for name in _SYNC_REPLY_KNOBS}
    # And every knob named really is a parameter — a rename would otherwise leave a dead entry.
    assert set(_SYNC_REPLY_KNOBS) <= set(params)


def test_an_empty_reply_from_is_refused() -> None:
    # "" is falsy, so it would read as "no sync reply" while looking configured in the file.
    with pytest.raises(WiringError, match="must name an outbound"):
        Http(port=8080, reply_from="")
    with pytest.raises(WiringError, match="must name an outbound"):
        Http(port=8080, reply_from="   ")


@pytest.mark.parametrize("knob", ["reply_timeout", "reply_write_timeout"])
@pytest.mark.parametrize("bad", [0, 0.0, -1, -0.5])
def test_a_non_positive_budget_is_refused(knob: str, bad: float) -> None:
    # Both bound a BLOCKED HTTP turn. Zero or negative is not "no timeout", it is a turn that cannot
    # succeed — and an operator writing 0 almost certainly means "unbounded", which is worse.
    with pytest.raises(WiringError, match="positive number of seconds"):
        Http(port=8080, reply_from="OB_PARTNER", **{knob: bad})


def test_the_status_choices_are_closed() -> None:
    with pytest.raises(WiringError, match="reply_on_timeout"):
        Http(port=8080, reply_from="OB_PARTNER", reply_on_timeout="500")  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="reply_on_empty"):
        Http(port=8080, reply_from="OB_PARTNER", reply_on_empty="204 No Content")  # type: ignore[arg-type]


def test_reply_content_type_must_be_passthrough_or_a_mime_type() -> None:
    with pytest.raises(WiringError, match="not empty"):
        Http(port=8080, reply_from="OB_PARTNER", reply_content_type="")
    with pytest.raises(WiringError, match="which is neither"):
        Http(port=8080, reply_from="OB_PARTNER", reply_content_type="json")
    # A real MIME type and the passthrough sentinel both pass.
    Http(port=8080, reply_from="OB_PARTNER", reply_content_type="application/soap+xml")
    Http(port=8080, reply_from="OB_PARTNER", reply_content_type="passthrough")


def test_sync_reply_and_intake_auth_compose() -> None:
    # The two increments' surfaces are orthogonal and must not interfere.
    from messagefoundry.config.wiring import env

    spec = Http(
        port=8443,
        intake_auth="api_key",
        intake_api_key=env("acme_intake_key"),
        reply_from="OB_PARTNER",
        reply_timeout=15.0,
    )
    assert spec.settings["intake_auth"] == "api_key"
    assert spec.settings["reply_from"] == "OB_PARTNER"
