# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #117 / ADR 0124 — build-time wiring rejects for the MLLP ``no_ack`` knob (AC-5, AC-6).

``no_ack`` skips the ACK read entirely, so there is nothing to capture (mutually exclusive with
``capture_response``/``reingress_to``) and it is MLLP-only (the generic ``Tcp()``/``X12()``
fire-and-forget is ``expect_reply=false``). Both are rejected at ``check``/dry-run time by
``build_outbound_connection`` — before any store or socket.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.wiring import (
    MLLP,
    Tcp,
    WiringError,
    build_outbound_connection,
)


def test_no_ack_mllp_accepted() -> None:
    # A plain fire-and-forward MLLP outbound is valid.
    build_outbound_connection("OB", MLLP(host="h", port=1, no_ack=True))


def test_no_ack_with_capture_response_rejected() -> None:
    with pytest.raises(WiringError, match="no ACK to capture"):
        build_outbound_connection("OB", MLLP(host="h", port=1, no_ack=True, capture_response=True))


def test_no_ack_with_reingress_rejected() -> None:
    # reingress_to desugars to capture_response=True, which is then incompatible with no_ack.
    with pytest.raises(WiringError, match="no ACK to capture"):
        build_outbound_connection("OB", MLLP(host="h", port=1, no_ack=True, reingress_to="LB_IN"))


def test_no_ack_on_tcp_rejected() -> None:
    # no_ack is MLLP-only; a connections.toml desugar that sets it on a TCP outbound is rejected.
    spec = Tcp(host="h", port=1)
    spec.settings["no_ack"] = True
    with pytest.raises(WiringError, match="MLLP-only"):
        build_outbound_connection("OB", spec)


def test_no_ack_with_verify_ack_control_id_rejected() -> None:
    # RECONCILE-TIME integration guard: #82's verify_ack_control_id landed on main AFTER this lane was
    # authored, so the two knobs had never met. no_ack skips the ACK read entirely, so there is no MSA-2
    # to match against the sent MSH-10 — asking for both is a config that can never do what it says, and
    # it fails at wiring rather than silently ignoring the correlation the operator asked for.
    with pytest.raises(WiringError, match="verify_ack_control_id is incompatible"):
        build_outbound_connection(
            "OB", MLLP(host="h", port=1, no_ack=True, verify_ack_control_id=True)
        )


def test_verify_ack_control_id_without_no_ack_still_accepted() -> None:
    # The #82 knob on its own is untouched by the #117 guard (no regression).
    build_outbound_connection("OB", MLLP(host="h", port=1, verify_ack_control_id=True))
