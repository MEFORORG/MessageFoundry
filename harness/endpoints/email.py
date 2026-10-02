# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Endpoints of ``harness/config/email.py``: the Email (SMTP) outbound graph.

``harness/config/direct/direct.py`` reads the same two keys. It is served on its own (it needs
trust material minted for the run) and not alongside ``harness/config``; two engines on the defaults
would contend for the ``email_in`` port.
"""

from __future__ import annotations

from harness.endpoints import PORT, Endpoint

ENDPOINTS = (
    Endpoint(
        "email_in", PORT, "2660", "IB_Harness_Email: the MLLP entry inbound of the email graph"
    ),
    Endpoint(
        "email_smtp",
        PORT,
        "2661",
        "OB_Harness_Email and OB_Harness_Email_Rejected: the SMTP peer (the harness email sink)",
    ),
)
