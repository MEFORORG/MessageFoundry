# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Endpoints of ``harness/config/remotefile/``: the REMOTEFILE (SFTP) graph and the harness share.

The graph lives in a SUBDIRECTORY because its inbound needs the harness SFTP share up and a password
in the environment, neither of which ``serve --config harness/config`` provides; see
``harness/scenarios/remotefile.py``.
"""

from __future__ import annotations

from harness.endpoints import PATH, PORT, Endpoint

ENDPOINTS = (
    Endpoint(
        "remotefile_sftp",
        PORT,
        "2670",
        "the harness SFTP share: IB_Harness_RemoteFile_Sftp polls its /inbox and "
        "OB_Harness_RemoteFile_Sftp writes its /outbox",
    ),
    Endpoint(
        "remotefile_known_hosts",
        PATH,
        "./harness_io/remotefile/known_hosts",
        "the known_hosts FILE pinning the share's throwaway host key; the share writes it on start "
        "and the engine and the driver verify against it",
    ),
)
