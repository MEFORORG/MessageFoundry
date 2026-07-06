# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Windows Server 2025 on-server acceptance harness.

Turns ``docs/testing/WIN2025-TEST-MATRIX.md`` into an executable runner: each matrix row is bound to
a *probe* (a live environment/host check), a set of *pytest node ids* (the existing suites that
already assert that row, run against whatever backends ``MEFOR_*`` env makes reachable), a *harness*
command, or a *manual* step. The runner executes what it can, leaves the rest clearly marked MANUAL
(never faked green), and emits a PASS/FAIL/SKIP/MANUAL report — optionally writing the verdict back
into the matrix spreadsheet's Status column.

Run it with ``python -m harness.acceptance`` (see ``--help``). It imports no PySide6 on the headless
path, so it runs on the server over a remote session as well as the console host.
"""

from __future__ import annotations

from harness.acceptance.matrix import MATRIX, Coverage, MatrixRow, Status
from harness.acceptance.runner import RowResult, run_matrix

__all__ = ["MATRIX", "Coverage", "MatrixRow", "Status", "RowResult", "run_matrix"]
