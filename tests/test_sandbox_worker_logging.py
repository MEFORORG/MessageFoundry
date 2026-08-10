# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1054: the ADR 0087 sandbox worker CHILD logs through the engine's PHI-redaction +
control-char-scrub filter chain.

``tests/test_logging.py`` covers :func:`~messagefoundry.logging_setup.configure_stderr_logging` as a
function. This file covers the thing that actually protects a deployment: that the **worker module's
own module-scope wiring** calls it, measured in a real child process rather than by reading the
source. The module reconfigures the root logger on import, so it cannot be imported in-process
without wrecking logging for the rest of the suite — hence the subprocess.
"""

from __future__ import annotations

import subprocess
import sys

#: Synthetic HL7 (never real PHI). HL7-shaped so ``redact`` rewrites the span.
SYNTHETIC_PHI = "PID|1||100^^^H^MR||DOE^JANE^Q||19800101|F"

# Importing the worker module is the thing under test: its module scope installs the filtered stderr
# handler. The CR/LF is built here rather than passed through argv, where a Windows command line would
# make its survival a property of the shell instead of a property of the code.
_CHILD = (
    "import sys\n"
    "import messagefoundry.pipeline._sandbox_worker as worker\n"
    "worker.log.warning(\n"
    "    'request failed on %s',\n"
    "    sys.argv[1] + chr(13) + chr(10) + 'WARNING forged-record',\n"
    ")\n"
)


def test_sandbox_worker_child_logs_redacted_and_scrubbed_to_stderr() -> None:
    proc = subprocess.run(  # noqa: S603 - fixed argv, this interpreter
        [sys.executable, "-c", _CHILD, SYNTHETIC_PHI],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    err = proc.stderr

    # stdout is the MFW2 IPC channel — not one log byte may land there, or a frame is corrupt.
    assert proc.stdout == ""

    assert "[redacted]" in err  # the HL7 span was rewritten by RedactionFilter...
    for token in ("DOE", "JANE", "19800101", "100^^^H^MR"):
        assert token not in err, f"unredacted {token!r} reached the child's stderr"

    # ...and ControlCharScrubFilter escaped the CR/LF, so the appended text cannot begin its own
    # physical line and impersonate a record prefix on the stream the engine inherits.
    assert "\\r\\n" in err
    assert "forged-record" in err  # kept and diagnosable, just not at column 0
    assert len([line for line in err.splitlines() if line.strip()]) == 1
