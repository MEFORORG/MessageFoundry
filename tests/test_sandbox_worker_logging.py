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

import ast
import subprocess
import sys
from pathlib import Path

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


def test_the_stdout_rebind_sits_between_the_frame_capture_and_the_boot_read() -> None:
    """ADR 0176 D3 is a SOURCE-ORDER property, so it needs a source-order instrument (SDS-3.8).

    ``_redirect_stdout_to_stderr()`` must run AFTER ``main`` captures ``sys.stdout.buffer`` -- at module
    scope that capture would resolve to fd 2 and every MFW2 frame would go to the wrong pipe -- and
    BEFORE the boot frame is read, whose reply path runs ``load_config()``, the earliest untrusted code
    and the first thing that can print.

    No runtime test can see this: moving the rebind to module scope breaks every frame, and moving it
    after the boot read leaves a window open, yet the test above passes either way because it never
    spawns a worker. The instrument has to be the source itself.

    Measured on the AST and not on the text, because a text scan matches a COMMENT naming the call —
    which is exactly how the first draft of this test passed while the call was deleted."""
    source = (
        Path(__file__).resolve().parents[1] / "messagefoundry" / "pipeline" / "_sandbox_worker.py"
    ).read_text(encoding="utf-8")
    main = next(
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    nodes = list(ast.walk(main))

    def _call_line(name: str) -> int:
        lines = [
            n.lineno
            for n in nodes
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name
        ]
        assert lines, f"main() contains no call to {name}()"
        return min(lines)

    capture = min(
        (
            n.lineno
            for n in nodes
            if isinstance(n, ast.Attribute)
            and n.attr == "buffer"
            and isinstance(n.value, ast.Attribute)
            and n.value.attr == "stdout"
        ),
        default=-1,
    )
    assert capture > 0, "main() no longer captures sys.stdout.buffer as the raw frame handle"
    rebind = _call_line("_redirect_stdout_to_stderr")
    boot_read = _call_line("_read_frame_bytes")
    assert capture < rebind < boot_read, (
        "the fd-1 capture / stdout rebind / boot-frame read are out of order in main(): the rebind "
        f"must follow the capture and precede the first untrusted code, ADR 0176 D3 "
        f"(capture line {capture}, rebind {rebind}, boot read {boot_read})"
    )
