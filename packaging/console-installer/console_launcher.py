# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Frozen-binary entry point for the MessageFoundry admin console (ADR 0032 Phase B).

PyInstaller freezes *this* tiny module, not ``messagefoundry/console/__main__.py`` directly: a
``__main__`` submodule is an awkward freeze target (PyInstaller would treat the package's own
``__main__`` specially and the module's ``if __name__ == "__main__"`` guard would not fire under the
frozen bootstrap), so the spec points at this stable launcher instead. It is byte-for-byte equivalent
to the wheel's windowed ``messagefoundry-console`` gui-script — both call the same
``messagefoundry.console.__main__:main`` — so the frozen exe behaves exactly like the pip-installed
launcher Phase A ships. Nothing about what the console imports or how it reaches the engine changes
(it stays PySide6, a separate process, HTTP-API-only — CLAUDE.md §2/§10); only the packaging differs.

The console parses its own ``--url``/``--insecure``/etc. from ``sys.argv`` inside ``main()``, so the
frozen exe accepts the same flags the shortcut bakes in.
"""

from __future__ import annotations

import multiprocessing
import sys

from messagefoundry.console.__main__ import main

if __name__ == "__main__":
    # PyInstaller-frozen apps that ever spawn a child process must call freeze_support() before any
    # such spawn, or the child re-bootstraps the whole app (the classic "fork bomb" of frozen GUIs).
    # The console does not spawn children today, but this is the documented, zero-cost safeguard for a
    # frozen Windows binary and keeps the launcher correct if a worker process is ever added.
    multiprocessing.freeze_support()
    sys.exit(main())
