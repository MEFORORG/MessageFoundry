# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Support-bundle assembly (#49).

``messagefoundry support-bundle`` writes a single zip an operator can hand to support without leaking
PHI or secrets: the engine ``__version__``, a **secret-free** config summary (registry COUNTS only —
never settings values or secrets), a ``/status`` snapshot built from the real status models, and a
**redacted** app-log tail. The hard rule is that nothing in the bundle may carry a raw message body or
a secret (see :mod:`messagefoundry.support.redact` for the log-line scrubber and
:func:`messagefoundry.support.bundle.build_bundle` for the assembly).

This is the CLI slice only; an admin-gated ``POST /support/bundle`` is a follow-up. Engine-side and
dependency-light (stdlib only), so it never pulls the API or console into the engine.
"""

from __future__ import annotations

from messagefoundry.support.bundle import BundleResult, build_bundle
from messagefoundry.support.redact import redact_log_line, redact_log_text

__all__ = ["BundleResult", "build_bundle", "redact_log_line", "redact_log_text"]
