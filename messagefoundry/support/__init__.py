# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Support-bundle assembly (#49).

``messagefoundry support-bundle`` writes a single zip for an operator to hand to support: the engine
``__version__``, a config summary of registry COUNTS and names only (never a settings value or a
secret), a ``/status`` snapshot built from the real status models, and a **best-effort redacted**
app-log tail. The rule for the code is no raw message body and no secret this package puts in itself.
The archive is not thereby PHI-free or secret-free: values survive the log-tail redaction, at least a
single-token identifier such as an operator username, so the bundle is handled as a copy of the app
log. The manifest's ``phi_contract`` states that once (BACKLOG #5385); see
:mod:`messagefoundry.support.redact` for the log-line scrubber and
:func:`messagefoundry.support.bundle.build_bundle` for the assembly.

This is the CLI slice only; an admin-gated ``POST /support/bundle`` is a follow-up. Engine-side and
dependency-light (stdlib only), so it never pulls the API or console into the engine.
"""

from __future__ import annotations

from messagefoundry.support.bundle import BundleResult, build_bundle
from messagefoundry.support.redact import redact_log_line, redact_log_text

__all__ = ["BundleResult", "build_bundle", "redact_log_line", "redact_log_text"]
