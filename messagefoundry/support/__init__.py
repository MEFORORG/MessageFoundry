# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Support-bundle assembly (#49).

``messagefoundry support-bundle`` writes a single zip for an operator to hand to support; the
``support-bundle`` CLI help names its members. The rule for the code is that no member it builds
reads a message body from the store.
The app-log tail is the one member that can carry a logged body or a residual secret: it copies what
the app log holds, which on a non-production instance at ``DEBUG`` can be a full message body, and the
redaction can leave a secret in it. So the archive is not PHI-free or secret-free; what it does and does not
hold is stated once, in the manifest's ``phi_contract`` (BACKLOG #5385). See
:mod:`messagefoundry.support.redact` for the log-line scrubber and
:func:`messagefoundry.support.bundle.build_bundle` for the assembly.

This is the CLI slice only; an admin-gated ``POST /support/bundle`` is a follow-up.
"""

from __future__ import annotations

from messagefoundry.support.bundle import BundleResult, build_bundle
from messagefoundry.support.redact import redact_log_line, redact_log_text

__all__ = ["BundleResult", "build_bundle", "redact_log_line", "redact_log_text"]
