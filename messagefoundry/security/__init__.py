# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Security assets shipped in the wheel (ADR 0144 Increment 3).

Currently the opt-in Semgrep taint rules for operator-authored Router/Handler config. Semgrep is
**not** a MessageFoundry dependency and does not run inside ``messagefoundry check`` — it is an opt-in
CI leg an operator wires over their own config repo. See
``docs/security/SECURING-HANDLER-CONFIG-IN-CI.md``.
"""

from __future__ import annotations

from importlib.resources import files
from importlib.resources.abc import Traversable


def handler_semgrep_rules() -> Traversable:
    """The packaged Semgrep taint-rules file for operator Router/Handler config (ADR 0144 Inc 3).

    Resolves the copy that ships with the installed engine wheel, so an operator's CI references the
    rules pinned to their engine version::

        RULES=$(python -c "from messagefoundry.security import handler_semgrep_rules as h; print(h())")
        semgrep --config "$RULES" --error config
    """
    return files("messagefoundry.security") / "semgrep" / "handler-security.yml"
