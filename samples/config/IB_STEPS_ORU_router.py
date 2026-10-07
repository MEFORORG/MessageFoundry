# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""IB_STEPS_ORU — Router for the typed-Steps worked example (ADR 0076, ADR 0106).

This feed is written ONLY in the typed action vocabulary, so the Steps view shows every line of it as
an editable row and none as a locked ``code`` row. It is the demo an analyst edits in the planned
desktop editor (ADR 0208). The feed is split by role, like IB_DEMO_ORU:

    connections.toml            IB_STEPS_ORU / OB_STEPS_ORU_EMR / OB_STEPS_ORU_ARCHIVE
    IB_STEPS_ORU_router.py      @router  — this file
    IB_STEPS_ORU_handler.py     @handler — field mapping, code lookup, If, For Each, fan-out

``tests/test_samples_typed_steps.py`` pins that neither file projects a ``code`` row.
"""

from messagefoundry import router


@router("steps_oru_router")
def route_steps_oru(msg):
    # Results go to the typed handler. Anything else is logged UNROUTED, never dropped.
    if msg.field("MSH-9.1") == "ORU":
        return ["steps_oru_handler"]
    return []
