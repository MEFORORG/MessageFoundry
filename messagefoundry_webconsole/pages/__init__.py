# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""HTML page/fragment builders for the /ui ops dashboard (ADR 0065), split by console area.

Every builder returns :class:`.._html.Markup`; every dynamic value is placed through the escaping
element builders in :mod:`.._html`, so attacker-influenced HL7/message content cannot inject markup.
No page emits inline script or ``on*`` handlers (CSP ``script-src 'self'``).

**Per-area package (ADR 0065 §multi-session-build).** Builders live in per-area modules so file
ownership matches lane ownership — a lane adds a page as a ``def`` + its name in that module's own
``__all__`` (a lane-private edit), with **no** shared central list to collide on. Callers keep using
``webui.pages.<fn>``; this ``__init__`` re-exports each module's public builders and is edited **only**
when a lane adds a wholly new area module.
"""

from __future__ import annotations

from .account import *  # noqa: F401,F403
from .admin import *  # noqa: F401,F403
from .audit import *  # noqa: F401,F403
from .config import *  # noqa: F401,F403
from .connections import *  # noqa: F401,F403
from .messages import *  # noqa: F401,F403
from .monitoring import *  # noqa: F401,F403
