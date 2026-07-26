# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Side-effect import that registers every built-in message type with the generator registry.

Import this before reading ``_core.message_codes()`` (the harness GUI does). Each generator
module registers itself on import; list new types here as they're built.
"""

from __future__ import annotations

# Each import runs the module's _core.register(...) side effect.
from messagefoundry.generators import (
    adt,  # noqa: F401
    bar,  # noqa: F401
    dft,  # noqa: F401
    mdm,  # noqa: F401
    mfn,  # noqa: F401
    oml,  # noqa: F401
    orl,  # noqa: F401
    orm,  # noqa: F401
    oru,  # noqa: F401
    ras,  # noqa: F401
    rde,  # noqa: F401
    siu,  # noqa: F401
    vxu,  # noqa: F401
)
