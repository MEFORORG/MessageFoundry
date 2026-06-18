# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Side-effect import that registers every built-in message type with the generator registry.

Import this before reading ``_core.message_codes()`` (the harness GUI does). Each generator
module registers itself on import; list new types here as they're built.
"""

from __future__ import annotations

# Each import runs the module's _core.register(...) side effect.
from messagefoundry.generators import adt  # noqa: F401
from messagefoundry.generators import bar  # noqa: F401
from messagefoundry.generators import dft  # noqa: F401
from messagefoundry.generators import mdm  # noqa: F401
from messagefoundry.generators import mfn  # noqa: F401
from messagefoundry.generators import oml  # noqa: F401
from messagefoundry.generators import orl  # noqa: F401
from messagefoundry.generators import orm  # noqa: F401
from messagefoundry.generators import oru  # noqa: F401
from messagefoundry.generators import ras  # noqa: F401
from messagefoundry.generators import rde  # noqa: F401
from messagefoundry.generators import siu  # noqa: F401
from messagefoundry.generators import vxu  # noqa: F401
