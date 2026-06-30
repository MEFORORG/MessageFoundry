# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Backend selector for the tolerant HL7 parse tier (ADR 0054).

The tolerant ``Peek``/``Message`` surface can be backed by either the low-allocation **built-ins**
parser (``_builtin_hl7.py``, the ADR 0054 drop-in) or the legacy **python-hl7** path. This module is
the single switch the two consult so the parity tests can drive the same suite over either backend.

* :data:`USE_BUILTIN` — module-level flag, **default ``True``**. Flip it (directly or via
  :func:`use_builtin`) to run the existing tests against the python-hl7 path for a parity check.
* A **runtime fallback guard** lives in ``peek.py``/``message.py``: each built-ins parse is wrapped so
  an *unexpected* internal error (anything other than the contract's :class:`HL7PeekError`) falls back
  to the python-hl7 path and is logged, never crashing a connection. ``HL7PeekError`` (no-MSH / empty /
  malformed-path) is the contract and is **re-raised**, not fallen back from.

The flag is read **per parse** (not cached), so a test can toggle it between calls.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

#: Use the built-ins parser (ADR 0054) for the tolerant tier. Default on. Set to ``False`` to run the
#: legacy python-hl7 path (parity testing). Read per-parse by ``Peek.parse``/``Message.parse``.
USE_BUILTIN: bool = True


def use_builtin() -> bool:
    """Whether the built-ins parser is selected for the tolerant tier (reads :data:`USE_BUILTIN`)."""
    return USE_BUILTIN


@contextlib.contextmanager
def backend(*, builtin: bool) -> Iterator[None]:
    """Temporarily select a backend within a ``with`` block, restoring the prior value on exit.

    Used by the parity tests to run the same assertions over both backends without leaking the flip
    into sibling tests.
    """
    global USE_BUILTIN
    prior = USE_BUILTIN
    USE_BUILTIN = builtin
    try:
        yield
    finally:
        USE_BUILTIN = prior
