# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Print a harness graph's knob refusal, which the engine's config loader would withhold.

The ``load_*shape`` readers run at config import. Their ``ValueError`` names the knob and how to fix
it, but the loader reports only a config module's exception type and line (vault BACKLOG #3249), so
the engine's output says ``ValueError in _shape.py at line N``. Printing the text here puts it in
the engine node's captured output, which the runners show on a failed start (vault BACKLOG #3765
item 3). The text is the harness's own: knob names and the value of a ``MEFOR_*`` load knob."""

from __future__ import annotations

import sys
from collections.abc import Callable
from functools import wraps


def prints_its_refusal[R](read_shape: Callable[[], R]) -> Callable[[], R]:
    """Wrap ``read_shape`` so a ``ValueError`` it raises is printed to stderr, then raised as is."""

    @wraps(read_shape)
    def reading() -> R:
        try:
            return read_shape()
        except ValueError as exc:
            print(f"harness shape refused: {exc}", file=sys.stderr, flush=True)
            raise

    return reading
