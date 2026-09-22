# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Coverage-guided fuzzing of the tolerant parsers (ADR 0191).

Not part of the distributed wheel: ``[tool.hatch.build]`` ships ``messagefoundry`` only, so this
package exists for the repository and its CI alone. ``targets.py`` holds the Atheris-free target
registry; ``fuzz_parsers.py`` is the Atheris entrypoint. See ``fuzz/README.md``.
"""

from __future__ import annotations
