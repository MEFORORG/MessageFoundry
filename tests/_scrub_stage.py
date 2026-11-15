# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Switch ``secretscrub.scrub_added_shapes`` (BACKLOG #5546 to #5550) off, or swap it, on every
module that holds it, for a test whose subject is the passes before it or the stage itself.

One helper, not a copy per test file: a module that imports the stage by name binds its own
reference at import, so patching ``secretscrub`` alone leaves that module running the real stage,
and a stage-on against stage-off comparison would then compare the stage with itself. The modules
are found by searching ``sys.modules`` for the real function, so a new importer is covered without
an edit here.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

import pytest

from messagefoundry import secretscrub
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER

#: The real stage, read once at import, before any test patches it.
REAL_STAGE: Callable[..., str] = secretscrub.scrub_added_shapes


def replace_the_added_stage(
    monkeypatch: pytest.MonkeyPatch, replacement: Callable[[str, str], str]
) -> list[str]:
    """Bind ``replacement`` in place of the stage on every ``messagefoundry`` module holding it, the
    real one or the one an earlier patch in the same test bound, and return their names, which always
    include ``messagefoundry.secretscrub``."""
    bound = {id(REAL_STAGE), id(secretscrub.scrub_added_shapes)}
    patched = []
    for name, module in list(sys.modules.items()):
        if (name == "messagefoundry" or name.startswith("messagefoundry.")) and id(
            getattr(module, "scrub_added_shapes", None)
        ) in bound:
            monkeypatch.setattr(module, "scrub_added_shapes", replacement)
            patched.append(name)
    assert "messagefoundry.secretscrub" in patched, f"the stage was not found, only in {patched}"
    return patched


def without_the_added_stage(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every surface as it read before the stage: the passes before it are unchanged, so switching
    the stage off is that code."""

    def identity(text: str, placeholder: str = CREDENTIAL_PLACEHOLDER) -> str:
        return text

    return replace_the_added_stage(monkeypatch, identity)
