# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The /ui config page's provenance badge (ADR 0041 D1, item C).

The rendering half of the provenance feature: pure, sync ``config_page(ConfigProvenance)`` markup
tests. They moved here with the /ui suite (Option B Phase 2, ADR 0065); the engine keeps the
JSON-API ``GET /config/provenance`` tests in ``tests/test_config_provenance.py``.
"""

from __future__ import annotations

from messagefoundry.api.models import ConfigProvenance
from messagefoundry_webconsole.pages.config import config_page


def test_config_page_badge_clean() -> None:
    html = config_page(
        ConfigProvenance(loaded=True, fingerprint="a" * 64, git_head="b" * 40, files=3, drift=False)
    )
    assert "Running config:" in html
    assert "commit bbbbbbb" in html  # 7-char abbreviated commit
    assert ">clean<" in html
    assert "status-running" in html
    assert "DRIFTED" not in html


def test_config_page_badge_drifted() -> None:
    html = config_page(
        ConfigProvenance(loaded=True, fingerprint="a" * 64, git_head="c" * 40, files=3, drift=True)
    )
    assert ">DRIFTED<" in html
    assert "status-error" in html
    assert ">clean<" not in html


def test_config_page_badge_without_git_uses_fingerprint() -> None:
    # No .git on the engine host (common) -> fall back to the content-fingerprint identity.
    html = config_page(
        ConfigProvenance(loaded=True, fingerprint="d" * 64, git_head=None, files=2, drift=False)
    )
    assert "fingerprint dddddddddddd" in html  # 12-char abbreviated fingerprint
    assert "commit" not in html


def test_config_page_no_badge_when_not_loaded() -> None:
    # Backward-compatible: no provenance (older/embedding path) renders the page unchanged.
    assert "Running config:" not in config_page(None)
    assert "Running config:" not in config_page(ConfigProvenance(loaded=False))
    assert "Reload configuration" in config_page(None)  # the page still renders its action
