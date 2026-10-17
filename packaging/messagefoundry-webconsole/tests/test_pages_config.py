# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The /ui config page's provenance badge (ADR 0041 D1, item C).

The rendering half of the provenance feature: pure, sync ``config_page(ConfigProvenance)`` markup
tests. They moved here with the /ui suite (Option B Phase 2, ADR 0065); the engine keeps the
JSON-API ``GET /config/provenance`` tests in ``tests/test_config_provenance.py``.
"""

from __future__ import annotations

from messagefoundry.api.models import RELOAD_REFUSED_CHANNEL_SCOPED, ConfigProvenance
from messagefoundry_webconsole.pages.config import config_page


def test_config_page_badge_clean() -> None:
    html = config_page(
        ConfigProvenance(
            loaded=True,
            fingerprint="a" * 64,
            git_head="b" * 40,
            files=3,
            drift=False,
            reload_refused=None,
        )
    )
    assert "Running config:" in html
    assert "commit bbbbbbb" in html  # 7-char abbreviated commit
    assert ">clean<" in html
    assert "status-running" in html
    assert "DRIFTED" not in html


def test_config_page_badge_drifted() -> None:
    html = config_page(
        ConfigProvenance(
            loaded=True,
            fingerprint="a" * 64,
            git_head="c" * 40,
            files=3,
            drift=True,
            reload_refused=None,
        )
    )
    assert ">DRIFTED<" in html
    assert "status-error" in html
    assert ">clean<" not in html


def test_config_page_badge_without_git_uses_fingerprint() -> None:
    # No .git on the engine host (common) -> fall back to the content-fingerprint identity.
    html = config_page(
        ConfigProvenance(
            loaded=True,
            fingerprint="d" * 64,
            git_head=None,
            files=2,
            drift=False,
            reload_refused=None,
        )
    )
    assert "fingerprint dddddddddddd" in html  # 12-char abbreviated fingerprint
    assert "commit" not in html


def test_config_page_no_badge_when_not_loaded() -> None:
    # Backward-compatible: no provenance (older/embedding path) renders the page unchanged.
    assert "Running config:" not in config_page(None)
    assert "Running config:" not in config_page(ConfigProvenance(loaded=False, reload_refused=None))
    assert "Reload configuration" in config_page(None)  # the page still renders its action


def test_config_page_offers_no_reload_the_engine_will_refuse() -> None:
    """BACKLOG #3189: the engine refuses a channel-scoped caller's reload after the step-up is
    spent, so the page states the engine's reason instead of offering the form. The control: with
    no refusal the form is offered."""
    refused = str(
        config_page(ConfigProvenance(loaded=False, reload_refused=RELOAD_REFUSED_CHANNEL_SCOPED))
    )
    assert 'action="/ui/config/reload"' not in refused
    assert RELOAD_REFUSED_CHANNEL_SCOPED in refused
    offered = str(config_page(ConfigProvenance(loaded=False, reload_refused=None)))
    assert 'action="/ui/config/reload"' in offered
    assert RELOAD_REFUSED_CHANNEL_SCOPED not in offered


def test_a_refused_caller_is_told_what_a_reload_needs_and_not_to_reload() -> None:
    """BACKLOG #3189: the banner names both halves a reload needs, so it never reads as "widen my
    scope and it will work" for a caller who also lacks config:deploy. A drifted badge beside it
    does not say "reload to apply". The control: with no refusal the badge still says it."""

    def _drifted(refused: str | None) -> str:
        return str(
            config_page(
                ConfigProvenance(
                    loaded=True,
                    fingerprint="a" * 64,
                    git_head="c" * 40,
                    files=3,
                    drift=True,
                    reload_refused=refused,
                )
            )
        )

    refused = _drifted(RELOAD_REFUSED_CHANNEL_SCOPED)
    assert "config:deploy" in refused and "all-channels scope" in refused
    assert "reload to apply" not in refused
    assert "reload to apply" in _drifted(None)
