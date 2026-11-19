# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The damaged-file notices take rotate-key's stance on a refused sidecar (BACKLOG #5387).

The engine's 423 does not say which damage it found. For a sidecar larger than a sidecar can be,
not UTF-8, or plaintext too long to seal, ``rotate-key`` says it may hold a value under the prior
key and not to retire that key until the sidecar is fixed or deliberately removed. So no damaged
notice may say only that the file may be deleted. Synthetic data only."""

from __future__ import annotations

import pytest

from messagefoundry_webconsole.routes import uploaded_logs as ul

_DAMAGED = (ul.BROWSE_DAMAGED_NOTICE, ul.RESEND_DAMAGED_NOTICE, ul.DELETE_DAMAGED_NOTICE)


@pytest.mark.parametrize("notice", _DAMAGED)
def test_every_damaged_notice_keeps_the_prior_key_until_the_sidecar_is_settled(notice: str) -> None:
    assert "larger than the engine reads" in notice
    assert "plaintext too long to seal" in notice
    assert "may still hold a value under a prior store encryption key" in notice
    assert (
        "An administrator should not retire a prior key until each such file is fixed, for "
        "example by restoring it from a backup, or is deliberately removed."
    ) in notice
    # The notices still name no command, as before.
    assert "rotate-key" not in notice


@pytest.mark.parametrize("notice", _DAMAGED[:2])
def test_the_delete_invitation_follows_the_prior_key_stance(notice: str) -> None:
    assert notice.index("retire a prior key") < notice.index("It may be deleted")
