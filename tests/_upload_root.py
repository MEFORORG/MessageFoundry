# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What an uploads root holds, for the tests that check it is empty or holds only a given pair."""

from __future__ import annotations

from pathlib import Path

from messagefoundry.config.atomic_edit import LOCK_FILE_NAME


def upload_entries(root: Path) -> list[Path]:
    """The entries of ``root``, less the pair lock file every removal leaves there (BACKLOG #3181
    item 5). It holds no data, and nothing removes it."""
    return [p for p in root.iterdir() if p.name != LOCK_FILE_NAME]


def upload_names(root: Path) -> list[str]:
    """:func:`upload_entries`, as sorted names."""
    return sorted(p.name for p in upload_entries(root))
