# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``run_restore`` resolves its keyring under the caller's hop posture, as ``run_restore_verify``
does, rather than always under none. Synthetic settings only; the keyring and the restore itself are
stubbed, so no store or archive is read."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.pipeline import dr_backup


def test_run_restore_passes_the_callers_posture_to_the_key_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    posture: Any = object()

    def _keys(_settings: object, *, posture: object = None) -> list[str]:
        seen["posture"] = posture
        return []

    def _restore(**kwargs: object) -> str:
        seen["keys"] = kwargs["keys"]
        return "restored"

    monkeypatch.setattr(dr_backup, "resolve_decrypt_keys", _keys)
    monkeypatch.setattr(dr_backup, "_restore_blocking", _restore)
    result: object = asyncio.run(
        dr_backup.run_restore(
            str(tmp_path / "a.mfbak"),
            dest_store_path=tmp_path / "store.db",
            store_settings=object(),
            posture=posture,
        )
    )
    assert result == "restored"
    assert seen == {"posture": posture, "keys": []}
