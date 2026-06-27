# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SEC-020 — the one-time bootstrap-admin password file is owner-only from the instant it exists.

``_emit_bootstrap_admin`` must create ``bootstrap-admin.txt`` via an exclusive 0o600 ``os.open`` so a
co-located local user can never read the standing admin credential in a create-then-chmod window
(POSIX TOCTOU), and ``O_EXCL`` must refuse to follow a pre-planted symlink/file at that path."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from messagefoundry.api.app import _emit_bootstrap_admin
from messagefoundry.auth.service import BootstrapAdmin
from messagefoundry.store import sqlite_settings


def _settings(tmp_path: Path) -> object:
    # path → tmp_path/db.sqlite; the secret lands beside it as bootstrap-admin.txt
    return sqlite_settings(tmp_path / "db.sqlite")


def _secret_path(tmp_path: Path) -> Path:
    return (tmp_path / "db.sqlite").resolve().parent / "bootstrap-admin.txt"


def test_creates_file_with_expected_content(tmp_path: Path) -> None:
    boot = BootstrapAdmin(username="admin", password="s3cr3t-one-time")
    _emit_bootstrap_admin(boot, _settings(tmp_path))  # type: ignore[arg-type]
    secret = _secret_path(tmp_path)
    assert secret.is_file()
    text = secret.read_text(encoding="utf-8")
    assert "username: admin" in text
    assert "password: s3cr3t-one-time" in text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX chmod semantics (Windows uses an ACL)")
def test_file_is_owner_only_0600(tmp_path: Path) -> None:
    boot = BootstrapAdmin(username="admin", password="s3cr3t")
    _emit_bootstrap_admin(boot, _settings(tmp_path))  # type: ignore[arg-type]
    mode = os.stat(_secret_path(tmp_path)).st_mode & 0o777
    assert mode == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only TOCTOU regression")
def test_does_not_leave_world_readable_or_follow_planted_file(tmp_path: Path) -> None:
    # Pre-plant a world-readable file at the target path: the O_EXCL create must NOT inherit its
    # permissions nor leave a 0o644 file — the secret only ever lands in a fresh 0o600 file we own.
    secret = _secret_path(tmp_path)
    secret.write_text("attacker-seeded\n", encoding="utf-8")
    os.chmod(secret, 0o644)
    boot = BootstrapAdmin(username="admin", password="s3cr3t")
    _emit_bootstrap_admin(boot, _settings(tmp_path))  # type: ignore[arg-type]
    mode = os.stat(secret).st_mode & 0o777
    assert mode == 0o600
    assert "attacker-seeded" not in secret.read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
def test_refuses_to_follow_planted_symlink(tmp_path: Path) -> None:
    # A pre-planted symlink to a victim file: O_EXCL must refuse to follow it, so the victim is never
    # overwritten with the secret and the secret never lands in an attacker-controlled location.
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched\n", encoding="utf-8")
    secret = _secret_path(tmp_path)
    secret.symlink_to(victim)
    boot = BootstrapAdmin(username="admin", password="s3cr3t")
    _emit_bootstrap_admin(boot, _settings(tmp_path))  # type: ignore[arg-type]
    # the symlink target was NOT overwritten with the credential
    assert victim.read_text(encoding="utf-8") == "untouched\n"
    # and the real secret file is a regular 0o600 file we created (not a symlink)
    assert not secret.is_symlink()
    assert os.stat(secret).st_mode & 0o777 == 0o600
