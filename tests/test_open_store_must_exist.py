# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``open_store`` refuses to create an absent SQLite store unless its caller provisions (BACKLOG #1780).

SQLite's own connect creates an absent file, and ``open_store`` then ensures the schema and runs the
migrations. So before this change a caller that meant *report on this store* got *create this store*:
a support bundle collected against a mistyped path built a 372 KB store and reported it healthy.

Every test here asserts the store file does NOT exist after the call, on each entry point that must
not create one, plus the two positive controls that must: ``create=True`` itself, and ``serve``'s
first run. Each test reads the outcome off the filesystem first and the exception type second, so on
the unfixed seam it fails on the file it created rather than on a missing name.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from messagefoundry.__main__ import main
from messagefoundry.api.app import create_managed_app
from messagefoundry.config.settings import ServiceSettings
from messagefoundry.store import base as store_base
from messagefoundry.store.base import open_store, sqlite_settings
from messagefoundry.support.bundle import build_bundle, status_snapshot


async def _open_then_close(target: Path, **kwargs: object) -> BaseException | None:
    """Open ``target`` through the seam and close it; return what the open raised, if anything."""
    try:
        store = await open_store(sqlite_settings(target), **kwargs)  # type: ignore[arg-type]
    except Exception as exc:  # the outcome under test, returned so the file check runs first
        return exc
    await store.close()
    return None


def _created(directory: Path) -> list[str]:
    """Every file under ``directory`` -- the store, and any ``-wal``/``-shm`` sibling it left."""
    return sorted(p.name for p in directory.iterdir())


# --- the seam ----------------------------------------------------------------------------------------


async def test_open_store_refuses_an_absent_sqlite_store_by_default(tmp_path: Path) -> None:
    target = tmp_path / "mistyped-store.db"

    raised = await _open_then_close(target)

    assert _created(tmp_path) == [], "open_store created the store it was only asked to open"
    assert isinstance(raised, store_base.StoreNotFoundError)
    assert raised.path == target
    # The operator reading this needs the path they configured, not a traceback into SQLite.
    assert str(target) in str(raised)


async def test_open_store_create_true_provisions_an_absent_store(tmp_path: Path) -> None:
    """Positive control: the refusal is the default, not a lost ability to create."""
    target = tmp_path / "first-run.db"

    raised = await _open_then_close(target, create=True)

    assert raised is None
    assert target.is_file()


async def test_open_store_default_still_opens_an_existing_store(tmp_path: Path) -> None:
    target = tmp_path / "existing.db"
    assert await _open_then_close(target, create=True) is None

    assert await _open_then_close(target) is None


async def test_open_store_memory_store_is_not_refused() -> None:
    """``:memory:`` puts nothing on disk, so there is no absent file for the default to protect."""
    store = await open_store(sqlite_settings(":memory:"))
    await store.close()


# --- the support bundle ------------------------------------------------------------------------------


def test_status_snapshot_reports_an_absent_store_without_creating_it(tmp_path: Path) -> None:
    target = tmp_path / "mistyped-store.db"

    snap = status_snapshot(ServiceSettings(store=sqlite_settings(target)))

    assert _created(tmp_path) == [], "the support bundle created the store it was reporting on"
    assert snap["db"] is None
    # A fixed code plus the exception type, never the path or the message (BACKLOG #1571).
    assert snap["db_error"] == "MF-BUNDLE-DB-001 StoreNotFoundError"


def test_build_bundle_reports_an_absent_store_without_creating_it(tmp_path: Path) -> None:
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    out = tmp_path / "bundle.zip"

    build_bundle(out, settings=ServiceSettings(store=sqlite_settings(store_dir / "typo.db")))

    assert _created(store_dir) == []
    assert out.is_file()


# --- a CLI subcommand that had no guard of its own ---------------------------------------------------


def test_backup_cli_refuses_an_absent_store(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    target = store_dir / "mistyped-store.db"
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text("[store]\n", encoding="utf-8")

    rc = main(
        [
            "backup",
            "--service-config",
            str(toml),
            "--db",
            str(target),
            "--destination",
            str(tmp_path / "backups"),
            "--json",
        ]
    )

    assert _created(store_dir) == [], "backup created the store it was asked to back up"
    assert rc == 2  # could not start, not a failed backup
    assert "no SQLite store" in capsys.readouterr().out


# --- the caller that must create ---------------------------------------------------------------------


def test_serve_first_run_still_creates_the_store(tmp_path: Path) -> None:
    """``serve``'s lifespan is the ordinary first run, so it opens with ``create=True``."""
    target = tmp_path / "first-run.db"
    app = create_managed_app(db_path=target, poll_interval=0.05)

    with TestClient(app):
        assert target.is_file()
