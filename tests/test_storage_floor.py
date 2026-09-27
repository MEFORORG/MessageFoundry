# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The low-disk storage floor, ``[retention].min_free_disk_mb`` (BACKLOG #290, slice 1).

Default-on for SQLite at 1024 MiB free (owner ruling 2026-09-27). ``serve`` refuses to start below
it, and the retention pass warns while free space stays below it. Server backends skip it.

Every test fakes ``shutil.disk_usage``. None of them fills or measures a real disk, so the result
does not depend on how much space the machine running the suite has.
"""

from __future__ import annotations

import logging
import shutil
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import NamedTuple

import pytest
from pydantic import ValidationError

from messagefoundry.__main__ import main
from messagefoundry.config.settings import RetentionSettings, StoreBackend
from messagefoundry.pipeline import retention as retention_mod
from messagefoundry.pipeline.retention import RetentionRunner, read_disk_floor
from messagefoundry.store import MessageStore

SAMPLES_CONFIG = Path(__file__).resolve().parent.parent / "samples" / "config"
MIB = 1 << 20


class _Usage(NamedTuple):
    total: int
    used: int
    free: int


def _fake_disk(free_mib: int, calls: list[str] | None = None) -> Callable[[object], _Usage]:
    def disk_usage(path: object) -> _Usage:
        if calls is not None:
            calls.append(str(path))
        return _Usage(total=1 << 40, used=(1 << 40) - free_mib * MIB, free=free_mib * MIB)

    return disk_usage


# --- the setting --------------------------------------------------------------------------------


def test_the_floor_ships_on_at_1024_mib() -> None:
    assert RetentionSettings().min_free_disk_mb == 1024


def test_a_negative_floor_is_refused_at_load() -> None:
    with pytest.raises(ValidationError):
        RetentionSettings(min_free_disk_mb=-1)


def test_the_floor_does_not_change_max_db_mb() -> None:
    assert RetentionSettings().max_db_mb == 0


# --- read_disk_floor ----------------------------------------------------------------------------


def test_read_disk_floor_is_none_when_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[str] = []
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(1, calls))
    assert read_disk_floor(str(tmp_path / "s.db"), 0) is None
    assert calls == []  # off means no probe at all


def test_read_disk_floor_below_and_above(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(1023))
    low = read_disk_floor(str(tmp_path / "s.db"), 1024)
    assert low is not None and low.below and low.free_mib == 1023 and low.floor_mib == 1024

    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(1024))
    exact = read_disk_floor(str(tmp_path / "s.db"), 1024)
    assert exact is not None and not exact.below  # AT the floor is not below it


def test_read_disk_floor_walks_up_to_an_existing_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The store's directory need not exist yet: the nearest existing ancestor is measured, because
    a directory created later lands on that ancestor's volume."""
    calls: list[str] = []
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(5000, calls))
    reading = read_disk_floor(str(tmp_path / "not" / "yet" / "made" / "s.db"), 1024)
    assert reading is not None and reading.free_bytes == 5000 * MIB
    assert calls == [str(tmp_path.resolve())]
    assert reading.probed == str(tmp_path.resolve())


def test_a_failed_probe_is_not_a_low_disk(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def broken(path: object) -> _Usage:
        raise OSError("device not ready")

    monkeypatch.setattr(shutil, "disk_usage", broken)
    reading = read_disk_floor(str(tmp_path / "s.db"), 1024)
    assert reading is not None
    assert reading.free_bytes is None
    assert reading.below is False


# --- the serve gate -----------------------------------------------------------------------------


def _write_quiet_config(tmp_path: Path, extra: str = "") -> None:
    """The loopback fixture from tests/test_api_tls.py that reaches a clean exit 0 with nothing on
    stderr, so any line the floor adds is visible. The key is configured by env in the caller."""
    (tmp_path / "messagefoundry.toml").write_text(
        "security.block_unlisted_outbound = true\n"
        'alerts.email_smtp_host = "smtp.example.org"\n'
        'alerts.email_from = "sec@example.org"\n'
        'alerts.email_to = ["ops@example.org"]\n'
        "security.delete_message_bodies_after_days = 30\n"
        "retention.dead_letter_days = 30\n"
        "retention.reference_snapshot_days = 30\n"
        "retention.state_max_age_days = 30\n"
        "retention.search_preset_days = 30\n"
        "security.local_access_only = true\n" + extra,
        encoding="utf-8",
    )


@pytest.fixture
def serve_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return tmp_path


def _serve() -> int:
    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"])


def test_serve_refuses_below_the_floor(
    serve_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_quiet_config(serve_env)
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(512))
    assert _serve() == 2
    err = capsys.readouterr().err
    assert "[retention].min_free_disk_mb" in err  # names the setting the operator can act on
    assert "512 MiB" in err and "1024 MiB" in err
    assert "refusing to start" in err


def test_serve_starts_above_the_floor_and_says_nothing(
    serve_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_quiet_config(serve_env)
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(4096))
    assert _serve() == 0
    assert capsys.readouterr().err == ""


def test_floor_zero_turns_the_serve_gate_off(
    serve_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_quiet_config(serve_env, "retention.min_free_disk_mb = 0\n")
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(1))
    assert _serve() == 0
    assert "min_free_disk_mb" not in capsys.readouterr().err


def test_a_lowered_floor_admits_a_start_the_default_refuses(
    serve_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_quiet_config(serve_env, "retention.min_free_disk_mb = 256\n")
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(512))
    assert _serve() == 0


def test_serve_warns_and_starts_when_the_disk_cannot_be_measured(
    serve_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_quiet_config(serve_env)

    def broken(path: object) -> _Usage:
        raise OSError("device not ready")

    monkeypatch.setattr(shutil, "disk_usage", broken)
    assert _serve() == 0
    err = capsys.readouterr().err
    assert "warning:" in err and "min_free_disk_mb" in err and "not checked" in err


def test_serve_skips_the_floor_on_a_server_backend(
    serve_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """SQL Server and Postgres are out of the floor's scope by the owner's ruling. A server store
    logs one INFO line naming the setting and never probes the disk, whatever it would read."""
    _write_quiet_config(
        serve_env,
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n',
    )
    calls: list[str] = []
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(1, calls))
    assert _serve() == 0  # a 1 MiB disk would refuse a SQLite start
    captured = capsys.readouterr()
    # serve's own logging handler writes to stdout (NSSM captures it), so the INFO line lands there.
    skipped = [ln for ln in captured.out.splitlines() if "min_free_disk_mb" in ln]
    assert len(skipped) == 1
    assert "INFO" in skipped[0] and StoreBackend.POSTGRES.value in skipped[0]
    assert "min_free_disk_mb" not in captured.err  # neither refused nor warned
    assert calls == []


# --- the runtime warning ------------------------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "floor.db")
    yield s
    await s.close()


async def test_the_retention_pass_warns_below_the_floor(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(100))
    runner = RetentionRunner(store, RetentionSettings(), clock=lambda: 1000.0)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await runner.run_once()
    assert result.below_disk_floor is True
    warned = [r for r in caplog.records if "min_free_disk_mb" in r.getMessage()]
    assert len(warned) == 1 and warned[0].levelno == logging.WARNING
    assert "100 MiB" in warned[0].getMessage()
    # A warning changes nothing in the store, so it writes no audit row.
    assert result.did_work is False
    assert [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"] == []


async def test_the_retention_pass_is_quiet_above_the_floor(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(4096))
    runner = RetentionRunner(store, RetentionSettings(), clock=lambda: 1000.0)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await runner.run_once()
    assert result.below_disk_floor is False
    assert not [r for r in caplog.records if "min_free_disk_mb" in r.getMessage()]


async def test_floor_zero_turns_the_runtime_check_off(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(1, calls))
    runner = RetentionRunner(store, RetentionSettings(min_free_disk_mb=0), clock=lambda: 1000.0)
    result = await runner.run_once()
    assert result.below_disk_floor is False
    assert calls == []


async def test_the_runtime_check_skips_a_server_backend(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A store reporting a server backend is never probed, and the floor alone does not start the
    runner there."""
    calls: list[str] = []
    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(1, calls))
    monkeypatch.setattr(store, "backend", StoreBackend.SQLSERVER)
    runner = RetentionRunner(store, RetentionSettings(), clock=lambda: 1000.0)
    assert runner.enabled is False
    result = await runner.run_once()
    assert result.below_disk_floor is False
    assert calls == []


async def test_a_probe_that_raises_never_stops_the_purges(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The floor check runs before every purge in the pass. If it raised, every pass would fail the
    same way and no PHI body would ever be purged, so any error is logged and the pass goes on."""

    def boom(*args: object) -> None:
        raise RuntimeError("probe blew up")

    monkeypatch.setattr(retention_mod, "read_disk_floor", boom)
    purged: list[float] = []

    async def fake_purge(*, older_than: float, **kw: object) -> int:
        purged.append(older_than)
        return 0

    monkeypatch.setattr(store, "purge_message_bodies", fake_purge)
    runner = RetentionRunner(store, RetentionSettings(messages_days=1), clock=lambda: 1000.0)
    result = await runner.run_once()
    assert result.below_disk_floor is False
    assert len(purged) == 1  # the purge still ran


async def test_an_in_memory_store_has_no_disk_to_floor() -> None:
    mem = await MessageStore.open(":memory:")
    try:
        assert RetentionRunner(mem, RetentionSettings()).enabled is False
    finally:
        await mem.close()


async def test_the_floor_warns_even_when_this_node_is_not_the_leader(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check measures this host's own volume and is read-only, so it runs before the leader
    gate rather than being skipped with the purges."""

    class _Follower:
        def is_leader(self) -> bool:
            return False

    monkeypatch.setattr(shutil, "disk_usage", _fake_disk(1))
    runner = RetentionRunner(
        store,
        RetentionSettings(),
        clock=lambda: 1000.0,
        coordinator=_Follower(),  # type: ignore[arg-type]
    )
    result = await runner.run_once()
    assert result.below_disk_floor is True
