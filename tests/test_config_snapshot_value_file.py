# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The value file a start reads is in the config snapshot wherever it sits (vault BACKLOG #2596).

In the default layout the value file, ``<base_dir>/environments/<env>.toml``, sits outside the
config directory, so the snapshot a load runs did not hold it and the digest an approval binds did
not cover it: an edit to it between a dual-control request and its release applied under an
unchanged digest. These tests fail on the code before the change. The value file is now read into
the snapshot by its resolved path, folded into the digest, and parsed by ``serve``'s provider from
those bytes.

Synthetic values only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.config.fingerprint import config_fingerprint, config_fingerprint_detail
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.snapshot import (
    ConfigSnapshot,
    read_config_snapshot,
    with_value_file,
)
from messagefoundry.config.wiring import WiringError, load_config
from messagefoundry.pipeline import _sandbox_codec as codec
from messagefoundry.pipeline.engine import Engine
from tests.test_dual_control_reload import (
    _digest_mismatch_rows,
    _held_params,
    _hold_then_release,
    _service,
    _write_valid_config,
)

_APPROVED = 'HOST = "approved.example.invalid"\n'
_UNREVIEWED = 'HOST = "unreviewed.example.invalid"\n'


def _layout(tmp_path: Path, text: str | None = _APPROVED) -> tuple[Path, Path]:
    """The default layout: a config directory and, beside it under the project root, the value
    file ``environments/dev.toml``, holding ``text`` or absent when it is ``None``."""
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    value_file = tmp_path / "environments" / "dev.toml"
    value_file.parent.mkdir()
    if text is not None:
        value_file.write_bytes(text.encode())
    return cfg, value_file


# --- the snapshot and the digest -----------------------------------------------------------------


def test_an_edit_to_a_value_file_outside_the_config_directory_changes_the_digest(
    tmp_path: Path,
) -> None:
    cfg, value_file = _layout(tmp_path)
    before = config_fingerprint(cfg, strict=True, value_file=value_file)
    value_file.write_text(_UNREVIEWED, encoding="utf-8")
    assert config_fingerprint(cfg, strict=True, value_file=value_file) != before


def test_creating_the_value_file_changes_the_digest(tmp_path: Path) -> None:
    cfg, value_file = _layout(tmp_path, None)
    before = config_fingerprint(cfg, strict=True, value_file=value_file)
    value_file.write_text("", encoding="utf-8")
    assert config_fingerprint(cfg, strict=True, value_file=value_file) != before


def test_the_digest_names_the_value_file_by_name_not_by_where_it_sits(tmp_path: Path) -> None:
    one_cfg, one_values = _layout(tmp_path / "one")
    other_cfg, other_values = _layout(tmp_path / "other")
    # Byte-identical bundles, apart from the paths the config module names.
    (other_cfg / "cfg.py").write_bytes((one_cfg / "cfg.py").read_bytes())
    assert config_fingerprint(one_cfg, value_file=one_values) == config_fingerprint(
        other_cfg, value_file=other_values
    )


def test_the_snapshot_holds_the_bytes_it_read_and_answers_them_after_an_edit(
    tmp_path: Path,
) -> None:
    cfg, value_file = _layout(tmp_path)
    snapshot = with_value_file(read_config_snapshot(cfg, strict=True), value_file, strict=True)
    value_file.write_text(_UNREVIEWED, encoding="utf-8")
    assert snapshot.value_file == value_file.absolute()
    assert snapshot.covers_environment_file(value_file)
    assert snapshot.environment_file(value_file) == _APPROVED.encode()
    # Another file in the same folder is not covered.
    assert not snapshot.covers_environment_file(value_file.with_name("prod.toml"))


def test_a_folder_named_like_the_value_file_is_no_value_file_as_a_start_judges_it(
    tmp_path: Path,
) -> None:
    cfg, value_file = _layout(tmp_path, None)
    value_file.mkdir()
    snapshot = with_value_file(read_config_snapshot(cfg, strict=True), value_file, strict=True)
    assert snapshot.environment_file(value_file) is None


def test_the_value_file_is_read_by_the_path_an_open_resolves(tmp_path: Path) -> None:
    """A link before ``..`` resolves first, as an open resolves it, so the snapshot reads the file
    a provider of the same path reads, not the one ``..`` names as text."""
    cfg, _ = _layout(tmp_path)
    real = tmp_path / "releases" / "42" / "project"
    real.mkdir(parents=True)
    (real.parent / "environments").mkdir()
    (real.parent / "environments" / "dev.toml").write_bytes(b'HOST = "linked"\n')
    link = tmp_path / "current"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create a directory link")
    via = link / ".." / "environments" / "dev.toml"
    snapshot = with_value_file(read_config_snapshot(cfg, strict=True), via, strict=True)
    # The bytes an open of the same path reads: on POSIX the linked file, while Windows folds
    # ``..`` before it opens, and ``realpath`` there does the same.
    assert snapshot.environment_file(via) == via.read_bytes()


def test_a_value_file_that_is_itself_a_link_is_covered_by_the_path_asked_for(
    tmp_path: Path,
) -> None:
    """A ConfigMap-style layout: the value file links to a file of another name elsewhere. The
    provider asks by the link's path, and the snapshot answers the bytes it read through it."""
    cfg, value_file = _layout(tmp_path, None)
    target = tmp_path / "data" / "shared-values"
    target.parent.mkdir()
    target.write_bytes(_APPROVED.encode())
    try:
        value_file.symlink_to(target)
    except OSError:
        pytest.skip("this account cannot create a file link")
    snapshot = with_value_file(read_config_snapshot(cfg, strict=True), value_file, strict=True)
    assert "@value-file/dev.toml" in snapshot.files
    assert snapshot.covers_environment_file(value_file)
    assert snapshot.environment_file(value_file) == _APPROVED.encode()


def test_a_strict_read_does_not_accept_a_lax_fault_it_is_handed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.config import snapshot as snapshot_module

    cfg, value_file = _layout(tmp_path)
    real_read = snapshot_module._read

    def _read(path: Path) -> bytes:
        if path == value_file.absolute():
            raise PermissionError(13, "denied", str(path))
        return real_read(path)

    monkeypatch.setattr(snapshot_module, "_read", _read)
    lax = with_value_file(read_config_snapshot(cfg, strict=True), value_file, strict=False)
    assert lax.unreadable == ("@value-file/dev.toml",)
    with pytest.raises(PermissionError):
        with_value_file(lax, value_file, strict=True)


def test_a_value_file_in_the_config_directory_is_not_read_twice(tmp_path: Path) -> None:
    cfg, _ = _layout(tmp_path)
    inside = cfg / "environments" / "dev.toml"
    inside.parent.mkdir()
    inside.write_text(_APPROVED, encoding="utf-8")
    snapshot = read_config_snapshot(cfg, strict=True)
    assert with_value_file(snapshot, inside, strict=True) is snapshot


def test_a_snapshot_already_holding_the_value_file_does_not_read_it_again(tmp_path: Path) -> None:
    cfg, value_file = _layout(tmp_path)
    snapshot = with_value_file(read_config_snapshot(cfg, strict=True), value_file, strict=True)
    value_file.write_text(_UNREVIEWED, encoding="utf-8")
    assert with_value_file(snapshot, value_file, strict=True) is snapshot
    detail = config_fingerprint_detail(cfg, snapshot=snapshot, value_file=value_file)
    assert detail["fingerprint"] == config_fingerprint_detail(cfg, snapshot=snapshot)["fingerprint"]


def test_a_value_file_that_cannot_be_read_is_named_or_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.config import snapshot as snapshot_module

    cfg, value_file = _layout(tmp_path)
    real_read = snapshot_module._read

    def _read(path: Path) -> bytes:
        if path.name == value_file.name and path.parent.name == "environments":
            raise PermissionError(13, "denied", str(path))
        return real_read(path)

    monkeypatch.setattr(snapshot_module, "_read", _read)
    base = read_config_snapshot(cfg, strict=True)
    lax = with_value_file(base, value_file, strict=False)
    assert lax.unreadable == ("@value-file/dev.toml",)
    assert lax.unreadable_loaded == ()  # a load still runs: the loader never reads it
    with pytest.raises(OSError):
        lax.environment_file(value_file)
    with pytest.raises(PermissionError):
        with_value_file(base, value_file, strict=True)


def test_a_sandbox_worker_is_not_sent_the_value_file(tmp_path: Path) -> None:
    cfg, value_file = _layout(tmp_path)
    snapshot = with_value_file(read_config_snapshot(cfg, strict=True), value_file, strict=True)
    loaded = snapshot.loaded()
    assert "@value-file/dev.toml" in snapshot.files
    assert not any(rel.startswith("@value-file") for rel in loaded.files)
    assert loaded.value_file is None
    node = codec.enc_snapshot(snapshot, codec._Blobs())
    assert [rel for rel, _ in node["files"]] == list(loaded.files)


def test_a_snapshot_names_no_value_file_path_a_listing_could_return() -> None:
    with pytest.raises(ValueError):
        ConfigSnapshot(directory=Path("cfg"), files={"@value-file/x.py": b""})
    with pytest.raises(ValueError):
        ConfigSnapshot(directory=Path("cfg"), files={"@value-file/a/b.toml": b""})
    assert ConfigSnapshot(directory=Path("cfg"), files={"@value-file/dev.toml": b""}).files


def test_serve_s_provider_parses_the_value_file_from_the_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.__main__ import _environment_values_reader

    monkeypatch.setattr(
        "messagefoundry.config.wiring.assert_trusted_start_paths", lambda *_a, **_k: None
    )
    cfg, value_file = _layout(tmp_path)
    provider = _environment_values_reader(
        base_dir=tmp_path, dir_name="environments", environment="dev"
    )
    assert provider.value_file == value_file
    snapshot = with_value_file(read_config_snapshot(cfg, strict=True), value_file, strict=True)
    value_file.write_text(_UNREVIEWED, encoding="utf-8")
    assert provider.from_snapshot(snapshot) == {"host": "approved.example.invalid"}
    assert provider() == {"host": "unreviewed.example.invalid"}  # the control: a start reads disk


def test_the_reload_snapshot_vets_the_value_file_before_it_reads_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.config import snapshot as snapshot_module

    cfg, value_file = _layout(tmp_path)
    vetted: list[tuple[list[Path], list[Path]]] = []

    def _refuse(files: Any, *, lead: str = "", folders: Any = ()) -> None:
        vetted.append((list(files), list(folders)))
        raise WiringError("refused for the test")

    read: list[Path] = []
    real_read = snapshot_module._read

    def _read(path: Path) -> bytes:
        read.append(path)
        return real_read(path)

    monkeypatch.setattr(snapshot_module, "_read", _read)
    monkeypatch.setattr("messagefoundry.pipeline.engine.assert_trusted_start_paths", _refuse)
    with pytest.raises(WiringError):
        Engine._reload_snapshot_blocking(cfg, value_file)
    assert vetted == [([value_file], [value_file.parent])]
    assert value_file not in read


# --- a dual-control release ------------------------------------------------------------------------


async def _engine(tmp_path: Path, cfg: Path) -> Engine:
    from messagefoundry.__main__ import _environment_values_reader

    return await Engine.create(
        tmp_path / "dc.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
        env_values_provider=_environment_values_reader(
            base_dir=tmp_path, dir_name="environments", environment="dev"
        ),
    )


async def test_a_value_file_edited_before_the_release_is_refused_as_not_approved(
    tmp_path: Path,
) -> None:
    """Before, the digest did not cover this file, so the release went through and applied the
    unreviewed values under the approved digest."""
    cfg, value_file = _layout(tmp_path)
    engine = await _engine(tmp_path, cfg)
    try:
        await engine.reload_detail(dry_run=False)  # a live runner, on the approved values
        runner = engine.registry_runner
        approved_values = {"host": "approved.example.invalid"}
        assert cast(Any, engine)._env_values == approved_values
        service = await _service(engine)
        approval_id, r = await _hold_then_release(
            engine,
            service,
            {},
            between=lambda: value_file.write_text(_UNREVIEWED, encoding="utf-8"),
        )
        assert r.status_code == 422, r.text
        assert engine.registry_runner is runner  # nothing swapped
        assert cast(Any, engine)._env_values == approved_values
        approved = _held_params(await engine.store.get_pending_approval(approval_id))
        rows = await _digest_mismatch_rows(engine)
        assert [row["approved_fingerprint"] for row in rows] == [approved["fingerprint"]]
        assert rows[0]["current_fingerprint"] == config_fingerprint(
            cfg, strict=True, value_file=value_file
        )
    finally:
        await engine.stop()


async def test_a_value_file_edited_after_the_release_read_its_snapshot_never_applies(
    tmp_path: Path,
) -> None:
    """Before, the provider read the file from disk after the check, and the edited values applied
    under the approved digest."""
    cfg, value_file = _layout(tmp_path)
    engine = await _engine(tmp_path, cfg)
    real = Engine._reload_snapshot_blocking

    def _read_then_edit(path: Path, *args: Any) -> ConfigSnapshot | None:
        snapshot = real(path, *args)
        value_file.write_text(_UNREVIEWED, encoding="utf-8")
        return snapshot

    approved_values = {"host": "approved.example.invalid"}
    # Its own patcher, so the control below undoes this patch and nothing else.
    edit = pytest.MonkeyPatch()
    try:
        assert cast(Any, engine)._env_values == approved_values
        service = await _service(engine)
        approval_id, r = await _hold_then_release(
            engine,
            service,
            {},
            between=lambda: edit.setattr(
                Engine, "_reload_snapshot_blocking", staticmethod(_read_then_edit)
            ),
        )
        assert r.status_code == 200, r.text
        assert cast(Any, engine)._env_values == approved_values
        runner = engine.registry_runner
        assert runner is not None and cast(Any, runner)._env_values == approved_values
        approved = _held_params(await engine.store.get_pending_approval(approval_id))
        rows = await engine.store.list_audit(action="config_reload")
        assert [json.loads(row["detail"])["fingerprint"] for row in rows] == [
            approved["fingerprint"]
        ]
        # The control: a reload that reads afresh applies the edited file.
        edit.undo()
        await engine.reload_detail(dry_run=False)
        assert cast(Any, engine)._env_values == {"host": "unreviewed.example.invalid"}
    finally:
        edit.undo()
        await engine.stop()


async def test_the_start_digest_folds_the_value_file_as_a_reload_does(tmp_path: Path) -> None:
    """So a start and an unchanged reload record the same digest, rather than a false change."""
    cfg, value_file = _layout(tmp_path)
    engine = await _engine(tmp_path, cfg)
    try:
        await engine.reload_detail(dry_run=False)
        reloaded = engine.loaded_config_fingerprint
        assert reloaded is not None
        assert reloaded["fingerprint"] == config_fingerprint(cfg, value_file=value_file)
        assert reloaded["fingerprint"] == await engine.reload_target_digest(None)
        # The start's shape: capture_start_provenance digests the start load's snapshot, which
        # holds no value file from outside the config directory, so the digest reads it in.
        start_snapshot = load_config(cfg).config_snapshot
        assert start_snapshot is not None and start_snapshot.value_file is None
        bundle, reason = await engine.fingerprint_bundle(cfg, start_snapshot)
        assert reason is None and bundle is not None
        assert bundle["fingerprint"] == reloaded["fingerprint"]
    finally:
        await engine.stop()
