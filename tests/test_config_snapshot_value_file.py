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

import errno
import json
import os
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


def test_a_snapshot_s_repr_does_not_carry_the_value_file_s_bytes(tmp_path: Path) -> None:
    # A value file can hold credentials, and a repr can reach a log or a traceback.
    cfg, value_file = _layout(tmp_path, 'PASSWORD = "s3cret-value-file-bytes"\n')
    snapshot = with_value_file(read_config_snapshot(cfg, strict=True), value_file, strict=True)
    assert snapshot.environment_file(value_file) is not None  # control: the bytes are held
    assert "s3cret-value-file-bytes" not in repr(snapshot)
    assert "s3cret-value-file-bytes" not in str(snapshot)


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


def test_a_snapshot_holds_one_value_file_by_a_plain_name() -> None:
    where = Path("values/x.py").absolute()
    with pytest.raises(ValueError):
        ConfigSnapshot(directory=Path("cfg"), files={"@value-file/a/b.toml": b""}, value_file=where)
    with pytest.raises(ValueError):
        ConfigSnapshot(directory=Path("cfg"), files={"@value-file/..": b""}, value_file=where)
    held = ConfigSnapshot(directory=Path("cfg"), files={"@value-file/x.py": b""}, value_file=where)
    # Any name, and never a module: a load runs none of it.
    assert held.files and held.modules == () and held.loaded().files == {}


def test_a_snapshot_holds_value_file_bytes_only_with_the_value_file_s_path() -> None:
    """Without the path, no reload could serve those bytes, and a digest would cover them."""
    with pytest.raises(ValueError, match="value_file"):
        ConfigSnapshot(directory=Path("cfg"), files={"@value-file/dev.toml": b""})
    with pytest.raises(ValueError, match="value_file"):
        ConfigSnapshot(directory=Path("cfg"), files={}, unreadable=("@value-file/dev.toml",))


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
    # The control: with the vet passing, the same recorder sees the value file read.
    _vet_nothing(monkeypatch)
    assert Engine._reload_snapshot_blocking(cfg, value_file) is not None
    assert value_file in read


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


# --- review repairs, round 2 ---------------------------------------------------------------------


def _fail_value_file_read(monkeypatch: pytest.MonkeyPatch, value_file: Path) -> None:
    """Make the snapshot's read of ``value_file`` fail as a lost share does, and nothing else."""
    from messagefoundry.config import snapshot as snapshot_module

    real_read = snapshot_module._read

    def _read(path: Path) -> bytes:
        if path == value_file.absolute():
            raise OSError(5, "the share went away", str(path))
        return real_read(path)

    monkeypatch.setattr(snapshot_module, "_read", _read)


def _vet_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "messagefoundry.pipeline.engine.assert_trusted_start_paths", lambda *_a, **_k: None
    )


def test_a_value_file_read_fault_refuses_the_reload_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before, the whole snapshot was dropped and an ungated reload read the values from disk,
    where the same fault can read as no file."""
    cfg, value_file = _layout(tmp_path)
    _vet_nothing(monkeypatch)
    _fail_value_file_read(monkeypatch, value_file)
    with pytest.raises(WiringError, match="dev.toml"):
        Engine._reload_snapshot_blocking(cfg, value_file)


def test_an_absent_value_file_is_no_value_file_not_a_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg, value_file = _layout(tmp_path, None)
    _vet_nothing(monkeypatch)
    snapshot = Engine._reload_snapshot_blocking(cfg, value_file)
    assert snapshot is not None and snapshot.value_file == value_file.absolute()
    assert snapshot.environment_file(value_file) is None


async def test_an_ungated_reload_refuses_a_value_file_it_cannot_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before, the ungated reload read the value file again from disk, so it went through on
    values from a second read the reload row's digest did not name."""
    cfg, value_file = _layout(tmp_path)
    engine = await _engine(tmp_path, cfg)
    try:
        approved_values = {"host": "approved.example.invalid"}
        await engine.reload_detail(dry_run=False)
        runner = engine.registry_runner
        value_file.write_text(_UNREVIEWED, encoding="utf-8")
        _fail_value_file_read(monkeypatch, value_file)
        with pytest.raises(WiringError, match="dev.toml"):
            await engine.reload_detail(dry_run=False)
        assert engine.registry_runner is runner
        assert cast(Any, engine)._env_values == approved_values
    finally:
        await engine.stop()


def test_every_folder_along_a_link_chain_is_vetted_before_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The writer of an intermediate link's folder could re-point that link between the vet and
    the read, so that folder is vetted too, not only the first and the last."""
    cfg, value_file = _layout(tmp_path, None)
    final = tmp_path / "data" / "values.toml"
    middle = tmp_path / "hop" / "middle.toml"
    final.parent.mkdir()
    middle.parent.mkdir()
    final.write_bytes(_APPROVED.encode())
    try:
        middle.symlink_to(final)
        value_file.symlink_to(middle)
    except OSError:
        pytest.skip("this account cannot create a file link")
    vetted: list[str] = []

    def _record(files: Any, *, lead: str = "", folders: Any = ()) -> None:
        vetted.extend(os.path.normcase(os.path.realpath(f)) for f in folders)

    monkeypatch.setattr("messagefoundry.pipeline.engine.assert_trusted_start_paths", _record)
    snapshot = Engine._reload_snapshot_blocking(cfg, value_file)
    assert snapshot is not None and snapshot.environment_file(value_file) == _APPROVED.encode()
    for folder in (value_file.parent, middle.parent, final.parent):
        assert os.path.normcase(os.path.realpath(folder)) in vetted


@pytest.mark.skipif(os.path.normcase("A") == "A", reason="Windows names files without case")
@pytest.mark.parametrize("outside", [True, False])
def test_a_held_value_file_removed_under_another_case_is_gone_not_none(
    tmp_path: Path, outside: bool
) -> None:
    """Before, asking by another case after the file was removed answered ``None``, so a release
    could apply values without the file its approval covered."""
    cfg, held = _layout(tmp_path, None)
    if not outside:
        held = cfg / "environments" / "dev.toml"
        held.parent.mkdir()
    held = held.with_name("DEV.toml")
    held.write_bytes(_APPROVED.encode())
    snapshot = with_value_file(read_config_snapshot(cfg, strict=True), held, strict=True)
    asked = held.with_name("dev.toml")
    assert snapshot.environment_file(asked) == _APPROVED.encode()  # control: held under any case
    held.unlink()
    with pytest.raises(OSError, match="gone"):
        snapshot.environment_file(asked)


def test_a_value_file_of_any_name_is_held(tmp_path: Path) -> None:
    """Before, a provider whose value file was not ``*.toml`` failed every digest."""
    cfg, _ = _layout(tmp_path)
    value_file = tmp_path / "environments" / "dev.json"
    value_file.write_bytes(b"{}")
    before = config_fingerprint(cfg, strict=True, value_file=value_file)
    snapshot = with_value_file(read_config_snapshot(cfg, strict=True), value_file, strict=True)
    assert snapshot.files["@value-file/dev.json"] == b"{}"
    value_file.write_bytes(b'{"a": 1}')
    assert config_fingerprint(cfg, strict=True, value_file=value_file) != before


def test_a_path_no_file_can_be_opened_by_is_no_value_file_to_a_start_or_a_snapshot(
    tmp_path: Path,
) -> None:
    """A folder in the path that is a file (ENOTDIR on POSIX), or on Windows a name it refuses
    (error 123), read as absent at start and as a fault in the snapshot before."""
    from messagefoundry.config.environments import load_environment_values

    cfg, _ = _layout(tmp_path)
    (tmp_path / "afile").write_text("", encoding="utf-8")
    cases = [("afile", "x")] + ([("environments", "bad?name")] if os.name == "nt" else [])
    for dir_name, environment in cases:
        path = tmp_path / dir_name / f"{environment}.toml"
        assert (
            load_environment_values(
                base_dir=tmp_path, dir_name=dir_name, environment=environment, environ={}
            )
            == {}
        )
        snapshot = with_value_file(read_config_snapshot(cfg, strict=True), path, strict=True)
        assert snapshot.environment_file(path) is None


def test_a_listed_config_module_a_stat_cannot_reach_is_still_a_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The value file's wider absence does not reach a file a listing returned: there a name too
    long, or a folder that is a file, is a fault, and a load refuses it rather than drop it."""
    cfg, _ = _layout(tmp_path)
    real_stat = Path.stat

    def _stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == "cfg.py":
            raise OSError(errno.ENAMETOOLONG, "name too long", str(self))
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", _stat)
    with pytest.raises(OSError, match="too long"):
        read_config_snapshot(cfg, strict=True)
    assert read_config_snapshot(cfg, strict=False).unreadable_loaded == ("cfg.py",)


def test_a_stat_fault_on_the_value_file_is_a_fault_to_a_start_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before, ``Path.is_file`` answered ``False`` and a start read no values from a value file it
    could not stat, while the snapshot raised."""
    from messagefoundry.config.environments import load_environment_values

    cfg, value_file = _layout(tmp_path)
    real_stat = Path.stat

    def _stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == value_file.name:
            raise PermissionError(13, "denied", str(self))
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", _stat)
    with pytest.raises(PermissionError):
        load_environment_values(
            base_dir=tmp_path, dir_name="environments", environment="dev", environ={}
        )
    with pytest.raises(PermissionError):
        with_value_file(read_config_snapshot(cfg, strict=True), value_file, strict=True)
