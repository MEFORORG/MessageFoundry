# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the config content fingerprint (ADR 0041 D1).

Verifies the fingerprint is stable, location-independent, and changes when *any* loaded file
changes — including a ``_``-prefixed helper (the loader skips it as a top-level module but still
executes it, so it must be in the fingerprint) and the data-authored ``connections.toml`` /
``environments`` / ``codesets`` files.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.config.fingerprint as fp_mod
from messagefoundry.config.fingerprint import (
    UNREADABLE_FILES_KEY,
    ConfigDirMissing,
    _git_head,
    config_fingerprint,
    config_fingerprint_detail,
    digest_coverage,
)

_HEXDIGITS = set("0123456789abcdef")


def _bundle(d: Path) -> None:
    """Write a representative config bundle: a module, a helper, and each data-authored artifact."""
    (d / "codesets").mkdir(parents=True, exist_ok=True)
    (d / "environments").mkdir(parents=True, exist_ok=True)
    (d / "cfg.py").write_text("inbound = 1\n", encoding="utf-8")
    (d / "_helper.py").write_text("HELPER = 1\n", encoding="utf-8")
    (d / "connections.toml").write_text("[x]\n", encoding="utf-8")
    (d / "codesets" / "diet.csv").write_text("key,value\na,b\n", encoding="utf-8")
    (d / "environments" / "dev.toml").write_text("host = 'x'\n", encoding="utf-8")


def test_fingerprint_is_stable(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    assert config_fingerprint(d) == config_fingerprint(d)


def test_fingerprint_is_64_hex(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    fp = config_fingerprint(d)
    assert len(fp) == 64
    assert set(fp) <= _HEXDIGITS


def test_fingerprint_is_path_relative_not_absolute(tmp_path: Path) -> None:
    # Two byte-identical bundles at different absolute paths must fingerprint identically — the
    # digest keys on each file's relative path + content, never its absolute location.
    a = tmp_path / "a" / "cfg"
    b = tmp_path / "b" / "cfg"
    _bundle(a)
    _bundle(b)
    assert config_fingerprint(a) == config_fingerprint(b)


def test_fingerprint_changes_on_module_edit(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "cfg.py").write_text("inbound = 2\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_changes_on_helper_edit(tmp_path: Path) -> None:
    # The insider point: a '_'-prefixed helper is skipped as a top-level module by the loader but is
    # still executed code (a sibling imports it), so editing it MUST change the fingerprint.
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "_helper.py").write_text("HELPER = 999\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_changes_on_connections_toml_edit(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "connections.toml").write_text("[y]\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_changes_on_environment_edit(tmp_path: Path) -> None:
    # A redirect via environments/<env>.toml changes effective behaviour with no code edit — it must
    # move the fingerprint, or an env-value redirect would slip past the audit unchanged.
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "environments" / "dev.toml").write_text("host = 'evil'\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_changes_on_codeset_edit(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "codesets" / "diet.csv").write_text("key,value\na,zzz\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_changes_on_new_file(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "extra.py").write_text("x = 1\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_ignores_unrelated_files(tmp_path: Path) -> None:
    # A README or a .pyc next to the config is not loaded code — it must not move the fingerprint.
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "README.md").write_text("notes\n", encoding="utf-8")
    (d / "cfg.pyc").write_text("compiled\n", encoding="utf-8")
    assert config_fingerprint(d) == before


def test_detail_has_fingerprint_and_file_count(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    detail = config_fingerprint_detail(d)
    assert detail["fingerprint"] == config_fingerprint(d)
    assert detail["files"] == 5
    # vault BACKLOG #2597: the scheme tag decides whether two digests are comparable at all.
    assert detail["scheme"] == "mefor-cfg-fp:v3"
    # tmp_path is outside any git work tree, so provenance is omitted (not None, absent).
    assert "git_head" not in detail


# --- vault BACKLOG #2596: the strict digest a dual-control approval binds fails closed ----------


def _unreadable(
    monkeypatch: pytest.MonkeyPatch, name: str, *, when: dict[str, bool] | None = None
) -> None:
    """Make ``read_bytes`` of every file called ``name`` fail as an access-denied read does, always,
    or while ``when["on"]``. A real access list cannot be set portably, and a Windows administrator
    reads through one anyway. tests/test_dual_control_reload.py uses it too."""
    real = Path.read_bytes

    def _read(self: Path) -> bytes:
        if (when is None or when["on"]) and self.name == name:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", _read)


def _unlistable(
    monkeypatch: pytest.MonkeyPatch, path: Path, *, when: dict[str, bool] | None = None
) -> None:
    """Make ``os.scandir`` of ``path`` fail as an access-denied listing does, always or while
    ``when["on"]``. A target may be a file descriptor, as ``shutil.rmtree`` passes on Linux, and
    ``Path`` of that raises."""
    real = os.scandir

    def _scandir(target: Any = ".") -> Any:
        if (
            (when is None or when["on"])
            and isinstance(target, str | os.PathLike)
            and Path(target) == path
        ):
            raise PermissionError(13, "Permission denied", str(target))
        return real(target)

    monkeypatch.setattr(os, "scandir", _scandir)


@pytest.mark.parametrize("name", ["cfg.py", "dev.toml"])
def test_strict_refuses_a_file_it_cannot_read_where_the_default_skips_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    readable = config_fingerprint(d, strict=True)
    _unreadable(monkeypatch, name)
    with pytest.raises(PermissionError):
        config_fingerprint(d, strict=True)
    # The control, and the observational rule every other caller keeps: the rest is digested.
    assert config_fingerprint(d) != readable
    assert config_fingerprint_detail(d)["files"] == 4


def test_strict_refuses_a_missing_directory_where_the_default_digests_an_empty_bundle(
    tmp_path: Path,
) -> None:
    gone, empty, a_file = tmp_path / "gone", tmp_path / "empty", tmp_path / "a-file"
    empty.mkdir()
    a_file.write_text("x", encoding="utf-8")
    for not_a_dir in (gone, a_file):
        with pytest.raises(FileNotFoundError):
            config_fingerprint(not_a_dir, strict=True)
    # The control: an empty directory is a directory, and the default digests a missing one as it.
    assert config_fingerprint(empty, strict=True) == config_fingerprint(gone)


#: Directory names no directory can have. A 300-character component is past every filesystem's
#: name limit, so Linux answers ENAMETOOLONG and Windows ERROR_INVALID_NAME. Windows also refuses a
#: ``?``, the name the PR 2239 review probed; elsewhere that is an ordinary missing name.
INVALID_DIR_NAMES = [
    pytest.param("a" * 300, id="too-long"),
    pytest.param(
        "sub?",
        id="question-mark",
        marks=pytest.mark.skipif(os.name != "nt", reason="only Windows refuses a ? in a name"),
    ),
]


@pytest.mark.parametrize("name", INVALID_DIR_NAMES)
def test_strict_refuses_a_name_no_directory_can_have_as_missing(tmp_path: Path, name: str) -> None:
    """The OS refuses the name with an error that is not ENOENT, so a strict digest raised that
    error, and a gated reload of the name answered ``digest_unavailable`` or ``unreadable``. No
    directory can have the name, so it is missing (vault BACKLOG #2596)."""
    with pytest.raises(ConfigDirMissing):
        config_fingerprint(tmp_path / name, strict=True)


def test_strict_refuses_a_folder_it_cannot_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``glob`` swallows a listing error, so an unlistable ``codesets`` folder would leave its
    tables out of the digest. A missing one is fine: nothing in it is left out."""
    d = tmp_path / "cfg"
    _bundle(d)
    readable = config_fingerprint(d, strict=True)
    real_scandir = os.scandir

    def _scandir(path: Any) -> Any:
        if Path(path).name == "codesets":
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", _scandir)
    with pytest.raises(PermissionError):
        config_fingerprint(d, strict=True)
    monkeypatch.undo()
    shutil.rmtree(d / "codesets")
    assert config_fingerprint(d, strict=True) != readable  # the control: absent, not refused


@pytest.mark.parametrize("name", ["codesets", "environments"])
def test_a_file_named_like_a_folder_it_lists_is_a_missing_folder(tmp_path: Path, name: str) -> None:
    """A sub-folder is judged as the directory itself is: a plain file in its place cannot be
    listed, and it holds nothing a digest leaves out (vault BACKLOG #3535). So it refuses nothing,
    is named as nothing left out, and does not move the digest."""
    d = tmp_path / "cfg"
    d.mkdir()
    (d / "cfg.py").write_text("inbound = 1\n", encoding="utf-8")
    without = config_fingerprint(d, strict=True)
    (d / name).write_text("not a folder\n", encoding="utf-8")
    assert config_fingerprint(d, strict=True) == without
    detail = config_fingerprint_detail(d)
    assert UNREADABLE_FILES_KEY not in detail and detail["fingerprint"] == without


# --- vault BACKLOG #2944: the observational digest says when it left something out --------------


@pytest.mark.parametrize("name", ["cfg.py", "dev.toml"])
def test_the_detail_marks_a_digest_that_left_out_a_file_it_could_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """An antivirus lock at one start and not the next gave two digests for the same bytes, and
    nothing in the detail said the first covered only part of the bundle."""
    d = tmp_path / "cfg"
    _bundle(d)
    assert UNREADABLE_FILES_KEY not in config_fingerprint_detail(d), "control: a whole bundle"
    _unreadable(monkeypatch, name)
    detail = config_fingerprint_detail(d)
    rel = "cfg.py" if name == "cfg.py" else "environments/dev.toml"
    assert detail[UNREADABLE_FILES_KEY] == [rel]
    # Still best-effort: the rest is digested, as config_fingerprint's default does.
    assert detail["files"] == 4 and detail["fingerprint"] == config_fingerprint(d)


def test_the_detail_marks_a_digest_whose_folder_could_not_be_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    real_scandir = os.scandir

    def _scandir(path: Any) -> Any:
        if Path(path).name == "codesets":
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", _scandir)
    assert config_fingerprint_detail(d)[UNREADABLE_FILES_KEY] == ["codesets"]
    monkeypatch.undo()
    shutil.rmtree(d / "codesets")
    # The control: a folder that is absent left nothing out.
    assert UNREADABLE_FILES_KEY not in config_fingerprint_detail(d)


def test_the_detail_of_a_missing_directory_is_an_empty_bundle_and_not_partial(
    tmp_path: Path,
) -> None:
    detail = config_fingerprint_detail(tmp_path / "gone")
    assert detail["files"] == 0 and UNREADABLE_FILES_KEY not in detail


@pytest.mark.parametrize(
    ("detail", "expected"),
    [
        ({"fingerprint": "f"}, ("f", ())),
        ({"fingerprint": "f", UNREADABLE_FILES_KEY: ["a.py", "b.py"]}, ("f", ("a.py", "b.py"))),
        ({"fingerprint": "f", UNREADABLE_FILES_KEY: 1}, ("f", ("?",))),
        ({"fingerprint": ""}, None),
        ({}, None),
        (None, None),
    ],
    ids=["whole", "partial", "not-a-list", "empty", "no-fingerprint", "none"],
)
def test_digest_coverage(detail: dict[str, object] | None, expected: object) -> None:
    assert digest_coverage(detail) == expected


def test_the_detail_names_every_folder_it_could_not_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 2: naming only the first unlistable folder let two digests that reported the
    same coverage cover different files."""
    d = tmp_path / "cfg"
    _bundle(d)
    real_scandir = os.scandir

    def _scandir(path: Any) -> Any:
        if Path(path).name in {"codesets", "environments"}:
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", _scandir)
    assert config_fingerprint_detail(d)[UNREADABLE_FILES_KEY] == ["codesets", "environments"]


def test_a_file_removed_mid_digest_is_gone_not_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    real = Path.read_bytes

    def _read(self: Path) -> bytes:
        if self.name == "cfg.py":
            self.unlink()
            raise FileNotFoundError(2, "No such file", str(self))
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", _read)
    detail = config_fingerprint_detail(d)
    assert UNREADABLE_FILES_KEY not in detail and detail["files"] == 4


def test_a_file_a_read_called_missing_that_is_still_there_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its stat says it exists, so it is not gone, and the digest must not read as a whole one."""
    d = tmp_path / "cfg"
    _bundle(d)
    real = Path.read_bytes

    def _read(self: Path) -> bytes:
        if self.name == "cfg.py":
            raise FileNotFoundError(2, "No such file", str(self))
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", _read)
    assert config_fingerprint_detail(d)[UNREADABLE_FILES_KEY] == ["cfg.py"]


# --- vault BACKLOG #5325: git_head is read safely, confined, and only an object id -------------

_SHA1 = "a" * 40
_SHA256 = "b" * 64


def _repo(tmp_path: Path, head: bytes) -> tuple[Path, Path]:
    """A work tree with a ``.git`` dir whose HEAD holds ``head``; returns (config dir, git dir)."""
    git_dir = tmp_path / "repo" / ".git"
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "HEAD").write_bytes(head)
    cfg = tmp_path / "repo" / "cfg"
    _bundle(cfg)
    return cfg, git_dir


@pytest.mark.parametrize("sha", [_SHA1, _SHA256])
def test_git_head_reads_a_detached_head(tmp_path: Path, sha: str) -> None:
    """The positive control: a detached HEAD in either object format is the recorded commit."""
    cfg, _ = _repo(tmp_path, f"{sha}\n".encode())
    assert config_fingerprint_detail(cfg)["git_head"] == sha


def test_git_head_resolves_a_loose_ref_then_packed_refs(tmp_path: Path) -> None:
    """The positive control: a symbolic HEAD under refs/ resolves loose first, then packed-refs."""
    cfg, git_dir = _repo(tmp_path, b"ref: refs/heads/main\n")
    (git_dir / "packed-refs").write_text(
        f"# pack-refs with: peeled\n{_SHA256} refs/heads/main\n^{_SHA1}\n", encoding="utf-8"
    )
    assert _git_head(cfg) == _SHA256
    (git_dir / "refs" / "heads" / "main").write_text(f"{_SHA1}\n", encoding="utf-8")
    assert _git_head(cfg) == _SHA1


def test_git_head_resolves_through_a_linked_worktree(tmp_path: Path) -> None:
    """The positive control: ``.git`` as a file points at a gitdir whose refs sit in commondir."""
    common = tmp_path / "main" / ".git"
    (common / "refs" / "heads").mkdir(parents=True)
    (common / "refs" / "heads" / "topic").write_text(f"{_SHA1}\n", encoding="utf-8")
    linked = common / "worktrees" / "wt"
    linked.mkdir(parents=True)
    (linked / "HEAD").write_text("ref: refs/heads/topic\n", encoding="utf-8")
    (linked / "commondir").write_text("../..\n", encoding="utf-8")
    cfg = tmp_path / "wt" / "cfg"
    _bundle(cfg)
    (tmp_path / "wt" / ".git").write_text(f"gitdir: {linked}\n", encoding="utf-8")
    assert _git_head(cfg) == _SHA1


_NOT_UTF8 = b"\xff\xfe" + _SHA1.encode()


@pytest.mark.parametrize(
    ("rel", "data"),
    [
        ("HEAD", _NOT_UTF8),
        ("packed-refs", _NOT_UTF8 + b" refs/heads/main\n"),
        ("refs/heads/main", _NOT_UTF8),
    ],
)
def test_a_git_file_that_is_not_utf8_reads_as_unknown(
    tmp_path: Path, rel: str, data: bytes
) -> None:
    """A non-UTF-8 git file raised UnicodeDecodeError out of provenance capture, and with it out of
    the whole fingerprint detail. Now it reads as unknown, as an unreadable file does."""
    cfg, git_dir = _repo(tmp_path, b"ref: refs/heads/main\n")
    (git_dir / rel).write_bytes(data)
    detail = config_fingerprint_detail(cfg)
    assert "git_head" not in detail
    assert detail["fingerprint"] == config_fingerprint(cfg)


def test_a_git_file_pointer_that_is_not_utf8_reads_as_unknown(tmp_path: Path) -> None:
    """The same for a linked worktree's ``.git`` file."""
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / ".git").write_bytes(b"gitdir: \xff\n")
    cfg = tmp_path / "repo" / "cfg"
    _bundle(cfg)
    assert "git_head" not in config_fingerprint_detail(cfg)


def test_a_commondir_that_is_not_utf8_reads_as_unknown(tmp_path: Path) -> None:
    """The shared refs live only where it points, so a ref in the gitdir is not read instead."""
    cfg, git_dir = _repo(tmp_path, b"ref: refs/heads/main\n")
    (git_dir / "commondir").write_bytes(_NOT_UTF8)
    (git_dir / "refs" / "heads" / "main").write_text(_SHA1, encoding="utf-8")
    assert "git_head" not in config_fingerprint_detail(cfg)


@pytest.mark.parametrize(
    "ref", ["refs/heads/feature/x", "refs/remotes/origin/main", "refs/tags/v1"]
)
def test_git_head_resolves_a_ref_of_any_depth(tmp_path: Path, ref: str) -> None:
    """The positive control for the confinement: a slash-named branch is still a ref."""
    cfg, git_dir = _repo(tmp_path, f"ref: {ref}\n".encode())
    (git_dir / ref).parent.mkdir(parents=True, exist_ok=True)
    (git_dir / ref).write_text(f"{_SHA1}\n", encoding="utf-8")
    assert _git_head(cfg) == _SHA1


def _linked(tmp_path: Path, head: str) -> tuple[Path, Path, Path]:
    """A linked worktree whose HEAD holds ``head``; returns (config dir, gitdir, commondir)."""
    common = tmp_path / "main" / ".git"
    (common / "refs" / "heads").mkdir(parents=True)
    linked = common / "worktrees" / "wt"
    (linked / "refs" / "heads").mkdir(parents=True)
    (linked / "HEAD").write_text(head, encoding="utf-8")
    (linked / "commondir").write_text("../..\n", encoding="utf-8")
    cfg = tmp_path / "wt" / "cfg"
    _bundle(cfg)
    (tmp_path / "wt" / ".git").write_text(f"gitdir: {linked}\n", encoding="utf-8")
    return cfg, linked, common


def test_a_shared_ref_is_read_only_from_the_commondir(tmp_path: Path) -> None:
    """git ignores a ``refs/heads`` file in a linked worktree's gitdir, and packed-refs there, so a
    stale or crafted one does not shadow the shared ref."""
    cfg, linked, common = _linked(tmp_path, "ref: refs/heads/topic\n")
    (linked / "refs" / "heads" / "topic").write_text(_SHA256, encoding="utf-8")
    (linked / "packed-refs").write_text("NOTANID refs/heads/topic\n", encoding="utf-8")
    (common / "packed-refs").write_text(f"{_SHA1} refs/heads/topic\n", encoding="utf-8")
    assert _git_head(cfg) == _SHA1


def test_a_per_worktree_ref_is_read_from_the_gitdir(tmp_path: Path) -> None:
    """A ``refs/bisect`` ref is the worktree's own."""
    cfg, linked, common = _linked(tmp_path, "ref: refs/bisect/bad\n")
    (linked / "refs" / "bisect").mkdir()
    (linked / "refs" / "bisect" / "bad").write_text(_SHA1, encoding="utf-8")
    (common / "refs" / "bisect").mkdir()
    (common / "refs" / "bisect" / "bad").write_text(_SHA256, encoding="utf-8")
    assert _git_head(cfg) == _SHA1


def test_a_ref_name_elsewhere_in_packed_refs_that_is_not_utf8_does_not_hide_head(
    tmp_path: Path,
) -> None:
    """git does not require UTF-8 ref names, so one Latin-1 branch must not drop provenance."""
    cfg, git_dir = _repo(tmp_path, b"ref: refs/heads/main\n")
    (git_dir / "packed-refs").write_bytes(
        f"{_SHA256} refs/heads/caf".encode() + b"\xe9\n" + f"{_SHA1} refs/heads/main\n".encode()
    )
    assert _git_head(cfg) == _SHA1


def test_a_loose_ref_that_is_a_directory_falls_through_to_packed_refs(tmp_path: Path) -> None:
    """As git does: a folder of that name is no loose ref."""
    cfg, git_dir = _repo(tmp_path, b"ref: refs/heads/main\n")
    (git_dir / "refs" / "heads" / "main").mkdir()
    (git_dir / "packed-refs").write_text(f"{_SHA1} refs/heads/main\n", encoding="utf-8")
    assert _git_head(cfg) == _SHA1


def test_a_loose_ref_that_cannot_be_stated_does_not_fall_back_to_packed_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A loose ref that is there but refused is not absent: packed-refs may hold a stale id."""
    cfg, git_dir = _repo(tmp_path, b"ref: refs/heads/main\n")
    loose = git_dir / "refs" / "heads" / "main"
    loose.write_text(_SHA256, encoding="utf-8")
    (git_dir / "packed-refs").write_text(f"{_SHA1} refs/heads/main\n", encoding="utf-8")
    real = os.stat

    def _stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if os.fspath(path) == str(loose):
            raise PermissionError(13, "Permission denied", str(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", _stat)
    assert _git_head(cfg) is None


def test_a_loose_ref_removed_before_its_read_falls_through_to_packed_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``git pack-refs`` writes packed-refs and then deletes the loose ref, so a ref gone by the
    read is packed, as git would read it."""
    cfg, git_dir = _repo(tmp_path, b"ref: refs/heads/main\n")
    loose = git_dir / "refs" / "heads" / "main"
    loose.write_text(_SHA256, encoding="utf-8")
    (git_dir / "packed-refs").write_text(f"{_SHA1} refs/heads/main\n", encoding="utf-8")
    real = os.open

    def _open(path: Any, *args: Any, **kwargs: Any) -> int:
        if os.fspath(path) == str(loose):
            loose.unlink()
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", _open)
    assert _git_head(cfg) == _SHA1


def test_a_reftable_head_reads_as_unknown_without_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Every reftable repository writes ``ref: refs/heads/.invalid``; that is no tampering."""
    cfg, _ = _repo(tmp_path, b"ref: refs/heads/.invalid\n")
    with caplog.at_level("DEBUG", logger="messagefoundry.config.fingerprint"):
        assert _git_head(cfg) is None
    assert not [r for r in caplog.records if r.levelname == "WARNING"]


def test_a_refused_symbolic_ref_logs_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A refusal is not silent, and the log line does not carry the crafted ref text."""
    cfg, _ = _repo(tmp_path, b"ref: ../crafted-text\n")
    with caplog.at_level("WARNING", logger="messagefoundry.config.fingerprint"):
        assert _git_head(cfg) is None
    assert [r.levelname for r in caplog.records] == ["WARNING"]
    assert "crafted-text" not in caplog.text


@pytest.mark.parametrize("rel", ["HEAD", "refs/heads/main"])
def test_a_git_file_longer_than_any_git_writes_reads_as_unknown(tmp_path: Path, rel: str) -> None:
    """Each is one line; a padded one is not read whole into memory and taken."""
    cfg, git_dir = _repo(tmp_path, b"ref: refs/heads/main\n")
    (git_dir / rel).write_text(_SHA1 + " " * 5000, encoding="utf-8")
    assert _git_head(cfg) is None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a POSIX FIFO")
def test_a_fifo_head_reads_as_unknown_without_blocking(tmp_path: Path) -> None:
    """Opening a FIFO for read blocks until a writer comes; it is not a regular file, so not read."""
    cfg, git_dir = _repo(tmp_path, b"")
    (git_dir / "HEAD").unlink()
    os.mkfifo(git_dir / "HEAD")
    assert _git_head(cfg) is None


@pytest.mark.parametrize(
    "ref",
    [
        "../outside",
        "refs/../../outside",
        "refs/heads/../../../outside",
        "heads/main",
        "refs",
        "refs/",
        "refs//main",
        "refs/heads/.hidden",
        "refs/heads/main.lock",
        "refs\\..\\..\\outside",
        "refs/heads/a:b",
        "refs/heads/a b",
        "refs/heads/main.",
    ],
)
def test_a_symbolic_ref_outside_refs_is_not_followed(tmp_path: Path, ref: str) -> None:
    """``ref:`` was joined onto the git dir unchecked, so a crafted HEAD read any file. Each file it
    could reach holds an object id here, so only the confinement can keep it out of git_head."""
    cfg, git_dir = _repo(tmp_path, f"ref: {ref}\n".encode())
    (tmp_path / "repo" / "outside").write_text(_SHA1, encoding="utf-8")
    (tmp_path / "outside").write_text(_SHA1, encoding="utf-8")
    (git_dir / "packed-refs").write_text(f"{_SHA1} {ref}\n", encoding="utf-8")
    assert _git_head(cfg) is None


@pytest.mark.parametrize("name", ["CON", "com1", "CONIN$", "nul.txt", "a."])
def test_a_symbolic_ref_naming_a_windows_device_is_refused_only_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """On Windows the read would open the device, or a name Windows strips; on POSIX each is an
    ordinary file name git accepts, so it still resolves."""
    ref = f"refs/heads/{name}/x"
    cfg, git_dir = _repo(tmp_path, f"ref: {ref}\n".encode())
    (git_dir / "packed-refs").write_text(f"{_SHA1} {ref}\n", encoding="utf-8")
    monkeypatch.setattr(os, "name", "nt")
    assert fp_mod._confined_ref(ref) is False
    monkeypatch.setattr(os, "name", "posix")
    assert fp_mod._confined_ref(ref) is True
    if os.name == "nt":
        monkeypatch.undo()
        assert _git_head(cfg) is None


def test_an_absolute_symbolic_ref_is_not_followed(tmp_path: Path) -> None:
    """An absolute path joined onto the git dir replaced it, reading that file."""
    target = tmp_path / "elsewhere"
    target.write_text(_SHA1, encoding="utf-8")
    cfg, _ = _repo(tmp_path, f"ref: {target}\n".encode())
    assert _git_head(cfg) is None


@pytest.mark.parametrize(
    "text",
    [
        "synthetic-file-text-not-a-commit",
        _SHA1.upper(),
        _SHA1[:-1],
        _SHA1 + "0",
        _SHA256 + "0",
        "g" * 40,
    ],
)
@pytest.mark.parametrize(
    ("rel", "template"),
    [("HEAD", "{}\n"), ("refs/heads/main", "{}"), ("packed-refs", "{} refs/heads/main\n")],
)
def test_git_head_records_only_an_object_id(
    tmp_path: Path, text: str, rel: str, template: str
) -> None:
    """Whatever text the ref file held became the git_head audit field. Only a 40- or 64-hex object
    id is recorded now; anything else reads as unknown. Writing HEAD replaces the symbolic ref with
    the text, as a detached HEAD. No text holds a space, so each packed-refs line names the ref."""
    cfg, git_dir = _repo(tmp_path, b"ref: refs/heads/main\n")
    (git_dir / rel).write_text(template.format(text), encoding="utf-8")
    assert "git_head" not in config_fingerprint_detail(cfg)


@pytest.mark.parametrize("text", ["not an id", "ref: refs/heads/other"])
def test_a_loose_ref_that_is_no_object_id_does_not_fall_back_to_packed_refs(
    tmp_path: Path, text: str
) -> None:
    """git reads the loose ref over packed-refs, so a malformed loose ref, or a nested symbolic ref
    this reader does not follow, is unknown, never the stale packed value."""
    cfg, git_dir = _repo(tmp_path, b"ref: refs/heads/main\n")
    (git_dir / "refs" / "heads" / "main").write_text(text, encoding="utf-8")
    (git_dir / "packed-refs").write_text(f"{_SHA1} refs/heads/main\n", encoding="utf-8")
    assert _git_head(cfg) is None
