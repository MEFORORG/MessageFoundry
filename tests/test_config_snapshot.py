# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The bytes a config load hashes are the bytes it compiles and runs (vault BACKLOG #2596).

Two probes from the 2026-10-01 architecture review, as tests that fail on the code before the
change:

* A cache file planted under ``__pycache__``, whose header matches the source's size and time,
  ran in place of the source while the fingerprint stayed the same. The loader now compiles each
  module from the one snapshot it hashed, so the cache is never consulted.
* A sandbox worker respawn loaded whatever was on disk then, with no reload. The worker is now sent
  the engine's snapshot and never reads the directory, so a respawn runs what the engine loaded.

Plus the two points the row folds in: a code-set table spelled ``x.CSV`` is hashed as the loader
reads it, on POSIX too, and a module linked in beside another changes the digest.

Synthetic HL7 and marker strings only."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import marshal
import os
import subprocess
from pathlib import Path, PurePath
from types import CodeType

import pytest

from messagefoundry.config.fingerprint import config_fingerprint
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.snapshot import ConfigSnapshot, config_py_files, read_config_snapshot
from messagefoundry.config.wiring import WiringError, load_config, load_snapshot
from messagefoundry.pipeline import _sandbox_codec as codec
from messagefoundry.pipeline.dryrun import transform_one
from messagefoundry.pipeline.sandbox import (
    SandboxError,
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
    SandboxWorkerRefused,
    graph_shape,
)

RAW = "MSH|^~\\&|SEND|F|RECV|F|20240101120000||ADT^A01|MSG00001|P|2.3\rPID|1||900001||DOE^JANE\r"

_GRAPH = """
import os
from messagefoundry import inbound, outbound, router, handler, MLLP, Send

inbound("IB_SNAP", MLLP(port=19471), router="r")
outbound("OB_SNAP", MLLP(host="127.0.0.1", port=19472))


@router("r")
def r(msg):
    return "h_ver"


@handler("h_ver")
def h_ver(msg):
    return Send("OB_SNAP", "__VERSION__")


@handler("h_die")
def h_die(msg):
    os._exit(3)
"""


def _graph(version: str) -> str:
    return _GRAPH.replace("__VERSION__", version)


def _ran(registry: object, name: str = "h_ver", **kwargs: object) -> str:
    deliveries, _, _, _ = transform_one(registry, name, RAW, **kwargs)  # type: ignore[arg-type]
    return str(deliveries[0].payload)


def _strings(code: CodeType | None) -> set[str]:
    """Every string constant in ``code`` and the code objects nested in it."""
    found: set[str] = set()
    if code is None:
        return found
    for const in code.co_consts:
        if isinstance(const, str):
            found.add(const)
        elif isinstance(const, CodeType):
            found |= _strings(const)
    return found


def _plant_cache(graph: Path, source: str) -> Path:
    """A timestamp-validated cache file for ``graph``, compiled from ``source``, whose header
    carries ``graph``'s own size and time: Python's source loader takes it as current."""
    st = graph.stat()
    header = (
        importlib.util.MAGIC_NUMBER
        + (0).to_bytes(4, "little")
        + (int(st.st_mtime) & 0xFFFFFFFF).to_bytes(4, "little")
        + (st.st_size & 0xFFFFFFFF).to_bytes(4, "little")
    )
    cache = Path(importlib.util.cache_from_source(str(graph)))
    cache.parent.mkdir(exist_ok=True)
    cache.write_bytes(header + marshal.dumps(compile(source, str(graph), "exec")))
    return cache


# --- probe 1: a planted cache file -----------------------------------------------------------------


def test_a_planted_cache_file_does_not_run_and_the_digest_names_what_does(tmp_path: Path) -> None:
    graph = tmp_path / "graph.py"
    graph.write_text(_graph("V1"), encoding="utf-8")
    before = config_fingerprint(tmp_path)
    cache = _plant_cache(graph, _graph("V2"))
    # Control: the planted file is one Python's ordinary source loader runs in place of graph.py,
    # which is the loader this module used before (vault BACKLOG #2596).
    spec = importlib.util.spec_from_file_location("mefor_probe_control", graph)
    assert spec is not None and isinstance(spec.loader, importlib.machinery.SourceFileLoader)
    control = _strings(spec.loader.get_code("mefor_probe_control"))
    assert "V2" in control and "V1" not in control
    registry = load_config(tmp_path)
    assert _ran(registry) == "V1"
    assert config_fingerprint(tmp_path) == before  # the cache is not part of what loads
    assert cache.exists(), "control: the planted file is still there"


def test_the_loader_never_reads_the_cache_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    graph = tmp_path / "graph.py"
    graph.write_text(_graph("V1"), encoding="utf-8")
    _plant_cache(graph, _graph("V2"))
    opened: list[str] = []
    real_open = open

    def recording_open(file: object, *args: object, **kwargs: object) -> object:
        opened.append(os.fspath(file) if isinstance(file, (str, os.PathLike)) else repr(file))
        return real_open(file, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr("builtins.open", recording_open)
    registry = load_config(tmp_path)
    monkeypatch.undo()
    assert _ran(registry) == "V1"
    assert not [name for name in opened if "__pycache__" in name]


def test_a_helper_runs_the_snapshot_bytes_too(tmp_path: Path) -> None:
    (tmp_path / "_shared.py").write_text('VERSION = "V1"\n', encoding="utf-8")
    (tmp_path / "graph.py").write_text(
        "import _shared\n" + _graph("V0").replace('"V0"', "_shared.VERSION"), encoding="utf-8"
    )
    _plant_cache(tmp_path / "_shared.py", 'VERSION = "V2"\n')
    assert _ran(load_config(tmp_path)) == "V1"


# --- probe 2: a sandbox worker respawn -------------------------------------------------------------


def _session(registry: object, config_dir: Path, *, snapshot: bool = True) -> SandboxSession:
    return SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0),
        inbound="IB_SNAP",
        config_dir=config_dir,
        env=None,
        graph=lambda: graph_shape(registry),
        snapshot=registry.config_snapshot if snapshot else None,  # type: ignore[attr-defined]
    )


def test_a_respawned_worker_runs_the_engines_bytes_not_the_disk(tmp_path: Path) -> None:
    graph = tmp_path / "graph.py"
    graph.write_text(_graph("V1"), encoding="utf-8")
    registry = load_config(tmp_path)  # the engine's graph, never reloaded below
    session = _session(registry, tmp_path)
    try:
        assert _ran(registry, sandbox=session, run_context=RunContext()) == "V1"
        first = session._proc.pid if session._proc else None
        graph.write_text(_graph("V2"), encoding="utf-8")
        with pytest.raises(SandboxError):
            _ran(registry, "h_die", sandbox=session, run_context=RunContext())
        # The next dispatch respawns the worker, with no reload asked for. Before, it loaded the
        # edited file from disk; then, with the digest comparison, it was refused.
        assert _ran(registry, sandbox=session, run_context=RunContext()) == "V1"
        assert session._proc is not None and session._proc.pid != first, "control: it respawned"
    finally:
        session.close()
    # Control: a session handed no snapshot reads the directory, and the edit is there to read, so
    # its worker is refused for loading other bytes than the engine's.
    blind = _session(registry, tmp_path, snapshot=False)
    try:
        with pytest.raises(SandboxWorkerRefused, match="config module content"):
            _ran(registry, sandbox=blind, run_context=RunContext())
    finally:
        blind.close()


def test_the_boot_frame_carries_the_snapshot_and_no_directory(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(_graph("V1"), encoding="utf-8")
    (tmp_path / "environments").mkdir()
    (tmp_path / "environments" / "dev.toml").write_text('X = "1"\n', encoding="utf-8")
    snapshot = load_config(tmp_path).config_snapshot
    assert snapshot is not None
    frame = codec.encode_boot(snapshot=snapshot, forbidden=(), mem_mb=None, code_sets=None)
    boot = codec.decode_boot(frame)
    assert dict(boot.snapshot.files) == {"graph.py": snapshot.files["graph.py"]}
    assert b"config_dir" not in frame
    # The worker's load reads nothing from disk: it runs with the directory gone.
    (tmp_path / "graph.py").unlink()
    assert _ran(load_snapshot(boot.snapshot)) == "V1"


@pytest.mark.parametrize(
    "rel", ["../graph.py", "sub/graph.py", "codesets/x.py", "/abs.py", ".hidden.py", "a\0b.py"]
)
def test_a_snapshot_refuses_a_path_no_load_reads(rel: str) -> None:
    with pytest.raises(ValueError, match="config snapshot path"):
        ConfigSnapshot(directory=Path("cfg"), files={rel: b""})


@pytest.mark.skipif(os.name != "nt", reason="a backslash and a drive are plain names on POSIX")
@pytest.mark.parametrize("rel", ["a\\b.py", "C:x.py", "codesets/C:x.csv"])
def test_a_snapshot_refuses_a_name_windows_would_not_keep_in_the_folder(rel: str) -> None:
    """Joined to the directory, ``C:x.py`` names another drive and ``a\\b.py`` a sub-folder, and
    either path's ``name`` is ``x.py`` or ``b.py``: a boot frame naming one could run another
    module's bytes under its name."""
    with pytest.raises(ValueError, match="config snapshot path"):
        ConfigSnapshot(directory=Path("cfg"), files={rel: b""})


@pytest.mark.skipif(os.name == "nt", reason="Windows refuses a backslash in a file name")
def test_a_posix_module_named_with_a_backslash_loads(tmp_path: Path) -> None:
    """A name the listing returns is one a snapshot holds, so it loads as it did, rather than
    escaping the load as a bare ValueError."""
    (tmp_path / "a\\graph.py").write_text(_graph("V1"), encoding="utf-8")
    registry = load_config(tmp_path)
    assert _ran(registry) == "V1"
    assert registry.config_snapshot is not None
    assert registry.config_snapshot.modules == ("a\\graph.py",)


def test_modules_run_in_the_order_the_directory_listing_gave(tmp_path: Path) -> None:
    """Path order, as the loader globbed it: without case on Windows, so a bundle's load order and
    the file a duplicate-name refusal names stay as they were."""
    names = ["A_feed.py", "a2.py", "b_feed.py", "Router.py"]
    for name in names:
        (tmp_path / name).write_text("X = 1\n", encoding="utf-8")
    snapshot = read_config_snapshot(tmp_path, strict=True)
    assert snapshot.modules == tuple(p.name for p in config_py_files(tmp_path))
    assert snapshot.modules == tuple(sorted(names, key=PurePath))


def test_a_worker_sent_the_engines_tables_is_not_sent_their_files(tmp_path: Path) -> None:
    """One boot frame carries each table once: the engine's parsed tables when it publishes any,
    so the frame's 64 MiB cap admits as many tables under ``subprocess`` as under ``off``. The
    worker's load publishes them before any module runs, so a top-level capture resolves."""
    (tmp_path / "graph.py").write_text(
        _graph("V1") + '\nfrom messagefoundry import code_set\nDIETS = code_set("diets")\n',
        encoding="utf-8",
    )
    (tmp_path / "codesets").mkdir()
    (tmp_path / "codesets" / "diets.csv").write_text("k,v\na,b\n", encoding="utf-8")
    registry = load_config(tmp_path)
    snapshot = registry.config_snapshot
    assert snapshot is not None and "codesets/diets.csv" in snapshot.files
    published = codec.decode_boot(
        codec.encode_boot(
            snapshot=snapshot, forbidden=(), mem_mb=None, code_sets=registry.code_sets
        )
    )
    assert set(published.snapshot.files) == {"graph.py"}
    assert published.code_sets is not None
    worker = load_snapshot(published.snapshot, code_sets=published.code_sets)
    assert worker.code_sets["diets"]["a"] == "b"
    assert worker.code_digest == registry.code_digest
    # Control: with no tables published, the files go instead, and the worker parses them.
    unpublished = codec.decode_boot(
        codec.encode_boot(snapshot=snapshot, forbidden=(), mem_mb=None, code_sets=None)
    )
    assert "codesets/diets.csv" in unpublished.snapshot.files
    assert load_snapshot(unpublished.snapshot).code_sets["diets"]["a"] == "b"


def test_a_session_that_cannot_read_its_snapshot_starts_no_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session given no snapshot reads its directory before the child is started, so a read
    that fails leaves no child, job handle or drain thread behind."""

    def no_child(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a worker was started")

    monkeypatch.setattr(subprocess, "Popen", no_child)
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0),
        inbound="IB_SNAP",
        config_dir=tmp_path / "missing",
        env=None,
        graph=None,
    )
    try:
        with pytest.raises(SandboxError, match="failed to bootstrap"):
            session._spawn()
        assert session._proc is None
    finally:
        session.close()


# --- the points the row folds in -------------------------------------------------------------------


def test_a_code_set_spelled_in_upper_case_is_hashed_as_it_loads(tmp_path: Path) -> None:
    """``codesets/*.csv`` was a case-sensitive glob on POSIX, while the loader matches the suffix
    in lower case, so ``x.CSV`` loaded unhashed on Linux. Only a POSIX run discriminates: a
    Windows glob already matched it."""
    (tmp_path / "graph.py").write_text(_graph("V1"), encoding="utf-8")
    (tmp_path / "codesets").mkdir()
    table = tmp_path / "codesets" / "diets.CSV"
    table.write_text("k,v\na,b\n", encoding="utf-8")
    assert "diets" in load_config(tmp_path).code_sets
    before = config_fingerprint(tmp_path)
    table.write_text("k,v\na,c\n", encoding="utf-8")
    assert config_fingerprint(tmp_path) != before
    assert "codesets/diets.CSV" in read_config_snapshot(tmp_path, strict=True).files


def test_a_module_linked_in_beside_another_changes_the_digest(tmp_path: Path) -> None:
    """A path that resolves to a file another path names was hashed once, so a ``_`` helper added
    as a link to an existing module released with an unchanged digest (vault BACKLOG #3535 item 2).
    Each path is hashed now. The link sorts after its target on every platform, which is the
    order in which the old fold skipped it; a link sorting first replaced its target's path and
    did change the digest."""
    (tmp_path / "graph.py").write_text(_graph("V1"), encoding="utf-8")
    (tmp_path / "_shared.py").write_text("X = 1\n", encoding="utf-8")
    before = config_fingerprint(tmp_path)
    try:
        os.symlink(tmp_path / "_shared.py", tmp_path / "_shared_copy.py")
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    assert config_fingerprint(tmp_path) != before


def test_a_load_refuses_a_module_it_cannot_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It cannot run bytes it does not have. The observational digest names the file instead."""
    (tmp_path / "graph.py").write_text(_graph("V1"), encoding="utf-8")
    real = Path.read_bytes

    def refuse(self: Path) -> bytes:
        if self.name == "graph.py":
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", refuse)
    with pytest.raises(WiringError, match="could not read graph.py"):
        load_config(tmp_path)
    assert read_config_snapshot(tmp_path, strict=False).unreadable == ("graph.py",)
