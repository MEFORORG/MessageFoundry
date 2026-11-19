# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""L3 multi-process supervisor: shard-spec derivation + spawn/restart/stop lifecycle.

The lifecycle tests inject a fake "process" (a controllable stand-in for an
``asyncio.subprocess.Process``) so they exercise the supervisor's monitor/restart/terminate logic
deterministically and fast, without launching real engine subprocesses (Windows-safe)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import subprocess
import sys
import threading
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import proctree, redaction
from messagefoundry.childenv import python_child_argv
from messagefoundry.config.settings import StoreBackend
from messagefoundry.pipeline import supervisor as supervisor_mod
from messagefoundry.pipeline.supervisor import (
    ShardSpec,
    Supervisor,
    _default_spawn,
    build_shard_specs,
    discover_shard_specs,
    preflight_shard_config,
    supervise,
)
from tests._refusal_log_capture import until

#: The arguments discovery and ``supervise`` share in the pre-flight tests.
_DISCOVERY: dict[str, Any] = {
    "store_backend": StoreBackend.SQLITE,
    "db_base": "preflight.db",
    "base_port": 18790,
}

# --- shard-spec derivation (pure) --------------------------------------------


def test_single_default_shard_keeps_base_path_and_port() -> None:
    specs = build_shard_specs(["default"], config="cfg", db_base="mefor.db", base_port=8765)
    assert len(specs) == 1
    spec = specs[0]
    assert spec.db_path == "mefor.db"  # bare base — identical to a non-sharded serve
    assert spec.port == 8765
    assert "--shard" in spec.argv and "default" in spec.argv


def test_multi_shard_derives_distinct_db_and_ports_in_sorted_order() -> None:
    specs = build_shard_specs(["b", "a"], config="cfg", db_base="store/mefor.db", base_port=9000)
    by_shard = {s.shard: s for s in specs}
    # Sorted order assigns ports deterministically (a -> base, b -> base+1).
    assert by_shard["a"].port == 9000
    assert by_shard["b"].port == 9001
    # Each shard gets its own db file (<stem>_<shard><suffix>), distinct from siblings.
    assert by_shard["a"].db_path.endswith("mefor_a.db")
    assert by_shard["b"].db_path.endswith("mefor_b.db")
    assert by_shard["a"].db_path != by_shard["b"].db_path


def test_spec_argv_includes_env_and_service_config_when_given() -> None:
    specs = build_shard_specs(
        ["a", "b"],
        config="cfg",
        db_base="m.db",
        base_port=8765,
        env="prod",
        service_config="svc.toml",
    )
    argv = specs[0].argv
    assert "--env" in argv and "prod" in argv
    assert "--service-config" in argv and "svc.toml" in argv
    # The shard starts through childenv's command line, which keeps the working directory off its
    # import path (vault BACKLOG #2587).
    head = python_child_argv("messagefoundry")
    assert argv[: len(head) + 1] == (*head, "serve")


def test_spec_argv_includes_project_root_when_given() -> None:
    # --project-root is forwarded to EVERY shard so a spawned `serve --env <e>` resolves
    # environments/<e>.toml against the given root, not the child's working directory.
    specs = build_shard_specs(
        ["a", "b"],
        config="cfg",
        db_base="m.db",
        base_port=8765,
        env="prod",
        project_root="C:/srv/mefor",
    )
    for spec in specs:
        argv = spec.argv
        assert "--project-root" in argv
        assert argv[argv.index("--project-root") + 1] == "C:/srv/mefor"


def test_spec_argv_omits_project_root_when_not_given() -> None:
    specs = build_shard_specs(["a"], config="cfg", db_base="m.db", base_port=8765)
    assert "--project-root" not in specs[0].argv


def test_shard_db_composes_under_project_root(tmp_path: object) -> None:
    """ADR 0050 AC-9: with ``supervise --project-root R`` and a relative ``--db`` (no absolute path), the
    supervisor composes each shard's ``<stem>_<shard>.db`` **under R** — not against the child CWD.

    Anchoring happens in ``_supervise`` BEFORE ``supervise()`` discovers shards, so the db_base passed to
    ``build_shard_specs`` is already absolute-under-R; the per-shard composition then keeps it there. We
    patch ``supervise`` (as imported into ``_supervise``) to capture the resolved config + db_base, run
    ``build_shard_specs`` on the captured base, and assert each shard DB lands under R.
    """
    from pathlib import Path

    from messagefoundry import __main__ as cli

    root = Path(str(tmp_path)) / "repo"
    root.mkdir()
    captured: dict[str, object] = {}

    async def _fake_supervise(config: str, *, db_base: str, **_kw: object) -> int:
        captured["config"] = config
        captured["db_base"] = db_base
        return 0

    from messagefoundry.store.crypto import generate_key

    monkey = pytest.MonkeyPatch()
    monkey.setattr("messagefoundry.pipeline.supervisor.supervise", _fake_supervise)
    # supervise applies serve's at-rest gate before it starts any shard (BACKLOG #1916), so the
    # fleet needs the key its shards would need. This test is about path anchoring, not that gate.
    monkey.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    # It applies serve's forwarding gates too (BACKLOG #2356), and refuses a fleet whose engine
    # shards would each refuse for want of a collector. Logging setup is stubbed: nothing is
    # forwarded.
    from tests._phi_gate_provisions import (
        make_syslog_ca_and_crl,
        setenv_declared_egress,
        setenv_verified_log_forwarding,
    )

    try:
        setenv_verified_log_forwarding(monkey, make_syslog_ca_and_crl(Path(str(tmp_path))))
        # And the open-egress gate, which it runs before it installs that forwarder.
        setenv_declared_egress(monkey)
        monkey.setattr(cli, "configure_logging", lambda *args, **kwargs: False)
        args = argparse.Namespace(
            config="config",  # relative — must resolve under R
            db="mefor.db",  # relative — must resolve under R
            base_port=8765,
            env="prod",
            service_config=None,
            project_root=str(root),
        )
        assert cli._supervise(args) == 0
    finally:
        monkey.undo()

    # The discovery config + db base are anchored under R (so discover_shard_specs.load_config and the
    # per-shard composition both resolve against R, from any CWD).
    assert captured["config"] == str(root / "config")
    assert captured["db_base"] == str(root / "mefor.db")
    # And the per-shard <stem>_<shard>.db therefore composes under R.
    specs = build_shard_specs(
        ["a", "b"], config=str(captured["config"]), db_base=str(captured["db_base"]), base_port=8765
    )
    for spec in specs:
        assert Path(spec.db_path).parent == root
        assert Path(spec.db_path).name in {"mefor_a.db", "mefor_b.db"}


def _supervise_captured(
    tmp_path: Path,
    monkey: pytest.MonkeyPatch,
    argv: list[str],
) -> dict[str, object]:
    """Run ``supervise`` through its own parser up to the fleet start and return what the fleet
    would be started with. The gates it passes on the way are provisioned as in the test above."""
    from messagefoundry import __main__ as cli
    from messagefoundry.store.crypto import generate_key
    from tests._phi_gate_provisions import (
        make_syslog_ca_and_crl,
        setenv_declared_egress,
        setenv_verified_log_forwarding,
    )

    captured: dict[str, object] = {}

    async def _fake_supervise(config: str, *, db_base: str, base_port: int, **_kw: object) -> int:
        captured["db_base"] = db_base
        captured["base_port"] = base_port
        return 0

    monkey.setattr("messagefoundry.pipeline.supervisor.supervise", _fake_supervise)
    monkey.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    setenv_verified_log_forwarding(monkey, make_syslog_ca_and_crl(tmp_path))
    setenv_declared_egress(monkey)
    monkey.setattr(cli, "configure_logging", lambda *args, **kwargs: False)
    args = cli._build_parser()[0].parse_args(["supervise", "--env", "prod", *argv])
    assert cli._supervise(args) == 0
    return captured


@pytest.mark.parametrize(
    ("flags", "env", "db_name", "port"),
    [
        pytest.param([], {}, "site.db", 9100, id="settings-file"),
        pytest.param(
            [],
            {"MEFOR_STORE_PATH": "envsite.db", "MEFOR_API_PORT": "9200"},
            "envsite.db",
            9200,
            id="mefor-env",
        ),
        pytest.param(
            ["--db", "flag.db", "--base-port", "9300"], {}, "flag.db", 9300, id="flags-override"
        ),
        pytest.param(["--db", "flag.db"], {}, "flag.db", 9100, id="db-flag-only"),
        pytest.param(["--base-port", "9300"], {}, "site.db", 9300, id="port-flag-only"),
    ],
)
def test_supervise_takes_store_path_and_api_port_from_settings_without_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flags: list[str],
    env: dict[str, str],
    db_name: str,
    port: int,
) -> None:
    """BACKLOG #5817: ``supervise --db`` and ``--base-port`` once defaulted to ``messagefoundry.db``
    and 8765, so [store].path, [api].port and their MEFOR_ variables never reached the engine
    shards. Absent flags now leave the settings' values in force; a given flag still overrides."""
    root = tmp_path / "repo"
    root.mkdir()
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text('[store]\npath = "site.db"\n\n[api]\nport = 9100\n', encoding="utf-8")
    monkeypatch.delenv("MEFOR_STORE_PATH", raising=False)
    monkeypatch.delenv("MEFOR_API_PORT", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    argv = ["--service-config", str(svc), "--project-root", str(root), *flags]
    captured = _supervise_captured(tmp_path, monkeypatch, argv)
    assert captured == {"db_base": str(root / db_name), "base_port": port}


#: The no-stem refusal's text, matched whole so a reworded message that no longer says what the
#: check tests fails here.
_NO_STEM = (
    r"^--db or \[store\]\.path is empty, ends in a '\.' or '\.\.' part, or names only a drive, "
    r"root or share \(value withheld\); several engine shards each derive their file name from "
    r"its last part, so name a file, e.g\. 'messagefoundry\.db'$"
)

_BS = "\\"
_ROOTS = ["/", "//"] + (
    [
        "C:/",
        "C:",
        "C:" + _BS,
        "//srv/share/",
        "//srv/share",
        _BS * 2 + "srv" + _BS + "share" + _BS,
        _BS * 2 + "srv" + _BS + "share",
    ]
    if sys.platform == "win32"
    else []
)


@pytest.mark.parametrize("db_base", _ROOTS)
def test_build_shard_specs_refuses_a_drive_root_or_share_with_the_value_withheld(
    db_base: str,
) -> None:
    """A drive, root or share has an empty pathlib name, so ``Path.with_name`` would raise its own
    ValueError, which quotes the path, and supervise would log it. It is refused first, with the
    value withheld (BACKLOG #5817)."""
    with pytest.raises(ValueError, match=_NO_STEM) as refused:
        build_shard_specs(["a", "b"], config="c", db_base=db_base, base_port=8765)
    # The match is anchored, so the message is the fixed text; this also pins that the path's own
    # text, and pathlib's error quoting it, appear nowhere in what supervise would log.
    assert db_base not in str(refused.value)
    assert refused.value.__context__ is None and refused.value.__cause__ is None


@pytest.mark.parametrize("db_base", ["", ".", "..", "data/..", "data/.", "C:/srv/repo/."])
def test_build_shard_specs_refuses_a_base_with_no_stem_for_several_engine_shards(
    db_base: str,
) -> None:
    """A server store's [store].path may name a directory. With --db no longer defaulted (BACKLOG
    #5817) that path is the base, and "" or a last part of "." or ".." has no stem for each engine
    shard's ``<stem>_<shard>`` name, so several engine shards are refused; one keeps the bare
    base, as a plain `serve` does."""
    with pytest.raises(ValueError, match=_NO_STEM):
        build_shard_specs(["a", "b"], config="c", db_base=db_base, base_port=8765)
    (single,) = build_shard_specs(["a"], config="c", db_base=db_base, base_port=8765)
    assert single.db_path == db_base


@pytest.mark.parametrize(
    ("db_base", "names"),
    [
        pytest.param("site.db", ["site_a.db", "site_b.db"], id="file"),
        pytest.param("state/", ["state_a", "state_b"], id="trailing-separator"),
        pytest.param("C:/mefor/state/", ["state_a", "state_b"], id="absolute-trailing-separator"),
    ],
)
def test_build_shard_specs_derives_names_from_a_base_with_a_stem(
    db_base: str, names: list[str]
) -> None:
    """A trailing separator after a real name is not refused: the name before it is the stem, as
    on origin/main before BACKLOG #5817."""
    specs = build_shard_specs(["a", "b"], config="c", db_base=db_base, base_port=8765)
    assert [Path(s.db_path).name for s in specs] == names


def test_each_engine_shard_gets_its_store_path_as_one_argv_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A [store].path such as "-x.db" now reaches each engine shard from the settings (BACKLOG
    #5817). As its own token after --db, argparse would take it for an option; as --db=<path> the
    engine shard's own parser reads it as the store path."""
    from messagefoundry import __main__ as cli

    monkeypatch.delenv("MEFOR_STORE_PATH", raising=False)
    monkeypatch.delenv("MEFOR_API_PORT", raising=False)
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text('[store]\npath = "-x.db"\n', encoding="utf-8")
    # Under a project root, so the TLS pair the start mints lands in tmp_path, not the cwd.
    root = tmp_path / "repo"
    root.mkdir()
    argv = ["--service-config", str(svc), "--project-root", str(root)]
    captured = _supervise_captured(tmp_path, monkeypatch, argv)
    db_base = str(captured["db_base"])
    assert db_base == str(root / "-x.db")
    # With no project root the base stays as written, leading "-" and all.
    for base, shards in [(b, s) for b in (db_base, "-x.db") for s in (["a"], ["a", "b"])]:
        for spec in build_shard_specs(shards, config="c", db_base=base, base_port=8765):
            serve_argv = list(spec.argv)[list(spec.argv).index("serve") :]
            args = cli._build_parser()[0].parse_args(serve_argv)
            assert args.db == spec.db_path, serve_argv
            assert args.port == spec.port


def test_supervise_refuses_an_api_port_no_socket_takes_before_the_tls_renewal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """[api].port is now the default base (BACKLOG #5817) and has no range check at load, so
    supervise refuses a value no socket takes before the TLS renewal can write anything."""
    from messagefoundry import __main__ as cli

    def _no_renewal(*args: object, **kwargs: object) -> Path:
        raise AssertionError("the TLS renewal ran before the port refusal")

    monkeypatch.setattr(cli, "_renew_api_tls_before_spawning", _no_renewal)
    monkeypatch.delenv("MEFOR_API_PORT", raising=False)
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text('[store]\npath = "site.db"\n\n[api]\nport = 70000\n', encoding="utf-8")
    args = cli._build_parser()[0].parse_args(
        ["supervise", "--env", "prod", "--service-config", str(svc)]
    )
    assert cli._supervise(args) == 2
    err = capsys.readouterr().err
    assert "[api].port 70000 is not a port from 0 to 65535" in err, err


class _AtTheRenewal(Exception):
    """Raised in place of the TLS renewal, so a test reads the base the supervisor derived."""


@pytest.mark.parametrize("path", ["", "state/", "."])
def test_supervise_keeps_a_directory_shaped_store_path_through_the_root_join(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    """Joining "" or "." under --project-root gives the root itself, whose name would become each
    engine shard's stem; the supervisor keeps it stemless, so several engine shards are refused
    (BACKLOG #5817). "state/" keeps deriving from "state", as before."""
    from messagefoundry import __main__ as cli
    from messagefoundry.store.crypto import generate_key
    from tests._phi_gate_provisions import (
        make_syslog_ca_and_crl,
        setenv_declared_egress,
        setenv_verified_log_forwarding,
    )

    seen: list[str] = []

    def _at_renewal(settings: object, db_base: str) -> Path:
        seen.append(db_base)
        raise _AtTheRenewal

    monkeypatch.setattr(cli, "_renew_api_tls_before_spawning", _at_renewal)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    setenv_verified_log_forwarding(monkeypatch, make_syslog_ca_and_crl(tmp_path))
    setenv_declared_egress(monkeypatch)
    monkeypatch.setattr(cli, "configure_logging", lambda *args, **kwargs: False)
    monkeypatch.delenv("MEFOR_STORE_PATH", raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text(
        f'[store]\nbackend = "postgres"\npath = "{path}"\nserver = "db.example.invalid"\n'
        'database = "mf"\nusername = "mefor"\n',
        encoding="utf-8",
    )
    argv = ["supervise", "--env", "prod", "--service-config", str(svc)]
    args = cli._build_parser()[0].parse_args([*argv, "--project-root", str(root)])
    with pytest.raises(_AtTheRenewal):
        cli._supervise(args)
    (db_base,) = seen
    if path == "state/":
        # A real name before the separator: derived from, as on origin/main, under the root.
        specs = build_shard_specs(["a", "b"], config="c", db_base=db_base, base_port=8765)
        assert [Path(s.db_path) for s in specs] == [root / "state_a", root / "state_b"]
        return
    # "" and "." join to the root itself; the base still names no stem, so several engine
    # shards are refused, and one engine shard's --db still names the root.
    assert Path(db_base) == root, db_base
    with pytest.raises(ValueError, match=_NO_STEM):
        build_shard_specs(["a", "b"], config="c", db_base=db_base, base_port=8765)


@pytest.mark.parametrize(
    ("shards", "base_port", "refused"),
    [
        pytest.param(["a"], 0, False, id="one-shard-ephemeral"),
        pytest.param(["a"], 65535, False, id="one-shard-65535"),
        pytest.param(["a"], 65536, True, id="one-shard-past-65535"),
        pytest.param(["a"], -1, True, id="one-shard-negative"),
        pytest.param(["a", "b"], 0, True, id="two-shards-from-zero"),
        pytest.param(["a", "b"], 65534, False, id="last-port-65535"),
        pytest.param(["a", "b"], 65535, True, id="past-65535"),
        pytest.param(["a", "b"], 1, False, id="from-one"),
    ],
)
def test_build_shard_specs_refuses_ports_no_engine_shard_can_bind(
    shards: list[str], base_port: int, refused: bool
) -> None:
    """With [api].port now the default base (BACKLOG #5817), a value serve accepts for its one
    socket, such as 0, would number several engine shards' ports from it."""
    if refused:
        with pytest.raises(ValueError, match=r"from [01] to 65535"):
            build_shard_specs(shards, config="c", db_base="m.db", base_port=base_port)
    else:
        specs = build_shard_specs(shards, config="c", db_base="m.db", base_port=base_port)
        assert [s.port for s in specs] == [base_port + i for i in range(len(shards))]


# --- lifecycle (fake process) ------------------------------------------------


def _spawner(
    fn: Callable[[ShardSpec], Awaitable[_FakeProcess]],
) -> Callable[[ShardSpec], Awaitable[asyncio.subprocess.Process]]:
    """Hand Supervisor a fake spawn. The fakes stand in for asyncio's Process and answer every call
    Supervisor makes on one; that is the whole of the claim this return type makes."""
    return fn  # type: ignore[return-value]


class _FakeProcess:
    """A controllable stand-in for asyncio.subprocess.Process.

    ``wait()`` blocks until ``finish(rc)`` is called (simulating a child exit / crash). ``terminate()``
    finishes it with rc=-15; ``kill()`` with rc=-9. ``returncode`` is None until it finishes."""

    _next_pid = 1000

    def __init__(self) -> None:
        type(self)._next_pid += 1
        self.pid = type(self)._next_pid
        self.returncode: int | None = None
        self._exited = asyncio.Event()
        self.terminated = False
        self.killed = False

    def finish(self, rc: int = 0) -> None:
        if self.returncode is None:
            self.returncode = rc
            self._exited.set()

    async def wait(self) -> int:
        await self._exited.wait()
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.finish(-15)

    def kill(self) -> None:
        self.killed = True
        self.finish(-9)


def _spec(shard: str, port: int = 8765) -> ShardSpec:
    return ShardSpec(shard=shard, db_path=f"{shard}.db", port=port, argv=("python", shard))


async def _no_wait(delay: float) -> None:
    """A backoff sleep that returns at once, for tests that are not about the delay."""


@pytest.mark.asyncio
async def test_spawns_one_child_per_shard_then_stops_cleanly() -> None:
    spawned: list[_FakeProcess] = []

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        spawned.append(p)
        return p

    sup = Supervisor(
        [_spec("a", 8765), _spec("b", 8766)], spawn=_spawner(spawn), terminate_grace=2.0
    )
    run = asyncio.create_task(sup.run())
    # Let both children spawn.
    for _ in range(50):
        if len(spawned) == 2:
            break
        await asyncio.sleep(0)
    assert len(spawned) == 2

    sup.stop()
    run.cancel()
    with pytest.raises(asyncio.CancelledError):
        await run
    # Every child was terminated on shutdown.
    assert all(p.terminated for p in spawned)


@pytest.mark.asyncio
async def test_restarts_a_crashed_child() -> None:
    spawned: list[_FakeProcess] = []

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        spawned.append(p)
        return p

    sup = Supervisor(
        [_spec("a")],
        spawn=_spawner(spawn),
        restart=True,
        terminate_grace=2.0,
        sleep=_no_wait,  # the restart backoff has its own tests below
    )
    run = asyncio.create_task(sup.run())
    while not spawned:
        await asyncio.sleep(0)

    # First child crashes -> the supervisor must spawn a replacement.
    spawned[0].finish(1)
    for _ in range(100):
        if len(spawned) == 2:
            break
        await asyncio.sleep(0)
    assert len(spawned) == 2
    assert sup.restarts["a"] == 1

    sup.stop()
    run.cancel()
    with pytest.raises(asyncio.CancelledError):
        await run


@pytest.mark.asyncio
async def test_no_restart_when_disabled() -> None:
    spawned: list[_FakeProcess] = []

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        spawned.append(p)
        return p

    sup = Supervisor([_spec("a")], spawn=_spawner(spawn), restart=False)
    run = asyncio.create_task(sup.run())
    while not spawned:
        await asyncio.sleep(0)

    spawned[0].finish(0)  # clean exit; restart disabled -> the watcher returns
    await asyncio.wait_for(run, timeout=2.0)  # run() completes once the only watcher returns
    assert len(spawned) == 1
    assert "a" not in sup.restarts


# --- BACKLOG #1557: stop() wakes supervision, and the launch makes a request deliverable ----


@pytest.mark.asyncio
async def test_stop_alone_drains_children_without_cancelling_run() -> None:
    """``stop()`` on its own must finish ``run()`` and drain the children.

    Nothing cancels the runner here, and that is the whole point: before the fix the watchers stayed
    blocked in ``child.process.wait()``, the event that ``stop()`` sets woke nobody, and ``run()``
    sat in ``gather`` until something else cancelled it. A responsive child needs no force, so no
    child may be killed.
    """
    spawned: list[_FakeProcess] = []

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        spawned.append(p)
        return p

    sup = Supervisor(
        [_spec("a", 8765), _spec("b", 8766)], spawn=_spawner(spawn), terminate_grace=2.0
    )
    run = asyncio.create_task(sup.run())
    for _ in range(50):
        if len(spawned) == 2:
            break
        await asyncio.sleep(0)
    assert len(spawned) == 2

    sup.stop()
    await asyncio.wait_for(run, timeout=5.0)  # completes on its own — no cancellation
    assert all(p.terminated for p in spawned)
    assert not any(p.killed for p in spawned)


@pytest.mark.asyncio
async def test_stop_requests_then_waits_then_forces() -> None:
    """The escalation is request, then the bounded wait, then force — in that order.

    Driven by ``stop()`` alone, so it also pins that the ordered drain is reachable without a
    cancellation. The child ignores the request, which is what makes the force observable.
    """
    events: list[tuple[str, float]] = []
    loop = asyncio.get_running_loop()

    class _Stubborn(_FakeProcess):
        def terminate(self) -> None:  # the cooperative request — deliberately ignored
            events.append(("request", loop.time()))
            self.terminated = True

        def kill(self) -> None:
            events.append(("force", loop.time()))
            super().kill()

    proc = _Stubborn()

    async def spawn(spec: ShardSpec) -> _Stubborn:
        return proc

    grace = 0.05
    sup = Supervisor([_spec("a")], spawn=_spawner(spawn), terminate_grace=grace)
    run = asyncio.create_task(sup.run())
    for _ in range(50):
        if "a" in sup._children:
            break
        await asyncio.sleep(0)
    assert "a" in sup._children

    sup.stop()
    await asyncio.wait_for(run, timeout=5.0)
    assert [name for name, _ in events] == ["request", "force"]
    assert events[1][1] - events[0][1] >= grace  # the bounded wait really sat between them


@pytest.mark.asyncio
async def test_default_spawn_gives_windows_children_their_own_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The launch flag is asserted STRUCTURALLY, by reading the creation flags.

    Never by firing a console control event at a child launched WITHOUT the flag: such an event
    reaches every process attached to the console, the sender included, so that negative control
    would kill the test runner instead of failing a test.
    """
    captured: dict[str, Any] = {}

    class _Started:
        pid = 4242

    async def fake_exec(*argv: str, **kwargs: Any) -> object:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _Started()

    def fake_resume(pid: int, *, who: str) -> None:
        captured["resumed"] = pid

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(proctree, "resume_into_job", fake_resume)
    await _default_spawn(_spec("a"))

    assert captured["argv"] == ("python", "a")
    flags = captured["kwargs"].get("creationflags")
    if sys.platform == "win32":
        # Suspended too, so the child is in its kill-on-close job before it runs (BACKLOG #5978).
        assert flags == subprocess.CREATE_NEW_PROCESS_GROUP | proctree.ADOPT_CREATIONFLAGS
        assert proctree.ADOPT_CREATIONFLAGS
        assert captured["resumed"] == 4242
    else:
        assert flags is None  # POSIX terminate() is already SIGTERM — no flag needed


#: A disposable synthetic child for the Windows cooperative-stop test. It arms a SIGBREAK handler,
#: announces readiness through a marker file (stdio is inherited, so there is nothing to read back),
#: then polls. Exit 0 = it handled the break; exit 3 = no break ever arrived; exit 1 =
#: TerminateProcess forced it.
_SYNTHETIC_CHILD = (
    "import signal, sys, time, pathlib\n"
    "seen = []\n"
    "signal.signal(signal.SIGBREAK, lambda *_: seen.append(1))\n"
    "pathlib.Path(sys.argv[1]).write_text('ready')\n"
    "for _ in range(200):\n"
    "    if seen:\n"
    "        sys.exit(0)\n"
    "    time.sleep(0.05)\n"
    "sys.exit(3)\n"
)


@pytest.mark.skipif(sys.platform != "win32", reason="CTRL_BREAK is a Windows console control event")
@pytest.mark.asyncio
async def test_windows_child_stops_on_the_cooperative_break(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """End-to-end Windows validation with a DISPOSABLE synthetic child — never a real service.

    The child is launched by the REAL ``_default_spawn``, so it carries the real
    ``CREATE_NEW_PROCESS_GROUP`` and the supervisor sends it a real ``CTRL_BREAK``. Nothing here may
    skip: a refused send must FAIL, because a skip would be green while proving nothing about the
    only path this row exists to close.
    """
    marker = tmp_path / "ready.txt"
    spec = ShardSpec(
        shard="synthetic",
        db_path=str(tmp_path / "unused.db"),
        port=0,
        argv=(sys.executable, "-c", _SYNTHETIC_CHILD, str(marker)),
    )
    sup = Supervisor([spec], restart=False, terminate_grace=10.0)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.supervisor"):
        run = asyncio.create_task(sup.run())
        try:
            for _ in range(400):  # the child writes the marker once its handler is armed
                if marker.exists():
                    break
                await asyncio.sleep(0.05)
            assert marker.exists(), "the synthetic child never armed its SIGBREAK handler"
            sup.stop()
            await asyncio.wait_for(run, timeout=30.0)
        finally:
            if not run.done():
                run.cancel()
                await asyncio.gather(run, return_exceptions=True)

    assert "CTRL_BREAK" not in caplog.text, f"the cooperative send was refused: {caplog.text}"
    # 0 = the child's own SIGBREAK handler ran; 1 = TerminateProcess forced it; 3 = no break arrived.
    assert sup._children["synthetic"].process.returncode == 0


@pytest.mark.asyncio
async def test_terminate_escalates_to_kill_after_grace() -> None:
    class _StubbornProcess(_FakeProcess):
        def terminate(self) -> None:  # ignore terminate -> force the kill escalation path
            self.terminated = True

    proc = _StubbornProcess()

    async def spawn(spec: ShardSpec) -> _StubbornProcess:
        return proc

    # A tiny grace so the kill-after-timeout path runs fast.
    sup = Supervisor([_spec("a")], spawn=_spawner(spawn), terminate_grace=0.05)
    run = asyncio.create_task(sup.run())
    for _ in range(50):
        if "a" in sup._children:  # wait until the child is spawned + registered
            break
        await asyncio.sleep(0)
    assert "a" in sup._children

    sup.stop()
    run.cancel()
    with pytest.raises(asyncio.CancelledError):
        await run
    assert proc.terminated and proc.killed  # escalated to kill after the grace elapsed


# --- BACKLOG #5978: the drain waits once, and a Windows engine shard ends with its supervisor ----


@pytest.mark.skipif(sys.platform != "win32", reason="the suspended launch is Windows only")
@pytest.mark.parametrize(
    "refusal", [PermissionError("access denied"), OSError(6, "the handle is invalid")]
)
@pytest.mark.asyncio
async def test_a_failed_resume_whose_kill_is_refused_does_not_hang_the_launch(
    refusal: OSError, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A suspended engine shard that cannot be resumed, and whose kill is refused with no job to
    end it, never exits. The launch still raises the resume error after a bounded wait, and says
    the process was left behind."""

    class _Stuck:
        pid = 4242

        def kill(self) -> None:
            raise refusal

        async def wait(self) -> int:
            await asyncio.Event().wait()  # never exits
            return 0

    async def fake_exec(*argv: str, **kwargs: Any) -> _Stuck:
        return _Stuck()

    def fake_resume(pid: int, *, who: str) -> None:
        raise OSError("resume refused")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(proctree, "resume_into_job", fake_resume)
    monkeypatch.setattr(supervisor_mod, "_UNRESUMED_EXIT_WAIT", 0.05)
    caplog.set_level(logging.WARNING, logger=supervisor_mod.logger.name)
    with pytest.raises(OSError, match="resume refused"):
        await asyncio.wait_for(_default_spawn(_spec("a")), timeout=5.0)
    assert "could not kill its unresumed process" in caplog.text
    assert "4242 did not exit" in caplog.text


@pytest.mark.asyncio
async def test_hung_children_wait_out_one_grace_together_not_one_each() -> None:
    """Every hung child's grace wait starts before any child is forced.

    Waiting for each in turn made a drain take one grace period per hung child, so a service
    manager's stop timeout could run out with engine shards still up. Read by event order, not by time."""
    events: list[str] = []
    asked: set[int] = set()

    class _Hung(_FakeProcess):
        def __init__(self, name: str) -> None:
            super().__init__()
            self.name = name

        def terminate(self) -> None:  # the cooperative request, ignored
            asked.add(self.pid)
            self.terminated = True

        async def wait(self) -> int:
            if self.pid in asked and self.returncode is None:
                events.append(f"wait {self.name}")
            return await super().wait()

        def kill(self) -> None:
            events.append(f"force {self.name}")
            super().kill()

    procs = {"a": _Hung("a"), "b": _Hung("b")}

    async def spawn(spec: ShardSpec) -> _Hung:
        return procs[spec.shard]

    sup = Supervisor(
        [_spec("a", 8765), _spec("b", 8766)], spawn=_spawner(spawn), terminate_grace=0.05
    )
    run = asyncio.create_task(sup.run())
    for _ in range(50):
        if len(sup._children) == 2:
            break
        await asyncio.sleep(0)
    assert len(sup._children) == 2

    sup.stop()
    await asyncio.wait_for(run, timeout=5.0)
    first_force = min(i for i, e in enumerate(events) if e.startswith("force"))
    waits_before = {e for e in events[:first_force] if e.startswith("wait")}
    assert waits_before == {"wait a", "wait b"}, events
    assert all(p.killed for p in procs.values())


@pytest.mark.asyncio
async def test_an_exited_engine_shards_job_is_released_and_a_forced_ones_after_its_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An engine shard that exits on its own has its job released before the relaunch, and an
    engine shard forced on the drain has its job released once it is gone. Released, not ended:
    what an engine shard left running on purpose outlives it as it did before the job existed
    (BACKLOG #5978)."""
    released: list[int] = []
    monkeypatch.setattr(proctree, "release_job", released.append)
    spawned: list[_FakeProcess] = []

    class _Hung(_FakeProcess):
        def terminate(self) -> None:  # the request, ignored, so the drain forces it
            self.terminated = True

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess() if not spawned else _Hung()
        spawned.append(p)
        # setitem, so the module-wide map holds none of these fakes after the test, pass or fail.
        monkeypatch.setitem(supervisor_mod._SHARD_JOBS, p, 7000 + len(spawned))  # type: ignore[misc]
        return p

    sup = Supervisor([_spec("a")], spawn=_spawner(spawn), terminate_grace=0.05, sleep=_no_wait)
    run = asyncio.create_task(sup.run())
    while not spawned:
        await asyncio.sleep(0)
    spawned[0].finish(1)
    for _ in range(100):
        if len(spawned) == 2:
            break
        await asyncio.sleep(0)
    assert len(spawned) == 2
    assert released == [7001]  # the exited engine shard's job, before the relaunch's

    sup.stop()
    await asyncio.wait_for(run, timeout=5.0)
    assert spawned[1].killed
    assert released == [7001, 7002]
    assert not any(p in supervisor_mod._SHARD_JOBS for p in spawned)  # type: ignore[comparison-overlap]


#: Long enough that nothing in a tree exits on its own inside the test, short enough that a tree
#: that escaped every cleanup still goes by itself.
_TREE_SLEEP = 90

#: The engine shard child for the Windows job tests: it starts a grandchild, then writes both pids to the
#: marker (renamed into place, so a reader never sees half of it), then sleeps.
_SHARD_WITH_GRANDCHILD = (
    "import os, subprocess, sys, time\n"
    f"g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep({_TREE_SLEEP})'])\n"
    "tmp = sys.argv[1] + '.tmp'\n"
    "with open(tmp, 'w') as f:\n"
    "    f.write(f'{os.getpid()} {g.pid}')\n"
    "os.replace(tmp, sys.argv[1])\n"
    f"time.sleep({_TREE_SLEEP})\n"
)

#: A stand-in supervisor: it launches one engine shard through the REAL ``_default_spawn``, then
#: idles until the test hard-kills it. ``argv[3] == "nojob"`` resumes the engine shard without a
#: job: the control.
_SUPERVISOR_STAND_IN = (
    "import asyncio, os, sys\n"
    "import psutil\n"
    "from messagefoundry import proctree\n"
    "from messagefoundry.pipeline.supervisor import ShardSpec, _default_spawn\n"
    "if sys.argv[3] == 'nojob':\n"
    "    def resume_without_job(pid, *, who):\n"
    "        psutil.Process(pid).resume()\n"
    "    proctree.resume_into_job = resume_without_job\n"
    "async def main():\n"
    "    with open(sys.argv[2] + '.sup.tmp', 'w') as f:\n"
    "        f.write(str(os.getpid()))\n"
    "    os.replace(sys.argv[2] + '.sup.tmp', sys.argv[2] + '.sup')\n"
    "    argv = (sys.executable, '-c', sys.argv[1], sys.argv[2])\n"
    "    await _default_spawn(ShardSpec(shard='s', db_path='unused', port=0, argv=argv))\n"
    f"    await asyncio.sleep({_TREE_SLEEP})\n"
    "asyncio.run(main())\n"
)


def _hard_kill_a_stand_in(tmp_path: Path, mode: str) -> tuple[list[Any], list[Any]]:
    """Start a stand-in supervisor in ``mode``, hard-kill it once its engine shard tree is up, and
    return the engine shard tree and every process this started, the stand-in's own included, for cleanup.

    Every process here is this test's own, and each is killed by its pid, never by image name. The
    stand-in's whole chain is killed (the venv launcher and the interpreter under it), with no
    chance to run any cleanup, as a hard kill or a service manager's forced stop would end it."""
    import time

    import psutil

    from tests._proc_tree import kill_all, tree_of, wait_until

    root = Path(__file__).resolve().parents[1]
    marker = tmp_path / f"pids-{mode}.txt"
    stand_in = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", _SUPERVISOR_STAND_IN, _SHARD_WITH_GRANDCHILD, str(marker), mode],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root)},
    )
    started = [psutil.Process(stand_in.pid)]
    try:
        deadline = time.monotonic() + 60.0
        while not marker.exists():
            assert stand_in.poll() is None, (
                "the stand-in supervisor exited before its engine shard started"
            )
            assert time.monotonic() < deadline, "the engine shard never wrote its pids"
            time.sleep(0.05)
        supervisor_pid = int(Path(f"{marker}.sup").read_text())
        # The stand-in's own chain: the venv launcher where there is one, and its interpreter.
        chain = [psutil.Process(pid) for pid in dict.fromkeys((stand_in.pid, supervisor_pid))]
        started += chain
        # The engine shard's own launcher (where there is one), its interpreter, and the grandchild
        # with its launcher. A venv launcher starts its interpreter a moment later, so the tree is
        # read until two reads agree; otherwise a late interpreter would escape the census.
        tree: list[Any] = []

        def settled() -> bool:
            nonlocal tree
            before = {p.pid for p in tree}
            tree = tree_of(supervisor_pid)[1:]
            return bool(before) and before == {p.pid for p in tree}

        wait_until(settled, 10.0)
        started += tree
        reported = {int(pid) for pid in marker.read_text().split()}
        assert reported <= {p.pid for p in tree}, "the engine shard tree is not under the stand-in"
        kill_all(chain)
        stand_in.wait(timeout=10)
        return tree, started
    except BaseException:
        kill_all(started)
        raise


@pytest.mark.skipif(sys.platform != "win32", reason="the kill-on-close job is a Windows job object")
def test_control_without_the_job_an_engine_shard_tree_outlives_its_hard_killed_supervisor(
    tmp_path: Path,
) -> None:
    """The control that arms the test below: with the job left out, the engine shard and its child must
    SURVIVE their killed supervisor. Otherwise a pass below could come from something else ending
    the tree, such as a job the test runner sits in, and would show nothing about this one."""
    import time

    from tests._proc_tree import alive, kill_all

    tree, started = _hard_kill_a_stand_in(tmp_path, "nojob")
    try:
        time.sleep(1.0)
        assert len(alive(tree)) == len(tree), (
            "THE CONTROL DID NOT LEAK; the test below proves nothing"
        )
    finally:
        kill_all(started)


@pytest.mark.skipif(sys.platform != "win32", reason="the kill-on-close job is a Windows job object")
def test_a_hard_killed_windows_supervisor_takes_its_engine_shards_with_it(tmp_path: Path) -> None:
    """Hard-kill a supervisor process, as a service manager's forced stop would, and its engine
    shard and that engine shard's own child must end too. Without the job both outlive it (BACKLOG #5978)."""
    from tests._proc_tree import alive, describe, kill_all, wait_until

    tree, started = _hard_kill_a_stand_in(tmp_path, "job")
    try:
        wait_until(lambda: not alive(tree), 10.0)
        survivors = alive(tree)
        assert not survivors, "outlived their supervisor:\n" + describe(survivors)
    finally:
        kill_all(started)


# --- vault BACKLOG #2773: restart backoff and the crash-loop breaker -------------------------------


class _FakeTime:
    """An injected clock and sleep. ``sleep`` records each delay and moves the clock past it at once,
    so a crash loop runs in no real time and its delays can be read back exactly."""

    def __init__(self) -> None:
        self.now = 0.0
        self.delays: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, delay: float) -> None:
        self.delays.append(delay)
        self.now += delay


def _exiting_at_once(
    time_: _FakeTime, uptimes: list[float], spawned: list[_FakeProcess]
) -> Callable[[ShardSpec], Awaitable[_FakeProcess]]:
    """A spawn whose children exit with rc=3 as soon as they start, the Nth one after running for
    ``uptimes[N]`` seconds of the fake clock (0 once the list runs out)."""

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        time_.now += uptimes[len(spawned)] if len(spawned) < len(uptimes) else 0.0
        spawned.append(p)
        p.finish(3)
        return p

    return spawn


async def test_a_child_that_exits_at_once_backs_off_then_trips_the_breaker(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Each fast exit doubles the delay up to the cap, and the fifth in a row stops the relaunching.
    The supervisor then ends on its own, because its only watcher has, and the ERROR line says why."""
    time_ = _FakeTime()
    spawned: list[_FakeProcess] = []
    sup = Supervisor(
        [_spec("a")],
        spawn=_spawner(_exiting_at_once(time_, [], spawned)),
        restart_backoff_initial=1.0,
        restart_backoff_max=4.0,
        stable_uptime=60.0,
        crash_loop_limit=5,
        clock=time_.clock,
        sleep=time_.sleep,
    )
    with caplog.at_level(logging.WARNING, logger=supervisor_mod.__name__):
        await asyncio.wait_for(sup.run(), timeout=5.0)

    assert time_.delays == [1.0, 2.0, 4.0, 4.0]  # doubling, capped at restart_backoff_max
    assert len(spawned) == 5  # the fifth fast exit tripped the breaker; no sixth launch
    assert sup.crash_looped == {"a"}
    assert sup.restarts["a"] == 4
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "crash loop" in errors[0].getMessage()


async def test_a_stable_run_resets_the_backoff_and_the_breaker() -> None:
    """The third child runs for longer than ``stable_uptime``. Its exit resets the count, so the
    breaker (limit 3) trips at the sixth exit and not the third, and the delay starts over."""
    time_ = _FakeTime()
    spawned: list[_FakeProcess] = []
    sup = Supervisor(
        [_spec("a")],
        spawn=_spawner(_exiting_at_once(time_, [0.0, 0.0, 120.0], spawned)),
        restart_backoff_initial=1.0,
        restart_backoff_max=60.0,
        stable_uptime=60.0,
        crash_loop_limit=3,
        clock=time_.clock,
        sleep=time_.sleep,
    )
    await asyncio.wait_for(sup.run(), timeout=5.0)

    assert len(spawned) == 6
    assert time_.delays == [1.0, 2.0, 1.0, 1.0, 2.0]
    assert sup.crash_looped == {"a"}
    assert sup.restarts["a"] == 5


async def test_stop_during_the_backoff_ends_the_watcher_without_a_relaunch() -> None:
    """The delay races the stop request, as the child's exit does, so a supervisor told to stop while
    a shard is backing off returns at once instead of sleeping the delay out and relaunching."""
    spawned: list[_FakeProcess] = []
    asleep = asyncio.Event()

    async def sleep_forever(delay: float) -> None:
        asleep.set()
        await asyncio.Event().wait()

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        spawned.append(p)
        return p

    sup = Supervisor([_spec("a")], spawn=_spawner(spawn), sleep=sleep_forever)
    run = asyncio.create_task(sup.run())
    while not spawned:
        await asyncio.sleep(0)
    spawned[0].finish(1)
    await asyncio.wait_for(asleep.wait(), timeout=2.0)

    sup.stop()
    await asyncio.wait_for(run, timeout=2.0)
    assert len(spawned) == 1
    assert sup.crash_looped == set()
    assert "a" not in sup.restarts  # the relaunch never ran, so it is not counted


async def test_a_launch_that_raises_counts_as_a_fast_exit() -> None:
    """A spawn that raises OSError backs off and trips the breaker like a child that exits at once.
    The breaker is per shard: the healthy sibling keeps running until a clean stop drains it."""
    time_ = _FakeTime()
    attempts: list[str] = []
    healthy: list[_FakeProcess] = []

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        if spec.shard == "a":
            attempts.append(spec.shard)
            raise OSError("no file handles")
        p = _FakeProcess()
        healthy.append(p)
        return p

    sup = Supervisor(
        [_spec("a"), _spec("b", 8766)],
        spawn=_spawner(spawn),
        crash_loop_limit=3,
        clock=time_.clock,
        sleep=time_.sleep,
    )
    run = asyncio.create_task(sup.run())
    try:
        for _ in range(200):
            if sup.crash_looped:
                break
            await asyncio.sleep(0)
        assert sup.crash_looped == {"a"}
        assert len(attempts) == 3
        assert time_.delays == [1.0, 2.0]
        for _ in range(20):  # a few more turns: nothing relaunches a, nothing stops b
            await asyncio.sleep(0)
        assert len(attempts) == 3
        assert not run.done()
        assert len(healthy) == 1 and not healthy[0].terminated
    finally:
        sup.stop()
        await asyncio.wait_for(run, timeout=2.0)
    assert healthy[0].terminated  # the clean stop still drains the sibling


async def test_a_watcher_that_raises_still_drains_the_other_shards() -> None:
    """With restart off, a launch failure is not counted; it propagates. run() must still ask the
    sibling shard to stop before the exception goes on, rather than leave it running."""
    healthy: list[_FakeProcess] = []

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        if spec.shard == "a":
            await asyncio.sleep(0)  # let b start first
            raise OSError("no file handles")
        p = _FakeProcess()
        healthy.append(p)
        return p

    sup = Supervisor([_spec("a"), _spec("b", 8766)], spawn=_spawner(spawn), restart=False)
    with pytest.raises(OSError, match="no file handles"):
        await asyncio.wait_for(sup.run(), timeout=5.0)
    assert len(healthy) == 1 and healthy[0].terminated


@pytest.mark.parametrize(
    ("knob", "value"),
    [
        ("crash_loop_limit", 0),
        ("crash_loop_limit", float("inf")),
        ("stable_uptime", 0.0),
        ("stable_uptime", -1.0),
        ("stable_uptime", float("nan")),
        ("restart_backoff_initial", 0.0),
        ("restart_backoff_initial", -1.0),
        ("restart_backoff_max", float("nan")),
    ],
)
def test_a_setting_that_would_switch_the_protection_off_is_refused(knob: str, value: float) -> None:
    with pytest.raises(ValueError, match=knob):
        Supervisor([_spec("a")], **{knob: value})  # type: ignore[arg-type]  # one knob per case


async def _stop(task: asyncio.Task[int], failure: BaseException) -> None:
    """On a test's failure path, cancel ``task`` and note its outcome on ``failure``.

    The assert that failed stays the reported error. ``supervise`` discovers engine shards in a
    worker thread (BACKLOG #3402 round 3), so a cancel can land on that await and raise
    ``CancelledError`` out of ``supervise``, which awaiting the task would report instead. The wait
    is ``asyncio.wait`` because it is bounded even for a task that absorbs the cancel, where
    ``wait_for`` waits for the task to finish."""
    task.cancel()
    done, _ = await asyncio.wait({task}, timeout=5.0)
    if not done:
        failure.add_note("supervise was still running 5 s after the cancel")
    elif task.cancelled():
        pass
    elif (exc := task.exception()) is not None:
        failure.add_note(f"supervise raised {exc!r}")
    else:
        failure.add_note(f"supervise returned {task.result()}")


async def test_a_cancel_during_discovery_stops_supervise_before_it_spawns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovery runs in a worker thread, so the loop stays live while it runs, and a cancel ends the
    ``supervise`` coroutine at once with ``CancelledError``, before it builds a supervisor. The
    cancel does not stop the thread: it runs discovery to its end, and ``asyncio.run`` waits for it
    when the loop closes. Before round 3 discovery held the loop, so a cancel took effect only once
    discovery had returned."""
    entered = threading.Event()
    release = threading.Event()
    returned = threading.Event()

    def discover(*_a: object, **_k: object) -> list[ShardSpec]:
        entered.set()
        release.wait(timeout=5.0)
        returned.set()
        return [_spec("a")]

    async def _loads(config: str) -> None:
        return None

    def _supervisor(specs: list[ShardSpec]) -> Supervisor:
        raise AssertionError("supervise went on to build a supervisor")

    monkeypatch.setattr(supervisor_mod, "discover_shard_specs", discover)
    monkeypatch.setattr(supervisor_mod, "preflight_shard_config", _loads)
    monkeypatch.setattr(supervisor_mod, "Supervisor", _supervisor)

    task = asyncio.create_task(supervise("cfg", install_signal_handlers=False, **_DISCOVERY))
    try:
        await until(entered.is_set, "discovery entering its worker thread")
        # Off the loop, discovery is still blocked in its thread when control comes back here. Had
        # discovery held the loop, control would come back only after it returned.
        assert not returned.is_set(), "discovery ran on the event loop"
        assert not task.done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2.0)
    except BaseException as failure:
        release.set()  # first, or a supervise still awaiting the thread waits out its timeout
        await _stop(task, failure)
        raise
    finally:
        release.set()


async def test_supervise_exits_nonzero_when_every_shard_crash_loops(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A fleet whose every shard tripped the breaker is not a clean shutdown, so supervise must not
    return the clean-shutdown 0 for it."""
    time_ = _FakeTime()
    spawned: list[_FakeProcess] = []
    real = Supervisor

    def _supervisor(specs: list[ShardSpec]) -> Supervisor:
        return real(
            specs,
            spawn=_spawner(_exiting_at_once(time_, [], spawned)),
            crash_loop_limit=2,
            clock=time_.clock,
            sleep=time_.sleep,
        )

    async def _loads(config: str) -> None:
        return None

    monkeypatch.setattr(supervisor_mod, "discover_shard_specs", lambda *a, **k: [_spec("a")])
    monkeypatch.setattr(supervisor_mod, "preflight_shard_config", _loads)
    monkeypatch.setattr(supervisor_mod, "Supervisor", _supervisor)

    with caplog.at_level(logging.ERROR, logger=supervisor_mod.__name__):
        code = await asyncio.wait_for(
            supervise("cfg", install_signal_handlers=False, **_DISCOVERY), timeout=5.0
        )
    assert code == 1
    assert len(spawned) == 2
    assert "whole fleet is down" in caplog.text


async def test_supervise_keeps_running_while_any_shard_is_alive(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Shard a crash-loops and trips; shard b is healthy. supervise does not return, and a later
    shutdown is a clean one (0) whose last ERROR line still names a as down."""
    time_ = _FakeTime()
    healthy: list[_FakeProcess] = []
    built: list[Supervisor] = []
    real = Supervisor

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        if spec.shard == "a":
            p.finish(3)
        else:
            healthy.append(p)
        return p

    def _supervisor(specs: list[ShardSpec]) -> Supervisor:
        sup = real(
            specs, spawn=_spawner(spawn), crash_loop_limit=2, clock=time_.clock, sleep=time_.sleep
        )
        built.append(sup)
        return sup

    async def _loads(config: str) -> None:
        return None

    monkeypatch.setattr(
        supervisor_mod, "discover_shard_specs", lambda *a, **k: [_spec("a"), _spec("b", 8766)]
    )
    monkeypatch.setattr(supervisor_mod, "preflight_shard_config", _loads)
    monkeypatch.setattr(supervisor_mod, "Supervisor", _supervisor)

    with caplog.at_level(logging.ERROR, logger=supervisor_mod.__name__):
        task = asyncio.create_task(supervise("cfg", install_signal_handlers=False, **_DISCOVERY))
        try:
            # Real time, not a tick count: discovery returns from a worker thread, which a loaded
            # runner can schedule after any fixed number of loop ticks (BACKLOG #3402).
            await until(
                lambda: task.done() or bool(built and built[0].crash_looped),
                "engine shard a tripping the breaker, or supervise returning",
            )
            assert built and built[0].crash_looped == {"a"}
            for _ in range(20):
                await asyncio.sleep(0)
            assert not task.done()  # b is alive, so the supervisor runs on
            assert len(healthy) == 1 and not healthy[0].terminated
        except BaseException as failure:
            await _stop(task, failure)
            raise
        # Stands in for the signal handler, which cancels the inner runner; supervise handles both
        # cancellations through the same except arm.
        task.cancel()
        code = await asyncio.wait_for(task, timeout=2.0)
    assert code == 0
    assert healthy[0].terminated
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 2
    assert (
        "'a'" in errors[0] and "rc=3" in errors[0] and "1 other shard(s) still running" in errors[0]
    )
    assert "a down after a crash loop" in errors[1]
    assert not any("whole fleet" in e for e in errors)


@pytest.mark.parametrize("names", [("EAST", "WEST"), ("East", "West")], ids=["caps", "title"])
@pytest.mark.parametrize("survivor", [False, True], ids=["whole-fleet", "one-alive"])
async def test_supervise_names_two_crash_looped_engine_shards_past_the_log_redaction(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    names: tuple[str, str],
    survivor: bool,
) -> None:
    """Two engine shards trip the breaker, and the closing ERROR line must still name both once the
    log's PHI pass has read it (vault BACKLOG #3227). That pass takes two capitalized words around a
    comma for a family-comma-given name, so ``EAST, WEST`` reached the log as ``[redacted]``. Both
    closing lines are held: every engine shard down, and two down beside one still alive."""
    time_ = _FakeTime()
    built: list[Supervisor] = []
    real = Supervisor

    async def spawn(spec: ShardSpec) -> _FakeProcess:
        p = _FakeProcess()
        if spec.shard in names:
            p.finish(3)
        return p

    def _supervisor(specs: list[ShardSpec]) -> Supervisor:
        sup = real(
            specs, spawn=_spawner(spawn), crash_loop_limit=2, clock=time_.clock, sleep=time_.sleep
        )
        built.append(sup)
        return sup

    async def _loads(config: str) -> None:
        return None

    specs = [_spec(name, 8765 + i) for i, name in enumerate(names)]
    if survivor:
        specs.append(_spec("spare", 8799))
    monkeypatch.setattr(supervisor_mod, "discover_shard_specs", lambda *a, **k: specs)
    monkeypatch.setattr(supervisor_mod, "preflight_shard_config", _loads)
    monkeypatch.setattr(supervisor_mod, "Supervisor", _supervisor)

    with caplog.at_level(logging.INFO, logger=supervisor_mod.__name__):
        task = asyncio.create_task(supervise("cfg", install_signal_handlers=False, **_DISCOVERY))
        try:
            # Real time, not a tick count: discovery returns from a worker thread, which a loaded
            # runner can schedule after any fixed number of loop ticks (BACKLOG #3402).
            await until(
                lambda: task.done() or bool(built and built[0].crash_looped == set(names)),
                "both engine shards tripping the breaker, or supervise returning",
            )
            assert built and built[0].crash_looped == set(names)
            if not survivor:
                # Every engine shard is down, so supervise returns by itself.
                await asyncio.wait_for(task, timeout=5.0)
        except BaseException as failure:
            await _stop(task, failure)
            raise
        # With one engine shard alive supervise runs on, so the cancel stands in for the signal
        # handler. It does nothing to a task that has returned.
        task.cancel()
        code = await asyncio.wait_for(task, timeout=5.0)
    assert code == (0 if survivor else 1)
    closing = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR][-1]
    assert ("down after a crash loop" if survivor else "whole fleet is down") in closing
    logged = redaction.redact(closing)
    assert all(name in logged for name in names), logged
    assert " / ".join(sorted(names)) in logged
    # The opening line joins `name->:port` pairs with a comma, and passes: a port number sits
    # before each comma, so no two names meet around one. Without the ports it would be scrubbed.
    opening = redaction.redact(
        next(r.getMessage() for r in caplog.records if r.getMessage().startswith("supervising "))
    )
    assert all(spec.shard in opening for spec in specs), opening


# --- the pre-flight: a config must load the way an engine shard will load it (vault BACKLOG #2587) -------

_SHARD_GRAPH = """
from messagefoundry import inbound, outbound, router, handler, MLLP, Send
from __HELPER__ import NAME

inbound(NAME, MLLP(port=19471), router="r")
outbound("OB_PREFLIGHT", MLLP(host="127.0.0.1", port=19472))


@router("r")
def r(msg):
    return "h"


@handler("h")
def h(msg):
    return Send("OB_PREFLIGHT", str(msg))
"""

_CWD_HELPER = "mf_b2587_cwd_only_helper"


def _shard_config(tmp_path: Path, helper: str) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "graph.py").write_text(_SHARD_GRAPH.replace("__HELPER__", helper), encoding="utf-8")
    return config


@pytest.mark.asyncio
async def test_a_config_that_needs_the_working_directory_is_refused_before_any_shard_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The config imports a helper that is importable only from the working directory. The
    supervisor's own load finds it; an engine shard would not, and would be restarted for ever. So the
    refusal has to come once, here, before an engine shard exists."""
    config = _shard_config(tmp_path, _CWD_HELPER)
    (tmp_path / f"{_CWD_HELPER}.py").write_text('NAME = "IB_PREFLIGHT"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    # What `python -m messagefoundry supervise` gives the supervisor: the working directory first.
    monkeypatch.syspath_prepend(str(tmp_path))
    built: list[object] = []
    monkeypatch.setattr(supervisor_mod, "Supervisor", lambda specs: built.append(specs))
    try:
        # Control: the supervisor's own load passes, so discovery alone would have started shards.
        assert len(discover_shard_specs(str(config), **_DISCOVERY)) == 1
        with caplog.at_level(logging.ERROR, logger=supervisor_mod.__name__):
            code = await supervise(str(config), install_signal_handlers=False, **_DISCOVERY)
    finally:
        sys.modules.pop(_CWD_HELPER, None)

    assert code == 2
    assert built == []
    assert "`_`-prefixed" in caplog.text
    assert _CWD_HELPER in caplog.text


@pytest.mark.asyncio
async def test_the_preflight_reports_the_exception_whatever_its_message_holds(
    tmp_path: Path,
) -> None:
    """The exception's name arrives; a config module's own message does not (vault BACKLOG #3249),
    however many lines it holds."""
    config = tmp_path / "config"
    config.mkdir()
    (config / "graph.py").write_text(
        'raise ValueError("the first line names the problem\\nthe second line")\n', encoding="utf-8"
    )
    refusal = await preflight_shard_config(str(config))
    assert refusal is not None
    assert "ValueError" in refusal
    assert "the first line" not in refusal and "the second line" not in refusal
    assert "`_`-prefixed" not in refusal  # not an import failure, so no advice about helpers


@pytest.mark.asyncio
async def test_a_config_whose_helper_sits_beside_it_passes_the_preflight(tmp_path: Path) -> None:
    """The control, and the documented layout: the same graph with its helper as a ``_``-prefixed
    file in the config directory."""
    config = _shard_config(tmp_path, "_helper")
    (config / "_helper.py").write_text('NAME = "IB_PREFLIGHT"\n', encoding="utf-8")
    assert await preflight_shard_config(str(config)) is None
