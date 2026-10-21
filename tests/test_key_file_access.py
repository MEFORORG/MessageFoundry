# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Under enforce, an operator's key file a broad group can read refuses the start (BACKLOG #3402).

Two halves, each with a control that gives the opposite answer:

* ``[api].tls_key_file``, or the certificate PEM that holds the key when it is unset, is judged by a
  start gate in ``serve`` and in ``supervise``, beside the gate for the key the engine mints;
* a connection's key file is graph data, judged by an awaited registry preflight, off the event
  loop, at the first load, every real reload and a DR activation, and by ``supervise`` before it
  spawns an engine shard.

Each file is broadened with :func:`tests.test_restricted_file._broaden`, which grants the local
Users group read on Windows and sets mode 0644 on POSIX, so every test here runs on every leg.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry import __main__ as cli
from messagefoundry.__main__ import main
from messagefoundry.config import key_file_access
from messagefoundry.config.key_file_access import (
    connection_key_file_problem,
    connection_key_files,
    make_connection_key_file_preflight,
)
from messagefoundry.config.models import ConnectorType, Priority
from messagefoundry.config.settings import DrSettings, EgressSettings, StoreSettings
from messagefoundry.config.wiring import (
    DICOM,
    MLLP,
    ConnectionSpec,
    Http,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    Soap,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
    env,
)
from messagefoundry.pipeline import Engine
from messagefoundry.restricted_file import write_restricted_file
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key
from tests._harness_engine import free_port
from tests._phi_gate_provisions import PHI_GATE_PROVISIONS_TOML, setenv_declared_egress
from tests.test_api_tls import _self_signed, _self_signed_combined
from tests.test_restricted_file import _broaden

# The two serve gates every enforcing start meets (tests/_phi_gate_provisions.py says why).
pytestmark = pytest.mark.usefixtures("bounded_warn_only_retention", "verified_log_forwarding")

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"
_LOG = logging.getLogger("tests.key_file_access")
_WARN = 'security.enforcement = "warn"\n'


def _key(path: Path, *, broad: bool) -> Path:
    """A stand-in key file at ``path``, created restricted and broadened when ``broad``."""
    write_restricted_file(path, b"KEY-MATERIAL-STAND-IN\n")
    if broad:
        _broaden(path)
    return path


def _registry(
    inbound: Mapping[str, ConnectionSpec] = {}, outbound: Mapping[str, ConnectionSpec] = {}
) -> Registry:
    return Registry(
        inbound={n: InboundConnection(n, s, router="r") for n, s in inbound.items()},
        outbound={n: OutboundConnection(n, s) for n, s in outbound.items()},
    )


# --- which files a graph names ---------------------------------------------------------------------


def test_each_connector_key_setting_is_found_with_env_refs_resolved() -> None:
    remote = ConnectionSpec(
        ConnectorType.REMOTEFILE,
        {"protocol": "ftps", "tls_cert_file": "ftps.crt", "tls_key_file": "ftps.key"},
    )
    registry = _registry(
        inbound={
            "IB_MLLP": MLLP(port=2575, tls=True, tls_cert_file="m.crt", tls_key_file="m.key"),
            "IB_HTTP": Http(port=8443, tls=True, tls_cert_file="h.crt", tls_key_file="h.key"),
            "IB_DICOM": DICOM(
                ae_title="MEFOR",
                port=11112,
                tls=True,
                tls_cert_file="d.crt",
                tls_key_file=env("dkey"),
            ),
        },
        outbound={
            "OB_SOAP": Soap(
                url="https://x.invalid/s", client_cert_file="s.crt", client_key_file="s.key"
            ),
            "OB_FTPS": remote,
        },
    )
    assert connection_key_files(registry, {"dkey": "d.key"}) == [
        ("inbound connection 'IB_DICOM' setting 'tls_key_file'", "d.key"),
        ("inbound connection 'IB_HTTP' setting 'tls_key_file'", "h.key"),
        ("inbound connection 'IB_MLLP' setting 'tls_key_file'", "m.key"),
        ("outbound connection 'OB_FTPS' setting 'tls_key_file'", "ftps.key"),
        ("outbound connection 'OB_SOAP' setting 'client_key_file'", "s.key"),
    ]


def test_a_certificate_holding_its_key_is_judged_and_pem_text_is_never_a_path() -> None:
    registry = _registry(
        inbound={"IB_COMBINED": MLLP(port=2575, tls=True, tls_cert_file="combined.pem")},
        outbound={
            "OB_INLINE": Soap(
                url="https://x.invalid/s",
                client_cert_file="s.crt",
                client_key_file=env("inline_key"),
            ),
            "OB_UNRESOLVED": Soap(
                url="https://x.invalid/s",
                client_cert_file="u.crt",
                client_key_file=env("never_set"),
            ),
        },
    )
    # A stand-in label: the marker alone makes a value PEM text, and no key needs to be in source.
    values = {"inline_key": "-----BEGIN STAND-IN-----\nAAAA\n-----END STAND-IN-----\n"}
    found = connection_key_files(registry, values)
    # The unset key falls back to the certificate the loader reads it from. The inline PEM is key
    # text, not a path. An env() that does not resolve is left to the connection's own build, which
    # names it, and its public certificate is not judged in its place.
    assert found == [("inbound connection 'IB_COMBINED' setting 'tls_cert_file'", "combined.pem")]


def test_a_path_typed_key_is_judged_and_files_without_a_tls_identity_are_not() -> None:
    registry = _registry(
        inbound={
            "IB_PATH": ConnectionSpec(
                ConnectorType.MLLP,
                {"tls": True, "tls_cert_file": "p.crt", "tls_key_file": Path("p.key")},
            ),
            "IB_PLAIN": ConnectionSpec(
                ConnectorType.MLLP,
                {"tls": False, "tls_cert_file": "x.crt", "tls_key_file": "x.key"},
            ),
            "IB_BLANK": ConnectionSpec(
                ConnectorType.MLLP,
                {"tls": True, "tls_cert_file": "b.pem", "tls_key_file": env("blank_key")},
            ),
        },
        outbound={
            "OB_FTPS": ConnectionSpec(
                ConnectorType.REMOTEFILE, {"protocol": "FTPS", "tls_cert_file": "f.pem"}
            ),
            "OB_SFTP": ConnectionSpec(
                ConnectorType.REMOTEFILE, {"protocol": "sftp", "tls_key_file": "s.key"}
            ),
            "OB_KEY_ONLY": ConnectionSpec(
                ConnectorType.MLLP, {"tls": True, "tls_key_file": "k.key"}
            ),
        },
    )
    # A blank key is read from the certificate, so the certificate is judged. Without a TLS
    # identity the loader opens neither file, and a key with no certificate loads no identity. The protocol is read case-blind, as the transport does.
    assert connection_key_files(registry, {"blank_key": ""}) == [
        ("inbound connection 'IB_BLANK' setting 'tls_cert_file'", "b.pem"),
        ("inbound connection 'IB_PATH' setting 'tls_key_file'", "p.key"),
        ("outbound connection 'OB_FTPS' setting 'tls_cert_file'", "f.pem"),
    ]


def test_a_key_path_holding_a_nul_is_refused_not_raised() -> None:
    graph = _registry(
        outbound={
            "OB_SOAP": Soap(
                url="https://x.invalid/s", client_cert_file="s.crt", client_key_file=env("k")
            )
        }
    )
    problem = connection_key_file_problem(graph, {"k": "a\x00b.key"})
    assert problem is not None and "could not be examined" in problem


# --- the registry preflight -----------------------------------------------------------------------


def _soap_graph(key: Path) -> Registry:
    return _registry(
        outbound={
            "OB_SOAP": Soap(
                url="https://x.invalid/s", client_cert_file="s.crt", client_key_file=str(key)
            )
        }
    )


async def test_the_preflight_refuses_a_broad_connection_key_under_enforce(tmp_path: Path) -> None:
    preflight = make_connection_key_file_preflight(enforcing=True, log=_LOG)
    await preflight(_soap_graph(_key(tmp_path / "restricted.key", broad=False)), {})  # the control
    await preflight(_soap_graph(tmp_path / "missing.key"), {})  # left to the connector

    broad = _key(tmp_path / "broad.key", broad=True)
    with pytest.raises(WiringError) as refused:
        await preflight(_soap_graph(broad), {})
    text = str(refused.value)
    assert "outbound connection 'OB_SOAP' setting 'client_key_file'" in text
    assert "is not restricted" in text
    assert str(broad) not in text  # the label names the setting, never the path


async def test_the_preflight_warns_and_passes_under_warn(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    preflight = make_connection_key_file_preflight(enforcing=False, log=_LOG)
    with caplog.at_level(logging.WARNING, logger=_LOG.name):
        await preflight(_soap_graph(_key(tmp_path / "restricted.key", broad=False)), {})  # control
        assert "is not restricted" not in caplog.text
        await preflight(_soap_graph(_key(tmp_path / "broad.key", broad=True)), {})
    assert "'client_key_file' is not restricted" in caplog.text
    assert "warning: the private key file named by outbound connection 'OB_SOAP'" in (
        capsys.readouterr().err
    )


async def test_the_preflight_judges_the_values_it_is_handed(tmp_path: Path) -> None:
    """A reload can change the env() values without a restart. The engine hands the preflight the
    values that reload read, so the check and the swap resolve one read, never a second one."""
    restricted = _key(tmp_path / "restricted.key", broad=False)
    broad = _key(tmp_path / "broad.key", broad=True)
    preflight = make_connection_key_file_preflight(enforcing=True, log=_LOG)
    graph = _registry(
        outbound={
            "OB_SOAP": Soap(
                url="https://x.invalid/s", client_cert_file="s.crt", client_key_file=env("soap_key")
            )
        }
    )
    await preflight(graph, {"soap_key": str(restricted)})
    with pytest.raises(WiringError, match="OB_SOAP"):
        await preflight(graph, {"soap_key": str(broad)})


def _tls_feed(tmp_path: Path, cert: Path, key: Path) -> Path:
    """A config dir whose one inbound serves TLS from ``cert`` and ``key``, on a free port."""
    cfg = tmp_path / "cfg"
    cfg.mkdir(exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    (cfg / "feed.py").write_text(
        "from messagefoundry import File, MLLP, Send, handler, inbound, outbound, router\n"
        f"inbound('IB_FEED', MLLP(port={free_port()}, tls=True,\n"
        f"        tls_cert_file={cert.as_posix()!r}, tls_key_file={key.as_posix()!r}),\n"
        "        router='r')\n"
        f"outbound('OB_FEED', File(directory={out.as_posix()!r}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OB_FEED', msg)\n",
        encoding="utf-8",
    )
    return cfg


async def _engine(tmp_path: Path, **kwargs: Any) -> Engine:
    store = await MessageStore.open(tmp_path / "e.db")
    return Engine(
        store,
        poll_interval=0.02,
        config_dir=None,
        egress_settings=EgressSettings(deny_by_default=False),
        registry_preflight=make_connection_key_file_preflight(enforcing=True, log=_LOG),
        **kwargs,
    )


async def test_a_real_reload_refuses_a_broad_key_and_keeps_the_running_graph(
    tmp_path: Path,
) -> None:
    cert, key = _self_signed(tmp_path)
    cfg = _tls_feed(tmp_path, cert, key)
    eng = await _engine(tmp_path)
    try:
        await eng.reload_detail(cfg)  # the control: a restricted key loads and serves
        runner = eng.registry_runner
        assert runner is not None and runner.inbound_running("IB_FEED")

        _broaden(key)
        with pytest.raises(WiringError, match="'IB_FEED' setting 'tls_key_file' is not restricted"):
            await eng.reload_detail(cfg)
        assert eng.registry_runner is runner and runner.inbound_running("IB_FEED")
        # A dry run skips the preflight, and starts no connection.
        await eng.reload_detail(cfg, dry_run=True)
    finally:
        await eng.stop()


async def test_the_reload_path_judges_key_files_off_the_event_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3402 round 3: the check reads each key file's access list, so it must not run on
    the loop thread. The stand-in records the thread it ran on and refuses, so the reload fails on
    it rather than on anything else."""
    seen: list[int] = []

    def stand_in(registry: Registry, env_values: Mapping[str, Any]) -> str:
        seen.append(threading.get_ident())
        return "stand-in key file problem"

    monkeypatch.setattr(key_file_access, "connection_key_file_problem", stand_in)
    cert, key = _self_signed(tmp_path)
    eng = await _engine(tmp_path)
    try:
        with pytest.raises(WiringError, match="stand-in key file problem"):
            await eng.reload_detail(_tls_feed(tmp_path, cert, key))
    finally:
        await eng.stop()
    assert len(seen) == 1 and seen[0] != threading.get_ident()


@pytest.mark.parametrize("broad", [False, True])
async def test_a_dr_activation_judges_the_running_graphs_key_files(
    broad: bool, tmp_path: Path
) -> None:
    """The activation re-applies the running graph, and the key file may have been re-granted
    since it loaded. The control activates and binds; a broad key refuses and binds nothing."""
    cert, key = _self_signed(tmp_path)
    eng = await _engine(
        tmp_path,
        store_settings=StoreSettings(path=str(tmp_path / "e.db")),
        dr_settings=DrSettings(enabled=True, activate=False),
    )
    try:
        reg = Registry()
        reg.add_inbound(
            build_inbound_connection(
                "IB_FEED",
                MLLP(port=free_port(), tls=True, tls_cert_file=str(cert), tls_key_file=str(key)),
                router="r",
                priority=Priority.CRITICAL,
            )
        )
        out = tmp_path / "out"
        out.mkdir()
        reg.add_outbound(
            build_outbound_connection(
                "OB_FEED",
                ConnectionSpec(ConnectorType.FILE, {"directory": str(out)}),
                priority=Priority.CRITICAL,
            )
        )
        reg.add_router("r", lambda m: ["h"])
        reg.add_handler("h", lambda m: Send("OB_FEED", m))
        eng.add_registry(reg)
        await eng.start()
        runner = eng.registry_runner
        assert runner is not None and not runner.inbound_running("IB_FEED")  # passive

        if broad:
            _broaden(key)
            with pytest.raises(WiringError, match="'IB_FEED' setting 'tls_key_file'"):
                await eng._dr_activate_profile()
            assert not runner.inbound_running("IB_FEED") and not eng.dr_active
        else:
            await eng._dr_activate_profile()
            assert runner.inbound_running("IB_FEED") and eng.dr_active
    finally:
        await eng.stop()


@pytest.mark.parametrize("broad", [False, True])
async def test_the_managed_app_awaits_the_preflight_at_the_first_load(
    broad: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``create_managed_app`` chains the caller's preflight before the trust-anchor one, so the
    start's own first load is judged as a reload is, and a graph it refuses writes no anchor
    audit row: the anchor preflight never runs on it."""
    from messagefoundry.api import app as app_module
    from messagefoundry.api import create_managed_app

    anchor_runs: list[Registry] = []

    def recording_anchor_preflight(store: object, *, enforcing: bool) -> Any:
        async def preflight(registry: Registry, env_values: Mapping[str, Any]) -> None:
            anchor_runs.append(registry)

        return preflight

    monkeypatch.setattr(app_module, "make_registry_anchor_preflight", recording_anchor_preflight)
    cert, key = _self_signed(tmp_path)
    if broad:
        _broaden(key)
    app = create_managed_app(
        db_path=tmp_path / "app.db",
        config_dir=_tls_feed(tmp_path, cert, key),
        poll_interval=0.05,
        egress_settings=EgressSettings(deny_by_default=False),
        registry_preflight=make_connection_key_file_preflight(enforcing=True, log=_LOG),
    )
    if broad:
        with pytest.raises(WiringError, match="'IB_FEED' setting 'tls_key_file'"):
            async with app.router.lifespan_context(app):
                pass
        assert anchor_runs == []
    else:
        async with app.router.lifespan_context(app):
            runner = app.state.engine.registry_runner
            assert runner is not None and runner.inbound_running("IB_FEED")
        assert len(anchor_runs) == 1  # the control: the anchor preflight still runs, beside it


async def test_the_chained_preflight_runs_each_in_order_and_keeps_a_lone_one() -> None:
    from messagefoundry.api.app import _chain_registry_preflights

    calls: list[str] = []

    async def first(registry: Registry, env_values: Mapping[str, Any]) -> None:
        calls.append("first")

    async def then(registry: Registry, env_values: Mapping[str, Any]) -> None:
        calls.append("then")

    assert _chain_registry_preflights(None, first) is first
    await _chain_registry_preflights(first, None, then)(Registry(), {})
    assert calls == ["first", "then"]


def test_every_broad_file_is_named_in_one_refusal(tmp_path: Path) -> None:
    graph = _registry(
        inbound={
            "IB_A": MLLP(
                port=2575,
                tls=True,
                tls_cert_file="a.crt",
                tls_key_file=str(_key(tmp_path / "a.key", broad=True)),
            ),
        },
        outbound={
            "OB_B": MLLP(
                host="127.0.0.1",
                port=2576,
                tls=True,
                tls_cert_file="b.crt",
                tls_key_file=str(_key(tmp_path / "b.key", broad=True)),
            ),
        },
    )
    problem = connection_key_file_problem(graph, {})
    assert problem is not None
    assert "'IB_A'" in problem and "'OB_B'" in problem


def test_a_key_file_two_connections_share_is_judged_once_and_names_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = str(_key(tmp_path / "shared.key", broad=True))
    graph = _registry(
        inbound={
            name: MLLP(port=port, tls=True, tls_cert_file="c.crt", tls_key_file=shared)
            for name, port in (("IB_A", 2575), ("IB_B", 2576))
        }
    )
    judged: list[str] = []
    real = key_file_access.key_file_problem

    def counting(path: str, **kwargs: Any) -> str | None:
        judged.append(path)
        return real(path, **kwargs)

    monkeypatch.setattr(key_file_access, "key_file_problem", counting)
    problem = connection_key_file_problem(graph, {})
    assert judged == [shared]  # one access-list read for the file, not one per setting
    assert problem is not None and "'IB_A'" in problem and "'IB_B'" in problem


# --- serve ----------------------------------------------------------------------------------------


def _serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str
) -> tuple[int, dict[str, Any]]:
    """``serve`` with the app and uvicorn stubbed: its return code and the app's keyword arguments."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    captured: dict[str, Any] = {}

    def _capture_app(**kw: Any) -> object:
        captured.update(kw)
        return object()

    monkeypatch.setattr("messagefoundry.api.create_managed_app", _capture_app)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]), captured


def _api_toml(cert: Path, key: Path | None) -> str:
    key_line = "" if key is None else f'tls_key_file = "{key.as_posix()}"\n'
    return PHI_GATE_PROVISIONS_TOML + f'[api]\ntls_cert_file = "{cert.as_posix()}"\n' + key_line


def test_serve_refuses_an_operator_api_tls_key_a_broad_account_can_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cert, key = _self_signed(tmp_path)
    # The control: the key is created restricted, so the start succeeds.
    assert _serve(tmp_path, monkeypatch, _api_toml(cert, key))[0] == 0
    assert "is not restricted" not in capsys.readouterr().err

    _broaden(key)
    assert _serve(tmp_path, monkeypatch, _api_toml(cert, key))[0] == 2
    err = capsys.readouterr().err
    assert "error: the TLS private key named by [api].tls_key_file is not restricted" in err
    assert "refusing to start" in err


def test_serve_warns_about_an_operator_api_tls_key_under_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cert, key = _self_signed(tmp_path)
    _broaden(key)
    assert _serve(tmp_path, monkeypatch, _WARN + _api_toml(cert, key))[0] == 0
    err = capsys.readouterr().err
    assert "warning: the TLS private key named by [api].tls_key_file is not restricted" in err


def test_serve_judges_the_certificate_when_it_holds_the_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With no ``[api].tls_key_file`` the key is in the certificate PEM, so skipping that file
    would leave the key unjudged."""
    combined = _self_signed_combined(tmp_path)
    assert _serve(tmp_path, monkeypatch, _api_toml(combined, None))[0] == 0  # the control
    assert "is not restricted" not in capsys.readouterr().err

    _broaden(combined)
    assert _serve(tmp_path, monkeypatch, _api_toml(combined, None))[0] == 2
    err = capsys.readouterr().err
    assert "error: the certificate named by [api].tls_cert_file, which holds the TLS" in err
    assert _serve(tmp_path, monkeypatch, _WARN + _api_toml(combined, None))[0] == 0
    assert "warning: the certificate named by [api].tls_cert_file" in capsys.readouterr().err


def test_serve_leaves_a_missing_api_key_file_to_the_loader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cert, _key = _self_signed(tmp_path)
    # The start still fails, at the TLS build. Only the exit is pinned: this gate is not its cause.
    assert _serve(tmp_path, monkeypatch, _api_toml(cert, tmp_path / "missing.pem"))[0] != 0
    assert "is not restricted" not in capsys.readouterr().err


@pytest.mark.parametrize(("toml", "refuses"), [("", True), (_WARN, False)])
def test_serve_hands_the_app_a_preflight_that_judges_connection_keys(
    toml: str, refuses: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc, captured = _serve(tmp_path, monkeypatch, toml + PHI_GATE_PROVISIONS_TOML)
    assert rc == 0
    preflight = cast(
        "Callable[[Registry, Mapping[str, Any]], Awaitable[None]]", captured["registry_preflight"]
    )
    asyncio.run(
        preflight(_soap_graph(_key(tmp_path / "restricted.key", broad=False)), {})
    )  # control
    broad = _soap_graph(_key(tmp_path / "broad.key", broad=True))
    if refuses:
        with pytest.raises(WiringError, match="'client_key_file' is not restricted"):
            asyncio.run(preflight(broad, {}))
    else:
        asyncio.run(preflight(broad, {}))
    # The synchronous guard no longer judges key files, so it does no such file I/O on the loop.
    guard = cast("Callable[[Registry], None]", captured["registry_guard"])
    guard(broad)


# --- supervise ------------------------------------------------------------------------------------


def _supervise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[int, dict[str, Any]]:
    """``supervise`` with the fleet stubbed out: its return code and what it would hand the fleet."""
    handed: dict[str, Any] = {}

    async def fake_supervise(config: str, **kwargs: Any) -> int:
        handed.update(kwargs, config=config)
        return 0

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", fake_supervise)
    monkeypatch.setattr(cli, "configure_logging", lambda *args, **kwargs: None)
    setenv_declared_egress(monkeypatch)
    args = argparse.Namespace(
        config=str(SAMPLES_CONFIG),
        db=str(tmp_path / "mefor.db"),
        base_port=8765,
        env="dev",
        service_config=None,
        project_root=str(tmp_path),
    )
    return cli._supervise(args), handed


def test_supervise_refuses_an_operator_api_tls_key_before_it_spawns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cert, key = _self_signed(tmp_path)
    monkeypatch.setenv("MEFOR_API_TLS_CERT_FILE", str(cert))
    monkeypatch.setenv("MEFOR_API_TLS_KEY_FILE", str(key))
    rc, handed = _supervise(tmp_path, monkeypatch)  # the control
    assert (rc, "config" in handed) == (0, True), capsys.readouterr().err

    _broaden(key)
    rc, handed = _supervise(tmp_path, monkeypatch)
    err = capsys.readouterr().err
    assert rc == 2 and handed == {}
    assert "error: the TLS private key named by [api].tls_key_file is not restricted" in err

    monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    rc, handed = _supervise(tmp_path, monkeypatch)
    assert (rc, "config" in handed) == (0, True)
    assert "warning: the TLS private key named by [api].tls_key_file" in capsys.readouterr().err


@pytest.mark.parametrize("enforcement", ["enforce", "warn"])
def test_supervise_refuses_a_graph_with_a_broad_connection_key_only_under_enforce(
    enforcement: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An engine shard would refuse the graph, so the supervisor refuses it once, over the whole
    graph. Under warn each engine shard writes its own warning, and the supervisor passes it."""
    monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", enforcement)
    rc, handed = _supervise(tmp_path, monkeypatch)
    assert rc == 0
    guard = cast("Callable[[Registry], None]", handed["registry_guard"])
    guard(_soap_graph(_key(tmp_path / "restricted.key", broad=False)))  # the control
    broad = _soap_graph(_key(tmp_path / "broad.key", broad=True))
    if enforcement == "enforce":
        with pytest.raises(WiringError, match="refusing to start the fleet"):
            guard(broad)
    else:
        guard(broad)


async def test_supervise_runs_its_graph_guard_off_the_event_loop(tmp_path: Path) -> None:
    """The fleet refusal reads each key file's access list, and the supervisor runs on a loop, so
    shard discovery and its guard run in a worker thread (BACKLOG #3402 round 3)."""
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.pipeline.supervisor import supervise

    seen: list[int] = []

    def guard(registry: Registry) -> None:
        seen.append(threading.get_ident())
        raise WiringError("stand-in refusal")

    cfg = _tls_feed(tmp_path, tmp_path / "c.crt", tmp_path / "c.key")
    rc = await supervise(
        str(cfg),
        store_backend=StoreBackend.SQLITE,
        db_base=str(tmp_path / "fleet.db"),
        base_port=18791,
        install_signal_handlers=False,
        registry_guard=guard,
    )
    assert rc == 2
    assert len(seen) == 1 and seen[0] != threading.get_ident()
