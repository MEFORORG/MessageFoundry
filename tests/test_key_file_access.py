# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Under enforce, an operator's key file a broad group can read refuses the start (BACKLOG #3402).

Two halves, each with a control that gives the opposite answer:

* ``[api].tls_key_file``, or the certificate PEM that holds the key when it is unset, is judged by a
  start gate in ``serve`` and in ``supervise``, beside the gate for the key the engine mints;
* a connection's key file is graph data, judged by a registry guard at each load, and by
  ``supervise`` before it spawns an engine shard.

Each file is broadened with :func:`tests.test_restricted_file._broaden`, which grants the local
Users group read on Windows and sets mode 0644 on POSIX, so every test here runs on every leg.
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry import __main__ as cli
from messagefoundry.__main__ import main
from messagefoundry.config.key_file_access import (
    connection_key_file_problem,
    connection_key_files,
    make_connection_key_file_guard,
)
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    DICOM,
    MLLP,
    ConnectionSpec,
    Http,
    InboundConnection,
    OutboundConnection,
    Registry,
    Soap,
    WiringError,
    env,
)
from messagefoundry.restricted_file import write_restricted_file
from messagefoundry.store.crypto import generate_key
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
    # names it; its certificate is judged meanwhile, as the loader would read the key from it.
    assert found == [
        ("inbound connection 'IB_COMBINED' setting 'tls_cert_file'", "combined.pem"),
        ("outbound connection 'OB_UNRESOLVED' setting 'client_cert_file'", "u.crt"),
    ]


# --- the registry guard ---------------------------------------------------------------------------


def _soap_graph(key: Path) -> Registry:
    return _registry(
        outbound={
            "OB_SOAP": Soap(
                url="https://x.invalid/s", client_cert_file="s.crt", client_key_file=str(key)
            )
        }
    )


def test_the_guard_refuses_a_broad_connection_key_under_enforce(tmp_path: Path) -> None:
    guard = make_connection_key_file_guard(dict, enforcing=True, log=_LOG)
    guard(_soap_graph(_key(tmp_path / "restricted.key", broad=False)))  # the control
    guard(_soap_graph(tmp_path / "missing.key"))  # left to the connector, which names it

    broad = _key(tmp_path / "broad.key", broad=True)
    with pytest.raises(WiringError) as refused:
        guard(_soap_graph(broad))
    text = str(refused.value)
    assert "outbound connection 'OB_SOAP' setting 'client_key_file'" in text
    assert "is not restricted" in text
    assert str(broad) not in text  # the label names the setting, never the path


def test_the_guard_warns_and_passes_under_warn(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    guard = make_connection_key_file_guard(dict, enforcing=False, log=_LOG)
    with caplog.at_level(logging.WARNING, logger=_LOG.name):
        guard(_soap_graph(_key(tmp_path / "restricted.key", broad=False)))  # the control
        assert "is not restricted" not in caplog.text
        guard(_soap_graph(_key(tmp_path / "broad.key", broad=True)))
    assert "'client_key_file' is not restricted" in caplog.text
    assert "warning: the private key file named by outbound connection 'OB_SOAP'" in (
        capsys.readouterr().err
    )


def test_the_guard_reads_the_values_again_for_each_graph(tmp_path: Path) -> None:
    """A reload can change the env() values without a restart, so each graph is judged against
    the values the provider returns for it."""
    restricted = _key(tmp_path / "restricted.key", broad=False)
    broad = _key(tmp_path / "broad.key", broad=True)
    values = {"soap_key": str(restricted)}
    guard = make_connection_key_file_guard(lambda: values, enforcing=True, log=_LOG)
    graph = _registry(
        outbound={
            "OB_SOAP": Soap(
                url="https://x.invalid/s", client_cert_file="s.crt", client_key_file=env("soap_key")
            )
        }
    )
    guard(graph)
    values["soap_key"] = str(broad)
    with pytest.raises(WiringError, match="OB_SOAP"):
        guard(graph)


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
def test_serve_hands_the_app_a_guard_that_judges_connection_keys(
    toml: str, refuses: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc, captured = _serve(tmp_path, monkeypatch, toml + PHI_GATE_PROVISIONS_TOML)
    assert rc == 0
    guard = cast("Callable[[Registry], None]", captured["registry_guard"])
    guard(_soap_graph(_key(tmp_path / "restricted.key", broad=False)))  # the control
    broad = _soap_graph(_key(tmp_path / "broad.key", broad=True))
    if refuses:
        with pytest.raises(WiringError, match="'client_key_file' is not restricted"):
            guard(broad)
    else:
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
    """Each engine shard would refuse the graph, so the supervisor refuses it once. Under warn each
    engine shard writes its own warning, and the supervisor passes the graph."""
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
