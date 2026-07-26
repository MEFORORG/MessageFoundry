"""Tray config compose + engine-URL discovery (ADR 0113 §5) — pure, runs on any OS."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.tray.config import (
    DEFAULT_ENGINE_URL,
    DEFAULT_SERVICE_NAME,
    ServiceRegistryInfo,
    build_engine_url,
    compose_config,
    is_local_engine,
    is_tls_url,
    load_config,
    parse_serve_args,
    parse_service_config_arg,
    service_toml_path,
    service_toml_uses_tls,
)


@pytest.mark.parametrize(
    ("args", "host", "port"),
    [
        ("serve --config C:\\cfg --host 127.0.0.1 --port 8765 --env prod", "127.0.0.1", 8765),
        ("serve --host=10.0.0.5 --port=9000", "10.0.0.5", 9000),
        ("serve --config C:\\cfg", None, None),
        ("serve --host 10.1.2.3", "10.1.2.3", None),
        ("serve --port 70000", None, None),  # out of range
        ("serve --port notanint", None, None),
        ("serve --host bad;host --port 8765", None, 8765),  # ';' is not a valid host char
    ],
)
def test_parse_serve_args(args: str, host: str | None, port: int | None) -> None:
    assert parse_serve_args(args) == (host, port)


def test_build_engine_url() -> None:
    assert build_engine_url("127.0.0.1", 8765) == "http://127.0.0.1:8765"
    assert build_engine_url(None, 8765) is None
    assert build_engine_url("127.0.0.1", None) is None
    assert build_engine_url("127.0.0.1", 0) is None
    assert build_engine_url("bad host", 8765) is None


def test_build_engine_url_scheme_follows_tls() -> None:
    """[api].tls_cert_file flips the same bind to https — the discovered URL must follow."""
    assert build_engine_url("127.0.0.1", 8765, tls=True) == "https://127.0.0.1:8765"
    assert build_engine_url("127.0.0.1", 8765, tls=False) == "http://127.0.0.1:8765"


def test_build_engine_url_brackets_a_bare_ipv6_literal() -> None:
    """`serve --host ::1` must not yield the unparseable "http://::1:8765"."""
    assert build_engine_url("::1", 8765) == "http://[::1]:8765"
    assert build_engine_url("[::1]", 8765) == "http://[::1]:8765"  # already bracketed
    assert is_local_engine(build_engine_url("::1", 8765) or "") is True


@pytest.mark.parametrize(
    ("url", "local"),
    [
        ("http://127.0.0.1:8765", True),
        ("http://localhost:8765", True),
        ("http://[::1]:8765", True),
        # A TLS-hardened loopback engine is STILL the local box: scheme is not locality.
        ("https://127.0.0.1:8765", True),
        ("https://localhost:8765", True),
        ("http://10.0.0.5:8765", False),  # remote → monitor-only
        ("https://10.0.0.5:8765", False),  # remote, TLS or not → monitor-only
        ("http://engine.example.com", False),
        ("file:///c:/nope", False),  # not an engine URL at all
        ("", False),
    ],
)
def test_is_local_engine(url: str, local: bool) -> None:
    assert is_local_engine(url) is local


@pytest.mark.parametrize(
    ("url", "tls"),
    [
        ("https://127.0.0.1:8765", True),
        ("http://127.0.0.1:8765", False),
        ("", False),
    ],
)
def test_is_tls_url(url: str, tls: bool) -> None:
    assert is_tls_url(url) is tls


def test_compose_defaults() -> None:
    cfg = compose_config(None, None)
    assert cfg.engine_url == DEFAULT_ENGINE_URL
    assert cfg.service_name == DEFAULT_SERVICE_NAME
    assert cfg.repo_path is None
    assert cfg.monitor_only is False


def test_compose_registry_hints() -> None:
    reg = ServiceRegistryInfo(
        app_directory="C:\\Users\\me\\Code\\MessageFoundry",
        app_parameters="serve --config C:\\cfg --host 127.0.0.1 --port 9100 --env prod",
        app_stdout="C:\\ProgramData\\MessageFoundry\\logs\\service.out.log",
    )
    cfg = compose_config(None, reg)
    assert cfg.engine_url == "http://127.0.0.1:9100"
    assert cfg.repo_path == "C:\\Users\\me\\Code\\MessageFoundry"
    assert cfg.log_path is not None and cfg.log_path.endswith("service.out.log")


def test_compose_toml_overrides_registry() -> None:
    reg = ServiceRegistryInfo(app_parameters="serve --host 127.0.0.1 --port 9100")
    toml_data: dict[str, object] = {
        "engine_url": "http://127.0.0.1:8765/",  # trailing slash normalized away
        "service_name": "MEFOR_Prod",
        "repo_path": "D:\\repo",
        "poll_seconds": 10,
    }
    cfg = compose_config(toml_data, reg)
    assert cfg.engine_url == "http://127.0.0.1:8765"  # toml wins, slash stripped
    assert cfg.service_name == "MEFOR_Prod"
    assert cfg.repo_path == "D:\\repo"
    assert cfg.poll_seconds == 10.0


def test_compose_rejects_unsafe_service_name() -> None:
    cfg = compose_config({"service_name": "evil & name | rm"}, None)
    assert cfg.service_name == DEFAULT_SERVICE_NAME


def test_compose_rejects_hostile_path_hints() -> None:
    reg = ServiceRegistryInfo(app_directory="C:\\ok\\path\x00malicious")
    assert compose_config(None, reg).repo_path is None
    toml_data: dict[str, object] = {"repo_path": "x" * 5000}
    assert compose_config(toml_data, None).repo_path is None


def test_compose_poll_seconds_bool_rejected_and_clamped() -> None:
    # bool is an int subclass — must not be accepted as a poll interval.
    assert compose_config({"poll_seconds": True}, None).poll_seconds == 5.0
    assert compose_config({"poll_seconds": 0.1}, None).poll_seconds == 1.0  # clamp floor
    assert compose_config({"poll_seconds": 999999}, None).poll_seconds == 3600.0  # clamp ceiling


def test_monitor_only_keys_on_locality_not_scheme() -> None:
    """The regression this fixes: TLS on the loopback bind used to grey out Start/Stop/Restart."""
    assert compose_config({"engine_url": "http://127.0.0.1:8765"}, None).monitor_only is False
    assert compose_config({"engine_url": "https://127.0.0.1:8765"}, None).monitor_only is False
    assert compose_config({"engine_url": "https://localhost:8765"}, None).monitor_only is False
    # Remote stays monitor-only regardless of scheme — service control needs the local box.
    assert compose_config({"engine_url": "http://10.0.0.9:8765"}, None).monitor_only is True
    assert compose_config({"engine_url": "https://10.0.0.9:8765"}, None).monitor_only is True


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ("serve --service-config C:\\svc\\mefor.toml", "C:\\svc\\mefor.toml"),
        ("serve --service-config=mefor.toml --env prod", "mefor.toml"),
        ("serve --config C:\\cfg --host 127.0.0.1", None),
        ("serve --service-config", None),  # trailing flag, no value
        ("serve --service-config bad\x00path", None),  # NUL-bearing → rejected
    ],
)
def test_parse_service_config_arg(args: str, expected: str | None) -> None:
    assert parse_service_config_arg(args) == expected


@pytest.mark.parametrize(
    ("data", "tls"),
    [
        ({"api": {"tls_cert_file": "C:\\certs\\engine.pem"}}, True),
        ({"api": {"tls_cert_file": ""}}, False),
        ({"api": {"tls_cert_file": "   "}}, False),
        ({"api": {"tls_cert_file": None}}, False),
        ({"api": {"host": "127.0.0.1"}}, False),
        ({"api": "not-a-table"}, False),
        ({}, False),
        (None, False),
    ],
)
def test_service_toml_uses_tls(data: dict[str, object] | None, tls: bool) -> None:
    assert service_toml_uses_tls(data) is tls


def test_service_toml_path_resolution(tmp_path: Path) -> None:
    # tmp_path (not a literal) so "absolute" means the same thing on the Windows and Linux legs.
    repo = tmp_path / "repo"
    elsewhere = tmp_path / "svc" / "x.toml"

    # Explicit absolute --service-config wins.
    reg = ServiceRegistryInfo(
        app_directory=str(repo), app_parameters=f"serve --service-config {elsewhere}"
    )
    assert service_toml_path(reg) == elsewhere
    # A relative one resolves against AppDirectory (a service's cwd), like serve itself.
    reg = ServiceRegistryInfo(
        app_directory=str(repo), app_parameters="serve --service-config x.toml"
    )
    assert service_toml_path(reg) == repo / "x.toml"
    # No flag → the engine's own default filename under AppDirectory.
    reg = ServiceRegistryInfo(app_directory=str(repo), app_parameters="serve --host 127.0.0.1")
    assert service_toml_path(reg) == repo / "messagefoundry.toml"
    # Nothing to anchor on → nothing to read.
    assert service_toml_path(ServiceRegistryInfo(app_parameters="serve")) is None
    assert service_toml_path(None) is None


class _FakeReader:
    def __init__(self, info: ServiceRegistryInfo | None) -> None:
        self._info = info
        self.asked: list[str] = []

    def read_service_params(self, service_name: str) -> ServiceRegistryInfo | None:
        self.asked.append(service_name)
        return self._info


def test_load_config_reads_toml_and_registry(tmp_path: Path) -> None:
    (tmp_path / "tray.toml").write_text(
        'service_name = "MEFOR_Prod"\npoll_seconds = 7\n', encoding="utf-8"
    )
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory="C:\\repo",
            app_parameters="serve --host 127.0.0.1 --port 9200",
        )
    )
    cfg = load_config(tmp_path, reader)
    # The registry was queried with the TOML-resolved service name.
    assert reader.asked == ["MEFOR_Prod"]
    assert cfg.service_name == "MEFOR_Prod"
    assert cfg.poll_seconds == 7.0
    assert cfg.engine_url == "http://127.0.0.1:9200"  # from the registry hint
    assert cfg.repo_path == "C:\\repo"


def test_load_config_discovers_an_https_engine_from_the_service_toml(tmp_path: Path) -> None:
    """NSSM discovery must be able to yield https — there is no `serve` TLS flag to sniff, so the
    scheme comes from [api].tls_cert_file in the engine's own settings TOML."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "messagefoundry.toml").write_text(
        '[api]\nhost = "127.0.0.1"\nport = 8765\ntls_cert_file = "C:\\\\certs\\\\engine.pem"\n',
        encoding="utf-8",
    )
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory=str(repo),
            app_parameters="serve --config C:\\cfg --host 127.0.0.1 --port 8765 --env prod",
        )
    )
    cfg = load_config(tmp_path, reader)
    assert cfg.engine_url == "https://127.0.0.1:8765"
    # ...and a TLS engine on loopback stays fully managed.
    assert cfg.monitor_only is False


def test_load_config_plaintext_service_toml_stays_http(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "messagefoundry.toml").write_text('[api]\nhost = "127.0.0.1"\n', encoding="utf-8")
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory=str(repo), app_parameters="serve --host 127.0.0.1 --port 8765"
        )
    )
    assert load_config(tmp_path, reader).engine_url == "http://127.0.0.1:8765"


def test_load_config_unreadable_service_toml_is_fail_soft(tmp_path: Path) -> None:
    """The service TOML is operator data reached via an untrusted registry hint: a missing or
    malformed file must degrade to 'no TLS hint', never raise into the tray's startup."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "messagefoundry.toml").write_text("this is = = not toml", encoding="utf-8")
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory=str(repo), app_parameters="serve --host 127.0.0.1 --port 8765"
        )
    )
    assert load_config(tmp_path, reader).engine_url == "http://127.0.0.1:8765"
    # Absent entirely (no AppDirectory to anchor on) is equally quiet.
    bare = _FakeReader(ServiceRegistryInfo(app_parameters="serve --host 127.0.0.1 --port 8765"))
    assert load_config(tmp_path, bare).engine_url == "http://127.0.0.1:8765"


def test_load_config_tray_toml_engine_url_beats_the_tls_hint(tmp_path: Path) -> None:
    """An explicit engine_url carries its own scheme and must not be scheme-rewritten."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "messagefoundry.toml").write_text('[api]\ntls_cert_file = "c.pem"\n', encoding="utf-8")
    (tmp_path / "tray.toml").write_text("engine_url = 'http://127.0.0.1:9999'\n", encoding="utf-8")
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory=str(repo), app_parameters="serve --host 127.0.0.1 --port 8765"
        )
    )
    assert load_config(tmp_path, reader).engine_url == "http://127.0.0.1:9999"


def test_load_config_missing_file_uses_defaults(tmp_path: Path) -> None:
    cfg = load_config(tmp_path, None)
    assert cfg.engine_url == DEFAULT_ENGINE_URL
    assert cfg.service_name == DEFAULT_SERVICE_NAME


def test_load_config_malformed_toml_falls_back(tmp_path: Path) -> None:
    (tmp_path / "tray.toml").write_text("this is = = not valid toml", encoding="utf-8")
    cfg = load_config(tmp_path, None)
    assert cfg.engine_url == DEFAULT_ENGINE_URL


def test_ensure_tray_toml_writes_template_then_is_idempotent(tmp_path: Path) -> None:
    from messagefoundry.tray.config import TRAY_TOML_TEMPLATE, ensure_tray_toml

    path = ensure_tray_toml(tmp_path)
    assert path == tmp_path / "tray.toml"
    written = path.read_text(encoding="utf-8")
    assert written == TRAY_TOML_TEMPLATE
    assert "repo_path" in written  # the key issue-2 asks about is documented
    # A written template is inert (all keys commented) → still resolves to defaults.
    assert load_config(tmp_path, None).engine_url == DEFAULT_ENGINE_URL
    # Idempotent: never clobbers an operator's edits.
    path.write_text("engine_url = 'http://x:9'\n", encoding="utf-8")
    ensure_tray_toml(tmp_path)
    assert path.read_text(encoding="utf-8") == "engine_url = 'http://x:9'\n"
