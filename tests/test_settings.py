"""Service settings: TOML + env + CLI loading with CLI > env > file > default precedence."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    ServiceSettings,
    SqlAuth,
    SqliteSync,
    StoreBackend,
    load_settings,
)


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_defaults_when_no_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)  # no ./messagefoundry.toml here
    s = load_settings(environ={})
    assert s.store.backend is StoreBackend.SQLITE
    assert s.store.path == "messagefoundry.db"
    assert s.store.synchronous is SqliteSync.NORMAL
    assert s.api.host == "127.0.0.1" and s.api.port == 8765
    assert s.logging.level == "INFO"


def test_file_is_loaded(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\npath = "x.db"\nsynchronous = "full"\n[api]\nport = 9000\n[logging]\nlevel = "warning"\n',
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.store.path == "x.db" and s.store.synchronous is SqliteSync.FULL
    assert s.api.port == 9000
    assert s.logging.level == "WARNING"  # normalized to upper-case


def test_default_file_used_when_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write(tmp_path / "messagefoundry.toml", "[api]\nport = 7000\n")
    s = load_settings(environ={})  # config_path=None -> picks up ./messagefoundry.toml
    assert s.api.port == 7000


def test_env_overrides_file(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", '[store]\npath = "file.db"\n[api]\nport = 1\n')
    s = load_settings(
        config_path=cfg,
        environ={"MEFOR_STORE_PATH": "env.db", "MEFOR_API_PORT": "2"},
    )
    assert s.store.path == "env.db"  # env wins over file
    assert s.api.port == 2  # string env value coerced to int


def test_config_reload_roots_from_env_splits_on_pathsep(tmp_path: Path) -> None:
    # low-12: the only list-typed setting must be settable via env; a single string is split on the
    # platform path separator into the list.
    roots = os.pathsep.join(["/srv/staging", "/srv/ide"])
    s = load_settings(environ={"MEFOR_API_CONFIG_RELOAD_ROOTS": roots})
    assert s.api.config_reload_roots == ["/srv/staging", "/srv/ide"]


def test_inbound_bind_host_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    s = load_settings(environ={})
    assert s.inbound.bind_host == "127.0.0.1"  # safe loopback default


def test_inbound_bind_host_from_file_and_env(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", '[inbound]\nbind_host = "0.0.0.0"\n')
    assert load_settings(config_path=cfg, environ={}).inbound.bind_host == "0.0.0.0"
    # env (MEFOR_INBOUND_BIND_HOST) overrides the file
    s = load_settings(config_path=cfg, environ={"MEFOR_INBOUND_BIND_HOST": "10.0.0.5"})
    assert s.inbound.bind_host == "10.0.0.5"


def test_environments_dir_default_and_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_settings(environ={}).environments.dir == "environments"  # default
    cfg = _write(tmp_path / "messagefoundry.toml", '[environments]\ndir = "envs"\n')
    assert load_settings(config_path=cfg, environ={}).environments.dir == "envs"


def test_cli_overrides_env_and_file(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", '[store]\npath = "file.db"\n')
    s = load_settings(
        config_path=cfg,
        environ={"MEFOR_STORE_PATH": "env.db"},
        cli={"store": {"path": "cli.db"}},
    )
    assert s.store.path == "cli.db"  # CLI is highest precedence


def test_unknown_sections_and_keys_ignored(tmp_path: Path) -> None:
    # A forward-looking config (an as-yet-unmodelled section + an unknown store key) must still load.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "sqlite"\nregion = "us-east"\n[telemetry]\nendpoint = "x"\n',
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.store.backend is StoreBackend.SQLITE
    assert not hasattr(s.store, "region")  # unknown key ignored, not an error
    assert not hasattr(s, "telemetry")  # unknown section ignored


def test_retention_section_loads(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[retention]\nmessages_days = 30\ndead_letter_days = 90\nvacuum_at = "03:30"\n',
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.retention.messages_days == 30
    assert s.retention.dead_letter_days == 90
    assert s.retention.vacuum_time() == (3, 30)


def test_store_encryption_rotation_settings(tmp_path: Path) -> None:
    # require_encryption from the file; the retired-keys list is a secret → env only.
    cfg = _write(tmp_path / "messagefoundry.toml", "[store]\nrequire_encryption = true\n")
    s = load_settings(
        config_path=cfg, environ={"MEFOR_STORE_ENCRYPTION_KEYS_RETIRED": "oldkey1,oldkey2"}
    )
    assert s.store.require_encryption is True
    assert s.store.encryption_keys_retired == "oldkey1,oldkey2"


def test_egress_allowlist_loads_from_file_and_env(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[egress]\nallowed_mllp = ["hl7.partner.org:2575", "10.0.0.5"]\n',
    )
    s = load_settings(
        config_path=cfg, environ={"MEFOR_EGRESS_ALLOWED_FILE_DIRS": "/data/out,/data/archive"}
    )
    assert s.egress.allowed_mllp == ["hl7.partner.org:2575", "10.0.0.5"]  # from file
    assert s.egress.allowed_file_dirs == ["/data/out", "/data/archive"]  # from env (comma-split)


def test_auth_password_policy_defaults_are_asvs_aligned() -> None:
    a = ServiceSettings().auth  # WP-3: length-first, no mandatory composition, breach screening on
    assert a.password_min_length == 15
    assert not (
        a.password_require_uppercase
        or a.password_require_lowercase
        or a.password_require_digit
        or a.password_require_symbol
    )
    assert a.password_check_breached and a.password_check_context
    assert a.password_check_username  # v2: own-username rejection on by default (6.2.11)
    assert a.password_breach_corpus_file is None  # opt-in larger offline corpus (6.2.12)
    assert a.bootstrap_expiry_hours == 72


def test_auth_breach_corpus_and_username_check_from_env() -> None:
    s = load_settings(
        environ={
            "MEFOR_AUTH_PASSWORD_CHECK_USERNAME": "false",
            "MEFOR_AUTH_PASSWORD_BREACH_CORPUS_FILE": "/srv/breach/extra.txt",
        }
    )
    assert s.auth.password_check_username is False
    assert s.auth.password_breach_corpus_file == "/srv/breach/extra.txt"


def test_missing_explicit_config_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_settings(config_path=tmp_path / "nope.toml", environ={})


def test_invalid_level_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValidationError):
        load_settings(environ={"MEFOR_LOGGING_LEVEL": "loud"})


def test_invalid_backend_rejected(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", '[store]\nbackend = "mongodb"\n')
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_settings_model_defaults_are_independent() -> None:
    # Guard against shared-mutable-default surprises across instances.
    a = ServiceSettings()
    b = ServiceSettings()
    assert a.store is not b.store and a.api is not b.api


# --- SQL Server [store] settings (stage 1; backend lands later) --------------


def test_sqlserver_settings_load(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "sqlserver"\nserver = "sql01.hospital.local"\n'
        'database = "MessageFoundry"\nusername = "mefor_svc"\nencrypt = true\n'
        'trust_server_certificate = false\npool_size = 8\ndb_schema = "mf"\n',
    )
    s = load_settings(config_path=cfg, environ={"MEFOR_STORE_PASSWORD": "s3cret"})
    assert s.store.backend is StoreBackend.SQLSERVER
    assert s.store.server == "sql01.hospital.local" and s.store.database == "MessageFoundry"
    assert s.store.auth is SqlAuth.SQL and s.store.username == "mefor_svc"
    assert s.store.password == "s3cret"  # secret comes from env, not the file
    assert s.store.port == 1433  # default
    assert s.store.encrypt is True and s.store.trust_server_certificate is False
    assert s.store.pool_size == 8 and s.store.db_schema == "mf"


def test_sqlserver_missing_server_database_rejected(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", '[store]\nbackend = "sqlserver"\n')
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_sqlserver_sql_auth_requires_username(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "sqlserver"\nserver = "s"\ndatabase = "d"\n',  # auth=sql default, no user
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_sqlserver_integrated_auth_needs_no_username(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "sqlserver"\nserver = "s"\ndatabase = "d"\nauth = "integrated"\n',
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.store.auth is SqlAuth.INTEGRATED and s.store.username is None


def test_sqlserver_env_coercion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    s = load_settings(
        environ={
            "MEFOR_STORE_BACKEND": "sqlserver",
            "MEFOR_STORE_SERVER": "s",
            "MEFOR_STORE_DATABASE": "d",
            "MEFOR_STORE_AUTH": "entra",
            "MEFOR_STORE_PORT": "14330",
            "MEFOR_STORE_ENCRYPT": "false",
            "MEFOR_STORE_DB_SCHEMA": "audit",
        }
    )
    assert s.store.port == 14330  # str -> int
    assert s.store.encrypt is False  # str -> bool
    assert s.store.auth is SqlAuth.ENTRA and s.store.db_schema == "audit"


def test_sqlite_default_unaffected_by_new_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    s = load_settings(environ={})
    assert s.store.backend is StoreBackend.SQLITE
    assert s.store.server is None and s.store.username is None  # SQL Server fields stay unset


# --- [auth] settings --------------------------------------------------------


def test_auth_defaults_required_with_secure_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    s = load_settings(environ={})
    assert s.auth.enabled is True  # authentication required by default
    assert s.auth.password_min_length == 15 and s.auth.lockout_threshold == 5  # ASVS-aligned (WP-3)
    assert s.auth.session_idle_timeout_minutes == 30
    assert s.auth.ad_enabled is False and s.auth.kerberos_enabled is False


def test_auth_ad_config_from_file_with_env_secret(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[auth]\nad_enabled = true\nad_server = "ldaps://dc1.example.com:636"\n'
        'ad_domain = "example.com"\nad_user_search_base = "OU=Users,DC=example,DC=com"\n'
        'ad_bind_dn = "CN=svc,OU=Svc,DC=example,DC=com"\n',
    )
    s = load_settings(config_path=cfg, environ={"MEFOR_AUTH_AD_BIND_PASSWORD": "s3cret"})
    assert s.auth.ad_enabled is True
    assert s.auth.ad_server == "ldaps://dc1.example.com:636"
    assert s.auth.ad_user_search_base == "OU=Users,DC=example,DC=com"
    assert s.auth.ad_bind_password == "s3cret"  # secret from env, never the file


def test_auth_ad_enabled_requires_server_and_base(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", "[auth]\nad_enabled = true\n")
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_auth_kerberos_requires_ad(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", "[auth]\nkerberos_enabled = true\n")
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})
