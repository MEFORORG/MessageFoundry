# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Service settings: TOML + env + CLI loading with CLI > env > file > default precedence."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    AuthSettings,
    DrSettings,
    ServiceSettings,
    SqlAuth,
    SqliteSync,
    StoreBackend,
    load_settings,
)
from messagefoundry.store.base import pool_over_provisioned_warning, warm_pool_target


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


def test_retention_secure_by_default_knob(tmp_path: Path) -> None:
    # #186a: allow_unbounded_phi defaults to the SECURE posture (False = the serve gate bounds PHI
    # retention). The [egress].deny_by_default MODEL default is left UNCHANGED (False) — the fail-closed
    # flip is a serve-side effective mutation, not a model default change, so loopback stays byte-
    # identical. Both parse from the file.
    s = ServiceSettings()
    assert s.retention.allow_unbounded_phi is False
    assert s.egress.deny_by_default is False  # unchanged model default (byte-identical constructor)
    cfg = _write(tmp_path / "messagefoundry.toml", "[retention]\nallow_unbounded_phi = true\n")
    loaded = load_settings(config_path=cfg, environ={})
    assert loaded.retention.allow_unbounded_phi is True


def test_security_notifications_required_default(tmp_path: Path) -> None:
    # #188: security_notifications_required defaults to the SECURE posture (True = the serve gate
    # requires an out-of-band channel). Parses false (the audited opt-out) from the file.
    assert ServiceSettings().alerts.security_notifications_required is True
    cfg = _write(
        tmp_path / "messagefoundry.toml", "[alerts]\nsecurity_notifications_required = false\n"
    )
    loaded = load_settings(config_path=cfg, environ={})
    assert loaded.alerts.security_notifications_required is False


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


# --- [logging] structured format + off-box forwarding (sec-offbox-log) --------


def test_logging_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    log = load_settings(environ={}).logging
    assert log.format.value == "text"  # stdout unchanged by default
    assert log.forward_enabled is False
    assert log.forward_port == 514
    assert log.forward_protocol.value == "udp"
    assert log.forward_format.value == "json"  # JSON is the SIEM-friendly off-box default


def test_logging_forward_enabled_requires_host(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", "[logging]\nforward_enabled = true\n")
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_logging_forward_settings_parsed(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[logging]\nformat = "json"\nforward_enabled = true\nforward_host = "siem.local"\n'
        'forward_port = 6514\nforward_protocol = "tcp"\nforward_format = "text"\n',
    )
    log = load_settings(config_path=cfg, environ={}).logging
    assert log.format.value == "json"
    assert log.forward_enabled and log.forward_host == "siem.local"
    assert log.forward_port == 6514
    assert log.forward_protocol.value == "tcp"
    assert log.forward_format.value == "text"


def test_logging_forward_port_out_of_range(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", "[logging]\nforward_port = 70000\n")
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_logging_invalid_format_rejected(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", '[logging]\nformat = "xml"\n')
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


# --- ADR 0080: default-on-when-configured + native TLS-syslog + clock-sync gate ------


def test_logging_forward_default_on_when_host_set(tmp_path: Path) -> None:
    # Configuring a collector (forward_host) turns forwarding ON by default (forward_enabled unset →
    # derived True), so an operator can't silently forget the enable flag.
    cfg = _write(tmp_path / "messagefoundry.toml", '[logging]\nforward_host = "siem.local"\n')
    log = load_settings(config_path=cfg, environ={}).logging
    assert log.forward_enabled is True
    assert log.forward_host == "siem.local"


def test_logging_forward_explicit_disable_wins_over_host(tmp_path: Path) -> None:
    # The documented opt-out: forward_enabled=false is honored even with a collector configured.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[logging]\nforward_enabled = false\nforward_host = "siem.local"\n',
    )
    log = load_settings(config_path=cfg, environ={}).logging
    assert log.forward_enabled is False


def test_logging_no_collector_leaves_forwarding_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No forward_host → forwarding OFF (byte-identical to the pre-0080 stdout-only default). The None
    # default is resolved to a concrete False by the validator.
    monkeypatch.chdir(tmp_path)
    log = load_settings(environ={}).logging
    assert log.forward_enabled is False


def test_logging_tls_requires_ca_when_verifying(tmp_path: Path) -> None:
    # protocol="tls" with verification on (the default) requires an explicit CA anchor.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[logging]\nforward_host = "siem.local"\nforward_protocol = "tls"\n',
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_logging_tls_with_ca_parses(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[logging]\nforward_host = "siem.local"\nforward_protocol = "tls"\n'
        'forward_tls_ca_file = "/etc/mefor/siem-ca.pem"\nforward_tls_client_cert = "/etc/mefor/client.pem"\n',
    )
    log = load_settings(config_path=cfg, environ={}).logging
    assert log.forward_protocol.value == "tls"
    assert log.forward_tls_ca_file == "/etc/mefor/siem-ca.pem"
    assert log.forward_tls_verify is True  # secure default
    assert log.forward_tls_client_cert == "/etc/mefor/client.pem"


def test_logging_tls_verify_false_needs_no_ca(tmp_path: Path) -> None:
    # The insecure opt-out: forward_tls_verify=false accepts an unverified collector without a CA file.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[logging]\nforward_host = "siem.local"\nforward_protocol = "tls"\nforward_tls_verify = false\n',
    )
    log = load_settings(config_path=cfg, environ={}).logging
    assert log.forward_protocol.value == "tls" and log.forward_tls_verify is False


def test_logging_time_sync_requires_peer(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "messagefoundry.toml", "[logging]\nrequire_time_sync = true\n")
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_logging_time_sync_fail_closed_requires_require(tmp_path: Path) -> None:
    # fail-closed without require_time_sync is incoherent (nothing to fail on).
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[logging]\ntime_sync_fail_closed = true\nntp_peer = "ntp.local"\n',
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_logging_time_sync_parsed(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[logging]\nrequire_time_sync = true\nntp_peer = "ntp.local"\n'
        "time_sync_max_skew_seconds = 0.5\ntime_sync_fail_closed = true\n",
    )
    log = load_settings(config_path=cfg, environ={}).logging
    assert log.require_time_sync is True and log.ntp_peer == "ntp.local"
    assert log.time_sync_max_skew_seconds == 0.5 and log.time_sync_fail_closed is True


def test_logging_time_sync_skew_threshold_must_be_positive(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[logging]\nrequire_time_sync = true\nntp_peer = "ntp.local"\ntime_sync_max_skew_seconds = 0\n',
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_logging_time_sync_default_noop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    log = load_settings(environ={}).logging
    assert log.require_time_sync is False and log.ntp_peer is None
    assert log.time_sync_fail_closed is False


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


# --- [cluster] settings (Track B Step 3) ------------------------------------


def test_cluster_defaults_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    s = load_settings(environ={})
    # Off by default → single-node, byte-identical to before the seam existed.
    assert s.cluster.enabled is False
    assert s.cluster.node_id is None
    assert s.cluster.heartbeat_seconds == 10.0
    assert s.cluster.node_timeout_seconds == 30.0
    assert s.cluster.reclaim_interval_seconds == 30.0


def test_cluster_parses_from_file_and_env(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        '[cluster]\nenabled = true\nnode_id = "node-A"\nheartbeat_seconds = 2.5\n',
    )
    s = load_settings(config_path=cfg, environ={"MEFOR_CLUSTER_NODE_TIMEOUT_SECONDS": "7.5"})
    assert s.cluster.enabled is True
    assert s.cluster.node_id == "node-A"
    assert s.cluster.heartbeat_seconds == 2.5
    assert s.cluster.node_timeout_seconds == 7.5  # str env value coerced to float


def test_cluster_enabled_requires_server_db_backend(tmp_path: Path) -> None:
    # SQLite is single-node, so enabling cluster coordination on it is refused (cross-section
    # validator on ServiceSettings). Postgres and SQL Server are the allowed server-DB backends.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "sqlite"\n[cluster]\nenabled = true\n',
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_cluster_enabled_on_postgres_is_ok(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.enabled is True and s.store.backend is StoreBackend.POSTGRES


# --- [store].pool_size default (B13 / ADR 0062) -----------------------------


def test_default_pool_size_is_40(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # B13 / ADR 0062: the unset server-DB pool default is 40 (the higher-N inverted-U optimum; was 5).
    # The single guard against an accidental revert of the default literal.
    monkeypatch.chdir(tmp_path)  # no ./messagefoundry.toml here
    assert load_settings(environ={}).store.pool_size == 40


def test_explicit_pool_size_overrides_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "Only the unset default moves" — an explicit file value wins, and an env value wins over the file,
    # so no existing config's pool changes under the 5->40 default bump.
    monkeypatch.chdir(tmp_path)
    cfg = _write(tmp_path / "messagefoundry.toml", "[store]\npool_size = 7\n")
    assert load_settings(config_path=cfg, environ={}).store.pool_size == 7  # file wins over default
    # config_path=None picks up ./messagefoundry.toml (pool_size = 7); env must still override it.
    assert load_settings(environ={"MEFOR_STORE_POOL_SIZE": "9"}).store.pool_size == 9


def test_warm_target_at_new_default() -> None:
    # ADR 0062 consequence: the implicit startup warm target scales with the default. At pool_size=40 the
    # unset target is min(39, 20) = 20 (was min(4, 2) = 2 at the old default of 5); an explicit count is
    # still clamped to maxsize-1.
    assert warm_pool_target(40, None) == 20
    assert warm_pool_target(5, None) == 2  # the OLD default's warm target, for contrast
    assert warm_pool_target(40, 4) == 4  # explicit honored: min(4, 39)


def test_cluster_floor_and_default_pool(tmp_path: Path) -> None:
    # The [cluster] pool_size >= 2 floor is untouched by the bump: an explicit pool_size=1 still refuses,
    # and the new default (40) trivially satisfies it.
    bad = _write(
        tmp_path / "bad.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\npool_size = 1\n'
        "[cluster]\nenabled = true\n",
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=bad, environ={})
    ok = _write(
        tmp_path / "ok.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\n",
    )
    s = load_settings(config_path=ok, environ={})
    assert s.store.pool_size == 40 and s.cluster.enabled is True


def test_pool_over_provisioned_warning() -> None:
    # ADR 0062 soft guard (pure policy; the caller skips it on SQLite where there is no pool). The default
    # (40) never warns, at any interface count.
    assert pool_over_provisioned_warning(40, 2) is None
    assert pool_over_provisioned_warning(40, 100) is None
    assert pool_over_provisioned_warning(20, 1) is None  # below the optimum
    # Cliff (>= 80): warns regardless of interface count.
    assert "cliff" in (pool_over_provisioned_warning(80, 200) or "")
    assert pool_over_provisioned_warning(150, 100) is not None
    # Idle over-provision: above the optimum AND well beyond the ~2.5x interface demand.
    assert "over-provisioned" in (pool_over_provisioned_warning(60, 2) or "")  # demand ~5
    # Justified: above the optimum but within the interface demand -> no warning.
    assert pool_over_provisioned_warning(60, 30) is None  # demand ~75 >= 60


def test_cluster_enabled_on_sqlserver_is_ok(tmp_path: Path) -> None:
    # SQL Server backs active-passive HA (the SqlServerCoordinator leadership lease), so cluster
    # coordination is allowed on it too (pool_size >= 2 like any clustered server-DB node).
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "sqlserver"\nserver = "mssql"\ndatabase = "d"\nusername = "u"\n'
        "pool_size = 3\n[cluster]\nenabled = true\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.enabled is True and s.store.backend is StoreBackend.SQLSERVER


def test_cluster_disabled_on_sqlite_is_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The constraint is only on enabled=true; the default SQLite + disabled cluster must load fine.
    monkeypatch.chdir(tmp_path)
    cfg = _write(tmp_path / "messagefoundry.toml", "[cluster]\nenabled = false\n")
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.enabled is False and s.store.backend is StoreBackend.SQLITE


def test_cluster_heartbeat_must_be_positive(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\nheartbeat_seconds = 0\n",
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_cluster_node_timeout_must_be_positive(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\nnode_timeout_seconds = -1\n",
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_cluster_node_timeout_must_exceed_heartbeat(tmp_path: Path) -> None:
    # A node must beat at least once before it is considered dead; a timeout <= the heartbeat would
    # let Step-4 election mark a live node dead between beats. Refused at config load.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\nheartbeat_seconds = 10\nnode_timeout_seconds = 10\n",
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


# --- [cluster] leader election + reclaim (Track B Step 4) -------------------


def test_cluster_reclaim_interval_must_be_positive(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\nreclaim_interval_seconds = 0\n",
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_cluster_reclaim_interval_parses(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\nreclaim_interval_seconds = 12.5\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.reclaim_interval_seconds == 12.5


def test_cluster_enabled_requires_pool_size_at_least_two(tmp_path: Path) -> None:
    # A clustered node drives concurrent background work (maintenance loop + reclaim sweep + workers)
    # against the pool, so a pool of 1 would serialize everything — refused at config load.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\npool_size = 1\n'
        "[cluster]\nenabled = true\n",
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_cluster_enabled_pool_size_two_is_ok(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\npool_size = 2\n'
        "[cluster]\nenabled = true\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.enabled is True and s.store.pool_size == 2


def test_cluster_disabled_pool_size_one_is_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The pool_size>=2 constraint only applies when cluster is enabled; a single-node SQLite deployment
    # with pool_size=1 (the constraint is moot for SQLite anyway) must still load.
    monkeypatch.chdir(tmp_path)
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        "[store]\npool_size = 1\n[cluster]\nenabled = false\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.enabled is False and s.store.pool_size == 1


# --- [cluster] leadership lease + self-fence (Workstream A2) -----------------


def test_cluster_lease_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    cfg = _write(tmp_path / "messagefoundry.toml", "")
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.leader_lease_ttl_seconds == 30.0
    assert s.cluster.leader_fence_timeout_seconds == 20.0


def test_cluster_lease_knobs_parse(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\npool_size = 3\n'
        "[cluster]\nenabled = true\nheartbeat_seconds = 5\n"
        "leader_fence_timeout_seconds = 12\nleader_lease_ttl_seconds = 20\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.leader_fence_timeout_seconds == 12.0
    assert s.cluster.leader_lease_ttl_seconds == 20.0


def test_cluster_fence_timeout_must_be_positive(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        "[cluster]\nenabled = true\nleader_fence_timeout_seconds = 0\n",
    )
    with pytest.raises(ValidationError):
        load_settings(config_path=cfg, environ={})


def test_cluster_fence_must_be_below_lease_ttl(tmp_path: Path) -> None:
    # The split-brain guard requires fence < TTL (the old leader must stop before the lease can expire).
    # fence == ttl violates it and is refused at config load.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        "[cluster]\nenabled = true\nleader_fence_timeout_seconds = 30\nleader_lease_ttl_seconds = 30\n",
    )
    with pytest.raises(ValidationError, match="leader_fence_timeout_seconds"):
        load_settings(config_path=cfg, environ={})


def test_cluster_heartbeat_must_be_below_fence(tmp_path: Path) -> None:
    # heartbeat must be < fence so a single missed renew doesn't fence the leader.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        "[cluster]\nenabled = true\nheartbeat_seconds = 20\nleader_fence_timeout_seconds = 20\n"
        "node_timeout_seconds = 40\n",
    )
    with pytest.raises(ValidationError, match="leader_fence_timeout_seconds"):
        load_settings(config_path=cfg, environ={})


# --- [cluster] leader preference / non-promotable standby (ADR 0096) --------


def test_cluster_leader_preference_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Default (no handicap, promotable) — byte-identical to before the knobs existed.
    monkeypatch.chdir(tmp_path)
    s = load_settings(environ={})
    assert s.cluster.acquire_delay_seconds == 0.0
    assert s.cluster.promotable is True


def test_cluster_leader_preference_parses(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\nacquire_delay_seconds = 5.0\npromotable = false\n",
    )
    s = load_settings(config_path=cfg, environ={"MEFOR_CLUSTER_ACQUIRE_DELAY_SECONDS": "7.5"})
    assert s.cluster.acquire_delay_seconds == 7.5  # env overrides file
    assert s.cluster.promotable is False


def test_cluster_acquire_delay_must_be_non_negative(tmp_path: Path) -> None:
    # A negative delay would let a node claim BEFORE the lease expires (a two-leader window) — refused.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\nacquire_delay_seconds = -1\n",
    )
    with pytest.raises(ValidationError, match="acquire_delay_seconds"):
        load_settings(config_path=cfg, environ={})


# --- [dr].activate + [cluster] mutual-exclusion guard (ADR 0096 rider) ------


def test_dr_activate_with_cluster_is_rejected(tmp_path: Path) -> None:
    # A DR box coming up under the DR run-profile must not also contend for the cluster lease (it could
    # win leadership and drive the primary store cross-WAN). Refused at config load.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\n[dr]\nenabled = true\nactivate = true\n",
    )
    with pytest.raises(ValidationError, match="dr.*activate|activate.*cluster"):
        load_settings(config_path=cfg, environ={})


def test_dr_enabled_but_not_activated_with_cluster_is_ok(tmp_path: Path) -> None:
    # Only [dr].activate is guarded: a provisioned-but-passive DR box (enabled, activate=false) may still
    # coexist with cluster membership (it binds no priority feeds until activated).
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
        "[cluster]\nenabled = true\n[dr]\nenabled = true\nactivate = false\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.enabled is True and s.dr.enabled is True and s.dr.activate is False


def test_dr_activate_without_cluster_is_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The classic DR posture: activate the DR profile with [cluster] disabled — must load fine.
    monkeypatch.chdir(tmp_path)
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        "[dr]\nenabled = true\nactivate = true\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.dr.activate is True and s.cluster.enabled is False


# --- [integrity] startup self-attestation (ADR 0041 D3) + dual-control config_reload (D2) ----


def test_integrity_defaults_are_safe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Safe defaults: attestation ON but alert-only (never blocks startup) — an existing deployment is
    # byte-unchanged. (The check is a no-op off an editable install regardless; see integrity.py.)
    monkeypatch.chdir(tmp_path)
    s = load_settings(environ={})
    assert s.integrity.enabled is True
    assert s.integrity.fail_closed_on_drift is False


def test_integrity_fail_closed_loads_from_file(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        "[integrity]\nenabled = true\nfail_closed_on_drift = true\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.integrity.fail_closed_on_drift is True


def test_config_reload_is_gateable_but_not_a_default_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ADR 0041 D2: config_reload is a VALID gated operation, but NOT enabled by default — turning
    # [approvals] on for replay/purge must not silently start holding every reload (deny-by-default).
    monkeypatch.chdir(tmp_path)
    default = load_settings(environ={})
    assert "config_reload" not in default.approvals.operations
    # ...and it can be opted in explicitly without a validation error.
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[approvals]\nenabled = true\noperations = ["config_reload", "connection_purge"]\n',
    )
    s = load_settings(config_path=cfg, environ={})
    assert "config_reload" in s.approvals.operations


# --- [backup] DR backup settings (ADR 0049, #60) ----------------------------


def test_backup_defaults() -> None:
    s = load_settings(environ={})
    b = s.backup
    assert b.enabled is False
    assert b.schedule_at == "02:00"
    assert b.retention_keep == 7
    assert b.snapshot_method == "vacuum_into"
    assert b.verify_after_backup is True
    assert b.full_restore_verify is False
    assert b.config_only_on_server_db is True


def test_backup_env_resolution_via_mefor_backup_prefix(tmp_path: Path) -> None:
    # AC: 'backup' is in _SECTIONS, so MEFOR_BACKUP_* env overrides resolve.
    env = {
        "MEFOR_BACKUP_ENABLED": "true",
        "MEFOR_BACKUP_DESTINATION": str(tmp_path / "nas"),
        "MEFOR_BACKUP_RETENTION_KEEP": "3",
        "MEFOR_BACKUP_SNAPSHOT_METHOD": "online_backup",
    }
    s = load_settings(environ=env)
    assert s.backup.enabled is True
    assert s.backup.destination == str(tmp_path / "nas")
    assert s.backup.retention_keep == 3
    assert s.backup.snapshot_method == "online_backup"


def test_invalid_backup_settings_rejected(tmp_path: Path) -> None:
    # AC-8: enabled with an empty destination is rejected.
    cfg = _write(tmp_path / "a.toml", "[backup]\nenabled = true\ndestination = ''\n")
    with pytest.raises((ValueError, ValidationError)):
        load_settings(config_path=cfg, environ={})

    # An unknown snapshot_method is rejected.
    cfg = _write(
        tmp_path / "b.toml",
        f"[backup]\nenabled = true\ndestination = '{tmp_path.as_posix()}'\nsnapshot_method = 'rsync'\n",
    )
    with pytest.raises((ValueError, ValidationError)):
        load_settings(config_path=cfg, environ={})

    # A non-HH:MM schedule_at is rejected.
    cfg = _write(
        tmp_path / "c.toml",
        f"[backup]\nenabled = true\ndestination = '{tmp_path.as_posix()}'\nschedule_at = '25:99'\n",
    )
    with pytest.raises((ValueError, ValidationError)):
        load_settings(config_path=cfg, environ={})

    # A negative retention_keep is rejected.
    cfg = _write(
        tmp_path / "d.toml",
        f"[backup]\nenabled = true\ndestination = '{tmp_path.as_posix()}'\nretention_keep = -1\n",
    )
    with pytest.raises((ValueError, ValidationError)):
        load_settings(config_path=cfg, environ={})

    # A cloud-URL destination is rejected (no cloud target — no new egress).
    cfg = _write(
        tmp_path / "e.toml",
        "[backup]\nenabled = true\ndestination = 's3://my-bucket/backups'\n",
    )
    with pytest.raises((ValueError, ValidationError)):
        load_settings(config_path=cfg, environ={})


def test_backup_failed_is_a_valid_alert_rule_event_type(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "f.toml",
        '[[alerts.rules]]\nevent_type = "backup_failed"\nseverity = "critical"\n',
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.alerts.rules[0].event_type == "backup_failed"


def test_delivery_priority_default_and_dr_section(tmp_path: Path) -> None:
    # [delivery].priority + [dr] load and default as decided (ADR 0048, #61).
    s = load_settings(config_path=_write(tmp_path / "g.toml", ""), environ={})
    assert s.delivery.priority.value == "normal"  # global default
    assert s.dr.enabled is False and s.dr.activate is False  # opt-in, no-op by default
    assert s.dr.priority_threshold.value == "critical"  # owner-locked default
    assert s.dr.activation_mode.value == "manual"  # only mode built this slice

    cfg = _write(
        tmp_path / "h.toml",
        "[delivery]\npriority = 'critical'\n"
        "[dr]\nenabled = true\nactivate = true\npriority_threshold = 'normal'\n"
        "takeover_hook = 'echo ok'\ntakeover_timeout_seconds = 5\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.delivery.priority.value == "critical"
    assert s.dr.enabled and s.dr.activate and s.dr.priority_threshold.value == "normal"
    assert s.dr.takeover_hook == "echo ok"


def test_invalid_priority_and_dr_settings_rejected(tmp_path: Path) -> None:
    # AC-10: an unknown [delivery].priority, an unknown/not-yet-supported [dr] value, an invalid
    # threshold, a blank hook, or a cloud-URL seed all FAIL config load (never a silent default).
    bad_configs = [
        "[delivery]\npriority = 'urgent'\n",  # unknown tier
        "[dr]\npriority_threshold = 'bogus'\n",  # invalid threshold
        "[dr]\nenabled = true\nactivation_mode = 'auto'\n",  # not-yet-supported (deferred) mode
        "[dr]\ntakeover_hook = '   '\n",  # blank-but-present hook
        "[dr]\ntakeover_timeout_seconds = 0\n",  # non-positive timeout
        "[dr]\nseed_archive = 's3://bucket/seed.mfbak'\n",  # cloud seed source
        "[dr]\nrestore_token = 'https://x/token.json'\n",  # BACKLOG #223: cloud restore-token source
    ]
    for i, body in enumerate(bad_configs):
        cfg = _write(tmp_path / f"bad_dr_{i}.toml", body)
        with pytest.raises((ValueError, ValidationError)):
            load_settings(config_path=cfg, environ={})


def test_dr_restore_token_local_path_parses(tmp_path: Path) -> None:
    # BACKLOG #223 / ADR 0102: a LOCAL restore-token path parses (default "" = OFF, byte-identical to
    # #102); a cloud URL is the only rejected form (covered above).
    assert DrSettings().restore_token == ""  # opt-in default OFF
    cfg = _write(
        tmp_path / "dr_token.toml",
        "[dr]\nenabled = true\nrestore_token = 'D:/dr/restore.token'\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.dr.restore_token == "D:/dr/restore.token"


def test_auth_mfa_secure_defaults_and_totp_skew_validation() -> None:
    # BACKLOG #187 secure-by-default posture: MFA required for the Administrator role, and a STRICT
    # (current-step-only) TOTP verify window out of the box.
    d = AuthSettings()
    assert d.require_mfa is True
    assert d.totp_skew_steps == 0
    # Documented org opt-outs parse.
    assert AuthSettings(require_mfa=False).require_mfa is False
    assert AuthSettings(totp_skew_steps=1).totp_skew_steps == 1
    assert AuthSettings(totp_skew_steps=2).totp_skew_steps == 2
    # The window is bounded 0..2 — a negative or over-wide window is rejected (an over-wide window
    # materially weakens replay resistance).
    for bad in (-1, 3):
        with pytest.raises(ValidationError):
            AuthSettings(totp_skew_steps=bad)
