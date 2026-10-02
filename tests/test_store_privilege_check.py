# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #305 part E2 (ASVS 13.2.2): the alert on the privilege probe's WARN arm, and the
read-only ``messagefoundry check-privileges`` command.

**Every elevated login here is MOCKED, on purpose.** CI's server-DB legs connect as ``sa`` and
``postgres``, which are over-granted by construction, so a green run against them proves nothing about
what the probe says for a least-privilege login, and nothing about whether the alert fires for an
elevated one. These tests hand the preflight and the command a report shaped like a real
``sysadmin`` read, a real ``unobservable`` read and a real clean read, and assert what each surface
does with it. The SQL the probes run is pinned elsewhere (``tests/test_store_privilege_preflight.py``
and ``tests/test_store_privilege_schema_split.py``).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import types
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import (
    _ALERT_EVENT_TYPES,
    AlertRule,
    SchemaManagement,
    ServiceSettings,
    SqlAuth,
    StoreBackend,
    StorePrivilegeStatus,
    StoreSettings,
)
from messagefoundry.pipeline.alert_sinks import AlertRuleSet
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.privilege_check import (
    EXIT_CLEAN,
    EXIT_OVER_PRIVILEGED,
    EXIT_SETTINGS,
    EXIT_UNOBSERVABLE,
    HopState,
    exit_code_for,
    settings_hops,
    store_hop,
)
from messagefoundry.store.base import probe_store_privileges
from messagefoundry.store.privilege import (
    StorePrivilegeError,
    StorePrivilegeReport,
    run_store_privilege_preflight,
    sqlserver_excess,
    store_privilege_alert_subject,
)

if TYPE_CHECKING:
    from messagefoundry.store.base import Store

REPO = Path(__file__).resolve().parent.parent


# --- mocked principals ------------------------------------------------------------------------


def _sysadmin_report() -> StorePrivilegeReport:
    """What the SQL Server probe returns for a ``sysadmin`` login under the external default."""
    return StorePrivilegeReport(
        backend=StoreBackend.SQLSERVER,
        status=StorePrivilegeStatus.OBSERVED,
        principal="CORP\\mefor-svc$",
        database="MessageFoundry",
        server_roles=("sysadmin",),
        database_roles=("db_owner",),
        excess=sqlserver_excess(
            server_roles=("sysadmin",),
            database_roles=("db_owner",),
            control_server=True,
            control_database=True,
            database="MessageFoundry",
            external=True,
        ),
    )


def _unobservable_report() -> StorePrivilegeReport:
    return StorePrivilegeReport(
        backend=StoreBackend.SQLSERVER,
        status=StorePrivilegeStatus.UNOBSERVABLE,
        detail="the privilege query returned NULL for 3 of 19 probed grant(s)",
    )


def _clean_report() -> StorePrivilegeReport:
    return StorePrivilegeReport(
        backend=StoreBackend.SQLSERVER,
        status=StorePrivilegeStatus.OBSERVED,
        principal="CORP\\mefor-svc$",
        database="MessageFoundry",
        database_roles=("db_datareader", "db_datawriter"),
    )


class _FakeStore:
    """Only what the preflight touches: a backend, a probe and an audit sink."""

    def __init__(self, report: StorePrivilegeReport) -> None:
        self.backend = report.backend
        self._report = report
        self.audits: list[str] = []

    async def probe_principal_privileges(self) -> StorePrivilegeReport:
        return self._report

    async def record_audit(self, action: str, *, actor: str | None, detail: str | None) -> None:
        self.audits.append(action)


def _store(report: StorePrivilegeReport) -> Store:
    """The fake, typed as the ``Store`` the preflight's signature names: it implements only the
    slice the preflight touches."""
    return cast("Store", _FakeStore(report))


class _RecordingSink(LoggingAlertSink):
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.cleared: list[str] = []

    def store_privilege_clean(self, name: str) -> None:
        self.cleared.append(name)

    def store_privilege_warning(
        self, name: str, *, finding: str, excess_count: int, detail: str
    ) -> None:
        self.events.append(
            {"name": name, "finding": finding, "excess_count": excess_count, "detail": detail}
        )


class _RaisingSink(LoggingAlertSink):
    def store_privilege_warning(
        self, name: str, *, finding: str, excess_count: int, detail: str
    ) -> None:
        raise RuntimeError("sink down")


# --- the alert on the WARN arm ----------------------------------------------------------------


async def test_a_mocked_sysadmin_login_warns_and_alerts(caplog: pytest.LogCaptureFixture) -> None:
    """Accepting the over-grant (ADR 0199's opt-out) lets the start proceed; it does not quiet the
    warning or the page."""
    sink = _RecordingSink()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.privilege"):
        report = await run_store_privilege_preflight(
            _store(_sysadmin_report()),
            require_least_privilege=False,
            enforcing=True,
            over_grant_accepted=True,
            alert_sink=sink,
        )
    assert report.excess
    assert any("BEYOND the documented" in r.getMessage() for r in caplog.records)
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event["name"] == "store:CORP\\mefor-svc$@MessageFoundry"
    assert event["finding"] == "over_granted"
    assert event["excess_count"] == len(report.excess)
    assert "server role sysadmin" in event["detail"]


async def test_an_unobservable_probe_alerts_under_its_own_finding() -> None:
    sink = _RecordingSink()
    await run_store_privilege_preflight(
        _store(_unobservable_report()),
        require_least_privilege=False,
        enforcing=True,
        alert_sink=sink,
    )
    assert [e["finding"] for e in sink.events] == ["unobservable"]
    assert sink.events[0]["excess_count"] == 0
    assert "could not observe" in sink.events[0]["detail"]


async def test_a_clean_login_raises_no_alert() -> None:
    """The control that makes the two above mean something: a least-privilege read stays silent."""
    sink = _RecordingSink()
    await run_store_privilege_preflight(
        _store(_clean_report()), require_least_privilege=False, enforcing=True, alert_sink=sink
    )
    assert sink.events == []
    # ...and it clears an open warning from an earlier start, so a fixed grant clears the dashboard.
    assert sink.cleared == ["store:CORP\\mefor-svc$@MessageFoundry"]


async def test_sqlite_raises_no_alert() -> None:
    sink = _RecordingSink()
    report = StorePrivilegeReport(
        backend=StoreBackend.SQLITE, status=StorePrivilegeStatus.NOT_APPLICABLE, detail="a file"
    )
    await run_store_privilege_preflight(
        _store(report), require_least_privilege=False, enforcing=True, alert_sink=sink
    )
    assert sink.events == []
    assert sink.cleared == []


async def test_the_refusing_arm_alerts_before_it_refuses() -> None:
    sink = _RecordingSink()
    with pytest.raises(StorePrivilegeError):
        await run_store_privilege_preflight(
            _store(_sysadmin_report()),
            require_least_privilege=True,
            enforcing=True,
            alert_sink=sink,
        )
    assert [e["finding"] for e in sink.events] == ["over_granted"]


async def test_a_failing_sink_never_masks_the_finding(caplog: pytest.LogCaptureFixture) -> None:
    fake = _FakeStore(_sysadmin_report())
    with caplog.at_level(logging.ERROR, logger="messagefoundry.store.privilege"):
        report = await run_store_privilege_preflight(
            cast("Store", fake),
            require_least_privilege=False,
            enforcing=True,
            over_grant_accepted=True,
            alert_sink=_RaisingSink(),
        )
    assert report.excess
    assert fake.audits == ["store_privilege_preflight"]
    assert any("alert" in r.getMessage() for r in caplog.records)


def test_each_principal_is_its_own_alert_subject() -> None:
    """HA nodes and engine shards share a store and may log in as different principals: one node's
    clean start must not resolve the warning another still earns."""
    other = StorePrivilegeReport(
        backend=StoreBackend.SQLSERVER,
        status=StorePrivilegeStatus.OBSERVED,
        principal="CORP\\mefor-node2$",
        database="MessageFoundry",
    )
    assert store_privilege_alert_subject(_sysadmin_report()) != store_privilege_alert_subject(other)
    assert store_privilege_alert_subject(_unobservable_report()) == "store"


async def test_the_notifier_payload_carries_no_count_for_an_unread_principal() -> None:
    from messagefoundry.pipeline.alert_sinks import NotifierAlertSink

    events: list[dict[str, Any]] = []

    class _Capture(NotifierAlertSink):
        def _emit(self, event: dict[str, Any]) -> None:
            events.append(event)

    sink = _Capture.__new__(_Capture)
    sink.store_privilege_warning("store", finding="unobservable", excess_count=0, detail="x")
    sink.store_privilege_warning("store:a@b", finding="over_granted", excess_count=2, detail="y")
    assert "excess_count" not in events[0]
    assert events[1]["excess_count"] == 2


def test_the_event_is_rule_targetable_and_routes() -> None:
    """A name a sink emits but the rule validator refuses is silently un-routable."""
    assert "store_privilege_warning" in _ALERT_EVENT_TYPES
    rule = AlertRule(event_type="store_privilege_warning")
    decision = AlertRuleSet([rule]).decide(
        {"type": "store_privilege_warning", "connection": "store"}
    )
    assert decision is not None


async def test_a_clean_start_auto_resolves_the_open_warning() -> None:
    """ADR 0044 durable state: the inverse event resolves the instance the warning opened."""
    from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE

    assert _AUTO_RESOLVE["store_privilege_clean"] == "store_privilege_warning"
    # The inverse is not a page, so a rule must not be able to target it.
    assert "store_privilege_clean" not in _ALERT_EVENT_TYPES


def test_an_unobservable_alert_line_does_not_read_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """The sink's own logger is swapped for a recorder: caplog depends on logger state other tests in
    the same xdist worker may change, and this assertion is about the text, not the plumbing."""
    import messagefoundry.pipeline.alerts as alerts_module

    lines: list[str] = []

    class _Recorder:
        def warning(self, msg: str, *args: object) -> None:
            lines.append(msg % args)

    monkeypatch.setattr(alerts_module, "log", _Recorder())
    LoggingAlertSink().store_privilege_warning(
        "store", finding="unobservable", excess_count=0, detail="COULD NOT OBSERVE"
    )
    (line,) = lines
    assert "not read" in line
    assert "0 privilege" not in line


def test_the_logging_sink_writes_the_alert(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().store_privilege_warning(
            "store", finding="over_granted", excess_count=2, detail="server role sysadmin"
        )
    assert any("ALERT store_privilege_warning" in r.getMessage() for r in caplog.records)


def test_the_serve_path_hands_the_notifier_to_the_preflight() -> None:
    """The alert is only as good as its wiring: the lifespan must pass a sink, not rely on a default."""
    source = (REPO / "messagefoundry" / "api" / "app.py").read_text(encoding="utf-8")
    start = source.index("await run_store_privilege_preflight(")
    call = source[start : source.index(".posture()", start)]
    assert "alert_sink=notifier or LoggingAlertSink()" in call


# --- the read-only store probe ----------------------------------------------------------------


async def test_the_sqlite_probe_opens_nothing(tmp_path: Path) -> None:
    target = tmp_path / "never.db"
    report = await probe_store_privileges(StoreSettings(path=str(target)))
    assert report.status is StorePrivilegeStatus.NOT_APPLICABLE
    assert not target.exists()


async def test_a_connect_failure_is_unobservable_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry.store.postgres import PostgresStore

    async def _boom(cls: Any, settings: StoreSettings, *, posture: Any = None) -> Any:
        raise OSError("connect failed password=hunter2")

    monkeypatch.setattr(PostgresStore, "probe_privileges", classmethod(_boom))
    settings = StoreSettings(
        backend=StoreBackend.POSTGRES, server="db.invalid", database="mf", username="mefor"
    )
    report = await probe_store_privileges(settings)
    assert report.status is StorePrivilegeStatus.UNOBSERVABLE
    assert "hunter2" not in report.detail


async def test_the_sqlserver_probe_runs_no_schema_work_and_closes_its_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read-only means no ``_ensure_schema``, no ``ALTER DATABASE`` and no migration: one pool, one
    probe, one close. The probe itself is stubbed to the mocked ``sysadmin`` read."""
    from messagefoundry.store.sqlserver import SqlServerStore

    events: list[str] = []

    class _Pool:
        def close(self) -> None:
            events.append("pool.close")

        async def wait_closed(self) -> None:
            return None

    async def _create_pool(**kwargs: Any) -> _Pool:
        events.append(f"create_pool maxsize={kwargs['maxsize']}")
        return _Pool()

    monkeypatch.setitem(sys.modules, "aioodbc", types.SimpleNamespace(create_pool=_create_pool))

    async def _probe(self: SqlServerStore) -> StorePrivilegeReport:
        events.append("probe")
        return _sysadmin_report()

    async def _forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the read-only probe must not run schema or database-option work")

    monkeypatch.setattr(SqlServerStore, "probe_principal_privileges", _probe)
    monkeypatch.setattr(SqlServerStore, "_ensure_schema", _forbidden)
    monkeypatch.setattr(SqlServerStore, "_ensure_database_options", staticmethod(_forbidden))
    settings = StoreSettings(
        backend=StoreBackend.SQLSERVER,
        auth=SqlAuth.INTEGRATED,
        server="db.invalid",
        database="MessageFoundry",
    )
    report = await probe_store_privileges(settings)
    assert report.excess
    assert events == ["create_pool maxsize=1", "probe", "pool.close"]


async def test_a_close_failure_keeps_the_observed_over_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Teardown failing after a finished read must not turn exit 3 into exit 4."""
    from messagefoundry.store.sqlserver import SqlServerStore

    class _Pool:
        def close(self) -> None:
            raise OSError("pool close failed")

        async def wait_closed(self) -> None:
            return None

    async def _create_pool(**kwargs: Any) -> _Pool:
        return _Pool()

    async def _probe(self: SqlServerStore) -> StorePrivilegeReport:
        return _sysadmin_report()

    monkeypatch.setitem(sys.modules, "aioodbc", types.SimpleNamespace(create_pool=_create_pool))
    monkeypatch.setattr(SqlServerStore, "probe_principal_privileges", _probe)
    report = await probe_store_privileges(_mssql())
    assert report.status is StorePrivilegeStatus.OBSERVED
    assert report.excess


# --- the pure half of the command -------------------------------------------------------------


def _mssql() -> StoreSettings:
    return StoreSettings(
        backend=StoreBackend.SQLSERVER,
        auth=SqlAuth.INTEGRATED,
        server="db.invalid",
        database="MessageFoundry",
    )


def test_store_hop_states_follow_the_report() -> None:
    assert store_hop(_sysadmin_report(), _mssql()).state is HopState.OVER_GRANTED
    assert store_hop(_unobservable_report(), _mssql()).state is HopState.UNOBSERVABLE
    assert store_hop(_clean_report(), _mssql()).state is HopState.CLEAN


def test_the_store_hop_names_the_grant_schema_management_selects() -> None:
    external = store_hop(_clean_report(), _mssql())
    auto = store_hop(
        _clean_report(), _mssql().model_copy(update={"schema_management": SchemaManagement.AUTO})
    )
    assert "db_ddladmin" not in external.minimal
    assert "db_ddladmin" in auto.minimal


def test_exit_codes_are_distinct_and_over_privilege_wins() -> None:
    codes = {EXIT_CLEAN, EXIT_SETTINGS, EXIT_OVER_PRIVILEGED, EXIT_UNOBSERVABLE}
    assert len(codes) == 4
    # 2 is argparse's usage error, so the command never spends it.
    assert 2 not in codes
    over, blind, clean = (
        store_hop(r, _mssql())
        for r in (_sysadmin_report(), _unobservable_report(), _clean_report())
    )
    assert exit_code_for([clean]) == EXIT_CLEAN
    assert exit_code_for([blind]) == EXIT_UNOBSERVABLE
    assert exit_code_for([over]) == EXIT_OVER_PRIVILEGED
    assert exit_code_for([blind, over]) == EXIT_OVER_PRIVILEGED


def test_a_hop_the_engine_cannot_probe_says_so_and_never_fails_the_run() -> None:
    """SMTP and the IdP have no probe and print as not probed. Vault and LDAP are probed; clean
    stub readings stand in for them here, and tests/test_vault_ldap_privilege_probes.py covers
    the probes themselves."""
    from messagefoundry.auth.ldap import BindAccountReading
    from messagefoundry.privilege_probes import VaultTokenReading

    settings = ServiceSettings.model_validate(
        {
            "store": {"key_provider": "vault"},
            "auth": {
                "ad_enabled": True,
                "ad_server": "ldaps://dc1.example.com:636",
                "ad_domain": "example.com",
                "ad_user_search_base": "DC=example,DC=com",
                "ad_bind_dn": "CN=mefor-ldap,OU=Svc,DC=example,DC=com",
                "ad_bind_password": "ldap-secret-value",
            },
            "alerts": {
                "email_smtp_host": "smtp.example.com",
                "email_from": "mefor@example.com",
                "email_to": ["ops@example.com"],
                "email_username": "mefor-smtp",
            },
        }
    )
    hops = {
        h.hop: h
        for h in settings_hops(
            settings,
            vault_probe=lambda consumer: VaultTokenReading(looked_up=True),
            ldap_probe=lambda: BindAccountReading("u:EXAMPLE\mefor-ldap", ("S-1-5-32-545",)),
        )
    }
    assert hops["vault.store"].state is HopState.CLEAN
    assert hops["ldap"].state is HopState.CLEAN
    assert hops["smtp"].state is HopState.NOT_PROBED
    assert hops["idp"].state is HopState.NOT_CONFIGURED
    assert "CN=mefor-ldap" in hops["ldap"].identity
    assert "mefor-smtp" in hops["smtp"].identity
    assert exit_code_for(list(hops.values())) == EXIT_CLEAN
    assert "ldap-secret-value" not in json.dumps([h.as_dict() for h in hops.values()])


# --- the command ------------------------------------------------------------------------------


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("MEFOR_"):
            monkeypatch.delenv(key, raising=False)


def _server_toml(tmp_path: Path) -> Path:
    toml = tmp_path / "svc.toml"
    toml.write_text(
        '[store]\nbackend = "postgres"\nserver = "db.invalid"\ndatabase = "messagefoundry"\n'
        'username = "mefor_runtime"\n'
        '[alerts]\nemail_smtp_host = "smtp.example.com"\nemail_from = "mefor@example.com"\n'
        'email_to = ["ops@example.com"]\nemail_username = "mefor-smtp"\n',
        encoding="utf-8",
    )
    return toml


def _stub_probe(monkeypatch: pytest.MonkeyPatch, report: StorePrivilegeReport) -> None:
    async def _probe(settings: StoreSettings, *, posture: Any = None) -> StorePrivilegeReport:
        return report

    monkeypatch.setattr("messagefoundry.store.base.probe_store_privileges", _probe)


def test_cli_exits_nonzero_on_a_mocked_sysadmin_and_names_the_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_env(monkeypatch)
    _stub_probe(monkeypatch, _sysadmin_report())
    assert main(["check-privileges", "--service-config", str(_server_toml(tmp_path))]) == 3
    out = capsys.readouterr().out
    assert "server role sysadmin" in out
    assert "store: OVER-GRANTED" in out


def test_cli_exits_on_an_unobservable_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_env(monkeypatch)
    _stub_probe(monkeypatch, _unobservable_report())
    assert main(["check-privileges", "--service-config", str(_server_toml(tmp_path))]) == 4


def test_cli_json_reports_every_family_and_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("MEFOR_ALERTS_EMAIL_PASSWORD", "smtp-secret-value")
    monkeypatch.setenv("MEFOR_STORE_PASSWORD", "store-secret-value")
    _stub_probe(monkeypatch, _clean_report())
    argv = ["check-privileges", "--service-config", str(_server_toml(tmp_path)), "--json"]
    assert main(argv) == 0
    out = capsys.readouterr().out
    assert "smtp-secret-value" not in out
    assert "store-secret-value" not in out
    payload = json.loads(out)
    assert payload["exit_code"] == 0
    by_hop = {h["hop"]: h for h in payload["hops"]}
    assert set(by_hop) == {"store", "vault", "ldap", "smtp", "idp"}
    assert by_hop["store"]["state"] == "clean"
    assert by_hop["smtp"]["state"] == "not_probed"


def test_cli_says_serve_would_refuse_an_over_grant_under_enforce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """ADR 0199: the read-out states what ``serve`` would now do with the same observation, so a DBA
    running it before a start learns about the refusal before the service does."""
    _clear_env(monkeypatch)
    _stub_probe(monkeypatch, _sysadmin_report())
    assert main(["check-privileges", "--service-config", str(_server_toml(tmp_path))]) == 3
    out = capsys.readouterr().out
    assert "serve: would REFUSE to start" in out
    assert "[security].allow_over_granted_store_principal" in out


def test_cli_says_serve_would_start_under_the_opt_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The exit code stays 3: the grant is still wider than the runbook's, whatever serve does."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_OVER_GRANTED_STORE_PRINCIPAL", "true")
    _stub_probe(monkeypatch, _sysadmin_report())
    argv = ["check-privileges", "--service-config", str(_server_toml(tmp_path)), "--json"]
    assert main(argv) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["serve"].startswith("would start: the over-grant is accepted")


def test_cli_says_serve_would_only_warn_under_enforcement_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    _stub_probe(monkeypatch, _sysadmin_report())
    assert main(["check-privileges", "--service-config", str(_server_toml(tmp_path))]) == 3
    assert "serve: would start with a warning (enforcement is 'warn')" in capsys.readouterr().out


def test_cli_names_the_declaration_when_it_refuses_an_unobservable_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("MEFOR_STORE_REQUIRE_LEAST_PRIVILEGE", "true")
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_OVER_GRANTED_STORE_PRINCIPAL", "true")
    _stub_probe(monkeypatch, _unobservable_report())
    assert main(["check-privileges", "--service-config", str(_server_toml(tmp_path))]) == 4
    out = capsys.readouterr().out
    assert "serve: would REFUSE to start: [store].require_least_privilege is set" in out


def test_cli_says_serve_would_only_warn_on_an_unobservable_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_env(monkeypatch)
    _stub_probe(monkeypatch, _unobservable_report())
    assert main(["check-privileges", "--service-config", str(_server_toml(tmp_path))]) == 4
    assert "serve: would start with a warning" in capsys.readouterr().out


def test_cli_on_sqlite_is_not_applicable_and_creates_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_env(monkeypatch)
    target = tmp_path / "never.db"
    toml = tmp_path / "svc.toml"
    toml.write_text(f'[store]\npath = "{target.as_posix()}"\n', encoding="utf-8")
    assert main(["check-privileges", "--service-config", str(toml)]) == 0
    assert "not applicable" in capsys.readouterr().out
    assert not target.exists()


def test_cli_db_overrides_the_store_path_like_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_env(monkeypatch)
    toml = tmp_path / "svc.toml"
    toml.write_text(f'[store]\npath = "{(tmp_path / "file.db").as_posix()}"\n', encoding="utf-8")
    override = tmp_path / "override.db"
    argv = ["check-privileges", "--service-config", str(toml), "--db", str(override), "--json"]
    assert main(argv) == 0
    store = next(h for h in json.loads(capsys.readouterr().out)["hops"] if h["hop"] == "store")
    assert "override.db" in store["identity"]
    assert not override.exists()


def test_cli_exits_1_when_the_settings_do_not_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_env(monkeypatch)
    assert main(["check-privileges", "--service-config", str(tmp_path / "missing.toml")]) == 1


# --- the docs ---------------------------------------------------------------------------------


def test_security_doc_carries_the_per_hop_matrix() -> None:
    text = (REPO / "docs" / "SECURITY.md").read_text(encoding="utf-8")
    assert "messagefoundry check-privileges" in text
    for hop in ("Store", "Vault", "LDAP", "SMTP", "IdP"):
        assert f"| {hop}" in text, hop


def _step_six() -> str:
    text = (REPO / "docs" / "DEPLOY-SERVER-DB.md").read_text(encoding="utf-8")
    section = text[text.index("### 1.1 Integrated (gMSA)") : text.index("### 1.2 ")]
    step = section[section.index("**6. ") :]
    return step[: step.index("> **Why the `$`:**")]


def test_the_gmsa_runbook_has_a_numbered_step_that_runs_the_command() -> None:
    step = _step_six()
    fence = step.index("```powershell")
    assert "messagefoundry check-privileges" in step[fence : step.index("```", fence + 3)]


def test_the_documented_exit_codes_match_the_code(capsys: pytest.CaptureFixture[str]) -> None:
    """The step, the SECURITY.md paragraph and ``--help`` each state the codes; all three must agree
    with the constants a job keys on."""
    step = _step_six()
    for code in (EXIT_CLEAN, EXIT_SETTINGS, EXIT_OVER_PRIVILEGED, EXIT_UNOBSERVABLE):
        assert f"exits {code}" in step, code
    security = " ".join((REPO / "docs" / "SECURITY.md").read_text(encoding="utf-8").split())
    assert (
        f"exits {EXIT_CLEAN} when every probe that ran was clean, {EXIT_OVER_PRIVILEGED} on an "
        f"over-grant, {EXIT_UNOBSERVABLE} when a probe could not read its principal, and "
        f"{EXIT_SETTINGS} when the settings do not load"
    ) in security
    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert f"Exits {EXIT_OVER_PRIVILEGED} on an over-grant, {EXIT_UNOBSERVABLE} when" in help_text
