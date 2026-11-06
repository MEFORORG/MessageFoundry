# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Orchestrate the deployment verify: host checks, store connectivity, smoke, manual rows."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from messagefoundry.config.settings import ServiceSettings, StoreBackend
from messagefoundry.transports.db_endpoint import (
    SQLSERVER_DEFAULT_DRIVER,
    generic_driver_family,
    sqlserver_preset_refusal,
)
from messagefoundry.verify.checks import (
    OdbcHops,
    check_credential_generation,
    check_lockable_accounts,
    run_host_checks,
)
from messagefoundry.verify.model import CheckResult, Status
from messagefoundry.verify.smoke import (
    check_store_connectivity,
    smoke_self,
    synthetic_message,
)

if TYPE_CHECKING:
    from messagefoundry.config.wiring import Registry

_log = logging.getLogger(__name__)

#: The five runnable sections; default is all of them. "federation" (ADR 0142) is offline and
#: emits a single SKIP row when [auth].oidc_enabled is false, so it costs a non-federated
#: deployment one line and never changes its exit code.
ALL_SECTIONS: tuple[str, ...] = ("host", "store", "smoke", "manual", "federation")

_DEFAULT_DICOM_PORT = 11112
#: The ``--config`` default, which is the sample graph.
_DEFAULT_CONFIG_DIR = "samples/config"
_DEFAULT_API_PORT = 8765

# Human-on-the-box steps the verifier cannot self-check — echoed MANUAL with instructions, never faked.
_MANUAL_ROWS: tuple[tuple[str, str, str], ...] = (
    ("manual.ad", "AD / Kerberos login", "sign in with a domain account (AD/LDAP/Kerberos)"),
    ("manual.mfa", "TOTP MFA", "enroll + sign in with native TOTP MFA on a local account"),
    (
        "manual.tls",
        "API bind + TLS",
        "confirm the API binds 127.0.0.1 (or TLS if off-loopback) and rejects unauthenticated calls",
    ),
    (
        "manual.nssm",
        "NSSM service",
        "install/uninstall the NSSM service; confirm autostart, restart-after-crash, stdout->log",
    ),
    (
        "manual.disposition",
        "End-to-end disposition",
        "in the console, confirm the smoke message shows RECEIVED->ROUTED->PROCESSED and the outbound delivered",
    ),
)


def _load_settings(service_config: str | None) -> tuple[ServiceSettings | None, str | None]:
    """Load the service settings, returning ``(settings, error)``.

    An **absent** config is NOT an error: ``load_settings`` returns defaults, so ``settings`` is
    non-None on a box with no ``messagefoundry.toml``. A ``None`` here therefore always means the
    config could not be *loaded* — an explicit ``--service-config`` path that does not exist, or a
    config that exists and fails to validate. Both are real deployment problems.

    This used to collapse both into a bare ``None``, so every dependent row read "no service settings
    — pass --service-config", sending an operator to look for a missing file that was usually present
    and simply broken. The reason is now surfaced (see the ``config.load`` row).

    The reason is rendered by :func:`~messagefoundry.config.settings.settings_error_detail`, which
    used to be a private copy here. A verify report is written to disk (``--report-md``/
    ``--report-json``) and pasted into tickets, so the detail must never carry ``input`` -- the value
    a failing ``[store]`` or ``[auth]`` section was given, which is where the env-supplied secrets
    are. That reasoning applies to every caller that shows a load failure, not just this one.
    """
    from pydantic import ValidationError

    from messagefoundry.config.settings import load_settings, settings_error_detail

    try:
        return load_settings(config_path=service_config), None
    except (FileNotFoundError, ValueError, ValidationError, OSError) as exc:
        # OSError covers a --service-config that names a DIRECTORY; the mechanism is stated once,
        # at messagefoundry.__main__._load_service_settings. It costs more here than there: the
        # report IS this command's output, so a traceback leaves an operator with no report at all.
        return None, settings_error_detail(exc)


def _writable_dir(settings: ServiceSettings | None) -> Path:
    if settings is not None and settings.store.backend is StoreBackend.SQLITE:
        return Path(settings.store.path).resolve().parent
    return Path.cwd()


def _microsoft_driver(driver: str) -> bool:
    """Whether ``driver``, an ``odbc_driver`` as written, is a Microsoft SQL Server driver: one the
    SQL Server preset accepts, or the generic dialect's Microsoft family."""
    return (
        sqlserver_preset_refusal({"odbc_driver": driver}) is None
        or generic_driver_family(driver) == "msodbc"
    )


class _Graph:
    """The ``--config`` graph, loaded at most once per verify run (BACKLOG #3803 R2).

    The hop census and the self smoke both read it, and a load runs every config module, so a
    second load ran them twice. The first load's outcome, the graph or what the load raised, is
    what every caller gets. It allows an empty graph, which the census reads as one with no hop,
    an answer rather than an unknown; :func:`~messagefoundry.verify.smoke.smoke_self` applies the
    empty-graph rule itself."""

    def __init__(self, config_dir: str) -> None:
        self.config_dir = config_dir
        self._outcome: Registry | BaseException | None = None

    def __call__(self) -> Registry:
        if self._outcome is None:
            from messagefoundry.config.wiring import load_config

            try:
                self._outcome = load_config(self.config_dir, allow_empty=True)
            except (Exception, SystemExit) as exc:  # each caller maps what was raised its own way
                self._outcome = exc
        if isinstance(self._outcome, BaseException):
            raise self._outcome
        return self._outcome


def _odbc_hops(
    settings: ServiceSettings | None,
    service_config: str | None,
    config_dir: str,
    graph: Callable[[], Registry],
    *,
    driver_18: bool = False,
) -> OdbcHops:
    """Which ODBC hops this deployment takes, for the ``host.ciphers`` row, or with ``driver_18``
    which of them name ODBC Driver 18 for SQL Server, for the ``host.odbc`` row (BACKLOG #3277,
    #3803 R6).

    The SQL Server store, which always names Driver 18, is read from the service settings. The
    graph's entries are read by :func:`~messagefoundry.config.wiring.odbc_hops` from ``graph``, the
    run's one load of ``config_dir``, only when the store has not already shown a hop. A hop found
    either way is enough. For ``host.ciphers`` a hop is an entry on a Microsoft SQL Server driver,
    whose TLS the host policy decides; for ``host.odbc`` it is an entry naming Driver 18, which
    pyodbc must list, so an entry on another driver needs nothing of that row.

    Anything not read leaves the answer unknown rather than "no hop", because a hop could sit in it:
    a graph that does not load, settings that did not load, or a shell with no
    ``MEFOR_STORE_BACKEND``. That variable overrides the settings file, and an operator's shell
    need not carry the service's own environment, so without it even a file that says sqlite does
    not show the service's store (BACKLOG #3803 R1). An entry whose driver is an ``env()``
    reference is unknown too, and so for ``host.ciphers`` is one on another vendor's driver, which
    may bring its own TLS."""
    if settings is not None and settings.store.backend is StoreBackend.SQLSERVER:
        return OdbcHops(found=("the [store] backend is sqlserver",))
    from messagefoundry.config.settings import settings_file_path
    from messagefoundry.config.wiring import WiringError, odbc_hops
    from messagefoundry.redaction import codec_safe_str

    if Path(config_dir) == Path(_DEFAULT_CONFIG_DIR):
        # The CLI fills this in when --config is left out, so it is not the deployment's graph.
        return OdbcHops(unknown=f"--config was left at {_DEFAULT_CONFIG_DIR!r}; pass --config")
    if not Path(config_dir).is_dir():
        return OdbcHops(unknown=f"no config dir at {config_dir!r}; pass --config")
    try:
        reg = graph()
    except (WiringError, OSError, ImportError, SyntaxError, ValueError, SystemExit) as exc:
        # SystemExit: a config module that exits at import must not end the verify run.
        reason = codec_safe_str(exc)[:200]
        return OdbcHops(unknown=f"the config dir {config_dir!r} did not load: {reason}")
    found: list[str] = []
    undecided: list[str] = []
    for kind, name, driver in odbc_hops(reg):
        label = f"{kind} {name}"
        if driver is None:
            undecided.append(f"{label} names its odbc_driver by an env() reference")
        elif driver_18:
            if driver.strip().lower() == SQLSERVER_DEFAULT_DRIVER.lower():
                found.append(label)
        elif _microsoft_driver(driver):
            found.append(label)
        else:
            undecided.append(
                f"{label} uses the driver {driver!r}, which may bring its own TLS, and this row "
                "does not read it"
            )
    if found:
        return OdbcHops(found=tuple(found))
    if undecided:
        return OdbcHops(unknown=undecided[0])
    if settings is None:
        return OdbcHops(unknown="service settings did not load, so the store backend is not known")
    # Spelled as load_settings reads it: the prefix exactly, the rest in any case.
    if not any(n.startswith("MEFOR_") and n[6:].lower() == "store_backend" for n in os.environ):
        if service_config is None and not settings_file_path(None).exists():
            return OdbcHops(
                unknown="no service config was read, so the store may be SQL Server; pass "
                "--service-config, and set MEFOR_STORE_BACKEND as the service sets it"
            )
        return OdbcHops(
            unknown=f"the store backend reads {settings.store.backend.value} from the service "
            "config or its defaults, but MEFOR_STORE_BACKEND, which overrides both, is not set in "
            "this shell, and the service's own environment may set it to sqlserver; set it here "
            "as the service sets it"
        )
    return OdbcHops(judged=f"the service settings and the graph in {config_dir!r}")


def _manual_rows() -> list[CheckResult]:
    return [CheckResult(rid, title, Status.MANUAL, detail) for rid, title, detail in _MANUAL_ROWS]


def _run_live_smoke(
    message: str,
    *,
    host: str,
    port: int,
    settings: ServiceSettings | None,
    check_disposition: bool,
    disposition_timeout: float,
    smoke_tls: bool = False,
    smoke_tls_ca: str | None = None,
) -> list[CheckResult]:
    """Live MLLP smoke (ACK), plus the opt-in store-disposition follow-up.

    The disposition follow-up snapshots the store *before* sending (so a re-used synthetic control id
    can't match a prior run), then — only if the ACK passed — polls for the message reaching a terminal
    disposition. It is the real "did it process" check; ``smoke.live`` alone proves only the ACK.

    ``smoke_tls`` sends the frame inside TLS, for an inbound configured ``tls = true`` (BACKLOG
    #1178). It is declared, never sniffed: the smoke does not probe one protocol and retry the
    other, because that fall-back is what ASVS 12.3.1 forbids.
    """
    from messagefoundry.parsing.peek import HL7PeekError, Peek
    from messagefoundry.verify.smoke import (
        check_smoke_disposition,
        live_smoke_ssl_context,
        newest_message_id,
        smoke_live,
    )

    control_id: str | None = None
    baseline_id: str | None = None
    baseline_error: str | None = None
    if check_disposition and settings is not None:
        try:
            control_id = Peek.parse(message).control_id
        except HL7PeekError:
            control_id = None
        if control_id:
            try:
                baseline_id = newest_message_id(settings.store, control_id)
            except Exception as exc:  # any open or driver failure: a row, never a crashed run
                # BACKLOG #1708: the read-only open refuses a store it cannot read as it is, such
                # as another application's SQLite file. Never fall back to no baseline: the
                # synthetic control id is fixed, so a prior run's message would then match.
                # Class named, and a codec error never printed raw (vault BACKLOG #3185).
                from messagefoundry.redaction import codec_safe_line

                baseline_error = codec_safe_line(exc)
                _log.warning("verify: the pre-send baseline read failed: %s", baseline_error)

    ctx = live_smoke_ssl_context(ca_file=smoke_tls_ca) if smoke_tls else None
    results = [smoke_live(host=host, port=port, message=message, ssl_context=ctx)]
    if not check_disposition:
        return results

    rid, title = "smoke.disposition", "Live smoke disposition"
    if settings is None:
        results.append(
            CheckResult(
                rid,
                title,
                Status.SKIP,
                "service settings did not load — see the config.load row",
            )
        )
    elif not control_id:
        results.append(
            CheckResult(rid, title, Status.SKIP, "no MSH-10 control id in the synthetic message")
        )
    elif baseline_error is not None:
        results.append(
            CheckResult(
                rid,
                title,
                Status.ERROR,
                "could not read the pre-send baseline from the store, so the disposition was not "
                f"polled: {baseline_error}",
            )
        )
    elif results[0].status is not Status.PASS:
        results.append(
            CheckResult(rid, title, Status.SKIP, "live smoke did not ACK — disposition not polled")
        )
    else:
        results.append(
            check_smoke_disposition(
                settings.store,
                control_id=control_id,
                baseline_id=baseline_id,
                timeout=disposition_timeout,
            )
        )
    return results


def run_verify(
    *,
    config_dir: str = _DEFAULT_CONFIG_DIR,
    service_config: str | None = None,
    sections: Sequence[str] | None = None,
    smoke_mode: str = "self",
    engine_host: str = "127.0.0.1",
    mllp_port: int = 2575,
    inbound: str | None = None,
    check_disposition: bool = False,
    disposition_timeout: float = 15.0,
    smoke_tls: bool = False,
    smoke_tls_ca: str | None = None,
    fed_id_token: str | None = None,
    fed_jwks: str | None = None,
    fed_nonce: str | None = None,
) -> list[CheckResult]:
    """Run the selected verify sections and return one :class:`CheckResult` per check.

    ``sections`` defaults to all of :data:`ALL_SECTIONS`. ``smoke_mode`` is ``self`` (dry-run through
    the config, safe anywhere), ``live`` (MLLP to a running engine), or ``none``.
    """
    selected = set(sections) if sections else set(ALL_SECTIONS)
    settings, settings_error = _load_settings(service_config)
    graph = _Graph(config_dir)
    results: list[CheckResult] = []
    if settings_error is not None:
        # Emitted ONLY on a real load failure, so a box with no config (which resolves to
        # defaults) sees no new row and no exit-code change.
        results.append(
            CheckResult(
                "config.load",
                "Service settings load",
                Status.FAIL,
                f"the service config could not be loaded: {settings_error}",
            )
        )

    if "host" in selected:
        api_port = settings.api.port if settings is not None else _DEFAULT_API_PORT
        ports = {"MLLP": mllp_port, "DICOM": _DEFAULT_DICOM_PORT, "API": api_port}
        results += run_host_checks(
            ports=ports,
            writable_dir=_writable_dir(settings),
            odbc_hops=lambda: _odbc_hops(settings, service_config, config_dir, graph),
            driver_18_hops=lambda: _odbc_hops(
                settings, service_config, config_dir, graph, driver_18=True
            ),
        )

    if "store" in selected:
        if settings is None:
            results.append(
                CheckResult(
                    "store.connect",
                    "Store connectivity",
                    Status.SKIP,
                    "service settings did not load — see the config.load row (a box with NO "
                    "config resolves to defaults, so this means the config is missing-at-path "
                    "or invalid, not simply absent)",
                )
            )
        else:
            results.append(check_store_connectivity(settings.store))
            # ADR 0197 Amendment A, AC-A9: the census of accounts with no way past a lock.
            results.append(
                check_lockable_accounts(
                    settings.store, settings.auth, public_origin=settings.api.public_origin
                )
            )
            # ADR 0197 Amendment A, Manager decision 2026-09-29: a sibling check, not part of the
            # census -- it is about the policy, not about any account.
            results.append(check_credential_generation(settings.auth))

    if "smoke" in selected:
        if smoke_mode == "self":
            # Mirror the live engine's copy-on-Send posture (ADR 0104) so the self-smoke previews what
            # a default engine actually delivers: a default engine runs [pipeline].snapshot_on_send ON
            # (PipelineSettings default True), while dry_run's library default is OFF. Keep that library
            # default when no service settings resolve (#241 F3, #230 CLI parity).
            snapshot_on_send = settings.pipeline.snapshot_on_send if settings is not None else False
            results.append(
                smoke_self(
                    config_dir, inbound=inbound, snapshot_on_send=snapshot_on_send, graph=graph
                )
            )
        elif smoke_mode == "live":
            # synthetic_message() is a module constant since #1192, so there is no generator step
            # left to fail here.
            results += _run_live_smoke(
                synthetic_message(),
                host=engine_host,
                port=mllp_port,
                settings=settings,
                check_disposition=check_disposition,
                disposition_timeout=disposition_timeout,
                smoke_tls=smoke_tls,
                smoke_tls_ca=smoke_tls_ca,
            )
        # smoke_mode == "none": nothing to run

    if "federation" in selected:
        # manual.ad stays as-is: it covers the AD/Kerberos sign-in, not federation, and every
        # federation row lives in the fed.* namespace, so no id can collide with it.
        from messagefoundry.verify.federation import run_federation_checks

        results += run_federation_checks(
            settings, id_token_file=fed_id_token, jwks_file=fed_jwks, nonce=fed_nonce
        )

    if "manual" in selected:
        results += _manual_rows()

    return results
