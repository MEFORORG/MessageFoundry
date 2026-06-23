# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Orchestrate the deployment verify: host checks, store connectivity, smoke, manual rows."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from messagefoundry.config.settings import ServiceSettings, StoreBackend
from messagefoundry.verify.checks import run_host_checks
from messagefoundry.verify.model import CheckResult, Status
from messagefoundry.verify.smoke import (
    check_store_connectivity,
    smoke_live,
    smoke_self,
    synthetic_message,
)

#: The four runnable sections; default is all of them.
ALL_SECTIONS: tuple[str, ...] = ("host", "store", "smoke", "manual")

_DEFAULT_DICOM_PORT = 11112
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


def _load_settings(service_config: str | None) -> ServiceSettings | None:
    from pydantic import ValidationError

    from messagefoundry.config.settings import load_settings

    try:
        return load_settings(config_path=service_config)
    except (FileNotFoundError, ValueError, ValidationError):
        return None


def _writable_dir(settings: ServiceSettings | None) -> Path:
    if settings is not None and settings.store.backend is StoreBackend.SQLITE:
        return Path(settings.store.path).resolve().parent
    return Path.cwd()


def _manual_rows() -> list[CheckResult]:
    return [CheckResult(rid, title, Status.MANUAL, detail) for rid, title, detail in _MANUAL_ROWS]


def run_verify(
    *,
    config_dir: str = "samples/config",
    service_config: str | None = None,
    sections: Sequence[str] | None = None,
    smoke_mode: str = "self",
    engine_host: str = "127.0.0.1",
    mllp_port: int = 2575,
    inbound: str | None = None,
) -> list[CheckResult]:
    """Run the selected verify sections and return one :class:`CheckResult` per check.

    ``sections`` defaults to all of :data:`ALL_SECTIONS`. ``smoke_mode`` is ``self`` (dry-run through
    the config, safe anywhere), ``live`` (MLLP to a running engine), or ``none``.
    """
    selected = set(sections) if sections else set(ALL_SECTIONS)
    settings = _load_settings(service_config)
    results: list[CheckResult] = []

    if "host" in selected:
        api_port = settings.api.port if settings is not None else _DEFAULT_API_PORT
        ports = {"MLLP": mllp_port, "DICOM": _DEFAULT_DICOM_PORT, "API": api_port}
        results += run_host_checks(ports=ports, writable_dir=_writable_dir(settings))

    if "store" in selected:
        if settings is None:
            results.append(
                CheckResult(
                    "store.connect",
                    "Store connectivity",
                    Status.SKIP,
                    "no service settings found — pass --service-config or run where messagefoundry.toml is",
                )
            )
        else:
            results.append(check_store_connectivity(settings.store))

    if "smoke" in selected:
        if smoke_mode == "self":
            results.append(smoke_self(config_dir, inbound=inbound))
        elif smoke_mode == "live":
            try:
                msg = synthetic_message()
            except Exception as exc:
                results.append(
                    CheckResult(
                        "smoke.live",
                        "Live smoke (MLLP + ACK)",
                        Status.ERROR,
                        f"could not generate a synthetic message: {exc}",
                    )
                )
            else:
                results.append(smoke_live(host=engine_host, port=mllp_port, message=msg))
        # smoke_mode == "none": nothing to run

    if "manual" in selected:
        results += _manual_rows()

    return results
