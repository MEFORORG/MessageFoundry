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


def _run_live_smoke(
    message: str,
    *,
    host: str,
    port: int,
    settings: ServiceSettings | None,
    check_disposition: bool,
    disposition_timeout: float,
) -> list[CheckResult]:
    """Live MLLP smoke (ACK), plus the opt-in store-disposition follow-up.

    The disposition follow-up snapshots the store *before* sending (so a re-used synthetic control id
    can't match a prior run), then — only if the ACK passed — polls for the message reaching a terminal
    disposition. It is the real "did it process" check; ``smoke.live`` alone proves only the ACK.
    """
    from messagefoundry.parsing.peek import HL7PeekError, Peek
    from messagefoundry.verify.smoke import (
        check_smoke_disposition,
        newest_message_id,
        smoke_live,
    )

    control_id: str | None = None
    baseline_id: str | None = None
    if check_disposition and settings is not None:
        try:
            control_id = Peek.parse(message).control_id
        except HL7PeekError:
            control_id = None
        if control_id:
            baseline_id = newest_message_id(settings.store, control_id)

    results = [smoke_live(host=host, port=port, message=message)]
    if not check_disposition:
        return results

    rid, title = "smoke.disposition", "Live smoke disposition"
    if settings is None:
        results.append(
            CheckResult(
                rid, title, Status.SKIP, "no service settings — pass --service-config to poll"
            )
        )
    elif not control_id:
        results.append(
            CheckResult(rid, title, Status.SKIP, "no MSH-10 control id in the synthetic message")
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
    config_dir: str = "samples/config",
    service_config: str | None = None,
    sections: Sequence[str] | None = None,
    smoke_mode: str = "self",
    engine_host: str = "127.0.0.1",
    mllp_port: int = 2575,
    inbound: str | None = None,
    check_disposition: bool = False,
    disposition_timeout: float = 15.0,
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
                results += _run_live_smoke(
                    msg,
                    host=engine_host,
                    port=mllp_port,
                    settings=settings,
                    check_disposition=check_disposition,
                    disposition_timeout=disposition_timeout,
                )
        # smoke_mode == "none": nothing to run

    if "manual" in selected:
        results += _manual_rows()

    return results
