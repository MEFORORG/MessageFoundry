# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Orchestrate the deployment verify: host checks, store connectivity, smoke, manual rows."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from messagefoundry.config.settings import ServiceSettings, StoreBackend
from messagefoundry.verify.checks import run_host_checks
from messagefoundry.verify.model import CheckResult, Status
from messagefoundry.verify.smoke import (
    check_store_connectivity,
    smoke_self,
    synthetic_message,
)

#: The five runnable sections; default is all of them. "federation" (ADR 0142) is offline and
#: emits a single SKIP row when [auth].oidc_enabled is false, so it costs a non-federated
#: deployment one line and never changes its exit code.
ALL_SECTIONS: tuple[str, ...] = ("host", "store", "smoke", "manual", "federation")

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


def _settings_error_detail(exc: Exception) -> str:
    """Render a settings-load failure WITHOUT echoing any configured value.

    A verify report is written to disk (``--report-md``/``--report-json``) and pasted into tickets, so
    a pydantic ``ValidationError`` must contribute only its field path + message — never ``input``,
    which for ``[auth].ad_bind_password`` or a store DSN would put a credential in the artifact.
    """
    from pydantic import ValidationError

    if isinstance(exc, ValidationError):
        rows = [
            f"{'.'.join(str(part) for part in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()[:5]
        ]
        extra = "" if len(exc.errors()) <= 5 else f" (+{len(exc.errors()) - 5} more)"
        return "; ".join(rows) + extra
    # Our own model validators raise plain ValueError with hand-authored text naming the key.
    return str(exc)


def _load_settings(service_config: str | None) -> tuple[ServiceSettings | None, str | None]:
    """Load the service settings, returning ``(settings, error)``.

    An **absent** config is NOT an error: ``load_settings`` returns defaults, so ``settings`` is
    non-None on a box with no ``messagefoundry.toml``. A ``None`` here therefore always means the
    config could not be *loaded* — an explicit ``--service-config`` path that does not exist, or a
    config that exists and fails to validate. Both are real deployment problems.

    This used to collapse both into a bare ``None``, so every dependent row read "no service settings
    — pass --service-config", sending an operator to look for a missing file that was usually present
    and simply broken. The reason is now surfaced (see the ``config.load`` row).
    """
    from pydantic import ValidationError

    from messagefoundry.config.settings import load_settings

    try:
        return load_settings(config_path=service_config), None
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        return None, _settings_error_detail(exc)


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
        results += run_host_checks(ports=ports, writable_dir=_writable_dir(settings))

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

    if "smoke" in selected:
        if smoke_mode == "self":
            # Mirror the live engine's copy-on-Send posture (ADR 0104) so the self-smoke previews what
            # a default engine actually delivers: a default engine runs [pipeline].snapshot_on_send ON
            # (PipelineSettings default True), while dry_run's library default is OFF. Keep that library
            # default when no service settings resolve (#241 F3, #230 CLI parity).
            snapshot_on_send = settings.pipeline.snapshot_on_send if settings is not None else False
            results.append(
                smoke_self(config_dir, inbound=inbound, snapshot_on_send=snapshot_on_send)
            )
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
