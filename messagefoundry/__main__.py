# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Command-line entrypoint for the MessageFoundry engine + IDE tooling.

    messagefoundry serve     --config ./samples/config --db ./messagefoundry.db   # run engine + API
    messagefoundry validate  --config ./samples/config --json                     # report problems
    messagefoundry graph     --config ./samples/config --json                     # the wired graph
    messagefoundry dryrun    --config ./samples/config --messages ./msgs --json   # run, don't send
    messagefoundry check     --config ./samples/config --messages ./msgs          # commit/CI gate
    messagefoundry connection upsert --config ./samples/config --data '{...}'      # edit connections.toml
    messagefoundry generate  --type ADT --count 5 --out ./out/adt                 # synthetic HL7
    messagefoundry hl7schema --json                                               # HL7 field schema
    messagefoundry init      ./my-config-repo                                      # scaffold a config repo

The introspection subcommands (validate/graph/dryrun/check/hl7schema) print to stdout for the VS
Code extension / git hooks; they touch no network and start no server. Heavy imports are deferred
per-command so a quick `validate`/`hl7schema` call doesn't pay for FastAPI/uvicorn.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from messagefoundry import __version__
from messagefoundry.logging_setup import LOG_LEVELS, SyslogForward, configure_logging


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="messagefoundry", description=__doc__)
    parser.add_argument("--version", action="version", version=f"messagefoundry {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the engine + localhost API")
    serve.add_argument("--config", default="samples/config", help="config modules directory (*.py)")
    serve.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    # These override the corresponding settings; defaults live in ServiceSettings, not argparse, so
    # precedence (CLI > env > file > default) is honored — an unset flag falls through.
    serve.add_argument("--db", default=None, help="message store path (overrides [store].path)")
    serve.add_argument("--host", default=None, help="API bind host (overrides [api].host)")
    serve.add_argument(
        "--port", type=int, default=None, help="API bind port (overrides [api].port)"
    )
    serve.add_argument(
        "--log-level",
        default=None,
        choices=LOG_LEVELS,
        help="logging verbosity (overrides [logging].level)",
    )
    serve.add_argument(
        "--env",
        default=None,
        help="active environment NAME (overrides [ai].environment; selects environments/<env>.toml "
        "values). Built-in names dev/staging/prod carry a default posture; a custom name also needs "
        "[ai].data_class + [ai].production set.",
    )
    serve.add_argument(
        "--project-root",
        default=None,
        help="anchor for the per-environment value dir (overrides [environments].base_dir): the "
        "config-repo root that environments/<env>.toml resolves against. Default = the working "
        "directory (unchanged). Set this when serve runs from elsewhere than the repo root (e.g. "
        "under NSSM) so env() values aren't silently empty.",
    )
    serve.add_argument(
        "--allow-insecure-bind",
        action="store_true",
        help="permit a non-loopback [api].host WITHOUT TLS (bearer tokens and PHI would cross the "
        "network in cleartext); a dev override for a trusted, firewalled network. Prefer configuring "
        "[api].tls_cert_file (+ tls_key_file) for in-process TLS, which is allowed off-loopback "
        "without this flag. Does not relax the no-auth refuse.",
    )

    validate = sub.add_parser("validate", help="check a config dir and report all problems")
    validate.add_argument("--config", default="samples/config", help="config modules directory")
    validate.add_argument("--json", action="store_true", help="emit JSON")

    graph = sub.add_parser("graph", help="print the wired Connection/Router/Handler graph")
    graph.add_argument("--config", default="samples/config", help="config modules directory")
    graph.add_argument("--json", action="store_true", help="emit JSON")

    dryrun = sub.add_parser("dryrun", help="run messages through the config without sending")
    dryrun.add_argument("--config", default="samples/config", help="config modules directory")
    dryrun.add_argument(
        "--messages", required=True, nargs="+", help="HL7 file(s) or directories of *.hl7"
    )
    dryrun.add_argument("--inbound", default=None, help="inbound connection to simulate")
    dryrun.add_argument("--json", action="store_true", help="emit JSON")
    dryrun.add_argument(
        "--show-phi",
        action="store_true",
        help="include full message bodies (raw + payloads) — PHI; redacted by default",
    )

    check = sub.add_parser(
        "check", help="run validate + dryrun (+ advisory ruff/mypy) as a commit/CI gate"
    )
    check.add_argument("--config", default="samples/config", help="config modules directory")
    check.add_argument(
        "--messages", default=None, help="HL7 fixtures dir (dryrun gates when it has *.hl7)"
    )
    check.add_argument("--no-lint", action="store_true", help="skip the advisory ruff/mypy checks")
    check.add_argument("--json", action="store_true", help="emit JSON")

    connection = sub.add_parser(
        "connection",
        help="manage connections.toml — list / upsert / remove (ADR 0007; the VS Code editor shells this)",
    )
    connection.add_argument("action", choices=["list", "upsert", "remove"])
    connection.add_argument("--config", default="samples/config", help="config modules directory")
    connection.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML for [egress]/active-env validation (default: "
        "./messagefoundry.toml if present)",
    )
    connection.add_argument("--name", default=None, help="connection name (for remove)")
    connection.add_argument(
        "--data", default=None, help="connection JSON for upsert (default: read from stdin)"
    )
    connection.add_argument("--json", action="store_true", help="emit JSON")

    generate = sub.add_parser(
        "generate", help="generate conformant synthetic HL7 messages (no real PHI)"
    )
    generate.add_argument("--type", default=None, help="message type, e.g. ADT, ORU (see --list)")
    generate.add_argument(
        "--triggers", default="", help="comma-separated subset (default: all for the type)"
    )
    generate.add_argument("--count", type=int, default=50, help="messages per trigger (default 50)")
    generate.add_argument(
        "--out", default=None, help="output root (default: samples/messages/<type>)"
    )
    generate.add_argument("--seed", default=None, help="RNG seed for reproducible output")
    generate.add_argument("--list", action="store_true", help="list registered message types")
    generate.add_argument("--json", action="store_true", help="emit JSON")

    schema = sub.add_parser("hl7schema", help="print HL7 v2.5.1 segment/field schema")
    schema.add_argument("--json", action="store_true", help="emit JSON")

    init = sub.add_parser(
        "init",
        help="scaffold a new config repo (starter feed + environments + CI + a pinned engine)",
    )
    init.add_argument("dir", nargs="?", default=".", help="target directory (default: current dir)")
    init.add_argument(
        "--force",
        action="store_true",
        help="scaffold into a non-empty directory (existing files are left untouched)",
    )
    init.add_argument("--json", action="store_true", help="emit JSON")

    sub.add_parser(
        "gen-key", help="generate a base64 key for MEFOR_STORE_ENCRYPTION_KEY (PHI-at-rest)"
    )

    protect_key = sub.add_parser(
        "protect-key",
        help="DPAPI-protect the store key to a file for [store].encryption_key_file (Windows-only)",
    )
    protect_key.add_argument("--out", required=True, help="path to write the protected key file")
    protect_key.add_argument(
        "--generate",
        action="store_true",
        help="mint a fresh key and protect it (printed once to stderr so you can back it up offline)",
    )
    protect_key.add_argument(
        "--user",
        action="store_true",
        help="protect under the current USER only (default: machine scope, so the low-privilege "
        "service account can read the key at startup)",
    )

    audit_verify = sub.add_parser(
        "audit-verify", help="verify the audit-log hash chain (tamper-evidence)"
    )
    audit_verify.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    audit_verify.add_argument("--db", default=None, help="store path (overrides [store].path)")

    rotate_key = sub.add_parser(
        "rotate-key",
        help="re-encrypt the store under the active MEFOR_STORE_ENCRYPTION_KEY (run with the engine "
        "stopped; keep the prior key in MEFOR_STORE_ENCRYPTION_KEYS_RETIRED)",
    )
    rotate_key.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    rotate_key.add_argument("--db", default=None, help="store path (overrides [store].path)")

    ai_policy = sub.add_parser(
        "ai-policy", help="print the effective AI-assistance policy (for the IDE gate)"
    )
    ai_policy.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    ai_policy.add_argument("--json", action="store_true", help="emit JSON only (parsed by the IDE)")

    args = parser.parse_args(argv)
    return _DISPATCH[args.command](args)


def _serve(args: argparse.Namespace) -> int:
    import uvicorn
    from pydantic import ValidationError

    from messagefoundry.api import create_managed_app
    from messagefoundry.config.settings import StoreBackend, load_settings

    # Only pass flags the user actually supplied so they override env/file but an unset flag doesn't.
    cli: dict[str, dict[str, object]] = {}
    if args.db is not None:
        cli.setdefault("store", {})["path"] = args.db
    if args.host is not None:
        cli.setdefault("api", {})["host"] = args.host
    if args.port is not None:
        cli.setdefault("api", {})["port"] = args.port
    if args.log_level is not None:
        cli.setdefault("logging", {})["level"] = args.log_level
    if args.env is not None:
        cli.setdefault("ai", {})["environment"] = args.env  # the single active-environment selector
    if args.project_root is not None:
        # Anchor for environments/<env>.toml resolution (overrides [environments].base_dir).
        cli.setdefault("environments", {})["base_dir"] = args.project_root

    try:
        settings = load_settings(config_path=args.service_config, cli=cli)
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Fail closed: with auth disabled the API answers as a full-privilege system identity, so a
    # non-loopback bind would publish admin access to the network. Loopback is the only no-auth posture.
    if not settings.auth.enabled and not settings.api.is_loopback:
        print(
            "error: refusing to serve with [auth] enabled=false on non-loopback host "
            f"{settings.api.host!r}; enable auth or bind 127.0.0.1",
            file=sys.stderr,
        )
        return 2

    if settings.store.backend is StoreBackend.SQLSERVER:
        import importlib.util

        if importlib.util.find_spec("aioodbc") is None:
            print(
                "error: the SQL Server backend needs the 'sqlserver' extra: "
                "pip install 'messagefoundry[sqlserver]' (plus the Microsoft ODBC Driver 18)",
                file=sys.stderr,
            )
            return 2

    # Active environment is REQUIRED (ADR 0017): no silent default, so a missing env can never resolve
    # another environment's values/secrets. Its security POSTURE (data_class / production) is derived
    # for the built-in names dev/staging/prod and must be explicit for a custom name.
    from messagefoundry.config.ai_policy import DataClass

    if settings.ai.environment is None:
        print(
            "error: no active environment set — pass --env <name> or set [ai].environment. It selects "
            "environments/<name>.toml and, with [ai].data_class/[ai].production, the instance's PHI "
            "posture.",
            file=sys.stderr,
        )
        return 2
    try:
        data_class, production = settings.ai.require_posture()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    env_name = settings.ai.environment

    # PHI-at-rest posture (WP-5/WP-11d): refuse (require_encryption) or warn (PHI-carrying instance)
    # when no key is configured. A DPAPI-protected key file (Windows) counts as a configured key; if
    # it's set but unreadable here, open_store fails closed at startup with the DPAPI error.
    if not (settings.store.encryption_key or settings.store.encryption_key_file):
        if settings.store.require_encryption:
            print(
                "error: [store].require_encryption is set but no MEFOR_STORE_ENCRYPTION_KEY (or "
                "[store].encryption_key_file) is configured; refusing to start (PHI would be stored "
                "unencrypted at rest)",
                file=sys.stderr,
            )
            return 2
        # Fail closed on a PRODUCTION PHI instance: a live production store must never run keyless
        # (the prod analogue of require_encryption — the deployment doesn't have to set the flag to
        # get the protection). staging/dev keep the softer posture below.
        if production and data_class is DataClass.PHI:
            print(
                f"error: no MEFOR_STORE_ENCRYPTION_KEY (or [store].encryption_key_file) set on a "
                f"production PHI instance ({env_name!r}); refusing to start — PHI bodies and the "
                "error/last_error/detail columns would be stored UNENCRYPTED at rest. Generate a key "
                "with `messagefoundry gen-key` (or protect one to a file with `messagefoundry "
                "protect-key`) and configure it before starting a production store.",
                file=sys.stderr,
            )
            return 2
        # Warn on a non-production PHI-carrying instance (e.g. staging). A synthetic instance stays
        # quiet to avoid alarm fatigue (CLAUDE.md §9 / docs/PHI.md).
        if data_class is DataClass.PHI:
            print(
                f"warning: no MEFOR_STORE_ENCRYPTION_KEY set in a PHI-carrying environment "
                f"({env_name!r}) — PHI bodies and the error/last_error/detail columns are stored "
                "UNENCRYPTED at rest (only volume encryption protects them). Generate a key with "
                "`messagefoundry gen-key` (or protect one to a file with `messagefoundry "
                "protect-key`), or set [store].require_encryption.",
                file=sys.stderr,
            )

    # Open-egress posture (Q5b): on a PHI-carrying instance, outbound egress that is fully
    # unrestricted — no [egress] allowlist AND deny_by_default off — lets a transform send PHI to any
    # destination. On a PRODUCTION instance this fails closed (refuse to start, the prod analogue of
    # the keyless-store refusal above); on a non-production PHI instance (e.g. staging) it is an
    # advisory warning. A synthetic instance stays quiet. Lock it down with [egress].deny_by_default
    # or per-transport [egress].allowed_* lists.
    if data_class is DataClass.PHI:
        eg = settings.egress
        egress_open = not eg.deny_by_default and not (
            eg.allowed_mllp
            or eg.allowed_tcp
            or eg.allowed_http
            or eg.allowed_db
            or eg.allowed_remote
            or eg.allowed_file_dirs
        )
        if egress_open:
            if production:
                print(
                    f"error: outbound egress is UNRESTRICTED on a production PHI instance "
                    f"({env_name!r}); refusing to start — a transform could send PHI to any "
                    "destination. Set [egress].deny_by_default=true, or declare the permitted "
                    "destinations with per-transport [egress].allowed_* allowlists.",
                    file=sys.stderr,
                )
                return 2
            print(
                f"warning: outbound egress is UNRESTRICTED in a PHI-carrying environment "
                f"({env_name!r}) — a transform may send to any destination. Set "
                "[egress].deny_by_default or per-transport [egress].allowed_* allowlists to fail "
                "closed.",
                file=sys.stderr,
            )

    # Gate #1: DEBUG logging can surface PHI (full message bodies / raw field values) into the general
    # log. Refuse it fail-closed on a production instance — real PHI flows there. A non-production
    # instance may use DEBUG for diagnostics.
    if production and settings.logging.level.upper() == "DEBUG":
        print(
            "error: DEBUG logging is refused on a production instance ([ai].production=true) — it can "
            "surface PHI (full message bodies / raw field values) into logs. Use INFO or higher in "
            "production (set [ai].production=false on a non-production instance for verbose "
            "diagnostics).",
            file=sys.stderr,
        )
        return 2

    # Off-box log forwarding (sec-offbox-log): ship a copy of every record to a syslog/SIEM collector
    # so evidence survives a host compromise. PHI redaction + control-char scrubbing apply to the
    # forwarded stream exactly as to stdout (configure_logging installs the same filters on both).
    log_forward = (
        SyslogForward(
            host=settings.logging.forward_host,
            port=settings.logging.forward_port,
            protocol=settings.logging.forward_protocol.value,
            fmt=settings.logging.forward_format.value,
        )
        if settings.logging.forward_enabled and settings.logging.forward_host
        else None
    )
    forwarder_live = configure_logging(
        settings.logging.level, fmt=settings.logging.format.value, forward=log_forward
    )
    if forwarder_live and log_forward is not None:
        # Only announce forwarding when configure_logging actually installed the handler — a TCP
        # collector that is down at startup is skipped (it warns), so this must not contradict it.
        logging.getLogger(__name__).info(
            "off-box log forwarding enabled → %s:%d (%s, %s)",
            log_forward.host,
            log_forward.port,
            log_forward.protocol,
            log_forward.fmt,
        )
    # Anchor for the per-environment value dir: [environments].base_dir (or --project-root) when set,
    # else the working directory (unchanged default). Resolved once here so the startup log shows the
    # exact file env() values come from — the standalone-repo / NSSM footgun is a silently-wrong path.
    from pathlib import Path

    from messagefoundry.config.environments import resolve_values_base_dir

    env_base = resolve_values_base_dir(settings.environments.base_dir, cwd=Path.cwd())
    # Announce the active environment + posture so an operator can see which env() values resolve and
    # the PHI posture in effect (the env is required — there is no silent default).
    logging.getLogger(__name__).info(
        "active environment: %s (data_class=%s, production=%s; env() values from %s + MEFOR_VALUE_*)",
        env_name,
        data_class.value,
        production,
        env_base / settings.environments.dir / f"{env_name}.toml",
    )
    # A non-loopback API bind puts bearer tokens + PHI on the wire. The exposed-gate (ADR 0002 §0):
    # TLS configured → the first-class secure path (allow); no TLS but --allow-insecure-bind → a loud
    # dev override (warn); otherwise → refuse fail-closed. The auth-disabled case is refused above
    # regardless of this flag — serving full-privilege admin to the network is never one "I accept the
    # risk" away.
    if not settings.api.is_loopback:
        if settings.api.tls_enabled:
            # WP-13a: TLS terminates in-process, so tokens + PHI are encrypted on the wire and HSTS
            # engages — no dev escape needed.
            logging.getLogger(__name__).info(
                "API on non-loopback host %r with in-process TLS (https/wss).", settings.api.host
            )
        elif settings.api.tls_terminated_upstream:
            # WP-15: a reverse proxy terminates TLS in front; trust forwarded headers only from the
            # declared proxies (the validator guarantees trusted_proxies is set here).
            logging.getLogger(__name__).info(
                "API on non-loopback host %r behind a TLS-terminating proxy; trusting forwarded "
                "headers from %s.",
                settings.api.host,
                settings.api.trusted_proxies,
            )
        elif args.allow_insecure_bind:
            print(
                f"warning: API bound to non-loopback host {settings.api.host!r} with "
                "--allow-insecure-bind and NO TLS; bearer tokens and PHI cross the network in "
                "cleartext — configure [api].tls_cert_file (+ tls_key_file) for real remote access.",
                file=sys.stderr,
            )
        else:
            print(
                "error: refusing to serve the API on non-loopback host "
                f"{settings.api.host!r} without TLS; bearer tokens and PHI would cross the network in "
                "cleartext. Configure [api].tls_cert_file for in-process TLS, set "
                "[api].tls_terminated_upstream (+ trusted_proxies) if a proxy terminates TLS, or pass "
                "--allow-insecure-bind to accept the cleartext risk on a trusted, firewalled network.",
                file=sys.stderr,
            )
            return 2

    # MFA-at-exposure posture (sec-mfa-on; WP-14, ASVS 6.3.3): an off-loopback bind serving local
    # accounts puts admin authentication on the network, where a single password factor is far weaker.
    # [auth].require_mfa adds the native TOTP second factor for the Administrator role; with it off the
    # admin interface is single-factor over the wire. Mirror the keyless-store / open-egress posture:
    # refuse on a production PHI instance (the prod fail-closed analogue), warn on a non-production PHI
    # instance, stay quiet on a synthetic instance. Reached only for an otherwise-permitted exposed
    # bind (the TLS gate above ran first); the loopback default never trips it. AD/Kerberos MFA is
    # delegated to the directory, so require_mfa only gates LOCAL Administrator accounts (the bootstrap
    # admin is one) — it is safe to enable even on an AD-only deployment.
    if not settings.api.is_loopback and settings.auth.enabled and not settings.auth.require_mfa:
        if data_class is DataClass.PHI:
            if production:
                print(
                    f"error: API bound to non-loopback host {settings.api.host!r} on a production PHI "
                    f"instance ({env_name!r}) with [auth].require_mfa off; refusing to start — the "
                    "Administrator role would authenticate with a single factor over the network. "
                    "Enable native TOTP MFA with [auth].require_mfa=true (WP-14) before exposing the "
                    "API (safe even on an AD-only deployment — it gates only local Administrator "
                    "accounts).",
                    file=sys.stderr,
                )
                return 2
            print(
                f"warning: API bound to non-loopback host {settings.api.host!r} in a PHI-carrying "
                f"environment ({env_name!r}) with [auth].require_mfa off — the Administrator role is "
                "single-factor over the network. Enable [auth].require_mfa=true (WP-14 native TOTP) "
                "before exposure.",
                file=sys.stderr,
            )

    # This instance's environment values (env() lookups in the graph): environments/<env>.toml +
    # MEFOR_VALUE_* env, anchored at env_base (above). The active environment is the single selector
    # [ai].environment. Passed as a provider (re-read on each reload, not just startup) so a promote
    # picks up edited values without a service restart (review M-23) — the anchor is fixed per process.
    import os

    from messagefoundry.config.environments import load_environment_values

    def env_values() -> dict[str, Any]:
        return load_environment_values(
            base_dir=env_base,
            dir_name=settings.environments.dir,
            environment=env_name,
            environ=os.environ,
        )

    app = create_managed_app(
        store_settings=settings.store,
        config_dir=args.config,
        config_reload_roots=settings.api.config_reload_roots,
        inbound_bind_host=settings.inbound.bind_host,
        allow_insecure_bind=args.allow_insecure_bind,
        delivery_defaults=settings.delivery.retry_policy(),
        ordering_default=settings.delivery.ordering,
        internal_error_default=settings.delivery.internal_error,
        buildup_default=settings.delivery.buildup_threshold(),
        ack_after_default=settings.inbound.ack_after,
        max_correlation_depth=settings.pipeline.max_correlation_depth,
        env_values_provider=env_values,
        auth_settings=settings.auth,
        ai_settings=settings.ai,
        alerts_settings=settings.alerts,
        retention_settings=settings.retention,
        cert_monitor_settings=settings.cert_monitor,
        api_tls_cert_file=settings.api.tls_cert_file,
        reference_settings=settings.reference,
        egress_settings=settings.egress,
        shadow_settings=settings.shadow,
        cluster_settings=settings.cluster,
        approvals_settings=settings.approvals,
        expose_docs=settings.api.expose_docs,
        ws_allowed_origins=settings.api.ws_allowed_origins,
    )
    # log_config=None: uvicorn's loggers propagate to the handler configure_logging installed,
    # so everything shares one format/stream (and one log file under NSSM).
    # WP-15: trust X-Forwarded-For/-Proto ONLY from the declared reverse proxies, so the audit /
    # rate-limit source IP is the real client (not the proxy). Empty list = trust nothing (the secure
    # default — the direct TCP peer is used), overriding uvicorn's loopback default.
    run_kwargs: dict[str, Any] = {
        "log_config": None,
        "forwarded_allow_ips": settings.api.trusted_proxies,
        # WP-L3-07 (ASVS 13.4.6): drop the `Server: uvicorn` banner so a response doesn't advertise the
        # server implementation/version to an unauthenticated caller.
        "server_header": False,
    }
    if settings.api.tls_enabled:
        # WP-13a: terminate TLS in-process. Build the context now so a bad cert/key/passphrase fails
        # fast (before uvicorn opens the socket); pass it via uvicorn's ssl_context_factory so the
        # tls_min_version floor is enforced exactly.
        from messagefoundry.api.tls import build_api_ssl_context

        ctx = build_api_ssl_context(settings.api)
        run_kwargs["ssl_context_factory"] = lambda config, default_factory: ctx
    from messagefoundry.last_resort import install_excepthook
    from messagefoundry.redaction import safe_exc

    install_excepthook()  # last-resort main-thread hook: an uncaught exception logs PHI-redacted (16.5.4)
    try:
        uvicorn.run(app, host=settings.api.host, port=settings.api.port, **run_kwargs)
    except Exception as exc:  # last-resort: log an abnormal server exit PHI-redacted, then re-raise
        logging.getLogger(__name__).critical("server exited abnormally: %s", safe_exc(exc))
        raise
    return 0


def _validate(args: argparse.Namespace) -> int:
    from messagefoundry.config.wiring import validate_config

    diags = validate_config(args.config)
    if args.json:
        print(
            json.dumps(
                [{"message": d.message, "file": d.file, "severity": d.severity} for d in diags]
            )
        )
    elif not diags:
        print("OK: no problems found")
    else:
        for d in diags:
            print(f"{d.severity}: {d.file or '-'}: {d.message}")
    return 1 if diags else 0


def _graph(args: argparse.Namespace) -> int:
    from messagefoundry.config.wiring import WiringError, display_settings, load_config

    try:
        reg = load_config(args.config)
    except WiringError as exc:
        return _emit_error(str(exc), as_json=args.json)
    data = {
        "inbound": [
            {
                "name": name,
                "type": c.spec.type.value,
                "settings": display_settings(c.spec.settings),
                "router": c.router,
                "ack_mode": c.ack_mode.value,
                "strict": c.validation.strict,
                "file": c.source_file,
                "line": c.source_line,
            }
            for name, c in reg.inbound.items()
        ],
        "outbound": [
            {
                "name": name,
                "type": c.spec.type.value,
                "settings": display_settings(c.spec.settings),
                "file": c.source_file,
                "line": c.source_line,
            }
            for name, c in reg.outbound.items()
        ],
        # router→handler and handler→outbound edges are decided in code, not declared, so they're
        # extracted best-effort: a handler/outbound name that appears as a string literal in the
        # function counts as a reference. Accurate for names written literally; misses computed names.
        "routers": [
            {"name": n, **_fn_location(fn), "handlers": _referenced(fn, reg.handlers)}
            for n, fn in sorted(reg.routers.items())
        ],
        "handlers": [
            {"name": n, **_fn_location(fn), "sends": _referenced(fn, reg.outbound)}
            for n, fn in sorted(reg.handlers.items())
        ],
    }
    _print_json(data, compact=args.json)
    return 0


def _fn_location(fn: object) -> dict[str, Any]:
    """File + line where a Router/Handler function is defined (for IDE go-to-definition)."""
    code = getattr(fn, "__code__", None)
    if code is None:
        return {"file": None, "line": None}
    return {"file": code.co_filename, "line": code.co_firstlineno}


def _referenced(fn: object, names: dict[str, Any]) -> list[str]:
    """Best-effort: which of ``names`` appear as string literals in ``fn`` (router/handler wiring)."""
    consts = _string_consts(fn)
    return sorted(name for name in names if name in consts)


def _string_consts(fn: object) -> set[str]:
    """All string constants in a function, recursing into nested code objects (comprehensions, etc.)."""
    import types

    code = getattr(fn, "__code__", None)
    if code is None:
        return set()
    found: set[str] = set()
    stack = [code]
    while stack:
        current = stack.pop()
        for const in current.co_consts:
            if isinstance(const, str):
                found.add(const)
            elif isinstance(const, types.CodeType):
                stack.append(const)
    return found


def _redact_body(body: str) -> str:
    """Replace a PHI-bearing message body with a length placeholder.

    ``dryrun`` is a dev tool whose output is routinely piped to files/CI logs, so it must not emit
    full bodies (raw + would-send payloads) by default; ``--show-phi`` opts in. See docs/PHI.md §7.
    """
    return f"<redacted {len(body)} chars; pass --show-phi>" if body else body


def _dryrun(args: argparse.Namespace) -> int:
    from messagefoundry.config.wiring import WiringError, load_config
    from messagefoundry.pipeline.dryrun import dry_run, read_messages

    try:
        reg = load_config(args.config)
    except WiringError as exc:
        return _emit_error(str(exc), as_json=args.json)
    try:
        messages = read_messages(args.messages)
    except (FileNotFoundError, ValueError) as exc:
        return _emit_error(str(exc), as_json=args.json)

    show_phi: bool = args.show_phi
    if not show_phi:
        print(
            "note: message bodies redacted; pass --show-phi to include raw/payloads (PHI)",
            file=sys.stderr,
        )

    out: list[dict[str, Any]] = []
    try:
        for source, path, raw in messages:
            result = dry_run(reg, raw, inbound=args.inbound)
            out.append(
                {
                    "source": source,
                    "path": path,
                    "inbound": result.inbound,
                    "disposition": result.disposition.value,
                    "message_type": result.message_type,
                    "control_id": result.control_id,
                    # The summary is PHI (MRN + patient name from PID-3/5), so gate it like raw/
                    # payloads — dryrun stdout is routinely piped to files/CI logs (review H-12).
                    # (The `error` text can also quote field values; that's tracked separately as
                    # low-8, gated holistically with the API's error exposure.)
                    "summary": result.summary if show_phi else None,
                    "handlers": result.handlers,
                    "deliveries": [
                        {"to": d.to, "payload": d.payload if show_phi else _redact_body(d.payload)}
                        for d in result.deliveries
                    ],
                    # Declared state writes (ADR 0005). The value can be PHI (e.g. an MRN→anon
                    # mapping), so gate it behind --show-phi exactly like a delivery payload.
                    "state_ops": [
                        {
                            "namespace": s.namespace,
                            "key": s.key if show_phi else _redact_body(str(s.key)),
                            "value": s.value if show_phi else _redact_body(str(s.value)),
                        }
                        for s in result.state_ops
                    ],
                    "error": result.error,
                    "raw": result.raw if show_phi else _redact_body(result.raw),
                }
            )
    except (ValueError, KeyError) as exc:  # e.g. ambiguous/unknown --inbound
        return _emit_error(str(exc), as_json=args.json)
    _print_json(out, compact=args.json)
    return 0


def _hl7schema(args: argparse.Namespace) -> int:
    from messagefoundry.hl7schema import hl7_schema

    _print_json(hl7_schema(), compact=args.json)
    return 0


def _init(args: argparse.Namespace) -> int:
    """Scaffold a new config repo into ``args.dir`` (starter feed + environments + CI + a pinned engine)."""
    from pathlib import Path

    from messagefoundry.scaffold import scaffold

    target = Path(args.dir)
    try:
        written = scaffold(target, force=args.force)
    except (FileExistsError, NotADirectoryError, OSError) as exc:
        return _emit_error(str(exc), as_json=args.json)

    rels = [str(p.relative_to(target)) for p in written]
    if args.json:
        _print_json({"target": str(target), "written": rels}, compact=True)
        return 0
    if not written:
        print(f"Nothing written — {target} already has every scaffold file.")
        return 0
    print(f"Scaffolded a config repo in {target} ({len(written)} files):")
    for rel in rels:
        print(f"  {rel}")
    print("\nNext steps:")
    print("  pip install -r requirements.txt        # the pinned engine (a read-only dependency)")
    print("  messagefoundry check --config config --messages messages/sets")
    print("  messagefoundry serve --config config --env dev")
    return 0


def _gen_key(_args: argparse.Namespace) -> int:
    from messagefoundry.store.crypto import generate_key

    # Print only the key (so it can be piped); set it as MEFOR_STORE_ENCRYPTION_KEY, never the file.
    print(generate_key())
    return 0


def _protect_key(args: argparse.Namespace) -> int:
    """DPAPI-protect the store encryption key to a file (WP-11d, ASVS 13.3.1; Windows-only).

    Source: ``--generate`` mints a fresh key (also printed once to stderr so it can be backed up
    offline — the machine-bound file is unrecoverable if the host is lost); otherwise the key is read
    from ``MEFOR_STORE_ENCRYPTION_KEY``. The file is written with an owner-only DACL on top of DPAPI.
    """
    import base64
    import os
    from pathlib import Path

    from messagefoundry.secrets_dpapi import DpapiError, DpapiUnavailable, protect_key_to_file
    from messagefoundry.store.crypto import generate_key
    from messagefoundry.store.store import _secure_file

    if args.generate:
        key_b64 = generate_key()
        print(
            "Generated a new store key. BACK IT UP OFFLINE — the protected file is bound to this "
            f"machine and cannot be recovered if the host is lost:\n  {key_b64}",
            file=sys.stderr,
        )
    else:
        key_b64 = os.environ.get("MEFOR_STORE_ENCRYPTION_KEY", "").strip()
        if not key_b64:
            print(
                "error: no key to protect — set MEFOR_STORE_ENCRYPTION_KEY, or pass --generate to "
                "mint a fresh one",
                file=sys.stderr,
            )
            return 2

    try:
        raw = base64.b64decode(key_b64, validate=True)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        raw = b""
    if len(raw) != 32:
        print(
            "error: the key must be base64 of 32 bytes (use `gen-key` or --generate)",
            file=sys.stderr,
        )
        return 2

    out = Path(args.out)
    try:
        protect_key_to_file(key_b64, out, machine_scope=not args.user)
    except DpapiUnavailable as exc:
        print(
            f"error: {exc}. protect-key is Windows-only; on other platforms keep the key in "
            "MEFOR_STORE_ENCRYPTION_KEY.",
            file=sys.stderr,
        )
        return 2
    except DpapiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _secure_file(out)  # owner-only DACL — defence in depth atop the DPAPI binding
    print(
        f"Wrote DPAPI-protected key to {out}.\nNext: set [store].encryption_key_file = {str(out)!r} "
        "and unset MEFOR_STORE_ENCRYPTION_KEY."
    )
    return 0


def _audit_verify(args: argparse.Namespace) -> int:
    import asyncio
    from pathlib import Path

    from pydantic import ValidationError

    from messagefoundry.config.settings import StoreBackend, load_settings
    from messagefoundry.store.base import open_store

    cli: dict[str, dict[str, object]] = {}
    if args.db is not None:
        cli.setdefault("store", {})["path"] = args.db
    try:
        settings = load_settings(config_path=args.service_config, cli=cli)
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # A SQLite store would otherwise be CREATED on open: a compliance job pointed at a typo'd path
    # would silently get a fresh empty DB and report "OK: verified 0 audit row(s)" forever (M-31).
    if settings.store.backend == StoreBackend.SQLITE and not Path(settings.store.path).exists():
        print(
            f"error: no audit database at {settings.store.path} — refusing to create one and report "
            f"a false 'verified 0 rows' (check --db / [store].path)",
            file=sys.stderr,
        )
        return 2

    async def run() -> tuple[bool, str | None]:
        store = await open_store(settings.store)
        try:
            return await store.verify_audit_chain()
        finally:
            await store.close()

    ok, message = asyncio.run(run())
    print(("OK: " if ok else "FAIL: ") + (message or ""))
    if ok and message and "verified 0 " in message:
        # An empty log on a real DB is legitimate but worth flagging — it's indistinguishable at a
        # glance from pointing at the wrong database (M-31).
        print(
            "warning: the audit log is empty — confirm this is the intended database.",
            file=sys.stderr,
        )
    return 0 if ok else 1


def _rotate_key(args: argparse.Namespace) -> int:
    """Re-encrypt every cipher-covered value under the active key (WP-5 key rotation, ASVS 11.2.2).

    Run **offline** (engine stopped): set ``MEFOR_STORE_ENCRYPTION_KEY`` to the NEW active key and keep
    the prior key(s) in ``MEFOR_STORE_ENCRYPTION_KEYS_RETIRED`` so existing rows can be decrypted, then
    rotate. After it finishes, the retired key can be removed.
    """
    import asyncio
    from pathlib import Path

    from pydantic import ValidationError

    from messagefoundry.config.settings import StoreBackend, load_settings
    from messagefoundry.secrets_dpapi import DpapiError, DpapiUnavailable
    from messagefoundry.store.base import open_store, resolve_active_key
    from messagefoundry.store.crypto import CipherError

    cli: dict[str, dict[str, object]] = {}
    if args.db is not None:
        cli.setdefault("store", {})["path"] = args.db
    try:
        settings = load_settings(config_path=args.service_config, cli=cli)
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        active_key = resolve_active_key(settings.store)
    except (DpapiError, DpapiUnavailable) as exc:
        print(f"error: cannot load the active key for rotation: {exc}", file=sys.stderr)
        return 2
    if not active_key:
        print(
            "error: rotate-key needs an active key — set MEFOR_STORE_ENCRYPTION_KEY (or "
            "[store].encryption_key_file) to the new active key, with any prior key in "
            "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED; none is configured",
            file=sys.stderr,
        )
        return 2
    if settings.store.backend == StoreBackend.SQLITE and not Path(settings.store.path).exists():
        print(
            f"error: no store at {settings.store.path} (check --db / [store].path)", file=sys.stderr
        )
        return 2

    async def run() -> int:
        store = await open_store(settings.store)
        try:
            return await store.reencrypt_to_active()
        finally:
            await store.close()

    try:
        count = asyncio.run(run())
    except CipherError as exc:
        # A value couldn't be decrypted by any supplied key — the prior key is missing. Nothing was
        # corrupted (a batch is all-or-nothing); supply the key and re-run.
        print(f"error: rotation aborted — {exc}", file=sys.stderr)
        return 1
    except NotImplementedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"OK: re-encrypted {count} value(s) under the active key")
    return 0


def _ai_policy(args: argparse.Namespace) -> int:
    """Print the effective AI-assistance policy resolved from local service settings.

    Offline mirror of ``GET /ai/policy`` for the IDE's fallback path: it reads the same [ai] config
    and runs the same clamp, but ``assist_permitted`` is always ``null`` because RBAC can't be
    evaluated without the engine. Prints config only — never message data (PHI-safe)."""
    from pydantic import ValidationError

    from messagefoundry.config.ai_policy import resolve_effective_policy
    from messagefoundry.config.settings import load_settings

    try:
        settings = load_settings(config_path=args.service_config)
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        # Surface via stdout so the IDE's runJson bridge sees it (mirrors the wire-error shape).
        print(json.dumps({"error": str(exc)}))
        return 2

    ai = settings.ai
    data_class, prod = ai.derived_posture()
    production = True if prod is None else prod  # unresolved posture -> strictest ceiling
    eff = resolve_effective_policy(mode=ai.mode, data_scope=ai.data_scope, production=production)
    payload = {
        "mode": eff.mode.value,
        "data_scope": eff.data_scope.value,
        "environment": ai.environment,
        "data_class": data_class.value if data_class is not None else None,
        "production": production,
        "assist_permitted": None,  # RBAC is not evaluable offline
        "reason": eff.reason,
    }
    _print_json(payload, compact=args.json)
    return 0


def _generate(args: argparse.Namespace) -> int:
    from messagefoundry.generators import _core
    from messagefoundry.generators import all_types  # noqa: F401  (registers every built-in type)

    if args.list:
        listing = {code: _core.triggers_for(code) for code in _core.message_codes()}
        if args.json:
            _print_json(listing, compact=True)
        else:
            for code, trigs in listing.items():
                print(f"{code}: {len(trigs)} trigger(s) ({', '.join(trigs)})")
        return 0

    if not args.type:
        print("error: --type is required (or use --list to see types)", file=sys.stderr)
        return 2

    code = args.type.upper()
    triggers = [t.strip().upper() for t in args.triggers.split(",") if t.strip()] or None
    out = args.out or f"samples/messages/{code.lower()}"
    seed = args.seed or _core.DEFAULT_SEED
    try:
        result = _core.write_corpus(code, triggers=triggers, count=args.count, out=out, seed=seed)
    except KeyError as exc:
        print(f"error: {exc.args[0] if exc.args else exc}", file=sys.stderr)
        return 2
    except _core.GenerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        _print_json(
            {
                "type": result.code,
                "out": result.out_dir,
                "total": result.total,
                "by_trigger": result.by_trigger,
            },
            compact=True,
        )
    else:
        for trig, n in result.by_trigger.items():
            print(f"{code}^{trig}: {n}")
        print(f"Generated {result.total} message(s) into {result.out_dir}/")
    return 0


def _check(args: argparse.Namespace) -> int:
    """Commit/CI gate: exit 0 iff every *required* check passed (advisory failures only print)."""
    from messagefoundry.checks import run_checks

    report = run_checks(args.config, messages_dir=args.messages, run_lint=not args.no_lint)
    if args.json:
        _print_json(report.to_json(), compact=True)
    else:
        for r in report.results:
            status = "skip" if r.skipped else ("ok" if r.ok else "FAIL")
            tag = "" if r.required else " (advisory)"
            line = f"{status:>4}  {r.name}{tag}"
            print(f"{line}: {r.detail}" if r.detail else line)
        print("PASS" if report.ok else "FAIL: a required check failed")
    return 0 if report.ok else 1


def _connection(args: argparse.Namespace) -> int:
    """Manage the data-authored ``connections.toml`` (ADR 0007): ``list`` to populate the VS Code
    editor, ``upsert``/``remove`` to save (a developer can also hand-edit the file). ``upsert``/
    ``remove`` validate the whole config dir (structure + connector/egress build-check) BEFORE
    persisting and roll back on failure. Offline: touches no network, starts no server."""
    import os
    from pathlib import Path

    from pydantic import ValidationError

    from messagefoundry.config import connections_edit
    from messagefoundry.config.environments import (
        load_environment_values,
        resolve_values_base_dir,
    )
    from messagefoundry.config.settings import load_settings
    from messagefoundry.config.wiring import WiringError, load_config
    from messagefoundry.pipeline.wiring_runner import build_check_registry

    if args.action == "list":
        try:
            entries = connections_edit.list_connections(args.config)
        except (OSError, WiringError) as exc:
            return _emit_error(str(exc), as_json=args.json)
        _print_json(entries, compact=args.json)
        return 0

    # upsert / remove: validate the candidate dir against this instance's [egress] allowlist + active
    # environment before persisting, so a GUI edit pointing at a non-allowlisted host fails at edit
    # time exactly as it would at reload.
    try:
        settings = load_settings(config_path=args.service_config)
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        return _emit_error(str(exc), as_json=args.json)
    env_name = settings.ai.environment
    # Anchor environments/<env>.toml the same way serve does (honor [environments].base_dir), so a
    # GUI/CLI edit validates against the same env() values the running instance will resolve.
    env_values = (
        load_environment_values(
            base_dir=resolve_values_base_dir(settings.environments.base_dir, cwd=Path.cwd()),
            dir_name=settings.environments.dir,
            environment=env_name,
            environ=os.environ,
        )
        if env_name is not None
        else {}
    )

    def validate(config_dir: Path) -> None:
        registry = load_config(config_dir)
        build_check_registry(
            registry,
            inbound_bind_host=settings.inbound.bind_host,
            env_values=env_values,
            egress=settings.egress,
        )

    try:
        if args.action == "upsert":
            raw = args.data if args.data is not None else sys.stdin.read()
            obj = json.loads(raw)
            result = connections_edit.upsert_connection(args.config, obj, validate=validate)
        else:  # remove
            if not args.name:
                return _emit_error("--name is required for `connection remove`", as_json=args.json)
            result = connections_edit.remove_connection(args.config, args.name, validate=validate)
    except json.JSONDecodeError as exc:
        return _emit_error(f"invalid connection JSON: {exc}", as_json=args.json)
    except (WiringError, OSError) as exc:
        return _emit_error(str(exc), as_json=args.json)
    _print_json(result, compact=args.json)
    return 0


def _print_json(data: object, *, compact: bool) -> None:
    print(json.dumps(data) if compact else json.dumps(data, indent=2))


def _emit_error(message: str, *, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"error": message}))
    else:
        print(f"error: {message}")
    return 1


_DISPATCH = {
    "serve": _serve,
    "init": _init,
    "validate": _validate,
    "graph": _graph,
    "dryrun": _dryrun,
    "check": _check,
    "connection": _connection,
    "generate": _generate,
    "hl7schema": _hl7schema,
    "gen-key": _gen_key,
    "protect-key": _protect_key,
    "audit-verify": _audit_verify,
    "rotate-key": _rotate_key,
    "ai-policy": _ai_policy,
}


if __name__ == "__main__":
    raise SystemExit(main())
