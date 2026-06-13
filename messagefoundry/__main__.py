"""Command-line entrypoint for the MessageFoundry engine + IDE tooling.

    messagefoundry serve     --config ./samples/config --db ./messagefoundry.db   # run engine + API
    messagefoundry validate  --config ./samples/config --json                     # report problems
    messagefoundry graph     --config ./samples/config --json                     # the wired graph
    messagefoundry dryrun    --config ./samples/config --messages ./msgs --json   # run, don't send
    messagefoundry check     --config ./samples/config --messages ./msgs          # commit/CI gate
    messagefoundry generate  --type ADT --count 5 --out ./out/adt                 # synthetic HL7
    messagefoundry hl7schema --json                                               # HL7 field schema

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
from messagefoundry.logging_setup import LOG_LEVELS, configure_logging


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
        choices=("dev", "staging", "prod"),
        help="active environment (overrides [ai].environment; selects environments/<env>.toml values)",
    )
    serve.add_argument(
        "--allow-insecure-bind",
        action="store_true",
        help="permit a non-loopback [api].host even though Phase 1 ships no API TLS (bearer tokens "
        "and PHI would cross the network in cleartext); without this flag a non-loopback bind is "
        "refused. Use only on a trusted, firewalled network — front the API with TLS for real "
        "remote access. Does not relax the no-auth refuse.",
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

    try:
        settings = load_settings(config_path=args.service_config, cli=cli)
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Fail closed: with auth disabled the API answers as a full-privilege system identity, so a
    # non-loopback bind would publish admin access to the network. Loopback is the only no-auth posture.
    if not settings.auth.enabled and settings.api.host not in ("127.0.0.1", "localhost", "::1"):
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
        print("warning: the SQL Server store backend is EXPERIMENTAL.", file=sys.stderr)

    # PHI-at-rest posture (WP-5/WP-11d): refuse (require_encryption) or warn (prod) when no key is
    # configured. A DPAPI-protected key file (Windows) counts as a configured key; if it's set but
    # unreadable here, open_store fails closed at startup with the DPAPI error.
    if not (settings.store.encryption_key or settings.store.encryption_key_file):
        if settings.store.require_encryption:
            print(
                "error: [store].require_encryption is set but no MEFOR_STORE_ENCRYPTION_KEY (or "
                "[store].encryption_key_file) is configured; refusing to start (PHI would be stored "
                "unencrypted at rest)",
                file=sys.stderr,
            )
            return 2
        # Warn in any environment that may carry real PHI (staging + prod). dev is synthetic-only by
        # policy (CLAUDE.md §9 / docs/PHI.md), so it stays quiet to avoid alarm fatigue.
        if settings.ai.environment.value in ("prod", "staging"):
            env_name = settings.ai.environment.value
            print(
                f"warning: no MEFOR_STORE_ENCRYPTION_KEY set in a {env_name!r} environment — PHI "
                "bodies and the error/last_error/detail columns are stored UNENCRYPTED at rest (only "
                "volume encryption protects them). Generate a key with `messagefoundry gen-key` (or "
                "protect one to a file with `messagefoundry protect-key`), or set "
                "[store].require_encryption.",
                file=sys.stderr,
            )

    configure_logging(settings.logging.level)
    # Announce the active environment: it defaults to 'prod', so a quickstart that doesn't pass
    # --env silently resolves the PROD env() values — make that visible, not a surprise (review low-24).
    logging.getLogger(__name__).info(
        "active environment: %s (env() values from %s/%s.toml + MEFOR_VALUE_*)",
        settings.ai.environment.value,
        settings.environments.dir,
        settings.ai.environment.value,
    )
    # Phase 1 ships no API TLS, so a non-loopback bind puts bearer tokens + PHI on the wire in
    # cleartext. Fail closed: refuse unless the operator explicitly accepts that with
    # --allow-insecure-bind (then still warn). The auth-disabled case is refused above regardless of
    # this flag — serving full-privilege admin to the network is never one "I accept the risk" away.
    if settings.api.host not in ("127.0.0.1", "localhost", "::1"):
        if not args.allow_insecure_bind:
            print(
                "error: refusing to serve the API on non-loopback host "
                f"{settings.api.host!r}; Phase 1 has no TLS, so bearer tokens and PHI would cross "
                "the network in cleartext. Bind 127.0.0.1 (front it with TLS for remote access), or "
                "pass --allow-insecure-bind to accept the risk on a trusted, firewalled network.",
                file=sys.stderr,
            )
            return 2
        print(
            f"warning: API bound to non-loopback host {settings.api.host!r} with "
            "--allow-insecure-bind; Phase 1 has no TLS, so bearer tokens and PHI cross the network "
            "in cleartext — front it with TLS.",
            file=sys.stderr,
        )

    # This instance's environment values (env() lookups in the graph): environments/<env>.toml +
    # MEFOR_VALUE_* env. The active environment is the single selector [ai].environment. Passed as a
    # provider (re-read on each reload, not just startup) so a promote picks up edited values without
    # a service restart (review M-23).
    import os
    from pathlib import Path

    from messagefoundry.config.environments import load_environment_values

    def env_values() -> dict[str, Any]:
        return load_environment_values(
            base_dir=Path.cwd(),
            dir_name=settings.environments.dir,
            environment=settings.ai.environment.value,
            environ=os.environ,
        )

    app = create_managed_app(
        store_settings=settings.store,
        config_dir=args.config,
        config_reload_roots=settings.api.config_reload_roots,
        inbound_bind_host=settings.inbound.bind_host,
        delivery_defaults=settings.delivery.retry_policy(),
        ordering_default=settings.delivery.ordering,
        internal_error_default=settings.delivery.internal_error,
        buildup_default=settings.delivery.buildup_threshold(),
        ack_after_default=settings.inbound.ack_after,
        env_values_provider=env_values,
        auth_settings=settings.auth,
        ai_settings=settings.ai,
        alerts_settings=settings.alerts,
        retention_settings=settings.retention,
        egress_settings=settings.egress,
        expose_docs=settings.api.expose_docs,
        ws_allowed_origins=settings.api.ws_allowed_origins,
    )
    # log_config=None: uvicorn's loggers propagate to the handler configure_logging installed,
    # so everything shares one format/stream (and one log file under NSSM).
    uvicorn.run(app, host=settings.api.host, port=settings.api.port, log_config=None)
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
    eff = resolve_effective_policy(
        mode=ai.mode, data_scope=ai.data_scope, environment=ai.environment
    )
    payload = {
        "mode": eff.mode.value,
        "data_scope": eff.data_scope.value,
        "environment": eff.environment.value,
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
    "validate": _validate,
    "graph": _graph,
    "dryrun": _dryrun,
    "check": _check,
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
