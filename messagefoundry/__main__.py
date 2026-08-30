# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Command-line entrypoint for the MessageFoundry engine + IDE tooling.

    messagefoundry serve     --config ./samples/config --db ./messagefoundry.db   # run engine + API
    messagefoundry validate  --config ./samples/config --json                     # report problems
    messagefoundry graph     --config ./samples/config --json                     # the wired graph
    messagefoundry dryrun    --config ./samples/config --messages ./msgs --json   # run, don't send
    messagefoundry check     --config ./samples/config --messages ./msgs          # commit/CI gate
    messagefoundry connection upsert --config ./samples/config --data '{...}'      # edit connections.toml
    messagefoundry codeset upsert --config ./samples/config --data '{...}'         # edit codesets/*.csv
    messagefoundry generate  --type ADT --count 5 --out ./out/adt                 # synthetic HL7
    messagefoundry hl7schema --json                                               # HL7 field schema
    messagefoundry lens schema --json                                             # Steps-view param widget schema
    messagefoundry init      ./my-config-repo                                      # scaffold a config repo

The introspection subcommands (validate/graph/dryrun/check/hl7schema/lens schema) print to stdout
for the VS Code extension / git hooks; they touch no network and start no server. Heavy imports are
deferred per-command so a quick `validate`/`hl7schema`/`lens schema` call doesn't pay for FastAPI/uvicorn.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tomllib  # stdlib; used to classify a malformed <env>.toml at serve startup (clean error, not a traceback)
from pathlib import (
    Path,
)  # stdlib, imported at interpreter startup — no cost to the fast subcommands
from typing import Any

from messagefoundry import __version__
from messagefoundry.logging_setup import (
    LOG_LEVELS,
    SyslogForward,
    configure_logging,
    query_sntp_offset,
)


def main(argv: list[str] | None = None) -> int:
    # Harden the human-facing streams for a legacy Windows codepage (cp1252/charmap): argparse's own
    # --help/usage printer and runtime log/print() lines bypass _safe_print, so a non-cp1252 char
    # (an arrow or other symbol in a help string or log line) would otherwise abort with
    # UnicodeEncodeError. errors="replace" is lossy for such chars, but the machine-read JSON
    # subcommands stay ASCII (json.dumps ensure_ascii=True). Guarded: some stream wrappers
    # (PYTHONLEGACYWINDOWSSTDIO, pytest capture) lack reconfigure or reject it, and the hardening
    # must never itself crash the CLI.
    for _stream in (sys.stdout, sys.stderr):
        _reconfigure = getattr(_stream, "reconfigure", None)
        if _reconfigure is not None:
            try:  # noqa: SIM105
                _reconfigure(errors="replace")
            except (ValueError, OSError):
                pass

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
        "--shard",
        default=None,
        help="run only the inbound connections tagged with this shard id (L3 multi-process "
        "sharding). Outbound/routers/handlers are shared; only intake is partitioned. Omit to run "
        "the whole graph. `messagefoundry supervise` sets this per subprocess.",
    )
    serve.add_argument(
        "--allow-insecure-bind",
        action="store_true",
        help="permit a non-loopback [api].host WITHOUT TLS (bearer tokens and PHI would cross the "
        "network in cleartext); a dev override for a trusted, firewalled network. Prefer configuring "
        "[api].tls_cert_file (+ tls_key_file) for in-process TLS, which is allowed off-loopback "
        "without this flag. Does not relax the no-auth refuse.",
    )

    supervise = sub.add_parser(
        "supervise",
        help="L3 multi-process sharding: spawn one `serve --shard <id>` subprocess per shard "
        "(each its own db file + API port), monitor + restart them, stop all on shutdown",
    )
    supervise.add_argument(
        "--config", default="samples/config", help="config modules directory (*.py)"
    )
    supervise.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML passed to each shard (default: ./messagefoundry.toml if present)",
    )
    supervise.add_argument(
        "--db",
        default="messagefoundry.db",
        help="base store path; each shard gets <stem>_<shard>.db (a single default shard keeps the "
        "bare path)",
    )
    supervise.add_argument(
        "--base-port",
        type=int,
        default=8765,
        help="API port for the first shard; subsequent shards get base+1, base+2, ... (sorted order)",
    )
    supervise.add_argument(
        "--env",
        default=None,
        help="active environment NAME passed to every shard (overrides each shard's [ai].environment)",
    )
    supervise.add_argument(
        "--project-root",
        default=None,
        help="anchor for each shard's environments/<env>.toml resolution, forwarded to every shard as "
        "`serve --project-root`. Set this together with --env so the spawned shards resolve the env "
        "value file regardless of their working directory (otherwise it resolves against the child CWD).",
    )

    validate = sub.add_parser("validate", help="check a config dir and report all problems")
    validate.add_argument("--config", default="samples/config", help="config modules directory")
    _add_anchor_flags(validate)
    validate.add_argument("--json", action="store_true", help="emit JSON")

    graph = sub.add_parser("graph", help="print the wired Connection/Router/Handler graph")
    graph.add_argument("--config", default="samples/config", help="config modules directory")
    _add_anchor_flags(graph)
    graph.add_argument("--json", action="store_true", help="emit JSON")

    dryrun = sub.add_parser(
        "dryrun",
        help="run messages through the config without sending",
        description="Run messages through the config without sending. The preview honors "
        "[pipeline].snapshot_on_send (copy-on-Send, ADR 0104) resolved best-effort from the service "
        "settings (--service-config, else ./messagefoundry.toml if present); when no settings load "
        "it falls back to the setting's own default (ON) — matching the default engine, never a "
        "silent OFF (#230).",
    )
    dryrun.add_argument("--config", default="samples/config", help="config modules directory")
    _add_anchor_flags(dryrun)
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
    dryrun.add_argument(
        "--trace",
        nargs="?",
        const="json",
        default=None,
        choices=["json"],
        help="emit a line-addressable sys.settrace execution trace of the Router/Handler run as JSON "
        "(ADR 0072; preview-only + additive — no dispatch change). Feeds the #92 live-debug loop and "
        "#84 profiling/coverage. Assigned locals and msg writes are PHI: REDACTED unless --show-phi. "
        "`--trace` is equivalent to `--trace json`.",
    )

    check = sub.add_parser(
        "check",
        help="run validate + dryrun (+ advisory ruff/mypy) as a commit/CI gate",
        description="Run validate + dryrun (+ advisory ruff/mypy) as a commit/CI gate. The dryrun "
        "sub-check previews under [pipeline].snapshot_on_send (copy-on-Send, ADR 0104) resolved "
        "best-effort from this instance's messagefoundry.toml (same resolution as the posture "
        "check); when no settings load it falls back to the setting's own default (ON) — matching "
        "the default engine, never a silent OFF (#230).",
    )
    check.add_argument("--config", default="samples/config", help="config modules directory")
    _add_anchor_flags(check)
    check.add_argument(
        "--messages", default=None, help="HL7 fixtures dir (dryrun gates when it has *.hl7)"
    )
    check.add_argument("--no-lint", action="store_true", help="skip the advisory ruff/mypy checks")
    check.add_argument(
        "--strict-handler-security",
        action="store_true",
        help="promote the ADR 0144 handler-security lint to a blocking (required) check",
    )
    check.add_argument(
        "--handler-security-allow",
        action="append",
        default=None,
        metavar="ROOT",
        help="vet a third-party import ROOT (e.g. dateutil) so unvetted-import does not flag it; "
        "repeatable. Matches the import root, not the PyPI dist name (ADR 0144)",
    )
    check.add_argument("--json", action="store_true", help="emit JSON")

    adr_analyze = sub.add_parser(
        "adr-analyze",
        help="advisory spec-driven ADR coverage: acceptance-criteria->test links, missing criteria, "
        "open clarifications (Secure Development Standards section 5)",
    )
    adr_analyze.add_argument(
        "--adr-dir", default="docs/adr", help="ADR directory (default: docs/adr)"
    )
    adr_analyze.add_argument(
        "--repo-root",
        default=None,
        help="root for resolving test/fixture refs (default: adr-dir/../..)",
    )
    adr_analyze.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 if any acceptance-criterion test ref is missing",
    )
    adr_analyze.add_argument("--json", action="store_true", help="emit JSON")

    connection = sub.add_parser(
        "connection",
        help="manage connections.toml — list / upsert / remove (ADR 0007; the VS Code editor shells this)",
    )
    connection.add_argument("action", choices=["list", "upsert", "remove", "schema"])
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

    codeset = sub.add_parser(
        "codeset",
        help="manage codesets/*.csv translation tables — list / show / upsert / "
        "rename / remove (the VS Code grid editor shells this)",
    )
    codeset.add_argument("action", choices=["list", "show", "upsert", "rename", "remove"])
    codeset.add_argument("--config", default="samples/config", help="config modules directory")
    codeset.add_argument(
        "--name",
        default=None,
        help="code-set name (the file stem; required for show/rename/remove)",
    )
    codeset.add_argument("--to", default=None, help="new name for `codeset rename`")
    codeset.add_argument(
        "--data",
        default=None,
        help="code-set DETAIL JSON for upsert (default: read from stdin)",
    )
    codeset.add_argument("--json", action="store_true", help="emit JSON")

    impact = sub.add_parser(
        "impact",
        help="reverse-dependency pre-flight for a rename/delete (#152): report who references an "
        "object, or plan/apply a rename that rewrites every referent (tokenize-safe; dry-run by default)",
    )
    impact.add_argument("--config", default="samples/config", help="config modules directory")
    impact.add_argument(
        "kind",
        choices=sorted(_IMPACT_KINDS),
        help="the object kind to analyze (router/handler/outbound/code_set/…)",
    )
    impact.add_argument("name", help="the object's current name")
    impact.add_argument(
        "--rename-to",
        default=None,
        metavar="NEW",
        help="plan a rename to NEW: print the concrete literal edits that rewrite the object + its "
        "referents (dry-run unless --apply)",
    )
    impact.add_argument(
        "--delete",
        action="store_true",
        help="delete pre-flight: list the live referrers that would dangle if the object were removed",
    )
    impact.add_argument(
        "--apply",
        action="store_true",
        help="with --rename-to: actually write the edits to disk (otherwise a dry-run that writes nothing)",
    )
    impact.add_argument("--json", action="store_true", help="emit JSON")

    alert = sub.add_parser(
        "alert",
        help="manage [[alerts.rules]] in the service-settings TOML — list / add / remove "
        "(ADR 0014; the VS Code 'New Alert' editor shells this)",
    )
    alert.add_argument("action", choices=["list", "add", "remove"])
    alert.add_argument(
        "--service-config",
        default="messagefoundry.toml",
        help="service settings TOML the rules live in (created on `add` if absent)",
    )
    alert.add_argument(
        "--data", default=None, help="alert-rule JSON for add (default: read from stdin)"
    )
    alert.add_argument("--index", type=int, default=None, help="rule ordinal (for remove)")
    alert.add_argument("--json", action="store_true", help="emit JSON")

    security = sub.add_parser(
        "security",
        help="show / set the [security] posture in the service-settings TOML — the plain-language "
        "secure-by-default switches (ADR 0118; the VS Code [security] editor shells this)",
    )
    security.add_argument("action", choices=["show", "set"])
    security.add_argument(
        "--service-config",
        default="messagefoundry.toml",
        help="service settings TOML the [security] section lives in (created on `set` if absent)",
    )
    security.add_argument(
        "--data",
        default=None,
        help="[security] updates JSON for set (default: read from stdin); a null value RESETS that "
        "switch to its secure default",
    )
    security.add_argument("--json", action="store_true", help="emit JSON")

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

    structures = sub.add_parser(
        "hl7structures",
        help="print HL7 v2.5.1 message-structure metadata (trigger->structure + structure->segments; "
        "ADR 0104 §2.3 field-picker scope) — regenerate ide/media/hl7structures.json",
    )
    structures.add_argument("--json", action="store_true", help="emit JSON")

    lens = sub.add_parser(
        "lens",
        help="structured Steps view over Handlers (ADR 0076): statically parse a config module "
        "into the per-@handler row contract (the VS Code Steps editor shells this)",
    )
    lens_sub = lens.add_subparsers(dest="lens_command", required=True)
    lens_parse = lens_sub.add_parser(
        "parse",
        help="statically parse one config module into its element row contract (never imports or "
        "executes the module; @router defs are projected at --contract 2 and above)",
    )
    lens_parse.add_argument(
        "module",
        help="config module .py file to parse, or '-' to read the source from stdin (the IDE re-projects "
        "the live buffer this way after a structural edit)",
    )
    lens_parse.add_argument("--json", action="store_true", help="emit JSON")
    lens_parse.add_argument(
        "--contract",
        type=int,
        default=1,
        help="the row-contract version to emit (default 1). 1 is the shipped grammar; 2 adds the "
        "'note' and 'route' row kinds and projects @router defs (ADR 0076 Amendments A + D). A "
        "consumer asks for the version it can RENDER, so a client that omits this can never be handed "
        "a kind it has no renderer for",
    )

    lens_rewrite = lens_sub.add_parser(
        "rewrite",
        help="apply one row edit to a Handler and print the rewritten module source (ADR 0076 phase 3): "
        "op is set_params (edit a param, incl. a literal arg of a multi-line call), delete_row, "
        "insert_row, or move_row; every untouched byte is preserved and the result is re-parsed (invalid "
        "Python is refused with zero change); never imports or executes the module",
    )
    lens_rewrite.add_argument(
        "module",
        help="config module .py file to rewrite, or '-' to read the source from stdin (the IDE passes "
        "the live editor buffer this way)",
    )
    lens_rewrite.add_argument(
        "--edit",
        help="the edit spec as a JSON object; op defaults to set_params. Examples: "
        '\'{"line_start":53,"line_end":53,"op":"set_params","params":{"to":"OB_NEW"}}\', '
        '\'{"line_start":7,"line_end":7,"op":"delete_row"}\', '
        '\'{"line_start":6,"line_end":6,"op":"insert_row","position":"after","action":"set_field",'
        '"params":{"path":"MSH-3","value":"MEFOR"}}\', '
        '\'{"line_start":7,"line_end":7,"op":"move_row","direction":"up"}\'; '
        "omit to read the edit spec from stdin (only when 'module' is a file path, not '-')",
    )
    lens_rewrite.add_argument(
        "--contract",
        type=int,
        default=1,
        help="the row-contract version the row coordinates were PROJECTED with (default 1) - it must "
        "match the 'lens parse --contract' that produced them, so a v1 client's coordinates resolve "
        "against the v1 partition and a v2 client's against the v2 one",
    )

    lens_schema = lens_sub.add_parser(
        "schema",
        help="emit the transform-vocabulary parameter schema as JSON (op -> params with "
        "kind/choices/required/keyword_only), derived from the action + diagnostic signatures; "
        "the Steps editor drives its per-param input widgets from it (never imports/executes a "
        "module, starts no server)",
    )
    lens_schema.add_argument("--json", action="store_true", help="emit compact JSON")

    import_cmd = sub.add_parser(
        "import",
        help="deterministically import a legacy integration export into code-first config modules "
        "(ADR 0086): parse the export -> emit @router/@handler modules calling the ADR 0076 vocabulary; "
        "unmapped actions become in-place TODO stubs (never silently dropped)",
    )
    import_sub = import_cmd.add_subparsers(dest="import_format", required=True)
    import_corepoint = import_sub.add_parser(
        "corepoint",
        help="import a Corepoint action-list export (the validated <Package> XML schema, ADR 0086; "
        "the superseded synthetic JSON model still parses) into one config module per channel",
    )
    import_corepoint.add_argument(
        "export", help="path to the Corepoint action-list export (<Package> XML, or legacy JSON)"
    )
    import_corepoint.add_argument(
        "--out", required=True, help="config directory to write the generated modules into"
    )
    import_corepoint.add_argument("--json", action="store_true", help="emit a JSON import summary")

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

    support_bundle = sub.add_parser(
        "support-bundle",
        help="write a SECRET-FREE / PHI-free support zip (engine version + config summary + a "
        "/status snapshot + a REDACTED app-log tail) to hand to support (#49)",
    )
    support_bundle.add_argument(
        "--out", required=True, help="path to write the support-bundle .zip"
    )
    support_bundle.add_argument(
        "--config",
        default=None,
        help="config modules directory — drives the secret-free graph summary (counts/names only)",
    )
    support_bundle.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present) — drives the status "
        "snapshot + the redacted log tail",
    )
    support_bundle.add_argument(
        "--log-tail-lines",
        type=int,
        default=None,
        help="number of trailing app-log lines to include (redacted); default 500",
    )

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
    protect_key.add_argument(
        "--grant-account",
        default=None,
        metavar="PRINCIPAL",
        help="also grant READ on the key file to this service principal — a name like "
        "'NT SERVICE\\MessageFoundry' or a SID. SYSTEM is always granted read (so a LocalSystem "
        "service starts); pass this for a virtual / gMSA service account.",
    )

    cert = sub.add_parser(
        "cert",
        help="certificate tooling (BACKLOG #71/#72): import a PKCS#12/.pfx bundle to the PEM files the "
        "TLS loaders read, list cert facts (read-only inventory), or mint a self-signed dev cert",
    )
    cert_sub = cert.add_subparsers(dest="cert_command", required=True)

    cert_import = cert_sub.add_parser(
        "import",
        help="import a PKCS#12/.pfx bundle into cert.pem / key.pem / ca-chain.pem. The passphrase is "
        "read ONLY from MEFOR_PFX_PASSWORD (never a CLI arg); key.pem is written 0600 and refuses to "
        "overwrite an existing key",
    )
    cert_import.add_argument(
        "--pfx", required=True, help="path to the PKCS#12/.pfx bundle to import"
    )
    cert_import.add_argument(
        "--out-dir",
        required=True,
        help="directory to write cert.pem / key.pem / ca-chain.pem into (created if absent)",
    )
    cert_import.add_argument("--json", action="store_true", help="emit JSON")

    cert_inventory = cert_sub.add_parser(
        "inventory",
        help="read-only certificate inventory: print subject / issuer / notAfter / SAN / days-remaining "
        "/ expired per cert. Sources: --cert PATH (repeatable) and/or the wired TLS certs of --config",
    )
    cert_inventory.add_argument(
        "--cert",
        action="append",
        default=None,
        metavar="PATH",
        help="a certificate PEM file to inventory (repeatable)",
    )
    cert_inventory.add_argument(
        "--config",
        default=None,
        help="config modules directory — inventory every wired TLS cert (Connection tls_cert_file)",
    )
    cert_inventory.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML — supplies the [api] TLS cert path added to the --config inventory",
    )
    cert_inventory.add_argument("--json", action="store_true", help="emit JSON")

    cert_self_signed = cert_sub.add_parser(
        "self-signed",
        help="mint a self-signed EC P-256 cert+key (cert.pem / key.pem) for NON-PROD TLS bring-up ONLY; "
        "key.pem is written 0600 and refuses to overwrite an existing key",
    )
    cert_self_signed.add_argument(
        "--cn", required=True, help="certificate common name (also added as a DNS SAN)"
    )
    cert_self_signed.add_argument(
        "--san", action="append", default=None, metavar="DNS", help="an extra DNS SAN (repeatable)"
    )
    cert_self_signed.add_argument(
        "--days", type=int, default=365, help="validity in days (default 365)"
    )
    cert_self_signed.add_argument(
        "--out-dir",
        required=True,
        help="directory to write cert.pem / key.pem into (created if absent)",
    )
    cert_self_signed.add_argument("--json", action="store_true", help="emit JSON")

    # BACKLOG #1236 (ASVS availability). A sole-administrator deployment had NO recovery from account
    # lockout: the bootstrap account is named `admin` so it is the one an attacker guesses first, it is
    # created with no email so the ACCOUNT_LOCKED notice never leaves the process, self-reset is
    # refused, an admin reset needs ANOTHER admin, re-bootstrap only fires on an EMPTY users table, and
    # no CLI managed users. Every exit is individually deliberate; they close SIMULTANEOUSLY for a
    # deployment with one administrator. This is the offline exit.
    admin_unlock = sub.add_parser(
        "admin-unlock",
        help="clear a local account's lockout from the host (offline sole-administrator recovery)",
    )
    admin_unlock.add_argument("--username", required=True, help="the locked account to unlock")
    admin_unlock.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    admin_unlock.add_argument("--db", default=None, help="store path (overrides [store].path)")
    admin_unlock.add_argument("--json", action="store_true", help="emit JSON")

    audit_verify = sub.add_parser(
        "audit-verify", help="verify the audit-log hash chain (tamper-evidence)"
    )
    audit_verify.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    audit_verify.add_argument("--db", default=None, help="store path (overrides [store].path)")
    # ONE mutually-exclusive group: the two flags carry the same value in two transports, and argparse
    # refusing both is better than silently letting one win.
    audit_verify_anchor = audit_verify.add_mutually_exclusive_group()
    audit_verify_anchor.add_argument(
        "--expected-anchor",
        default=None,
        metavar="COUNT:HEAD",
        help="also compare against an anchor previously printed by 'audit-anchor'. The hash-chain "
        "walk alone CANNOT see a truncated tail (the surviving prefix still chains cleanly); this "
        "is what detects it",
    )
    audit_verify_anchor.add_argument(
        "--expected-anchor-file",
        default=None,
        metavar="PATH",
        help="read the COUNT:HEAD anchor from a UTF-8 text file holding the output of "
        "'messagefoundry audit-anchor' (on PowerShell 5.1 pipe to 'Set-Content -Encoding utf8' — "
        "its '>' writes UTF-16, which is refused)",
    )

    audit_anchor = sub.add_parser(
        "audit-anchor",
        help="print the audit log's external anchor (COUNT:HEAD) to hold out-of-band and pass back "
        "to 'audit-verify --expected-anchor'",
    )
    audit_anchor.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    audit_anchor.add_argument("--db", default=None, help="store path (overrides [store].path)")
    audit_anchor.add_argument("--json", action="store_true", help="emit JSON")

    rekey_audit = sub.add_parser(
        "rekey-audit",
        help="enable HMAC keying of an existing keyless audit chain (#190-D migration; non-silent, "
        "re-verifies first, requires the store encryption key — run with the engine stopped)",
    )
    rekey_audit.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    rekey_audit.add_argument("--db", default=None, help="store path (overrides [store].path)")

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

    backup = sub.add_parser(
        "backup",
        help="take an on-demand DR backup now: snapshot the store + bundle the config, encrypt to a "
        ".mfbak archive at the destination, restore-verify, prune to keep-N (ADR 0049, #60)",
    )
    backup.add_argument(
        "--config", default="samples/config", help="config modules dir bundled into the archive"
    )
    backup.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present) — [backup] + the "
        "store key source",
    )
    backup.add_argument("--db", default=None, help="store path (overrides [store].path)")
    backup.add_argument(
        "--destination",
        default=None,
        help="LOCAL or UNC destination dir (overrides [backup].destination). No cloud target.",
    )
    backup.add_argument(
        "--no-verify", action="store_true", help="skip the restore-verify after writing the archive"
    )
    backup.add_argument(
        "--full-verify",
        action="store_true",
        help="also run the heavier full restore-verify (open the snapshot through open_store)",
    )
    backup.add_argument(
        "--config-only",
        action="store_true",
        help="back up the config bundle only (no store snapshot) — forced on a server-DB store",
    )
    backup.add_argument("--json", action="store_true", help="emit JSON")

    restore_verify = sub.add_parser(
        "restore-verify",
        help="verify an existing .mfbak archive WITHOUT activating it: key-fingerprint precheck "
        "(KEY_MISMATCH before decrypt) -> decrypt -> integrity_check + row-count (ADR 0049, #60)",
    )
    restore_verify.add_argument("archive", help="path to the .mfbak archive to verify")
    restore_verify.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present) — the store key source",
    )
    restore_verify.add_argument("--db", default=None, help="store path (overrides [store].path)")
    restore_verify.add_argument(
        "--full",
        action="store_true",
        help="run the heavier full restore-verify (open the embedded store through open_store)",
    )
    restore_verify.add_argument("--json", action="store_true", help="emit JSON")

    ai_policy = sub.add_parser(
        "ai-policy", help="print the effective AI-assistance policy (for the IDE gate)"
    )
    ai_policy.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    ai_policy.add_argument("--json", action="store_true", help="emit JSON only (parsed by the IDE)")

    verify = sub.add_parser(
        "verify",
        help="on-box deployment acceptance: host checks + store connectivity + end-to-end smoke",
    )
    verify.add_argument(
        "--config", default="samples/config", help="config modules dir (for the self smoke)"
    )
    verify.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    verify.add_argument(
        "--section",
        default=None,
        help="comma-separated sections to run: host,store,smoke,manual,federation (default: all)",
    )
    verify.add_argument(
        "--smoke",
        default="self",
        choices=["self", "live", "none"],
        help="self = dry-run through the config (safe anywhere); live = MLLP to a running engine; none",
    )
    verify.add_argument("--engine-host", default="127.0.0.1", help="live smoke: engine host")
    verify.add_argument("--mllp-port", type=int, default=2575, help="live smoke: inbound MLLP port")
    verify.add_argument(
        "--inbound",
        default=None,
        help="self smoke: inbound connection name (if config has several)",
    )
    verify.add_argument(
        "--check-disposition",
        action="store_true",
        help="live smoke: after the ACK, poll the store for the message's FINAL disposition (PASS "
        "only if it reached PROCESSED — catches post-ACK dead-letters); needs --service-config",
    )
    verify.add_argument(
        "--disposition-timeout",
        type=float,
        default=15.0,
        help="seconds to wait for the live-smoke message to reach a terminal disposition (default 15)",
    )
    verify.add_argument(
        "--fed-id-token",
        default=None,
        help="federation: replay a captured id_token (file) through the validation ladder, "
        "OFFLINE, reporting a verdict per rung. Requires --fed-jwks",
    )
    verify.add_argument(
        "--fed-jwks",
        default=None,
        help="federation: the JWKS (file) to verify --fed-id-token against. Required with it "
        "-- without a key source there is nothing to verify the signature against",
    )
    verify.add_argument(
        "--fed-nonce",
        default=None,
        help="federation: the flow nonce the captured id_token was minted for. Without it the "
        "nonce rung (and everything after it) is reported SKIP, never PASS",
    )
    verify.add_argument("--report-md", default=None, help="also write the Markdown report here")
    verify.add_argument("--report-json", default=None, help="also write the JSON report here")

    service = sub.add_parser(
        "service",
        help="control the engine's Windows service (install|start|stop|status). Windows-only for "
        "the actions (start/stop are elevated via UAC); status is a plain `sc query`. Elsewhere the "
        "actions are no-ops and status reports 'unavailable'.",
    )
    service.add_argument("action", choices=["install", "start", "stop", "status"])
    service.add_argument(
        "--name",
        default="MessageFoundry",
        help="Windows service name to control (default: MessageFoundry)",
    )
    service.add_argument(
        "--env",
        default=None,
        help="active environment the service runs as (required for `install`; passed to "
        "install-service.ps1 as -Environment, i.e. serve --env)",
    )

    args = parser.parse_args(argv)
    return _DISPATCH[args.command](args)


def _add_anchor_flags(p: argparse.ArgumentParser) -> None:
    """Add the project-root / active-env / service-config trio to an OFFLINE subcommand (ADR 0050 §3).

    ``validate``/``graph``/``dryrun``/``check`` carried only ``--config`` before, so the commit/CI gate
    could resolve a DIFFERENT environment view than ``serve`` (review C3). These flags let the gate
    anchor the same bundle root and select the same active environment ``serve`` does — value
    resolution only, WITHOUT adopting serve's required-active-env / explicit-posture refusal (AC-6).
    """
    p.add_argument(
        "--project-root",
        default=None,
        help="anchor for the config bundle (overrides [environments].base_dir): the config-repo root "
        "that a relative --config / --service-config / environments/<env>.toml resolves against. "
        "Default = the working directory (unchanged). Match serve so the gate validates the same view.",
    )
    p.add_argument(
        "--env",
        default=None,
        help="active environment NAME (selects environments/<env>.toml values). With no --env the gate "
        "behaves exactly as before (no env values loaded); it never adopts serve's required-env refusal.",
    )
    p.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present). When passed (or with "
        "--project-root) check suppresses its messagefoundry.toml upward-walk and uses this instead.",
    )


def _resolve_offline_anchor(args: argparse.Namespace) -> tuple[str, str | None] | int:
    """Apply the ADR 0050 project-root anchor to an offline subcommand's paths, and fail loud on the
    one scoped missing-value-file case. Returns ``(config_dir, service_config)`` resolved under the
    root, or a non-zero exit code (already reported to stderr) on the hard failure.

    Precedence (explicit absolute > project-root > CWD) matches ``serve``: a relative ``--config`` /
    ``--service-config`` resolves under ``--project-root`` (or ``[environments].base_dir`` when only the
    service config is given); an absolute one is used as-is. The fail-loud trigger (AC-3) fires ONLY
    when an *explicit* ``--project-root`` is set AND the loaded graph references ``env()`` AND the
    selected ``<env>.toml`` is absent — a zero-``env()`` deployment, or a no-root launch, never trips it.
    """
    from messagefoundry.config.anchor import anchor_under_root, resolve_project_root

    cwd = Path.cwd()
    # --project-root is the explicit anchor; absent it, an explicit --service-config may still carry a
    # [environments].base_dir, but for the OFFLINE gate we only anchor against the explicit flag (no
    # settings load here — load_config below stays settings-free, like validate/graph/dryrun today).
    root = resolve_project_root(args.project_root, cwd=cwd)
    config_dir = anchor_under_root(args.config, root, cwd=cwd)
    assert config_dir is not None  # args.config always has a string default
    service_config = anchor_under_root(args.service_config, root, cwd=cwd)
    # Under an explicit root with no --service-config, the consumer-model messagefoundry.toml sits at
    # the repo root (a sibling of --config, ADR 0017). Point the posture check there so it resolves the
    # same file serve would — but ONLY if it exists, so a bundle that ships no service toml still SKIPs
    # (never a spurious failure).
    if service_config is None and root is not None:
        root_toml = root / "messagefoundry.toml"
        if root_toml.is_file():
            service_config = str(root_toml)

    # Fail loud only under an EXPLICIT root with an env name AND an env-referencing graph AND no file
    # (ADR 0050 §2, ratified). Without --env there is no value file to require; without --project-root
    # the silent-empty default is preserved; a zero-env() graph is never failed.
    if args.project_root is not None and args.env is not None and root is not None:
        env_dir = _env_dir_name(service_config)
        rc = _check_env_file_present(config_dir, root, args.env, env_dir)
        if rc is not None:
            return rc
    return config_dir, service_config


def _env_dir_name(service_config: str | None) -> str:
    """The ``[environments].dir`` value-dir name (default ``"environments"``).

    Read from the resolved ``service_config`` TOML (a tiny, settings-free tomllib read) so the offline
    AC-3 check honors a CUSTOM ``dir = "envs"`` instead of false-positive-failing on the hardcoded
    literal. Best-effort: no/unreadable/malformed file -> the default. The full ``load_settings`` is
    deliberately avoided here (the offline gate stays settings-free, like validate/graph/dryrun)."""
    if service_config is None:
        return "environments"
    try:
        with Path(service_config).open("rb") as fh:
            data = tomllib.load(fh)
    except (tomllib.TOMLDecodeError, OSError):
        return "environments"
    env_section = data.get("environments")
    if isinstance(env_section, dict):
        name = env_section.get("dir")
        if isinstance(name, str) and name:
            return name
    return "environments"


def _check_env_file_present(config_dir: str, root: Path, env_name: str, env_dir: str) -> int | None:
    """Hard-fail (return exit 2) if the graph references ``env()`` but ``<root>/<env_dir>/<env>.toml``
    is absent; otherwise ``None``. ``env_dir`` is ``[environments].dir`` (default ``environments``),
    read from the resolved service config so a custom value-dir name is honored, not false-failed."""
    from messagefoundry.config.anchor import graph_references_env
    from messagefoundry.config.wiring import WiringError, load_config

    try:
        reg = load_config(config_dir)
    except (WiringError, FileNotFoundError, OSError):
        # A config that doesn't load is reported by the subcommand's own validate/load path with a
        # precise message; don't pre-empt it here (and don't claim a missing env file for it). OSError
        # (e.g. an unreadable codesets dir) is swallowed best-effort, matching _graph_references_env_safe
        # — the subcommand's own load reports the real error, this pre-check must never raise a traceback.
        return None
    if not graph_references_env(reg):
        return None  # zero-env() deployment: the silent-empty contract is preserved (AC-3).
    env_file = root / env_dir / f"{env_name}.toml"
    if not env_file.is_file():
        print(
            f"error: the graph references env() but no value file was found at {env_file} under the "
            f"explicit --project-root {str(root)!r} for --env {env_name!r}. Create "
            f"{env_dir}/{env_name}.toml under the project root (or drop --project-root to use the "
            "working directory).",
            file=sys.stderr,
        )
        return 2
    return None


def _graph_references_env_safe(config_dir: str) -> bool:
    """Whether the loaded graph references ``env()`` — best-effort, never raises. A config that doesn't
    load returns ``False`` (the engine's own load reports the real error); used only to gate the ADR
    0050 advisory/fail-loud diagnostics, so a load hiccup must not abort serve here."""
    from messagefoundry.config.anchor import graph_references_env
    from messagefoundry.config.wiring import WiringError, load_config

    try:
        return graph_references_env(load_config(config_dir))
    except (WiringError, FileNotFoundError, OSError):
        return False


def _is_under(path: str, base: Path) -> bool:
    """Whether ``path`` resolves at or under ``base`` (best-effort; never raises).

    Used by the AC-5 NSSM diagnostic to ask "does the CWD look like the repo root?" against the
    --config target — robust to an ABSOLUTE --config (the NSSM case), where a bare ``Path(config).is_dir()``
    is True no matter where serve was launched. A relative --config (resolved against the CWD) is always
    under it; an absolute one is under the CWD only when serve really was launched from the repo.
    """
    try:
        return Path(path).resolve().is_relative_to(base.resolve())
    except (OSError, ValueError):
        return False


def _emit_anchor_diagnostics(
    *,
    root: Path | None,
    cwd: Path,
    config_dir: str,
    env_file: Path,
    service_config: str | None,
    store_path: str,
    env_values_empty: bool,
) -> int | None:
    """The three ADR 0050 §2 startup diagnostics (paths only, PHI-safe; once at boot, not per reload).

    Returns a non-zero exit code for the one scoped hard failure (AC-3), else ``None`` after emitting at
    most one advisory WARNING:

    * **AC-3 (ERROR / exit 2):** an EXPLICIT root is set, the graph references ``env()``, and the
      resolved ``<env>.toml`` is absent. The only new hard failure — scoped so a zero-``env()`` graph or
      a no-root launch keeps the shipped silent-empty contract.
    * **AC-4 (WARNING):** a root is set and CWD ≠ the resolved root — name the four members so an
      operator can confirm they agree (the wrong-DB / wrong-root footgun made visible, not refused).
    * **AC-5 (WARNING):** NO root, the launch dir is detectably not a config root, and the resolved
      ``env()`` values are empty (the NSSM silent miss) — point at ``--project-root``.
    """
    log = logging.getLogger(__name__)
    if root is not None:
        # AC-3: the one new hard failure, scoped to an explicit root + an env()-referencing graph.
        if not env_file.is_file() and _graph_references_env_safe(config_dir):
            print(
                f"error: the graph references env() but no value file was found at {env_file} under "
                f"the project root {str(root)!r}. Create it, or correct --project-root / "
                "[environments].base_dir (drop the root to fall back to the working directory).",
                file=sys.stderr,
            )
            return 2
        # AC-4: a deliberate cross-root layout is allowed but announced (paths only).
        if cwd.resolve() != root.resolve():
            log.warning(
                "project root %s differs from the working directory %s; bundle members resolve under "
                "the root: env values=%s, service config=%s, store db=%s. Confirm these are the "
                "intended locations.",
                root,
                cwd,
                env_file,
                service_config or "(default ./messagefoundry.toml)",
                store_path,
            )
        return None

    # AC-5: no root. The NSSM silent miss = launch dir is not a config root AND env values resolve
    # empty. "Not a config root" must be judged against the CWD, NOT the (possibly absolute) --config
    # path: an NSSM launch passes an ABSOLUTE --config that exists, so testing `Path(config_dir).is_dir()`
    # was always True and the warning never fired (the flagship-scenario dead branch). Instead ask
    # whether the CWD itself looks like the repo root: the config dir lives UNDER it, OR the env value
    # dir is under it (env_file.parent == cwd/<dir> when no root is set), OR a messagefoundry.toml sits
    # in it — any of which means serve was launched from the repo, not from an unrelated dir.
    if env_values_empty:
        launch_is_config_root = (
            _is_under(config_dir, cwd)
            or env_file.parent.is_dir()
            or (cwd / _DEFAULT_SERVICE_TOML).is_file()
        )
        if not launch_is_config_root:
            log.warning(
                "no env() values resolved and the working directory %s does not look like a config "
                "root (no %s, no %s, no %s). If serve was launched from elsewhere (e.g. under NSSM), "
                "set --project-root / [environments].base_dir to the config-repo root so env() values "
                "and the store DB are found there.",
                cwd,
                config_dir,
                env_file.parent,
                _DEFAULT_SERVICE_TOML,
            )
    return None


#: The default per-instance service-settings filename (mirrors config.settings._DEFAULT_FILE; named
#: here so the anchor diagnostics don't import a private settings symbol).
_DEFAULT_SERVICE_TOML = "messagefoundry.toml"


def _serve(args: argparse.Namespace) -> int:
    import uvicorn
    from pydantic import ValidationError

    from messagefoundry.api import create_managed_app
    from messagefoundry.auth.trust_anchors import collect_anchor_specs
    from messagefoundry.config.anchor import anchor_under_root, resolve_project_root
    from messagefoundry.config.memory_encryption import (
        READOUT_DISCLAIMER,
        platform_memory_encryption_readout,
    )
    from messagefoundry.config.settings import (
        StoreBackend,
        SyslogProtocol,
        forward_hop_disposition,
        hop_posture_from_ai,
        load_settings,
        security_loosenings,
    )
    from messagefoundry.config.tls_policy import (
        HopDisposition,
        in_process_tls_revocation_refused,
        tls_revocation_attested,
    )
    from messagefoundry.crashdump import suppress_crash_dumps
    from messagefoundry.store.crypto import memory_locking_available

    # ADR 0152 Phase 0 — in-USE PHI hygiene, applied before anything can put PHI in this address
    # space. A Windows Error Reporting dump of the engine writes every in-flight HL7 body, every
    # decrypted plaintext and the unwrapped DEK to a file outside the store's encryption, ACLs and
    # retention sweep. The call is process-local (nothing persisted, no privilege needed) and a no-op
    # off Windows. Scoped to `serve` deliberately: it is the only long-running command that holds
    # live PHI: `dryrun`/`generate` are operator-invoked and already documented as PHI-unsafe
    # (CLAUDE.md §9). It does NOT move ASVS 11.7.1 — memory hygiene is not memory encryption (OWASP
    # deleted 4.0.3 V8.3.6 and kept 11.7.1); this is worth doing on its own merits only.
    #
    # APPLIED here, REPORTED after configure_logging (below). The call must run before PHI can be
    # resident; the report must not, because at this point the root logger still has no handlers and
    # every record is serviced by logging.lastResort — which drops < WARNING at ANY --log-level and
    # reaches none of the handlers/filters/off-box forwarder the operator configured. A hardened
    # container (RLIMIT_MEMLOCK=0) would otherwise print a WARNING to stderr on every start that no
    # log level could suppress and no SIEM would ever receive.
    _dumps = suppress_crash_dumps()

    # Single project-root anchor (ADR 0050): --project-root (== [environments].base_dir) is the bundle
    # root; a relative --config / --service-config / [store].path resolves UNDER it, an absolute one is
    # used as-is, and an unset root keeps every member's CWD-relative default (unchanged). The flag is
    # also the env-value anchor, so write it into [environments].base_dir below.
    cwd = Path.cwd()
    root = resolve_project_root(args.project_root, cwd=cwd)
    config_dir = anchor_under_root(args.config, root, cwd=cwd)
    assert config_dir is not None  # args.config always has a string default
    service_config = anchor_under_root(args.service_config, root, cwd=cwd)

    # Only pass flags the user actually supplied so they override env/file but an unset flag doesn't.
    cli: dict[str, dict[str, object]] = {}
    if args.db is not None:
        # A relative --db follows the root; an absolute one is honored as-is (AC-7). Resolved here so
        # it lands in [store].path the same way a file-set relative path is anchored below.
        anchored_db = anchor_under_root(args.db, root, cwd=cwd)
        cli.setdefault("store", {})["path"] = anchored_db
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
        settings = load_settings(config_path=service_config, cli=cli)
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # The bundle root from BOTH sources (ADR 0050 §1 "the same merged value"): --project-root is already
    # written into cli["environments"]["base_dir"] above, so the MERGED settings.environments.base_dir
    # carries the CLI flag OR a file/env-set base_dir. Derive the effective root from it so a file-only
    # [environments].base_dir anchors [store].path + drives the AC-3/AC-4 diagnostics exactly like
    # --project-root — not a half-anchored bundle. (Scoped limit: --config / --service-config are resolved
    # BEFORE load_settings, so a FILE-set base_dir cannot retro-anchor THOSE two members — use
    # --project-root to anchor them; see config/anchor.py. The DB + env values + diagnostics, all resolved
    # post-load, honor either source.)
    effective_root = resolve_project_root(settings.environments.base_dir or None, cwd=cwd)

    # Anchor a relative [store].path under the root too (whether it came from --db or the settings
    # file): one DB location follows the project root, an absolute path stays put (AC-1/AC-7). Done on
    # the loaded settings so a file-authored relative path is anchored exactly like a relative --db.
    if effective_root is not None and not Path(settings.store.path).is_absolute():
        settings.store.path = str(effective_root / settings.store.path)

    # THE SINGLE DEFINITION of "this instance is exposed" (BACKLOG #326): an off-loopback bind OR a
    # declared upstream TLS terminator. Hoisted here so its earliest consumer — the auth-off arm just
    # below (BACKLOG #1013) — can read it; the full rationale (why not `serve_ui`, why deliberately
    # narrow) sits at the MFA-at-exposure gate that was its original first consumer. Defined ONCE: a
    # second copy is exactly how the ASVS 11.7.1 and 6.3.3 arms once disagreed about the same boot (#326).
    instance_exposed = not settings.api.is_loopback or settings.api.tls_terminated_upstream

    # Fail closed: with auth disabled the API would answer as a full-privilege system identity, so any
    # exposed instance would publish admin access to the network with no authentication at all. Exposure
    # is EITHER a non-loopback bind OR a declared upstream TLS terminator on a loopback bind — the same
    # `instance_exposed` the MFA-at-exposure gate consults (BACKLOG #1013: this arm previously keyed on
    # the bind alone, so an auth-off PHI instance behind a declared terminator would have started
    # silently on first deployment). A true loopback posture with no declared terminator is the only
    # place no-auth may run.
    if not settings.auth.enabled and instance_exposed:
        exposure_desc = (
            f"non-loopback host {settings.api.host!r}"
            if not settings.api.is_loopback
            else "loopback host behind a declared TLS-terminating reverse proxy "
            "([api].tls_terminated_upstream)"
        )
        print(
            f"error: refusing to serve with [auth] enabled=false on {exposure_desc}; the API would "
            "answer as a full-privilege system identity with no authentication. Enable auth or bind a "
            "loopback host with no declared terminator.",
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
    from messagefoundry.config.ai_policy import DataClass, SecurityEnforcement

    if settings.ai.environment is None:
        print(
            "error: no active environment set — pass --env <name> or set [ai].environment. It selects "
            "environments/<name>.toml and, with [security].handles_real_patient_data/production_instance, "
            "the instance's PHI posture.",
            file=sys.stderr,
        )
        return 2
    try:
        data_class, production = settings.ai.require_posture()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    env_name = settings.ai.environment

    # The security REFUSE/WARN dial (this refactor): the serve-gate posture gates + the ADR 0092 escape-
    # clamp key on this, NOT the production-tier `production` fact. ENFORCE (the secure default)
    # reproduces the historical production=True refuse posture byte-identically; `warn` reproduces the
    # historical non-production warn+audit+continue. The `production` tier fact is retained ONLY where it
    # reflects a true property (the DEBUG-logging refusal below; the AI data-scope ceiling).
    enforcing = settings.security.enforcement is SecurityEnforcement.ENFORCE

    # ADR 0118: [security].require_encryption_for_remote=false is the config-file twin of
    # --allow-insecure-bind (accept cleartext for off-machine access). It rides the SAME exposed-bind
    # gate + the SAME ADR 0092 production-PHI clamp below — it can never relax a production-PHI cleartext
    # bind. Fold both escapes into one flag the exposed-gate + create_managed_app read.
    insecure_bind_ok = (
        args.allow_insecure_bind or not settings.security.require_encryption_for_remote
    )

    # Delegated-identity precondition (#203, ASVS 13.2.1/13.3.2): when the operator declares
    # [store].require_managed_identity, refuse to start if the store authenticates with a static
    # credential rather than a managed/delegated identity (Windows Integrated / Entra). The refuse/warn
    # split is [security].enforcement, NOT the deployment tier — the branch below reads `enforcing`, and
    # `enforce` is the shipped default on dev and staging as much as on prod, so a staging box that
    # turns this on and leaves a static credential is REFUSED, not warned. It downgrades to a warning
    # only under enforcement = warn. Off by default → byte-identical. Admin device posture and AD/SMTP
    # managed identity stay deployment-delegated (documented in docs/SECURITY.md), not engine-checked.
    mi_reason = settings.store.managed_identity_precondition()
    if mi_reason is not None:
        if enforcing:
            print(
                f"error: [store].require_managed_identity is set but {mi_reason}; refusing to start.",
                file=sys.stderr,
            )
            return 2
        print(
            f"warning: [store].require_managed_identity is set but {mi_reason}.",
            file=sys.stderr,
        )

    # PHI-at-rest posture (H3, OWASP *Fail Securely* / SDS §4.3 PW.9 secure-by-default): with no key
    # configured, a PHI-carrying instance — gated on data_class == phi, NOT the environment label, so a
    # custom-named dev/test box holding near-real PHI is covered the same as prod — REFUSES to start
    # (fail-closed). The refusal fires in EVERY environment (dev/staging/prod) once data_class is phi.
    # An explicit [security].allow_unencrypted_phi=true is the loud, audited override that lets such an
    # instance start keyless (warn). A synthetic/non-PHI instance stays key-free (CI parity), and
    # [store].require_encryption forces the refusal even for a synthetic instance. A DPAPI-protected key
    # file (Windows) counts as a configured key; if it's set but unreadable here, open_store fails closed
    # at startup with the DPAPI error.
    if not (settings.store.encryption_key or settings.store.encryption_key_file):
        if settings.store.require_encryption:
            print(
                "error: [store].require_encryption is set but no MEFOR_STORE_ENCRYPTION_KEY (or "
                "[store].encryption_key_file) is configured; refusing to start (PHI would be stored "
                "unencrypted at rest)",
                file=sys.stderr,
            )
            return 2
        if data_class is DataClass.PHI:
            if not settings.store.allow_unencrypted_phi:
                # Secure-by-default: any PHI instance (data_class==phi), in any environment, refuses to
                # run keyless. This is the H3 tightening — previously prod refused and non-prod only
                # warned (fail-open), but dev/staging routinely hold near-real PHI.
                print(
                    f"error: no MEFOR_STORE_ENCRYPTION_KEY (or [store].encryption_key_file) set on a "
                    f"PHI instance (environment {env_name!r}, [ai].data_class=phi); refusing to start "
                    "— PHI bodies and the summary/metadata (MRN + patient name) and "
                    "error/last_error/detail columns would be stored UNENCRYPTED at rest. Generate a "
                    "key with `messagefoundry gen-key` (or protect one to a file with `messagefoundry "
                    "protect-key`) and configure it; or, to deliberately run without at-rest "
                    "encryption, set [security].allow_unencrypted_phi=true (audited).",
                    file=sys.stderr,
                )
                return 2
            if enforcing and not settings.security.allow_unencrypted_phi_under_strict_enforcement:
                # Secure-by-default under STRICT ENFORCEMENT (ADR 0140): keyless PHI under enforcement
                # requires a SECOND acknowledgment beyond [security].allow_unencrypted_phi — the highest-
                # risk posture (real PHI + strict enforcement) is never one flag away from plaintext at
                # rest. Under warn enforcement PHI keeps the single-flag audited override below.
                print(
                    "error: [security].allow_unencrypted_phi=true on a PHI instance under strict "
                    f"enforcement (environment {env_name!r}), but "
                    "[security].allow_unencrypted_phi_under_strict_enforcement is not set; refusing to "
                    "start — PHI bodies and the summary/metadata (MRN + patient name) and "
                    "error/last_error/detail columns would be stored UNENCRYPTED at rest. Configure a "
                    "key (MEFOR_STORE_ENCRYPTION_KEY), or set "
                    "[security].allow_unencrypted_phi_under_strict_enforcement=true to deliberately run "
                    "keyless under strict enforcement (audited).",
                    file=sys.stderr,
                )
                return 2
            # Explicit, audited override: start keyless on a PHI instance. Emit a loud warning AND a
            # WARNING-level audit record (captured by NSSM stdout/SIEM) so the deliberate weakening is
            # never silent. (Logging isn't configured yet here, so this goes through the root logger,
            # which emits >=WARNING to stderr by default — a durable startup audit line.) Under strict
            # enforcement the second ack ([security].allow_unencrypted_phi_under_strict_enforcement=true)
            # was verified above, so the AUDIT line names both flags; the warn posture names just the one.
            logging.getLogger(__name__).warning(
                "AUDIT: starting keyless on a %sPHI instance (environment %r, data_class=phi) because "
                "[security].allow_unencrypted_phi=true%s — PHI is stored UNENCRYPTED at rest "
                "(at-rest encryption opt-out override).",
                "production " if production else "",
                env_name,
                " + [security].allow_unencrypted_phi_under_strict_enforcement=true"
                if enforcing
                else "",
            )
            print(
                f"warning: [security].allow_unencrypted_phi=true — starting a "
                f"{'production ' if production else ''}PHI environment "
                f"({env_name!r}) keyless; PHI bodies and the summary/metadata (MRN + patient name) and "
                "error/last_error/detail columns are stored UNENCRYPTED at rest (only volume "
                "encryption protects them). Configure MEFOR_STORE_ENCRYPTION_KEY to encrypt them.",
                file=sys.stderr,
            )

    # PHI-at-rest invariant (#186b, ASVS 13.2.4): at-rest encryption is effective-by-default on ANY PHI
    # instance (data_class==phi), not only a production one — the keyless gate ABOVE already fails
    # closed in every environment unless an encryption key is configured or the audited
    # [security].allow_unencrypted_phi opt-out is set, so by the time control reaches here a PHI instance
    # necessarily has a key or the explicit opt-out. No further runtime check is added: an executable
    # re-assertion here would be unreachable dead code. Synthetic instances carry no PHI and are exempt,
    # so a dev/loopback synthetic start stays byte-identical.
    #
    # Open-egress posture (Q5b): on a PHI-carrying instance, outbound egress that is fully
    # unrestricted — no [egress] allowlist AND deny_by_default off — lets a transform send PHI to any
    # destination. The refuse/warn split is [security].enforcement, NOT the deployment tier: the branch
    # below reads `enforcing`, and `enforce` is the shipped default on dev and staging as much as on
    # prod, so all three REFUSE on stock defaults. It downgrades to an advisory warning only under
    # enforcement = warn. A synthetic instance carries no PHI and stays quiet. Lock it down with
    # [security].block_unlisted_outbound or per-transport [egress].allowed_* lists.
    #
    # [egress] declares EIGHT allowed_* lists and every one is enforced downstream by _allowlist_for
    # (pipeline/wiring_runner.py). Counting only six here meant a mail-only or Direct-only instance
    # could enumerate every destination it actually uses and still be refused as "UNRESTRICTED", with
    # nothing in the refusal naming the two lists that did not count. allowed_smtp/allowed_direct are
    # counted only when [security].block_unlisted_outbound was NOT set explicitly — precisely the state
    # the flip below turns deny-by-default ON for, so such an instance still starts fail-closed. An
    # instance that explicitly opted OUT of deny-by-default is deliberately unchanged: it cannot
    # satisfy this gate on smtp/direct alone, because there the other six transports stay allow-any.
    if data_class is DataClass.PHI:
        eg = settings.egress
        listed = (
            eg.allowed_mllp
            or eg.allowed_tcp
            or eg.allowed_http
            or eg.allowed_db
            or eg.allowed_remote
            or eg.allowed_file_dirs
        )
        if "deny_by_default" not in eg.model_fields_set:
            listed = listed or eg.allowed_smtp or eg.allowed_direct
        egress_open = not eg.deny_by_default and not listed
        if egress_open:
            # Reaching here WITH allowed_smtp/allowed_direct declared is only possible when
            # [security].block_unlisted_outbound was set explicitly (otherwise those two count above), so
            # name that override rather than leaving the operator to wonder why a declared allowlist did
            # not satisfy the gate.
            mail_only_note = (
                " You have declared [egress].allowed_smtp/allowed_direct, but those satisfy this gate "
                "only when [security].block_unlisted_outbound is left unset — setting it false opts out "
                "of the deny-by-default flip, which would leave every OTHER transport allow-any. Remove "
                "that override (or set it true) and a mail-only/Direct-only allowlist is accepted."
                if (eg.allowed_smtp or eg.allowed_direct)
                else ""
            )
            if enforcing:
                print(
                    f"error: outbound egress is UNRESTRICTED on a "
                    f"{'production ' if production else ''}PHI instance "
                    f"({env_name!r}); refusing to start — a transform could send PHI to any "
                    "destination. Set [security].block_unlisted_outbound=true, or declare the permitted "
                    f"destinations with per-transport [egress].allowed_* allowlists.{mail_only_note}",
                    file=sys.stderr,
                )
                return 2
            print(
                f"warning: outbound egress is UNRESTRICTED in a PHI-carrying environment "
                f"({env_name!r}) — a transform may send to any destination. Set "
                "[security].block_unlisted_outbound or per-transport [egress].allowed_* allowlists to fail "
                "closed.",
                file=sys.stderr,
            )

    # Egress deny-by-default effective flip (#186c, ASVS 13.2.4/13.2.5): a PRODUCTION PHI instance
    # defaults to FAIL-CLOSED egress. Unless the operator explicitly set [security].block_unlisted_outbound, turn
    # it ON here so a transport whose per-type [egress].allowed_* list is EMPTY refuses every
    # destination of that type — closing the gap the all-or-nothing open-egress gate above leaves (a
    # partially-configured instance would otherwise allow-any the transports it did not list). The
    # opt-out is EXPLICIT + audited: writing [security].block_unlisted_outbound=false restores the per-list opt-in
    # (empty = allow-any) posture. Gated on ANY PHI instance (WP243/#243, ASVS 13.2.4/13.2.5 — broadened
    # from production-only): a synthetic/dev instance is exempt (non-PHI carries no egress posture, so
    # existing dev/loopback configs load byte-identical), but a non-production (staging / declared-PHI
    # loopback) instance now also flips. Placed AFTER the open-egress gate so a fully-open production
    # instance hits that gate's refusal first. settings.egress is the same object later passed to
    # create_managed_app, so the in-place flip threads through to the wiring_runner egress enforcement
    # (no forbidden-file edit).
    if data_class is DataClass.PHI:
        if "deny_by_default" not in settings.egress.model_fields_set:
            settings.egress.deny_by_default = True
            # configure_logging has not run yet (root lastResort drops < WARNING), so announce on stderr
            # like the sibling posture gates rather than logging.info.
            print(
                f"info: [security].block_unlisted_outbound defaulted ON for a "
                f"{'production ' if production else ''}PHI instance "
                f"({env_name!r}) — a transport with an empty [egress].allowed_* list now refuses every "
                "destination of that type (secure-by-default). Declare the permitted destinations per "
                "transport, or set [security].block_unlisted_outbound=false to restore allow-any.",
                file=sys.stderr,
            )
        elif not settings.egress.deny_by_default:
            # Explicit, audited opt-out on a production PHI instance (mirrors allow_unencrypted_phi):
            # the operator has chosen the allow-any (empty = unrestricted) egress posture. This audit
            # line is WARNING-level so the root lastResort handler still surfaces it before
            # configure_logging.
            logging.getLogger(__name__).warning(
                "AUDIT: [security].block_unlisted_outbound=false on a %sPHI instance (environment %r) — "
                "outbound egress uses the allow-any posture (a transport with an empty allowlist may "
                "send to ANY destination of that type); the secure-by-default deny is opted out.",
                "production " if production else "",
                env_name,
            )
            print(
                f"warning: [security].block_unlisted_outbound=false on a "
                f"{'production ' if production else ''}PHI instance ({env_name!r}) "
                "— a transport with an empty [egress].allowed_* list may send PHI to ANY destination of "
                "that type. Remove the override (or set it true) to fail closed.",
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
            # Native TLS-syslog (ADR 0080): applied only when protocol == "tls"; unused otherwise.
            tls_ca_file=settings.logging.forward_tls_ca_file,
            tls_verify=settings.logging.forward_tls_verify,
            tls_client_cert=settings.logging.forward_tls_client_cert,
        )
        if settings.logging.forward_enabled and settings.logging.forward_host
        else None
    )
    # #200 (ADR 0092) residual: the forwarder was the ONE egress path with no posture gate — its
    # plaintext-UDP default shipped the (PHI-redacted, but still sensitive) log + audit evidence stream
    # off-box in the clear, silently. Decide it with the SAME shared authority the transports use, and
    # BEFORE configure_logging installs the handler, so a refused hop never emits a single record.
    # Loopback (the ADR 0080 local-agent deployment) and a synthetic instance are untouched; the
    # acknowledged opt-out is [logging].forward_hop_attested.
    if log_forward is not None:
        _forward_hop = forward_hop_disposition(
            settings.logging,
            hop_posture_from_ai(settings.ai, enforcement=settings.security.enforcement),
        )
        # Name WHY the hop is unprotected: a plaintext protocol, or tls with verification opted out
        # (encrypted but unauthenticated => MITM-able). Both land on the gradient.
        _forward_why = (
            "certificate verification is disabled (forward_tls_verify=false)"
            if settings.logging.forward_protocol is SyslogProtocol.TLS
            else f"forward_protocol={settings.logging.forward_protocol.value!r} is plaintext"
        )
        if _forward_hop is HopDisposition.REFUSE:
            print(
                "error: [logging] off-box forwarding to "
                f"{settings.logging.forward_host}:{settings.logging.forward_port} is not a verified-TLS "
                f"hop ({_forward_why}) — the log/audit evidence stream would cross the network "
                f"unprotected on a PHI instance under [security].enforcement=enforce ({env_name!r}). "
                "Set [logging].forward_protocol='tls' with [logging].forward_tls_ca_file (ADR 0080), or "
                "point the forwarder at 127.0.0.1 and let a local agent add TLS, or set "
                "[logging].forward_hop_attested=true (+ forward_hop_attested_reason) to attest the hop "
                "is secure by other means.",
                file=sys.stderr,
            )
            return 2
        if _forward_hop is HopDisposition.WARN:
            # Crossed, but never silent — the point of the fix. WARNING surfaces via the root
            # lastResort handler even though configure_logging has not run yet.
            logging.getLogger(__name__).warning(
                "AUDIT: off-box log/audit forwarding to %s:%d is NOT a verified-TLS hop (%s), so the "
                "evidence stream crosses the network unprotected on a PHI instance. Set "
                "[logging].forward_protocol='tls' (ADR 0080) or forward via a local agent on 127.0.0.1.",
                settings.logging.forward_host,
                settings.logging.forward_port,
                _forward_why,
            )
    forwarder_live = configure_logging(
        settings.logging.level, fmt=settings.logging.format.value, forward=log_forward
    )
    if forwarder_live and log_forward is not None:
        # Only announce forwarding when configure_logging actually installed the handler — a TCP
        # collector that is down at startup is skipped (it warns), so this must not contradict it.
        logging.getLogger(__name__).info(
            "off-box log forwarding enabled -> %s:%d (%s, %s)",
            log_forward.host,
            log_forward.port,
            log_forward.protocol,
            log_forward.fmt,
        )

    # ADR 0152 Phase 0 read-outs, reported HERE rather than where they were taken (see the
    # suppress_crash_dumps() call site): only past configure_logging do these honor --log-level and
    # reach the handlers/filters/off-box forwarder. Both are memory HYGIENE — neither bears on ASVS
    # 11.7.1 — and neither is ever a refusal.
    _hygiene_log = logging.getLogger(__name__)
    if _dumps.supported and not (_dumps.error_mode_set and _dumps.wer_flags_set):
        # Degraded, not fatal: refusing to start an interface engine because a WER flag would not set
        # would be a worse outcome than the dump it was meant to prevent. Say so rather than hide it.
        _hygiene_log.warning(
            "Windows crash-dump suppression is INCOMPLETE (error mode set=%s, WER flags set=%s) — a "
            "fault report of this process could capture plaintext PHI from the heap.",
            _dumps.error_mode_set,
            _dumps.wer_flags_set,
        )
    # The store cipher's mlock/VirtualLock residency (store/crypto.py) is best-effort and swallows
    # every failure BY DESIGN, which is right for the hot path and is also exactly how a silently
    # degraded deployment stays invisible. Probe it once so an operator learns from a log line rather
    # than from a forensic report. Safe HERE and only here: the probe locks and then unlocks a page,
    # and page unlocking is not reference-counted on any platform, so it must run before the store
    # cipher installs a DEK (see memory_locking_available's docstring).
    if not memory_locking_available():
        _hygiene_log.warning(
            "secret memory residency is UNAVAILABLE in this process (mlock/VirtualLock refused a "
            "DEK-sized buffer) — key material and transient plaintext may be paged to swap/disk. "
            "Raise the process locked-memory limit (RLIMIT_MEMLOCK on POSIX, the minimum working-set "
            "quota on Windows) if your threat model includes an attacker reading the page file."
        )

    # ADR 0118 (AC-4): name every [security] switch that has been loosened from its secure default, in
    # plain language, so a deliberate opt-out is never silent. Advisory only — the posture GATES below
    # still refuse a production-PHI weakening (the ADR 0092 clamp is unchanged). The shared
    # security_loosenings() feeds both this warning and the read-only GET /security/posture view.
    # The connection graph is NOT loaded yet here (the Engine loads it inside the ASGI lifespan, well
    # below), so this early warning covers the SETTINGS-scoped switches only and passes empty lists for
    # all THREE connection-scoped deviations. That is not a silent subset: each is reported moments
    # later — per connection — by the connector's own construction-time WARN (the ADR 0153 acceptance
    # with its reason and an audit record; the #333 generic-ODBC TLS reminder naming the connection),
    # and completely by `messagefoundry check` and GET /security/posture, which both have the graph.
    _loosenings = security_loosenings(
        settings.security, settings.store, settings.auth, settings.alerts, (), (), ()
    )
    if _loosenings:
        _seclog = logging.getLogger(__name__)
        _seclog.warning(
            "[security] posture loosened from the secure defaults (%d): %s — see "
            "docs/SECURITY-LOOSENING.md. Production-PHI weakenings are still refused below. "
            "Per-connection cleartext_accepted (ADR 0153), tls_allow_expired and generic-ODBC "
            "DATABASE TLS declarations are NOT in this list — the graph is not loaded yet; they are "
            "reported by the connector construction gate, `messagefoundry check` and "
            "GET /security/posture.",
            len(_loosenings),
            "; ".join(f"{name} ({risk})" for name, risk in _loosenings),
        )

    # Startup clock-sync gate (ASVS 16.2.2; ADR 0080): cross-host log/audit correlation assumes the
    # engine host's clock tracks a reference. Opt-in (require_time_sync + ntp_peer) because the engine
    # can only verify skew against a configured peer — default is a NO-OP, byte-identical startup. The
    # SNTP probe is fully bounded (query_sntp_offset carries its own socket timeout), so it can never
    # hang serve(); it runs BEFORE listeners start so a fail-closed refusal never accepts a message
    # under an unsynchronized clock. WARN loudly by default; refuse only under time_sync_fail_closed.
    lg = settings.logging
    if lg.require_time_sync and lg.ntp_peer:  # validator guarantees ntp_peer when require_time_sync
        sync_log = logging.getLogger(__name__)
        try:
            offset = query_sntp_offset(lg.ntp_peer)
        except OSError as exc:
            # Unreachable / non-responsive peer: we cannot confirm sync. Fail closed if asked, else warn.
            if lg.time_sync_fail_closed:
                print(
                    f"error: [logging].require_time_sync is set but the time reference "
                    f"{lg.ntp_peer!r} could not be queried ({exc}); refusing to start "
                    "([logging].time_sync_fail_closed). Restore NTP reachability, or unset "
                    "time_sync_fail_closed to downgrade this to a warning.",
                    file=sys.stderr,
                )
                return 2
            sync_log.warning(
                "clock-sync check: could not query time reference %r (%s); continuing — cross-host "
                "log correlation may be unreliable (ASVS 16.2.2)",
                lg.ntp_peer,
                exc,
            )
        else:
            skew = abs(offset)
            if skew > lg.time_sync_max_skew_seconds:
                if lg.time_sync_fail_closed:
                    print(
                        f"error: local clock skew {skew:.3f}s vs {lg.ntp_peer!r} exceeds "
                        f"[logging].time_sync_max_skew_seconds={lg.time_sync_max_skew_seconds}; "
                        "refusing to start ([logging].time_sync_fail_closed). Synchronize the host "
                        "clock (w32tm/NTP), or unset time_sync_fail_closed to warn instead.",
                        file=sys.stderr,
                    )
                    return 2
                sync_log.warning(
                    "clock-sync check: local clock is %.3fs off time reference %r (threshold %.3fs) "
                    "— cross-host log correlation may be unreliable (ASVS 16.2.2)",
                    offset,
                    lg.ntp_peer,
                    lg.time_sync_max_skew_seconds,
                )
            else:
                sync_log.info(
                    "clock-sync check: local clock within %.3fs of %r (skew %.3fs)",
                    lg.time_sync_max_skew_seconds,
                    lg.ntp_peer,
                    skew,
                )

    # Anchor for the per-environment value dir: [environments].base_dir (or --project-root) when set,
    # else the working directory (unchanged default). Resolved once here so the startup log shows the
    # exact file env() values come from — the standalone-repo / NSSM footgun is a silently-wrong path.
    from messagefoundry.config.environments import resolve_values_base_dir

    env_base = resolve_values_base_dir(settings.environments.base_dir, cwd=cwd)
    env_file = env_base / settings.environments.dir / f"{env_name}.toml"
    # Announce the active environment + posture so an operator can see which env() values resolve and
    # the PHI posture in effect (the env is required — there is no silent default).
    logging.getLogger(__name__).info(
        "active environment: %s (data_class=%s, production=%s; env() values from %s + MEFOR_VALUE_*)",
        env_name,
        data_class.value,
        production,
        env_file,
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
        elif insecure_bind_ok and not (data_class is DataClass.PHI and enforcing):
            print(
                f"warning: API bound to non-loopback host {settings.api.host!r} with "
                "--allow-insecure-bind and NO TLS; bearer tokens and PHI cross the network in "
                "cleartext — configure [api].tls_cert_file (+ tls_key_file) for real remote access.",
                file=sys.stderr,
            )
        elif insecure_bind_ok:
            # #200 (ADR 0092, decision 2) + [security].enforcement: --allow-insecure-bind is CLAMPED
            # shut while the security dial is ENFORCING — a PHI listener refuses cleartext even WITH the
            # flag (a staging PHI instance under the default enforce refuses exactly like prod; the same
            # decoupling as every other posture gate — set [security].enforcement=warn to accept the
            # risk). Serving bearer tokens + PHI in the clear under strict enforcement is never one
            # "I accept the risk" away.
            print(
                "error: refusing to serve the API on non-loopback host "
                f"{settings.api.host!r} without TLS on a PHI instance under "
                f"[security].enforcement=enforce ({env_name!r}) — --allow-insecure-bind cannot relax a "
                "PHI cleartext bind under strict enforcement (#200). Configure [api].tls_cert_file for "
                "in-process TLS, set [api].tls_terminated_upstream (+ trusted_proxies) if a proxy "
                "terminates TLS, or set [security].enforcement=warn to accept the cleartext risk on a "
                "trusted, firewalled network.",
                file=sys.stderr,
            )
            return 2
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

    # Gate: certificate REVOCATION posture (ASVS 12.1.4, ADR 0078 — the ENFORCED half of ADR 0002's
    # documented delegation). WHEN the engine terminates TLS IN-PROCESS (uvicorn, [api].tls_cert_file)
    # on a network-reachable host, a REVOKED-but-unexpired server (or mTLS client) certificate is still
    # accepted: stdlib `ssl` performs no OCSP/CRL fetch and the engine deliberately attempts none (on-
    # prem, offline-by-default; CLAUDE.md §2). Revocation must be PROVEN IN FRONT — a declared TLS-
    # terminating reverse proxy (tls_terminated_upstream + trusted_proxies, WP-15, which does its own
    # OCSP-must-staple / CRL revocation) OR an explicit operator attestation
    # (MEFOR_TLS_REVOCATION_ATTESTED=1) that the terminator/PKI enforces revocation. Absent both, refuse
    # fail-closed. Loopback and proxy-terminated deployments never reach this — they start byte-
    # identically (the predicate short-circuits). Layered AFTER the §0 exposed-bind ladder above
    # (extend-never-weaken), like the keyless-store / open-egress / MFA-at-exposure gates.
    proxy_terminated = settings.api.tls_terminated_upstream and bool(settings.api.trusted_proxies)
    if in_process_tls_revocation_refused(
        tls_enabled=settings.api.tls_enabled,
        is_loopback=settings.api.is_loopback,
        proxy_terminated=proxy_terminated,
        attested=tls_revocation_attested(),
    ):
        print(
            "error: refusing to serve the API with in-process TLS on non-loopback host "
            f"{settings.api.host!r}: the engine terminates TLS itself but performs NO certificate "
            "revocation check (stdlib ssl has no OCSP/CRL fetch; the engine is offline-by-default), so "
            "a revoked-but-unexpired certificate would still be accepted (ASVS 12.1.4). Terminate TLS "
            "at a revocation-checking reverse proxy (set [api].tls_terminated_upstream + "
            "[api].trusted_proxies; e.g. OCSP-must-staple at IIS/nginx/Caddy), or set "
            "MEFOR_TLS_REVOCATION_ATTESTED=1 to attest that your TLS terminator/PKI enforces "
            "revocation. See docs/adr/0078-certificate-revocation-posture.md.",
            file=sys.stderr,
        )
        return 2

    # --- #200 Posture-B (upstream TLS termination) fail-closed gate (ASVS 4.2.1/4.4.1, 11.6.2) ------
    # When a reverse proxy terminates TLS in front (settings.api.tls_terminated_upstream), the exposed-
    # gate above ALLOWS the off-loopback bind unconditionally — but two properties are then UNVERIFIABLE
    # by the engine: (a) the proxy→engine internal hop is a plaintext segment, so a rogue peer on that
    # segment could impersonate the proxy unless the hop is authenticated; and (b) the engine terminates
    # no browser TLS, so it cannot observe the proxy's negotiated version/KEX floor (11.6.2). The engine
    # cannot inspect either, so it requires the operator to AFFIRMATIVELY DECLARE them (attestations made
    # fail-closed) before a PHI-PRODUCTION Posture-B bind may start. Mirror the require_mfa / keyless-
    # store posture EXACTLY: REFUSE on a production PHI instance, WARN on a non-production PHI instance,
    # stay QUIET (byte-identical) on a synthetic/non-PHI instance. --allow-insecure-bind CANNOT reach
    # here: it lives only in the no-TLS arm of the mutually-exclusive exposed-gate if/elif above, so a
    # Posture-B (tls_terminated_upstream) bind never consults it — the refusal cannot be flag-bypassed.
    # Keyed on the DECLARATION, not the bind. It used to require `not is_loopback`, which meant the
    # topology OFF-LOOPBACK-DEPLOYMENT.md actually RECOMMENDS — engine stays on 127.0.0.1, nginx/Caddy
    # on the same host faces the network — never consulted this gate at all, while the discouraged
    # direct NIC bind did. Backwards: the operators taking the safest path got the least verification.
    # The loopback arm WARNS rather than refuses (owner decision): the engine cannot distinguish
    # "loopback behind a declared proxy" from "loopback and genuinely unexposed" beyond the declaration
    # itself, and refusing would hard-stop working deployments on upgrade. The off-loopback arm keeps
    # refusing exactly as before, so this change is additive — it can only add a warning, never a new
    # refusal.
    if settings.api.tls_terminated_upstream:
        posture_b_missing = []
        if not settings.api.proxy_intra_service_declared:
            posture_b_missing.append(
                "[api].proxy_intra_service_auth (proxy→engine hop authentication)"
            )
        if not settings.api.proxy_tls_floor_declared:
            posture_b_missing.append("[api].proxy_tls_min_version (attested proxy TLS/KEX floor)")
        if posture_b_missing and data_class is DataClass.PHI:
            missing_desc = "; ".join(posture_b_missing)
            if enforcing and not settings.api.is_loopback:
                print(
                    f"error: refusing to serve on a {'production ' if production else ''}PHI instance "
                    f"({env_name!r}) behind an upstream TLS terminator ([api].tls_terminated_upstream) "
                    f"without: {missing_desc}. The engine cannot verify the proxy→engine internal hop "
                    "or the proxy's negotiated TLS/KEX (it terminates no browser TLS here), so it "
                    "requires these operator attestations before exposure. Declare "
                    "[api].proxy_intra_service_auth (mtls/network/shared_secret) and "
                    "[api].proxy_tls_min_version (1.2/1.3). See "
                    "docs/security/OFF-LOOPBACK-DEPLOYMENT.md (ADR 0002).",
                    file=sys.stderr,
                )
                return 2
            loopback_note = (
                " This is the recommended loopback-behind-proxy topology, so it warns rather than "
                "refuses — but the proxy is facing the network on your behalf, and the attestations "
                "are the only record that its internal hop and TLS floor were considered."
                if settings.api.is_loopback
                else ""
            )
            print(
                "warning: upstream TLS terminator ([api].tls_terminated_upstream) in a PHI-carrying "
                f"environment ({env_name!r}) without: {missing_desc}. Declare "
                "[api].proxy_intra_service_auth and [api].proxy_tls_min_version before exposure — the "
                "engine cannot verify the internal hop or the proxy's TLS/KEX for itself (attestation)."
                f"{loopback_note}",
                file=sys.stderr,
            )

    # The browser ops console ([api].serve_ui, ADR 0065) is a SEPARATE optional wheel
    # (messagefoundry-webconsole) mounted same-origin in-process. Refuse serve_ui when it is absent with
    # a clean, actionable message BEFORE the exposure gates below (mirrors the sqlserver find_spec
    # precedent) — the guarded mount_ui import in create_app would otherwise RuntimeError deeper in.
    if settings.api.serve_ui:
        import importlib.util

        if importlib.util.find_spec("messagefoundry_webconsole") is None:
            if settings.api.serve_ui_explicit:
                # (b) [security].serve_web_console was EXPLICITLY set true but the optional wheel is
                # absent — keep the HARD refuse (ADR 0143 soft-degrade contract): the operator asked
                # for the console by name, so a silent JSON-only downgrade would be surprising.
                print(
                    "error: [security].serve_web_console=true needs the web console package "
                    "'messagefoundry-webconsole', which is not installed; install it and retry "
                    "(or set [security].serve_web_console=false)",
                    file=sys.stderr,
                )
                return 2
            # (a) The console is ON BY DEFAULT (ADR 0143) but the optional wheel is absent — SOFT-DEGRADE
            # to a JSON-only serve with a WARNING rather than refusing every serve: a default-on posture
            # must not turn a package-layout choice into a start failure. Flip serve_ui off IN PLACE so
            # the JSON-only decision threads through the exposure gates below + create_managed_app
            # (mirrors the existing in-place [security]/egress/retention flips).
            print(
                "warning: the web console is on by default (ADR 0143) but the package "
                "'messagefoundry-webconsole' is not installed — serving the JSON API only. Install it "
                "for the /ui console, or set [security].serve_web_console=false to silence this warning.",
                file=sys.stderr,
            )
            settings.api.serve_ui = False

    # ADR 0143: the console defaults ON for LOCAL loopback binds — the local-operator convenience. When
    # the instance is EXPOSED off-box it stays OPT-IN: an off-box browser console is a stricter surface
    # that needs TLS + an explicit public origin, so it must be requested deliberately. "Exposed" here is
    # a non-loopback host, a declared TLS-terminating proxy (tls_terminated_upstream), or a set
    # public_origin — every case that would otherwise enter the /ui exposure ladder below. A DEFAULT-on
    # (not explicitly requested) console on an exposed bind therefore AUTO-DEGRADES to JSON-only here —
    # default-on must not turn a previously-working exposed JSON serve into a start failure — rather than
    # tripping those refusals. An EXPLICIT [security].serve_web_console=true is left ON and still hits the
    # ladder (unchanged). Flipped in place so the JSON-only decision threads through the gates below +
    # create_managed_app (mirrors the package-absent soft-degrade above and the existing in-place flips).
    console_exposed = (
        not settings.api.is_loopback
        or settings.api.tls_terminated_upstream
        or bool(settings.api.public_origin)
    )
    if settings.api.serve_ui and not settings.api.serve_ui_explicit and console_exposed:
        print(
            "warning: the web console is on by default (ADR 0143) for LOCAL loopback binds only; this "
            "instance is exposed off-box (a non-loopback host, a declared TLS-terminating proxy, or "
            "[security].web_console_public_address is set), so the console is NOT served. To serve the "
            "console off-box set [security].serve_web_console=true with TLS + "
            "[security].web_console_public_address (see docs/security/OFF-LOOPBACK-DEPLOYMENT.md).",
            file=sys.stderr,
        )
        settings.api.serve_ui = False

    # The browser ops dashboard ([api].serve_ui, ADR 0065) is a STRICTER surface than the JSON API: it
    # puts an HttpOnly session cookie and PHI-rendering HTML on the wire. An off-loopback /ui bind
    # therefore REQUIRES exposure_protected (in-process TLS or a declared upstream terminator) and is
    # refused even under --allow-insecure-bind (that dev override covers only the JSON API's cleartext
    # risk, never the browser surface). The loopback default never trips this.
    if (
        settings.api.serve_ui
        and not settings.api.is_loopback
        and not settings.api.exposure_protected
    ):
        print(
            "error: refusing to serve the browser ops dashboard ([api].serve_ui) on non-loopback host "
            f"{settings.api.host!r} without TLS. The /ui surface requires in-process TLS "
            "([api].tls_cert_file) or a declared TLS-terminating proxy ([api].tls_terminated_upstream "
            "+ trusted_proxies); --allow-insecure-bind does not cover it. Bind [api].host to a loopback "
            "address for local-only access, or configure TLS.",
            file=sys.stderr,
        )
        return 2

    # --- L5b off-loopback browser-exposure ladder (ADR 0068 §8) — EXTENDS the gates above, never
    # weakens them. Ordered refusals first, then warnings, then advisories.
    if settings.api.serve_ui and settings.api.tls_terminated_upstream:  # noqa: SIM102
        if not settings.api.public_origin:
            # Deliberate upgrade-time behavior change (owner-confirmed, ADR 0068 §7): with a
            # DECLARED reverse proxy the request Host header is client-forwardable — without the
            # exact origin, the /ui same-origin CSRF check degrades to Host comparison and the
            # WebAuthn rp_id would have anchored to attacker-influenceable input.
            # Names the OPERATOR-FACING key (BACKLOG #1026), for the same reason as the ASVS 12.1.1
            # refusal further down: ADR 0118 relocated `[api].public_origin` to
            # `[security].web_console_public_address` and REJECTS the old spelling as file or env
            # input, so an instruction to set it fails at load.
            print(
                "error: serving the web console behind a declared TLS terminator requires an "
                'external origin (e.g. "https://mefor.example.org") — behind a declared '
                "reverse proxy the Host header is client-forwardable, so the browser console's "
                "same-origin CSRF check and the WebAuthn passkey origin binding need the exact "
                "external origin. Set [security].web_console_public_address to the origin the "
                "browser uses. See docs/security/OFF-LOOPBACK-DEPLOYMENT.md (ADR 0068).",
                file=sys.stderr,
            )
            return 2
    if (
        settings.api.serve_ui
        and settings.api.public_origin
        and settings.api.public_origin.startswith("http://")
        and (settings.api.tls_terminated_upstream or settings.api.tls_enabled)
    ):
        # An http:// public origin contradicts a declared TLS posture in EITHER termination mode
        # (settings deliberately admit http:// public_origin for the loopback dev flow only).
        print(
            "error: [api].public_origin is http:// while a TLS posture is declared "
            "([api].tls_terminated_upstream or [api].tls_cert_file) — the browser console would "
            "bind its origin checks and WebAuthn passkeys to a cleartext origin. Use the https:// "
            "external origin. See docs/security/OFF-LOOPBACK-DEPLOYMENT.md (ADR 0068).",
            file=sys.stderr,
        )
        return 2
    if settings.api.serve_ui and settings.api.public_origin and not settings.api.exposure_protected:
        # The undeclared-proxy heuristic (ADR 0068 §8): a set public_origin on an unprotected
        # instance is a strong signal of intended off-box exposure through an undeclared proxy —
        # the session cookie would ship without Secure and HSTS stays suppressed. (A truly
        # signal-less undeclared proxy is undetectable in-engine — runbook-only.)
        print(
            "warning: [api].public_origin is set but the proxy posture is undeclared "
            "(no [api].tls_cert_file, and no [api].tls_terminated_upstream + trusted_proxies) — "
            "until it is declared, the /ui session cookie ships WITHOUT Secure and HSTS is "
            "suppressed. See docs/security/OFF-LOOPBACK-DEPLOYMENT.md.",
            file=sys.stderr,
        )
    if settings.api.serve_ui and not settings.api.is_loopback and not settings.api.public_origin:
        # In-process-TLS off-loopback with no public_origin (survives the refusals above): the
        # CSRF check and WebAuthn RP derive from the request URL — legitimate (the browser
        # connects DIRECTLY to the engine), but origin-stability is on the operator, and WebAuthn
        # ceremonies fail closed until public_origin is set (ADR 0068 §7; owner kept warn-not-refuse).
        print(
            "warning: [api].serve_ui is bound off-loopback without [api].public_origin — the /ui "
            "origin checks use the request Host and WebAuthn passkeys are unavailable (fail-closed) "
            "until public_origin is set. See docs/security/OFF-LOOPBACK-DEPLOYMENT.md.",
            file=sys.stderr,
        )
    ui_exposed = settings.api.serve_ui and (
        not settings.api.is_loopback or settings.api.tls_terminated_upstream
    )
    if ui_exposed:
        # The ASVS 8.4.2 managed-admin-host / reverse-proxy-mTLS posture is deployment-delegated
        # BY DESIGN (ADR 0068 §10) — point the operator at the reference configs + runbook.
        print(
            "info: the browser ops console is exposed off-box — review the managed-admin-host / "
            "reverse-proxy-mTLS guidance in docs/security/OFF-LOOPBACK-DEPLOYMENT.md (ASVS 8.4.2).",
            file=sys.stderr,
        )
        if (
            settings.auth.enabled
            and not settings.auth.admin_new_ip_step_up
            and data_class is DataClass.PHI
        ):
            # Advisory only — the default deliberately stays False (a flip would churn NAT'd
            # hospital networks; flag_new_client_ip stays advisory-only, preserving the ASVS
            # 8.1.3/8.1.4/8.2.4 N/A keystone). Mirrors the require_mfa advisory pattern.
            print(
                "warning: the browser console is exposed on a PHI instance with "
                "[auth].admin_new_ip_step_up off — enabling it forces a step-up when an admin "
                "session appears from a new client address (recommended at exposure).",
                file=sys.stderr,
            )

    # THE SINGLE DEFINITION OF "this instance is exposed" (BACKLOG #326) is derived above, before the
    # auth-off arm (BACKLOG #1013) that also consumes it, from two fields no earlier arm reassigns —
    # `is_loopback` and `tls_terminated_upstream` are read straight off the loaded config and are never
    # mutated in place, unlike `serve_ui`.
    #
    # WHY IT CANNOT READ `settings.api.serve_ui`: that field is flipped to False IN PLACE twice above —
    # the ADR 0143 soft-degrade when the console wheel is absent, and the ADR 0143 auto-degrade when a
    # default-on console meets an exposed bind. By this line it answers "is /ui mounted?", a PRESENTATION
    # fact, not "is the admin interface reachable from the network?", the EXPOSURE fact these gates need.
    # Keying an exposure gate on it let one boot call the same instance exposed for ASVS 11.7.1 (the
    # ADR 0152 arm below, which already used this predicate) and NOT exposed for ASVS 6.3.3 (the MFA arm
    # here) — so the refusal was unreachable on the runbook's RECOMMENDED loopback-behind-proxy topology.
    # The admin surface that authenticates with a single factor is the JSON API, which is served whether
    # or not the browser console is.
    #
    # Deliberately NARROW: a set `public_origin` with no declared proxy is NOT exposure here. Widening
    # it that far would convert a heuristic into a hard refusal, and the signal is genuinely weaker —
    # nothing has been declared, so the engine is guessing. The residual that leaves is warned about
    # EXPLICITLY, by the arm below the MFA gate. It must not lean on the ADR 0068 §8 undeclared-proxy
    # warning at the top of this ladder: that one is about the /ui cookie and HSTS, it says nothing
    # about admin factors, and it is gated on `serve_ui`, which the ADR 0143 auto-degrade has already
    # cleared for exactly this input — a DEFAULT-on console plus a set `public_origin` — so on the
    # commonest shape of this posture it does not print at all. Citing it as the compensating control
    # would have rested that control on a premise measurement contradicts.

    # MFA-at-exposure posture (sec-mfa-on; WP-14, ASVS 6.3.3): an off-loopback bind serving local
    # accounts puts admin authentication on the network, where a single password factor is far weaker.
    # [security].require_mfa adds the native TOTP second factor for the Administrator role; with it off the
    # admin interface is single-factor over the wire. Since BACKLOG #187 require_mfa DEFAULTS ON (even
    # on loopback), so this gate no longer catches the common "forgot to enable it" case — it now fires
    # only when an operator has EXPLICITLY opted out ([security].require_mfa=false) AND exposed the admin
    # interface. That explicit opt-out at exposure is exactly the posture to refuse/warn on. Mirror the
    # keyless-store / open-egress posture: refuse on a production PHI instance (the prod fail-closed
    # analogue), warn on a non-production PHI instance, stay quiet on a synthetic instance. Reached only
    # for an otherwise-permitted exposed bind (the TLS gate above ran first); the loopback default (now
    # require_mfa on) never trips it. AD/Kerberos MFA is delegated to the directory, so require_mfa only
    # gates LOCAL Administrator accounts (the bootstrap admin is one) — it is safe to leave on even on
    # an AD-only deployment.
    #
    # L5b review fix (ADR 0068 §8), corrected by BACKLOG #326: the gate keys on the same EXPOSURE signal
    # as the ladder above, not the bind host alone — the runbook's RECOMMENDED topology (loopback bind
    # BEHIND a declared proxy) puts the admin interface on the network exactly as an off-loopback bind
    # does, so a production PHI instance reached through a declared proxy with require_mfa off is refused
    # identically (extend-never-weaken). It reads `instance_exposed`, NOT the mutated console flag: the
    # single-factor admin surface is the JSON API, so whether /ui happens to be mounted is irrelevant.
    admin_exposed = instance_exposed
    if admin_exposed and settings.auth.enabled and not settings.auth.require_mfa:
        exposure_desc = (
            f"API bound to non-loopback host {settings.api.host!r}"
            if not settings.api.is_loopback
            else "admin interface reached through a declared reverse proxy "
            "([api].tls_terminated_upstream)"
        )
        if data_class is DataClass.PHI:
            if enforcing and not settings.security.allow_single_factor_admin_when_exposed:
                print(
                    f"error: {exposure_desc} on a {'production ' if production else ''}PHI "
                    f"instance ({env_name!r}) with [security].require_mfa off; refusing to start — the "
                    "Administrator role would authenticate with a single factor over the network. "
                    "Enable native TOTP MFA with [security].require_mfa=true (WP-14) before exposing the "
                    "API (safe even on an AD-only deployment — it gates only local Administrator "
                    "accounts); or set [security].allow_single_factor_admin_when_exposed=true to "
                    "deliberately permit single-factor admin at exposure (audited).",
                    file=sys.stderr,
                )
                return 2
            if enforcing:
                # ADR 0140: single-factor admin at exposure under strict enforcement was explicitly
                # acknowledged — emit a loud WARNING-level AUDIT line, then fall through to the shared
                # warn posture (permitted-but-audited, never silent).
                logging.getLogger(__name__).warning(
                    "AUDIT: %s on a %sPHI instance (environment %r) with [security].require_mfa "
                    "off, permitted because [security].allow_single_factor_admin_when_exposed=true — the "
                    "Administrator role is single-factor over the network.",
                    exposure_desc,
                    "production " if production else "",
                    env_name,
                )
            print(
                f"warning: {exposure_desc} in a PHI-carrying "
                f"environment ({env_name!r}) with [security].require_mfa off — the Administrator role is "
                "single-factor over the network. Enable [security].require_mfa=true (WP-14 native TOTP) "
                "before exposure.",
                file=sys.stderr,
            )

    # --- the UNDECLARED-proxy residual of the gate above, made visible (BACKLOG #326) ---------------
    # `instance_exposed` is deliberately narrow, so a set `public_origin` on a loopback bind with no
    # declared terminator does not refuse. That is the right call — nothing was declared, so the engine
    # is inferring — but it must not be SILENT, and until this arm existed it was: the only other thing
    # that could have spoken is the ADR 0068 §8 undeclared-proxy warning above, which is scoped to the
    # /ui cookie and HSTS and is suppressed outright when the ADR 0143 auto-degrade clears `serve_ui`
    # (which that same `public_origin` triggers). So the documented compensating control did not exist
    # on the commonest shape of this posture. WARN, never refuse: the ruling that tightened the gate
    # above was about a DECLARED proxy, and promoting an inference to a refusal is a different decision.
    # Scoped as tightly as the refusal is: PHI only, and only where require_mfa was EXPLICITLY opted out.
    if (
        not instance_exposed
        and settings.api.public_origin
        and settings.auth.enabled
        and not settings.auth.require_mfa
        and data_class is DataClass.PHI
    ):
        print(
            "warning: [api].public_origin is set with no declared TLS terminator on a PHI instance "
            f"({env_name!r}) with [security].require_mfa off — if that origin is served by an "
            "UNDECLARED reverse proxy, the Administrator role is single-factor over the network and "
            "the MFA-at-exposure refusal cannot see it (an undeclared proxy is not, and cannot be, an "
            "exposure signal the engine can verify). Declare it with [api].tls_terminated_upstream + "
            "trusted_proxies, or set [security].require_mfa=true.",
            file=sys.stderr,
        )

    # --- #189 dual-control-at-exposure posture (ASVS 2.3.5) -----------------------------------------
    # High-value runtime actions (dead-letter replay, connection purge) complete on a SINGLE caller's
    # authority unless [approvals].enabled turns on maker-checker (a distinct second user holding
    # approvals:approve releases the request). On an off-box admin surface that concentration is the
    # weakest link: one compromised/coerced admin session can replay full-PHI dead-letters or purge a
    # connection with no second sign-off. Key on the SAME exposure signal as the MFA gate above
    # (admin_exposed = instance_exposed = off-loopback bind OR a declared TLS-terminating proxy), so a
    # plain loopback default is byte-identical (admin_exposed is False → this never trips, BACKLOG #326
    # preserved that property deliberately) and a synthetic instance stays quiet
    # (gated on data_class is PHI). This is WARN-ONLY by design (the reviewed default): dual-control is
    # off-by-default precisely so a genuine single-operator hospital deployment is never wedged, so
    # refusing to start on its absence would break a supported topology.
    #
    # OWNER FORK (TODO, ADR/PR body): whether a PRODUCTION PHI exposed instance should REFUSE (mirror
    # the sec-mfa-on / retention / notifications prod-refuse ladder above, returning 2) instead of
    # warning is an owner decision — kept WARN-only here until adjudicated; flip by adding the
    # `if production: ... return 2` arm and an audited [approvals].allow_single_control override.
    if admin_exposed and not settings.approvals.enabled and data_class is DataClass.PHI:
        approvals_exposure_desc = (
            f"API bound to non-loopback host {settings.api.host!r}"
            if not settings.api.is_loopback
            else "admin interface reached through a declared reverse proxy "
            "([api].tls_terminated_upstream)"
        )
        print(
            f"warning: {approvals_exposure_desc} in a PHI-carrying environment ({env_name!r}) with "
            "[approvals].enabled off — high-value actions (dead_letter_replay, connection_purge) each "
            "complete on a single caller's authority with no second sign-off (ASVS 2.3.5). Enable "
            "dual-control with [approvals].enabled=true so a distinct approver (approvals:approve) must "
            "release them before exposure.",
            file=sys.stderr,
        )

    # --- startup TLS-floor probe of the declared front door (ASVS 12.1.1) ---------------------------
    # ORDER MATTERS: this sits AFTER the config-only exposure refusals (auth-off, /ui exposure,
    # MFA-at-exposure) deliberately. It is the only gate that makes NETWORK CALLS, and pre-empting
    # a config refusal with three handshake round-trips means an operator fixes the TLS floor,
    # restarts, and only then learns MFA was off — two trips for one boot. Cheap refusals first.
    #
    # The banner above is not decoration: test_startup_dual_control_arm_is_documented_as_warn_only
    # slices the #189 approvals arm out of this file and asserts it contains no `return 2`. Without a
    # banner here that slice ran straight through into this block and attributed THIS refusal to that
    # arm. The guard has since been made to slice the arm by its own indentation, but every section in
    # this ladder carries a banner and a new one must too.
    #
    # `proxy_tls_min_version` is an attestation: the operator types "1.2" and nothing checks it.
    # Making an unverified declaration mandatory does not close the requirement, so the gate above
    # is not the cell — this is. The probe dials `public_origin` and offers TLS 1.0 and 1.1; a
    # SUCCESSFUL handshake is the failure, because it proves the front door accepts a protocol
    # NIST SP 800-52r2 withdrew. It then asks what a default-capability client actually negotiates,
    # which measures the proxy's PREFERENCE rather than merely its support.
    #
    # This is also what retires the loopback carve-out above. That arm warns because "the engine
    # cannot distinguish loopback-behind-a-declared-proxy from loopback-and-genuinely-unexposed
    # beyond the declaration itself" — true of a declaration, false of a measurement. A reachable
    # front door that speaks TLS 1.0 is a fact, on loopback or not.
    #
    # REQUIRE `public_origin` IN THIS POSTURE, REGARDLESS OF `serve_ui` (BACKLOG #1026, owner-ruled
    # 2026-08-14). There IS a refusal for an unset `public_origin`, and it is gated on the console:
    # `if settings.api.serve_ui and settings.api.tls_terminated_upstream`. With `serve_ui` false
    # nothing required it, so a PHI instance behind a declared terminator under `enforce` could start
    # with it unset and the probe below simply never ran -- with nothing reporting the skip.
    #
    # That is the failure this same block already refuses twice, one level down. It returns 2 when the
    # probe's MECHANISM is missing, because "a check that degrades to a no-op when its mechanism
    # disappears reports success forever afterwards", and it refuses on unreachable because "a gate
    # that is trivially defeated is not a gate". Leaving `public_origin` unset WAS trivially defeating
    # this gate, and the outcome WAS a check that reports success forever. The principle was stated
    # twice here and violated one level up.
    #
    # This refuses a posture that starts today. Per CLAUDE.md section 0 there are zero deployments, so
    # that costs nothing now and will never be cheaper to add -- and the owner was told the cost
    # rather than it being hidden. It is NOT the reason the answer is (a): the reason is that this is
    # the only end where the control measures its own posture instead of measuring whether someone
    # happened to configure an unrelated console setting.
    if (
        settings.api.tls_terminated_upstream
        and data_class is DataClass.PHI
        and enforcing
        and not settings.api.public_origin
    ):
        # THE REMEDIATION NAMES THE KEY THE LOADER ACCEPTS, NOT THE FIELD THIS CODE READS
        # (BACKLOG #1026). `[api].public_origin` is the INTERNAL field; ADR 0118 relocated the
        # operator-facing key to `[security].web_console_public_address` and REJECTS the old
        # spelling as file or env input (`_RELOCATED_TO_SECURITY` in config/settings.py). So the
        # refusal this block shipped with handed an operator a remediation that fails at load: do
        # what it says and the next start dies on "unrecognized config key(s)".
        #
        # A hard refusal that names an unusable fix is worse than one that names none -- it costs a
        # restart cycle to discover, and it reads as authoritative because it is coming from the
        # gate itself. tests/test_api_tls.py pins the remediation string AGAINST the relocation map
        # so the two cannot drift apart again.
        print(
            f"error: refusing to serve on a PHI instance ({env_name!r}) behind a declared TLS "
            "terminator under `enforce` without an external origin — the ASVS 12.1.1 TLS-floor "
            "probe dials that origin, so leaving it unset silently disables the check rather than "
            "failing it. Set [security].web_console_public_address to the origin the browser uses "
            '(e.g. "https://mefor.example.org"). See docs/security/OFF-LOOPBACK-DEPLOYMENT.md.',
            file=sys.stderr,
        )
        return 2

    # Scope is the posture the requirement is about: a declared terminator, PHI, and `enforce`. Every
    # other posture never reaches here and is byte-identical.
    #
    # `public_origin` appears as a fourth condition and is NOT a fourth scope narrowing: the refusal
    # directly above guarantees it is set for exactly this posture, so the two agree by construction
    # rather than by coincidence. It is kept as a belt-and-braces and as the type narrowing the probe
    # call needs. Before #1026 this comment named three conditions while the gate had four, and the
    # undocumented fourth was the whole defect -- a reader concluded the probe runs whenever a PHI
    # instance sits behind a declared terminator under `enforce`, and it did not.
    if (
        settings.api.tls_terminated_upstream
        and data_class is DataClass.PHI
        and enforcing
        and settings.api.public_origin
    ):
        from messagefoundry.config.tls_probe import TlsProbeUnavailable, probe_tls_floor

        try:
            probe = probe_tls_floor(settings.api.public_origin)
        except TlsProbeUnavailable as exc:
            # NOT a skip. See tls_probe's module docstring: a check that degrades to a no-op when
            # its mechanism disappears reports success forever afterwards.
            print(f"error: the ASVS 12.1.1 TLS-floor probe cannot run: {exc}", file=sys.stderr)
            return 2
        if not probe.ok:
            # Unreachable refuses too, and the reason is start-ordering: if "unreachable" merely
            # warned, an operator could always bring the engine up before the proxy and the check
            # would never run — a gate that is trivially defeated is not a gate. The cost is real
            # and is stated in the message rather than left for an assessor to find.
            print(
                f"error: refusing to serve on a PHI instance ({env_name!r}) behind a declared "
                f"upstream TLS terminator whose TLS floor does not verify — {probe.describe()}. "
                "The browser hop is the operator's proxy, so the engine measures it at startup "
                "rather than trusting [api].proxy_tls_min_version (ASVS 12.1.1). Required: the "
                "front door must refuse TLS 1.0 and 1.1 and negotiate TLS 1.3 with a "
                "default-capability client. NOTE: this makes startup depend on the proxy being "
                "reachable — deliberate, because warning on unreachable is defeated by start "
                "ordering. See docs/security/OFF-LOOPBACK-DEPLOYMENT.md.",
                file=sys.stderr,
            )
            return 2
        print(
            f"info: TLS-floor probe passed — {probe.describe()} (ASVS 12.1.1).",
            file=sys.stderr,
        )

    # --- #186(a) secure-by-default data retention (ASVS 14.2.4) --------------------------------------
    # RetentionSettings defaults every window to 0 (keep-forever) and RetentionRunner then purges
    # NOTHING, so a PHI instance accumulates PHI bodies indefinitely. Both PHI-body windows must be
    # bounded: messages_days (inbound bodies) AND dead_letter_days (dead-lettered outbound bodies stay
    # replayable, i.e. full PHI, until their own window purges them). Mirror the open-egress / MFA-at-
    # exposure posture: a PRODUCTION PHI instance with EITHER window unbounded REFUSES to start; a
    # non-production PHI instance (staging / declared-PHI loopback) AUTO-BOUNDS each UNSET window to 30
    # days (WP243/#243, secure-by-default) and only WARNS on a window explicitly left unbounded; a
    # synthetic/dev instance is byte-identical (starts with windows=0). The explicit, audited opt-out is
    # [security].allow_keeping_phi_indefinitely=true, which downgrades the production refusal to a loud audited
    # warning (and suppresses the non-production auto-bound). Placed after the exposure gates so an
    # exposed instance's cleartext/MFA refusals surface first.
    if data_class is DataClass.PHI:
        # WP243 (#243, ASVS 14.2.7): a NON-PRODUCTION PHI instance auto-bounds each UNSET PHI-body
        # retention window to 30 days (secure-by-default), mirroring the egress deny_by_default flip
        # above. PRODUCTION PHI is deliberately EXCLUDED so the #186(a) refuse-to-start gate below is
        # unchanged (a silent auto-bound there would mask the deliberate fail-closed refusal). Only an
        # UNSET window is defaulted (model_fields_set), so an explicit value — including an explicit 0 —
        # is respected; the audited keep-forever opt-out is [security].allow_keeping_phi_indefinitely=true.
        # settings.retention is the same object later passed to create_managed_app, so the in-place
        # default threads through to the RetentionRunner (no forbidden-file edit).
        # messages_days moved to [security].delete_message_bodies_after_days (ADR 0118);
        # dead_letter_days stays [retention] plumbing — label each window at its real home.
        # ASVS 14.2.7: the tier list is GENERATED from the classification in
        # config/retention_classification.py, which a drift test holds equal — in both directions — to
        # docs/PHI.md §2's Retention column. It used to be a two-element literal here, and the cell
        # broke once because a new PHI tier landed and nobody widened it. A wider literal with no
        # binding to the classification is the same defect with more characters.
        from messagefoundry.config.retention_classification import (
            MIN_PHI_RETENTION_WINDOWS,
            PHI_RETENTION_WINDOWS,
            auto_bounded_windows,
        )
        from messagefoundry.config.retention_classification import (
            unbounded_windows as _unbounded_windows,
        )

        # A FLOOR, not an emptiness check. `if not PHI_RETENTION_WINDOWS` passes for a one-element
        # tuple, so a bad merge dropping most entries would leave this gate checking one window while
        # reporting success — the precise shape of failure this whole change set exists to remove.
        if len(PHI_RETENTION_WINDOWS) < MIN_PHI_RETENTION_WINDOWS:
            print(
                f"error: the PHI retention classification has shrunk to "
                f"{len(PHI_RETENTION_WINDOWS)} windows (floor {MIN_PHI_RETENTION_WINDOWS}); refusing "
                "to start rather than gate on a partial classification. This is a build defect, not a "
                "configuration one — see messagefoundry/config/retention_classification.py.",
                file=sys.stderr,
            )
            return 2

        # AUTO-BOUND. Owner ruling 2026-07-30: the three PHI-BODY windows default to 30 days when
        # UNSET, on BOTH dials — previously this ran only when `not enforcing`, so on the shipped
        # `enforce` posture an unset window took the refusal below instead of a default.
        #
        # THE SAFETY TRADE IS DELIBERATE AND WORTH STATING: a production PHI instance with an unset
        # window used to REFUSE TO START, which forced an operator to choose a number. It now starts
        # with 30. What survives is the fail-closed path for an EXPLICIT 0 — choosing keep-forever is
        # still refused unless the audited opt-out is set. So "unbounded by accident" is still
        # prevented; "unbounded by inattention" becomes "30 days by inattention".
        #
        # The warn-only windows are NOT auto-bounded, and that is also a ruling rather than an
        # omission: `purge_state` and `purge_search_presets` key on timestamps that only move on a
        # WRITE, so silently bounding them deletes live operational data a Handler is still reading.
        if not settings.retention.allow_unbounded_phi:
            defaulted = [
                w
                for w in auto_bounded_windows()
                if w.field not in getattr(settings, w.reads_from.strip("[]")).model_fields_set
            ]
            for window in defaulted:
                setattr(
                    getattr(settings, window.reads_from.strip("[]")),
                    window.field,
                    window.auto_bound_days,
                )
            if defaulted:
                print(
                    f"info: {', '.join(w.setting for w in defaulted)} defaulted ON (30 days) for a PHI "
                    f"instance ({env_name!r}) — these PHI tiers are now bounded at rest "
                    "(secure-by-default, ASVS 14.2.7). Set an explicit window to override, or "
                    "[security].allow_keeping_phi_indefinitely=true to retain indefinitely.",
                    file=sys.stderr,
                )

        # REFUSE / WARN. `unbounded_windows` skips the tiers where 0 does not mean unbounded
        # (`connection_event_retention_hours` INHERITS the body window; `uploads_retention_days` has a
        # ge=1 floor so 0 is unrepresentable) and those whose `requires_setting` is unmet — with no
        # [logging].log_dir there is nothing for the app-log sweep to sweep.
        still_unbounded = _unbounded_windows(settings)
        refusable = [w for w in still_unbounded if w.auto_bound_days is not None]
        warn_only = [w for w in still_unbounded if w.auto_bound_days is None]

        if warn_only:
            # Classified and warned, never refused. Naming the tier AND its protection level is the
            # point: an operator who sees "PL-1" knows a full body is involved.
            print(
                "warning: these classified PHI tiers have no retention window on a PHI instance "
                f"({env_name!r}) and will accumulate without bound: "
                + ", ".join(f"{w.setting} ({w.level})" for w in warn_only)
                + ". They are deliberately NOT defaulted — each keys on a timestamp that only moves on "
                "a write, so a silent default would delete data still in use (ASVS 14.2.7).",
                file=sys.stderr,
            )

        if refusable:
            windows_desc = ", ".join(w.setting for w in refusable)
            if not settings.retention.allow_unbounded_phi:
                if enforcing:
                    print(
                        f"error: a data-retention window is explicitly disabled for {windows_desc} on "
                        f"a {'production ' if production else ''}PHI instance ({env_name!r}); refusing "
                        "to start — PHI message bodies would be retained indefinitely (unbounded PHI "
                        "at rest, ASVS 14.2.4/14.2.7). Set the window(s) to a positive number of days "
                        "(e.g. 30); or, to deliberately retain forever, set "
                        "[security].allow_keeping_phi_indefinitely=true (audited).",
                        file=sys.stderr,
                    )
                    return 2
                print(
                    f"warning: no data-retention window is configured for {windows_desc} in a "
                    f"PHI-carrying environment ({env_name!r}) — PHI message bodies accumulate without "
                    "bound. Set the window(s) to bound PHI at rest (ASVS 14.2.4).",
                    file=sys.stderr,
                )
            elif enforcing:
                # Explicit, audited override: unbounded PHI retention under strict enforcement.
                logging.getLogger(__name__).warning(
                    "AUDIT: starting a %sPHI instance (environment %r) with unbounded data "
                    "retention ([security].allow_keeping_phi_indefinitely=true; %s = 0) — PHI message "
                    "bodies are retained INDEFINITELY (retention opt-out override).",
                    "production " if production else "",
                    env_name,
                    windows_desc,
                )
                print(
                    f"warning: [security].allow_keeping_phi_indefinitely=true — a "
                    f"{'production ' if production else ''}PHI instance "
                    f"({env_name!r}) retains PHI message bodies indefinitely ({windows_desc} unset). "
                    "Configure a window to bound PHI at rest.",
                    file=sys.stderr,
                )

    # --- #188 out-of-band security notifications effective by default (ASVS 6.3.5/6.3.7) -------------
    # The per-user security-event push (lockout, password/email/roles change, new-IP admin action)
    # rides the [alerts] SMTP transport AND the [auth].notify_security_events kill-switch — api/app.py
    # builds the notifier only when BOTH are on, so with either off it is silently absent (which the
    # defaults and the off-loopback runbook never set). A PHI instance with no effective channel REFUSES
    # to start; synthetic/dev is byte-identical. The refuse/warn split is [security].enforcement, NOT the
    # deployment tier — the branch below reads `enforcing`, and `enforce` is the shipped default on dev
    # and staging as much as on prod, so `serve --env staging` on stock defaults with no [alerts] SMTP is
    # REFUSED, not warned. It downgrades to a warning only under enforcement = warn. This gate is why
    # [alerts] is not optional on a stock instance. The explicit, audited opt-out is
    # [alerts].security_notifications_required=false (accept the pull-only /me/security-events feed in
    # writing). "Effective channel" == notify_security_events on + SMTP host + sender (parity with the
    # app.py notifier wiring). Skipped when auth is disabled (no accounts to notify — a non-loopback
    # no-auth serve is already refused elsewhere).
    if data_class is DataClass.PHI and settings.auth.enabled:
        security_channel_ready = bool(
            settings.auth.notify_security_events
            and settings.alerts.email_smtp_host
            and settings.alerts.email_from
        )
        if not security_channel_ready:
            if settings.alerts.security_notifications_required:
                if enforcing:
                    print(
                        "error: no out-of-band security-notification channel is configured on a "
                        f"{'production ' if production else ''}PHI instance ({env_name!r}); refusing to "
                        "start — account-security events (lockout, password/roles change, new-IP admin "
                        "action) would have no push channel, only the pull-only /me/security-events feed "
                        "(ASVS 6.3.5/6.3.7). Configure the [alerts] SMTP transport (email_smtp_host + "
                        'email_from; add email_to as well if any [[alerts.rules]] routes to "email" — '
                        "the alert email transport requires all three) and keep "
                        "[auth].notify_security_events on; or, to rely on the "
                        "pull-only feed, set [alerts].security_notifications_required=false (audited).",
                        file=sys.stderr,
                    )
                    return 2
                print(
                    "warning: no out-of-band security-notification channel is configured in a "
                    f"PHI-carrying environment ({env_name!r}) — account-security events have no push "
                    "channel, only the pull-only /me/security-events feed. Configure the [alerts] SMTP "
                    "transport (email_smtp_host + email_from) with [auth].notify_security_events on "
                    "(ASVS 6.3.5/6.3.7).",
                    file=sys.stderr,
                )
            elif enforcing:
                logging.getLogger(__name__).warning(
                    "AUDIT: starting a %sPHI instance (environment %r) with no security-"
                    "notification channel ([alerts].security_notifications_required=false) — "
                    "account-security events are recorded only in the pull-only /me/security-events "
                    "feed (out-of-band-notification opt-out override).",
                    "production " if production else "",
                    env_name,
                )
                print(
                    f"warning: [alerts].security_notifications_required=false — a "
                    f"{'production ' if production else ''}PHI "
                    f"instance ({env_name!r}) has no out-of-band security-event push (only the "
                    "pull-only /me/security-events feed). Configure [alerts] SMTP + "
                    "[auth].notify_security_events to enable it.",
                    file=sys.stderr,
                )

    # --- #323 layer 3: the alerts / security-event SMTP hop must AUTHENTICATE the relay -------------
    # The [alerts] SMTP transport carries operator alert bodies and every per-user security-event email
    # (lockout, password/email/roles change, new-IP admin action) — and the SMTP AUTH password. Before
    # #323 that hop called starttls() with NO context, so smtplib's fallback (ssl._create_stdlib_context,
    # which IS _create_unverified_context) accepted ANY certificate: encrypted, unauthenticated, and an
    # on-path attacker read all of it. The connectors (EMAIL/DIRECT, layers 1-2) key their refusal on the
    # CLAMPED weakened_tls_escape_permitted_here(), but that mechanism is INERT here — this notifier is
    # built in the API lifespan, outside build_check_registry's active_hop_posture scope, so
    # current_hop_posture() is None and the clamp degrades to the unclamped escape. Hence an explicit
    # acknowledgment switch at this gate instead, in the shape of the keyless-PHI second ack (ADR 0140).
    #
    # IT COVERS BOTH UNAUTHENTICATED SHAPES, DELIBERATELY. email_use_tls=false (no TLS at all) is
    # strictly worse than email_tls_verify=false (TLS that authenticates nothing), and it was previously
    # ungated. A gate that refused only the second would hand an operator a bypass that lands them on
    # the WORSE posture — so the condition is "this hop does not authenticate the relay", which is true
    # of both. Strictly ADDS refusals (ADR 0092 decision 5); byte-identical on the shipped defaults,
    # which verify.
    #
    # Gated on a CONFIGURED transport: with no email_smtp_host/email_from there is no hop to protect,
    # and the #188 gate above already owns the "no channel at all" case.
    if (
        data_class is DataClass.PHI
        and settings.alerts.email_smtp_host
        and settings.alerts.email_from
    ):
        if not settings.alerts.email_use_tls:
            hop_desc = "[alerts].email_use_tls=false (the SMTP hop is CLEARTEXT)"
        elif not settings.alerts.email_tls_verify:
            hop_desc = "[alerts].email_tls_verify=false (the SMTP hop verifies no certificate)"
        else:
            hop_desc = ""
        if hop_desc:
            if enforcing and not settings.security.allow_unverified_alert_smtp_tls:
                print(
                    f"error: {hop_desc} on a {'production ' if production else ''}PHI instance "
                    f"({env_name!r}); refusing to start — operator alert bodies, every per-user "
                    "security-event email, and the SMTP AUTH password would cross a hop that does not "
                    "authenticate the relay, so an on-path attacker can read them. Remove the override "
                    "(the default verifies), or point [alerts].email_tls_ca_file / [tls].internal_ca_file "
                    "at the relay's CA; or set [security].allow_unverified_alert_smtp_tls=true to "
                    "deliberately accept an unauthenticated alert hop (audited).",
                    file=sys.stderr,
                )
                return 2
            if enforcing:
                # Explicitly acknowledged under strict enforcement — a loud WARNING-level AUDIT line
                # (captured by NSSM stdout/SIEM), then the shared warn posture below. Never silent.
                logging.getLogger(__name__).warning(
                    "AUDIT: starting a %sPHI instance (environment %r) with %s, permitted because "
                    "[security].allow_unverified_alert_smtp_tls=true — alert bodies, security-event "
                    "email and the SMTP AUTH credential cross an UNAUTHENTICATED hop "
                    "(alert-SMTP-TLS verification opt-out override).",
                    "production " if production else "",
                    env_name,
                    hop_desc,
                )
            print(
                f"warning: {hop_desc} in a PHI-carrying environment ({env_name!r}) — alert bodies, "
                "per-user security-event email and the SMTP AUTH password cross a hop that does not "
                "authenticate the relay (MITM-able). Remove the override, or trust the relay's CA via "
                "[alerts].email_tls_ca_file / [tls].internal_ca_file.",
                file=sys.stderr,
            )

    # --- ADR 0152 rung 2: in-USE PHI protection (ASVS 11.7.1) ------------------------------------
    # Placed LAST in the posture ladder on purpose (extend, never weaken): every more SPECIFIC
    # refusal — cleartext bind, revocation, Posture-B, /ui exposure, MFA-at-exposure, retention,
    # security notifications — must surface first. An operator who is missing three declarations
    # should be told about the concrete misconfiguration before the platform-property one, and a
    # gate that jumped the queue would silently change which error every existing exposed-PHI test
    # (and every existing exposed-PHI deployment) reports.
    # ASVS 3.7.3: the "you are leaving this site" interstitial. Two knobs can weaken it, and BOTH are
    # announced at start rather than discovered in a later assessment. Warn-only by design: neither is
    # a PHI-safety property and refusing on an operator's deliberate UX decision would be a
    # self-inflicted availability failure — the same reasoning as the read-out below.
    _ext_allow = list(settings.security.external_link_allowlist)
    if not settings.security.external_link_interstitial:
        print(
            "warning: [security].external_link_interstitial=false — the console will navigate "
            "OFF-SITE with no notification and no cancel. This is the ASVS 3.7.3 control; disabling "
            "it is a posture decision, not a convenience one.",
            file=sys.stderr,
        )
    elif _ext_allow:
        # Named individually, never counted. "3 destinations exempted" is the shape of message that
        # lets an entry nobody intended sit in a list for a year.
        print(
            "warning: [security].external_link_allowlist exempts "
            f"{', '.join(repr(d) for d in _ext_allow)} from the off-site interstitial (ASVS 3.7.3) — "
            "navigation to these destinations shows no notification and offers no cancel.",
            file=sys.stderr,
        )
    # NOT warned: an empty `organization_domains`. It is the STRICT position (every off-site
    # destination is interstitialed) and it is the shipped default, so a note here would print on
    # every stock start — `test_serve_loopback_emits_no_new_stderr` catches exactly that, and it is
    # right to. Start-time output is for a posture that is WEAKER than the default, not for the
    # default itself. The guidance that matters — declare your domains rather than reaching for the
    # allowlist escape — belongs in docs/CONFIGURATION.md, where it is, and not in every boot log.
    #
    # PHI is plaintext in CPython heap while it is being processed — an HL7 body is `str` end to end
    # by design, and every parse/transform step allocates a fresh immutable copy no application code
    # can reach or wipe. The only control that protects it there is HARDWARE memory encryption (AMD
    # SEV-SNP / Intel TDX), which is a property of the HOST, not of anything this engine configures.
    # The engine cannot verify it either: a CPU flag is emitted by the OS whose integrity the control
    # exists to protect against. So it takes the established unverifiable-property shape —
    # MEFOR_TLS_REVOCATION_ATTESTED (ADR 0078), the Posture-B proxy declarations above — and asks the
    # operator to DECLARE it ([security].memory_encryption_operator_declared).
    #
    # WARN BY DEFAULT; REFUSE ONLY ON AN OPT-IN. This is the load-bearing scoping decision and it is
    # not a softening — it is the only shape that does not hard-stop deployments that boot today:
    #   * ADR 0148 makes EVERY built-in environment name derive DataClass.PHI, `dev` included, so an
    #     exposed dev/test instance that declared nothing at all is a PHI instance by derivation;
    #   * "exposed" includes the loopback-behind-proxy topology OFF-LOOPBACK-DEPLOYMENT.md actually
    #     RECOMMENDS (it declares tls_terminated_upstream), which the Posture-B gate 400 lines above
    #     deliberately spares from its own refusal for exactly this reason;
    #   * on Windows — the primary deployment platform — the read-out is ALWAYS null, so no host can
    #     ever clear such a gate by being correctly configured.
    # A default refusal would therefore stop a working dev/staging/prod service from booting on
    # upgrade over a platform property nobody can satisfy on Windows. That is the outcome ADR 0151
    # avoided by scoping its companion refusal to its own opt-in ("only fire on the opt-in, so it
    # cannot break an existing deployment"). Same rule here: the warning is the default; the refusal
    # requires [security].require_memory_encryption_declaration = true, which nothing has set. The
    # ADR 0148 refuse/warn dial then applies on top of the opt-in, as it does everywhere else.
    #
    # Deliberately NOT mirrored in checks.py. That gate runs on a developer's machine / a CI runner
    # against a config repo, and it mirrors gates whose answer is derivable FROM THE CONFIG (the
    # unresolved posture, the backend/ordering pairing). This one is a property of the DEPLOYMENT
    # HOST — reading the build agent's /proc/cpuinfo would answer a question nobody asked and would
    # fail every commit made on a laptop.
    #
    # EXPOSURE KEYING IS A BLAST-RADIUS COMPROMISE, NOT A THREAT BOUNDARY — say so plainly, because
    # the earlier framing read as the latter. The threat hardware memory encryption addresses (host,
    # hypervisor, physical attacker) does not care whether any socket faces the network: a loopback
    # instance with an MLLP listener ingesting real HL7 holds exactly the same plaintext heap. It is
    # keyed on exposure because that keeps the new startup output off every deployment whose console
    # is closed, and the property is instead stated for EVERY instance on GET /security/posture
    # (memory_encryption_note, always populated), which is the surface ADR 0152 designates as the
    # evidence artifact and which an assessor reads without log access.
    #
    # THE READ-OUT DOES NOT SUBSTITUTE FOR THE DECLARATION. An earlier revision let a positive
    # read-out clear the gate on the ergonomic argument that a host reporting a confidential-guest
    # interface has plainly not overlooked the question. That made a signal the ADR calls
    # non-evidentiary the one input in this feature that could RELAX a control — a wrongly-positive
    # read-out (or a bind-mounted device node) discharged the requirement with no human declaring
    # anything. The read-out now only softens the MESSAGE. What remains true is the asymmetry the
    # contradiction branch rests on: nothing here refuses on a read-out, in either direction.
    #
    # `instance_exposed` is NOT re-derived here. It is defined ONCE, above the MFA-at-exposure gate, and
    # this arm shares that definition — the two must agree by construction. BACKLOG #326: a second copy
    # is exactly how the ASVS 11.7.1 arm and the ASVS 6.3.3 arm came to disagree about whether the same
    # boot was exposed.
    memory_declared = settings.security.memory_encryption_operator_declared
    memory_undeclared_at_exposure = (
        instance_exposed and data_class is DataClass.PHI and not memory_declared
    )
    # Read the platform ONLY when one of the two branches below will consume the answer. A stock
    # loopback/synthetic start must not pay for a read it discards — on Linux that is a
    # /proc/cpuinfo read (hundreds of KB on a large host) plus two device stats.
    if memory_undeclared_at_exposure or memory_declared:
        memory_readout = platform_memory_encryption_readout()
        if memory_undeclared_at_exposure:
            # State what was ACTUALLY measured. "This host reports no active memory encryption" is a
            # claim about a measurement that, on Windows, was never taken — the host reported NOTHING.
            readout_desc = (
                f"this host reports no active hardware memory encryption (capability="
                f"{memory_readout.capability}, active={memory_readout.active}, "
                f"source={memory_readout.source!r})"
                if memory_readout.active is False
                else f"this host's memory-encryption state could not be read at all "
                f"(source={memory_readout.source!r}) — on Windows it never can be"
                if memory_readout.active is None
                else f"this host does report an active confidential-guest interface "
                f"({memory_readout.mechanism}), which is a self-report and not a declaration"
            )
            # What is missing is the DECLARATION, not the protection: the engine cannot see the
            # protection at all. Never phrase the remedy so that a one-line TOML edit reads as having
            # supplied ASVS 11.7.1 — the disclaimer sentence is part of both strings for that reason.
            remedy = (
                "Run the engine as a confidential guest on a host that provides in-use data protection "
                "(AMD SEV-SNP / Intel TDX), and set "
                "[security].memory_encryption_operator_declared=true to record that you take "
                f"responsibility for that claim. {READOUT_DISCLAIMER} See "
                "docs/adr/0152-in-use-data-protection-for-phi-platform-memory-encryption-attestation"
                "-asvs-11-7-1.md."
            )
            if enforcing and settings.security.require_memory_encryption_declaration:
                print(
                    f"error: [security].require_memory_encryption_declaration=true, and this EXPOSED "
                    f"{'production ' if production else ''}PHI instance ({env_name!r}) has no "
                    "declaration of in-use data protection (ASVS 11.7.1) on record. PHI is plaintext in "
                    f"process memory while it is routed and transformed, and {readout_desc}. {remedy} "
                    "Unset [security].require_memory_encryption_declaration to accept the residual with "
                    "a warning instead.",
                    file=sys.stderr,
                )
                return 2
            print(
                f"warning: EXPOSED PHI instance ({env_name!r}) has no declaration of in-use data "
                "protection (ASVS 11.7.1) on record — PHI is plaintext in process memory while it is "
                f"routed and transformed, and {readout_desc}. {remedy}",
                file=sys.stderr,
            )
        if memory_declared and memory_readout.contradicts_declaration:
            # CONTRADICTION: the operator declared memory encryption and the platform positively says
            # otherwise. WARN, never refuse — a deliberate decision, not an oversight.
            #
            # The read-out is explicitly NOT evidence (that is the whole premise of ADR 0152), and it has
            # known false negatives: a SEV-SNP guest whose sev-guest driver is not loaded, or a container
            # that does not map the device node, reports inactive while memory genuinely is encrypted.
            # Refusing here would let an untrusted, known-fallible signal HALT A CLINICAL INTERFACE
            # ENGINE — a self-inflicted availability failure keyed on exactly the input we have already
            # declared unreliable. Nothing in this feature refuses on a read-out in EITHER direction, so
            # a wrong read-out can never change whether the engine starts.
            #
            # `contradicts_declaration` is tri-state and deliberately under-reports: it is None (silent)
            # unless the host advertises a mechanism that WOULD have a guest interface, so an AMD SME /
            # Intel TME host — memory-controller-wide encryption, the most literal reading of 11.7.1, and
            # a mechanism with no guest-visible activation signal at all — is never accused.
            #
            # "Loudly" is satisfied on a surface that outlives a startup line: the contradiction is also
            # a first-class field on GET /security/posture
            # (memory_encryption_readout_contradicts_declaration), which an assessor reads without log
            # access. It fires on ANY posture, exposed or not — the operator opted in by setting the
            # switch, so there is no byte-identity cost.
            print(
                "warning: [security].memory_encryption_operator_declared=true, but this platform "
                f"advertises {memory_readout.mechanism} and exposes no confidential-guest interface "
                f"(capability={memory_readout.capability}, source={memory_readout.source!r}). A "
                "declaration the platform contradicts is worse than no declaration. Legitimate causes: "
                "the guest driver (/dev/sev-guest, /dev/tdx_guest) is not loaded; a container that does "
                "not map the device node; an Azure confidential VM, whose paravisor hides the native "
                "interface. The other possibility is that the host is not the confidential-computing "
                "host you believe it is. This is NOT refused — the read-out is a self-report, not "
                "evidence, and must never halt the engine — but it is reported on GET /security/posture "
                "until it is resolved.",
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

    # ADR 0050 anchoring diagnostics. Emitted ONCE here at startup (NOT inside env_values(), which is
    # re-invoked on every reload), and they log resolved file PATHS only — never env() values or
    # bodies — so they are PHI-safe at INFO/WARNING. The one eager env_values() evaluation here is the
    # only place the empty-values (NSSM-silent-miss) state is observable; the provider re-reads later.
    # Guard it: a malformed/unreadable <env>.toml makes tomllib raise here (TOMLDecodeError/OSError) —
    # without this, that surfaced as a raw traceback (the lazy lifespan used to swallow it). Route it to
    # a clean error like every other serve gate. The value file is named (path only, PHI-safe).
    try:
        env_values_empty = not env_values()
    except (tomllib.TOMLDecodeError, ValueError, OSError) as exc:
        print(
            f"error: could not read environment values from {env_file}: {exc}",
            file=sys.stderr,
        )
        return 2
    # Drive the diagnostics off the MERGED root (effective_root), so a file/env-set [environments].base_dir
    # raises the AC-3 fail-loud + AC-4 cross-root WARNING exactly like an explicit --project-root (ADR §1
    # "the same merged value"); with neither source, effective_root is None and the AC-5 no-root path runs.
    rc = _emit_anchor_diagnostics(
        root=effective_root,
        cwd=cwd,
        config_dir=config_dir,
        env_file=env_file,
        service_config=service_config,
        store_path=settings.store.path,
        env_values_empty=env_values_empty,
    )
    if rc is not None:
        return rc

    # L3 multi-process sharding (ADR-pending; messagefoundry/pipeline/sharding.py): with --shard the
    # loaded graph is filtered to that shard's inbounds before the Engine is built (and re-filtered on
    # every reload), so this process owns a disjoint slice of intake. Without it, the whole graph runs
    # exactly as before. The supervisor spawns one such process per shard with its own --db and --port.
    registry_filter = None
    if args.shard is not None:
        from messagefoundry.config.wiring import Registry
        from messagefoundry.pipeline.sharding import filter_registry_for_shard

        # ADR 0073: engine sharding and [cluster] active-passive are mutually exclusive, fail-closed.
        # The cluster leadership lease is store-wide, so leadership would transfer ACROSS shard ids —
        # and a promoted shard's ownership-scoped recovery would then skip (permanently strand) the
        # dead prior leader shard's in-flight lanes. HA for a sharded fleet is the supervisor's
        # restart-on-exit per shard, not [cluster].
        if settings.cluster is not None and settings.cluster.enabled:
            print(
                "error: --shard cannot be combined with [cluster].enabled — engine sharding (ADR "
                "0037/0073) and active-passive clustering use incompatible recovery models (the "
                "store-wide leadership lease would transfer across shard ids). Disable [cluster] "
                "for a sharded fleet (the supervisor restarts crashed shards), or run clustered "
                "without --shard.",
                file=sys.stderr,
            )
            return 2

        shard_id: str = args.shard

        def registry_filter(reg: Registry) -> Registry:  # noqa: F811 (local shard-bound closure)
            return filter_registry_for_shard(reg, shard_id)

    # ADR 0118: reflect the serve-gate EFFECTIVE flips (egress deny-by-default, retention auto-bound) back
    # into the [security] view so GET /security/posture reports what is actually in effect, not just the
    # authored config. The internal egress/retention objects were mutated in place by the gates above.
    settings.security.block_unlisted_outbound = settings.egress.deny_by_default
    settings.security.delete_message_bodies_after_days = settings.retention.messages_days

    app = create_managed_app(
        store_settings=settings.store,
        security_settings=settings.security,
        config_dir=config_dir,
        registry_filter=registry_filter,
        config_reload_roots=settings.api.config_reload_roots,
        inbound_bind_host=settings.inbound.bind_host,
        allow_insecure_bind=insecure_bind_ok,
        delivery_defaults=settings.delivery.retry_policy(),
        ordering_default=settings.delivery.ordering,
        internal_error_default=settings.delivery.internal_error,
        buildup_default=settings.delivery.buildup_threshold(),
        stall_default=settings.delivery.stall_threshold(),
        saturation_default=settings.delivery.saturation_threshold(),
        ack_after_default=settings.inbound.ack_after,
        stream_inflight_budget_bytes=settings.inbound.stream_inflight_budget_bytes,
        priority_default=settings.delivery.priority,
        max_correlation_depth=settings.pipeline.max_correlation_depth,
        per_lane_wake=settings.pipeline.per_lane_wake,
        claim_mode=settings.pipeline.claim_mode,
        pooled_claimers_per_stage=settings.pipeline.pooled_claimers_per_stage,
        pooled_sweep_interval=settings.pipeline.pooled_sweep_interval,
        pooled_claim_lane_chunk=settings.pipeline.pooled_claim_lane_chunk,
        pooled_max_processing_lanes=settings.pipeline.pooled_max_processing_lanes,
        require_rcsi_for_pooled=settings.pipeline.require_rcsi_for_pooled,
        infra_fault_policy=settings.pipeline.infra_fault_policy,
        infra_fault_stop_after=settings.pipeline.infra_fault_stop_after,
        infra_fault_backoff_cap=settings.pipeline.infra_fault_backoff_cap,
        credential_fault_policy=settings.pipeline.credential_fault_policy,
        schedule_tick_seconds=settings.pipeline.schedule_tick_seconds,
        fuse_thread_hops=settings.pipeline.fuse_thread_hops,
        pooled_fusing_workers=settings.pipeline.pooled_fusing_workers,
        batch_handoff_statements=settings.pipeline.batch_handoff_statements,
        snapshot_on_send=settings.pipeline.snapshot_on_send,
        sandbox_settings=settings.sandbox,
        connection_events=settings.diagnostics.connection_events,
        response_sent_default=settings.diagnostics.response_sent,
        message_events=settings.diagnostics.message_events,
        audit_all_authz=settings.diagnostics.audit_all_authz,
        env_values_provider=env_values,
        auth_settings=settings.auth,
        ai_settings=settings.ai,
        alerts_settings=settings.alerts,
        secrets_settings=settings.secrets,
        retention_settings=settings.retention,
        cert_monitor_settings=settings.cert_monitor,
        secret_rotation_settings=settings.secret_rotation,
        # ASVS 13.3.4 ENFORCE escalation arm reads the [security].enforcement dial (ADR 0148).
        security_enforcement=settings.security.enforcement,
        update_check_settings=settings.update_check,
        backup_settings=settings.backup,
        dr_settings=settings.dr,
        api_tls_cert_file=settings.api.tls_cert_file,
        # ASVS 6.4.5: operator-held copies of inbound service callers' client certs — watched by the same
        # [cert_monitor] scan, so a caller's cert cannot expire unnoticed while it has stopped connecting.
        api_tls_client_cert_files=settings.api.tls_client_cert_files,
        # Reserve the engine's own API listener so no inbound can be wired onto it (it would collide
        # with uvicorn at bind); surfaced as a clear PortConflictError at check/start instead.
        api_listener=(settings.api.host, settings.api.port),
        reference_settings=settings.reference,
        egress_settings=settings.egress,
        # #190 (ADR 0093): the [tls] client trust-anchor policy — the internal-CA fallback the
        # internal-outbound TLS context builders verify an internal hop against.
        tls_settings=settings.tls,
        shadow_settings=settings.shadow,
        cluster_settings=settings.cluster,
        approvals_settings=settings.approvals,
        integrity_settings=settings.integrity,
        service_settings=settings.service,  # [service] service-status reporting (L6a, default off)
        expose_docs=settings.api.expose_docs,
        ws_allowed_origins=settings.api.ws_allowed_origins,
        serve_ui=settings.api.serve_ui,  # read-only browser ops dashboard under /ui (ADR 0065)
        public_origin=settings.api.public_origin,  # /ui external origin for off-loopback same-origin
        # WebAuthn rp_id may derive from the request URL ONLY on a loopback bind with no reverse
        # proxy declared (ADR 0068 §7) — behind a declared proxy the Host header is client-
        # forwardable, so ceremonies fail closed unless public_origin is set.
        webauthn_rp_from_request=(
            not settings.api.tls_terminated_upstream and settings.api.is_loopback
        ),
        # L5b (ADR 0068 §8): exposure_protected forces the session cookie's Secure flag + HSTS
        # (the operator's declaration that the browser-facing scheme is https — the per-request
        # scheme is proxy-dependent); tls_terminated_upstream arms the one-shot /ui cleartext-
        # scheme tripwire (proxy not sending X-Forwarded-Proto / untrusted peer).
        exposure_protected=settings.api.exposure_protected,
        # ADR 0143: whether the API binds a loopback host — the web console engages the http-SAFE
        # browser hardening over this cleartext loopback secure-context (http://127.0.0.1) WITHOUT
        # auto-TLS; the session cookie's Secure/__Host- still keys on effective_https (real https).
        loopback=settings.api.is_loopback,
        tls_terminated_upstream=settings.api.tls_terminated_upstream,
        # #200 residual (ADR 0092): the API PHI-read data-path guard keys on whether the serve hop is
        # proven secure — a loopback bind (on-box), in-process TLS, or a declared TLS-terminating proxy
        # (exposure_protected). A prod-PHI instance whose serve hop is none of these refuses to emit PHI
        # over the response path, mirroring the transport-cell posture-keyed refusal.
        phi_read_hop_secure=settings.api.is_loopback or settings.api.exposure_protected,
        # #200 (ADR 0002): mTLS client-cert → principal allow-list, consumed by
        # security.resolve_client_cert_identity (deny-by-default; empty = cert-identity off).
        tls_client_cert_identities=settings.api.tls_client_cert_identities,
        # The SAME list that becomes uvicorn's forwarded_allow_ips below. The client-network gate does
        # NOT key its decision on this — it reads the scope address uvicorn already resolved — it is
        # passed only so the address-monoculture tripwire knows whether a proxy was declared.
        trusted_proxies=settings.api.trusted_proxies,
        log_dir=settings.logging.log_dir,  # GET /status app-log disk metering (#50)
        # BACKLOG #171 (ADR 0130): the startup [logging].level baseline a restart returns to, reported by
        # GET /logging/level next to the (possibly runtime-overridden) effective level.
        configured_log_level=settings.logging.level,
        # #285 (ASVS 6.7.1): the operator-supplied auth-path trust anchors (OIDC / AD / api-mTLS client
        # CA) the lifespan + /config/reload preflight for ACL + optional SHA-256 pin. Empty when none is
        # configured → dormant, byte-identical. `enforcing` is the [security].enforcement refuse/warn dial.
        trust_anchor_specs=collect_anchor_specs(settings.auth, settings.api),
        trust_anchors_enforcing=enforcing,
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
    # BACKLOG #1276: THE ENGINE ALWAYS SERVES TLS. Owner ruling 2026-08-22 (option 3), which
    # SUPERSEDES ADR 0143's premise that the console is hardened "over a cleartext loopback
    # secure-context WITHOUT auto-TLS". An operator certificate always wins; with none configured
    # the engine mints a self-signed placeholder rather than opening a cleartext socket.
    #
    # Unconditional on purpose: a CONDITIONAL scheme is what let the tray, the harness and the
    # DAST target each decide it their own way, which is the defect this item exists to remove.
    from pathlib import Path as _Path

    from messagefoundry.api.tls import build_api_ssl_context, ensure_api_tls_material

    _material = ensure_api_tls_material(
        settings.api, state_dir=_Path(settings.store.path).resolve().parent
    )
    if _material is not None:
        _cert, _key = _material
        _api_tls = settings.api.model_copy(update={"tls_cert_file": _cert, "tls_key_file": _key})
        # WP-13a: terminate TLS in-process. Build the context now so a bad cert/key/passphrase fails
        # fast (before uvicorn opens the socket); pass it via uvicorn's ssl_context_factory so the
        # tls_min_version floor is enforced exactly.
        # #285: build_api_ssl_context preflights [api].tls_client_ca_file (pin + owner-only DACL) at
        # construction; enforcing is the [security].enforcement refuse/warn dial.
        ctx = build_api_ssl_context(_api_tls, enforcing=enforcing)
        run_kwargs["ssl_context_factory"] = lambda config, default_factory: ctx
        # ADR 0083 activation: only when in-process mTLS (client CA) AND a cert-identity map are BOTH
        # configured, swap in the scope-populating HTTP protocol so a verified peer cert reaches
        # resolve_client_cert_identity. Gated on both so a mutual-auth-only bind (console mTLS, no map)
        # and every non-mTLS bind keep the stock protocol — no behaviour change without a client CA + map.
        if settings.api.tls_client_ca_file and settings.api.tls_client_cert_identities:
            from messagefoundry.api.tls_client_cert import client_cert_http_protocol_class

            run_kwargs["http"] = client_cert_http_protocol_class()
    from messagefoundry.last_resort import install_excepthook, install_thread_excepthook
    from messagefoundry.redaction import safe_exc

    install_excepthook()  # last-resort main-thread hook: an uncaught exception logs PHI-redacted (16.5.4)
    # The sibling hook for every OTHER thread (BACKLOG #1055). sys.excepthook does not cover them, and
    # the engine runs non-asyncio threads whose except clauses are deliberately narrow — the sandbox
    # session's raw stdout reader catches only OSError — so anything else would otherwise reach the
    # stdlib default and print an unredacted traceback to the NSSM-captured stderr.
    install_thread_excepthook()
    try:
        uvicorn.run(app, host=settings.api.host, port=settings.api.port, **run_kwargs)
    except Exception as exc:  # last-resort: log an abnormal server exit PHI-redacted, then re-raise
        logging.getLogger(__name__).critical("server exited abnormally: %s", safe_exc(exc))
        raise
    return 0


def _supervise(args: argparse.Namespace) -> int:
    """L3 multi-process sharding (messagefoundry/pipeline/supervisor.py): discover the shard ids in the
    config and run one `serve --shard <id>` subprocess per shard, each with its own SQLite db file and
    API port. Monitors + restarts crashed shards, and stops them all cleanly on SIGINT/SIGTERM. A single
    (default) shard yields a single subprocess — identical to a plain `serve`."""
    import asyncio

    from messagefoundry.config.anchor import anchor_under_root, resolve_project_root
    from messagefoundry.pipeline.supervisor import supervise

    configure_logging("INFO")

    # ADR 0050 AC-9: anchor the discovery --config and the --db base under the project root HERE, before
    # discover_shard_specs runs load_config() — so `supervise --project-root R --config <relative>` from a
    # non-root CWD discovers shards under R, and each shard's <stem>_<shard>.db composes under R in the
    # supervisor (not only via each child re-anchoring a relative --db). --service-config is forwarded raw
    # and each child serve resolves it under the forwarded --project-root (same precedence as serve).
    cwd = Path.cwd()
    root = resolve_project_root(args.project_root, cwd=cwd)
    config = anchor_under_root(args.config, root, cwd=cwd)
    assert config is not None  # args.config always has a string default
    db_base = anchor_under_root(args.db, root, cwd=cwd)
    assert db_base is not None  # supervise --db has a string default ("messagefoundry.db")

    # Resolve the store backend up front so the no-split-store guard (ADR 0063) can refuse a >1-shard
    # config on SQLite BEFORE any subprocess is spawned. --service-config is anchored the same way each
    # child resolves it; --db only sets the SQLite path, never the backend.
    from pydantic import ValidationError

    from messagefoundry.config.settings import load_settings

    # anchor_under_root(None, ...) returns None (config/anchor.py), so this is safe when unset; each child
    # re-anchors the raw --service-config to the same path under the forwarded --project-root.
    service_config = anchor_under_root(args.service_config, root, cwd=cwd)
    try:
        settings = load_settings(config_path=service_config)
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return asyncio.run(
        supervise(
            config,
            store_backend=settings.store.backend,
            db_base=db_base,
            base_port=args.base_port,
            env=args.env,
            service_config=args.service_config,
            project_root=args.project_root,
        )
    )


def _validate(args: argparse.Namespace) -> int:
    from messagefoundry.config.wiring import validate_config

    resolved = _resolve_offline_anchor(args)
    if isinstance(resolved, int):
        return resolved
    config_dir, _ = resolved
    diags = validate_config(config_dir)
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
    from messagefoundry.config.graph import build_wiring_graph
    from messagefoundry.config.wiring import WiringError, display_settings, load_config

    resolved = _resolve_offline_anchor(args)
    if isinstance(resolved, int):
        return resolved
    config_dir, _ = resolved
    try:
        reg = load_config(config_dir)
    except WiringError as exc:
        return _emit_error(str(exc), as_json=args.json)
    # Edges come from the one authoritative static extractor (ADR 0091 D1): AST-first with the
    # legacy string-constant scan as a fallback tier, provenance-tagged, plus reverse adjacency.
    # v1 fields ("handlers"/"sends" name lists, per-element file/line) are preserved unchanged;
    # v2 adds "edges"/"fed_by"/"receives_from"/"dynamic" and the top-level "version".
    graph = build_wiring_graph(reg)

    def edges_out(kind: str, name: str) -> list[dict[str, str]]:
        return [
            {"target": e.target, "target_kind": e.target_kind, "provenance": e.provenance}
            for e in sorted(graph.targets(kind, name), key=lambda e: (e.target_kind, e.target))
        ]

    def out_names(kind: str, name: str, target_kind: str) -> list[str]:
        return sorted({e.target for e in graph.targets(kind, name) if e.target_kind == target_kind})

    def in_names(kind: str, name: str, source_kind: str) -> list[str]:
        return sorted(
            {e.source for e in graph.referrers(kind, name) if e.source_kind == source_kind}
        )

    data = {
        "version": 2,
        "inbound": [
            {
                "name": name,
                "type": c.spec.type.value,
                "settings": display_settings(c.spec.settings),
                "router": c.router,
                "ack_mode": c.ack_mode.value,
                "strict": c.validation.strict,
                # #233 (ADR 0111): present in the graph but never wired when False. Emitted so tooling
                # can tell a not-deployed connection (deployed=false) from a merely stopped one — the
                # static graph carries no lifecycle state otherwise (AC-3).
                "deployed": c.deployed,
                "file": c.source_file,
                "line": c.source_line,
                # Non-empty only for a pass-through (PT) inbound — the handlers that Send here.
                "receives_from": in_names("inbound", name, "handler"),
            }
            for name, c in reg.inbound.items()
        ],
        "outbound": [
            {
                "name": name,
                "type": c.spec.type.value,
                "settings": display_settings(c.spec.settings),
                # #233 (ADR 0111): see the inbound note above — distinguishes not-deployed from stopped.
                "deployed": c.deployed,
                "file": c.source_file,
                "line": c.source_line,
                "receives_from": in_names("outbound", name, "handler"),
            }
            for name, c in reg.outbound.items()
        ],
        "routers": [
            {
                "name": n,
                **_fn_location(fn),
                "handlers": out_names("router", n, "handler"),
                "edges": edges_out("router", n),
                "fed_by": in_names("router", n, "inbound"),
                "dynamic": graph.is_dynamic("router", n),
            }
            for n, fn in sorted(reg.routers.items())
        ],
        "handlers": [
            {
                "name": n,
                **_fn_location(fn),
                "sends": out_names("handler", n, "outbound"),
                "edges": edges_out("handler", n),
                "fed_by": in_names("handler", n, "router"),
                "dynamic": graph.is_dynamic("handler", n),
            }
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


def _redact_body(body: str) -> str:
    """Replace a PHI-bearing message body with a length placeholder.

    ``dryrun`` is a dev tool whose output is routinely piped to files/CI logs, so it must not emit
    full bodies (raw + would-send payloads) by default; ``--show-phi`` opts in. See docs/PHI.md §7.
    """
    return f"<redacted {len(body)} chars; pass --show-phi>" if body else body


def _snapshot_on_send_setting(service_config: str | None) -> bool:
    """Best-effort ``[pipeline].snapshot_on_send`` for the offline preview commands (#230 CLI parity).

    Loads the service settings the way ``serve`` resolves them (an explicit/anchored
    ``--service-config``, else ``./messagefoundry.toml`` only if present, ``MEFOR_*`` env overrides on
    top) and returns the loaded flag. When no settings load (no file, or one that won't
    parse/validate), fall back to the **Settings-model default (True)** — the posture of exactly the
    default, un-overridden engine — never a hardcoded ``False``, which would make the preview diverge
    from the engine this command exists to mirror (ADR 0104 §8.1)."""
    from pydantic import ValidationError

    from messagefoundry.config.settings import PipelineSettings, load_settings

    try:
        return load_settings(config_path=service_config).pipeline.snapshot_on_send
    except (FileNotFoundError, ValueError, ValidationError, OSError):
        return PipelineSettings().snapshot_on_send


def _dryrun(args: argparse.Namespace) -> int:
    from messagefoundry.config.wiring import WiringError, load_config
    from messagefoundry.pipeline.dryrun import dry_run, read_messages

    resolved = _resolve_offline_anchor(args)
    if isinstance(resolved, int):
        return resolved
    config_dir, service_config = resolved
    try:
        reg = load_config(config_dir)
    except WiringError as exc:
        return _emit_error(str(exc), as_json=args.json)
    try:
        messages = read_messages(args.messages)
    except (FileNotFoundError, ValueError) as exc:
        return _emit_error(str(exc), as_json=args.json)

    # #230 P4 (ADR 0104): preview under the engine's copy-on-Send posture, resolved from the service
    # settings serve would load — the library defaults stay False, but the CLI mirrors the live engine.
    snapshot_on_send = _snapshot_on_send_setting(service_config)

    show_phi: bool = args.show_phi
    if not show_phi:
        print(
            "note: message bodies redacted; pass --show-phi to include raw/payloads (PHI)",
            file=sys.stderr,
        )

    # Traced dry-run (ADR 0072): a sys.settrace execution trace of each Router/Handler, byte-identical
    # in disposition/routing to a plain dryrun. Preview-only and additive — no dispatch change. Assigned
    # locals + msg writes are PHI, so they honor the same --show-phi gate.
    if args.trace is not None:
        from messagefoundry.pipeline.dryrun_trace import trace_dry_run

        traced: list[dict[str, Any]] = []
        try:
            for source, path, raw in messages:
                entry = trace_dry_run(
                    reg,
                    raw,
                    inbound=args.inbound,
                    show_phi=show_phi,
                    snapshot_on_send=snapshot_on_send,
                )
                traced.append({"source": source, "path": path, **entry})
        except (ValueError, KeyError) as exc:  # e.g. ambiguous/unknown --inbound
            return _emit_error(str(exc), as_json=args.json)
        _print_json(traced, compact=args.json)
        return 0

    out: list[dict[str, Any]] = []
    try:
        for source, path, raw in messages:
            result = dry_run(reg, raw, inbound=args.inbound, snapshot_on_send=snapshot_on_send)
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


def _hl7structures(args: argparse.Namespace) -> int:
    from messagefoundry.hl7structures import to_json

    _print_json(to_json(), compact=args.json)
    return 0


def _lens(args: argparse.Namespace) -> int:
    """Statically parse or rewrite a config module's @handler rows (ADR 0076 §3 / §5).

    The module is never imported/executed (static ``ast`` only), so a module whose top level would raise
    still parses/rewrites. An unparseable file / refused edit is a clean ``{"error": …}`` + non-zero
    exit, matching the IDE's degradation-to-text-editor behavior."""
    if args.lens_command == "rewrite":
        return _lens_rewrite(args)
    if args.lens_command == "schema":
        return _lens_schema(args)
    return _lens_parse(args)


def _lens_schema(args: argparse.Namespace) -> int:
    """``lens schema`` — emit the transform-vocabulary param schema (ADR 0076 §5) the Steps editor's
    per-param input widgets consume.

    Derived from the action + diagnostic signatures via stdlib ``inspect``/``typing`` only (no new
    runtime dependency, ADR 0076 §6.5); lazy-imported inside the handler like ``_hl7schema`` so a
    quick call never pays for FastAPI/uvicorn. Starts no server; imports/executes no config module."""
    from messagefoundry.lens_schema import op_param_schema

    _print_json(op_param_schema(), compact=args.json)
    return 0


def _lens_parse(args: argparse.Namespace) -> int:
    """``lens parse`` — emit the per-@handler row contract (ADR 0076 §3).

    Reads the source from the ``module`` file, or from stdin when it is ``-`` (the IDE re-projects the
    live buffer this way after a structural edit shifts every row coordinate). Static-only either way."""
    import sys

    from messagefoundry.lens import LensParseError, parse_module, parse_source

    try:
        if args.module == "-":
            # Raw UTF-8 (never the Windows locale codepage) so the buffer's non-ASCII round-trips exactly.
            module_label = "<stdin>"
            handlers = parse_source(
                sys.stdin.buffer.read().decode("utf-8"),
                module=module_label,
                contract=args.contract,
            )
        else:
            module_label = args.module
            handlers = parse_module(args.module, contract=args.contract)
    except LensParseError as exc:
        return _emit_error(str(exc), as_json=args.json)
    _print_json({"module": module_label, "handlers": handlers}, compact=args.json)
    return 0


def _lens_rewrite(args: argparse.Namespace) -> int:
    """``lens rewrite`` — apply one row param-edit and print the rewritten module source (ADR 0076 §5).

    Reads the source from ``module`` (or stdin when it is ``-``) and the edit spec from ``--edit`` (or
    stdin otherwise); prints the rewritten source (byte-identical outside the edited row) on success, or
    ``{"error": …}`` + exit 1 on any refusal — never a partial/lossy write."""
    import sys

    from messagefoundry.lens import LensParseError, LensRewriteError, rewrite_module, rewrite_source

    # Read stdin as raw UTF-8 (never the Windows locale codepage) so source bytes round-trip exactly —
    # byte-stability (gate 2) would break if a non-ASCII char (the samples carry — and → in comments)
    # were re-encoded through cp1252.
    def _read_stdin() -> str:
        return sys.stdin.buffer.read().decode("utf-8")

    if args.edit is not None:
        edit_text = args.edit
    elif args.module != "-":
        edit_text = _read_stdin()
    else:
        return _emit_error(
            "provide the edit spec via --edit when the source is read from stdin ('-')",
            as_json=True,
        )
    try:
        edit = json.loads(edit_text)
    except json.JSONDecodeError as exc:
        return _emit_error(f"invalid --edit JSON: {exc}", as_json=True)
    if not isinstance(edit, dict):
        return _emit_error("the edit spec must be a JSON object", as_json=True)

    try:
        if args.module == "-":
            rewritten = rewrite_source(
                _read_stdin(), edit, module="<stdin>", contract=args.contract
            )
        else:
            rewritten = rewrite_module(args.module, edit, contract=args.contract)
    except (LensParseError, LensRewriteError) as exc:
        return _emit_error(str(exc), as_json=True)
    # The rewritten module source is file content, not a JSON report — write the exact UTF-8 bytes to
    # stdout (not sys.stdout.write, which would re-encode through the console codepage and corrupt
    # non-ASCII, defeating byte-stability).
    sys.stdout.buffer.write(rewritten.encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


def _import(args: argparse.Namespace) -> int:
    """``import corepoint`` — translate a Corepoint action-list export into code-first config (ADR 0086).

    Writes one ``@router``/``@handler`` module per channel into ``--out`` and reports the count-and-log
    summary (mapped vs. unmapped actions). The export is untrusted data — a malformed export is a clean
    error + exit 1, never a traceback."""
    from messagefoundry.corepoint_import import CorepointImportError, import_corepoint

    try:
        result = import_corepoint(args.export, args.out)
    except CorepointImportError as exc:
        return _emit_error(str(exc), as_json=args.json)

    if args.json:
        _print_json(result.to_json(), compact=True)
        return 0
    disabled_total = (
        f", {result.total_disabled} disabled kept as comments" if result.total_disabled else ""
    )
    print(
        f"Imported {len(result.channels)} channel(s) into {args.out} "
        f"({result.total_mapped} action(s) mapped, {result.total_unmapped} left as TODO stubs"
        f"{disabled_total}):"
    )
    for c in result.channels:
        note = (
            f" — {c.unmapped} unmapped: {', '.join(sorted(set(c.unmapped_classes)))}"
            if c.unmapped
            else ""
        )
        renamed = (
            f" [renamed from {c.renamed_from} to avoid a filename collision]"
            if c.renamed_from
            else ""
        )
        disabled = (
            f" — {c.disabled} @Disabled element(s) preserved as comments" if c.disabled else ""
        )
        print(f"  {c.filename} ({c.mapped} mapped){note}{disabled}{renamed}")
    if result.total_unmapped:
        print(
            "\nReview the `# TODO: Corepoint ...` markers in the generated modules and hand-finish them, "
            "then run: messagefoundry check --config " + str(args.out)
        )
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


def _service(args: argparse.Namespace) -> int:
    """Control the engine's Windows service (ADR 0088). ``status`` queries state (no elevation);
    ``start``/``stop`` elevate once via UAC; ``install`` runs scripts/service/install-service.ps1
    elevated. The engine can't stop/start its *own* hosting service through the API, so this is a
    local, out-of-band CLI over the Windows SCM. Off Windows the actions are no-ops (return 1) and
    ``status`` prints ``unavailable``."""
    from messagefoundry import service as svc

    action = args.action
    if action == "status":
        print(svc.service_state(args.name))
        return 0
    if action == "install":
        if args.env is None:
            print(
                "error: `service install` requires --env <name> (the active environment the service "
                "runs as, passed to install-service.ps1)",
                file=sys.stderr,
            )
            return 2
        script = svc.install_script_path()
        if script is None:
            print(
                "error: could not locate scripts/service/install-service.ps1 (is the engine "
                "installed from a source checkout?)",
                file=sys.stderr,
            )
            return 2
        try:
            started = svc.install_service(str(script), args.env)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not started:
            print("error: `service install` is Windows-only", file=sys.stderr)
            return 1
        print(f"launched the elevated installer for environment {args.env!r}")
        return 0
    # start / stop
    try:
        started = svc.control_service(action, args.name)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not started:
        print(f"error: `service {action}` is Windows-only", file=sys.stderr)
        return 1
    print(
        f"requested elevated `{action}` of service {args.name!r}; poll `service status` for state"
    )
    return 0


def _gen_key(_args: argparse.Namespace) -> int:
    from messagefoundry.store.crypto import generate_key

    # Print only the key (so it can be piped); set it as MEFOR_STORE_ENCRYPTION_KEY, never the file.
    print(generate_key())
    return 0


def _cert_fail(message: str, *, as_json: bool, code: int = 2) -> int:
    """Report a `cert` command failure. JSON mode emits ``{"error": …}`` on stdout (machine-readable),
    human mode prints ``error: …`` to stderr. Returns ``code`` (2 = config/hard error, 1 = soft error).
    The message must never carry key or passphrase material (scrubbed at the call site)."""
    if as_json:
        print(json.dumps({"error": message}))
    else:
        print(f"error: {message}", file=sys.stderr)
    return code


def _write_private_key(path: Path, pem: bytes) -> None:
    """Write a private-key PEM with ``O_EXCL`` (refuse to overwrite) + ``0o600``, then tighten the
    Windows DACL via ``_secure_file`` — the write-then-secure sequence ``protect-key`` uses. Raises
    ``FileExistsError`` when ``path`` already exists (never clobber a key) or ``OSError`` on write
    failure. The PEM bytes are secret — never logged or surfaced in an exception."""
    import os

    from messagefoundry.store.store import _secure_file

    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    _secure_file(path)


def _cert(args: argparse.Namespace) -> int:
    """`cert` command group (BACKLOG #71/#72) — dispatch to import / inventory / self-signed."""
    if args.cert_command == "import":
        return _cert_import(args)
    if args.cert_command == "inventory":
        return _cert_inventory(args)
    return _cert_self_signed(args)


def _cert_import(args: argparse.Namespace) -> int:
    """`cert import` — import a PKCS#12/.pfx bundle into the PEM files the TLS loaders read.

    The bundle passphrase comes ONLY from ``MEFOR_PFX_PASSWORD`` (absent/empty ⇒ an unencrypted bundle,
    ``password=None``); it is never a CLI arg and never echoed. A bad password / malformed bundle is
    reported with a scrubbed message so the passphrase can never leak. cert.pem + ca-chain.pem are
    public; key.pem is written ``O_EXCL`` + ``0o600`` + ``_secure_file`` and refuses to overwrite."""
    import os

    from messagefoundry import pki

    pfx_path = Path(args.pfx)
    out_dir = Path(args.out_dir)
    try:
        pfx_bytes = pfx_path.read_bytes()
    except OSError as exc:
        return _cert_fail(f"cannot read --pfx {args.pfx!r}: {exc}", as_json=args.json)

    pw_env = os.environ.get("MEFOR_PFX_PASSWORD")
    password = pw_env.encode() if pw_env else None
    try:
        key, cert, cas = pki.load_pkcs12(pfx_bytes, password)
    except Exception:
        # NEVER surface the underlying exception text — a bad-password/decrypt error must not leak the
        # passphrase into stderr/logs/CI. The failure cause is intentionally generic.
        return _cert_fail(
            "could not load the PKCS#12 bundle (wrong MEFOR_PFX_PASSWORD, or not a valid .pfx)",
            as_json=args.json,
        )

    if cert is None:
        return _cert_fail("the PKCS#12 bundle contains no certificate", as_json=args.json)
    if key is None:
        return _cert_fail("the PKCS#12 bundle contains no private key", as_json=args.json)

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return _cert_fail(f"cannot create --out-dir {args.out_dir!r}: {exc}", as_json=args.json)

    cert_path = out_dir / "cert.pem"
    key_path = out_dir / "key.pem"
    ca_path = out_dir / "ca-chain.pem"

    # Key FIRST (O_EXCL): if it would clobber an existing key we stop before touching cert.pem.
    try:
        _write_private_key(key_path, pki.key_to_pem(key))
    except FileExistsError:
        return _cert_fail(
            f"refusing to overwrite an existing key file: {key_path} (remove it first)",
            as_json=args.json,
        )
    except OSError as exc:
        return _cert_fail(f"cannot write {key_path}: {exc}", as_json=args.json)

    cert_path.write_bytes(pki.cert_to_pem(cert))
    wrote_ca = bool(cas)
    if wrote_ca:
        ca_path.write_bytes(pki.ca_chain_to_pem(cas))

    result: dict[str, object] = {
        "cert": str(cert_path),
        "key": str(key_path),
        "ca_chain": str(ca_path) if wrote_ca else None,
        "ca_count": len(cas),
    }
    if args.json:
        _print_json(result, compact=True)
    else:
        _safe_print(f"Imported .pfx into {out_dir}:")
        _safe_print(f"  cert:     {cert_path}")
        _safe_print(f"  key:      {key_path} (private; 0600)")
        if wrote_ca:
            _safe_print(f"  ca-chain: {ca_path} ({len(cas)} CA cert(s))")
        else:
            _safe_print("  ca-chain: (none — the bundle carried no CA certs)")
    return 0


def _cert_inventory(args: argparse.Namespace) -> int:
    """`cert inventory` — read-only listing of cert facts (subject/issuer/notAfter/SAN/days/expired).

    Sources (at least one required): explicit ``--cert PATH`` (repeatable, always included) and/or the
    wired TLS certs of ``--config`` (loaded like ``validate``/``graph`` via ``load_config`` →
    ``certs_from_registry``; ``--service-config`` adds the ``[api]`` TLS cert). Reads only public certs.
    An unreadable/unparseable cert is reported per-row (no secret text) and makes the command exit 1."""
    import time

    from messagefoundry import pki
    from messagefoundry.pipeline.cert_expiry import certs_from_registry

    explicit = args.cert or []
    if not explicit and not args.config:
        return _cert_fail(
            "no certificate source: pass --cert PATH (repeatable) and/or --config DIR",
            as_json=args.json,
        )

    # (label, path) pairs — explicit --cert first (label = the path), then the wired TLS certs.
    pairs: list[tuple[str, str]] = [(p, p) for p in explicit]

    if args.config:
        api_tls_cert_file: str | None = None
        api_tls_client_cert_files: list[str] = []
        if args.service_config:
            from pydantic import ValidationError

            from messagefoundry.config.settings import load_settings

            try:
                settings = load_settings(config_path=args.service_config)
            except (FileNotFoundError, ValueError, ValidationError, OSError) as exc:
                return _cert_fail(f"cannot load --service-config: {exc}", as_json=args.json)
            api_tls_cert_file = settings.api.tls_cert_file
            # ASVS 6.4.5: inventory the service-caller certs the operator listed, too.
            api_tls_client_cert_files = list(settings.api.tls_client_cert_files)
        from messagefoundry.config.wiring import WiringError, load_config

        try:
            reg = load_config(args.config)
        except (WiringError, FileNotFoundError, OSError) as exc:
            return _cert_fail(f"cannot load --config: {exc}", as_json=args.json)
        pairs.extend(
            (mc.label, mc.path)
            for mc in certs_from_registry(reg, api_tls_cert_file, api_tls_client_cert_files)
        )

    now = time.time()
    entries: list[dict[str, object]] = []
    had_error = False
    for label, path in pairs:
        try:
            pem = Path(path).read_bytes()
            facts = pki.read_cert_facts(pem, now=now)
        except FileNotFoundError:
            had_error = True
            entries.append({"label": label, "path": path, "error": "file not found"})
            if not args.json:
                _safe_print(f"{label}  [{path}]  ERROR: file not found")
            continue
        except Exception:
            # Any read/parse failure → a generic per-row error (the documented contract), matching the
            # expiry monitor's own broad guard. Broad on purpose: cryptography can raise non-ValueError
            # types on odd certs (e.g. UnsupportedAlgorithm at load). Generic message ONLY — never echo
            # cryptography's exception text (defense in depth if a key file is pointed at by mistake; the
            # inventory must not surface private material).
            had_error = True
            msg = "could not read or parse certificate"
            entries.append({"label": label, "path": path, "error": msg})
            if not args.json:
                _safe_print(f"{label}  [{path}]  ERROR: {msg}")
            continue
        entries.append(
            {
                "label": label,
                "path": path,
                "subject": facts.subject,
                "issuer": facts.issuer,
                "not_after": facts.not_after_iso,
                "sans": facts.sans,
                "days_remaining": facts.days_remaining,
                "expired": facts.expired,
            }
        )
        if not args.json:
            flag = "EXPIRED" if facts.expired else f"{facts.days_remaining} day(s) remaining"
            _safe_print(f"{label}  [{path}]")
            _safe_print(f"  subject:  {facts.subject}")
            _safe_print(f"  issuer:   {facts.issuer}")
            _safe_print(f"  notAfter: {facts.not_after_iso}  ({flag})")
            _safe_print(f"  SAN(DNS): {', '.join(facts.sans) if facts.sans else '(none)'}")

    if args.json:
        _print_json({"certs": entries}, compact=True)
    elif not entries:
        _safe_print("no certificates to inventory")
    return 1 if had_error else 0


def _cert_self_signed(args: argparse.Namespace) -> int:
    """`cert self-signed` — mint a self-signed EC P-256 cert+key for NON-PROD TLS bring-up.

    Writes cert.pem + key.pem to ``--out-dir``; key.pem is written ``O_EXCL`` + ``0o600`` +
    ``_secure_file`` and refuses to overwrite. Prints a clear DEV/non-prod note (a self-signed cert has
    no chain of trust)."""
    from messagefoundry import pki

    if args.days <= 0:
        return _cert_fail("--days must be a positive integer", as_json=args.json)
    out_dir = Path(args.out_dir)
    sans = args.san or []
    cert_pem, key_pem = pki.make_self_signed(args.cn, sans, args.days)

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return _cert_fail(f"cannot create --out-dir {args.out_dir!r}: {exc}", as_json=args.json)

    cert_path = out_dir / "cert.pem"
    key_path = out_dir / "key.pem"
    try:
        _write_private_key(key_path, key_pem)
    except FileExistsError:
        return _cert_fail(
            f"refusing to overwrite an existing key file: {key_path} (remove it first)",
            as_json=args.json,
        )
    except OSError as exc:
        return _cert_fail(f"cannot write {key_path}: {exc}", as_json=args.json)
    cert_path.write_bytes(cert_pem)

    dns = list(dict.fromkeys([args.cn, *sans]))
    result: dict[str, object] = {
        "cert": str(cert_path),
        "key": str(key_path),
        "cn": args.cn,
        "sans": dns,
        "days": args.days,
        "note": "DEV/non-prod only — self-signed, no chain of trust",
    }
    if args.json:
        _print_json(result, compact=True)
    else:
        _safe_print(
            f"Wrote a self-signed DEV certificate (non-prod TLS bring-up ONLY) to {out_dir}:"
        )
        _safe_print(f"  cert: {cert_path}")
        _safe_print(f"  key:  {key_path} (private; 0600)")
        _safe_print(f"  CN={args.cn}  SAN(DNS)={', '.join(dns)}  valid {args.days} day(s)")
        _safe_print(
            "  NOTE: self-signed — no chain of trust; never front production PHI with this."
        )
    return 0


def _protect_key(args: argparse.Namespace) -> int:
    """DPAPI-protect the store encryption key to a file (WP-11d, ASVS 13.3.1; Windows-only).

    Source: ``--generate`` mints a fresh key (also printed once to stderr so it can be backed up
    offline — the machine-bound file is unrecoverable if the host is lost); otherwise the key is read
    from ``MEFOR_STORE_ENCRYPTION_KEY``. The file is written with a tight DACL — the minting owner plus
    READ for the engine's service principal (SYSTEM by default, or ``--grant-account``) — atop DPAPI, so
    the service account (not just the minting admin) can read the key at startup.
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
    # Lock the key file down, but keep it readable by the engine's service principal: SYSTEM by default
    # (a LocalSystem service) plus an explicit --grant-account for a virtual / gMSA account. Machine-scope
    # DPAPI already lets any host principal decrypt; without these read grants the owner-only DACL would
    # lock the file to the minting admin and the service would fail closed at startup (DpapiError). The
    # generic _secure_file (store DB/WAL) passes no grants and stays owner-only.
    grants = ["*S-1-5-18"]  # NT AUTHORITY\SYSTEM — well-known SID, robust on non-English Windows
    if args.grant_account:
        grants.append(args.grant_account)
    _secure_file(out, extra_read_grants=grants)
    granted = "SYSTEM" + (f" + {args.grant_account!r}" if args.grant_account else "")
    print(
        f"Wrote DPAPI-protected key to {out} (read-granted to {granted}).\n"
        f"Next: set [store].encryption_key_file = {str(out)!r} and unset MEFOR_STORE_ENCRYPTION_KEY. "
        "If the engine runs as a virtual / gMSA account (not LocalSystem), re-run with "
        "--grant-account '<that account>' so the service can read the key at startup."
    )
    return 0


_ANCHOR_FORM = (
    "expected COUNT:HEAD — the row count and the FULL head, copied verbatim from "
    "'messagefoundry audit-anchor' (the 12-character head printed inside a FAIL message is a display "
    "truncation, not an anchor); an empty log anchors as '0:'"
)

#: Every hex character, both cases. The store only ever emits lowercase (``hexdigest()``); uppercase is
#: admitted and NORMALISED rather than rejected, because an operator who upper-cased the value in a
#: ticket must get a verify, not a tamper alarm.
_ANCHOR_HEX = frozenset("0123456789abcdefABCDEF")
#: ``hashlib.sha256``/``hmac.new(..., sha256)`` ``hexdigest()`` width — the only hex head length the
#: chain can produce, keyless or keyed (``store/store.py``, ``audit_row_hash``).
_ANCHOR_DIGEST_HEX_LEN = 64
#: ADR 0138 ``vault_transit``: the row MAC is computed INSIDE Vault/OpenBao Transit
#: (``crypto_transit.TransitCipher.audit_hmac``), which returns its own opaque ``vault:v<N>:<base64>``
#: string — not hex, not 64 characters — and that string lands in ``row_hash`` verbatim. A future
#: isolated-module MAC provider with a different prefix MUST be added here, or a legitimate anchor from
#: that deployment is refused as malformed.
_ANCHOR_ISOLATED_MAC_PREFIX = "vault:v"


def _parse_anchor(text: str) -> tuple[int, str]:
    """Parse a ``COUNT:HEAD`` audit anchor into the tuple ``verify_audit_chain`` expects.

    Raises ``ValueError`` naming the form. It must RAISE rather than fall back to an unanchored
    verify: a silently-ignored anchor turns the whole control into a gate that reports green while
    checking nothing, which is precisely the failure this subcommand exists to close.

    It must ALSO refuse rather than hand the comparator a head the store can never emit.
    ``verify_audit_chain`` compares the head byte-exactly and reports *any* difference as
    ``truncated or rewritten``, so an accepted-but-impossible head becomes a FALSE tamper alarm — a
    red light on an intact chain, indistinguishable from a real detection. A control whose whole value
    is that a FAIL means something cannot be allowed to manufacture FAILs out of its own input
    handling — the inverse of the green-while-checking-nothing hole above, and it costs just as much.

    Two head shapes are legal, because exactly two are producible:

    * a **hex digest** — ``audit_row_hash``'s keyless SHA-256 or in-heap HMAC-SHA256 ``hexdigest()``,
      always exactly 64 lowercase hex characters. Case is normalised, and the length is *required*: a
      12-character head pasted out of a FAIL message's display truncation is refused as malformed
      input (rc 2) instead of being reported as tampering (rc 1).
    * an **isolated-module MAC** — ADR 0138 ``vault_transit`` mode, whose ``vault:v1:…`` string is
      passed through UNCHANGED. ``partition`` splits on the FIRST colon, so its internal colons
      survive the ``COUNT:HEAD`` split.

    An EMPTY head is legal and load-bearing — ``audit_anchor()`` returns ``(0, "")`` for an empty log,
    so ``0:`` must round-trip or a fresh instance is the one state that cannot be anchored.
    """
    raw = text.strip()
    count_text, sep, head = raw.partition(":")
    if not sep:
        raise ValueError(f"malformed audit anchor {text!r}: no ':' separator — {_ANCHOR_FORM}")
    try:
        count = int(count_text)
    except ValueError:
        raise ValueError(
            f"malformed audit anchor {text!r}: row count {count_text!r} is not an integer — "
            f"{_ANCHOR_FORM}"
        ) from None
    if count < 0:
        raise ValueError(
            f"malformed audit anchor {text!r}: row count {count} is negative — {_ANCHOR_FORM}"
        )
    head = head.strip()
    if not head:
        return count, head
    if all(c in _ANCHOR_HEX for c in head):
        if len(head) != _ANCHOR_DIGEST_HEX_LEN:
            raise ValueError(
                f"malformed audit anchor {text!r}: head {head!r} is {len(head)} hex characters, not "
                f"a full {_ANCHOR_DIGEST_HEX_LEN}-character digest — {_ANCHOR_FORM}"
            )
        return count, head.lower()
    if head.startswith(_ANCHOR_ISOLATED_MAC_PREFIX):
        return count, head  # opaque by construction; never normalise what we do not define
    raise ValueError(
        f"malformed audit anchor {text!r}: head {head!r} is neither a "
        f"{_ANCHOR_DIGEST_HEX_LEN}-character hex digest nor an isolated-module "
        f"{_ANCHOR_ISOLATED_MAC_PREFIX}… MAC (ADR 0138) — {_ANCHOR_FORM}"
    )


def _resolve_expected_anchor(args: argparse.Namespace) -> tuple[int, str] | None | int:
    """The anchor for ``audit-verify``, or the exit code 2 if the flags are unusable.

    Returns ``None`` when neither flag was given (an unanchored verify, the historical behaviour).
    Argparse's mutually-exclusive group has already refused both-at-once.
    """
    from pathlib import Path

    raw: str | None
    if args.expected_anchor_file is not None:
        try:
            # `utf-8-sig` absorbs a leading BOM: PowerShell 5.1's `Out-File`/`Set-Content -Encoding
            # utf8` writes UTF-8 WITH one, and this product is deployed as a Windows service, so that
            # is a first-class way an operator produces this file.
            raw = Path(args.expected_anchor_file).read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            # `UnicodeDecodeError` subclasses `ValueError`, NOT `OSError` — catching only the latter
            # let a mis-encoded file raise an unhandled traceback and exit 1, the SAME code
            # `audit-verify` returns for a BROKEN CHAIN, so a compliance job keying on exit codes
            # would have read a file-encoding problem as a detected tamper. PowerShell 5.1's `>`
            # writes UTF-16LE, so this is the likely file, not an exotic one.
            print(
                f"error: cannot read --expected-anchor-file {args.expected_anchor_file!r}: {exc}. "
                "It must be a UTF-8 text file holding the COUNT:HEAD line; PowerShell 5.1's '>' "
                "writes UTF-16 — pipe to 'Set-Content -Encoding utf8' there.",
                file=sys.stderr,
            )
            return 2
    else:
        raw = args.expected_anchor
    if raw is None:
        return None
    try:
        return _parse_anchor(raw)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _admin_unlock(args: argparse.Namespace) -> int:
    """Clear a local account's lockout from the host (BACKLOG #1236, ADR 0171).

    THE GATE IS HOST ACCESS, AND IT IS A REAL ONE RATHER THAN AN ABSENT ONE. Reaching this needs the
    service config, the store path and, on an encrypted store, the key material -- which is the
    operator who installed the engine. Anyone holding all three already has the database and does not
    need an unlock affordance to reach an account. So this grants no capability that the trust
    boundary did not already imply, which is what makes it safe to ship unauthenticated.

    IT DOES NOT RESET A PASSWORD, DELIBERATELY. Clearing the lockout returns the account to its
    ordinary state and the holder still needs their credential. An unlock is the narrowest thing that
    resolves the lockout, and a reset would hand whoever runs this a working account.
    """
    import asyncio
    import getpass
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
        return _emit_error(str(exc), as_json=args.json)

    # The same M-31 guard _audit_verify carries, and it matters identically here: a SQLite store is
    # CREATED on open, so a typo'd path would yield a fresh empty DB and report "no such user" --
    # which reads as "you got the username wrong" when the truth is "you got the DATABASE wrong".
    if settings.store.backend == StoreBackend.SQLITE and not Path(settings.store.path).exists():
        return _emit_error(
            f"no store at {settings.store.path} — refusing to create one and report a false "
            f"'no such user' (check --db / [store].path)",
            as_json=args.json,
        )

    async def run() -> tuple[str, float | None]:
        store = await open_store(settings.store)
        try:
            user = await store.get_user_by_username(args.username)
            if user is None:
                return ("no-such-user", None)
            was = user.locked_until
            # Reuse the shipped write rather than adding a protocol method. `record_login_failure`
            # with zero attempts and no deadline is exactly "the lockout state is cleared", and it is
            # already implemented on all backends -- so this needs no migration and no store change.
            # The name reads oddly at a call site that UNLOCKS, which is why it is explained here.
            await store.record_login_failure(user.id, failed_attempts=0, locked_until=None)
            await store.record_audit(
                "auth.admin_unlocked",
                actor=f"cli:{getpass.getuser()}",
                detail=json.dumps({"username": args.username, "was_locked_until": was}),
            )
            return ("unlocked", was)
        finally:
            await store.close()

    outcome, was = asyncio.run(run())
    if outcome == "no-such-user":
        return _emit_error(f"no local account named {args.username!r}", as_json=args.json)
    if args.json:
        print(json.dumps({"ok": True, "username": args.username, "was_locked_until": was}))
    else:
        state = "was not locked" if was is None else f"was locked until epoch {was:.0f}"
        print(f"OK: cleared lockout for {args.username!r} ({state}); the password is UNCHANGED")
    return 0


def _audit_verify(args: argparse.Namespace) -> int:
    import asyncio
    from pathlib import Path

    from pydantic import ValidationError

    from messagefoundry.config.settings import StoreBackend, load_settings
    from messagefoundry.store.base import open_store

    # Resolve the anchor FIRST: it is a pure argv/file error, so it should not depend on a config load
    # succeeding, and refusing it early keeps a typo from costing a store open.
    resolved = _resolve_expected_anchor(args)
    if isinstance(resolved, int):
        return resolved
    expected_anchor = resolved

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
            return await store.verify_audit_chain(expected_anchor=expected_anchor)
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


def _audit_anchor(args: argparse.Namespace) -> int:
    """Print ``COUNT:HEAD`` — the audit log's external anchor, to be held OUT-OF-BAND.

    The hash chain links each row to its predecessor, so deleting the NEWEST rows leaves a shorter
    chain that still verifies: ``audit-verify`` alone reports OK on a truncated log. Comparing against
    an anchor recorded elsewhere is what makes that visible, and this subcommand is how an operator
    gets one. The anchor is a row count plus a digest — no PHI, no secret — so it is safe to store in
    a ticket, an object store, or a compliance job's own database.
    """
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

    # The SAME M-31 guard as _audit_verify, and it matters MORE here: opening a SQLite store creates
    # it, so a typo'd path would mint a fresh empty DB and print `0:` — an anchor OF NOTHING, which a
    # later verify against the wrong database would then happily confirm.
    if settings.store.backend == StoreBackend.SQLITE and not Path(settings.store.path).exists():
        print(
            f"error: no audit database at {settings.store.path} — refusing to create one and print "
            f"an anchor of an empty log (check --db / [store].path)",
            file=sys.stderr,
        )
        return 2

    async def run() -> tuple[int, str]:
        store = await open_store(settings.store)
        try:
            return await store.audit_anchor()
        finally:
            await store.close()

    count, head = asyncio.run(run())
    anchor = f"{count}:{head}"
    if args.json:
        _print_json({"count": count, "head": head, "anchor": anchor}, compact=True)
    else:
        print(anchor)
    if count == 0:
        # Same reasoning as the verify twin: an empty log on a real DB is legitimate, and at a glance
        # indistinguishable from having anchored the wrong database (M-31).
        print(
            "warning: the audit log is empty — confirm this is the intended database.",
            file=sys.stderr,
        )
    return 0


def _rekey_audit(args: argparse.Namespace) -> int:
    """Enable HMAC keying of an EXISTING keyless audit chain (#190-D migration).

    This is the owner-visible fork the spec asked for: fresh encrypted stores auto-key from row 1, but
    an already-deployed keyless encrypted store only becomes keyed through this explicit, **non-silent**
    step — never on ``open()``. It requires the store encryption key (``MEFOR_STORE_ENCRYPTION_KEY``),
    FIRST re-verifies the existing keyless chain (refusing to bless a broken/forged one), then sets the
    keying watermark to the next id without rewriting any existing ``row_hash``. Run with the engine
    stopped so no concurrent append races the watermark move."""
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

    # Refuse to create-and-key a fresh empty SQLite DB from a typo'd path (mirrors _audit_verify M-31).
    if settings.store.backend == StoreBackend.SQLITE and not Path(settings.store.path).exists():
        print(
            f"error: no audit database at {settings.store.path} — refusing to create one "
            f"(check --db / [store].path)",
            file=sys.stderr,
        )
        return 2

    async def run() -> tuple[bool, str]:
        store = await open_store(settings.store)
        try:
            return await store.rekey_audit_chain()
        finally:
            await store.close()

    ok, message = asyncio.run(run())
    print(("OK: " if ok else "FAIL: ") + message)
    return 0 if ok else 1


def _rotate_key(args: argparse.Namespace) -> int:
    """Re-encrypt every cipher-covered value under the active key (WP-5 key rotation, ASVS 11.2.2).

    Run **offline** (engine stopped): set ``MEFOR_STORE_ENCRYPTION_KEY`` to the NEW active key and keep
    the prior key(s) in ``MEFOR_STORE_ENCRYPTION_KEYS_RETIRED`` so existing rows can be decrypted, then
    rotate. After it finishes, the retired key can be removed.

    **Invocation bound (ASVS 11.3.4).** ``key_id`` is a one-way SHA-256 fingerprint of the DEK, so the
    NEW key has no ``cipher_meta`` row and its persisted AES-GCM invocation count starts at zero for
    free — that IS the reset, and it is the only safe one: a "zero the active key's counter" operation
    would let an operator refresh the birthday budget of a key they never actually changed, so none is
    offered. The old key's row is retained, so re-supplying that key inherits its accumulated count.
    Rotation is also the single largest encrypt burst in the product — one per stored ciphered value —
    and it runs in THIS process on its own store handle, so those invocations are charged to the NEW
    key: the first block is reserved at open, the reserve is topped up after **every committed batch**
    (so an interrupted rotation still accounts for everything it already re-encrypted — it cannot
    silently under-count the new key), and ``store.close()`` settles the remainder exactly.
    """
    import asyncio
    from pathlib import Path

    from pydantic import ValidationError

    from messagefoundry.config.settings import StoreBackend, load_settings
    from messagefoundry.secrets_dpapi import DpapiError, DpapiUnavailable
    from messagefoundry.store.base import open_store, resolve_active_key
    from messagefoundry.store.crypto import CipherError
    from messagefoundry.store.keyprovider import KeyProviderError

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
    except (DpapiError, DpapiUnavailable, KeyProviderError) as exc:
        # KeyProviderError: a non-default [store].key_provider that is unknown or not-yet-built (an
        # external HSM/KMS/Vault provider) — fail closed with a clean exit-2, not a traceback (ADR 0019).
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
        import datetime

        from messagefoundry.store.store import SecretRotationMetaStore

        store = await open_store(settings.store)
        try:
            count = await store.reencrypt_to_active()
            # ASVS 13.3.4: stamp the DEK rotation so the watcher's clock resets automatically (rotation
            # auto-detected). The store is open under the NEW active key, so its key-id is the new
            # fingerprint; preserve the tracked-since floor. NON-SECRET (key-id + dates only).
            if isinstance(store, SecretRotationMetaStore):
                key_id = store.cipher_info().active_key_id
                if key_id:
                    today = datetime.datetime.now(tz=datetime.UTC).date().isoformat()
                    meta = await store.get_secret_rotation_meta()
                    prior = meta.get("MEFOR_STORE_ENCRYPTION_KEY")
                    await store.upsert_secret_rotation_meta(
                        "MEFOR_STORE_ENCRYPTION_KEY",
                        fingerprint=key_id,
                        tracked_since=prior.tracked_since if prior is not None else today,
                        last_rotated=today,
                    )
            return count
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


def _backup(args: argparse.Namespace) -> int:
    """Take an on-demand DR backup now (ADR 0049, #60): resolve settings + the store key, snapshot the
    store, bundle the config dir, encrypt to a ``.mfbak`` archive at the destination, restore-verify,
    and prune to keep-N. PHI-safe output (paths/counts/fingerprints only — never a body or key bytes).
    Run any time; it is read-only against the live store and writes one ``dr_backup`` audit row."""
    import asyncio

    from pydantic import ValidationError

    from messagefoundry import __version__
    from messagefoundry.config.settings import load_settings
    from messagefoundry.pipeline.dr_backup import BackupError, BackupResult
    from messagefoundry.pipeline.dr_backup import BackupRunner as _BackupRunner
    from messagefoundry.store.base import open_store

    cli: dict[str, dict[str, object]] = {}
    if args.db is not None:
        cli.setdefault("store", {})["path"] = args.db
    if args.destination is not None:
        cli.setdefault("backup", {})["destination"] = args.destination
    # On-demand backup is opt-in by invocation, so enable it for this run regardless of [backup].enabled
    # (the file flag governs only the SCHEDULED loop). The destination must still resolve.
    cli.setdefault("backup", {})["enabled"] = True
    try:
        settings = load_settings(config_path=args.service_config, cli=cli)
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        return _emit_error(str(exc), as_json=args.json)
    if not settings.backup.destination.strip():
        return _emit_error(
            "no backup destination — pass --destination or set [backup].destination (a LOCAL/UNC path)",
            as_json=args.json,
        )

    backup_settings = settings.backup.model_copy(
        update={
            "verify_after_backup": not args.no_verify,
            "full_restore_verify": args.full_verify or settings.backup.full_restore_verify,
        }
    )

    async def run() -> BackupResult | None:
        store = await open_store(settings.store)
        try:
            runner = _BackupRunner(
                store,
                backup_settings,
                store_settings=settings.store,
                config_dir=args.config,
                engine_version=__version__,
                instance=settings.ai.environment or "",
            )
            return await runner.run_once(force_config_only=args.config_only)
        finally:
            await store.close()

    try:
        result = asyncio.run(run())
    except BackupError as exc:
        return _emit_error(f"backup failed ({exc.kind}): {exc}", as_json=args.json)
    if result is None:  # leader-gated no-op (never on the single-node CLI path) — defensive
        return _emit_error("backup did not run (not leader)", as_json=args.json)
    payload = {
        "archive": result.archive_path,
        "archive_bytes": result.archive_bytes,
        "encrypted": result.encrypted,
        "config_only": result.config_only,
        "snapshot_method": result.snapshot_method,
        "key_id": result.key_id,
        "config_fingerprint": result.config_fingerprint,
        "snapshot_sha256": result.snapshot_sha256,
        "row_counts": result.row_counts,
        "verify": result.verify.status if result.verify is not None else "skipped",
        "pruned": result.pruned,
    }
    if args.json:
        _print_json(payload, compact=True)
    else:
        print(f"OK: wrote {result.archive_path} ({result.archive_bytes} bytes)")
        print(
            f"  encrypted={result.encrypted} config_only={result.config_only} key_id={result.key_id}"
        )
        print(f"  verify={payload['verify']} row_counts={result.row_counts} pruned={result.pruned}")
    return 0


def _restore_verify(args: argparse.Namespace) -> int:
    """Verify an existing ``.mfbak`` archive WITHOUT activating it (ADR 0049, #60 — 0049's owned
    primitive that ADR 0048's cold-seed activation calls): key-fingerprint precheck (a clean
    ``KEY_MISMATCH`` before any decrypt) -> decrypt -> open the embedded store read-only ->
    ``integrity_check`` + per-table row-count vs the manifest. Reports ``PASS``/``FAIL``/
    ``KEY_MISMATCH``; PHI-safe (counts + a reason only, never a body)."""
    import asyncio
    from pathlib import Path

    from pydantic import ValidationError

    from messagefoundry.config.settings import load_settings
    from messagefoundry.pipeline.dr_backup import run_restore_verify

    if not Path(args.archive).is_file():
        return _emit_error(f"no archive at {args.archive}", as_json=args.json)
    cli: dict[str, dict[str, object]] = {}
    if args.db is not None:
        cli.setdefault("store", {})["path"] = args.db
    try:
        settings = load_settings(config_path=args.service_config, cli=cli)
    except (FileNotFoundError, ValueError, ValidationError) as exc:
        return _emit_error(str(exc), as_json=args.json)

    result = asyncio.run(
        run_restore_verify(args.archive, store_settings=settings.store, full=args.full)
    )
    payload = {
        "status": result.status,
        "integrity_ok": result.integrity_ok,
        "row_counts": result.row_counts,
        "manifest_counts": result.manifest_counts,
        "reason": result.reason,
    }
    if args.json:
        _print_json(payload, compact=True)
    else:
        print(f"{result.status}: {result.reason or 'archive verified'}")
        if result.row_counts:
            print(f"  row_counts={result.row_counts}")
    # exit 0 only on PASS; FAIL/KEY_MISMATCH are non-zero so a script/cold-seed activation can gate on it.
    return 0 if result.ok else 1


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
    from messagefoundry.generators import (
        _core,
        all_types,  # noqa: F401  (registers every built-in type)
    )

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

    resolved = _resolve_offline_anchor(args)
    if isinstance(resolved, int):
        return resolved
    config_dir, service_config = resolved
    # ADR 0050 §3 / AC-6: when --service-config or --project-root is supplied, the explicit service
    # config takes precedence and check's messagefoundry.toml upward-walk is suppressed; with neither,
    # service_config is None and _find_service_toml keeps its legacy walk (no regression for the
    # documented `messagefoundry check --config config` invocation).
    report = run_checks(
        config_dir,
        messages_dir=args.messages,
        run_lint=not args.no_lint,
        strict_handler_security=args.strict_handler_security,
        handler_security_allow=frozenset(args.handler_security_allow or ()),
        service_config=service_config,
        suppress_service_toml_search=args.project_root is not None,
        # The root was already used to anchor --config/--service-config and to REQUIRE that
        # <root>/<env_dir>/<env>.toml exists; pass it on so the build check READS the values from there
        # too, rather than from wherever the shell happens to be (BACKLOG #1062).
        project_root=args.project_root,
    )
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


def _adr_analyze(args: argparse.Namespace) -> int:
    """Advisory spec-driven ADR coverage (Secure Development Standards §5). Reports acceptance-
    criteria→test link coverage, Accepted ADRs missing criteria, and open ``- [ ]`` clarifications.
    Exits 0 unless ``--strict`` and a linked test/fixture is missing — no new blocking gate by default."""
    from messagefoundry.adr_analyze import analyze_adrs

    result = analyze_adrs(args.adr_dir, repo_root=args.repo_root)
    if args.json:
        _print_json(result.to_json(), compact=True)
    else:
        with_criteria = sum(1 for r in result.reports if r.has_criteria)
        _safe_print(
            f"ADRs analyzed: {len(result.reports)} ({with_criteria} with acceptance criteria)"
        )
        for adr in result.accepted_without_criteria:
            _safe_print(f"  recommend: {adr} is Accepted with no acceptance-criteria block")
        for adr, ref in result.coverage_gaps:
            _safe_print(f"  COVERAGE GAP: {adr} links a missing test/fixture: {ref}")
        for adr, item in result.open_clarifications:
            _safe_print(f"  clarify: {adr} - open item: {item}")
        _safe_print("ok" if result.ok else "coverage gaps found (advisory)")
    return 1 if args.strict and not result.ok else 0


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
    from messagefoundry.config.settings import hop_posture_from_ai, load_settings
    from messagefoundry.config.wiring import API_LISTENER_LABEL, WiringError, load_config
    from messagefoundry.pipeline.wiring_runner import build_check_registry

    if args.action == "schema":
        # Describes the ENGINE, not a workspace: no --config, no load_config. A schema fetch must not
        # fail because some unrelated module in the user's config dir does not import, and it must
        # not trip the Windows config-source trust check (ADR 0036) merely to draw a form.
        from messagefoundry.config.connection_schema import build_schema

        _print_json(build_schema(), compact=args.json)
        return 0

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
            # Reserve the configured API listener so an edit that puts an inbound on the API's port is
            # rejected here, before it persists — same check the running engine applies.
            reserved_bindings=((API_LISTENER_LABEL, settings.api.host, settings.api.port),),
            # #200 (ADR 0092): key the posture-keyed insecure-hop refusal on THIS instance's derived
            # posture, so an edit adding a cleartext-egress hop is refused at edit time exactly as at
            # reload — rather than defaulting wrong (strictest) and failing an otherwise-valid non-prod edit.
            posture=hop_posture_from_ai(settings.ai, enforcement=settings.security.enforcement),
            # #190 (ADR 0093): resolve internal-outbound TLS hops against the [tls] internal-CA anchor at
            # edit-time build-check exactly as at reload (None-safe: default system policy = no-op).
            trust_anchor_policy=settings.tls.policy(),
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


def _codeset(args: argparse.Namespace) -> int:
    """Manage ``codesets/*.csv`` translation tables: ``list`` / ``show`` to populate the VS Code grid,
    ``upsert`` / ``rename`` / ``remove`` to save (a developer can also hand-edit the files). Offline:
    touches no network, starts no server, loads no config modules — validating a code set means
    "does this file load as a CodeSet", done by re-running the code_sets.py loader on the candidate.
    ``upsert`` writes ``.csv`` atomically with owner-only perms and rolls back on a load failure."""
    from messagefoundry.config import codeset_edit
    from messagefoundry.config.code_sets import CodeSetError, load_code_set
    from messagefoundry.config.wiring import WiringError

    # The post-write check is the REAL loader on the written file (no egress/env build-check — a code
    # set is standalone data): if the candidate .csv doesn't load, the writer rolls back.
    def validate(path: Path) -> None:
        load_code_set(path)

    try:
        if args.action == "list":
            entries = codeset_edit.list_code_sets(args.config)
            _print_json(entries, compact=args.json)
            return 0
        if args.action == "show":
            if not args.name:
                return _emit_error("--name is required for `codeset show`", as_json=args.json)
            detail = codeset_edit.show_code_set(args.config, args.name)
            _print_json(detail, compact=args.json)
            return 0
        if args.action == "upsert":
            raw = args.data if args.data is not None else sys.stdin.read()
            detail = json.loads(raw)
            if not isinstance(detail, dict):
                return _emit_error("code set: input must be a JSON object", as_json=args.json)
            fmt = detail.get("format")
            if fmt is not None and fmt != "csv":
                return _emit_error(
                    f"code set: only CSV code sets are editable here (got format {fmt!r})",
                    as_json=args.json,
                )
            result = codeset_edit.upsert_code_set(
                args.config,
                detail.get("name"),
                detail.get("columns"),
                detail.get("rows", []),
                validate=validate,
                # Create-intent (#240) from the editName signal: the grid editor passes `--name
                # <editName>` on an EDIT of an existing stem (overwrite is the intent) and OMITS it when
                # CREATING a new table — so an absent `--name` is a create and refuses to silently
                # overwrite an existing code set (mirrors the wizard/form collision refusal, PR #1081).
                create=args.name is None,
            )
        elif args.action == "rename":
            if not args.name:
                return _emit_error("--name is required for `codeset rename`", as_json=args.json)
            if not args.to:
                return _emit_error("--to is required for `codeset rename`", as_json=args.json)
            result = codeset_edit.rename_code_set(
                args.config, args.name, args.to, validate=validate
            )
        else:  # remove
            if not args.name:
                return _emit_error("--name is required for `codeset remove`", as_json=args.json)
            result = codeset_edit.remove_code_set(args.config, args.name, validate=validate)
    except json.JSONDecodeError as exc:
        return _emit_error(f"invalid code set JSON: {exc}", as_json=args.json)
    except (WiringError, CodeSetError, OSError) as exc:
        # codeset_edit raises WiringError for its own (pre-write) validation, but the post-write
        # reload callback calls load_code_set() directly, which raises the loader's own CodeSetError
        # (a sibling of WiringError, not a subclass). Catch both so a post-write reload rejection is
        # surfaced as {"error": ...} for the IDE rather than crashing with no JSON on stdout.
        return _emit_error(str(exc), as_json=args.json)
    _print_json(result, compact=args.json)
    return 0


#: The object kinds `messagefoundry impact` accepts (mirrors config.impact.RENAMEABLE_KINDS; kept as a
#: literal so building the argparse choices doesn't import the engine on every CLI invocation).
_IMPACT_KINDS = frozenset(
    {"inbound", "router", "handler", "outbound", "code_set", "reference", "lookup", "fhir_lookup"}
)


def _impact(args: argparse.Namespace) -> int:
    """Reverse-dependency pre-flight (#152): report referrers, or plan/apply a rename that rewrites an
    object AND every referent. Offline — loads the config graph, touches no network, starts no server.
    A rename is a **dry-run** (prints the edits) unless ``--apply`` writes them; ``--delete`` lists the
    live referrers that would dangle. Rename/delete are mutually exclusive."""
    from messagefoundry.config.impact import apply_rename, delete_impact, plan_rename
    from messagefoundry.config.reachability import build_reference_index
    from messagefoundry.config.wiring import WiringError, load_config

    if args.rename_to is not None and args.delete:
        return _emit_error("--rename-to and --delete are mutually exclusive", as_json=args.json)
    if args.apply and args.rename_to is None:
        return _emit_error("--apply is only valid with --rename-to", as_json=args.json)

    try:
        registry = load_config(args.config)
    except (WiringError, FileNotFoundError, OSError) as exc:
        return _emit_error(str(exc), as_json=args.json)

    index = build_reference_index(registry)

    if args.rename_to is not None:
        try:
            plan = plan_rename(registry, args.config, args.kind, args.name, args.rename_to)
        except (WiringError, OSError) as exc:
            return _emit_error(str(exc), as_json=args.json)
        result = plan.as_dict()
        if args.apply:
            try:
                applied = apply_rename(plan)
            except OSError as exc:
                return _emit_error(str(exc), as_json=args.json)
            result["applied"] = len(applied)
            result["dry_run"] = False
        else:
            result["dry_run"] = True
        _print_json(result, compact=args.json)
        return 0

    if args.delete:
        referrers = delete_impact(index, args.kind, args.name)
        result = {
            "op": "delete",
            "kind": args.kind,
            "name": args.name,
            "referrers": [_reference_dict(r) for r in referrers],
            "would_dangle": len(referrers),
        }
        _print_json(result, compact=args.json)
        return 0

    referrers = index.referrers(args.kind, args.name)
    _print_json(
        {
            "kind": args.kind,
            "name": args.name,
            "referrers": [_reference_dict(r) for r in referrers],
            "count": len(referrers),
        },
        compact=args.json,
    )
    return 0


def _reference_dict(ref: Any) -> dict[str, str]:
    """JSON view of a :class:`~messagefoundry.config.reachability.Reference` (referrer -> target edge)."""
    return {
        "referrer_kind": ref.referrer_kind,
        "referrer": ref.referrer,
        "target_kind": ref.target_kind,
        "target": ref.target,
    }


def _verify(args: argparse.Namespace) -> int:
    """On-box deployment acceptance (ADR: wheel-only verifier). Host/store/smoke/manual checks; exits
    0 iff none FAIL/ERROR (MANUAL/SKIP don't fail). The self smoke is side-effect-free (dry-run); the
    live smoke MLLP-sends one synthetic message to a running engine."""
    from pathlib import Path

    from messagefoundry.verify.report import (
        exit_code,
        render_console,
        render_json,
        render_markdown,
    )
    from messagefoundry.verify.runner import ALL_SECTIONS, run_verify

    sections = None
    if args.section:
        sections = [s.strip().lower() for s in args.section.split(",") if s.strip()]
        unknown = [s for s in sections if s not in ALL_SECTIONS]
        if unknown:
            print(
                f"unknown section(s): {', '.join(unknown)}; choices: {', '.join(ALL_SECTIONS)}",
                file=sys.stderr,
            )
            return 2

    results = run_verify(
        config_dir=args.config,
        service_config=args.service_config,
        sections=sections,
        smoke_mode=args.smoke,
        engine_host=args.engine_host,
        mllp_port=args.mllp_port,
        inbound=args.inbound,
        check_disposition=args.check_disposition,
        disposition_timeout=args.disposition_timeout,
        fed_id_token=args.fed_id_token,
        fed_jwks=args.fed_jwks,
        fed_nonce=args.fed_nonce,
    )
    print(render_console(results))
    if args.report_md:
        Path(args.report_md).write_text(render_markdown(results), encoding="utf-8")
    if args.report_json:
        Path(args.report_json).write_text(render_json(results), encoding="utf-8")
    return exit_code(results)


def _support_bundle(args: argparse.Namespace) -> int:
    """Write a secret-free / PHI-free support zip (#49): engine version + a config summary (registry
    COUNTS/names only — never settings values or secrets) + a ``/status`` snapshot built from the real
    status models + a REDACTED app-log tail. Offline: touches no network, starts no server. The status
    snapshot + log tail come from the service settings (the configured store + ``[logging].log_dir``);
    the config summary comes from ``--config``. A missing service config or store is tolerated — the
    bundle is still produced (support is most wanted when something is already broken)."""
    from pydantic import ValidationError

    from messagefoundry.config.settings import load_settings
    from messagefoundry.support import build_bundle

    settings = None
    try:
        settings = load_settings(config_path=args.service_config)
    except FileNotFoundError:
        # An explicit --service-config that doesn't exist is a user error; a default (None) just means
        # "no settings" — the bundle then carries version + config summary only.
        if args.service_config is not None:
            print(f"error: service config not found: {args.service_config}", file=sys.stderr)
            return 2
    except (ValueError, ValidationError) as exc:
        # A broken settings file shouldn't block the bundle, but warn so the operator knows the status
        # snapshot/log tail are absent because of it.
        print(
            f"warning: could not load service settings ({exc}); status/log omitted", file=sys.stderr
        )

    kwargs: dict[str, Any] = {"config_dir": args.config, "settings": settings}
    if args.log_tail_lines is not None:
        kwargs["log_tail_lines"] = args.log_tail_lines
    try:
        result = build_bundle(args.out, **kwargs)
    except OSError as exc:
        print(f"error: could not write support bundle: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote support bundle to {result.path} ({len(result.members)} members):")
    for name in result.members:
        print(f"  {name}")
    return 0


def _alert(args: argparse.Namespace) -> int:
    """Manage the operator-authored ``[[alerts.rules]]`` in the service-settings TOML (ADR 0014):
    ``list`` to populate the VS Code editor, ``add``/``remove`` to save (a developer can also hand-
    edit the file). ``add``/``remove`` re-load the whole settings file BEFORE persisting and roll
    back on failure. Offline: touches no network, starts no server. Rules apply on engine restart
    (the settings TOML is read at startup, not by ``POST /config/reload``)."""
    from pydantic import ValidationError

    from messagefoundry.config import alerts_edit
    from messagefoundry.config.settings import AlertRule, load_settings
    from messagefoundry.pipeline.alert_sinks import configured_alert_transport_names

    path = args.service_config

    if args.action == "list":
        try:
            rules = alerts_edit.list_rules(path)
        except (OSError, alerts_edit.AlertRuleError) as exc:
            return _emit_error(str(exc), as_json=args.json)
        _print_json(rules, compact=args.json)
        return 0

    def validate(settings_path: Path) -> None:
        # Re-load the file exactly as the engine does, so a structurally-broken write (or a rule the
        # full model rejects) fails at edit time and rolls back rather than at next startup.
        load_settings(config_path=settings_path)

    try:
        if args.action == "add":
            raw = args.data if args.data is not None else sys.stdin.read()
            obj = json.loads(raw)
            try:
                new_rule = AlertRule.model_validate(obj)
            except ValidationError as exc:
                return _emit_error(f"invalid alert rule: {exc}", as_json=args.json)
            # Routing cross-check at AUTHORING time. notifier_from_settings refuses a rule that routes to
            # an unconfigured transport, but that fires at the next START — so without this the editor
            # happily writes a rule that bricks the following boot with no diagnostic here. Scoped to the
            # rule being ADDED (not every rule in the file) so a file that already contains a bad rule can
            # still be repaired with `alert remove` instead of being wedged shut.
            routed = set(new_rule.transports or [])
            for step in new_rule.escalate:
                routed |= set(step.transports or [])
            if routed:
                # Only a rule that NAMES a transport can be refused, so only that case needs the settings
                # file — which keeps `alert add` working against a file that does not exist yet (the
                # from-scratch create path, where a rule routing nowhere is still perfectly valid).
                try:
                    configured = configured_alert_transport_names(
                        load_settings(config_path=path).alerts
                    )
                except (OSError, ValueError):
                    configured = (
                        set()
                    )  # unreadable/absent settings file → nothing is configured yet
                unknown = sorted(routed - configured)
                if unknown:
                    return _emit_error(
                        f"alert rule routes to unconfigured transport(s) {unknown}; this instance "
                        f"configures {sorted(configured) or 'none'}. Configure [alerts].webhook_url, or "
                        "email_smtp_host + email_from + email_to (all three), before adding the rule — "
                        "otherwise the engine refuses to start.",
                        as_json=args.json,
                    )
            result = alerts_edit.add_rule(path, obj, validate=validate)
        else:  # remove
            if args.index is None:
                return _emit_error("--index is required for `alert remove`", as_json=args.json)
            result = alerts_edit.remove_rule(path, args.index, validate=validate)
    except json.JSONDecodeError as exc:
        return _emit_error(f"invalid alert rule JSON: {exc}", as_json=args.json)
    except (alerts_edit.AlertRuleError, FileNotFoundError, ValueError, OSError) as exc:
        return _emit_error(str(exc), as_json=args.json)
    _print_json(result, compact=args.json)
    return 0


def _security(args: argparse.Namespace) -> int:
    """Show / set the ``[security]`` posture in the service-settings TOML (ADR 0118): ``show`` populates
    the VS Code ``[security]`` editor (resolved values + which are explicitly set + the secure defaults +
    the active loosenings); ``set`` saves an update JSON (a ``null`` value resets a switch to its secure
    default). ``set`` re-loads the whole settings file BEFORE persisting — which also **rejects the
    relocated legacy keys** — and rolls back on failure. Offline; applies on the next engine restart."""
    from pydantic import ValidationError

    from messagefoundry.config import security_edit
    from messagefoundry.config.settings import (
        AlertsSettings,
        AuthSettings,
        SecuritySettings,
        StoreSettings,
        load_settings,
        security_loosenings,
    )

    path = args.service_config

    # This subcommand edits [security], but security_loosenings() also reports [store]/[auth] deviations
    # (ADR 0148: one posture). Resolve those from the whole file so the list is complete. If the file will
    # not load — it may be invalid OUTSIDE [security], which must not break `security show` — fall back to
    # the shipped defaults and SAY SO via the emitted `loosenings_partial` marker, rather than silently
    # reporting a subset as if it were everything.
    _loosenings_partial = False
    _store, _auth, _alerts = StoreSettings(), AuthSettings(), AlertsSettings()
    if Path(path).exists():
        # An ABSENT file is not a degraded read — the shipped defaults ARE the effective posture there,
        # and `security show` is expected to work offline before any config exists. Only a file that
        # exists and will not resolve is partial.
        try:
            _full = load_settings(config_path=path)
            _store, _auth, _alerts = _full.store, _full.auth, _full.alerts
        except (ValidationError, tomllib.TOMLDecodeError, OSError, ValueError):
            # The specific ways a settings file fails to resolve: a schema/cross-field violation,
            # malformed TOML, an unreadable path, and the plain ValueErrors load_settings raises for a
            # bad env/section. Anything else is a programming error and must surface, not be degraded
            # into a boolean.
            _loosenings_partial = True

    def _loosenings(sec: SecuritySettings) -> list[dict[str, str]]:
        # This CLI reads a SETTINGS file and never loads the connection graph, so it cannot see ANY of
        # the three per-connection declarations — it passes empty lists and declares the gap in
        # `loosenings_scope` below, instead of reporting a settings-only view as if it were the whole
        # posture. `messagefoundry check` and GET /security/posture are the complete surfaces.
        return [
            {"switch": s, "risk": r}
            for s, r in security_loosenings(sec, _store, _auth, _alerts, (), (), ())
        ]

    #: Emitted alongside every loosening list this subcommand prints, so a reader can never mistake a
    #: degraded or settings-only report for a complete one. `partial` means [store]/[auth] could not be
    #: read at all (the file did not load); the scope string is the standing limitation above. It names
    #: ALL THREE connection-scoped deviations (#333) — naming only cleartext_accepted made the DECLARED
    #: scope itself incomplete, which is the same defect one level up.
    _loosenings_scope = {
        "loosenings_partial": _loosenings_partial,
        "loosenings_scope": (
            "settings only ([security]/[store]/[auth]/[alerts]); the per-connection "
            "cleartext_accepted, tls_allow_expired and generic-ODBC DATABASE TLS declarations are NOT "
            "included — see `messagefoundry check` or GET /security/posture"
        ),
    }

    if args.action == "show":
        try:
            raw = security_edit.read_security(path)
            resolved = SecuritySettings.model_validate(raw)
        except (OSError, security_edit.SecurityEditError) as exc:
            return _emit_error(str(exc), as_json=args.json)
        except ValidationError as exc:
            return _emit_error(f"invalid [security] in {path}: {exc}", as_json=args.json)
        _print_json(
            {
                "values": resolved.model_dump(),
                "set": sorted(raw.keys()),
                "defaults": SecuritySettings().model_dump(),
                "loosenings": _loosenings(resolved),
                **_loosenings_scope,
            },
            compact=args.json,
        )
        return 0

    def validate(settings_path: Path) -> None:
        # Re-load exactly as the engine does, so a bad value OR a relocated legacy key fails at edit time
        # and rolls back rather than at next startup.
        load_settings(config_path=settings_path)

    try:
        data = args.data if args.data is not None else sys.stdin.read()
        updates = json.loads(data)
        if not isinstance(updates, dict):
            return _emit_error(
                "security updates must be a JSON object {key: value}", as_json=args.json
            )
        # Precise per-field error before we touch the file: validate the merged [security] view.
        merged = dict(security_edit.read_security(path))
        for key, value in updates.items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        try:
            SecuritySettings.model_validate(merged)
        except ValidationError as exc:
            return _emit_error(f"invalid [security] value: {exc}", as_json=args.json)
        result = security_edit.set_security(path, updates, validate=validate)
        result["loosenings"] = _loosenings(SecuritySettings.model_validate(merged))
        result.update(_loosenings_scope)
    except json.JSONDecodeError as exc:
        return _emit_error(f"invalid security update JSON: {exc}", as_json=args.json)
    except (security_edit.SecurityEditError, FileNotFoundError, ValueError, OSError) as exc:
        return _emit_error(str(exc), as_json=args.json)
    _print_json(result, compact=args.json)
    return 0


def _safe_print(line: str) -> None:
    """Print a line, re-encoding to stdout's codec with replacement so a non-cp1252 character (an
    ADR's em-dash or ``≥``) never crashes the human output on a legacy Windows console."""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    sys.stdout.write(line.encode(enc, "replace").decode(enc) + "\n")


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
    "supervise": _supervise,
    "import": _import,
    "init": _init,
    "validate": _validate,
    "graph": _graph,
    "dryrun": _dryrun,
    "check": _check,
    "adr-analyze": _adr_analyze,
    "connection": _connection,
    "codeset": _codeset,
    "impact": _impact,
    "alert": _alert,
    "security": _security,
    "generate": _generate,
    "hl7schema": _hl7schema,
    "hl7structures": _hl7structures,
    "lens": _lens,
    "gen-key": _gen_key,
    "cert": _cert,
    "protect-key": _protect_key,
    "admin-unlock": _admin_unlock,
    "audit-verify": _audit_verify,
    "audit-anchor": _audit_anchor,
    "rekey-audit": _rekey_audit,
    "rotate-key": _rotate_key,
    "backup": _backup,
    "restore-verify": _restore_verify,
    "ai-policy": _ai_policy,
    "verify": _verify,
    "support-bundle": _support_bundle,
    "service": _service,
}


if __name__ == "__main__":
    raise SystemExit(main())
