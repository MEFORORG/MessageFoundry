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
            try:
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

    dryrun = sub.add_parser("dryrun", help="run messages through the config without sending")
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
        "check", help="run validate + dryrun (+ advisory ruff/mypy) as a commit/CI gate"
    )
    check.add_argument("--config", default="samples/config", help="config modules directory")
    _add_anchor_flags(check)
    check.add_argument(
        "--messages", default=None, help="HL7 fixtures dir (dryrun gates when it has *.hl7)"
    )
    check.add_argument("--no-lint", action="store_true", help="skip the advisory ruff/mypy checks")
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
        help="statically parse one config module into its @handler row contract (never imports or "
        "executes the module; routers are out of v1 scope)",
    )
    lens_parse.add_argument(
        "module",
        help="config module .py file to parse, or '-' to read the source from stdin (the IDE re-projects "
        "the live buffer this way after a structural edit)",
    )
    lens_parse.add_argument("--json", action="store_true", help="emit JSON")

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

    import_cmd = sub.add_parser(
        "import",
        help="deterministically import a legacy integration export into code-first config modules "
        "(ADR 0086): parse the export -> emit @router/@handler modules calling the ADR 0076 vocabulary; "
        "unmapped actions become in-place TODO stubs (never silently dropped)",
    )
    import_sub = import_cmd.add_subparsers(dest="import_format", required=True)
    import_corepoint = import_sub.add_parser(
        "corepoint",
        help="import a Corepoint action-list export (SYNTHETIC-until-validated schema, ADR 0086) into "
        "one config module per channel",
    )
    import_corepoint.add_argument("export", help="path to the Corepoint action-list export (JSON)")
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

    audit_verify = sub.add_parser(
        "audit-verify", help="verify the audit-log hash chain (tamper-evidence)"
    )
    audit_verify.add_argument(
        "--service-config",
        default=None,
        help="service settings TOML (default: ./messagefoundry.toml if present)",
    )
    audit_verify.add_argument("--db", default=None, help="store path (overrides [store].path)")

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
        help="comma-separated sections to run: host,store,smoke,manual (default: all)",
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
    from messagefoundry.config.anchor import anchor_under_root, resolve_project_root
    from messagefoundry.config.settings import StoreBackend, load_settings
    from messagefoundry.config.tls_policy import (
        in_process_tls_revocation_refused,
        tls_revocation_attested,
    )

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

    # Delegated-identity precondition (#203, ASVS 13.2.1/13.3.2): when the operator declares
    # [store].require_managed_identity, refuse (production) / warn (non-production) if the store
    # authenticates with a static credential rather than a managed/delegated identity (Windows
    # Integrated / Entra). Off by default → byte-identical. Admin device posture and AD/SMTP managed
    # identity stay deployment-delegated (documented in docs/SECURITY.md), not engine-checked here.
    mi_reason = settings.store.managed_identity_precondition()
    if mi_reason is not None:
        if production:
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
    # An explicit [store].allow_unencrypted_phi=true is the loud, audited override that lets such an
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
                    "encryption, set [store].allow_unencrypted_phi=true (audited).",
                    file=sys.stderr,
                )
                return 2
            # Explicit, audited override: start keyless on a PHI instance. Emit a loud warning AND a
            # WARNING-level audit record (captured by NSSM stdout/SIEM) so the deliberate weakening is
            # never silent. (Logging isn't configured yet here, so this goes through the root logger,
            # which emits >=WARNING to stderr by default — a durable startup audit line.)
            logging.getLogger(__name__).warning(
                "AUDIT: starting keyless on a PHI instance (environment %r, data_class=phi) because "
                "[store].allow_unencrypted_phi=true — PHI is stored UNENCRYPTED at rest "
                "(at-rest encryption opt-out override).",
                env_name,
            )
            print(
                f"warning: [store].allow_unencrypted_phi=true — starting a PHI environment "
                f"({env_name!r}) keyless; PHI bodies and the summary/metadata (MRN + patient name) and "
                "error/last_error/detail columns are stored UNENCRYPTED at rest (only volume "
                "encryption protects them). Configure MEFOR_STORE_ENCRYPTION_KEY to encrypt them.",
                file=sys.stderr,
            )

    # PHI-at-rest invariant (#186b, ASVS 13.2.4): at-rest encryption is effective-by-default on ANY PHI
    # instance (data_class==phi), not only a production one — the keyless gate ABOVE already fails
    # closed in every environment unless an encryption key is configured or the audited
    # [store].allow_unencrypted_phi opt-out is set, so by the time control reaches here a PHI instance
    # necessarily has a key or the explicit opt-out. No further runtime check is added: an executable
    # re-assertion here would be unreachable dead code. Synthetic instances carry no PHI and are exempt,
    # so a dev/loopback synthetic start stays byte-identical.
    #
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

    # Egress deny-by-default effective flip (#186c, ASVS 13.2.4/13.2.5): a PRODUCTION PHI instance
    # defaults to FAIL-CLOSED egress. Unless the operator explicitly set [egress].deny_by_default, turn
    # it ON here so a transport whose per-type [egress].allowed_* list is EMPTY refuses every
    # destination of that type — closing the gap the all-or-nothing open-egress gate above leaves (a
    # partially-configured instance would otherwise allow-any the transports it did not list). The
    # opt-out is EXPLICIT + audited: writing [egress].deny_by_default=false restores the per-list opt-in
    # (empty = allow-any) posture. Gated on production PHI only — a synthetic/dev instance and a
    # non-production (staging) PHI instance stay byte-identical, so existing dev/loopback configs load
    # unchanged. Placed AFTER the open-egress gate so a fully-open production instance hits that gate's
    # refusal first. settings.egress is the same object later passed to create_managed_app, so the
    # in-place flip threads through to the wiring_runner egress enforcement (no forbidden-file edit).
    if data_class is DataClass.PHI and production:
        if "deny_by_default" not in settings.egress.model_fields_set:
            settings.egress.deny_by_default = True
            # configure_logging has not run yet (root lastResort drops < WARNING), so announce on stderr
            # like the sibling posture gates rather than logging.info.
            print(
                f"info: [egress].deny_by_default defaulted ON for a production PHI instance "
                f"({env_name!r}) — a transport with an empty [egress].allowed_* list now refuses every "
                "destination of that type (secure-by-default). Declare the permitted destinations per "
                "transport, or set [egress].deny_by_default=false to restore allow-any.",
                file=sys.stderr,
            )
        elif not settings.egress.deny_by_default:
            # Explicit, audited opt-out on a production PHI instance (mirrors allow_unencrypted_phi):
            # the operator has chosen the allow-any (empty = unrestricted) egress posture. This audit
            # line is WARNING-level so the root lastResort handler still surfaces it before
            # configure_logging.
            logging.getLogger(__name__).warning(
                "AUDIT: [egress].deny_by_default=false on a production PHI instance (environment %r) — "
                "outbound egress uses the allow-any posture (a transport with an empty allowlist may "
                "send to ANY destination of that type); the secure-by-default deny is opted out.",
                env_name,
            )
            print(
                f"warning: [egress].deny_by_default=false on a production PHI instance ({env_name!r}) "
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
        elif args.allow_insecure_bind and not (data_class is DataClass.PHI and production):
            print(
                f"warning: API bound to non-loopback host {settings.api.host!r} with "
                "--allow-insecure-bind and NO TLS; bearer tokens and PHI cross the network in "
                "cleartext — configure [api].tls_cert_file (+ tls_key_file) for real remote access.",
                file=sys.stderr,
            )
        elif args.allow_insecure_bind:
            # #200 (ADR 0092, decision 2): --allow-insecure-bind is CLAMPED to a NON production-PHI
            # instance — a production-PHI listener refuses cleartext even WITH the flag. Serving bearer
            # tokens + PHI in the clear on production is never one "I accept the risk" away.
            print(
                "error: refusing to serve the API on non-loopback host "
                f"{settings.api.host!r} without TLS on a PRODUCTION PHI instance ({env_name!r}) — "
                "--allow-insecure-bind cannot relax a production-PHI cleartext bind (#200). Configure "
                "[api].tls_cert_file for in-process TLS, or set [api].tls_terminated_upstream "
                "(+ trusted_proxies) if a proxy terminates TLS.",
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
    if not settings.api.is_loopback and settings.api.tls_terminated_upstream:
        posture_b_missing = []
        if not settings.api.proxy_intra_service_declared:
            posture_b_missing.append(
                "[api].proxy_intra_service_auth (proxy→engine hop authentication)"
            )
        if not settings.api.proxy_tls_floor_declared:
            posture_b_missing.append("[api].proxy_tls_min_version (attested proxy TLS/KEX floor)")
        if posture_b_missing and data_class is DataClass.PHI:
            missing_desc = "; ".join(posture_b_missing)
            if production:
                print(
                    "error: refusing to serve on a production PHI instance "
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
            print(
                "warning: upstream TLS terminator ([api].tls_terminated_upstream) in a PHI-carrying "
                f"environment ({env_name!r}) without: {missing_desc}. Declare "
                "[api].proxy_intra_service_auth and [api].proxy_tls_min_version before exposure — the "
                "engine cannot verify the internal hop or the proxy's TLS/KEX for itself (attestation).",
                file=sys.stderr,
            )

    # The browser ops console ([api].serve_ui, ADR 0065) is a SEPARATE optional wheel
    # (messagefoundry-webconsole) mounted same-origin in-process. Refuse serve_ui when it is absent with
    # a clean, actionable message BEFORE the exposure gates below (mirrors the sqlserver find_spec
    # precedent) — the guarded mount_ui import in create_app would otherwise RuntimeError deeper in.
    if settings.api.serve_ui:
        import importlib.util

        if importlib.util.find_spec("messagefoundry_webconsole") is None:
            print(
                "error: [api].serve_ui needs the web console package 'messagefoundry-webconsole', "
                "which is not installed; install it and retry (or unset [api].serve_ui)",
                file=sys.stderr,
            )
            return 2

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
    if settings.api.serve_ui and settings.api.tls_terminated_upstream:
        if not settings.api.public_origin:
            # Deliberate upgrade-time behavior change (owner-confirmed, ADR 0068 §7): with a
            # DECLARED reverse proxy the request Host header is client-forwardable — without the
            # exact origin, the /ui same-origin CSRF check degrades to Host comparison and the
            # WebAuthn rp_id would have anchored to attacker-influenceable input.
            print(
                "error: [api].serve_ui with [api].tls_terminated_upstream requires "
                '[api].public_origin (e.g. "https://mefor.example.org") — behind a declared '
                "reverse proxy the Host header is client-forwardable, so the browser console's "
                "same-origin CSRF check and the WebAuthn passkey origin binding need the exact "
                "external origin. Set [api].public_origin to the origin the browser uses. See "
                "docs/security/OFF-LOOPBACK-DEPLOYMENT.md (ADR 0068).",
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

    # MFA-at-exposure posture (sec-mfa-on; WP-14, ASVS 6.3.3): an off-loopback bind serving local
    # accounts puts admin authentication on the network, where a single password factor is far weaker.
    # [auth].require_mfa adds the native TOTP second factor for the Administrator role; with it off the
    # admin interface is single-factor over the wire. Since BACKLOG #187 require_mfa DEFAULTS ON (even
    # on loopback), so this gate no longer catches the common "forgot to enable it" case — it now fires
    # only when an operator has EXPLICITLY opted out ([auth].require_mfa=false) AND exposed the admin
    # interface. That explicit opt-out at exposure is exactly the posture to refuse/warn on. Mirror the
    # keyless-store / open-egress posture: refuse on a production PHI instance (the prod fail-closed
    # analogue), warn on a non-production PHI instance, stay quiet on a synthetic instance. Reached only
    # for an otherwise-permitted exposed bind (the TLS gate above ran first); the loopback default (now
    # require_mfa on) never trips it. AD/Kerberos MFA is delegated to the directory, so require_mfa only
    # gates LOCAL Administrator accounts (the bootstrap admin is one) — it is safe to leave on even on
    # an AD-only deployment.
    #
    # L5b review fix (ADR 0068 §8): the gate keys on the same EXPOSURE signal as the ladder above,
    # not the bind host alone — the runbook's RECOMMENDED topology (loopback bind BEHIND a declared
    # proxy, `ui_exposed`) puts the admin interface on the network exactly as an off-loopback bind
    # does, so a production PHI console exposed through a declared proxy with require_mfa off is
    # refused identically (extend-never-weaken).
    admin_exposed = not settings.api.is_loopback or ui_exposed
    if admin_exposed and settings.auth.enabled and not settings.auth.require_mfa:
        exposure_desc = (
            f"API bound to non-loopback host {settings.api.host!r}"
            if not settings.api.is_loopback
            else "browser console exposed through a declared reverse proxy "
            "([api].serve_ui + tls_terminated_upstream)"
        )
        if data_class is DataClass.PHI:
            if production:
                print(
                    f"error: {exposure_desc} on a production PHI "
                    f"instance ({env_name!r}) with [auth].require_mfa off; refusing to start — the "
                    "Administrator role would authenticate with a single factor over the network. "
                    "Enable native TOTP MFA with [auth].require_mfa=true (WP-14) before exposing the "
                    "API (safe even on an AD-only deployment — it gates only local Administrator "
                    "accounts).",
                    file=sys.stderr,
                )
                return 2
            print(
                f"warning: {exposure_desc} in a PHI-carrying "
                f"environment ({env_name!r}) with [auth].require_mfa off — the Administrator role is "
                "single-factor over the network. Enable [auth].require_mfa=true (WP-14 native TOTP) "
                "before exposure.",
                file=sys.stderr,
            )

    # --- #189 dual-control-at-exposure posture (ASVS 2.3.5) -----------------------------------------
    # High-value runtime actions (dead-letter replay, connection purge) complete on a SINGLE caller's
    # authority unless [approvals].enabled turns on maker-checker (a distinct second user holding
    # approvals:approve releases the request). On an off-box admin surface that concentration is the
    # weakest link: one compromised/coerced admin session can replay full-PHI dead-letters or purge a
    # connection with no second sign-off. Key on the SAME exposure signal as the MFA gate above
    # (admin_exposed = off-loopback bind OR declared-proxy ui_exposed), so a loopback default is
    # byte-identical (admin_exposed is False → this never trips) and a synthetic instance stays quiet
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
            else "browser console exposed through a declared reverse proxy "
            "([api].serve_ui + tls_terminated_upstream)"
        )
        print(
            f"warning: {approvals_exposure_desc} in a PHI-carrying environment ({env_name!r}) with "
            "[approvals].enabled off — high-value actions (dead_letter_replay, connection_purge) each "
            "complete on a single caller's authority with no second sign-off (ASVS 2.3.5). Enable "
            "dual-control with [approvals].enabled=true so a distinct approver (approvals:approve) must "
            "release them before exposure.",
            file=sys.stderr,
        )

    # --- #186(a) secure-by-default data retention (ASVS 14.2.4) --------------------------------------
    # RetentionSettings defaults every window to 0 (keep-forever) and RetentionRunner then purges
    # NOTHING, so a PHI instance accumulates PHI bodies indefinitely. Both PHI-body windows must be
    # bounded: messages_days (inbound bodies) AND dead_letter_days (dead-lettered outbound bodies stay
    # replayable, i.e. full PHI, until their own window purges them). Mirror the open-egress / MFA-at-
    # exposure posture: a PRODUCTION PHI instance with EITHER window unbounded REFUSES to start; a
    # non-production PHI instance (staging) WARNS; a synthetic/dev instance is byte-identical (starts
    # with windows=0). The explicit, audited opt-out is [retention].allow_unbounded_phi=true, which
    # downgrades the production refusal to a loud audited warning. Placed after the exposure gates so an
    # exposed instance's cleartext/MFA refusals surface first.
    if data_class is DataClass.PHI:
        unbounded_windows = [
            field
            for field, days in (
                ("messages_days", settings.retention.messages_days),
                ("dead_letter_days", settings.retention.dead_letter_days),
            )
            if days <= 0
        ]
        if unbounded_windows:
            windows_desc = ", ".join(f"[retention].{field}" for field in unbounded_windows)
            if not settings.retention.allow_unbounded_phi:
                if production:
                    print(
                        f"error: no data-retention window is configured for {windows_desc} on a "
                        f"production PHI instance ({env_name!r}); refusing to start — PHI message "
                        "bodies would be retained indefinitely (unbounded PHI at rest, ASVS 14.2.4). "
                        "Set the window(s) to a positive number of days (e.g. 30) to bound PHI at "
                        "rest; or, to deliberately retain forever, set "
                        "[retention].allow_unbounded_phi=true (audited).",
                        file=sys.stderr,
                    )
                    return 2
                print(
                    f"warning: no data-retention window is configured for {windows_desc} in a "
                    f"PHI-carrying environment ({env_name!r}) — PHI message bodies accumulate without "
                    "bound. Set the window(s) to bound PHI at rest (ASVS 14.2.4).",
                    file=sys.stderr,
                )
            elif production:
                # Explicit, audited override: unbounded PHI retention on a production instance.
                logging.getLogger(__name__).warning(
                    "AUDIT: starting a production PHI instance (environment %r) with unbounded data "
                    "retention ([retention].allow_unbounded_phi=true; %s = 0) — PHI message bodies are "
                    "retained INDEFINITELY (retention opt-out override).",
                    env_name,
                    windows_desc,
                )
                print(
                    f"warning: [retention].allow_unbounded_phi=true — a production PHI instance "
                    f"({env_name!r}) retains PHI message bodies indefinitely ({windows_desc} unset). "
                    "Configure a window to bound PHI at rest.",
                    file=sys.stderr,
                )

    # --- #188 out-of-band security notifications effective by default (ASVS 6.3.5/6.3.7) -------------
    # The per-user security-event push (lockout, password/email/roles change, new-IP admin action)
    # rides the [alerts] SMTP transport AND the [auth].notify_security_events kill-switch — api/app.py
    # builds the notifier only when BOTH are on, so with either off it is silently absent (which the
    # defaults and the off-loopback runbook never set). Mirror the retention posture: a PRODUCTION PHI
    # instance with no effective channel REFUSES to start; a non-production PHI instance WARNS;
    # synthetic/dev is byte-identical. The explicit, audited opt-out is
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
                if production:
                    print(
                        "error: no out-of-band security-notification channel is configured on a "
                        f"production PHI instance ({env_name!r}); refusing to start — account-security "
                        "events (lockout, password/roles change, new-IP admin action) would have no "
                        "push channel, only the pull-only /me/security-events feed (ASVS 6.3.5/6.3.7). "
                        "Configure the [alerts] SMTP transport (email_smtp_host + email_from) and keep "
                        "[auth].notify_security_events on; or, to rely on the pull-only feed, set "
                        "[alerts].security_notifications_required=false (audited).",
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
            elif production:
                logging.getLogger(__name__).warning(
                    "AUDIT: starting a production PHI instance (environment %r) with no security-"
                    "notification channel ([alerts].security_notifications_required=false) — "
                    "account-security events are recorded only in the pull-only /me/security-events "
                    "feed (out-of-band-notification opt-out override).",
                    env_name,
                )
                print(
                    "warning: [alerts].security_notifications_required=false — a production PHI "
                    f"instance ({env_name!r}) has no out-of-band security-event push (only the "
                    "pull-only /me/security-events feed). Configure [alerts] SMTP + "
                    "[auth].notify_security_events to enable it.",
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

    app = create_managed_app(
        store_settings=settings.store,
        config_dir=config_dir,
        registry_filter=registry_filter,
        config_reload_roots=settings.api.config_reload_roots,
        inbound_bind_host=settings.inbound.bind_host,
        allow_insecure_bind=args.allow_insecure_bind,
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
        env_values_provider=env_values,
        auth_settings=settings.auth,
        ai_settings=settings.ai,
        alerts_settings=settings.alerts,
        secrets_settings=settings.secrets,
        retention_settings=settings.retention,
        cert_monitor_settings=settings.cert_monitor,
        secret_rotation_settings=settings.secret_rotation,
        update_check_settings=settings.update_check,
        backup_settings=settings.backup,
        dr_settings=settings.dr,
        api_tls_cert_file=settings.api.tls_cert_file,
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
        tls_terminated_upstream=settings.api.tls_terminated_upstream,
        # #200 (ADR 0002): mTLS client-cert → principal allow-list, consumed by
        # security.resolve_client_cert_identity (deny-by-default; empty = cert-identity off).
        tls_client_cert_identities=settings.api.tls_client_cert_identities,
        log_dir=settings.logging.log_dir,  # GET /status app-log disk metering (#50)
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
        # ADR 0083 activation: only when in-process mTLS (client CA) AND a cert-identity map are BOTH
        # configured, swap in the scope-populating HTTP protocol so a verified peer cert reaches
        # resolve_client_cert_identity. Gated on both so a mutual-auth-only bind (console mTLS, no map)
        # and every non-mTLS bind keep the stock protocol — no behaviour change without a client CA + map.
        if settings.api.tls_client_ca_file and settings.api.tls_client_cert_identities:
            from messagefoundry.api.tls_client_cert import client_cert_http_protocol_class

            run_kwargs["http"] = client_cert_http_protocol_class()
    from messagefoundry.last_resort import install_excepthook
    from messagefoundry.redaction import safe_exc

    install_excepthook()  # last-resort main-thread hook: an uncaught exception logs PHI-redacted (16.5.4)
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


def _dryrun(args: argparse.Namespace) -> int:
    from messagefoundry.config.wiring import WiringError, load_config
    from messagefoundry.pipeline.dryrun import dry_run, read_messages

    resolved = _resolve_offline_anchor(args)
    if isinstance(resolved, int):
        return resolved
    config_dir, _ = resolved
    try:
        reg = load_config(config_dir)
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

    # Traced dry-run (ADR 0072): a sys.settrace execution trace of each Router/Handler, byte-identical
    # in disposition/routing to a plain dryrun. Preview-only and additive — no dispatch change. Assigned
    # locals + msg writes are PHI, so they honor the same --show-phi gate.
    if args.trace is not None:
        from messagefoundry.pipeline.dryrun_trace import trace_dry_run

        traced: list[dict[str, Any]] = []
        try:
            for source, path, raw in messages:
                entry = trace_dry_run(reg, raw, inbound=args.inbound, show_phi=show_phi)
                traced.append({"source": source, "path": path, **entry})
        except (ValueError, KeyError) as exc:  # e.g. ambiguous/unknown --inbound
            return _emit_error(str(exc), as_json=args.json)
        _print_json(traced, compact=args.json)
        return 0

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
    return _lens_parse(args)


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
            handlers = parse_source(sys.stdin.buffer.read().decode("utf-8"), module=module_label)
        else:
            module_label = args.module
            handlers = parse_module(args.module)
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
            rewritten = rewrite_source(_read_stdin(), edit, module="<stdin>")
        else:
            rewritten = rewrite_module(args.module, edit)
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
    print(
        f"Imported {len(result.channels)} channel(s) into {args.out} "
        f"({result.total_mapped} action(s) mapped, {result.total_unmapped} left as TODO stubs):"
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
        print(f"  {c.filename} ({c.mapped} mapped){note}{renamed}")
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
        service_config=service_config,
        suppress_service_toml_search=args.project_root is not None,
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
            posture=hop_posture_from_ai(settings.ai),
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
                AlertRule.model_validate(obj)  # precise per-field error before we touch the file
            except ValidationError as exc:
                return _emit_error(f"invalid alert rule: {exc}", as_json=args.json)
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
    "generate": _generate,
    "hl7schema": _hl7schema,
    "hl7structures": _hl7structures,
    "lens": _lens,
    "gen-key": _gen_key,
    "protect-key": _protect_key,
    "audit-verify": _audit_verify,
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
