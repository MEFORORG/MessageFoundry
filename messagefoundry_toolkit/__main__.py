# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Command-line entrypoint for the MessageFoundry toolkit (ADR 0201).

    messagefoundry-toolkit init      ./my-config-repo                       # scaffold a config repo
    messagefoundry-toolkit generate  --type ADT --count 5 --out ./out/adt   # synthetic HL7
    messagefoundry-toolkit hl7schema --json                                 # HL7 field schema
    messagefoundry-toolkit lens schema --json                               # Steps-view param schema
    messagefoundry-toolkit lens parse ./config/IB_DEMO.py --json            # Steps-view rows
    messagefoundry-toolkit impact --config ./config router demo_router      # who references it
    messagefoundry-toolkit import corepoint ./export.xml --out ./config     # legacy import
    messagefoundry-toolkit adr-analyze --adr-dir docs/adr --json            # ADR criteria->test coverage

In a checkout, run it as ``python -m messagefoundry_toolkit``. Each command here is a row that
``messagefoundry.cli_surface.CLI_TIERS`` marks ``toolkit``. The engine's ``messagefoundry`` command
does not register these rows, and refuses them with a line naming this command. Heavy imports are
deferred per command, as on the engine's command, so a quick ``lens schema`` call stays cheap.

The process shell around dispatch is the engine's own, ``messagefoundry.cli_common.run_cli``: stream
hardening, the last-resort exception hooks, the redacting stderr log sink and the JSON error floor.
This module never imports ``messagefoundry.__main__``.
"""

from __future__ import annotations

from messagefoundry.remotedebug import install_remote_debug_guard

# The engine command's guard against an injected script (vault BACKLOG #2742), installed the same way
# and for the same reason: `impact` loads and runs config modules, `lens rewrite` and
# `import corepoint` read operator input, so the commands that left the engine's command keep the
# hook they had there (ADR 0201 slice 4). Put nothing above this call but its import.
install_remote_debug_guard()

# E402 on each import below: they follow the install call above on purpose.
import argparse  # noqa: E402
import sys  # noqa: E402
from collections.abc import Callable  # noqa: E402
from importlib import metadata  # noqa: E402
from typing import Any  # noqa: E402

from messagefoundry import __version__  # noqa: E402
from messagefoundry.cli_common import (  # noqa: E402
    Dispatch,
    HelpFormatter,
    _emit_error,
    _load_operator_json,
    _OperatorJsonError,
    _print_json,
    _safe_print,
    argv_refusal_code,
    argv_wants_json,
    run_cli,
)
from messagefoundry.cli_surface import TOOLKIT_COMMAND  # noqa: E402
from messagefoundry.console_streams import harden_console_streams  # noqa: E402
from messagefoundry.logging_setup import install_filtered_last_resort  # noqa: E402
from messagefoundry.odbc_env import disable_driver_manager_pooling  # noqa: E402
from messagefoundry.terminal_text import escape_for_terminal  # noqa: E402

#: The two distributions whose versions must match (ADR 0201 section 1). The toolkit's distribution
#: and command share one name, held in ``cli_surface`` so the engine's refusal names the same one.
TOOLKIT_DISTRIBUTION = TOOLKIT_COMMAND
ENGINE_DISTRIBUTION = "messagefoundry"


def main(argv: list[str] | None = None) -> int:
    # FIRST STATEMENT, as in every console entry point (BACKLOG #1875):
    # tests/test_cp1252_console_safety.py reads it here. run_cli() hardens again, which is a no-op.
    harden_console_streams()
    # BACKLOG #3768: before parsing, as the engine's main() does, so a record no handler takes
    # meets the filter chain. A second main() in one process builds nothing new.
    install_filtered_last_resort()
    args = sys.argv[1:] if argv is None else argv
    mismatch = version_mismatch(metadata.version)
    if mismatch is not None:
        # Exit 2, the usage-error code, and not 1: no command ran, so no command's result is being
        # reported. _emit_error keeps the JSON-XOR-text rule, and its own return value is 1.
        _emit_error(mismatch, as_json=argv_wants_json(args), code=argv_refusal_code(args))
        return 2
    # run_cli's JSON error floor adds `lens rewrite`'s generic code itself (argv_refusal_code).
    return run_cli(args, _build_parser)


def version_mismatch(version_of: Callable[[str], str]) -> str | None:
    """The refusal line when the installed toolkit and engine differ in version, or None (AC-4).

    ``version_of`` is ``importlib.metadata.version``, passed in so a test can supply the metadata.
    It compares METADATA WITH METADATA, never with the engine's live ``__version__``: the question
    is which two distributions pip installed side by side. ``pip install -U messagefoundry``
    upgrades the engine past the toolkit's ``==`` pin with only a resolver warning and exit 0, so
    the pin alone does not hold the pair together.

    With no toolkit metadata the check is skipped. That is every dev and CI environment, where the
    toolkit is imported from the checkout beside the engine and the two cannot differ. With toolkit
    metadata and no engine metadata, the pair cannot be checked, so the line refuses it.
    """
    try:
        toolkit = version_of(TOOLKIT_DISTRIBUTION)
    except metadata.PackageNotFoundError:
        return None
    try:
        engine = version_of(ENGINE_DISTRIBUTION)
    except metadata.PackageNotFoundError:
        engine = "not installed"
    if engine == toolkit:
        return None
    return (
        f"{TOOLKIT_DISTRIBUTION} {toolkit} runs only beside {ENGINE_DISTRIBUTION} {toolkit}, but "
        f"the installed {ENGINE_DISTRIBUTION} is {engine}. Install the two at one version."
    )


def _build_parser() -> tuple[argparse.ArgumentParser, Dispatch]:
    """Build the toolkit's argument parser, and return it with the dispatch map.

    Building has no side effect, as with the engine's builder, so a test can read the toolkit's
    command surface without running ``main()``. The map returned is :data:`_DISPATCH` itself.
    """
    parser = argparse.ArgumentParser(
        prog=TOOLKIT_COMMAND,
        description=__doc__,
        formatter_class=HelpFormatter,
        allow_abbrev=False,  # the pre-parse refusal reads --help and --version by exact spelling
    )
    parser.add_argument("--version", action="version", version=f"{TOOLKIT_COMMAND} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    adr_analyze = sub.add_parser(
        "adr-analyze",
        help="advisory spec-driven ADR coverage: acceptance-criteria->test links, missing criteria, "
        "open clarifications (Secure Development Standards section 5)",
    )
    adr_analyze.add_argument(
        "--adr-dir",
        default="docs/adr",
        help="ADR directory (default: docs/adr). Exits 2, with or without --strict, if it is "
        "missing, is not a directory, or holds no ADR",
    )
    adr_analyze.add_argument(
        "--repo-root",
        default=None,
        help="root for resolving test/fixture refs (default: adr-dir/../..; required when adr-dir "
        "sits directly under a drive or filesystem root)",
    )
    adr_analyze.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 if any acceptance-criterion test ref is missing",
    )
    adr_analyze.add_argument("--json", action="store_true", help="emit JSON")

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
    lens_rewrite.add_argument(
        "--typed-only",
        action="store_true",
        help="refuse at least the edits known to carry raw Python source - a 'paste_block', an "
        "if/elif 'test', and a move or delete of code not shown as typed steps (default off; an "
        "analyst-facing editor must set it)",
    )
    # `lens rewrite` has no --json flag, yet every error it reports is JSON on stdout. Setting the
    # attribute lets `main` treat it as a --json command: its logging goes to stderr (BACKLOG #1489),
    # and an uncaught exception still yields `{"error": ...}` (#1863). `_lens_rewrite` never reads it.
    lens_rewrite.set_defaults(json=True)

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
    import_corepoint.add_argument(
        "--force",
        action="store_true",
        help="replace modules already in --out under the names this import writes (without it, an "
        "existing module is refused and nothing is written)",
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

    return parser, _DISPATCH


def _adr_analyze(args: argparse.Namespace) -> int:
    """Advisory spec-driven ADR coverage (Secure Development Standards §5). Reports acceptance-
    criteria→test link coverage, Accepted ADRs missing criteria, and open ``- [ ]`` clarifications.

    Two exit codes, and which one a condition gets is the point of the split. A *finding* is
    advisory: a missing linked test/fixture, or one outside the repository root, exits 0, or 1
    under ``--strict``. An *absent corpus*, or an ADR directory with no grandparent to default
    the repository root to —
    :attr:`~messagefoundry_toolkit.adr_analyze.AnalysisResult.error`, defined at
    :func:`~messagefoundry_toolkit.adr_analyze.analyze_adrs` — exits **2 with or without
    ``--strict``**, because the analyzer never ran. 2 and not 1 keeps "could not start" apart from
    "ran and reported a problem", the same split the engine's ``_emit_store_open_error`` spends 2 on;
    and not 0 because this subcommand is otherwise unfailable by default, so a withdrawn ADR set
    would silently turn a failing report into a passing one.

    That split is between this command's own codes. It does **not** separate 2 from argparse's own
    usage-error 2, so a caller that must tell a withdrawn corpus from a mistyped flag has to read
    the output, not the code. Every subcommand here inherits that, ``--json`` disambiguates it, and
    widening it was not worth a third code."""
    from messagefoundry_toolkit.adr_analyze import analyze_adrs

    result = analyze_adrs(args.adr_dir, repo_root=args.repo_root)
    if args.json:
        _print_json(result.to_json(), compact=True)
    if result.error is not None:
        # JSON on stdout XOR the human line on stderr. Emitting both would reorder under `2>&1`: a
        # piped stdout is block-buffered and stderr is not, so the error line would land ahead of
        # the JSON and break the parse it was meant to protect. The JSON body is the full report
        # with `error` inside it, and so is NOT _emit_store_open_error's bare {"error": ...}: `ok`
        # has to stay readable for a consumer that branches on it and nothing else.
        if not args.json:
            # _print_record_line's rule, on stderr: a control in the path, a symlink's resolved
            # target included, is escaped, and a non-ASCII letter prints as itself, so the
            # operator can paste most paths back; the rule doubles a backslash before a component
            # that starts with one (BACKLOG #2891).
            shown = escape_for_terminal(result.error, single_line=True, keep_printable_unicode=True)
            print(f"error: {shown}", file=sys.stderr)
        return 2
    if not args.json:
        with_criteria = sum(1 for r in result.reports if r.has_criteria)
        _print_record_line(
            f"ADRs analyzed: {len(result.reports)} ({with_criteria} with acceptance criteria)"
        )
        for adr in result.accepted_without_criteria:
            _print_record_line(f"  recommend: {adr} is Accepted with no acceptance-criteria block")
        for adr, ref in result.coverage_gaps:
            _print_record_line(f"  COVERAGE GAP: {adr} links a missing test/fixture: {ref}")
        for adr, ref in result.outside_refs:
            _print_record_line(
                f"  OUTSIDE REPO: {adr} links a path outside the repository root, "
                f"not checked: {ref}"
            )
        for adr, item in result.open_clarifications:
            _print_record_line(f"  clarify: {adr} - open item: {item}")
        _print_record_line(
            "ok" if result.ok else "coverage gaps or links outside the repository found (advisory)"
        )
    return 1 if args.strict and not result.ok else 0


def _print_record_line(line: str) -> None:
    """``_safe_print`` a line that carries record text, with each character a terminal would act
    on written as a visible escape (BACKLOG #2516). Every human stdout line goes through here, so
    a new one cannot forget the escape. The ``error:`` line on stderr does not go through here,
    but takes the same rule.

    THE RULE IS THE ENGINE'S SHARED ONE, :func:`messagefoundry.terminal_text.escape_for_terminal`
    (BACKLOG #2891), so a later hardening there reaches this command too; its docstring says what
    it escapes. ``keep_printable_unicode`` because an ADR's own text is not ASCII and its em dash
    should print as one, while the engine's ``CONTROL_CATEGORIES`` are still escaped (BACKLOG
    #2976). ``single_line`` because each call is one line of the report, so a newline or tab in an
    item cannot start a line of its own.

    The JSON output needs nothing: ``json.dumps`` already escapes every control and non-ASCII
    character. ``_safe_print`` handles only the console codec, as it does for every engine
    command."""
    _safe_print(escape_for_terminal(line, single_line=True, keep_printable_unicode=True))


def _hl7schema(args: argparse.Namespace) -> int:
    from messagefoundry_toolkit.hl7schema import hl7_schema

    _print_json(hl7_schema(), compact=args.json)
    return 0


def _hl7structures(args: argparse.Namespace) -> int:
    from messagefoundry_toolkit.hl7structures import to_json

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
    from messagefoundry_toolkit.lens_schema import op_param_schema

    _print_json(op_param_schema(), compact=args.json)
    return 0


def _lens_parse(args: argparse.Namespace) -> int:
    """``lens parse`` — emit the per-@handler row contract (ADR 0076 §3).

    Reads the source from the ``module`` file, or from stdin when it is ``-`` (the IDE re-projects the
    live buffer this way after a structural edit shifts every row coordinate). Static-only either way."""
    from messagefoundry_toolkit.lens import LensParseError, parse_module, parse_source

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
    from messagefoundry.redaction import safe_exc
    from messagefoundry_toolkit.lens import (
        REFUSAL_GENERIC,
        LensParseError,
        LensRewriteError,
        rewrite_module,
        rewrite_source,
    )

    # Read stdin as raw UTF-8 (never the Windows locale codepage) so source bytes round-trip exactly —
    # byte-stability (gate 2) would break if a non-ASCII char (the samples carry — and → in comments)
    # were re-encoded through cp1252.
    def _read_stdin() -> str:
        return sys.stdin.buffer.read().decode("utf-8")

    # Every refusal here carries a code, the generic one where no specific family applies, so a
    # consumer branching on "code" never meets a payload without it (BACKLOG #237). main()'s floor
    # adds the same generic code for an exception this function does not name.
    if args.edit is None and args.module == "-":
        return _emit_error(
            "provide the edit spec via --edit when the source is read from stdin ('-')",
            as_json=True,
            code=REFUSAL_GENERIC,
        )
    # Stdin carries either the edit spec or the source, never both, and it is decoded HERE, before
    # the rewrite runs, so this arm can only ever describe the operator's stdin. The message names
    # the position only: the exception's ``object`` is the whole input, which is never echoed.
    try:
        edit_text = args.edit if args.edit is not None else _read_stdin()
        stdin_source = _read_stdin() if args.module == "-" else None
    except UnicodeDecodeError as exc:
        return _emit_error(
            f"<stdin>: cannot read (not UTF-8: {safe_exc(exc)})",
            as_json=True,
            code=REFUSAL_GENERIC,
        )
    try:
        edit = _load_operator_json(edit_text, "--edit JSON")
    except _OperatorJsonError as exc:
        return _emit_error(str(exc), as_json=True, code=REFUSAL_GENERIC)
    if not isinstance(edit, dict):
        return _emit_error(
            "the edit spec must be a JSON object", as_json=True, code=REFUSAL_GENERIC
        )

    try:
        if stdin_source is not None:
            rewritten = rewrite_source(
                stdin_source,
                edit,
                module="<stdin>",
                contract=args.contract,
                typed_only=args.typed_only,
            )
        else:
            rewritten = rewrite_module(
                args.module, edit, contract=args.contract, typed_only=args.typed_only
            )
    except LensRewriteError as exc:
        # The code is the refusal family the IDE branches on (BACKLOG #237); the message stays prose.
        return _emit_error(str(exc), as_json=True, code=exc.code)
    except LensParseError as exc:
        return _emit_error(str(exc), as_json=True, code=REFUSAL_GENERIC)
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
    error + exit 1, never a traceback. A module already in ``--out`` under a name this import writes
    is refused (exit 1, naming each file, nothing written) unless ``--force`` is given."""
    from messagefoundry_toolkit.corepoint_import import CorepointImportError, import_corepoint

    try:
        result = import_corepoint(args.export, args.out, force=args.force)
    except (CorepointImportError, OSError, RecursionError) as exc:
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
    # Every generated endpoint is undeployed, whatever mapped (BACKLOG #1130), so say so every time:
    # a fully mapped import would otherwise read as ready to run while the engine binds nothing.
    # The wording holds for both layers: an XML endpoint is a placeholder to replace, a JSON one is
    # export text to review, and the generated module's own TODO says which.
    print(
        "\nEvery endpoint is emitted deployed=False and binds nothing. Follow the endpoint TODO in "
        "each generated module, then drop deployed=False."
    )
    return 0


def _init(args: argparse.Namespace) -> int:
    """Scaffold a new config repo into ``args.dir`` (starter feed + environments + CI + a pinned engine)."""
    from pathlib import Path

    from messagefoundry_toolkit.scaffold import scaffold

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
    print("  pip install -r requirements-dev.txt    # the toolkit, on an authoring machine only")
    print("  messagefoundry check --config config --messages messages/sets")
    print("  python -P -X disable-remote-debug -m messagefoundry serve --config config --env dev")
    return 0


def _generate(args: argparse.Namespace) -> int:
    from messagefoundry_toolkit.generators import (
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


#: The object kinds `messagefoundry-toolkit impact` accepts (mirrors config.impact.RENAMEABLE_KINDS; kept as a
#: literal so building the argparse choices doesn't import the engine on every CLI invocation).
#: tests/test_toolkit_cli.py holds the two equal.
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

    # A process property honoured only before pyodbc's first ODBC use, set as the engine's main()
    # sets it (BACKLOG #2049): `impact` is the one toolkit command that loads config modules, which
    # may open a database. Here, not in main(), so the Steps view's per-edit calls skip the import.
    disable_driver_manager_pooling()

    if args.rename_to is not None and args.delete:
        return _emit_error("--rename-to and --delete are mutually exclusive", as_json=args.json)
    if args.apply and args.rename_to is None:
        return _emit_error("--apply is only valid with --rename-to", as_json=args.json)

    try:
        # allow_empty: `impact` is the CLI front door to the SAME rename/delete pre-flight
        # `codeset_edit` runs (BACKLOG #1648), and reverse-dependency analysis over Routers,
        # Handlers and code sets needs no connection. Exempting the pre-flight and refusing here
        # would leave the two disagreeing about the same config.
        registry = load_config(args.config, allow_empty=True)
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


_DISPATCH: dict[str, Callable[[argparse.Namespace], int]] = {
    "adr-analyze": _adr_analyze,
    "generate": _generate,
    "hl7schema": _hl7schema,
    "hl7structures": _hl7structures,
    "impact": _impact,
    "import": _import,
    "init": _init,
    "lens": _lens,
}


if __name__ == "__main__":
    raise SystemExit(main())
