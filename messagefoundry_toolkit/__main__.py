# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Command-line entrypoint for the MessageFoundry toolkit (ADR 0201).

    messagefoundry-toolkit adr-analyze --adr-dir docs/adr --json   # ADR criteria->test coverage

In a checkout, run it as ``python -m messagefoundry_toolkit``. Each command here is a row that
``messagefoundry.cli_surface.CLI_TIERS`` marks ``toolkit``. The engine's ``messagefoundry`` command
does not register these rows, and refuses them with a line naming this command.

The process shell around dispatch is the engine's own, ``messagefoundry.cli_common.run_cli``: stream
hardening, the last-resort exception hooks, the redacting stderr log sink and the JSON error floor.
This module never imports ``messagefoundry.__main__``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from importlib import metadata

from messagefoundry import __version__
from messagefoundry.cli_common import (
    Dispatch,
    HelpFormatter,
    _emit_error,
    _print_json,
    _safe_print,
    argv_wants_json,
    run_cli,
)
from messagefoundry.cli_surface import TOOLKIT_COMMAND
from messagefoundry.console_streams import harden_console_streams

#: The two distributions whose versions must match (ADR 0201 section 1). The toolkit's distribution
#: and command share one name, held in ``cli_surface`` so the engine's refusal names the same one.
TOOLKIT_DISTRIBUTION = TOOLKIT_COMMAND
ENGINE_DISTRIBUTION = "messagefoundry"


def main(argv: list[str] | None = None) -> int:
    # FIRST STATEMENT, as in every console entry point (BACKLOG #1875):
    # tests/test_cp1252_console_safety.py reads it here. run_cli() hardens again, which is a no-op.
    harden_console_streams()
    args = sys.argv[1:] if argv is None else argv
    mismatch = version_mismatch(metadata.version)
    if mismatch is not None:
        # Exit 2, the usage-error code, and not 1: no command ran, so no command's result is being
        # reported. _emit_error keeps the JSON-XOR-text rule, and its own return value is 1.
        _emit_error(mismatch, as_json=argv_wants_json(args))
        return 2
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
        help="root for resolving test/fixture refs (default: adr-dir/../..)",
    )
    adr_analyze.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 if any acceptance-criterion test ref is missing",
    )
    adr_analyze.add_argument("--json", action="store_true", help="emit JSON")

    return parser, _DISPATCH


def _adr_analyze(args: argparse.Namespace) -> int:
    """Advisory spec-driven ADR coverage (Secure Development Standards §5). Reports acceptance-
    criteria→test link coverage, Accepted ADRs missing criteria, and open ``- [ ]`` clarifications.

    Two exit codes, and which one a condition gets is the point of the split. A *finding* is
    advisory: a missing linked test/fixture exits 0, or 1 under ``--strict``. An *absent corpus* —
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
            print(f"error: {result.error}", file=sys.stderr)  # not _safe_print; see its docstring
        return 2
    if not args.json:
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


_DISPATCH: dict[str, Callable[[argparse.Namespace], int]] = {
    "adr-analyze": _adr_analyze,
}


if __name__ == "__main__":
    raise SystemExit(main())
