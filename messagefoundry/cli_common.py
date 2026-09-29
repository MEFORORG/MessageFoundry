# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The code a ``messagefoundry`` command line shares with any sibling command (ADR 0201 slice 1).

ADR 0201 plans a separate ``messagefoundry-toolkit`` command for the authoring tools (BACKLOG
#1192, ASVS 15.2.3). It needs the same process shell and the same output helpers the engine CLI
has, and it must never import ``messagefoundry.__main__``. So they live here, and both commands
import them:

* :func:`run_cli` is the process shell around dispatch: stream hardening, the last-resort
  exception hooks, parsing, the redacting stderr log sink and the JSON error floor.
* ``_safe_print``, ``_print_json``, ``_emit_error``, ``_load_operator_json`` and
  ``_OperatorJsonError`` are the output and input helpers the handlers share. They moved here
  verbatim from ``__main__.py``, private names included, so its handlers call them unchanged.

Process setup that one command needs and the other does not stays in that command's ``main()``,
before it calls :func:`run_cli`. The engine's ODBC pooling switch is the example.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Callable, Mapping
from typing import Any

from messagefoundry.console_streams import harden_console_streams
from messagefoundry.logging_setup import configure_stderr_logging

__all__ = ["Dispatch", "run_cli"]

#: A command's top-level subcommand names, each mapped to the handler that runs it.
Dispatch = Mapping[str, Callable[[argparse.Namespace], int]]


def run_cli(
    argv: list[str] | None,
    build_parser: Callable[[], tuple[argparse.ArgumentParser, Dispatch]],
    *,
    configures_own_logging: frozenset[str] = frozenset(),
) -> int:
    """Run one command line: harden, install the hooks, parse, dispatch, and return the exit code.

    ``build_parser`` is called, not passed in built, so the parser is built after the hooks are in
    place. That is the order the engine's ``main()`` always had. Its parser must put the subcommand
    in ``args.command``, as ``add_subparsers(dest="command", required=True)`` does, because the
    dispatch and the log-sink choice both key on it. ``configures_own_logging`` names the
    subcommands that install their own redacting root handler, so this shell gives them none.
    """
    # Every console entry point hardens its streams first (BACKLOG #1875), and a caller's main()
    # has usually done so already. Doing it here too costs nothing, because the call is idempotent,
    # and it keeps a new caller safe before its first line of output.
    harden_console_streams()

    # The last-resort hooks are a PROCESS property, so they are installed here, once, for every
    # subcommand (BACKLOG #1674). `last_resort` states the ASVS 16.5.4 guarantee that an unhandled
    # error can never escape as a raw traceback quoting a PHI-bearing value; until this call site they
    # were installed inside `_serve` only, leaving the other 33 subcommands unguarded. `dryrun`,
    # `audit-verify` and `backup` open the store, so an uncaught exception from one of them is the
    # case that could carry a field value.
    #
    # INSTALLING THE HOOK CHANGES NO EXIT CODE: the interpreter still exits 1 after calling
    # `sys.excepthook`. That is why this shape was taken over the alternative of wrapping the dispatch
    # and exiting 2, which would have made every CLI exit-code assertion in the suite a fresh question.
    # The dispatch IS now wrapped (BACKLOG #1863, at the foot of this function), but it returns 1,
    # so that reasoning still holds. The hooks stay: they cover everything outside that `try`.
    #
    # LATE IMPORT, DELIBERATELY. Two `tests/test_config_anchoring.py` monkeypatches target the module
    # attribute `messagefoundry.last_resort.install_excepthook`; importing the name at module scope
    # here would bind it before they can patch it, and they would silently stop applying.
    from messagefoundry.last_resort import install_excepthook, install_thread_excepthook

    install_excepthook()
    # The sibling hook for every OTHER thread (BACKLOG #1055), which had the identical serve-only gap.
    # sys.excepthook does not cover them, and the engine runs non-asyncio threads whose except clauses
    # are deliberately narrow -- the sandbox session's raw stdout reader catches only OSError -- so
    # anything else would otherwise reach the stdlib default and print an unredacted traceback to the
    # NSSM-captured stderr.
    install_thread_excepthook()

    parser, dispatch = build_parser()
    args = parser.parse_args(argv)
    # A `--json` subcommand's stdout is a machine-parsed document, so NOTHING else may write there
    # (BACKLOG #1489). The engine's default log sink is stdout too, and one log line ahead of the
    # payload makes `json.loads` raise `Extra data: line 1 column 5`, because the text format opens
    # with the ISO timestamp: `2026` parses as a number and the payload becomes trailing garbage.
    # It cost real CI time before it was fixed; the census lives on the ledger item, with its
    # provenance, rather than being restated here.
    #
    # DECIDED HERE, and not in `logging_guard`, which is where the symptom shows up. That module
    # writes its rollover notice to the ROLLED SINK on purpose: the notice landing is the proof that
    # the replacement stream accepted a write, which is precisely what separates stage 1 (healed)
    # from stage 2 (unwritable). Move the notice and the fail-closed halt loses its trigger. The
    # collision is two contracts on one file descriptor, and the CLI is what owns that choice.
    #
    # `configure_stderr_logging` is the shipped answer to "this process's stdout is not a log
    # channel" (the ADR 0087 sandbox worker, whose stdout carries IPC frames), and it carries the
    # PHI-redaction + control-char-scrub filter chain. `serve` and `supervise` take no `--json`,
    # print no payload and are untouched: they still log to the stdout NSSM captures.
    #
    # EVERY OTHER SUBCOMMAND GETS THE SAME STDERR SINK, `--json` OR NOT (BACKLOG #1441). Before this,
    # a subcommand without `--json` ran with NO root handler, so a WARNING or above went to the
    # standard library's `logging.lastResort`: no filters and no formatter. A traceback quoting a PHI
    # segment printed as written. Redaction is a property of the HANDLER, so a process that installs
    # none has no chain at all. Stderr keeps stdout for data. The root stays at WARNING, the level
    # `lastResort` used. At least these visible changes follow:
    #   * Every such record now carries the timestamp/level/logger prefix and is redacted.
    #   * The handler is at NOTSET, so a logger given its OWN level below WARNING (an operator's
    #     `log.setLevel(logging.INFO)`, or the audit tee's) now prints those records. `lastResort`
    #     dropped them. They pass the same chain as under `serve`, which prints them too; the chain
    #     does not catch a lone identifier, so "never put PHI in a log message" still applies.
    #   * A library that puts a NullHandler on its own logger (urllib3, pynetdicom and others) had
    #     its WARNINGs DROPPED, because a NullHandler counts as "a handler found" and so skips
    #     `lastResort`. They now print, through the chain, exactly as they already do under `serve`.
    #   * A stdlib `basicConfig(...)` call in an operator's config module becomes a no-op under
    #     `dryrun`/`check`/`validate`, because basicConfig does nothing once the root has a handler.
    #     `serve` already behaves this way. The fix for an operator is a named logger, not basicConfig.
    # The audit tee's INFO records reached stderr through `ensure_logger_sink` (#1199) before this;
    # that now finds this handler and adds no second one. The exempt subcommands, and the one
    # residual the exemption leaves, are stated once at `_CONFIGURES_OWN_LOGGING` in `__main__.py`.
    #
    # Only when the root has NO handler yet, which is the state a `python -m messagefoundry` process
    # starts in. A caller that configured logging before calling main() owns its own handlers, and
    # main() does not take them away: an embedding host, or pytest, whose `caplog` capture lives on
    # the root (replacing it would empty `caplog`, as the ledger row measured). That host's handler
    # is then the host's to filter. `--json` still replaces unconditionally, because a handler left
    # in place could write to stdout and corrupt the document (#1489).
    as_json = bool(getattr(args, "json", False))
    needs_sink = args.command not in configures_own_logging and not logging.getLogger().handlers
    if as_json or needs_sink:
        configure_stderr_logging()
    # THE FLOOR UNDER `_emit_error`'s --json CONTRACT (BACKLOG #1863). Without this `try`, an exception
    # no subcommand arm names went to `sys.excepthook`: one redacted CRITICAL line on stderr, exit 1,
    # and stdout EMPTY. A machine consumer could not tell that from a command with no output. Now it
    # gets `{"error": ...}` on stdout under --json. Text mode prints nothing new, as before; only the
    # log line appears, on whatever sink logging uses (stdout for `serve`/`supervise`, per NSSM).
    #
    # The exit code stays 1, the same 1 the hook path gave, so #1674's reasoning above still holds.
    # `report_uncaught` is the hook's own rendering, so the stderr line is unchanged and the stdout
    # text is the same PHI-redacted string. Never format `exc` here.
    #
    # `Exception`, not `BaseException`: Ctrl-C and `SystemExit` keep their own meaning. A command that
    # printed part of its JSON before raising still leaves two documents on stdout; this catch cannot
    # take back what was already written.
    try:
        return dispatch[args.command](args)
    except Exception as exc:
        from messagefoundry.last_resort import report_uncaught

        text = report_uncaught(exc)
        return _emit_error(text, as_json=True) if as_json else 1


def _safe_print(line: str) -> None:
    """Print a line, re-encoding to stdout's codec with replacement so a non-cp1252 character (an
    ADR's em-dash or ``≥``) never crashes the human output on a legacy Windows console.

    STDOUT ONLY, AND DO NOT EXTEND IT TO STDERR. ``sys.stdout`` carries ``surrogateescape``, which
    still raises on an unencodable codepoint; ``sys.stderr`` carries ``backslashreplace`` and never
    raises. So stderr needs no protection, and routing an error line through this would be a
    downgrade: it would blank a character stderr prints as a readable escape, handing an operator a
    path they cannot paste back. ``tests/test_cp1252_console_safety.py`` measures that asymmetry."""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    sys.stdout.write(line.encode(enc, "replace").decode(enc) + "\n")


def _print_json(data: object, *, compact: bool) -> None:
    print(json.dumps(data) if compact else json.dumps(data, indent=2))


class _OperatorJsonError(Exception):
    """Operator-supplied JSON that ``json`` would not decode -- malformed, or nested too deep.

    A private CLI signal raised ONLY by :func:`_load_operator_json`, never by engine code. The TYPE
    is the scope: a subcommand can catch it on a ``try`` that also wraps its edit/validate calls
    without that catch ever attributing a downstream fault to the operator's input."""


def _load_operator_json(raw: str, what: str) -> Any:
    """Decode operator-supplied JSON (an argument or stdin), reporting either failure as
    :class:`_OperatorJsonError` with ``what`` naming which input was at fault.

    ``json`` guards its own decode depth and raises ``RecursionError`` -- a ``RuntimeError``, and
    neither a ``JSONDecodeError`` nor a ``ValueError`` -- so before this helper existed, deeply
    nested input escaped every subcommand that reads operator JSON. The cost is not a traceback:
    ``main`` installs the last-resort excepthook (BACKLOG #1674), so the escape was redacted to one
    CRITICAL line and exit 1 with **stdout empty**. That breaks :func:`_emit_error`'s contract that
    under ``--json`` the error object IS the command's machine-readable output -- measured on a real
    subprocess, a consumer piping to ``jq`` got a parse failure, and the CRITICAL line named only
    the exception type, never which input was at fault.

    BOTH conversions happen HERE, around ``json.loads`` alone, and that is what scopes them. Four of
    the five callers wrap the decode AND their edit/validate calls in ONE ``try``; raising a
    dedicated type from a function that wraps only the decode means a ``RecursionError`` (or a
    ``JSONDecodeError``) from ``upsert_connection`` or ``load_settings`` is NOT an
    ``_OperatorJsonError`` and still falls through -- so no caller's arm can blame an input nothing
    has established is at fault. The stack has already unwound to this shallow frame before either
    clause runs, so raising cannot re-trip the limit.

    Each caller keeps its OWN arm even though ``main`` now has a dispatch-level catch (BACKLOG #1863).
    That catch is only a floor: it reports the exception type and redacted message, and cannot say
    WHICH operator input was at fault. The arm here can, so it is the better report where it applies.

    DO NOT DRIVE A TEST OF THE RECURSION ARM WITH REAL DEEPLY-NESTED INPUT -- manufacture the
    exception. The depth where ``json``'s C accelerator gives out is a property of the runner, not
    of this code; ``tests/test_sandbox_codec.py::test_recursion_error_is_not_a_value_error`` is the
    canonical write-up of why, with the measurements (BACKLOG #1222).

    Both refusals are raised after the handler, so neither chains the decode error: a
    ``JSONDecodeError`` holds the whole input on ``.doc``, and operator JSON can carry a connection's
    credentials (BACKLOG #2085). Its TEXT is json's fixed reason and a position, never the input, so
    the message keeps it: that is the diagnosis an operator fixing hand-written JSON needs."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        refused = f"invalid {what}: {exc}"
    except RecursionError:
        refused = f"{what} is nested too deeply to parse"
    raise _OperatorJsonError(refused)


def _emit_error(message: str, *, as_json: bool) -> int:
    """Report a command failure on the right stream and return its exit code.

    Text goes to **stderr**. A shell redirect of a command's output --
    ``messagefoundry validate --config x > report.txt`` -- must not swallow the reason the command
    failed into the file it was writing, and ``2>/dev/null`` must be able to silence diagnostics
    without silencing results (BACKLOG #1673).

    JSON stays on **stdout**, deliberately. Under ``--json`` the error object IS the command's
    machine-readable output: a consumer piping to ``jq`` reads it there, and the non-zero exit code
    is what tells it apart from a success payload."""
    if as_json:
        print(json.dumps({"error": message}))
    else:
        print(f"error: {message}", file=sys.stderr)
    return 1
