# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ``messagefoundry check`` commit/CI gate — one callable for the git hook and the IDE.

``run_checks`` runs the project's checks against a config directory and reports a clear pass/fail,
reusing the in-process ``validate``/``dry_run`` paths (no re-shelling for the MessageFoundry-native
checks). Two checks are **required** (they can block a commit):

* ``validate`` — every config module loads and every ``inbound → router`` reference resolves.
* ``dryrun`` — *only when* a fixtures dir with ``*.hl7`` is given (searched recursively): each message
  routes through its inbound's Router/Handler(s) without erroring. A fixture under a
  ``<messages>/<inbound_name>/`` subdir is dry-run **only** against that feed (#11); a fixture not under
  such a subdir runs against **every** inbound. A fixture may also declare its expected dry-run
  disposition in a sibling ``<fixture>.expect`` file (``RECEIVED``/``UNROUTED``/``FILTERED``/``ERROR``)
  — an executable acceptance-criteria check (Secure Development Standards §5); without one the default
  is "must not ERROR". Absent fixtures → skipped (never blocks). The preview runs under
  ``[pipeline].snapshot_on_send`` (copy-on-Send, ADR 0104) resolved best-effort from this instance's
  ``messagefoundry.toml`` (same resolution as the posture check); when no settings load it falls back
  to the setting's own default (ON) — so the gate previews what the default engine actually delivers,
  never a silent OFF (#230).

A third required check, ``posture``, is **best-effort**: when a ``messagefoundry.toml`` is present
(searched from ``config_dir`` upward + the CWD) it loads the service settings and — if an active
environment is set whose security posture is unresolved (a *custom* name with no ``[ai].data_class``
/ ``[ai].production``) — it FAILS, mirroring ``serve``'s fail-closed ``require_posture()`` so the
foot-gun is caught at commit/CI time instead of at runtime. No ``messagefoundry.toml`` → SKIP.

A fourth required check, ``build-check``, runs the **posture-stamped** ``build_check_registry`` that
``serve``/``reload`` run (which ``validate`` does not): it constructs every connector with this
instance's derived security posture stamped, so a config ``serve`` would REFUSE — most importantly a
production-PHI cleartext / weakened-TLS transport hop (#200, ADR 0092) — FAILS at commit/CI time
instead of only at runtime. Fail-safe SKIP when it can't resolve a real posture (no
``messagefoundry.toml``, or settings/graph that won't load), so a bare config dir is byte-identical.

A fifth required check, ``reference-backend``, closes the ADR 0006 gap: a config declaring a
``Reference(...)`` against a ``[store] backend`` with no reference-snapshot store (SQL Server — its schema
has no ``reference`` tables) would pass this gate and then raise on every ``reference(...)`` read at run
time, post-ACK, forever. It refuses that pairing here, keyed on the DECLARED backend, mirroring the
engine's start-time refusal. Same fail-safe SKIPs as ``build-check`` (no ``messagefoundry.toml``, or
settings/config that won't load).

``ruff`` and ``mypy`` are **advisory**: run only when installed (``shutil.which``) and never block —
a non-developer author shouldn't be stopped by a lint nit. So is ``raise-fstring`` — an AST scan of the
config-dir Router/Handler modules that flags ``raise <Exc>(f"...{var}...")``, the exact pattern that can
carry free-text PHI past the exception-path redaction (``redaction.py``); it only ever **prints** a
heuristic reminder of the "never put PHI in an exception message" convention, never blocks the gate.
So is ``accepts-candidate`` — an AST scan that flags a ``@handler`` opening with a guard-filter
(``if <cond>: return []``), a filter that belongs in an ``accepts=`` router-stage predicate (ADR 0084)
where it costs 0 transactions instead of 2; also advisory (prints, never blocks).
So is ``alert-smtp-tls`` (#323 layer 3) — it reports whether the ``[alerts]`` SMTP hop AUTHENTICATES the
relay, naming the trust anchor when it does and the acknowledgment state when it does not. Advisory
because the **serve gate** is what refuses an unauthenticated alert hop on an enforcing PHI instance;
this only makes the hop's posture readable in review. It states the secure case out loud rather than
going quiet, so a passing line is never confused with a check that did not run.
Exit-code policy lives in the CLI (``__main__._check``): 0 iff no required check failed.
"""

from __future__ import annotations

import ast
import functools
import importlib.metadata
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["CheckResult", "CheckReport", "run_checks"]


@dataclass(frozen=True)
class CheckResult:
    """The outcome of one check."""

    name: str
    ok: bool
    required: bool
    skipped: bool = False
    detail: str = ""

    @property
    def blocking(self) -> bool:
        """A required check that ran and failed — the only thing that fails the gate."""
        return self.required and not self.ok and not self.skipped

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "required": self.required,
            "skipped": self.skipped,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CheckReport:
    """All check outcomes for one run."""

    results: list[CheckResult]

    @property
    def ok(self) -> bool:
        """True unless a required check ran and failed."""
        return not any(r.blocking for r in self.results)

    def to_json(self) -> dict[str, Any]:
        return {"ok": self.ok, "checks": [r.to_json() for r in self.results]}


def run_checks(
    config_dir: str | Path,
    *,
    messages_dir: str | Path | None = None,
    run_lint: bool = True,
    strict_handler_security: bool = False,
    handler_security_allow: frozenset[str] = frozenset(),
    service_config: str | Path | None = None,
    suppress_service_toml_search: bool = False,
) -> CheckReport:
    """Run the gate against ``config_dir``; ``messages_dir`` enables the dry-run check when it has
    fixtures. Set ``run_lint=False`` to skip the advisory ruff/mypy pass. ``strict_handler_security``
    (the opt-in ``--strict-handler-security``) promotes the ADR 0144 handler-security lint from
    advisory to a **blocking** (required) check. ``handler_security_allow`` adds operator-vetted import
    roots (``--handler-security-allow``) that the ``unvetted-import`` rule treats as known-good.

    ``service_config`` / ``suppress_service_toml_search`` plumb the ADR 0050 anchor (AC-6): an explicit
    ``messagefoundry.toml`` path (from ``--service-config``, resolved under ``--project-root``) is used
    directly for the posture check, and ``suppress_service_toml_search`` (set when ``--project-root`` is
    given) suppresses the legacy upward-walk so ``check`` matches ``serve``'s resolution. With both
    defaulted (today's ``messagefoundry check --config config``), the upward-walk is preserved — no
    regression.
    """
    results = [
        _check_validate(config_dir),
        _check_dryrun(
            config_dir,
            messages_dir,
            service_config=service_config,
            suppress_search=suppress_service_toml_search,
        ),
        _check_posture(
            config_dir,
            service_config=service_config,
            suppress_search=suppress_service_toml_search,
        ),
        _check_build(
            config_dir,
            service_config=service_config,
            suppress_search=suppress_service_toml_search,
        ),
        _check_reference_backend(
            config_dir,
            service_config=service_config,
            suppress_search=suppress_service_toml_search,
        ),
        # ADR 0153: name every outbound that declares cleartext_accepted, so the accepted set is visible
        # in review rather than discoverable only by reading each connection. Advisory — see the check.
        _check_cleartext_accepted(config_dir),
        # #323 layer 3: report whether the [alerts] SMTP hop authenticates the relay. The defect this
        # closes was invisible for exactly as long as nothing reported it. Advisory — see the check.
        _check_alert_smtp_tls(
            config_dir,
            service_config=service_config,
            suppress_search=suppress_service_toml_search,
        ),
    ]
    if run_lint:
        results.append(_run_tool("ruff", ["ruff", "check", str(config_dir)]))
        results.append(_run_tool("mypy", ["mypy", str(config_dir)]))
        # ADR 0144 part B (Increment 3 curation): flake8-bandit "S" over the config dir — advisory,
        # run-if-installed, the generic SAST net beside the domain-aware _check_handler_security. Keep
        # the FULL S select for breadth (it still catches weak crypto S324, unsafe yaml.load S506,
        # insecure-scheme urlopen S310, tarfile.extractall S202, mktemp S306, jinja autoescape S701,
        # XXE S320, verify=False S501/S323) but --ignore the hardcoded-secret trio S105/S106/S107: they
        # structurally false-positive on the ADR-0015 body_secrets placeholder tokens (committed PUBLIC
        # high-entropy strings) and any password-shaped literal; real secrets never appear inline here
        # (env()/MEFOR_VALUE_* substituted in the transport). Overlap with the AST ambient-authority /
        # unsafe-db-lookup rules (S102/S307/S301/S602-605/S608) is harmless for an advisory print.
        results.append(
            _run_tool(
                "ruff-security",
                ["ruff", "check", "--select", "S", "--ignore", "S105,S106,S107", str(config_dir)],
            )
        )
    # Appended AFTER the ruff/mypy advisory block. The first four are advisory (required=False, never
    # block). _check_handler_security is advisory too UNLESS strict_handler_security promotes it to a
    # required/blocking check (--strict-handler-security, ADR 0144 Increment 2).
    results.append(_check_raise_fstring(config_dir))
    results.append(_check_accepts_candidate(config_dir))
    results.append(_check_dead_config(config_dir))
    results.append(_check_send_target(config_dir))
    results.append(
        _check_handler_security(
            config_dir, strict=strict_handler_security, allow=handler_security_allow
        )
    )
    return CheckReport(results)


def _check_dead_config(config_dir: str | Path) -> CheckResult:
    """Advisory: list registered Handlers / outbound Connections / routers / lookup tables that no
    object reachable from the inbound roots references — dead config an author can remove (#176).

    Uses the reverse-reachability index (``config.reachability``), whose router->handler / handler->
    ``Send()`` / ``code_set()`` edges are **heuristic string literals** from each function's
    ``co_consts``: a dynamically-computed name is invisible (a false positive here) and a name used
    only in a docstring reads as a live reference (a false negative). So the check is **advisory**
    (prints, never blocks). A config dir that fails to load is left to ``validate`` (this check skips)."""
    from messagefoundry.config.reachability import build_reference_index
    from messagefoundry.config.wiring import WiringError, load_config

    try:
        registry = load_config(config_dir)
    except (WiringError, OSError, ImportError, SyntaxError, ValueError):
        # A broken config is reported (blocking) by validate; the advisory never crashes the gate.
        return CheckResult(
            "dead-config", ok=True, required=False, skipped=True, detail="config did not load"
        )
    dead = build_reference_index(registry).unreferenced(registry)
    if not dead:
        return CheckResult(
            "dead-config", ok=True, required=False, skipped=True, detail="no dead config"
        )
    shown = ", ".join(f"{kind}:{name}" for kind, name in dead[:8])
    more = "" if len(dead) <= 8 else f" (+{len(dead) - 8} more)"
    return CheckResult(
        "dead-config",
        ok=False,
        required=False,
        detail=f"{len(dead)} unreferenced object(s): {shown}{more}",
    )


def _check_send_target(config_dir: str | Path) -> CheckResult:
    """Advisory: flag a **literal** ``Send("...")`` target (or Router return) that names nothing
    registered — a typo the runtime would only catch post-ACK as a dead-letter (ADR 0091 AC-2).

    Uses the authoritative static wiring graph (``config.graph``): only AST-proven string literals
    are judged, so a dynamically-computed name never trips it (those are surfaced as ``dynamic``
    in ``graph --json``, not here). Advisory (prints, never blocks): the fail-closed runtime path
    (``transform_one``) remains the authority, and a config dir that fails to load is left to
    ``validate`` (this check skips)."""
    from messagefoundry.config.graph import build_wiring_graph
    from messagefoundry.config.wiring import WiringError, load_config

    try:
        registry = load_config(config_dir)
    except (WiringError, OSError, ImportError, SyntaxError, ValueError):
        return CheckResult(
            "send-target", ok=True, required=False, skipped=True, detail="config did not load"
        )
    dangling = build_wiring_graph(registry).dangling
    if not dangling:
        return CheckResult(
            "send-target",
            ok=True,
            required=False,
            skipped=True,
            detail="no dangling literal targets",
        )
    shown = "; ".join(
        f"{d.source_kind} {d.source!r} -> unknown {d.expected} {d.target!r}" for d in dangling[:5]
    )
    more = "" if len(dangling) <= 5 else f" (+{len(dangling) - 5} more)"
    return CheckResult(
        "send-target",
        ok=False,
        required=False,
        detail=f"{len(dangling)} dangling literal target(s): {shown}{more}",
    )


def _check_raise_fstring(config_dir: str | Path) -> CheckResult:
    """Advisory: flag ``raise <Exc>(f"...{var}...")`` in the config-dir Router/Handler modules — an
    f-string ``raise`` that interpolates a variable, the one pattern that can carry **free-text PHI**
    past the exception-path redaction (``redaction.py``) into the stored ``last_error``/``detail`` and
    the log. It is a heuristic reminder of the "never put PHI in an exception message" convention, not a
    hard rule: a benign interpolation (``raise ValueError(f"port {p} in use")``) trips it too, so the
    check is **advisory** (prints, never blocks).

    Scans every ``*.py`` under ``config_dir`` (helpers included — a ``_*`` helper can ``raise`` too).
    A malformed module never crashes the gate (``SyntaxError``/``OSError`` → skip that file; ``validate``
    already reports a broken module). A single file / non-dir ``config_dir`` yields no glob hits → skip.
    """
    base = Path(config_dir)
    if not base.is_dir():
        return CheckResult(
            "raise-fstring", ok=True, required=False, skipped=True, detail="not a config dir"
        )
    hits: list[str] = []
    for path in sorted(base.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, OSError):
            # A broken module is already caught by validate; never crash the advisory gate on it.
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
                continue
            args = node.exc.args
            first = args[0] if args else None
            # An f-string with at least one ``{var}`` (FormattedValue); a constant-only f-string or a
            # plain string literal is fine and not flagged.
            if isinstance(first, ast.JoinedStr) and any(
                isinstance(part, ast.FormattedValue) for part in first.values
            ):
                hits.append(f"{path.name}:{node.lineno}")
    if not hits:
        return CheckResult(
            "raise-fstring", ok=True, required=False, skipped=True, detail="no f-string raises"
        )
    shown = ", ".join(hits[:5])
    more = f" (+{len(hits) - 5} more)" if len(hits) > 5 else ""
    detail = (
        f"{len(hits)} f-string raise(s) interpolate a variable (heuristic PHI reminder — keep "
        f"identifiers out of exception messages): {shown}{more}"
    )
    return CheckResult("raise-fstring", ok=True, required=False, detail=detail)


def _handler_decorator(node: ast.AST) -> ast.Call | None:
    """The ``@handler(...)`` decorator Call on ``node`` (bare ``Name`` or dotted ``Attribute``), or None.

    Only the decorator *shape* is matched — the loader is what actually registers a handler, so this
    static heuristic deliberately does not resolve the import; a function that merely looks like a
    handler at most trips an advisory print.
    """
    if not isinstance(node, ast.FunctionDef):
        return None
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        func = dec.func
        if (isinstance(func, ast.Name) and func.id == "handler") or (
            isinstance(func, ast.Attribute) and func.attr == "handler"
        ):
            return dec
    return None


def _is_handler_def(node: ast.AST) -> bool:
    """A ``def`` decorated with ``@handler(...)``."""
    return _handler_decorator(node) is not None


def _already_declares_accepts(dec: ast.Call) -> bool:
    """True when the ``@handler(...)`` call already carries an ``accepts=`` keyword — the handler has
    adopted the seam, so a residual second-stage guard in its body is NOT an accepts-candidate to nag
    about (the guard may be one that CANNOT move to the router, e.g. it reads run-scoped state)."""
    return any(kw.arg == "accepts" for kw in dec.keywords)


def _names_forbidden_router_accessor(body: list[ast.stmt]) -> bool:
    """True when the guard-filter references ``state_get``/``response_get`` — a run-scoped read that
    FAILS OPEN in the router phase (Registry.validate rejects it in an ``accepts=`` predicate). Such a
    guard must NOT be recommended for migration: it belongs in the transform phase where the view is
    active. Scans only the leading ``if`` guard (what the advisory would tell the author to move)."""
    stmts = list(body)
    if stmts and isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant):
        stmts = stmts[1:]
    if not stmts or not isinstance(stmts[0], ast.If):
        return False
    for sub in ast.walk(stmts[0]):
        if isinstance(sub, ast.Name) and sub.id in ("state_get", "response_get"):
            return True
    return False


def _opens_with_guard_filter(body: list[ast.stmt]) -> bool:
    """True when the def's first executable statement is a bare guard-filter ``if <cond>: return []``.

    "Bare filter" = an ``if`` with no ``else``/``elif`` whose body is a single filter-return (``return``,
    ``return None``, ``return []`` or ``return ()`` — either empty container). A leading docstring is
    skipped. This is deliberately conservative: a filter buried after real transform work is a genuine
    handler concern (not an applicability rule) and is not flagged — the advisory only targets the
    leading guard that belongs in ``accepts=``.
    """
    stmts = list(body)
    # Skip a docstring first statement.
    if stmts and isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant):
        stmts = stmts[1:]
    if not stmts:
        return False
    first = stmts[0]
    if not isinstance(first, ast.If) or first.orelse or len(first.body) != 1:
        return False
    inner = first.body[0]
    if not isinstance(inner, ast.Return):
        return False
    val = inner.value
    # bare ``return`` / ``return None`` / ``return []`` / ``return ()`` are all filter-drops. The tuple
    # half matters as much as the list half: an EMPTY container of either kind partitions to no
    # deliveries (``dryrun._partition`` materialises any non-``str`` iterable — BACKLOG #341), and
    # ``return ()`` is a documented filter idiom the Steps lens already recognizes alongside ``return []``
    # (``lens.py::_is_send_return`` / ``_is_collector_init``'s sibling gate, ADR 0108 §6). Recognizing
    # only the list form made this advisory the sole place in the codebase that treated the two
    # differently — it under-flagged a `return ()` guard rather than mis-flagging, but silently.
    if val is None:
        return True
    if isinstance(val, ast.Constant) and val.value is None:
        return True
    return isinstance(val, ast.List | ast.Tuple) and not val.elts


def _check_accepts_candidate(config_dir: str | Path) -> CheckResult:
    """Advisory: flag a ``@handler`` that opens with a guard-filter (``if <cond>: return []``) — a
    filter that belongs in an ``accepts=`` router-stage predicate (ADR 0084), where it costs 0
    transactions instead of the 2 a materialized routed row charges (ADR 0051 ``txn/msg = 3 + 2H + 2N``).

    A pure heuristic reminder, never a hard rule — the author still ports the guard by hand and the
    dry-run / ``validate`` checks catch a bad port. Mirrors :func:`_check_raise_fstring` exactly in
    shape: static ``ast`` only (never imports/executes the config module), scans every ``*.py`` under
    ``config_dir`` (helpers included), skips a broken/unreadable file, and is **advisory** (prints,
    never blocks — ``required=False`` keeps the gate's "0 iff no required check failed" exit policy).
    """
    base = Path(config_dir)
    if not base.is_dir():
        return CheckResult(
            "accepts-candidate", ok=True, required=False, skipped=True, detail="not a config dir"
        )
    hits: list[str] = []
    for path in sorted(base.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, OSError):
            # A broken module is already caught by validate; never crash the advisory gate on it.
            continue
        for node in ast.walk(tree):
            dec = _handler_decorator(node)
            if dec is None:
                continue
            # narrowed by _handler_decorator; assert for the type checker.
            assert isinstance(node, ast.FunctionDef)
            # Skip a handler that already declares accepts= (it adopted the seam; a residual guard is a
            # legitimate second-stage filter) and one whose guard reads fail-open router-phase state
            # (state_get/response_get) — validate() would reject moving THAT guard, so don't recommend it.
            if _already_declares_accepts(dec):
                continue
            if _opens_with_guard_filter(node.body) and not _names_forbidden_router_accessor(
                node.body
            ):
                hits.append(f"{path.name}:{node.lineno} ({node.name})")
    if not hits:
        return CheckResult(
            "accepts-candidate", ok=True, required=False, skipped=True, detail="no guard-filters"
        )
    shown = ", ".join(hits[:5])
    more = f" (+{len(hits) - 5} more)" if len(hits) > 5 else ""
    detail = (
        f"{len(hits)} handler(s) open with a guard-filter (`if …: return []`) — consider declaring it "
        f"as `accepts=` so it declines at routing time (0 transactions, not 2; ADR 0084): {shown}{more}"
    )
    return CheckResult("accepts-candidate", ok=True, required=False, detail=detail)


# --- ADR 0144: advisory security lint over admin-authored Router/Handler code -------------------
# A stdlib-`ast` scan (mirroring _check_raise_fstring) that flags four families of risky patterns in
# the config-dir Router/Handler modules. It is a documented COMPENSATING control for ASVS 15.2.5 /
# 15.2.4 — the *static* half; the opt-in ADR 0087 subprocess sandbox is the runtime half. Static
# analysis catches only a fraction of insecure code, so it is a **filter, not a boundary**, and is
# therefore **advisory** (required=False, prints, never blocks) — a non-developer feed author is
# never stopped by a lint nit (the same principle as ruff/mypy in run_checks).

# phi-to-log: the message body reaching a print()/INFO+ log call (CLAUDE.md §9 "never log full
# bodies at INFO or above"). DEBUG is below the bar and excluded.
_LOG_SINK_ATTRS = frozenset(
    {"info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
)
# control-metadata kwargs that never carry message content. NOTE: ``extra=`` is deliberately NOT here
# — it is a structured-logging PHI channel, so it is scanned like any other content argument.
_LOG_META_KWARGS = frozenset({"exc_info", "stack_info", "stacklevel"})
# An attribute sink counts only on a *logger-shaped* receiver — a name ending in log/logger (log,
# _log, audit_log, logger, _logger), the ``logging`` module, or a ``getLogger(...)`` result — so a
# FHIR/ACK/validation builder like ``outcome.error(...)`` or ``warnings.warn(...)`` is not a sink.
_LOGGER_NAME_SUFFIXES = ("log", "logger")

# ambient-authority: reaching past the sanctioned Send/db_lookup boundary (CLAUDE.md §2/§8).
_AMBIENT_BARE_NAMES = frozenset({"eval", "exec", "compile", "__import__"})
_AMBIENT_ROOTS = frozenset(
    {"subprocess", "socket", "requests", "httpx", "pickle", "marshal", "shelve", "ctypes", "shutil"}
)
# read-only socket lookups (host-local, no network I/O) — exempt from the socket root so stamping the
# sending host into MSH-3/MSH-4 stays clean.
_SOCKET_READONLY = frozenset(
    {"gethostname", "getfqdn", "gethostbyname", "gethostbyaddr", "getservbyname", "getprotobyname"}
)
_AMBIENT_OS_PATHS = frozenset(
    {
        "os.system",
        "os.popen",
        "os.remove",
        "os.unlink",
        "os.rename",
        "os.replace",
        "os.mkdir",
        "os.makedirs",
        "os.rmdir",
        "os.chmod",
        "os.chown",
        "os.kill",
        "os.putenv",
        "os.fork",
    }
)
# filesystem-mutating method names matched on any receiver (pathlib + friends). Receiver-agnostic,
# so a rare same-named in-memory method is an accepted advisory FP (ADR 0144 known gaps).
_AMBIENT_FS_WRITE_ATTRS = frozenset(
    {"write_text", "write_bytes", "unlink", "rmdir", "mkdir", "touch"}
)

# impure-transform: a re-run-divergent nondeterministic source inside a router/handler, breaking the
# at-least-once purity invariant (CLAUDE.md §2). db_lookup/fhir_lookup are the sanctioned non-pure
# reads and are deliberately NOT flagged.
_IMPURE_PATHS = frozenset(
    {
        "time.time",
        "time.time_ns",
        "time.monotonic",
        "time.monotonic_ns",
        "time.perf_counter",
        "time.perf_counter_ns",
        "time.process_time",
        "time.process_time_ns",
        "uuid.uuid1",
        "uuid.uuid4",
        "os.urandom",
        "os.getrandom",
    }
)
_IMPURE_ROOTS = frozenset({"random", "secrets"})
_DATETIME_NOW_ATTRS = frozenset({"now", "utcnow", "today"})
# time.* wall-clock reads that diverge on a re-run ONLY when called with no time-tuple argument
# (``time.gmtime(0)`` is deterministic; ``time.gmtime()`` reads the current clock).
_TIME_WALLCLOCK_NOARG = frozenset({"time.localtime", "time.gmtime", "time.ctime", "time.asctime"})

# db_lookup/fhir_lookup: the SQL statement / FHIR query is the 2nd positional or the
# statement=/query= keyword; the params dict (parameterized / percent-encoded) is safe.
_LOOKUP_NAMES = frozenset({"db_lookup", "fhir_lookup"})
_LOOKUP_QUERY_KW = frozenset({"statement", "query"})


def _message_fn_decorator(
    node: ast.AST, names: tuple[str, ...] = ("handler", "router")
) -> ast.Call | None:
    """The ``@handler(...)`` / ``@router(...)`` decorator Call on ``node`` (bare or dotted), or None.

    Generalizes :func:`_handler_decorator` to also match ``@router`` — the two decorated-scope
    security rules (phi-to-log, impure-transform) apply to both. ``FunctionDef`` only (matching
    ``_handler_decorator``); an ``async def`` handler is out of scope (a known ADR 0144 gap)."""
    if not isinstance(node, ast.FunctionDef):
        return None
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        func = dec.func
        if (isinstance(func, ast.Name) and func.id in names) or (
            isinstance(func, ast.Attribute) and func.attr in names
        ):
            return dec
    return None


def _dotted_call_name(func: ast.expr) -> str | None:
    """Reconstruct a dotted Name/Attribute chain (``os.path.join``) from a call's ``func``, or None
    when it is not a pure Name/Attribute chain (e.g. the receiver is itself a call or subscript)."""
    parts: list[str] = []
    cur: ast.expr = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


# HL7 MSH envelope metadata (control id / message type) is non-PHI, so logging it is the recommended
# safe pattern — a msg reference solely through one of these accessors does not count as PHI-bearing.
_NON_PHI_MSG_ACCESSORS = frozenset({"control_id", "message_type", "message_code", "trigger_event"})


def _references_phi(node: ast.AST, symbol: str) -> bool:
    """True when ``node``'s subtree references the message ``symbol`` in a PHI-bearing way — a bare
    ``msg`` / ``msg.raw`` / ``msg["PID-3"]`` reaching a sink directly or via an f-string / concat /
    ``.format`` / attribute access. A reference that is ONLY the receiver of a non-PHI MSH accessor
    (``msg.control_id`` / ``msg.message_type``) is exempt — that envelope metadata is safe to log."""
    exempt: set[int] = set()
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Attribute)
            and n.attr in _NON_PHI_MSG_ACCESSORS
            and isinstance(n.value, ast.Name)
            and n.value.id == symbol
        ):
            exempt.add(id(n.value))
    return any(
        isinstance(n, ast.Name) and n.id == symbol and id(n) not in exempt for n in ast.walk(node)
    )


def _folds_to_constant(node: ast.expr) -> bool:
    """True when ``node`` is a compile-time-constant string expression (only literals joined by
    ``+``/``%``) — a ``"a" + "b"`` that carries no injected value and so is not a query risk."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _folds_to_constant(node.left) and _folds_to_constant(node.right)
    return False


def _is_dynamic_string(node: ast.expr) -> bool:
    """True when ``node`` is a string built by interpolating a *non-constant* value (f-string with a
    ``{expr}`` / ``+`` or ``%`` with a variable operand / ``.format(...)`` with args) — the injection
    shape for a ``db_lookup``/``fhir_lookup`` query. A pure-literal concat folds to a constant and is
    not flagged. (A trusted-identifier concat like ``"select from " + TABLE`` still flags — SQL cannot
    parameterize an identifier, so the concatenation nudge is intentional; ADR 0144 known FP.)"""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not _folds_to_constant(node)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and bool(node.args or node.keywords)
    )


def _is_logger_receiver(recv: ast.expr) -> bool:
    """True when ``recv`` looks like a stdlib logger — a Name/attribute ending in log/logger, the
    ``logging`` module, or an inline ``getLogger(...)`` result. Distinguishes ``log.error(...)`` (a
    sink) from ``outcome.error(...)`` / ``result.info(...)`` / ``warnings.warn(...)`` (not sinks)."""
    if isinstance(recv, ast.Name):
        return recv.id == "logging" or recv.id.endswith(_LOGGER_NAME_SUFFIXES)
    if isinstance(recv, ast.Attribute):
        return recv.attr == "logging" or recv.attr.endswith(_LOGGER_NAME_SUFFIXES)
    if isinstance(recv, ast.Call):
        fn = recv.func
        return (isinstance(fn, ast.Name) and fn.id == "getLogger") or (
            isinstance(fn, ast.Attribute) and fn.attr == "getLogger"
        )
    return False


def _phi_to_log_hit(call: ast.Call, msg_sym: str) -> bool:
    """The message symbol reaches a ``print`` / INFO+ *logger* call (its args, minus logging control
    metadata). An attribute-form level call counts only on a logger-shaped receiver."""
    func = call.func
    if isinstance(func, ast.Name):
        is_sink = func.id == "print"
    elif isinstance(func, ast.Attribute):
        is_sink = func.attr in _LOG_SINK_ATTRS and _is_logger_receiver(func.value)
    else:
        is_sink = False
    if not is_sink:
        return False
    checked: list[ast.expr] = list(call.args)
    checked += [kw.value for kw in call.keywords if kw.arg not in _LOG_META_KWARGS]
    return any(_references_phi(arg, msg_sym) for arg in checked)


def _unsafe_lookup_hit(call: ast.Call) -> bool:
    """A ``db_lookup``/``fhir_lookup`` whose statement/query argument is interpolated, not a literal."""
    func = call.func
    is_lookup = (isinstance(func, ast.Name) and func.id in _LOOKUP_NAMES) or (
        isinstance(func, ast.Attribute) and func.attr in _LOOKUP_NAMES
    )
    if not is_lookup:
        return False
    query: ast.expr | None = None
    # 2nd positional — but only when neither of the first two args is a ``*args`` splat (which would
    # make positional indexing meaningless).
    if len(call.args) >= 2 and not any(isinstance(a, ast.Starred) for a in call.args[:2]):
        query = call.args[1]
    for kw in call.keywords:
        if kw.arg in _LOOKUP_QUERY_KW:
            query = kw.value
    return query is not None and _is_dynamic_string(query)


def _open_mode(call: ast.Call, index: int = 1) -> str | None:
    """The literal string mode of an open-style call, or None. ``index`` is the positional slot of the
    mode arg — ``1`` for builtin ``open(file, mode)``, ``0`` for ``Path(...).open(mode)`` — and the
    ``mode=`` keyword is honored either way."""
    if len(call.args) > index:
        arg = call.args[index]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    for kw in call.keywords:
        if (
            kw.arg == "mode"
            and isinstance(kw.value, ast.Constant)
            and isinstance(kw.value.value, str)
        ):
            return kw.value.value
    return None


def _is_write_mode(mode: str | None) -> bool:
    """True when an ``open(...)`` mode string requests write/append/create/update access."""
    return mode is not None and any(c in mode for c in ("w", "a", "x", "+"))


def _ambient_authority_hit(call: ast.Call) -> bool:
    """The call reaches past the sanctioned Send/db_lookup boundary (subprocess/socket/eval/raw
    HTTP/dynamic-import/file-write). The sanctioned reads and pure stdlib data ops are exempt."""
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in _AMBIENT_BARE_NAMES:
            return True
        if func.id == "open" and _is_write_mode(_open_mode(call)):
            return True
    if isinstance(func, ast.Attribute):
        if func.attr in _AMBIENT_FS_WRITE_ATTRS:
            return True
        # the attribute form ``Path(...).open("w")`` — mode is the FIRST arg here — flag only a write.
        if func.attr == "open" and _is_write_mode(_open_mode(call, 0)):
            return True
    dotted = _dotted_call_name(func)
    if dotted is None:
        return False
    parts = dotted.split(".")
    root = parts[0]
    if root == "socket":
        # every socket.* is egress EXCEPT the read-only host lookups.
        return len(parts) < 2 or parts[1] not in _SOCKET_READONLY
    if root in _AMBIENT_ROOTS:
        return True
    if dotted in _AMBIENT_OS_PATHS:
        return True
    if len(parts) == 2 and root == "os" and parts[1].startswith(("exec", "spawn", "posix_spawn")):
        return True
    if dotted.startswith(("urllib.request.", "http.client.")):
        return True
    return dotted == "importlib.import_module"


def _impure_transform_hit(call: ast.Call, imported: set[str]) -> bool:
    """A re-run-divergent nondeterministic source in a router/handler body: wall clock (``time.time``,
    no-arg ``time.localtime``/``gmtime``/``ctime``/``asctime``, single-arg ``time.strftime``),
    ``random.*`` / ``secrets.*``, ``uuid1``/``uuid4``, ``os.urandom``/``os.getrandom``, or
    ``datetime.now``/``utcnow``/``today``. ``strftime`` of a given tuple, ``uuid5``, and the sanctioned
    ``db_lookup``/``fhir_lookup`` reads are not flagged.

    Every rule except the ``datetime`` case is gated on ``imported`` (module names bound by an
    ``import`` in this file), so a local variable shadowing ``secrets``/``random``/``time`` is not
    mistaken for the stdlib module."""
    dotted = _dotted_call_name(call.func)
    if dotted is None:
        return False
    parts = dotted.split(".")
    if parts[0] == "datetime" and parts[-1] in _DATETIME_NOW_ATTRS:
        return True
    if parts[0] not in imported:
        return False
    if dotted in _IMPURE_PATHS:
        return True
    if parts[0] in _IMPURE_ROOTS:
        return True
    if dotted in _TIME_WALLCLOCK_NOARG and not call.args:
        return True
    return dotted == "time.strftime" and len(call.args) == 1


def _imported_modules(tree: ast.Module) -> set[str]:
    """The module root names bound by an ``import`` in ``tree`` (``import a.b`` binds ``a``; ``import
    a as x`` binds ``x``). Used to gate the impure-transform rule to real stdlib-module references."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
    return names


def _body_calls(fn: ast.FunctionDef) -> list[ast.Call]:
    """Every ``ast.Call`` in a function's executable body, NOT descending into nested def/class bodies
    (each nested def is scanned on its own iteration) and NOT into the signature (decorators, default
    args, annotations) — those are evaluated once at import time, so they cannot break per-message
    purity or leak the message body, matching the undecorated-helper carve-out."""
    nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    calls: list[ast.Call] = []
    stack: list[ast.AST] = [stmt for stmt in fn.body if not isinstance(stmt, nested)]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Call):
            calls.append(node)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, nested):
                continue
            stack.append(child)
    return calls


# unvetted-import (ADR 0144 Increment 2): a config-dir import of a package that is neither stdlib nor
# first-party (`messagefoundry`) nor a shipped engine dependency nor a sibling config module — an
# operator-added third-party package pulled into the engine process, i.e. the supply-chain surface a
# typosquat / AI-hallucinated ("slopsquat") name lands on. First-party root always vetted.
_FIRST_PARTY_ROOTS = frozenset({"messagefoundry"})


def _normalize_dist(name: str) -> str:
    """PEP 503 distribution-name normalization (``argon2-cffi`` / ``Argon2_CFFI`` → ``argon2-cffi``)."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


@functools.cache
def _shipped_dep_import_roots() -> frozenset[str]:
    """Top-level import names of MessageFoundry's declared distribution dependencies, so a Handler
    importing a shipped dep (e.g. ``hl7``, or a lazily-imported optional-extra dep like ``pydicom``)
    is not mistaken for an operator-added package. **Install-independent:** an installed dep maps to
    its real import name(s); a declared-but-uninstalled dep falls back to a best-effort guess from the
    dist name, so vetting does not drift with which extras happen to be installed on the box running
    ``check``. Best-effort: any ``importlib.metadata`` failure degrades to empty and the caller then
    skips the rule (never flags/blocks on a blind vet). Cached — the environment is stable per process."""
    try:
        dist_to_imports: dict[str, set[str]] = {}
        for import_name, dists in importlib.metadata.packages_distributions().items():
            for dist in dists:
                dist_to_imports.setdefault(_normalize_dist(dist), set()).add(import_name)
        roots: set[str] = set()
        for req in importlib.metadata.requires("messagefoundry") or []:
            dist = _normalize_dist(re.split(r"[<>=!~;\[( ]", req, maxsplit=1)[0])
            # installed -> real import name(s); declared-but-uninstalled (an unbuilt optional extra
            # like [dicom]'s pydicom) -> a dist-name guess, so a lazy `import pydicom` is vetted whether
            # or not that extra is installed.
            roots |= dist_to_imports.get(dist) or {dist.replace("-", "_")}
        return frozenset(roots)
    except Exception:  # noqa: BLE001 — best-effort env probe; degrade, never crash the advisory gate
        return frozenset()


def _is_type_checking_guard(node: ast.If) -> bool:
    """True for ``if TYPE_CHECKING:`` / ``if typing.TYPE_CHECKING:`` — its body is type-only, never
    executed, so imports inside it are not a runtime supply-chain surface."""
    test = node.test
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _unvetted_import_hits(
    tree: ast.Module,
    local_modules: frozenset[str],
    shipped_roots: frozenset[str],
    allow: frozenset[str] = frozenset(),
) -> list[tuple[int, str]]:
    """Absolute imports of a top-level name that is not stdlib, not first-party, not a shipped engine
    dep, not a sibling config module (``local_modules`` = the config dir's own ``*.py`` stems), and not
    an operator-vetted root (``allow`` = ``--handler-security-allow``, import roots not dist names).
    ``TYPE_CHECKING``-guarded (type-only) imports are excluded — they never run."""
    vetted = sys.stdlib_module_names | _FIRST_PARTY_ROOTS | shipped_roots | local_modules | allow
    type_only: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _is_type_checking_guard(node):
            for stmt in node.body:
                for sub in ast.walk(stmt):
                    if isinstance(sub, (ast.Import, ast.ImportFrom)):
                        type_only.add(id(sub))
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if id(node) in type_only:
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in vetted:
                    hits.append((node.lineno, root))
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            # level>0 is a relative (sibling-config) import — always first-party.
            root = node.module.split(".")[0]
            if root not in vetted:
                hits.append((node.lineno, root))
    return hits


def _check_handler_security(
    config_dir: str | Path, *, strict: bool = False, allow: frozenset[str] = frozenset()
) -> CheckResult:
    """Flag risky patterns in the config-dir Router/Handler modules — a static compensating control
    for ASVS 15.2.5 / 15.2.4 (ADR 0144). Five rule families:

    * ``phi-to-log`` — the message body reaching a ``print``/INFO+ log call (CLAUDE.md §9).
    * ``unsafe-db-lookup`` — an f-string/concatenated statement into ``db_lookup``/``fhir_lookup``
      instead of the parameterized ``params`` / structured form.
    * ``ambient-authority`` — reaching past the sanctioned ``Send``/``db_lookup`` boundary
      (``subprocess``/``socket``/``eval``/raw HTTP/dynamic import/file writes; CLAUDE.md §2/§8).
    * ``impure-transform`` — a re-run-divergent nondeterministic source (wall clock / ``random`` /
      ``uuid4``) in a router/handler, breaking the at-least-once purity invariant (CLAUDE.md §2).
    * ``unvetted-import`` — an operator-added third-party import (supply-chain / slopsquat surface).

    Static analysis catches only a fraction of insecure code, so this is a **filter, not a fix**.
    **Advisory by default** (``required=False``, prints, never blocks); ``strict=True`` (the opt-in
    ``--strict-handler-security`` block mode) promotes any finding to a **blocking** failure for an org
    that wants a hard gate on its own CI. The runtime half is the opt-in ADR 0087 sandbox. Mirrors
    :func:`_check_raise_fstring`: static ``ast`` only (never imports/executes the config), globs
    ``*.py`` under ``config_dir`` (helpers included), and skips a broken/unreadable file (``validate``
    reports those) so it never crashes the gate. ``phi-to-log`` and ``impure-transform`` are scoped to
    ``@router``/``@handler`` bodies (so an undecorated helper's wall-clock fallback is not a false
    positive); the other three scan the whole module."""
    base = Path(config_dir)
    if not base.is_dir():
        return CheckResult(
            "handler-security", ok=True, required=False, skipped=True, detail="not a config dir"
        )
    # sibling config modules (the dir's own *.py stems) are first-party for the unvetted-import rule.
    local_modules = frozenset(p.stem for p in base.glob("*.py"))
    # unvetted-import needs a trustworthy shipped-dep set to tell operator-added from shipped; if the
    # metadata probe degraded to empty, skip the rule entirely rather than flag/block on a blind vet.
    shipped = _shipped_dep_import_roots()
    hits: list[str] = []
    for path in sorted(base.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, OSError):
            # A broken module is already caught by validate; never crash the advisory gate on it.
            continue
        imported = _imported_modules(tree)
        file_hits: list[tuple[int, str]] = (
            [
                (lineno, f"unvetted-import:{mod}")
                for lineno, mod in _unvetted_import_hits(tree, local_modules, shipped, allow)
            ]
            if shipped
            else []
        )
        # Whole-file rules — unsafe-db-lookup + ambient-authority (helpers + module level included).
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _unsafe_lookup_hit(node):
                file_hits.append((node.lineno, "unsafe-db-lookup"))
            if _ambient_authority_hit(node):
                file_hits.append((node.lineno, "ambient-authority"))
        # Decorated-scope rules — phi-to-log + impure-transform, over each router/handler's own body
        # only (not nested defs, not the signature), so each call is scanned once with its own message
        # symbol and an import-time default arg is never mistaken for per-message impurity.
        for node in ast.walk(tree):
            if _message_fn_decorator(node) is None:
                continue
            assert isinstance(node, ast.FunctionDef)  # narrowed by _message_fn_decorator
            params = node.args.posonlyargs + node.args.args
            msg_sym = params[0].arg if params else None
            for sub in _body_calls(node):
                if msg_sym is not None and _phi_to_log_hit(sub, msg_sym):
                    file_hits.append((sub.lineno, "phi-to-log"))
                if _impure_transform_hit(sub, imported):
                    file_hits.append((sub.lineno, "impure-transform"))
        hits += [f"{path.name}:{lineno} [{rule}]" for lineno, rule in sorted(file_hits)]
    if not hits:
        return CheckResult(
            "handler-security",
            ok=True,
            required=False,
            skipped=True,
            detail="no handler-security findings",
        )
    shown = ", ".join(hits[:5])
    more = f" (+{len(hits) - 5} more)" if len(hits) > 5 else ""
    kind = "finding(s)" if strict else "advisory finding(s)"
    detail = (
        f"{len(hits)} handler-security {kind} — static compensating control for "
        f"ASVS 15.2.5, a filter not a boundary (ADR 0144): {shown}{more}"
    )
    # Advisory by default (ok=True/required=False — never blocks); strict block mode makes a finding a
    # required failure (ok=False/required=True). The finding text is identical either way.
    return CheckResult("handler-security", ok=not strict, required=strict, detail=detail)


def _check_validate(config_dir: str | Path) -> CheckResult:
    from messagefoundry.config.wiring import validate_config

    errors = [d for d in validate_config(config_dir) if d.severity == "error"]
    if errors:
        detail = f"{len(errors)} problem(s): " + "; ".join(
            f"{d.file or '-'}: {d.message}" for d in errors[:5]
        )
        return CheckResult("validate", ok=False, required=True, detail=detail)
    return CheckResult("validate", ok=True, required=True, detail="no problems")


# Executable acceptance criteria for dry-run fixtures (Secure Development Standards §5): a fixture may
# declare its expected dry-run disposition in a sibling ``<fixture>.expect`` file. ``dry_run`` reports
# ``RECEIVED`` (would route + deliver), ``UNROUTED`` (no handler matched), ``FILTERED`` (a handler ran
# but delivered nothing), or ``ERROR`` (parse/validate/router-handler failure). ``PROCESSED``/``ROUTED``
# are live-only post-delivery states, so they alias to ``RECEIVED`` for authoring ergonomics.
_DRYRUN_DISPOSITIONS = frozenset({"RECEIVED", "UNROUTED", "FILTERED", "ERROR"})
_DISPOSITION_ALIASES = {
    "PROCESSED": "RECEIVED",
    "ROUTED": "RECEIVED",
    "DELIVERED": "RECEIVED",
    "DELIVERS": "RECEIVED",
}


def _expected_disposition(fixture_path: str | Path) -> str | None:
    """Read an optional ``<fixture>.expect`` sidecar declaring the expected dry-run disposition.

    Returns the normalized disposition name (``RECEIVED``/``UNROUTED``/``FILTERED``/``ERROR``), or
    ``None`` when no sidecar exists — then the fixture keeps the default "must not ERROR" semantics.
    Raises ``ValueError`` for an unreadable or unrecognized declaration (a fixture-authoring mistake).
    """
    sidecar = Path(f"{fixture_path}.expect")
    if not sidecar.is_file():
        return None
    try:
        raw = sidecar.read_text(encoding="utf-8").strip().upper()
    except OSError as exc:
        raise ValueError(f"cannot read {sidecar.name}: {exc}") from exc
    normalized = _DISPOSITION_ALIASES.get(raw, raw)
    if normalized not in _DRYRUN_DISPOSITIONS:
        valid = ", ".join(sorted(_DRYRUN_DISPOSITIONS))
        raise ValueError(
            f"invalid .expect disposition {raw!r} (use one of {valid}; PROCESSED/ROUTED alias RECEIVED)"
        )
    return normalized


def _resolve_snapshot_on_send(
    config_dir: str | Path,
    *,
    service_config: str | Path | None,
    suppress_search: bool,
) -> bool:
    """Best-effort ``[pipeline].snapshot_on_send`` for the dry-run preview (#230 parity, ADR 0104).

    Resolves this instance's ``messagefoundry.toml`` exactly like :func:`_check_posture` (explicit
    ``service_config`` > root-anchored when ``suppress_search`` > legacy upward-walk) and returns the
    loaded flag. When no settings resolve (no toml, or one that won't parse/validate), fall back to the
    **Settings-model default (True)** — the posture of exactly the default, un-overridden engine —
    never a hardcoded ``False``, which would preview the wrong posture for the engine this gate exists
    to mirror (ADR 0104 §8.1)."""
    from pydantic import ValidationError

    from messagefoundry.config.settings import PipelineSettings, load_settings

    if service_config is not None:
        toml: Path | None = Path(service_config) if Path(service_config).is_file() else None
    elif suppress_search:
        candidate = Path(config_dir) / "messagefoundry.toml"
        toml = candidate if candidate.is_file() else None
    else:
        toml = _find_service_toml(config_dir)
    if toml is None:
        return PipelineSettings().snapshot_on_send
    try:
        return load_settings(config_path=toml).pipeline.snapshot_on_send
    except (FileNotFoundError, ValueError, ValidationError, OSError):
        return PipelineSettings().snapshot_on_send


def _check_dryrun(
    config_dir: str | Path,
    messages_dir: str | Path | None,
    *,
    service_config: str | Path | None = None,
    suppress_search: bool = False,
) -> CheckResult:
    from messagefoundry.config.wiring import WiringError, load_config
    from messagefoundry.pipeline.dryrun import dry_run, read_message_sets
    from messagefoundry.store import MessageStatus

    if messages_dir is None:
        return CheckResult(
            "dryrun", ok=True, required=False, skipped=True, detail="no fixtures dir"
        )
    mpath = Path(messages_dir)
    if not mpath.exists():
        # An explicitly-given path that doesn't exist is a mistake (renamed/typo'd fixtures dir),
        # not "no fixtures" — fail the gate rather than silently skip the required check (low-20).
        return CheckResult(
            "dryrun", ok=False, required=True, detail=f"messages path not found: {mpath}"
        )
    if mpath.is_dir() and not any(mpath.glob("**/*.hl7")):
        # A real dir with no fixtures (searched recursively, since per-feed fixtures live in
        # <messages>/<inbound>/ subdirs) is the documented "absent fixtures -> skipped" case. A single
        # file (any extension) falls through and is dry-run like the `dryrun` CLI accepts (low-20).
        return CheckResult(
            "dryrun", ok=True, required=False, skipped=True, detail=f"no *.hl7 fixtures in {mpath}"
        )
    try:
        reg = load_config(config_dir)
    except WiringError as exc:
        # validate already reports (and blocks on) this — don't double-fail here.
        return CheckResult(
            "dryrun", ok=True, required=False, skipped=True, detail=f"config did not load: {exc}"
        )
    if not reg.inbound:
        return CheckResult(
            "dryrun", ok=True, required=False, skipped=True, detail="no inbound connections"
        )

    # Per-feed mapping (#11): a fixture under <messages>/<inbound_name>/ is dry-run only against that
    # feed; an unmapped fixture (top-level, or under a non-feed subdir) cross-products every inbound.
    #
    # The DIRECTORY map keeps every inbound name (#233, ADR 0111): a fixture dir named after a
    # not-deployed feed must still resolve to that feed, or it would silently become "unmapped" and be
    # cross-producted against every OTHER feed — worse than the problem. It is the cross-product target
    # list that drops the not-deployed feeds: an unmapped fixture must not be run against a feed nobody
    # deployed (its Sends are declined, so it would report FILTERED and fail a .expect). An explicitly
    # PINNED fixture still runs against its not-deployed feed — carrying the record is the point of the
    # state, and dry-run resolves no env(), so previewing its router/handler logic stays free.
    inbound_names = list(reg.inbound)
    deployed_inbounds = [n for n, ic in reg.inbound.items() if ic.deployed]
    message_sets = read_message_sets(mpath, inbound_names)
    # #230 P4 (ADR 0104): preview under the engine's copy-on-Send posture (best-effort; fallback = the
    # Settings-model default, ON) so the gate exercises the fixtures exactly as the engine would run them.
    snapshot_on_send = _resolve_snapshot_on_send(
        config_dir, service_config=service_config, suppress_search=suppress_search
    )
    errors: list[str] = []
    total = 0
    pinned = 0
    asserted = (
        0  # runs checked against a declared .expect disposition (executable acceptance criteria)
    )
    for label, path, raw, target in message_sets:
        try:
            expected = _expected_disposition(path)
        except ValueError as exc:
            errors.append(f"{label}: {exc}")
            continue
        targets = [target] if target is not None else deployed_inbounds
        if target is not None:
            pinned += 1
        for ic_name in targets:
            total += 1
            result = dry_run(reg, raw, inbound=ic_name, snapshot_on_send=snapshot_on_send)
            if expected is not None:
                asserted += 1
                actual = result.disposition.name
                if actual != expected:
                    errors.append(
                        f"{label} @ {ic_name}: expected {expected}, got {result.error or actual}"
                    )
            elif result.error or result.disposition is MessageStatus.ERROR:
                errors.append(f"{label} @ {ic_name}: {result.error or result.disposition.value}")
    if errors:
        detail = f"{len(errors)}/{total} run(s) failed: " + "; ".join(errors[:5])
        return CheckResult("dryrun", ok=False, required=True, detail=detail)
    pin_note = f", {pinned} feed-pinned" if pinned else ""
    exp_note = f", {asserted} expectation-checked" if asserted else ""
    detail = f"{total} run(s) clean across {len(message_sets)} message(s){pin_note}{exp_note}"
    return CheckResult("dryrun", ok=True, required=True, detail=detail)


def _find_service_toml(config_dir: str | Path) -> Path | None:
    """Best-effort locate this instance's ``messagefoundry.toml`` for the posture check.

    A config repo (ADR 0017) keeps the service toml at its root and the modules under ``config/``,
    so we search ``config_dir`` and each parent (then the CWD) for ``messagefoundry.toml`` and return
    the first hit. Absent → ``None`` (the posture check then skips, never errors)."""
    seen: set[Path] = set()
    candidates = [Path(config_dir).resolve(), *Path(config_dir).resolve().parents, Path.cwd()]
    for base in candidates:
        if base in seen:
            continue
        seen.add(base)
        toml = base / "messagefoundry.toml"
        if toml.is_file():
            return toml
    return None


def _check_posture(
    config_dir: str | Path,
    *,
    service_config: str | Path | None = None,
    suppress_search: bool = False,
) -> CheckResult:
    """Catch the ADR-0017 foot-gun at commit/CI time: a CUSTOM active-environment name (not
    dev/staging/prod) with no explicit ``[ai].data_class`` / ``[ai].production`` makes ``serve`` fail
    closed at runtime (``settings.ai.require_posture()``). Mirror that fail-closed check here.

    Service-toml resolution (ADR 0050 AC-6): an explicit ``service_config`` is used as-is; otherwise,
    when ``suppress_search`` is set (``--project-root`` was given) the upward-walk is skipped — so
    ``check`` matches ``serve`` only when the flags are given. With neither, the legacy
    ``_find_service_toml`` upward-walk runs, unchanged.

    Best-effort: no ``messagefoundry.toml`` → SKIP (this gate also runs against a bare config dir).
    No active environment set → SKIP (``serve`` reports that separately; not this check's concern).
    Settings that won't load → SKIP (don't double-report a config error the operator hits at serve)."""
    from pydantic import ValidationError

    from messagefoundry.config.settings import load_settings

    if service_config is not None:
        toml: Path | None = Path(service_config) if Path(service_config).is_file() else None
    elif suppress_search:
        # --project-root given but no --service-config: anchor at the root, don't walk up (AC-6).
        candidate = Path(config_dir) / "messagefoundry.toml"
        toml = candidate if candidate.is_file() else None
    else:
        toml = _find_service_toml(config_dir)
    if toml is None:
        return CheckResult(
            "posture", ok=True, required=True, skipped=True, detail="no messagefoundry.toml"
        )
    try:
        settings = load_settings(config_path=toml)
    except (FileNotFoundError, ValueError, ValidationError, OSError) as exc:
        return CheckResult(
            "posture", ok=True, required=True, skipped=True, detail=f"settings did not load: {exc}"
        )

    if settings.ai.environment is None:
        # No active environment is a serve-time error of its own; don't conflate it with posture.
        return CheckResult(
            "posture", ok=True, required=True, skipped=True, detail="no active environment set"
        )
    try:
        data_class, production = settings.ai.require_posture()
    except ValueError as exc:
        # A custom env name with no explicit posture: serve refuses to start. Fail the gate now,
        # naming the missing keys exactly as serve's error does.
        return CheckResult("posture", ok=False, required=True, detail=str(exc))
    return CheckResult(
        "posture",
        ok=True,
        required=True,
        detail=(
            f"environment {settings.ai.environment!r}: "
            f"data_class={data_class.value}, production={production}"
        ),
    )


def _check_build(
    config_dir: str | Path,
    *,
    service_config: str | Path | None = None,
    suppress_search: bool = False,
) -> CheckResult:
    """Run the **posture-stamped** ``build_check_registry`` that ``serve``/``reload`` run, so a config
    ``serve`` would REFUSE — most importantly a production-PHI cleartext / weakened-TLS transport hop
    (#200, ADR 0092) — fails at commit/CI time instead of only at runtime.

    ``validate`` loads the graph and resolves references but never constructs the connectors, so it does
    NOT run the posture-keyed insecure-hop refusal (nor the ``[egress]`` allowlists). This check closes
    that gap: it loads this instance's ``messagefoundry.toml`` (same resolution as :func:`_check_posture`),
    resolves ``env()`` values against the active environment exactly as ``serve`` does, and calls
    :func:`~messagefoundry.pipeline.wiring_runner.build_check_registry` with the instance's **derived
    posture** stamped — so a prod-PHI cleartext egress hop raises a ``WiringError`` and FAILS the gate.

    Required, but **fail-safe SKIP** when it can't resolve a real posture, so it never blocks a bare
    config dir or a dev checkout: no ``messagefoundry.toml`` → SKIP (a bare dir has no declared posture,
    byte-identical to before this check); settings/graph that won't load → SKIP (``validate`` already
    reports that). Only a genuine build/posture refusal on a fully-resolved config blocks."""
    import os

    from pydantic import ValidationError

    from messagefoundry.config.environments import (
        load_environment_values,
        resolve_values_base_dir,
    )
    from messagefoundry.config.settings import hop_posture_from_ai, load_settings
    from messagefoundry.config.wiring import API_LISTENER_LABEL, WiringError, load_config
    from messagefoundry.pipeline.wiring_runner import build_check_registry

    if service_config is not None:
        toml: Path | None = Path(service_config) if Path(service_config).is_file() else None
    elif suppress_search:
        candidate = Path(config_dir) / "messagefoundry.toml"
        toml = candidate if candidate.is_file() else None
    else:
        toml = _find_service_toml(config_dir)
    if toml is None:
        # No declared instance posture — a bare config dir. The posture-keyed refusal has nothing to key
        # on, so skip (byte-identical to before this check); a prod-PHI instance always has a toml.
        return CheckResult(
            "build-check", ok=True, required=True, skipped=True, detail="no messagefoundry.toml"
        )
    try:
        settings = load_settings(config_path=toml)
    except (FileNotFoundError, ValueError, ValidationError, OSError) as exc:
        return CheckResult(
            "build-check",
            ok=True,
            required=True,
            skipped=True,
            detail=f"settings did not load: {exc}",
        )
    try:
        registry = load_config(config_dir)
    except (WiringError, OSError, ImportError, SyntaxError, ValueError) as exc:
        # A broken graph is reported (blocking) by validate; don't double-fail here.
        return CheckResult(
            "build-check",
            ok=True,
            required=True,
            skipped=True,
            detail=f"config did not load: {exc}",
        )
    env_name = settings.ai.environment
    # Resolve env() against the active environment the same way serve does, so a hop's host/scheme (an
    # env()-supplied value) is built exactly as at runtime rather than left as an unresolved reference.
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
    try:
        build_check_registry(
            registry,
            inbound_bind_host=settings.inbound.bind_host,
            env_values=env_values,
            egress=settings.egress,
            reserved_bindings=((API_LISTENER_LABEL, settings.api.host, settings.api.port),),
            # The residual: stamp THIS instance's derived posture so the posture-keyed insecure-hop
            # refusal (ADR 0092) decides at commit/CI exactly as serve/reload do — a prod-PHI cleartext
            # hop raises here rather than shipping and only refusing at serve.
            posture=hop_posture_from_ai(settings.ai, enforcement=settings.security.enforcement),
            trust_anchor_policy=settings.tls.policy(),
            # ADR 0154 D4: the EFFECTIVE ordering / max_attempts refusals need the resolved
            # [delivery] defaults. Without them that arm is skipped rather than guessed, and the
            # misconfiguration would surface only at serve rather than at commit/CI.
            delivery=settings.delivery,
        )
    except WiringError as exc:
        return CheckResult("build-check", ok=False, required=True, detail=str(exc))
    return CheckResult(
        "build-check",
        ok=True,
        required=True,
        detail=f"connectors build against the {env_name or 'default'} posture",
    )


def _check_alert_smtp_tls(
    config_dir: str | Path,
    *,
    service_config: str | Path | None = None,
    suppress_search: bool = False,
) -> CheckResult:
    """Surface whether the ``[alerts]`` SMTP hop **authenticates the relay** (#323 layer 3).

    That hop carries operator alert bodies, every per-user security-event email, and the SMTP AUTH
    password. Before #323 it issued ``starttls()`` with no context, so it accepted any certificate —
    encrypted, unauthenticated, and invisible: nothing in the product reported it, which is why the
    defect survived in three docs that described the hop as verified. This check is the review surface
    that makes the hop's posture readable without opening the code.

    Advisory (``required=False``) for the same reason as ``cleartext-accepted``: a deliberate,
    acknowledged deviation is a reasoned choice, not a config error, and the **serve gate** is what
    refuses it on an enforcing PHI instance. Blocking here would duplicate that refusal at the wrong
    altitude and punish a synthetic/dev instance where the deviation is legitimate.

    States the SECURE case explicitly rather than going quiet — an absent line is indistinguishable
    from a check that did not run.

    Service-toml resolution is :func:`_check_posture`'s, verbatim; no ``messagefoundry.toml`` or
    settings that will not load → SKIP (``validate``/``posture`` report those)."""
    from pydantic import ValidationError

    from messagefoundry.config.settings import load_settings

    if service_config is not None:
        toml: Path | None = Path(service_config) if Path(service_config).is_file() else None
    elif suppress_search:
        candidate = Path(config_dir) / "messagefoundry.toml"
        toml = candidate if candidate.is_file() else None
    else:
        toml = _find_service_toml(config_dir)
    if toml is None:
        return CheckResult(
            "alert-smtp-tls", ok=True, required=False, skipped=True, detail="no messagefoundry.toml"
        )
    try:
        settings = load_settings(config_path=toml)
    except (FileNotFoundError, ValueError, ValidationError, OSError) as exc:
        return CheckResult(
            "alert-smtp-tls",
            ok=True,
            required=False,
            skipped=True,
            detail=f"settings did not load: {exc}",
        )
    alerts = settings.alerts
    if not (alerts.email_smtp_host and alerts.email_from):
        return CheckResult(
            "alert-smtp-tls",
            ok=True,
            required=False,
            detail="no [alerts] SMTP transport configured — no hop to report",
        )
    acked = settings.security.allow_unverified_alert_smtp_tls
    ack_note = (
        " — acknowledged by [security].allow_unverified_alert_smtp_tls"
        if acked
        else " — NOT acknowledged; an enforcing PHI instance will REFUSE to start"
    )
    if not alerts.email_use_tls:
        return CheckResult(
            "alert-smtp-tls",
            ok=True,
            required=False,
            detail=(
                f"[alerts].email_use_tls=false — the SMTP hop to {alerts.email_smtp_host} is "
                f"CLEARTEXT{ack_note}"
            ),
        )
    if not alerts.email_tls_verify:
        return CheckResult(
            "alert-smtp-tls",
            ok=True,
            required=False,
            detail=(
                f"[alerts].email_tls_verify=false — the SMTP hop to {alerts.email_smtp_host} is "
                f"encrypted but accepts ANY certificate{ack_note}"
            ),
        )
    anchor = (
        f"[alerts].email_tls_ca_file ({alerts.email_tls_ca_file})"
        if alerts.email_tls_ca_file
        else (
            f"[tls].internal_ca_file ({settings.tls.internal_ca_file})"
            if settings.tls.internal_ca_file
            else "the OS trust store"
        )
    )
    return CheckResult(
        "alert-smtp-tls",
        ok=True,
        required=False,
        detail=(
            f"the [alerts] SMTP hop to {alerts.email_smtp_host} verifies the relay certificate "
            f"against {anchor}"
        ),
    )


def _check_cleartext_accepted(
    config_dir: str | Path,
) -> CheckResult:
    """Surface **the whole set** of connections that declare ``cleartext_accepted`` (ADR 0153).

    ADR 0153 accepts, and cannot prevent, an operator declaring the acceptance broadly enough to
    approximate the blanket escape it removed. Its stated mitigations are that the declaration is
    per-connection, that it warns and audits at every construction, and that **``check`` surfaces the
    whole accepted set** — this is that surface. Advisory (``required=False``): a declared acceptance is
    a legitimate, reasoned choice, not a config error, and blocking on it would push operators back
    toward a false ``tls_hop_attested``. It exists so the set is *visible in review*, next to the hosts.

    Covers outbound connections AND ``FhirLookup`` read connections — ``accepted_cleartext_hops`` walks
    both, so the "whole accepted set" claim is true rather than nearly true.

    SKIPs when the graph will not load — ``validate`` reports that, and a check that silently reported
    an empty accepted set on an unloadable config would be worse than one that says it could not look."""
    from messagefoundry.config.wiring import WiringError, accepted_cleartext_hops, load_config

    try:
        registry = load_config(config_dir)
    except (WiringError, OSError, ImportError, SyntaxError, ValueError) as exc:
        return CheckResult(
            "cleartext-accepted",
            ok=True,
            required=False,
            skipped=True,
            detail=f"config did not load: {exc}",
        )
    accepted = accepted_cleartext_hops(registry)
    if not accepted:
        return CheckResult(
            "cleartext-accepted",
            ok=True,
            required=False,
            detail="no connection declares cleartext_accepted",
        )
    listed = "; ".join(f"{name} ({reason})" for name, reason in accepted)
    return CheckResult(
        "cleartext-accepted",
        ok=True,
        required=False,
        detail=(f"{len(accepted)} connection(s) cross a cleartext hop by declaration — {listed}"),
    )


def _check_reference_backend(
    config_dir: str | Path,
    *,
    service_config: str | Path | None = None,
    suppress_search: bool = False,
) -> CheckResult:
    """Refuse a config that declares an ADR 0006 ``Reference(...)`` against a store backend with no
    reference-snapshot store — the same fail-closed gate ``serve``/``reload`` apply
    (:func:`~messagefoundry.pipeline.wiring_runner.check_reference_backend_supported`), brought forward to
    commit/CI time.

    Without it, a config declaring a reference set against a backend with no snapshot store passes the
    whole gate and then breaks every message that reads the set at run time — post-ACK, forever, because
    ``write_reference_snapshot`` can never materialize it there (the pre-#235 SQL Server failure this
    check was built for; all three shipped backends now implement the snapshot store, so today it guards
    a future backend that leaves the allow-list default). The engine-start gate reads the capability
    off the LIVE store; ``check`` has no store, so it reads it off the DECLARED backend
    (``settings.store.backend``) via :func:`~messagefoundry.store.base.backend_supports_reference_sets`,
    which resolves the same class flag — one source of truth, no drift.

    Required, but **fail-safe SKIP** on the same convention as :func:`_check_build`: no
    ``messagefoundry.toml`` → SKIP (a bare config dir declares no backend, and the SQLITE default supports
    reference sets anyway); settings or config that won't load → SKIP (``validate``/``build-check`` already
    report those). A ``serve``-time backend override can still diverge from the toml this reads — the
    engine-start gate is the backstop for that, which is why both halves exist."""
    from pydantic import ValidationError

    from messagefoundry.config.settings import load_settings
    from messagefoundry.config.wiring import WiringError, load_config
    from messagefoundry.store.base import backend_supports_reference_sets

    if service_config is not None:
        toml: Path | None = Path(service_config) if Path(service_config).is_file() else None
    elif suppress_search:
        candidate = Path(config_dir) / "messagefoundry.toml"
        toml = candidate if candidate.is_file() else None
    else:
        toml = _find_service_toml(config_dir)
    if toml is None:
        return CheckResult(
            "reference-backend",
            ok=True,
            required=True,
            skipped=True,
            detail="no messagefoundry.toml",
        )
    try:
        settings = load_settings(config_path=toml)
    except (FileNotFoundError, ValueError, ValidationError, OSError) as exc:
        return CheckResult(
            "reference-backend",
            ok=True,
            required=True,
            skipped=True,
            detail=f"settings did not load: {exc}",
        )
    try:
        registry = load_config(config_dir)
    except (WiringError, OSError, ImportError, SyntaxError, ValueError) as exc:
        return CheckResult(
            "reference-backend",
            ok=True,
            required=True,
            skipped=True,
            detail=f"config did not load: {exc}",
        )
    backend = settings.store.backend
    if registry.references and not backend_supports_reference_sets(backend):
        names = ", ".join(repr(n) for n in sorted(registry.references))
        plural = "s" if len(registry.references) > 1 else ""
        detail = (
            f"reference set{plural} {names} require{'' if plural else 's'} a store backend that "
            f"implements ADR 0006 reference snapshots; backend "
            f"{backend.value!r} does not — serve would refuse to start"
        )
        return CheckResult("reference-backend", ok=False, required=True, detail=detail)
    return CheckResult(
        "reference-backend",
        ok=True,
        required=True,
        detail=(
            f"{len(registry.references)} reference set(s) against the {backend.value} backend"
            if registry.references
            else "no reference sets declared"
        ),
    )


def _run_tool(name: str, cmd: list[str]) -> CheckResult:
    """Advisory: run ``cmd`` only if its executable resolves; absent → skipped, never blocking."""
    if shutil.which(cmd[0]) is None:
        return CheckResult(name, ok=True, required=False, skipped=True, detail="not installed")
    try:
        # nosec: cmd[0] is a fixed tool name (ruff/mypy), no shell; args are repo paths (low-27).
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)  # nosec B603 B607
    except subprocess.TimeoutExpired:
        # A wedged advisory tool must not block a commit forever — degrade to a skip (low-21).
        return CheckResult(name, ok=True, required=False, skipped=True, detail="timed out (120s)")
    except OSError as exc:
        return CheckResult(
            name, ok=True, required=False, skipped=True, detail=f"could not run: {exc}"
        )
    if proc.returncode == 0:
        return CheckResult(name, ok=True, required=False, detail="passed")
    detail = (proc.stdout or proc.stderr).strip().replace("\n", " ")[:300] or "failed"
    return CheckResult(name, ok=False, required=False, detail=detail)
