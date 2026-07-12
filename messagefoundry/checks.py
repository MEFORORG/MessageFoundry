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
  is "must not ERROR". Absent fixtures → skipped (never blocks).

A third required check, ``posture``, is **best-effort**: when a ``messagefoundry.toml`` is present
(searched from ``config_dir`` upward + the CWD) it loads the service settings and — if an active
environment is set whose security posture is unresolved (a *custom* name with no ``[ai].data_class``
/ ``[ai].production``) — it FAILS, mirroring ``serve``'s fail-closed ``require_posture()`` so the
foot-gun is caught at commit/CI time instead of at runtime. No ``messagefoundry.toml`` → SKIP.

``ruff`` and ``mypy`` are **advisory**: run only when installed (``shutil.which``) and never block —
a non-developer author shouldn't be stopped by a lint nit. So is ``raise-fstring`` — an AST scan of the
config-dir Router/Handler modules that flags ``raise <Exc>(f"...{var}...")``, the exact pattern that can
carry free-text PHI past the exception-path redaction (``redaction.py``); it only ever **prints** a
heuristic reminder of the "never put PHI in an exception message" convention, never blocks the gate.
So is ``accepts-candidate`` — an AST scan that flags a ``@handler`` opening with a guard-filter
(``if <cond>: return []``), a filter that belongs in an ``accepts=`` router-stage predicate (ADR 0084)
where it costs 0 transactions instead of 2; also advisory (prints, never blocks).
Exit-code policy lives in the CLI (``__main__._check``): 0 iff no required check failed.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
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
    service_config: str | Path | None = None,
    suppress_service_toml_search: bool = False,
) -> CheckReport:
    """Run the gate against ``config_dir``; ``messages_dir`` enables the dry-run check when it has
    fixtures. Set ``run_lint=False`` to skip the advisory ruff/mypy pass.

    ``service_config`` / ``suppress_service_toml_search`` plumb the ADR 0050 anchor (AC-6): an explicit
    ``messagefoundry.toml`` path (from ``--service-config``, resolved under ``--project-root``) is used
    directly for the posture check, and ``suppress_service_toml_search`` (set when ``--project-root`` is
    given) suppresses the legacy upward-walk so ``check`` matches ``serve``'s resolution. With both
    defaulted (today's ``messagefoundry check --config config``), the upward-walk is preserved — no
    regression.
    """
    results = [
        _check_validate(config_dir),
        _check_dryrun(config_dir, messages_dir),
        _check_posture(
            config_dir,
            service_config=service_config,
            suppress_search=suppress_service_toml_search,
        ),
    ]
    if run_lint:
        results.append(_run_tool("ruff", ["ruff", "check", str(config_dir)]))
        results.append(_run_tool("mypy", ["mypy", str(config_dir)]))
    # Appended AFTER the ruff/mypy advisory block so it only adds an advisory result and never blocks
    # the gate (required=False keeps __main__._check's "0 iff no required check failed" exit policy).
    results.append(_check_raise_fstring(config_dir))
    results.append(_check_accepts_candidate(config_dir))
    results.append(_check_dead_config(config_dir))
    results.append(_check_send_target(config_dir))
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
    ``return None``, or ``return []`` — the empty list). A leading docstring is skipped. This is
    deliberately conservative: a filter buried after real transform work is a genuine handler concern
    (not an applicability rule) and is not flagged — the advisory only targets the leading guard that
    belongs in ``accepts=``.
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
    # bare ``return`` / ``return None`` / ``return []`` are all filter-drops.
    if val is None:
        return True
    if isinstance(val, ast.Constant) and val.value is None:
        return True
    return isinstance(val, ast.List) and not val.elts


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


def _check_dryrun(config_dir: str | Path, messages_dir: str | Path | None) -> CheckResult:
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
    inbound_names = list(reg.inbound)
    message_sets = read_message_sets(mpath, inbound_names)
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
        targets = [target] if target is not None else inbound_names
        if target is not None:
            pinned += 1
        for ic_name in targets:
            total += 1
            result = dry_run(reg, raw, inbound=ic_name)
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
