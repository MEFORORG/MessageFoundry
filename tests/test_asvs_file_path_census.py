# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 5.3.2 file-path census: the places the assessed code builds a file path, in the shapes listed
below, each graded with a written reason and derived from the code, so a new site of those shapes
fails the build until graded.

ASVS 5.3.2 asks that a file path come from internally generated or trusted data, or that a supplied
name pass strict validation and sanitization. Grading a handful of sites by hand cannot show that
for every path, so BACKLOG #1130 asked for a census. This module is that census, with its command
and its positive control.

**The command.** :func:`derived_python_sites` walks the AST of every ``.py`` file under
:data:`PY_ROOTS`. A site is any of these:

1. a ``/`` division whose two sides are not number literals and where one side is path-shaped (a
   string literal, an f-string, a call such as ``Path(...)`` or ``.resolve()``, or a name holding a
   path word such as ``dir``, ``root`` or ``name``, split on underscores);
2. a call to ``os.path.join``, ``posixpath.join`` or ``ntpath.join``, or a join on ``os.sep`` or
   either module's ``sep``;
3. a call to ``.joinpath(...)``, ``.with_name(...)`` or ``.with_stem(...)``;
4. ``Path(...)`` (or a pure-path class) given two or more arguments or a ``*parts``, or given an f-string or a ``+``
   concatenation, and ``open(...)`` given an f-string or a ``+`` concatenation;
5. an augmented ``p /= name`` that would match shape 1.

Sites are counted per enclosing function, keyed ``<file>::<qualname>``. :data:`SITES` must equal
the derived map exactly, counts included, so a new join in a graded function fails too. Line numbers
are not keys, so moving code does not churn the table. :func:`derived_ide_sites` counts
``path.join`` and ``path.resolve`` (``path.posix`` and ``path.win32`` too) and ``.joinPath`` per file under ``ide/src/`` (tests excluded, comments
stripped), and :func:`derived_script_sites` counts ``Join-Path`` and ``[IO.Path]::Combine`` per
operator-run script.

**The positive control.** :func:`test_the_walker_finds_every_shape_and_skips_arithmetic` plants each
shape and some arithmetic in a source string. The planted-omission tests prove the comparison names
a missing or a stale row. When this landed (2026-10-09), a negative control listed every ``/`` the
walker skipped as not path-shaped, and every one was arithmetic. Re-run that listing after widening
or narrowing the path words; :data:`SITES` itself is the current count.

**Scope.** Method section 2 names the engine, the web console, the IDE extension, the harness and
the operator-run scripts (``scripts/service/`` less ``measure-store-access.ps1``). The census adds
``messagefoundry_toolkit`` too: its scope is not ruled, and grading it costs nothing. ``tee/`` is out
by owner ruling and is not walked.

**Grades.** Each site gets one:

- ``internal``: every part is a code literal, an install or package location, or a value the code
  generates itself (a uuid, a token, a pid, a counter, a timestamp, a fixed enum).
- ``operator``: a part comes from the operator, through configuration, a CLI argument, an
  environment variable, or a file in the operator's own config directory or workspace. The operator
  can already name any path on the host, so the join grants nothing new.
- ``listed``: a part is a name read back from listing a directory the code chose itself (an install,
  its own staging directory, the operator's config directory), not one another party supplies.
- ``guarded``: a part another party chooses (a partner server, a message, an archive, an export)
  passes the named guard before the join. The row names that guard. For Python the test checks it
  is still defined where it says, and, where the row says the unit calls it itself, that the call is
  still there. For TypeScript the guard is a fragment of code that must still be present.
- ``compare-only``: the path is built only to compare or test for existence, and nothing is opened,
  read, written, moved or deleted through it.

**Not derived, so not proved here:** at least a join spelled as string concatenation (``d + "/" +
n``) or an f-string that is not passed straight to ``Path`` or ``open``, a ``/`` whose operands carry
no path word, a literal ``"/".join`` (display text everywhere in this code), a TypeScript
template-literal path or a ``path`` module imported under another name in the IDE, a PowerShell path written as a quoted string, named in a
trailing comment, or hidden after a string that starts a line with ``<#``, and a ``tempfile`` ``prefix`` argument. A graded function that changes what feeds
a join without changing the count keeps its grade until someone re-reads it. Where the guard runs in
a caller rather than in the unit, the check proves only that the guard is still defined; where the
unit calls it, the check proves the call is there, not that it runs before the join.
"""

from __future__ import annotations

import ast
import functools
import importlib.util
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

import pytest

from tests._ast_sites import callee_name, find_funcs, parse_source
from tests.test_browser_storage_doc_drift import _js_code

_ROOT = Path(__file__).resolve().parent.parent

#: The Python trees the census walks.
PY_ROOTS: tuple[str, ...] = (
    "messagefoundry",
    "messagefoundry_webconsole",
    "messagefoundry_toolkit",
    "harness",
)

#: The operator-run scripts (method section 2): ``scripts/service/`` less this one CI measurement.
_SCRIPTS_DIR = _ROOT / "scripts" / "service"
_SCRIPTS_EXCLUDED = frozenset({"measure-store-access.ps1"})

_IDE_SRC = _ROOT / "ide" / "src"

INTERNAL = "internal"
OPERATOR = "operator"
LISTED = "listed"
GUARDED = "guarded"
COMPARE_ONLY = "compare-only"
GRADES = frozenset({INTERNAL, OPERATOR, LISTED, GUARDED, COMPARE_ONLY})


class Site(NamedTuple):
    """One graded unit: how many sites it holds, its grade, why, and for ``guarded`` the guard as
    ``<repo-relative file>::<symbol>`` (a Python function) or ``<file>::<code fragment>`` (anything
    else). ``called`` says the unit calls a Python guard itself, which the test then checks."""

    sites: int
    grade: str
    reason: str
    guard: str = ""
    called: bool = False


# --- the walker ----------------------------------------------------------------------------------

_PATH_TOKENS = frozenset(
    {
        "archive", "assets", "companion", "cwd", "db", "dest", "dir", "directory", "dirs", "dll",
        "exe", "file", "filename", "folder", "full", "here", "home", "keep", "local", "logs", "main",
        "name", "out", "parent", "path", "paths", "pkg", "prefix", "private", "profiles", "rel",
        "repo", "resolved", "root", "scripts", "spool", "src", "staging", "static", "stem", "suffix",
        "td", "temp", "tmp", "trigger", "where", "work",
    }
)  # fmt: skip
_PATH_CALLS = frozenset(
    {
        "Path", "PurePath", "PurePosixPath", "PureWindowsPath", "absolute", "cwd", "dirname",
        "expanduser", "files", "home", "joinpath", "resolve", "with_name", "with_suffix",
    }
)  # fmt: skip
_PATH_CTORS = frozenset({"Path", "PurePath", "PurePosixPath", "PureWindowsPath"})
_JOIN_MODULES = frozenset({"os.path", "posixpath", "ntpath"})
#: Receivers of a separator join such as ``os.sep.join(parts)``. A literal ``"/".join`` is left out:
#: in this code it builds display text (``a/b/c`` in a message), never a file path.
_SEPARATORS = frozenset({"os.sep", "os.path.sep", "posixpath.sep", "ntpath.sep"})


def _ident_is_pathy(ident: str) -> bool:
    return any(token.lower() in _PATH_TOKENS for token in re.split(r"_+", ident) if token)


def _is_pathy(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call):
        name = callee_name(node) or ""
        return name in _PATH_CALLS or _ident_is_pathy(name)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _is_pathy(node.left) or _is_pathy(node.right)
    if isinstance(node, ast.Attribute):
        return _ident_is_pathy(node.attr)
    if isinstance(node, ast.Name):
        return _ident_is_pathy(node.id)
    if isinstance(node, ast.Subscript):
        return _is_pathy(node.value)
    if isinstance(node, ast.BoolOp | ast.IfExp):
        return any(
            _is_pathy(child) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)
        )
    return False


def _is_number(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, int | float)


def _is_composed_text(node: ast.expr) -> bool:
    return isinstance(node, ast.JoinedStr) or (
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
    )


class _Walker(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []
        self.sites: Counter[str] = Counter()

    def _scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scope

    def _hit(self) -> None:
        self.sites[".".join(self.stack) or "<module>"] += 1

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if _is_path_div(node.op, node.left, node.right):
            # One site per chain: ``root / a / b`` is one join, so its inner ``/`` is not re-counted,
            # but a join nested in an operand (``out / os.path.join(a, b)``) still is.
            self._hit()
            self._visit_chain(node)
            return
        self.generic_visit(node)

    def _visit_chain(self, node: ast.expr) -> None:
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            self._visit_chain(node.left)
            self._visit_chain(node.right)
        else:
            self.visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if _is_path_div(node.op, node.target, node.value):  # ``target /= name``
            self._hit()
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _is_path_call(node):
            self._hit()
        self.generic_visit(node)


def _is_path_div(op: ast.operator, left: ast.expr, right: ast.expr) -> bool:
    """Shape 1 of the module docstring."""
    return (
        isinstance(op, ast.Div)
        and not _is_number(left)
        and not _is_number(right)
        and (_is_pathy(left) or _is_pathy(right))
    )


def _is_path_call(node: ast.Call) -> bool:
    """Shapes 2 to 4 of the module docstring."""
    name = callee_name(node) or ""
    composed = bool(node.args) and _is_composed_text(node.args[0])
    if isinstance(node.func, ast.Attribute):
        receiver = ast.unparse(node.func.value)
        if name == "join" and (receiver in _JOIN_MODULES or receiver in _SEPARATORS):
            return True
        if name in ("joinpath", "with_name", "with_stem"):
            return True
    if name in _PATH_CTORS:
        starred = any(isinstance(arg, ast.Starred) for arg in node.args)
        return len(node.args) > 1 or composed or starred
    return name == "open" and composed


def path_sites(source: str) -> Counter[str]:
    """Path-building sites in ``source``, counted per enclosing qualname."""
    walker = _Walker()
    walker.visit(ast.parse(source))
    return walker.sites


def derived_python_sites() -> dict[str, int]:
    found: dict[str, int] = {}
    for top in PY_ROOTS:
        for path in sorted((_ROOT / top).rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            for unit, count in path_sites(path.read_text(encoding="utf-8-sig")).items():
                found[f"{rel}::{unit}"] = count
    return found


_TS_JOIN = re.compile(r"\bpath\.(?:(?:posix|win32)\.)?(?:join|resolve)\s*\(|\.joinPath\s*\(")


_PS_JOIN = re.compile(r"\bJoin-Path\b|\[(?:System\.)?IO\.Path\]::Combine", re.I)


@functools.cache
def _powershell_code() -> Callable[[str], list[str]]:
    """The leak-and-crypto gate's PowerShell comment stripper, loaded the way its own tests load it.
    It knows a ``<#`` inside a string or a trailing comment opens no block."""
    spec = importlib.util.spec_from_file_location(
        "_census_crypto_inventory_check",
        _ROOT / "scripts" / "security" / "crypto_inventory_check.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    strip: Callable[[str], list[str]] = module._powershell_code
    return strip


def _code_text(path: Path) -> str:
    """``path``'s code with comments removed: :func:`_js_code` for TypeScript, which skips strings,
    and the crypto gate's PowerShell stripper, whose limits the module docstring lists."""
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix == ".ts":
        return _js_code(text)
    if path.suffix == ".ps1":
        return "\n".join(_powershell_code()(text))
    raise ValueError(f"no comment stripper for {path.suffix} files")


def _count_per_file(paths: list[Path], join: re.Pattern[str]) -> dict[str, int]:
    found: dict[str, int] = {}
    for path in paths:
        count = len(join.findall(_code_text(path)))
        if count:
            found[path.relative_to(_ROOT).as_posix()] = count
    return found


def derived_ide_sites() -> dict[str, int]:
    paths = [
        p for p in sorted(_IDE_SRC.rglob("*.ts")) if "test" not in p.relative_to(_IDE_SRC).parts
    ]
    return _count_per_file(paths, _TS_JOIN)


def derived_script_sites() -> dict[str, int]:
    paths = [p for p in sorted(_SCRIPTS_DIR.glob("*.ps1")) if p.name not in _SCRIPTS_EXCLUDED]
    return _count_per_file(paths, _PS_JOIN)


# --- the graded census ---------------------------------------------------------------------------

_PKG_LITERAL = "Package-relative literal."
_PROC_PID = "A /proc path for an integer pid."
_TRAY_FIXED = "A fixed name in the tray's config directory."
_CONFIG_FIXED = "A fixed name under the operator's config directory."
_TEMP_FIXED = "A fixed name in a temp directory the runner made."
_SQLITE_SIDECARS = "Fixed SQLite sidecar suffixes on the operator's store path."
_PKG_WALK = "Names from walking the installed package directory."
_REPO_LITERAL = "Repo-relative literal."
_CERT_OUT = "A fixed file name under the --out directory the operator named."
_STORE_PATH = "The [store].path the operator configured, or its directory, joined to a fixed name."
_CODESETS = "The operator's config directory joined to the fixed codesets directory name."
_CODESET_NAME = "A code-set name from the CLI or the IDE webview, refused by the guard before it."
_STAGING = "Fixed lock or marker names inside a staging directory this module created."
_CONFINED = (
    "Parts of a partner-dropped name the guard split below the watch root, refusing an empty, `.` "
    "or `..` part; the open then walks without following a link."
)
_DEST_NAME = "A name the engine rendered through the guard, never a raw message field."
_LISTING = (
    "A server-chosen listing name; the guard refuses it at the head of the poll loop, before every "
    "consumer."
)
_TRAY_SERVICE = "The service's app directory and parameters, read from the service registration."
_PROFILE_NAME = (
    "A profile name from the operator's CLI flag; the same flag accepts any full path, so the join "
    "grants nothing new. Read only."
)

SITES: dict[str, Site] = {
    # --- harness/ ---
    "harness/acceptance/probes.py::probe_console_no_window": Site(1, INTERNAL, _REPO_LITERAL),
    "harness/acceptance/probes.py::probe_python_runtime": Site(1, INTERNAL, _REPO_LITERAL),
    "harness/acceptance/runner.py::default_pytest_runner": Site(1, INTERNAL, _TEMP_FIXED),
    "harness/config/connscale/gen_toml.py::write_config_dir": Site(
        2, OPERATOR, "Fixed names under the output directory the operator named."
    ),
    "harness/drivers/file.py::_check_contained": Site(
        1, COMPARE_ONLY, "The containment guard itself: it builds the target only to compare it."
    ),
    "harness/drivers/file.py::drop_atomic": Site(
        2,
        GUARDED,
        "The drop name (a message's MSH-10 on the Compose tab) is refused unless it is one plain "
        "file name in the directory; the collision name adds only `-N` digits to it.",
        "harness/drivers/file.py::_check_contained",
        called=True,
    ),
    "harness/drivers/file.py::unique_path": Site(
        1, INTERNAL, "A `-N` counter on a target drop_atomic already checked."
    ),
    "harness/drivers/remotefile.py::RemoteFileDriver._upload": Site(
        2, INTERNAL, "A uuid4 name under the remote directory the operator configured."
    ),
    "harness/fuzz/campaign.py::_Session._write": Site(
        1, INTERNAL, "A name built from the seed, iteration and transport kind, all generated."
    ),
    "harness/load/_lookup.py::<module>": Site(2, INTERNAL, "Package-relative literals."),
    "harness/load/_lookup.py::local_profiles_dir": Site(
        1, INTERNAL, "A fixed subpath under the working directory."
    ),
    "harness/load/_lookup.py::resolve_profile": Site(2, OPERATOR, _PROFILE_NAME),
    "harness/load/connscale/batchbox.py::_drive_cell_fleet": Site(
        1,
        INTERNAL,
        "The cell id joins profile axis values with fixed tags; the report directory is the "
        "operator's.",
    ),
    "harness/load/connscale/probe.py::FdSampler._enumerate_posix": Site(
        1, LISTED, "A /proc entry name, kept only when it is all digits."
    ),
    "harness/load/connscale/probe.py::FdSampler._posix_cpu_seconds": Site(1, INTERNAL, _PROC_PID),
    "harness/load/connscale/probe.py::FdSampler._posix_handles": Site(1, INTERNAL, _PROC_PID),
    "harness/load/connscale/probe.py::FdSampler._posix_rss_bytes": Site(1, INTERNAL, _PROC_PID),
    "harness/load/connscale/runner.py::_run_one_step": Site(
        1, INTERNAL, "A tag of fixed arms and integers in a temp directory the runner made."
    ),
    "harness/load/coord.py::FileDropCoord._path": Site(
        1,
        INTERNAL,
        "The run id and message name come from code (a base id plus a cell id or rung suffix); the "
        "coord directory is the operator's.",
    ),
    "harness/load/coord.py::FileDropCoord.post": Site(
        1, INTERNAL, "A pid and nanosecond temp suffix on the target _path built."
    ),
    "harness/load/estate/runner.py::_run_one": Site(1, INTERNAL, _TEMP_FIXED),
    "harness/load/failover.py::EngineNode.__init__": Site(
        1,
        INTERNAL,
        "The node id comes from code; the keep directory is the operator's MEFOR_BENCH_KEEP_NODE_LOGS.",
    ),
    "harness/load/ingress_probe.py::_probe": Site(
        1, INTERNAL, "A fixed name in a temp directory the probe made."
    ),
    "harness/load/shardcert_ladder.py::_rung_log_paths": Site(
        1, INTERNAL, "Shard ids from the profile, under the operator's keep directory."
    ),
    "harness/load/shardcert_ladder.py::run_engine_ladder": Site(
        2, INTERNAL, "A rung suffix (`r<int>` or `soak`) under the operator's keep directory."
    ),
    "harness/load/tlsmat.py::harness_tls_material": Site(
        2, INTERNAL, "Fixed names in the harness state directory."
    ),
    "harness/scenarios/hostile.py::<module>": Site(1, INTERNAL, _PKG_LITERAL),
    "harness/scenarios/hostile.py::escaped_files": Site(
        1,
        COMPARE_ONLY,
        "Builds where a hostile control id WOULD land, to test for an escape; it checks existence "
        "only and skips a NUL-bearing id.",
    ),
    "harness/sinks/_sftp_server.py::_confined": Site(
        2, COMPARE_ONLY, "The served-directory guard itself: it normalizes against `/` and checks."
    ),
    "harness/sinks/_sftp_server.py::_interface._Share.canonicalize": Site(
        1, COMPARE_ONLY, "Returns a normalized remote path string; no file operation."
    ),
    "harness/sinks/_sftp_server.py::_interface._Share.list_folder": Site(
        1,
        GUARDED,
        "Lists a directory the guard confined first, then joins the names that listing returned.",
        "harness/sinks/_sftp_server.py::_confined",
        called=True,
    ),
    # --- messagefoundry/ ---
    "messagefoundry/__main__.py::_cert_import": Site(3, OPERATOR, _CERT_OUT),
    "messagefoundry/__main__.py::_cert_self_signed": Site(2, OPERATOR, _CERT_OUT),
    "messagefoundry/__main__.py::_check_env_file_present": Site(
        1,
        COMPARE_ONLY,
        "The raw --env value joined under the project root to test that the value file exists.",
    ),
    "messagefoundry/__main__.py::_emit_anchor_diagnostics": Site(
        1, COMPARE_ONLY, "The working directory and a fixed name, tested for existence."
    ),
    "messagefoundry/__main__.py::_forward_spool_dir": Site(
        1, OPERATOR, "A shard id from --shard or the operator's config, under the spool root."
    ),
    "messagefoundry/__main__.py::_forward_spool_root": Site(1, OPERATOR, _STORE_PATH),
    "messagefoundry/__main__.py::_is_console_source_checkout": Site(
        2, COMPARE_ONLY, "Package-relative literals, tested for existence."
    ),
    "messagefoundry/__main__.py::_renew_api_tls_before_spawning": Site(1, OPERATOR, _STORE_PATH),
    "messagefoundry/__main__.py::_resolve_offline_anchor": Site(
        1, OPERATOR, "A fixed name under the project root the operator named."
    ),
    "messagefoundry/__main__.py::_serve": Site(
        2,
        GUARDED,
        "The store path is the operator's; the environment name passes the settings validator, "
        "which allows no separator.",
        "messagefoundry/config/settings.py::_valid_environment_name",
    ),
    "messagefoundry/__main__.py::_supervisor_forward_spool_dir": Site(2, OPERATOR, _STORE_PATH),
    "messagefoundry/__main__.py::_webconsole_provenance_problem": Site(
        1, COMPARE_ONLY, "A package-relative literal, compared."
    ),
    "messagefoundry/_child_bootstrap.py::_load_this_build": Site(
        1, INTERNAL, "A fixed name in the engine's own package directory."
    ),
    "messagefoundry/anon/leak.py::_scanner": Site(1, INTERNAL, _PKG_LITERAL),
    "messagefoundry/anon/surrogates.py::_resolve_token_text": Site(
        1, INTERNAL, "A fixed name under a parent of the package."
    ),
    "messagefoundry/api/tls.py::_generated_pair": Site(
        2, INTERNAL, "Fixed names in the engine's state directory."
    ),
    "messagefoundry/api/tls.py::_generated_pair_lock": Site(
        1, INTERNAL, "A fixed name in the engine's state directory."
    ),
    "messagefoundry/api/tls.py::_staged_pair": Site(
        2, OPERATOR, "A fixed suffix on the certificate paths the operator configured."
    ),
    "messagefoundry/auth/anchor_path.py::posix_path_verdict": Site(
        2,
        OPERATOR,
        "Walks the operator's configured path component by component to judge it; names come from "
        "that path and its own link targets.",
    ),
    "messagefoundry/auth/anchor_path.py::windows_chain": Site(
        4,
        OPERATOR,
        "Walks the operator's configured path component by component to judge it; names come from "
        "that path and its own reparse targets.",
    ),
    "messagefoundry/auth/policy.py::_common_passwords": Site(
        1, INTERNAL, "Package resource literal."
    ),
    "messagefoundry/checks.py::_expected_disposition": Site(
        1, OPERATOR, "A fixed suffix on a fixture path from the operator's config directory."
    ),
    "messagefoundry/checks.py::_find_service_toml": Site(
        1, OPERATOR, "A fixed name under a directory the operator named."
    ),
    "messagefoundry/checks.py::_resolve_service_toml": Site(
        1, OPERATOR, "A fixed name under the config directory the operator named."
    ),
    "messagefoundry/checks.py::_unread_working_dir_toml": Site(
        1, INTERNAL, "A fixed name in the working directory."
    ),
    "messagefoundry/childenv.py::<module>": Site(1, INTERNAL, _PKG_LITERAL),
    "messagefoundry/config/anchor.py::anchor_under_root": Site(
        2, OPERATOR, "A config path value anchored under the project root the operator named."
    ),
    "messagefoundry/config/atomic_edit.py::lock_path_for": Site(
        1, INTERNAL, "A fixed lock name beside the edited file."
    ),
    "messagefoundry/config/atomic_edit.py::replace_validated": Site(
        2,
        OPERATOR,
        "The edited config file's own name, in a private temp directory this function made.",
    ),
    "messagefoundry/config/code_sets.py::_policy_sidecar_path": Site(
        1, LISTED, "A fixed suffix on a code-set file found in the config directory."
    ),
    "messagefoundry/config/code_sets.py::is_policy_sidecar": Site(
        2, COMPARE_ONLY, "A listed file's own stem, tested for a companion's existence."
    ),
    "messagefoundry/config/codeset_edit.py::_codesets_dir": Site(1, OPERATOR, _CODESETS),
    "messagefoundry/config/codeset_edit.py::_existing_path_or_none": Site(
        1,
        GUARDED,
        "Every caller runs the guard on the name first (BACKLOG #1130 shipped the rename source).",
        "messagefoundry/config/codeset_edit.py::_validate_name",
    ),
    "messagefoundry/config/codeset_edit.py::_reject_toml_collision": Site(
        1, GUARDED, _CODESET_NAME, "messagefoundry/config/codeset_edit.py::_validate_name"
    ),
    "messagefoundry/config/codeset_edit.py::_validate_name": Site(
        1, COMPARE_ONLY, "The guard itself: it resolves the candidate to check its parent."
    ),
    "messagefoundry/config/codeset_edit.py::rename_code_set": Site(
        1,
        GUARDED,
        _CODESET_NAME,
        "messagefoundry/config/codeset_edit.py::_validate_name",
        called=True,
    ),
    "messagefoundry/config/codeset_edit.py::upsert_code_set": Site(
        1,
        GUARDED,
        _CODESET_NAME,
        "messagefoundry/config/codeset_edit.py::_validate_name",
        called=True,
    ),
    "messagefoundry/config/connections_edit.py::_path": Site(1, OPERATOR, _CONFIG_FIXED),
    "messagefoundry/config/connections_file.py::connections_file_path": Site(
        1, OPERATOR, _CONFIG_FIXED
    ),
    "messagefoundry/config/connections_file.py::validating_candidate": Site(
        1, OPERATOR, _CONFIG_FIXED
    ),
    "messagefoundry/config/environments.py::load_environment_values": Site(
        1,
        GUARDED,
        "Every caller passes [ai].environment, which the validator holds to letters, digits, `.`, "
        "`_` and `-`.",
        "messagefoundry/config/settings.py::_valid_environment_name",
    ),
    "messagefoundry/config/environments.py::resolve_values_base_dir": Site(
        1, OPERATOR, "The operator's [environments].base_dir under the working directory."
    ),
    "messagefoundry/config/fingerprint.py::_git_head": Site(
        7,
        OPERATOR,
        "Reads the git metadata of the operator's own config checkout; read only, to a commit hash.",
    ),
    "messagefoundry/config/impact.py::_validate_new_name": Site(1, OPERATOR, _CODESETS),
    "messagefoundry/config/tls_policy.py::staged_crl": Site(
        1, INTERNAL, "A fixed name in a private temp directory this function made."
    ),
    "messagefoundry/config/wiring.py::_HelperImporter._load": Site(
        1, OPERATOR, "A helper module name from an import in the operator's own config code."
    ),
    "messagefoundry/config/wiring.py::load_config": Site(1, OPERATOR, _CODESETS),
    "messagefoundry/config/wiring.py::validate_config": Site(1, OPERATOR, _CODESETS),
    "messagefoundry/corepoint_import.py::_replace_modules": Site(
        1, INTERNAL, "A pid temp name beside a target the importer already built."
    ),
    "messagefoundry/corepoint_import.py::import_corepoint": Site(
        1,
        GUARDED,
        "The module stem from an export's inbound name is folded through the guard (BACKLOG #1130).",
        "messagefoundry/corepoint_import.py::_sanitize",
    ),
    "messagefoundry/generators/_core.py::write_corpus": Site(
        2,
        OPERATOR,
        "A trigger checked against the registry before the join, and a numbered file name, under "
        "the operator's --out.",
    ),
    "messagefoundry/integrity.py::_attested_asset_files": Site(
        1, INTERNAL, "Fixed asset paths under the installed package."
    ),
    "messagefoundry/integrity.py::_console_loaded_files": Site(3, LISTED, _PKG_WALK),
    "messagefoundry/integrity.py::_import_capable_files": Site(1, LISTED, _PKG_WALK),
    "messagefoundry/log_spool.py::LogSpool._path": Site(
        1, INTERNAL, "A fixed prefix and an integer sequence in the spool directory."
    ),
    "messagefoundry/log_spool.py::LogSpool.discard_unused": Site(
        1, INTERNAL, "A fixed lock name in the spool directory."
    ),
    "messagefoundry/log_spool.py::LogSpool.open": Site(
        1, INTERNAL, "A fixed lock name in the spool directory."
    ),
    "messagefoundry/pipeline/dr_backup.py::BackupRunner._add_config_dir": Site(
        1, LISTED, "Parents of files found walking the operator's config directory."
    ),
    "messagefoundry/pipeline/dr_backup.py::BackupRunner._build_archive_blocking": Site(
        1, INTERNAL, "A fixed name in a work directory this module made."
    ),
    "messagefoundry/pipeline/dr_backup.py::BackupRunner._do_backup": Site(
        3,
        GUARDED,
        "The instance name is reduced by the guard; the stamp, extension and suffixes are fixed, "
        "under the operator's backup destination.",
        "messagefoundry/pipeline/dr_backup.py::_safe_segment",
        called=True,
    ),
    "messagefoundry/pipeline/dr_backup.py::BackupRunner._keep_failed_archive": Site(
        1, INTERNAL, "A fixed suffix on an archive path this module built."
    ),
    "messagefoundry/pipeline/dr_backup.py::BackupRunner._preflight_destination": Site(
        1, OPERATOR, "A fixed probe name in the operator's backup destination."
    ),
    "messagefoundry/pipeline/dr_backup.py::_empty_files_in_place": Site(
        3, LISTED, "Names from walking a staging directory this module made, never through a link."
    ),
    "messagefoundry/pipeline/dr_backup.py::_extract_member": Site(
        1, INTERNAL, "A fixed name in a destination this module chose."
    ),
    "messagefoundry/pipeline/dr_backup.py::_is_staging_dir": Site(1, COMPARE_ONLY, _STAGING),
    "messagefoundry/pipeline/dr_backup.py::_open_staging": Site(2, INTERNAL, _STAGING),
    "messagefoundry/pipeline/dr_backup.py::_refuse_colliding_config_members": Site(
        2,
        COMPARE_ONLY,
        "Archive member names joined only to compare against the paths the restore writes; the "
        "restore itself gates every name.",
    ),
    "messagefoundry/pipeline/dr_backup.py::_refuse_existing_destination": Site(
        1, COMPARE_ONLY, "Fixed sidecar suffixes on the operator's --to path, tested for existence."
    ),
    "messagefoundry/pipeline/dr_backup.py::_restore_blocking": Site(
        1, INTERNAL, "A fixed name in a staging directory this module made."
    ),
    "messagefoundry/pipeline/dr_backup.py::_restore_config_members": Site(
        1,
        GUARDED,
        "Each archive member name passes the guard, then a resolved-path containment backstop.",
        "messagefoundry/parsing/sniff.py::archive_member_name_reason",
        called=True,
    ),
    "messagefoundry/pipeline/dr_backup.py::_staging_root_for": Site(
        1, INTERNAL, "A fixed directory name under the operator's destination."
    ),
    "messagefoundry/pipeline/dr_backup.py::_sweep_abandoned_staging": Site(
        3,
        INTERNAL,
        "Fixed lock and marker names inside directories listed by this module's own prefix, after "
        "link and owner checks.",
    ),
    "messagefoundry/pipeline/dr_backup.py::_teardown_staging": Site(1, INTERNAL, _STAGING),
    "messagefoundry/pipeline/dr_backup.py::_tree_size": Site(
        1, LISTED, "Names from walking a directory this module measures; lstat only."
    ),
    "messagefoundry/pipeline/dr_backup.py::_verify_in_staging": Site(
        1, INTERNAL, "A fixed name in a staging directory this module made."
    ),
    "messagefoundry/pipeline/supervisor.py::_shard_db_path": Site(
        1, OPERATOR, "A shard tag from the operator's config on the operator's --db path."
    ),
    "messagefoundry/scaffold.py::scaffold": Site(
        1, INTERNAL, "Template paths from the module's own table, under the operator's target."
    ),
    "messagefoundry/security/__init__.py::handler_semgrep_rules": Site(
        1, INTERNAL, "Package resource literal."
    ),
    "messagefoundry/service.py::install_script_path": Site(
        1, INTERNAL, "A repo-relative literal beside the installed package."
    ),
    "messagefoundry/service.py::uninstall_script_path": Site(
        1, INTERNAL, "A repo-relative literal beside the installed package."
    ),
    "messagefoundry/service_status.py::_system_dir": Site(
        1, OPERATOR, "The system directory from the OS, or the host's SystemRoot as a fallback."
    ),
    "messagefoundry/service_status.py::_system_exe": Site(
        1, INTERNAL, "Fixed executable names in the system directory."
    ),
    "messagefoundry/startupcode.py::_made_by_a_packaging_tool": Site(
        1, INTERNAL, "A fixed name under the interpreter prefix."
    ),
    "messagefoundry/startupcode.py::_pth_items": Site(
        1, LISTED, "`.pth` names from listing a site-packages directory, to inventory them."
    ),
    "messagefoundry/store/store.py::MessageStore._db_size_bytes": Site(
        1, OPERATOR, _SQLITE_SIDECARS
    ),
    "messagefoundry/store/store.py::MessageStore._ensure_schema": Site(
        2, OPERATOR, _SQLITE_SIDECARS
    ),
    "messagefoundry/store/store.py::forget_store_salt": Site(
        1, OPERATOR, "A fixed SQLite sidecar suffix on the operator's store path."
    ),
    "messagefoundry/transports/file.py::FileDestination._write": Site(
        1, GUARDED, _DEST_NAME, "messagefoundry/transports/file.py::render_filename", called=True
    ),
    "messagefoundry/transports/file.py::FileSource.__init__": Site(
        2, OPERATOR, "The operator's processed and error subdirectory settings."
    ),
    "messagefoundry/transports/file.py::_archive": Site(
        1,
        GUARDED,
        "The listed file's own base name, which the read already confined, into an archive "
        "directory opened through no link.",
        "messagefoundry/transports/file.py::_listed_parts",
    ),
    "messagefoundry/transports/file.py::_free_names": Site(
        1, INTERNAL, "A `-N` counter on a target the caller already built."
    ),
    "messagefoundry/transports/file.py::_mkstemp_at": Site(
        1, INTERNAL, "A pid and monotonic-clock temp name."
    ),
    "messagefoundry/transports/file.py::_open_confined": Site(
        1, GUARDED, _CONFINED, "messagefoundry/transports/file.py::_listed_parts", called=True
    ),
    "messagefoundry/transports/file.py::_open_dest": Site(
        1,
        OPERATOR,
        "The operator's archive directory, split below the watch root.",
    ),
    "messagefoundry/transports/file.py::_win_hold_dirs": Site(
        1, OPERATOR, "Parts of the operator's archive directory below the watch root."
    ),
    "messagefoundry/transports/file.py::_win_open_confined": Site(
        1, GUARDED, _CONFINED, "messagefoundry/transports/file.py::_listed_parts"
    ),
    "messagefoundry/transports/remotefile.py::RemoteFileDestination._unique": Site(
        1,
        GUARDED,
        "Candidates come from the rendered name; names the partner server lists are only compared.",
        "messagefoundry/transports/file.py::render_filename",
    ),
    "messagefoundry/transports/remotefile.py::RemoteFileDestination._upload": Site(
        2, GUARDED, _DEST_NAME, "messagefoundry/transports/file.py::render_filename", called=True
    ),
    "messagefoundry/transports/remotefile.py::RemoteFileSource.__init__": Site(
        2, OPERATOR, "The operator's processed and error subdirectory settings."
    ),
    "messagefoundry/transports/remotefile.py::RemoteFileSource._after_processing": Site(
        1, GUARDED, _LISTING, "messagefoundry/transports/remotefile.py::_is_contained_name"
    ),
    "messagefoundry/transports/remotefile.py::RemoteFileSource._file_key": Site(
        1, GUARDED, _LISTING, "messagefoundry/transports/remotefile.py::_is_contained_name"
    ),
    "messagefoundry/transports/remotefile.py::RemoteFileSource._move": Site(
        1, GUARDED, _LISTING, "messagefoundry/transports/remotefile.py::_is_contained_name"
    ),
    "messagefoundry/transports/remotefile.py::RemoteFileSource._poll_once": Site(
        1,
        GUARDED,
        _LISTING,
        "messagefoundry/transports/remotefile.py::_is_contained_name",
        called=True,
    ),
    "messagefoundry/transports/remotefile.py::_FtpClient._list": Site(
        1,
        GUARDED,
        "An NLST entry loses only an exact `remote_dir/` prefix (as spelled, or with trailing "
        "slashes collapsed) and is never folded, so `../x/a.hl7` reaches the guard as sent. It is sized only when the guard "
        "accepts it (BACKLOG #1130); a refused one still lists, unsized, for the poll loop to "
        "refuse and log.",
        "messagefoundry/transports/remotefile.py::_is_contained_name",
        called=True,
    ),
    "messagefoundry/tray/__main__.py::_setup_logging": Site(
        1, INTERNAL, "A fixed log name in the tray's config directory."
    ),
    "messagefoundry/tray/actions.py::_launcher_for": Site(
        1, OPERATOR, "A fixed executable name beside the VS Code install the host reports."
    ),
    "messagefoundry/tray/autostart.py::pythonw_executable": Site(
        1, INTERNAL, "A fixed name beside the running interpreter."
    ),
    "messagefoundry/tray/branding.py::_base_pythonw": Site(
        2, INTERNAL, "A fixed name beside the base interpreter."
    ),
    "messagefoundry/tray/branding.py::_stage_runtime": Site(
        1, LISTED, "Runtime DLL names found beside the base interpreter, copied into Scripts."
    ),
    "messagefoundry/tray/branding.py::ensure_branded_launcher": Site(
        1, INTERNAL, "A fixed launcher name in the venv's Scripts directory."
    ),
    "messagefoundry/tray/config.py::default_config_dir": Site(
        2, INTERNAL, "Fixed names under the user's profile directories."
    ),
    "messagefoundry/tray/config.py::ensure_tray_toml": Site(1, INTERNAL, _TRAY_FIXED),
    "messagefoundry/tray/config.py::generated_cert_path": Site(2, OPERATOR, _TRAY_SERVICE),
    "messagefoundry/tray/config.py::load_config": Site(1, INTERNAL, _TRAY_FIXED),
    "messagefoundry/tray/config.py::service_toml_path": Site(2, OPERATOR, _TRAY_SERVICE),
    "messagefoundry/tray/iconset.py::<module>": Site(1, INTERNAL, _PKG_LITERAL),
    "messagefoundry/tray/iconset.py::icon_path": Site(
        1, INTERNAL, "An icon name built from fixed state and theme values."
    ),
    "messagefoundry/uploads.py::UploadStore._paths": Site(
        2,
        INTERNAL,
        "A 32-hex id the store generated, refused by regex if malformed, then a parent check.",
    ),
    "messagefoundry/uploads.py::_atomic_write_text": Site(
        1, INTERNAL, "A random-token temp name beside a path the store built."
    ),
    "messagefoundry_toolkit/adr_analyze.py::_criteria": Site(
        1,
        GUARDED,
        "A test reference from an ADR, kept only when it stays inside the repo; existence check only.",
        "messagefoundry_toolkit/adr_analyze.py::_inside",
        called=True,
    ),
    "messagefoundry_webconsole/__init__.py::<module>": Site(1, INTERNAL, _PKG_LITERAL),
}

_IDE_WORKSPACE = (
    "The workspace folder joined to the extension's own settings or fixed names; the workspace and "
    "its settings are the operator's."
)
_IDE_MEDIA = "The extension's install directory joined to fixed media or snippet names."

IDE_SITES: dict[str, Site] = {
    "ide/src/chat.ts": Site(1, INTERNAL, _IDE_MEDIA),
    "ide/src/cli.ts": Site(2, OPERATOR, "Fixed venv interpreter paths under the workspace."),
    "ide/src/configRefresh.ts": Site(1, OPERATOR, _IDE_WORKSPACE),
    "ide/src/editorToolbar.ts": Site(1, OPERATOR, _IDE_WORKSPACE),
    "ide/src/engineTrustModel.ts": Site(
        1, OPERATOR, "The trust anchor setting, resolved under the workspace."
    ),
    "ide/src/extension.ts": Site(
        2,
        OPERATOR,
        "openSource joins a file the engine's graph reports, or the open document, onto the "
        "workspace and opens it in an ordinary, editable editor; the second join is a settings directory. "
        "No receiver re-checks that the path is one the graph reported.",
    ),
    "ide/src/generate.ts": Site(
        2, OPERATOR, "A message type picked from a fixed list, under the message-sets setting."
    ),
    "ide/src/graphTree.ts": Site(1, OPERATOR, _IDE_WORKSPACE),
    "ide/src/hl7schema.ts": Site(1, INTERNAL, _IDE_MEDIA),
    "ide/src/insertElement.ts": Site(1, INTERNAL, _IDE_MEDIA),
    "ide/src/liveDebug.ts": Site(
        4,
        OPERATOR,
        "A sample the operator picked from a listing of the samples setting, and paths compared "
        "for a breakpoint match.",
    ),
    "ide/src/newRoute.ts": Site(
        2,
        GUARDED,
        "The wizard's inbound name is reduced to `[A-Za-z0-9_-]` before it names the new file.",
        'ide/src/newRoute.ts::.replace(/[^A-Za-z0-9_-]/g, "_")}.py`',
    ),
    "ide/src/promote.ts": Site(1, OPERATOR, _IDE_WORKSPACE),
    "ide/src/sourceControl.ts": Site(7, OPERATOR, _IDE_WORKSPACE),
    "ide/src/statusBar.ts": Site(2, OPERATOR, _IDE_WORKSPACE),
    "ide/src/stepsView.ts": Site(3, OPERATOR, _IDE_WORKSPACE + " Two are fixed media names."),
    "ide/src/symbolIndex.ts": Site(
        1, LISTED, "Names from listing the operator's config directory."
    ),
    "ide/src/testBench.ts": Site(
        3,
        INTERNAL,
        "A temp directory the extension made and generated case-file names, or the fixtures setting.",
    ),
    "ide/src/validate.ts": Site(1, OPERATOR, _IDE_WORKSPACE),
}

SCRIPT_SITES: dict[str, Site] = {
    "scripts/service/install-net-helper.ps1": Site(
        7, OPERATOR, "Fixed names under the repo root, the helper source and the install directory."
    ),
    "scripts/service/install-service.ps1": Site(
        19,
        OPERATOR,
        "Fixed names under paths the operator passes or the script derives (repo root, data "
        "directory, NSSM directory, temp), plus registry keys named after the service's own images.",
    ),
    "scripts/service/uninstall-net-helper.ps1": Site(
        1, OPERATOR, "A fixed name under the install directory."
    ),
    "scripts/service/uninstall-service.ps1": Site(
        5, OPERATOR, "Fixed names under temp and registry keys named after the service's images."
    ),
}


# --- the checks ----------------------------------------------------------------------------------


def _compare(derived: dict[str, int], graded: dict[str, Site]) -> list[str]:
    """Every way ``graded`` disagrees with ``derived``, as one line each. Empty means equal."""
    problems: list[str] = []
    for key in sorted(derived.keys() - graded.keys()):
        problems.append(f"UNGRADED: {key} builds {derived[key]} path(s); add a SITES row")
    for key in sorted(graded.keys() - derived.keys()):
        problems.append(f"STALE: {key} builds no path now; remove its row")
    for key in sorted(derived.keys() & graded.keys()):
        if derived[key] != graded[key].sites:
            problems.append(
                f"RECOUNT: {key} builds {derived[key]} path(s), graded for {graded[key].sites}; "
                "re-read it and re-grade"
            )
    return problems


def _guard_problems(graded: dict[str, Site]) -> list[str]:
    problems: list[str] = []
    for key, site in sorted(graded.items()):
        if site.grade not in GRADES:
            problems.append(f"{key}: unknown grade {site.grade!r}")
        if not site.reason.strip():
            problems.append(f"{key}: no reason")
        if site.grade != GUARDED:
            if site.guard or site.called:
                problems.append(f"{key}: names a guard but is graded {site.grade}")
            continue
        if not site.guard:
            problems.append(f"{key}: graded guarded but names no guard")
            continue
        problems.extend(f"{key}: {p}" for p in _guard_missing(key, site))
    return problems


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _scopes_named(node: ast.AST, name: str) -> list[ast.AST]:
    """The scopes named ``name`` directly inside ``node``, looking through ``if``, ``try`` and other
    statements the walker also looks through, but not into another scope."""
    found: list[ast.AST] = []
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _SCOPES):
            if child.name == name:
                found.append(child)
        else:
            found.extend(_scopes_named(child, name))
    return found


def _unit_node(tree: ast.AST, qualname: str) -> list[ast.AST]:
    """Every class or function ``qualname`` names under ``tree``. More than one when the same name
    is defined in two branches, which the walker counts as one unit. ``<module>`` is the tree."""
    nodes: list[ast.AST] = [tree]
    if qualname == "<module>":
        return nodes
    for part in qualname.split("."):
        nodes = [found for node in nodes for found in _scopes_named(node, part)]
    return nodes


def _calls_itself(unit: ast.AST, guard: str) -> bool:
    """Whether ``unit``'s own code calls ``guard``: a nested function, class or lambda is its own
    unit, so a call there does not count for this one."""
    for child in ast.iter_child_nodes(unit):
        if isinstance(child, (*_SCOPES, ast.Lambda)):
            continue
        if isinstance(child, ast.Call) and callee_name(child) == guard:
            return True
        if _calls_itself(child, guard):
            return True
    return False


def _guard_missing(key: str, site: Site) -> list[str]:
    file, _, guard = site.guard.partition("::")
    path = _ROOT / file
    if not path.is_file():
        return [f"its guard file {file} does not exist"]
    if path.suffix != ".py":
        if site.called:
            return ["`called` checks a Python guard only"]
        if path.suffix not in (".ts", ".ps1"):
            return [f"no comment stripper for a {path.suffix} guard file"]
        return [] if guard in _code_text(path) else [f"its guard {site.guard} is not in the code"]
    if not find_funcs(parse_source(path.read_text(encoding="utf-8")), guard):
        return [f"its guard {site.guard} is not defined there"]
    if not site.called:
        return []
    unit_file, _, qualname = key.partition("::")
    units = _unit_node(parse_source((_ROOT / unit_file).read_text(encoding="utf-8")), qualname)
    if not units or not all(_calls_itself(unit, guard) for unit in units):
        return [f"no longer calls its guard {guard}"]
    return []


def test_every_python_path_site_is_graded() -> None:
    assert _compare(derived_python_sites(), SITES) == []


def test_every_ide_path_site_is_graded() -> None:
    assert _compare(derived_ide_sites(), IDE_SITES) == []


def test_every_operator_script_path_site_is_graded() -> None:
    assert _compare(derived_script_sites(), SCRIPT_SITES) == []


def test_every_grade_is_known_and_every_guard_still_exists() -> None:
    assert _guard_problems({**SITES, **IDE_SITES, **SCRIPT_SITES}) == []


_PLANTED = """
import os, posixpath, ntpath
from pathlib import Path, PurePosixPath

def joins(directory, name, rel):
    a = directory / name
    b = directory / "fixed" / f"{name}.hl7"
    c = os.path.join(directory, name)
    d = posixpath.join("/in", name)
    e = ntpath.join("C:\\\\x", name)
    f = Path(directory).joinpath(rel)
    g = Path(directory).with_name(name)
    h = Path(directory, name)
    i = PurePosixPath(f"/in/{name}")
    j = open(directory + "/" + name)
    k = Path(f"{directory}.expect")
    m = Path(directory).with_stem(name)
    n = os.sep.join([directory, name])
    o = directory / os.path.join(rel, name)
    p = Path(*rel)
    q = os.path.sep.join([directory, name])
    directory /= name
    return a, b, c, d, e, f, g, h, i, j, k, m, n, o, p, q, directory


def display(parts):
    return "/".join(parts)

class Holder:
    def method(self, root):
        return root / "x.toml"

def arithmetic(total, count, rate):
    return total / count, rate / 2, 1 / rate, (total - count) / total

MODULE = Path(__file__).parent / "static"
"""


def test_the_walker_finds_every_shape_and_skips_arithmetic() -> None:
    # The positive control: each shape the docstring lists is planted once, and so is arithmetic.
    assert path_sites(_PLANTED) == Counter({"joins": 18, "Holder.method": 1, "<module>": 1})


def test_a_missing_row_and_a_stale_row_are_both_named() -> None:
    derived = {"a.py::f": 1, "b.py::g": 2}
    graded = {"b.py::g": Site(1, INTERNAL, "x"), "c.py::h": Site(1, INTERNAL, "x")}
    assert _compare(derived, graded) == [
        "UNGRADED: a.py::f builds 1 path(s); add a SITES row",
        "STALE: c.py::h builds no path now; remove its row",
        "RECOUNT: b.py::g builds 2 path(s), graded for 1; re-read it and re-grade",
    ]


@pytest.mark.parametrize(
    ("site", "expected"),
    [
        (Site(1, "trusted", "x"), "unknown grade"),
        (Site(1, INTERNAL, " "), "no reason"),
        (Site(1, GUARDED, "x"), "names no guard"),
        (Site(1, INTERNAL, "x", "harness/drivers/file.py::drop_name"), "names a guard"),
        (Site(1, GUARDED, "x", "harness/drivers/file.py::no_such_guard"), "is not defined there"),
        (Site(1, INTERNAL, "x", called=True), "names a guard"),
        (Site(1, GUARDED, "x", "ide/src/newRoute.ts::A-Za-z", called=True), "Python guard only"),
        (Site(1, GUARDED, "x", "ide/src/newRoute.ts::no such fragment"), "is not in the code"),
        # unique_path builds a name but never calls _check_contained; drop_atomic does.
        (
            Site(1, GUARDED, "x", "harness/drivers/file.py::_check_contained", called=True),
            "no longer calls its guard",
        ),
    ],
)
def test_a_bad_grade_is_named(site: Site, expected: str) -> None:
    problems = _guard_problems({"harness/drivers/file.py::unique_path": site})
    assert any(expected in p for p in problems), problems


@pytest.mark.parametrize(
    ("key", "site"),
    [
        (
            "harness/drivers/file.py::drop_atomic",
            Site(1, GUARDED, "x", "harness/drivers/file.py::_check_contained", called=True),
        ),
        ("harness/x.py::f", Site(1, GUARDED, "x", "harness/drivers/file.py::_check_contained")),
        ("ide/src/newRoute.ts", Site(1, GUARDED, "x", "ide/src/newRoute.ts::A-Za-z0-9_-")),
    ],
)
def test_a_guard_that_holds_passes(key: str, site: Site) -> None:
    assert _guard_problems({key: site}) == []
