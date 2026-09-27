# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 5.1.1 drift guard: the file-surface inventory in ``docs/CONNECTIONS.md`` must name every
surface the code ships on its derived axes, and every figure it quotes must match the code constant
beside it.

For 5.1.1 the documentation IS the control, so a stale table is the defect. The inventory went wrong
three times while it was hand-kept (BACKLOG #1127): each fix added the one surface the last reviewer
named and left the rest. ``tests/test_asvs_file_surface_doc_drift.py`` pins TOKENS in the prose and
says of itself that it guards text, not code. This module derives the surface list from the code, so a
new surface on a derived axis fails the build until it has a row. Modelled on
``tests/test_communications_inventory.py``.

A row's KEY is the first backticked token in its first cell. Keys are what the axes compare, so a
passing mention of ``file`` or ``database`` elsewhere in a row cannot stand in for a missing row.

Four derived axes, and the hand-kept parts the doc discloses:

1. **Receivers.** Importing ``messagefoundry.transports`` runs every ``register_source(...)``. Each
   registered source type's ``.value`` must key an upload row, or be named in the exclusion bullet
   that lists registered sources. Every row key must be one of: a registered source value, a path in
   ``_UPLOAD_BODY_PATHS`` or :data:`CONTENT_ROUTES`, or a hand-kept key in :data:`HAND_KEPT_UPLOAD_KEYS`
   whose factory parameter still exists. Anything else is a stale row.
2. **Upload routes.** Every path in ``api/app.py``'s ``_UPLOAD_BODY_PATHS`` must key an upload row.
3. **IDE pickers and harness receivers.** Every ``showOpenDialog`` call in ``ide/src/``, plus the
   pinned pick lists in :data:`IDE_PICK_LISTS`, must be named in the IDE picker row. Every code unit
   in ``harness/`` that starts a server and builds an ``MLLPDecoder`` must be named in the harness row,
   and must bound each decoder at the engine's ``DEFAULT_MAX_FRAME_BYTES``. Every code unit there that
   builds a ``QFileSystemWatcher`` reads files another party writes, so it must be named in the same
   row, must cap its reads at ``DEFAULT_MAX_MESSAGE_BYTES``, and must not read a file whole.
4. **Downloads.** An AST walk over ``messagefoundry/`` and ``messagefoundry_webconsole/`` finds every
   code site that writes a ``Content-Disposition`` header (``str`` or ``bytes``) or builds a
   ``FileResponse``, and names its file and enclosing function. That set must equal
   :data:`DOWNLOAD_EMITTERS` exactly, and each emitter's route must key a download row.

**Not derived, and disclosed in the doc:** :data:`CONTENT_ROUTES` (no code marker tells a content body
from a parameter body on a JSON route), the reply-capture row, the ``/ui`` delegates, and the
exclusions. A ``/ui`` delegate that re-serves an emitter by calling it in-process writes no header of
its own, so the AST walk cannot see it.

Figures are imported from the code (``DEFAULT_*`` constants, factory signature defaults, pydantic field
metadata and live route bounds) and matched with number boundaries, so ``= 500`` does not pass for a
code value of ``50``. The checkers are pure functions with planted-omission self-tests, so the guard
cannot quietly stop asserting. PHI-free: it reads names, doc prose and constants only.
"""

from __future__ import annotations

import ast
import inspect
import re
from collections.abc import Iterable
from pathlib import Path

import pytest

import messagefoundry.transports  # noqa: F401 - import runs every register_source(...)
from messagefoundry.api import app as api_app
from messagefoundry.api.models import AiChatRequest, EditResendRequest, MessageExportRequest
from messagefoundry.api.validation import MAX_EXPORT_IDS
from messagefoundry.config import wiring
from messagefoundry.config.settings import StoreSettings
from messagefoundry.parsing import compression
from messagefoundry.parsing.dicom._inflate import DEFAULT_MAX_INFLATED_BYTES
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.parsing.x12.delimiters import DEFAULT_MAX_INTERCHANGE_BYTES
from messagefoundry.pipeline import dr_backup, dryrun
from messagefoundry.transports.base import _SOURCES, DEFAULT_MAX_ITEMS_PER_POLL
from messagefoundry.transports.bounded_read import DEFAULT_MAX_RESPONSE_BYTES
from messagefoundry.transports.database import DEFAULT_DB_LOOKUP_MAX_ROWS
from messagefoundry.transports.dicom import DEFAULT_MAX_OBJECT_BYTES
from messagefoundry.transports.file import DEFAULT_MAX_DECOMPRESSED_BYTES, DEFAULT_MAX_FILE_BYTES
from messagefoundry.transports.http_listener import DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADER_BYTES
from messagefoundry.transports.mllp import DEFAULT_MAX_FRAME_BYTES
from messagefoundry.uploads import _ALLOWED_UPLOAD_EXTENSIONS
from messagefoundry_webconsole._static import ALLOWED_STATIC_EXTENSIONS

_ROOT = Path(__file__).resolve().parent.parent
_DOC = (_ROOT / "docs" / "CONNECTIONS.md").read_text(encoding="utf-8")

_BLOCK_START = "#### File handling & quarantine policy (ASVS 5.1.1)"
_BLOCK_END = "#### Uploaded-logs file policy (ASVS 5.1.1)"
_UPLOAD_CAPTION = "**Upload features.**"
_DOWNLOAD_CAPTION = "**Downloads.**"
_EXCLUDED_CAPTION = "**Excluded, with the reason.**"
_SOURCE_EXCLUSION_MARKER = "are registered sources"

#: ``<repo-relative file>::<function>`` that writes a download header -> the route path(s) its
#: download row must be keyed by. Must equal what the AST walk finds; the test says which side is off.
DOWNLOAD_EMITTERS: dict[str, tuple[str, ...]] = {
    "messagefoundry/api/app.py::download_attachment": (
        "/messages/{message_id}/attachments/{attachment_id}",
    ),
    "messagefoundry/api/app.py::export_messages": ("/messages/export",),
    "messagefoundry/api/auth_routes.py::export_audit": ("/audit/export",),
}

#: JSON routes whose body carries CONTENT (a message body), listed by hand -- no code marker exists.
CONTENT_ROUTES: tuple[str, ...] = ("/messages/{message_id}/edit-resend",)

#: Hand-kept upload-row keys -> the factory whose parameter of that name must still exist.
HAND_KEPT_UPLOAD_KEYS: dict[str, object] = {"capture_response": wiring.MLLP}

#: Every ``wiring`` factory taking ``capture_response`` -> the word the reply-capture row must use for
#: it. Must equal the factories found by signature, so a new capturing outbound fails until named.
CAPTURE_FACTORIES: dict[str, str] = {
    "MLLP": "MLLP",
    "Tcp": "TCP",
    "X12": "X12",
    "Rest": "REST",
    "Soap": "SOAP",
    "FHIR": "FHIR",
    "DICOMweb": "DICOMweb",
    "Database": "database",
}

#: Where the IDE extension's local file pickers live (the doc's IDE row says why they count).
_IDE_SRC = _ROOT / "ide" / "src"
_PICKER_CALL = re.compile(r"\.showOpenDialog\s*\(")
_TS_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def _ts_code(path: Path) -> str:
    return _TS_COMMENT.sub("", path.read_text(encoding="utf-8"))


def ide_pickers(src: Path, root: Path) -> set[str]:
    """Repo-relative paths of the shipped ``.ts`` files that call ``showOpenDialog(``. Comments and
    the extension's own tests (``src/test/``) are skipped: neither is a surface a user reaches."""
    return {
        f.relative_to(root).as_posix()
        for f in sorted(src.rglob("*.ts"))
        if "test" not in f.relative_to(src).parts[:-1] and _PICKER_CALL.search(_ts_code(f))
    }


#: IDE sample choices that are a pick list rather than a ``showOpenDialog``: file -> the calls that make
#: the choice. A pick list over a directory listing cannot be told from a menu by a call name alone
#: (``statusBar.ts`` also lists a directory and shows a pick list), so these are pinned, and each must
#: still make every call named here.
IDE_PICK_LISTS: dict[str, tuple[str, ...]] = {
    "ide/src/liveDebug.ts": ("readdirSync(", ".hl7", "showQuickPick("),
}

#: The Steps view's own capped read of its picked sample (the IDE row says why it exists).
_IDE_SAMPLE_CAP = _IDE_SRC / "sampleFile.ts"
_TS_SIZE = re.compile(r"export const MAX_SAMPLE_FILE_BYTES = ([\d\s*]+);")


def ts_sample_cap(path: Path) -> int:
    """``MAX_SAMPLE_FILE_BYTES`` in ``sampleFile.ts``: a product of integer literals, evaluated here."""
    m = _TS_SIZE.search(_ts_code(path))
    assert m, f"MAX_SAMPLE_FILE_BYTES is not a product of integer literals in {path.name}"
    value = 1
    for factor in m.group(1).split("*"):
        value *= int(factor)
    return value


#: Where the test harness lives; its MLLP receivers are an upload row by Manager decision.
_HARNESS = _ROOT / "harness"
_SERVER_CALLS = frozenset({"QTcpServer", "start_server"})


def harness_receivers(src: Path, root: Path) -> dict[str, list[ast.Call]]:
    """``<file>::<unit>`` -> its ``MLLPDecoder(...)`` calls, for every top-level class or function in
    ``src`` that both starts a server and builds an ``MLLPDecoder``. A client that only reads ACKs
    starts no server, so it is not a receiver."""
    found: dict[str, list[ast.Call]] = {}
    for path in sorted(src.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "MLLPDecoder" not in text:
            continue  # most harness files never parse: no decoder, no receiver
        for node in ast.parse(text).body:
            if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = [c for c in ast.walk(node) if isinstance(c, ast.Call)]
            decoders = [c for c in calls if _call_name(c) == "MLLPDecoder"]
            if decoders and any(_call_name(c) in _SERVER_CALLS for c in calls):
                found[f"{path.relative_to(root).as_posix()}::{node.name}"] = decoders
    return found


def unbounded_decoders(
    receivers: dict[str, list[ast.Call]], root: Path, cap_name: str = "DEFAULT_MAX_FRAME_BYTES"
) -> list[str]:
    """Receivers with an ``MLLPDecoder`` built without ``max_frame_bytes=`` (or with it ``None``),
    or whose file does not import ``cap_name`` from ``messagefoundry.mllpcodec`` and use it in
    that unit. A cap read from a setting that defaults to ``cap_name`` passes: the check is on the
    default, and a site may raise it as the engine's own setting may. The module is the client-
    importable leaf, not ``transports.mllp``: a harness file may not import ``transports`` (BACKLOG
    #1697, enforced in ``tests/test_dependency_boundaries.py``)."""
    bad: list[str] = []
    for key, decoders in receivers.items():
        file, unit = key.split("::")
        if not _imports_and_uses(root / file, unit, "messagefoundry.mllpcodec", cap_name):
            bad.append(f"{key} (does not bound at {cap_name})")
        for call in decoders:
            cap = next((k.value for k in call.keywords if k.arg == "max_frame_bytes"), None)
            if cap is None or (isinstance(cap, ast.Constant) and cap.value is None):
                bad.append(f"{key}:{call.lineno} (MLLPDecoder without max_frame_bytes)")
    return bad


def _imports_and_uses(path: Path, unit: str, module: str, cap_name: str) -> bool:
    """``path`` imports ``cap_name`` from ``module`` at top level, and top-level ``unit`` uses it."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = any(
        isinstance(n, ast.ImportFrom)
        and n.module == module
        and any(a.name == cap_name for a in n.names)
        for n in tree.body
    )
    node = next(n for n in tree.body if getattr(n, "name", None) == unit)
    return imported and any(isinstance(n, ast.Name) and n.id == cap_name for n in ast.walk(node))


_WATCHER_CALLS = frozenset({"QFileSystemWatcher"})
_WHOLE_FILE_READS = frozenset({"read_text", "read_bytes"})


def harness_file_watchers(src: Path, root: Path) -> list[str]:
    """``<file>::<unit>`` for every top-level class or function in ``src`` that builds a
    ``QFileSystemWatcher``: it reads files another party writes into a directory it watches."""
    found: list[str] = []
    for path in sorted(src.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "QFileSystemWatcher" not in text:
            continue
        for node in ast.parse(text).body:
            if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(
                isinstance(c, ast.Call) and _call_name(c) in _WATCHER_CALLS for c in ast.walk(node)
            ):
                found.append(f"{path.relative_to(root).as_posix()}::{node.name}")
    return found


def uncapped_watchers(
    watchers: Iterable[str], root: Path, cap_name: str = "DEFAULT_MAX_MESSAGE_BYTES"
) -> list[str]:
    """Watchers that do not cap at ``cap_name`` (imported from ``messagefoundry.parsing.peek`` and
    used in the unit), or that read a file whole: ``read_text``, ``read_bytes``, or a ``read()`` with
    no size."""
    bad: list[str] = []
    for key in watchers:
        file, unit = key.split("::")
        path = root / file
        if not _imports_and_uses(path, unit, "messagefoundry.parsing.peek", cap_name):
            bad.append(f"{key} (does not cap at {cap_name})")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        node = next(n for n in tree.body if getattr(n, "name", None) == unit)
        for call in (c for c in ast.walk(node) if isinstance(c, ast.Call)):
            name = _call_name(call)
            if name in _WHOLE_FILE_READS or (name == "read" and not call.args):
                bad.append(f"{key}:{call.lineno} (reads a file whole: {name})")
    return bad


#: The registered sources the doc excludes as reading nothing from outside. Pinned here so a NEW
#: source cannot pass by a doc-only edit that adds it to the exclusion bullet.
INERT_SOURCES: frozenset[str] = frozenset({"loopback", "passthrough", "timer"})


# --- pure helpers ---------------------------------------------------------------------------------


def _block(doc: str) -> str:
    start = doc.index(_BLOCK_START)
    end = doc.index(_BLOCK_END, start)
    return doc[start:end]


def _table_after(text: str, caption: str) -> list[str]:
    """The markdown table rows (header and separator dropped) of the first table after ``caption``."""
    lines = text[text.index(caption) :].splitlines()[1:]
    rows: list[str] = []
    for line in lines:
        if line.startswith("|"):
            rows.append(line)
        elif rows:
            break
    return rows[2:]


def _keyed_rows(rows: Iterable[str]) -> dict[str, str]:
    """A row's key (the first backticked token of its first cell) -> that whole row."""
    keyed: dict[str, str] = {}
    for row in rows:
        tokens = re.findall(r"`([^`]+)`", row.split("|")[1])
        if tokens:
            assert tokens[0] not in keyed, f"two 5.1.1 rows share the key `{tokens[0]}`"
            keyed[tokens[0]] = row
    return keyed


def _source_exclusions(text: str) -> set[str]:
    """Tokens before ``are registered sources`` in the exclusion bullet that lists sources."""
    excluded = text[text.index(_EXCLUDED_CAPTION) :]
    bullet = next(b for b in excluded.split("\n- ") if _SOURCE_EXCLUSION_MARKER in b)
    return set(re.findall(r"`([^`]+)`", bullet[: bullet.index(_SOURCE_EXCLUSION_MARKER)]))


def missing_sources(sources: set[str], keys: set[str], excluded: set[str]) -> set[str]:
    return sources - keys - excluded


def stale_keys(keys: set[str], allowed: set[str]) -> set[str]:
    return keys - allowed


def has_figure(text: str, needle: str) -> bool:
    """``needle`` occurs with no digit or thousands comma running on at either end."""
    return re.search(r"(?<![\d,])" + re.escape(needle) + r"(?![\d]|,\d)", text) is not None


def _size(n: int) -> str:
    for unit, factor in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n % factor == 0:
            return f"{n // factor} {unit}"
    return f"{n:,}"


def _call_name(call: ast.Call) -> str | None:
    func = call.func
    return func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)


def _is_emitter(node: ast.AST, file_responses: set[str]) -> bool:
    """A header write (a ``str``/``bytes`` constant naming the header, or an f-string header line) or
    a call to ``FileResponse`` under any imported name. A bare ``"content-disposition:"`` constant is a
    PARSER's prefix test (``api/multipart.py``), not a write, so constants must match exactly."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        value = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
        return value.lower() == "content-disposition"
    if isinstance(node, ast.JoinedStr) and node.values:
        head = node.values[0]
        return (
            isinstance(head, ast.Constant)
            and isinstance(head.value, str)
            and head.value.lower().startswith("content-disposition:")
        )
    if isinstance(node, ast.Call):
        return _call_name(node) in file_responses
    return False


def _walk(
    node: ast.AST, stack: list[str], where: str, file_responses: set[str], out: set[str]
) -> None:
    is_fn = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):  # narrows; `is_fn` cannot
        stack.append(node.name)
    if _is_emitter(node, file_responses):
        out.add(f"{where}::{stack[-1] if stack else '<module>'}")
    for child in ast.iter_child_nodes(node):
        _walk(child, stack, where, file_responses, out)
    if is_fn:
        stack.pop()


def emitters(paths: Iterable[Path], root: Path) -> set[str]:
    """``<file>::<function>`` for every Content-Disposition write or FileResponse call."""
    out: set[str] = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        file_responses = {"FileResponse"} | {
            alias.asname
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
            if alias.name == "FileResponse" and alias.asname
        }
        _walk(tree, [], path.relative_to(root).as_posix(), file_responses, out)
    return out


def callers(paths: Iterable[Path], names: set[str]) -> set[str]:
    """``names`` plus every function whose body calls one of them directly (one level)."""
    found = set(names)
    for path in paths:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for call in ast.walk(node):
                if isinstance(call, ast.Call) and _call_name(call) in names:
                    found.add(node.name)
    return found


# --- fixtures -------------------------------------------------------------------------------------

_BLOCK = _block(_DOC)
_UPLOAD_ROWS = _keyed_rows(_table_after(_BLOCK, _UPLOAD_CAPTION))
_DOWNLOAD_ROWS = _keyed_rows(_table_after(_BLOCK, _DOWNLOAD_CAPTION))
_EXCLUDED_SOURCES = _source_exclusions(_BLOCK)
_SOURCE_VALUES = {kind.value for kind in _SOURCES}


@pytest.fixture(scope="module")
def app_routes() -> dict[tuple[str, str], object]:
    from fastapi.routing import APIRoute

    app = api_app.create_app()
    return {
        (method, route.path): route
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods or ()
    }


# --- axis 1: receivers, and stale keys ------------------------------------------------------------


def test_every_registered_source_keys_a_row_or_is_excluded() -> None:
    missing = missing_sources(_SOURCE_VALUES, set(_UPLOAD_ROWS), _EXCLUDED_SOURCES)
    assert not missing, f"register_source types with no 5.1.1 row or exclusion: {sorted(missing)}"


def test_a_source_is_either_a_row_or_an_exclusion_not_both() -> None:
    both = set(_UPLOAD_ROWS) & _EXCLUDED_SOURCES
    assert not both, f"listed as an upload feature AND excluded: {sorted(both)}"


def test_only_the_pinned_inert_sources_are_excluded() -> None:
    assert _EXCLUDED_SOURCES == INERT_SOURCES, (
        "the registered-source exclusion changed; a new exclusion needs a reviewed edit to "
        f"INERT_SOURCES, not only to the doc: {sorted(_EXCLUDED_SOURCES ^ INERT_SOURCES)}"
    )


def test_no_upload_row_or_source_exclusion_names_a_surface_the_code_lacks() -> None:
    allowed = (
        _SOURCE_VALUES
        | set(api_app._UPLOAD_BODY_PATHS)
        | set(CONTENT_ROUTES)
        | set(HAND_KEPT_UPLOAD_KEYS)
        | ide_pickers(_IDE_SRC, _ROOT)
        | set(IDE_PICK_LISTS)
        | {key.split("::")[0] for key in harness_receivers(_HARNESS, _ROOT)}
        | {key.split("::")[0] for key in harness_file_watchers(_HARNESS, _ROOT)}
    )
    stale = stale_keys(set(_UPLOAD_ROWS), allowed) | stale_keys(_EXCLUDED_SOURCES, _SOURCE_VALUES)
    assert not stale, f"5.1.1 rows or exclusions naming nothing the code registers: {sorted(stale)}"


def test_hand_kept_keys_still_exist_in_the_factories() -> None:
    for key, factory in HAND_KEPT_UPLOAD_KEYS.items():
        assert key in inspect.signature(factory).parameters, f"{key} is gone from its factory"  # type: ignore[arg-type]
        assert key in _UPLOAD_ROWS, f"{key} has no 5.1.1 upload row"
    assert "reingress_to" in inspect.signature(wiring.MLLP).parameters


def test_every_capturing_outbound_is_named_in_the_reply_row() -> None:
    capturing = {
        name
        for name, fn in inspect.getmembers(wiring, inspect.isfunction)
        if fn.__module__ == wiring.__name__
        and "capture_response" in inspect.signature(fn).parameters
    }
    assert capturing == set(CAPTURE_FACTORIES), (
        f"capture_response factories changed: {sorted(capturing ^ set(CAPTURE_FACTORIES))}"
    )
    size_cell = _UPLOAD_ROWS["capture_response"].split("|")[4]
    for word in CAPTURE_FACTORIES.values():
        assert re.search(rf"\b{re.escape(word)}\b", size_cell), f"reply row does not name {word}"


def test_every_ide_file_picker_is_named_in_the_picker_row() -> None:
    dialogs = ide_pickers(_IDE_SRC, _ROOT)
    assert dialogs, "instrument found no showOpenDialog call in ide/src at all"
    for file, calls in IDE_PICK_LISTS.items():
        code = _ts_code(_ROOT / file)
        missing = [c for c in calls if c not in code]
        assert not missing, f"pinned pick list {file} no longer makes {missing}"
    pickers = dialogs | set(IDE_PICK_LISTS)
    first_cells = {
        token
        for row in _UPLOAD_ROWS.values()
        for token in re.findall(r"`([^`]+)`", row.split("|")[1])
        if token.startswith("ide/")
    }
    assert first_cells == pickers, (
        f"IDE picker row differs from the code: {sorted(first_cells ^ pickers)}"
    )
    row = next((r for key, r in _UPLOAD_ROWS.items() if key in pickers), None)
    assert row is not None, "no upload row is KEYED by an IDE picker path"
    assert has_figure(row, f"MAX_FIXTURE_FILE_BYTES` = {_size(dryrun.MAX_FIXTURE_FILE_BYTES)}")
    assert has_figure(row, f"MAX_SAMPLE_FILE_BYTES` = {_size(ts_sample_cap(_IDE_SAMPLE_CAP))}")


def test_the_steps_view_reads_its_sample_only_through_the_cap() -> None:
    """The Steps view read its picked sample whole before ``dryrun`` saw it (BACKLOG #1127). Its cap
    must equal ``dryrun``'s default, and ``stepsView.ts`` must check at pick time and read capped."""
    assert ts_sample_cap(_IDE_SAMPLE_CAP) == dryrun.MAX_FIXTURE_FILE_BYTES
    code = _ts_code(_IDE_SRC / "stepsView.ts")
    assert "checkSampleSize(" in code and "readSampleCapped(" in code
    assert "readFileSync(" not in code, "stepsView.ts reads a file outside the sample cap"


# --- the harness's MLLP receivers -----------------------------------------------------------------


def test_every_harness_receiver_is_named_in_the_harness_row_and_bounded() -> None:
    receivers = harness_receivers(_HARNESS, _ROOT)
    assert receivers, "instrument found no server-side MLLPDecoder in harness/ at all"
    files = {key.split("::")[0] for key in receivers}
    named = {
        token
        for row in _UPLOAD_ROWS.values()
        for token in re.findall(r"`([^`]+)`", row.split("|")[1])
        if token.startswith("harness/")
    }
    watcher_files = {key.split("::")[0] for key in harness_file_watchers(_HARNESS, _ROOT)}
    assert named == files | watcher_files, (
        f"harness row differs from the code: {sorted(named ^ (files | watcher_files))}"
    )
    bad = unbounded_decoders(receivers, _ROOT)
    assert not bad, bad
    row = next((r for key, r in _UPLOAD_ROWS.items() if key in files), None)
    assert row is not None, "no upload row is KEYED by a harness receiver path"
    assert has_figure(row, f"DEFAULT_MAX_FRAME_BYTES` = {_size(DEFAULT_MAX_FRAME_BYTES)}")


def test_every_harness_file_watcher_is_named_in_the_harness_row_and_capped() -> None:
    """The File tab's watch pane read each new file whole with no cap (BACKLOG #1127 follow-up). A
    unit that watches a directory another party writes to must cap its reads like the engine."""
    watchers = harness_file_watchers(_HARNESS, _ROOT)
    assert watchers, "instrument found no QFileSystemWatcher in harness/ at all"
    bad = uncapped_watchers(watchers, _ROOT)
    assert not bad, bad
    row = next((r for key, r in _UPLOAD_ROWS.items() if key.startswith("harness/")), None)
    assert row is not None, "no upload row is KEYED by a harness path"
    first_cell = row.split("|")[1]
    for key in watchers:
        assert f"`{key.split('::')[0]}`" in first_cell, f"{key} is not named in the harness row"
    assert has_figure(row, f"DEFAULT_MAX_MESSAGE_BYTES` = {_size(DEFAULT_MAX_MESSAGE_BYTES)}")


# --- axis 2: upload routes ------------------------------------------------------------------------


def test_every_upload_body_path_keys_an_upload_row() -> None:
    # The console delegate shares its row with /uploads, so a path may sit in a row's first cell
    # without being its key; the key test below covers the API path.
    first_cells = " ".join(row.split("|")[1] for row in _UPLOAD_ROWS.values())
    missing = sorted(p for p in api_app._UPLOAD_BODY_PATHS if f"`{p}`" not in first_cells)
    assert not missing, f"_UPLOAD_BODY_PATHS with no 5.1.1 upload row: {missing}"
    assert "/uploads" in _UPLOAD_ROWS


def test_hand_listed_content_routes_exist_and_key_a_row(
    app_routes: dict[tuple[str, str], object],
) -> None:
    paths = {path for _, path in app_routes}
    for route in CONTENT_ROUTES:
        assert route in paths, f"{route} is listed as a content route but create_app() lacks it"
        assert route in _UPLOAD_ROWS, f"{route} has no 5.1.1 upload row"


# --- axis 3: downloads ----------------------------------------------------------------------------


def _code_paths() -> list[Path]:
    return [
        p
        for pkg in ("messagefoundry", "messagefoundry_webconsole")
        for p in sorted((_ROOT / pkg).rglob("*.py"))
    ]


def test_download_emitters_match_the_code_exactly() -> None:
    found = emitters(_code_paths(), _ROOT)
    # multipart.py PARSES an inbound part's Content-Disposition line and writes none; its literal
    # carries a trailing colon, so the exact-equality walk never matches it.
    unmapped = found - set(DOWNLOAD_EMITTERS)
    gone = set(DOWNLOAD_EMITTERS) - found
    assert not unmapped, (
        f"new Content-Disposition/FileResponse emitter(s) {sorted(unmapped)}: "
        "add a 5.1.1 download row and map it in DOWNLOAD_EMITTERS"
    )
    assert not gone, f"DOWNLOAD_EMITTERS names sites that no longer emit: {sorted(gone)}"


def test_every_download_emitter_route_keys_a_download_row(
    app_routes: dict[tuple[str, str], object],
) -> None:
    paths = {path for _, path in app_routes}
    for site, routes in DOWNLOAD_EMITTERS.items():
        for route in routes:
            assert route in paths, f"{site}: route {route} is not in create_app()"
            assert route in _DOWNLOAD_ROWS, f"{site}: route {route} has no 5.1.1 download row"


def test_download_routes_are_derived_from_the_emitters(
    app_routes: dict[tuple[str, str], object],
) -> None:
    """Every JSON route whose endpoint IS an emitter, or calls one, must be a mapped download route,
    so a third route onto ``export_messages`` fails until it has a row."""
    reach = callers(_code_paths(), {site.split("::")[1] for site in DOWNLOAD_EMITTERS})
    derived = {
        path
        for (_, path), route in app_routes.items()
        if getattr(getattr(route, "endpoint", None), "__name__", None) in reach
    }
    mapped = {r for routes in DOWNLOAD_EMITTERS.values() for r in routes}
    assert derived == mapped, f"download routes differ from the code: {sorted(derived ^ mapped)}"


def test_download_rows_name_only_emitting_routes() -> None:
    mapped = {r for routes in DOWNLOAD_EMITTERS.values() for r in routes}
    extra = set(_DOWNLOAD_ROWS) - mapped
    assert not extra, f"download rows for routes no emitter serves: {sorted(extra)}"


# --- figures, imported from the code --------------------------------------------------------------


def _row(key: str, rows: dict[str, str]) -> str:
    assert key in rows, f"no 5.1.1 row keyed by `{key}`"
    return rows[key]


def _lines_with(symbol: str, text: str = _BLOCK) -> str:
    lines = [line for line in text.splitlines() if symbol in line]
    assert lines, f"`{symbol}` is not named in the 5.1.1 block"
    return "\n".join(lines)


def _sig_default(fn: object, name: str) -> object:
    return inspect.signature(fn).parameters[name].default  # type: ignore[arg-type]


def _max_len(field: object) -> int:
    return next(m.max_length for m in field.metadata if hasattr(m, "max_length"))  # type: ignore[attr-defined]


def _assert_figures(key: str, needles: Iterable[str], rows: dict[str, str]) -> None:
    row = _row(key, rows)
    for needle in needles:
        assert has_figure(row, needle), f"`{key}` row lost or changed `{needle}`"


def test_receiver_figures_match_their_constants() -> None:
    # The factory signatures quote the same numbers as literals; pin that they still agree.
    assert _sig_default(wiring.File, "max_file_bytes") == DEFAULT_MAX_FILE_BYTES
    assert _sig_default(wiring.File, "max_decompressed_bytes") == DEFAULT_MAX_DECOMPRESSED_BYTES
    assert _sig_default(wiring.Http, "max_body_bytes") == DEFAULT_MAX_BODY_BYTES
    assert _sig_default(wiring.Http, "max_header_bytes") == DEFAULT_MAX_HEADER_BYTES
    assert _sig_default(wiring.DICOM, "max_object_bytes") == DEFAULT_MAX_OBJECT_BYTES
    assert _sig_default(wiring.MLLP, "max_frame_bytes") == DEFAULT_MAX_FRAME_BYTES
    assert _sig_default(wiring.Tcp, "max_frame_bytes") == DEFAULT_MAX_FRAME_BYTES
    assert _sig_default(wiring.X12, "max_interchange_bytes") == DEFAULT_MAX_INTERCHANGE_BYTES
    assert _sig_default(wiring.DatabasePoll, "poll_max_rows") == DEFAULT_MAX_ITEMS_PER_POLL
    assert _sig_default(wiring.Sftp, "pattern") == _sig_default(wiring.Ftp, "pattern")
    for factory in (wiring.Sftp, wiring.Ftp):
        assert _sig_default(factory, "max_file_bytes") == DEFAULT_MAX_FILE_BYTES
        assert "decompress" not in inspect.signature(factory).parameters

    pins = {
        "file": [
            f"DEFAULT_MAX_FILE_BYTES` = {_size(DEFAULT_MAX_FILE_BYTES)}",
            f"DEFAULT_MAX_DECOMPRESSED_BYTES` = {_size(DEFAULT_MAX_DECOMPRESSED_BYTES)}",
            f"`{_sig_default(wiring.File, 'pattern')}`",
        ],
        "remotefile": [
            f"DEFAULT_MAX_FILE_BYTES` = {_size(DEFAULT_MAX_FILE_BYTES)}",
            f"`{_sig_default(wiring.Sftp, 'pattern')}`",
        ],
        "dimse": [
            f"DEFAULT_MAX_OBJECT_BYTES` = {_size(DEFAULT_MAX_OBJECT_BYTES)}",
            f"DEFAULT_MAX_INFLATED_BYTES` = {_size(DEFAULT_MAX_INFLATED_BYTES)}",
        ],
        "http": [
            f"DEFAULT_MAX_BODY_BYTES` = {_size(DEFAULT_MAX_BODY_BYTES)}",
            f"DEFAULT_MAX_HEADER_BYTES` = {_size(DEFAULT_MAX_HEADER_BYTES)}",
        ],
        "mllp": [f"DEFAULT_MAX_FRAME_BYTES` = {_size(DEFAULT_MAX_FRAME_BYTES)}"],
        "tcp": [f"DEFAULT_MAX_FRAME_BYTES` = {_size(DEFAULT_MAX_FRAME_BYTES)}"],
        "x12": [f"DEFAULT_MAX_INTERCHANGE_BYTES` = {_size(DEFAULT_MAX_INTERCHANGE_BYTES)}"],
        "database": [f"DEFAULT_MAX_ITEMS_PER_POLL` = {DEFAULT_MAX_ITEMS_PER_POLL}"],
    }
    for key, needles in pins.items():
        _assert_figures(key, needles, _UPLOAD_ROWS)


def test_route_and_reply_figures_match_their_constants() -> None:
    uploads = _row("/uploads", _UPLOAD_ROWS)
    ext_cell = uploads.split("|")[3]
    assert set(re.findall(r"`(\.[a-z0-9]+)`", ext_cell)) == set(_ALLOWED_UPLOAD_EXTENSIONS)
    _assert_figures(
        "/uploads",
        [f"default {_size(StoreSettings.model_fields['max_upload_bytes'].default)}"],
        _UPLOAD_ROWS,
    )
    _assert_figures(
        CONTENT_ROUTES[0],
        [
            f"_MAX_REQUEST_BODY_BYTES` = {_size(api_app._MAX_REQUEST_BODY_BYTES)}",
            f"{_max_len(EditResendRequest.model_fields['raw']):,} characters",
        ],
        _UPLOAD_ROWS,
    )
    _assert_figures(
        "capture_response",
        [
            f"DEFAULT_MAX_RESPONSE_BYTES` = {_size(DEFAULT_MAX_RESPONSE_BYTES)}",
            f"default {_sig_default(wiring.Database, 'capture_max_rows')}",
        ],
        _UPLOAD_ROWS,
    )


def _bound(route: object, name: str) -> tuple[int, int]:
    param = next(q for q in route.dependant.query_params if q.name == name)  # type: ignore[attr-defined]
    le = next(m.le for m in param.field_info.metadata if hasattr(m, "le"))
    return param.field_info.default, le


def test_download_figures_match_the_routes(app_routes: dict[tuple[str, str], object]) -> None:
    default, ceiling = _bound(app_routes[("GET", "/messages/export")], "limit")
    body = MessageExportRequest.model_fields["limit"]
    body_le = next(m.le for m in body.metadata if hasattr(m, "le"))
    assert (default, ceiling) == (body.default, body_le), "GET and POST export bounds diverged"
    _assert_figures(
        "/messages/export",
        [f"default {default}, ceiling {ceiling:,}", f"MAX_EXPORT_IDS` = {MAX_EXPORT_IDS:,}"],
        _DOWNLOAD_ROWS,
    )
    default, ceiling = _bound(app_routes[("GET", "/audit/export")], "limit")
    _assert_figures("/audit/export", [f"default {default:,}, ceiling {ceiling:,}"], _DOWNLOAD_ROWS)
    assert "_csv_safe" in _row("/audit/export", _DOWNLOAD_ROWS)


#: Every ``SYMBOL`` the block quotes as ``SYMBOL` = figure``, and its code value. The test below
#: finds EVERY such occurrence in the block; one quoting a symbol missing here fails, so a new quoted
#: figure must be pinned before it can ship.
QUOTED_CONSTANTS: dict[str, int] = {
    "DEFAULT_MAX_FILE_BYTES": DEFAULT_MAX_FILE_BYTES,
    "DEFAULT_MAX_DECOMPRESSED_BYTES": DEFAULT_MAX_DECOMPRESSED_BYTES,
    "DEFAULT_MAX_OBJECT_BYTES": DEFAULT_MAX_OBJECT_BYTES,
    "DEFAULT_MAX_INFLATED_BYTES": DEFAULT_MAX_INFLATED_BYTES,
    "DEFAULT_MAX_BODY_BYTES": DEFAULT_MAX_BODY_BYTES,
    "DEFAULT_MAX_HEADER_BYTES": DEFAULT_MAX_HEADER_BYTES,
    "DEFAULT_MAX_FRAME_BYTES": DEFAULT_MAX_FRAME_BYTES,
    "DEFAULT_MAX_INTERCHANGE_BYTES": DEFAULT_MAX_INTERCHANGE_BYTES,
    "DEFAULT_MAX_ITEMS_PER_POLL": DEFAULT_MAX_ITEMS_PER_POLL,
    "DEFAULT_MAX_MESSAGE_BYTES": DEFAULT_MAX_MESSAGE_BYTES,
    "DEFAULT_MAX_RESPONSE_BYTES": DEFAULT_MAX_RESPONSE_BYTES,
    "DEFAULT_DB_LOOKUP_MAX_ROWS": DEFAULT_DB_LOOKUP_MAX_ROWS,
    "_MAX_REQUEST_BODY_BYTES": api_app._MAX_REQUEST_BODY_BYTES,
    "MAX_EXPORT_IDS": MAX_EXPORT_IDS,
    "_MAX_RESTORE_MEMBER_BYTES": dr_backup._MAX_RESTORE_MEMBER_BYTES,
    "_MAX_CONFIG_MEMBERS": dr_backup._MAX_CONFIG_MEMBERS,
    "_MAX_CONFIG_BYTES": dr_backup._MAX_CONFIG_BYTES,
    "MAX_FIXTURE_FILE_BYTES": dryrun.MAX_FIXTURE_FILE_BYTES,
    "MAX_SAMPLE_FILE_BYTES": ts_sample_cap(_IDE_SAMPLE_CAP),
}

_QUOTED = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)` = (\d+(?:,\d{3})*(?: [KMG]iB)?)")


def misquoted(text: str, constants: dict[str, int]) -> list[str]:
    """Every ``SYMBOL` = figure`` in ``text`` whose symbol is unpinned or whose figure is wrong."""
    bad: list[str] = []
    for symbol, figure in _QUOTED.findall(text):
        if symbol not in constants:
            bad.append(f"{symbol} (not pinned)")
        elif figure not in (_size(constants[symbol]), f"{constants[symbol]:,}"):
            bad.append(f"{symbol} = {figure}")
    return bad


def test_every_quoted_constant_matches_the_code_everywhere_in_the_block() -> None:
    assert _QUOTED.findall(_BLOCK), "instrument found no quoted constants at all"
    assert not misquoted(_BLOCK, QUOTED_CONSTANTS), misquoted(_BLOCK, QUOTED_CONSTANTS)


def test_common_limits_and_exclusion_figures_match_their_constants() -> None:
    assert has_figure(
        _lines_with("DEFAULT_MAX_MESSAGE_BYTES`"),
        f"DEFAULT_MAX_MESSAGE_BYTES` = {_size(DEFAULT_MAX_MESSAGE_BYTES)}",
    )
    # The decompressors' ceiling is a required keyword with NO default; the doc says so.
    for fn in (
        compression.gzip_decompress,
        compression.deflate_decompress,
        compression.deflate_decompress_with_tail,
        compression.zip_decompress,
    ):
        param = inspect.signature(fn).parameters["max_output_bytes"]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY
        assert param.default is inspect.Parameter.empty, f"{fn.__name__} grew a default"
        assert fn.__name__ in _BLOCK
    entries = _sig_default(compression.zip_decompress, "max_entries")
    assert has_figure(_BLOCK, f"`max_entries`, default {entries}")

    static = _lines_with("ALLOWED_STATIC_EXTENSIONS")
    assert set(re.findall(r"`(\.[a-z0-9]+)`", static)) == set(ALLOWED_STATIC_EXTENSIONS)

    excluded = _BLOCK[_BLOCK.index(_EXCLUDED_CAPTION) :]
    for needle in (
        f"_MAX_RESTORE_MEMBER_BYTES` = {_size(dr_backup._MAX_RESTORE_MEMBER_BYTES)}",
        f"_MAX_CONFIG_MEMBERS` = {dr_backup._MAX_CONFIG_MEMBERS:,}",
        f"_MAX_CONFIG_BYTES` = {_size(dr_backup._MAX_CONFIG_BYTES)}",
        f"{_max_len(AiChatRequest.model_fields['prompt']):,} characters",
    ):
        assert has_figure(excluded, needle), f"exclusions lost or changed `{needle}`"


def test_retired_hedge_stays_gone() -> None:
    """The hand-kept "at least four parts ... not a closed set" sentence could not be falsified, which
    is why it could not carry a per-feature inventory (BACKLOG #1127)."""
    assert "at least four" not in _BLOCK
    assert "not as a closed set" not in _BLOCK


def test_the_1_3_4_clause_stays_scoped_to_the_attachment_route() -> None:
    clause_start = _DOC.index("**Downloads are made safe at serve (ASVS 1.3.4).**")
    clause = _DOC[clause_start : _DOC.index("\n### ", clause_start)]
    assert "/messages/export" not in clause
    assert "/audit/export" not in clause


def test_in_block_anchors_resolve() -> None:
    def slug(heading: str) -> str:
        return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")

    def anchors(text: str) -> set[str]:
        # Skip fenced code: a `# comment` line there is not a heading and renders no anchor.
        prose = re.sub(r"^```.*?^```", "", text, flags=re.M | re.S)
        return {slug(m) for m in re.findall(r"^#{1,6} (.+)$", prose, flags=re.M)}

    docs = {"": _DOC}
    for target, anchor in re.findall(r"\]\(([A-Z]+\.md)?#([^)]+)\)", _BLOCK):
        if target not in docs:
            docs[target] = (_ROOT / "docs" / target).read_text(encoding="utf-8")
        assert anchor in anchors(docs[target]), f"dead anchor {target}#{anchor} in the 5.1.1 block"


# --- the checkers can fail (planted omissions) ----------------------------------------------------


def test_self_test_a_planted_missing_receiver_is_caught() -> None:
    keys = set(_UPLOAD_ROWS) - {"x12"}
    assert missing_sources(_SOURCE_VALUES, keys, _EXCLUDED_SOURCES) == {"x12"}


def test_self_test_a_passing_mention_does_not_count_as_a_row() -> None:
    doc = _BLOCK.replace("| `x12`: X12 EDI listener", "| `X12(...)` EDI listener, see `x12`")
    keys = set(_keyed_rows(_table_after(doc, _UPLOAD_CAPTION)))
    assert missing_sources(_SOURCE_VALUES, keys, _source_exclusions(doc)) == {"x12"}


def test_self_test_a_row_for_a_deleted_connector_type_is_stale() -> None:
    # The usual removal deletes the enum member too, so staleness must not depend on ConnectorType.
    assert stale_keys(set(_UPLOAD_ROWS), _SOURCE_VALUES - {"tcp"} | set(CONTENT_ROUTES)) >= {"tcp"}


def test_self_test_a_planted_emitter_is_found(tmp_path: Path) -> None:
    planted = tmp_path / "planted.py"
    planted.write_text(
        "def leak():\n    return {'Content-Disposition': 'attachment'}\n"
        "def raw():\n    return [(b'content-disposition', b'attachment')]\n"
        "def other():\n    return FileResponse('x', filename='y')\n"
        "from starlette.responses import FileResponse as FR\n"
        "def aliased():\n    return FR('x')\n"
        "def fstr(n):\n    return f'Content-Disposition: attachment; filename={n}'\n"
        "def parse(line):\n    return line.startswith('content-disposition:')\n",
        encoding="utf-8",
    )
    assert emitters([planted], tmp_path) == {
        "planted.py::leak",
        "planted.py::raw",
        "planted.py::other",
        "planted.py::aliased",
        "planted.py::fstr",
    }


def test_self_test_a_misquoted_figure_is_caught() -> None:
    text = (
        "`DEFAULT_MAX_RESPONSE_BYTES` = 32 MiB and `NEW_CAP` = 1 MiB and `MAX_EXPORT_IDS` = 100,000"
    )
    assert misquoted(text, QUOTED_CONSTANTS) == [
        "DEFAULT_MAX_RESPONSE_BYTES = 32 MiB",
        "NEW_CAP (not pinned)",
    ]


def test_self_test_download_routes_follow_callers(tmp_path: Path) -> None:
    planted = tmp_path / "routes.py"
    planted.write_text(
        "def emit():\n    return {'Content-Disposition': 'attachment'}\n"
        "def route_a():\n    return emit()\n"
        "def unrelated():\n    return 1\n",
        encoding="utf-8",
    )
    assert callers([planted], {"emit"}) == {"emit", "route_a"}


def test_self_test_a_new_ide_picker_is_found(tmp_path: Path) -> None:
    src = tmp_path / "ide" / "src"
    src.mkdir(parents=True)
    (src / "a.ts").write_text("await vscode.window.showOpenDialog({});", encoding="utf-8")
    (src / "b.ts").write_text("// showOpenDialog is mentioned, not called", encoding="utf-8")
    (src / "c.ts").write_text("/* vscode.window.showOpenDialog({}) */", encoding="utf-8")
    (src / "test").mkdir()
    (src / "test" / "d.ts").write_text("await vscode.window.showOpenDialog({});", encoding="utf-8")
    assert ide_pickers(src, tmp_path) == {"ide/src/a.ts"}


def test_self_test_duplicate_row_keys_fail_closed() -> None:
    with pytest.raises(AssertionError, match="share the key"):
        _keyed_rows(["| `file`: a | x |", "| `file`: b | y |"])


def test_self_test_figure_match_respects_number_boundaries() -> None:
    row = "| `database` | ... `DEFAULT_MAX_ITEMS_PER_POLL` = 500, bounds rows | 16,000,000 characters |"
    assert has_figure(row, "DEFAULT_MAX_ITEMS_PER_POLL` = 500")
    assert not has_figure(row, "DEFAULT_MAX_ITEMS_PER_POLL` = 50")
    assert not has_figure(row, "6,000,000 characters")
    assert not has_figure("ceiling 1,000,000", "ceiling 1,000")
    assert not has_figure("MAX_EXPORT_IDS` = 100,000", "MAX_EXPORT_IDS` = 100")


def test_self_test_a_harness_receiver_is_found_and_an_unbounded_one_flagged(tmp_path: Path) -> None:
    src = tmp_path / "harness"
    src.mkdir()
    (src / "rx.py").write_text(
        "from messagefoundry.mllpcodec import DEFAULT_MAX_FRAME_BYTES, MLLPDecoder\n"
        "class Bounded:\n"
        "    async def start(self):\n        await asyncio.start_server(self.on, 'h', 0)\n"
        "    def on(self):\n        return MLLPDecoder(max_frame_bytes=DEFAULT_MAX_FRAME_BYTES)\n"
        "class Unbounded:\n"
        "    def __init__(self):\n        self.s = QTcpServer(self)\n"
        "    def on(self):\n        return MLLPDecoder()\n"
        "class ExplicitNone:\n"
        "    def run(self):\n        start_server(DEFAULT_MAX_FRAME_BYTES)\n"
        "        return MLLPDecoder(max_frame_bytes=None)\n"
        "class ClientOnly:\n"
        "    def read_ack(self):\n        return MLLPDecoder()\n",
        encoding="utf-8",
    )
    receivers = harness_receivers(src, tmp_path)
    assert set(receivers) == {
        "harness/rx.py::Bounded",
        "harness/rx.py::Unbounded",
        "harness/rx.py::ExplicitNone",
    }
    assert unbounded_decoders(receivers, tmp_path) == [
        "harness/rx.py::Unbounded (does not bound at DEFAULT_MAX_FRAME_BYTES)",
        "harness/rx.py::Unbounded:11 (MLLPDecoder without max_frame_bytes)",
        "harness/rx.py::ExplicitNone:15 (MLLPDecoder without max_frame_bytes)",
    ]


def test_self_test_the_ts_sample_cap_is_evaluated(tmp_path: Path) -> None:
    ts = tmp_path / "sampleFile.ts"
    ts.write_text(
        "// export const MAX_SAMPLE_FILE_BYTES = 1;\nexport const MAX_SAMPLE_FILE_BYTES = 4 * 1024;\n",
        encoding="utf-8",
    )
    assert ts_sample_cap(ts) == 4096


def test_self_test_a_harness_file_watcher_is_found_and_an_uncapped_one_flagged(
    tmp_path: Path,
) -> None:
    src = tmp_path / "harness"
    src.mkdir()
    (src / "fw.py").write_text(
        "from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES\n"
        "class Capped:\n"
        "    def __init__(self):\n        self.w = QFileSystemWatcher(self)\n"
        "    def scan(self, p):\n"
        "        with p.open('rb') as fh:\n            return fh.read(DEFAULT_MAX_MESSAGE_BYTES + 1)\n"
        "class Whole:\n"
        "    def __init__(self):\n        self.w = QFileSystemWatcher(self)\n"
        "    def scan(self, p):\n        return p.read_text()\n"
        "class BareRead:\n"
        "    def __init__(self):\n        self.w = QFileSystemWatcher(self)\n"
        "    def scan(self, p):\n"
        "        DEFAULT_MAX_MESSAGE_BYTES\n        with p.open('rb') as fh:\n"
        "            return fh.read()\n"
        "class NotAWatcher:\n"
        "    def scan(self, p):\n        return p.read_text()\n",
        encoding="utf-8",
    )
    watchers = harness_file_watchers(src, tmp_path)
    assert watchers == ["harness/fw.py::Capped", "harness/fw.py::Whole", "harness/fw.py::BareRead"]
    assert uncapped_watchers(watchers, tmp_path) == [
        "harness/fw.py::Whole (does not cap at DEFAULT_MAX_MESSAGE_BYTES)",
        "harness/fw.py::Whole:12 (reads a file whole: read_text)",
        "harness/fw.py::BareRead:19 (reads a file whole: read)",
    ]
