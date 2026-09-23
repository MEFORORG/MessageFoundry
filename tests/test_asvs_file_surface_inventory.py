# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 5.1.1 drift guard: the file-surface inventory in ``docs/CONNECTIONS.md`` must name every
surface the code ships, and every figure it quotes must match the code constant beside it.

For 5.1.1 the documentation IS the control, so a stale table is the defect. The inventory went wrong
three times while it was hand-kept (BACKLOG #1127): each fix added the one surface the last reviewer
named and left the rest. ``tests/test_asvs_file_surface_doc_drift.py`` pins TOKENS in the prose and
says of itself that it guards text, not code. This module derives the surface list from the code, so a
new surface fails the build until it has a row. Modelled on ``tests/test_communications_inventory.py``.

Three derived axes, and one disclosed manual list:

1. **Receivers.** Importing ``messagefoundry.transports`` runs every ``register_source(...)``. Each
   registered source type's ``.value`` must appear in backticks in the FIRST cell of an upload-table
   row, or in the exclusions list. A table or exclusion that names a type the registry no longer holds
   fails too. First-cell matching matters: ``file`` and ``http`` are ordinary words that other cells use.
2. **Upload routes.** Every path in ``api/app.py``'s ``_UPLOAD_BODY_PATHS`` must head an upload row.
3. **Downloads.** An AST walk over ``messagefoundry/`` and ``messagefoundry_webconsole/`` finds every
   code site that writes a ``Content-Disposition`` header or builds a ``FileResponse``, and names the
   function it sits in. That set must equal :data:`DOWNLOAD_EMITTERS` exactly, and each emitter's route
   must head a download row. A new emitter fails until someone maps it and writes its row.
4. **Manual, disclosed.** No code marker tells a content body from a parameter body on a JSON route,
   so :data:`CONTENT_ROUTES` lists those routes by hand. Each must still exist in ``create_app()``.

Figures are imported from the code (``DEFAULT_*`` constants, factory signature defaults, pydantic field
metadata and live route bounds) and asserted on the same line as their symbol, so changing a constant
reds the doc. The checkers are pure functions with planted-omission self-tests, so the guard cannot
quietly stop asserting. PHI-free: it reads names, doc prose and constants only.
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
from messagefoundry.api.models import EditResendRequest, MessageExportRequest
from messagefoundry.api.validation import MAX_EXPORT_IDS
from messagefoundry.config import wiring
from messagefoundry.config.settings import StoreSettings
from messagefoundry.parsing import compression
from messagefoundry.parsing.dicom._inflate import DEFAULT_MAX_INFLATED_BYTES
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.parsing.x12.delimiters import DEFAULT_MAX_INTERCHANGE_BYTES
from messagefoundry.pipeline import dr_backup
from messagefoundry.transports.base import _SOURCES, DEFAULT_MAX_ITEMS_PER_POLL
from messagefoundry.transports.bounded_read import DEFAULT_MAX_RESPONSE_BYTES
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

#: Function that writes a download header -> the route path(s) its download row must name. Keep this
#: equal to what the AST walk finds; the test says which side is missing.
DOWNLOAD_EMITTERS: dict[str, tuple[str, ...]] = {
    "download_attachment": ("/messages/{message_id}/attachments/{attachment_id}",),
    "export_messages": ("/messages/export",),
    "export_audit": ("/audit/export",),
}

#: JSON routes whose body carries CONTENT (a message body), listed by hand -- see mechanism 4.
CONTENT_ROUTES: tuple[str, ...] = ("/messages/{message_id}/edit-resend",)


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


def _first_cell_tokens(rows: Iterable[str]) -> dict[str, str]:
    """Backticked token in a row's first cell -> that whole row."""
    found: dict[str, str] = {}
    for row in rows:
        first = row.split("|")[1]
        for token in re.findall(r"`([^`]+)`", first):
            found[token] = row
    return found


def _exclusion_tokens(text: str) -> set[str]:
    start = text.index(_EXCLUDED_CAPTION)
    rest = text[start:]
    stop = rest.find("\n\n", rest.index("\n- "))
    return set(re.findall(r"`([^`]+)`", rest[: stop if stop != -1 else len(rest)]))


def missing_sources(sources: set[str], table: set[str], excluded: set[str]) -> set[str]:
    return sources - table - excluded


def stale_sources(sources: set[str], known_types: set[str], named: set[str]) -> set[str]:
    """Names that ARE connector-type values but are no longer registered sources."""
    return (named & known_types) - sources


def _size(n: int) -> str:
    for unit, factor in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n % factor == 0:
            return f"{n // factor} {unit}"
    return f"{n:,}"


def _is_emitter(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower() == "content-disposition"
    if isinstance(node, ast.Call):
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        return name == "FileResponse"
    return False


def _walk(node: ast.AST, stack: list[str], where: str, out: dict[str, set[str]]) -> None:
    is_fn = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    if is_fn:
        stack.append(node.name)
    if _is_emitter(node):
        out.setdefault(stack[-1] if stack else "<module>", set()).add(where)
    for child in ast.iter_child_nodes(node):
        _walk(child, stack, where, out)
    if is_fn:
        stack.pop()


def _emitters(paths: Iterable[Path]) -> dict[str, set[str]]:
    """Enclosing function name -> files, for every Content-Disposition write or FileResponse call."""
    out: dict[str, set[str]] = {}
    for path in paths:
        _walk(ast.parse(path.read_text(encoding="utf-8")), [], path.as_posix(), out)
    return out


# --- fixtures -------------------------------------------------------------------------------------

_BLOCK = _block(_DOC)
_UPLOAD_ROWS = _first_cell_tokens(_table_after(_BLOCK, _UPLOAD_CAPTION))
_DOWNLOAD_ROWS = _first_cell_tokens(_table_after(_BLOCK, _DOWNLOAD_CAPTION))
_EXCLUDED = _exclusion_tokens(_BLOCK)
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


# --- axis 1: receivers ----------------------------------------------------------------------------


def test_every_registered_source_has_a_row_or_an_exclusion() -> None:
    missing = missing_sources(_SOURCE_VALUES, set(_UPLOAD_ROWS), _EXCLUDED)
    assert not missing, f"register_source types with no 5.1.1 row or exclusion: {sorted(missing)}"


def test_no_row_names_a_source_type_the_registry_no_longer_holds() -> None:
    from messagefoundry.config.models import ConnectorType

    known = {kind.value for kind in ConnectorType}
    stale = stale_sources(_SOURCE_VALUES, known, set(_UPLOAD_ROWS) | _EXCLUDED)
    assert not stale, f"5.1.1 names connector types that register no source: {sorted(stale)}"


def test_a_source_is_either_a_row_or_an_exclusion_not_both() -> None:
    both = _SOURCE_VALUES & set(_UPLOAD_ROWS) & _EXCLUDED
    assert not both, f"listed as an upload feature AND excluded: {sorted(both)}"


# --- axis 2 and 4: upload routes ------------------------------------------------------------------


def test_every_upload_body_path_heads_an_upload_row() -> None:
    missing = sorted(p for p in api_app._UPLOAD_BODY_PATHS if p not in _UPLOAD_ROWS)
    assert not missing, f"_UPLOAD_BODY_PATHS with no 5.1.1 upload row: {missing}"


def test_hand_listed_content_routes_exist_and_head_a_row(
    app_routes: dict[tuple[str, str], object],
) -> None:
    paths = {path for _, path in app_routes}
    for route in CONTENT_ROUTES:
        assert route in paths, (
            f"{route} is listed as a content route but create_app() has no such route"
        )
        assert route in _UPLOAD_ROWS, f"{route} has no 5.1.1 upload row"


# --- axis 3: downloads ----------------------------------------------------------------------------


def _code_paths() -> list[Path]:
    return [
        p
        for pkg in ("messagefoundry", "messagefoundry_webconsole")
        for p in sorted((_ROOT / pkg).rglob("*.py"))
    ]


def test_download_emitters_match_the_code_exactly() -> None:
    found = _emitters(_code_paths())
    # multipart.py PARSES an inbound part's Content-Disposition line, it does not write one; its
    # literal carries a trailing colon, so the exact-equality walk above never matches it.
    unmapped = set(found) - set(DOWNLOAD_EMITTERS)
    gone = set(DOWNLOAD_EMITTERS) - set(found)
    assert not unmapped, (
        f"new Content-Disposition/FileResponse emitter(s) {sorted(unmapped)} in "
        f"{sorted(f for k in unmapped for f in found[k])}: add a 5.1.1 download row and map it here"
    )
    assert not gone, f"DOWNLOAD_EMITTERS names functions that no longer emit: {sorted(gone)}"


def test_every_download_emitter_route_heads_a_download_row(
    app_routes: dict[tuple[str, str], object],
) -> None:
    paths = {path for _, path in app_routes}
    for fn, routes in DOWNLOAD_EMITTERS.items():
        for route in routes:
            assert route in paths, f"{fn}: route {route} is not in create_app()"
            assert route in _DOWNLOAD_ROWS, f"{fn}: route {route} has no 5.1.1 download row"


def test_download_rows_name_only_emitting_routes() -> None:
    mapped = {r for routes in DOWNLOAD_EMITTERS.values() for r in routes}
    # `/ui` alone marks a same-handler console delegate, not a route of its own.
    extra = {t for t in _DOWNLOAD_ROWS if t.startswith("/") and t != "/ui" and t not in mapped}
    assert not extra, f"download rows for routes no emitter serves: {sorted(extra)}"


# --- figures, imported from the code --------------------------------------------------------------


def _row(token: str, rows: dict[str, str]) -> str:
    assert token in rows, f"no 5.1.1 row headed by `{token}`"
    return rows[token]


def _line_with(symbol: str) -> str:
    lines = [line for line in _BLOCK.splitlines() if symbol in line]
    assert lines, f"`{symbol}` is not named in the 5.1.1 block"
    return "\n".join(lines)


def _sig_default(fn: object, name: str) -> object:
    return inspect.signature(fn).parameters[name].default  # type: ignore[arg-type]


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
    assert _sig_default(wiring.Sftp, "pattern") == _sig_default(wiring.Ftp, "pattern")
    for token, needles in pins.items():
        row = _row(token, _UPLOAD_ROWS)
        for needle in needles:
            assert needle in row, f"`{token}` row lost or changed `{needle}`"


def test_route_and_reply_figures_match_their_constants() -> None:
    uploads = _row("/uploads", _UPLOAD_ROWS)
    for ext in _ALLOWED_UPLOAD_EXTENSIONS:
        assert f"`{ext}`" in uploads
    assert f"default {_size(StoreSettings.model_fields['max_upload_bytes'].default)}" in uploads

    edit = _row(CONTENT_ROUTES[0], _UPLOAD_ROWS)
    assert f"_MAX_REQUEST_BODY_BYTES` = {_size(api_app._MAX_REQUEST_BODY_BYTES)}" in edit
    raw_max = next(
        m.max_length
        for m in EditResendRequest.model_fields["raw"].metadata
        if hasattr(m, "max_length")
    )
    assert f"{raw_max:,} characters" in edit

    reply = _row("capture_response", _UPLOAD_ROWS)
    assert f"DEFAULT_MAX_RESPONSE_BYTES` = {_size(DEFAULT_MAX_RESPONSE_BYTES)}" in reply
    assert f"default {_sig_default(wiring.Database, 'capture_max_rows')}" in reply


def _bound(route: object, name: str) -> tuple[object, object]:
    param = next(q for q in route.dependant.query_params if q.name == name)  # type: ignore[attr-defined]
    le = next(m.le for m in param.field_info.metadata if hasattr(m, "le"))
    return param.field_info.default, le


def test_download_figures_match_the_routes(app_routes: dict[tuple[str, str], object]) -> None:
    export = _row("/messages/export", _DOWNLOAD_ROWS)
    default, ceiling = _bound(app_routes[("GET", "/messages/export")], "limit")
    body = MessageExportRequest.model_fields["limit"]
    body_le = next(m.le for m in body.metadata if hasattr(m, "le"))
    assert (default, ceiling) == (body.default, body_le), "GET and POST export bounds diverged"
    assert f"default {default}, ceiling {ceiling:,}" in export
    assert f"MAX_EXPORT_IDS` = {MAX_EXPORT_IDS:,}" in export

    audit = _row("/audit/export", _DOWNLOAD_ROWS)
    default, ceiling = _bound(app_routes[("GET", "/audit/export")], "limit")
    assert f"default {default:,}, ceiling {ceiling:,}" in audit
    assert "_csv_safe" in audit


def test_common_limits_and_exclusion_figures_match_their_constants() -> None:
    assert f"DEFAULT_MAX_MESSAGE_BYTES` = {_size(DEFAULT_MAX_MESSAGE_BYTES)}" in _line_with(
        "DEFAULT_MAX_MESSAGE_BYTES`"
    )
    # The decompressors' ceiling is a required keyword with NO default; the doc says so.
    for fn in (
        compression.gzip_decompress,
        compression.deflate_decompress,
        compression.zip_decompress,
    ):
        param = inspect.signature(fn).parameters["max_output_bytes"]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY
        assert param.default is inspect.Parameter.empty, f"{fn.__name__} grew a default"
        assert fn.__name__ in _BLOCK
    assert (
        f"`max_entries`, default {_sig_default(compression.zip_decompress, 'max_entries')}"
        in _BLOCK
    )

    static = _line_with("ALLOWED_STATIC_EXTENSIONS")
    for ext in ALLOWED_STATIC_EXTENSIONS:
        assert f"`{ext}`" in static
    excluded = _BLOCK[_BLOCK.index(_EXCLUDED_CAPTION) :]
    assert f"_MAX_RESTORE_MEMBER_BYTES` = {_size(dr_backup._MAX_RESTORE_MEMBER_BYTES)}" in excluded
    assert f"_MAX_CONFIG_MEMBERS` = {dr_backup._MAX_CONFIG_MEMBERS:,}" in excluded
    assert f"_MAX_CONFIG_BYTES` = {_size(dr_backup._MAX_CONFIG_BYTES)}" in excluded


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
        s = heading.strip().lower()
        s = re.sub(r"[^\w\- ]", "", s)
        return s.replace(" ", "-")

    def anchors(text: str) -> set[str]:
        return {slug(m) for m in re.findall(r"^#{1,6} (.+)$", text, flags=re.M)}

    docs = {"": _DOC}
    for target, anchor in re.findall(r"\]\(([A-Z]+\.md)?#([^)]+)\)", _BLOCK):
        if target not in docs:
            docs[target] = (_ROOT / "docs" / target).read_text(encoding="utf-8")
        assert anchor in anchors(docs[target]), f"dead anchor {target}#{anchor} in the 5.1.1 block"


# --- the checkers can fail (planted omissions) ----------------------------------------------------


def test_self_test_a_planted_missing_receiver_is_caught() -> None:
    table = set(_UPLOAD_ROWS) - {"x12"}
    assert missing_sources(_SOURCE_VALUES, table, _EXCLUDED) == {"x12"}


def test_self_test_a_planted_stale_row_is_caught() -> None:
    sources = _SOURCE_VALUES - {"tcp"}
    assert stale_sources(sources, _SOURCE_VALUES, set(_UPLOAD_ROWS)) == {"tcp"}


def test_self_test_a_planted_emitter_is_found(tmp_path: Path) -> None:
    planted = tmp_path / "planted.py"
    planted.write_text(
        "def leak():\n    return {'Content-Disposition': 'attachment'}\n"
        "def other():\n    return FileResponse('x', filename='y')\n"
        "def parse(line):\n    return line.startswith('content-disposition:')\n",
        encoding="utf-8",
    )
    assert set(_emitters([planted])) == {"leak", "other"}


def test_self_test_a_planted_table_drops_a_row() -> None:
    doc = _BLOCK.replace("| `x12`:", "| x12:")
    rows = _first_cell_tokens(_table_after(doc, _UPLOAD_CAPTION))
    assert missing_sources(_SOURCE_VALUES, set(rows), _exclusion_tokens(doc)) == {"x12"}
