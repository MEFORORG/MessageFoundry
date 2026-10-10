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
   row, must cap its reads at ``DEFAULT_MAX_MESSAGE_BYTES``, and must not read a file whole. Every
   module in ``harness/sinks/`` the harness discovers as a sink (public, not a package) must be named in
   the harness sink row, must bound at an engine cap constant (itself, or through a sink module or a
   ``_``-prefixed harness helper it imports), and must not read a file whole. The reconcile loader
   (:data:`HARNESS_FILE_LOADERS`) is hand-kept: it must read only through the capped reader, at a
   default pinned to its constant.
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

import harness.drivers.dimse as dimse_driver
import harness.drivers.http as http_driver
import harness.fuzz.transport as fuzz_transport
import harness.load.coord as harness_coord
import harness.load.failover as rig_failover
import harness.load.rigadmin as rig_admin
import harness.load.shardcert_ladder as harness_ladder
import harness.sinks.email as email_sink
import messagefoundry.transports  # noqa: F401 - import runs every register_source(...)
from harness.drivers import _database as harness_database
from harness.reconcile import compare
from harness.sinks import dimse as dimse_sink
from harness.sinks.file import FileSink
from messagefoundry.api import app as api_app
from messagefoundry.api.models import AiChatRequest, EditResendRequest, MessageExportRequest
from messagefoundry.api.validation import MAX_EXPORT_IDS
from messagefoundry.apiclient.client import MAX_RESPONSE_BYTES as APICLIENT_MAX_RESPONSE_BYTES
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


#: The harness's scenario sinks; each is an upload row since the owner ruling of 2026-10-02 (R1 of
#: the vault's ``docs/security/ASVS-OWNER-RULINGS-2026-10-02-1130.md``) put ``harness/`` inside the
#: ASVS assessed scope.
_SINKS = _HARNESS / "sinks"
#: The engine cap constants a sink may bound at. Each is imported from a ``messagefoundry`` leaf.
_SINK_CAPS = frozenset(
    {"DEFAULT_MAX_MESSAGE_BYTES", "DEFAULT_MAX_FRAME_BYTES", "DEFAULT_MAX_INTERCHANGE_BYTES"}
)

#: Hand-kept harness units that read files another system produced, though an operator names them ->
#: the function that reads them. No code marker tells such a loader from an operator's own input.
HARNESS_FILE_LOADERS: dict[str, str] = {"harness/reconcile/compare.py": "load_messages"}


#: What builds a frame reader in the harness: the MLLP decoder, the X12 reader, and a framing codec's
#: ``decoder`` (the TCP driver's ``self.codec.decoder(...)``). Each must be built with a cap keyword.
_FRAME_READER_CALLS = frozenset({"MLLPDecoder", "X12FrameReader", "decoder"})
_FRAME_CAP_KEYWORDS = frozenset({"max_frame_bytes", "max_interchange_bytes"})

#: ``<file>::<unit>`` whose frame reader decodes the operator's own bytes, not another party's reply,
#: so it takes no cap -> why. Keyed by unit, not file, so a new reader elsewhere in the same file is
#: still checked. Pinned so a new uncapped reader cannot pass by a doc edit alone.
HARNESS_OWN_BYTES_READERS: dict[str, str] = {
    "harness/fuzz/mutate.py::frames": (
        "decodes a fuzz case's wire bytes, generated by the fuzzer or read from a replay file the "
        "operator names; never the engine's reply"
    ),
}

#: Harness clients that read the engine's answers with no frame reader -> the constant capping the
#: read. No frame reader means the derivation below cannot see them, so they are named by hand.
HARNESS_HAND_KEPT_CLIENTS: dict[str, str] = {"harness/drivers/http.py": "MAX_REPLY_BYTES"}

#: Harness units that read a file the engine under test or another host wrote -> the unit. Kept by
#: hand: nothing in the code tells such a file from the operator's own.
HARNESS_FOREIGN_FILE_READS: dict[str, str] = {
    "harness/load/shardcert_ladder.py": "read_node_log",
    "harness/load/failover.py": "EngineNode",
    "harness/load/coord.py": "FileDropCoord",
}

#: The load rig's reads of the engine API and the DIMSE driver's reads of the engine's SCP -> the
#: name each file must load to read under its cap (BACKLOG #1127). Kept by hand: they read with no
#: frame reader, so the client walk cannot see them. ``shardcert`` reads through the failover
#: helper. The connscale, estate and ingress-probe runners poll through ``EngineNode``, so the
#: ``failover`` entry covers them.
HARNESS_RIG_API_READS: dict[str, str] = {
    "harness/load/rigadmin.py": "MAX_API_REPLY_BYTES",
    "harness/load/failover.py": "MAX_STATUS_REPLY_BYTES",
    "harness/load/shardcert.py": "_get_status_json",
    "harness/drivers/dimse.py": "MAX_ASSOCIATION_READ_BYTES",
}

_HTTP_CLIENT_MODULES = frozenset({"httpx", "urllib.request"})


def harness_http_clients(src: Path, root: Path) -> list[str]:
    """Repo-relative path of every file in ``src`` that imports ``httpx`` or ``urllib.request``,
    at any depth: each may read an engine API answer, so each is scanned for unbounded reads."""
    found: list[str] = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            if any(n in _HTTP_CLIENT_MODULES for n in names):
                found.append(path.relative_to(root).as_posix())
                break
    return found


#: ``httpx`` request methods that read the whole answer unless streamed.
_UNSTREAMED_HTTP_CALLS = frozenset({"get", "post", "put", "patch", "delete", "head", "request"})


def unbounded_api_reads(tree: ast.AST) -> list[str]:
    """Every call in ``tree`` that reads an HTTP answer with no bound: a request method called on a
    name or attribute ending in ``client`` (``client.get(...)`` or ``self._client.get(...)``
    buffers the answer whole), a response's ``.json()``, and each :func:`whole_read`. A tripwire
    on the shapes the rig used, not proof."""
    bad: list[str] = []
    calls = sorted(
        (c for c in ast.walk(tree) if isinstance(c, ast.Call)),
        key=lambda c: (c.lineno, c.col_offset),
    )
    for call in calls:
        func = call.func
        name = _call_name(call)
        receiver = func.value if isinstance(func, ast.Attribute) else None
        receiver_name = (
            receiver.id
            if isinstance(receiver, ast.Name)
            else receiver.attr
            if isinstance(receiver, ast.Attribute)
            else ""
        )
        on_client = receiver_name.lower().endswith("client")
        if (on_client and name in _UNSTREAMED_HTTP_CALLS) or (
            name == "json" and isinstance(func, ast.Attribute) and not call.args
        ):
            bad.append(f"{call.lineno} (reads an answer whole: {name})")
        elif whole := whole_read(call):
            bad.append(f"{call.lineno} (reads an answer whole: {whole})")
    return bad


#: The fewest calls the whole-read walk must see in each file of :data:`HARNESS_FOREIGN_FILE_READS`
#: before its "reads nothing whole" verdict means anything.
_MIN_FOREIGN_READ_FILE_CALLS = 10


def harness_frame_readers(src: Path, root: Path) -> dict[str, tuple[bool, list[ast.Call]]]:
    """``<file>::<unit>`` -> (starts a server, its frame-reader calls), for every top-level class or
    function in ``src`` that builds a frame reader (:data:`_FRAME_READER_CALLS`)."""
    found: dict[str, tuple[bool, list[ast.Call]]] = {}
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = [c for c in ast.walk(node) if isinstance(c, ast.Call)]
            readers = [c for c in calls if _call_name(c) in _FRAME_READER_CALLS]
            if readers:
                server = any(_call_name(c) in _SERVER_CALLS for c in calls)
                found[f"{path.relative_to(root).as_posix()}::{node.name}"] = (server, readers)
    return found


def harness_clients(
    readers: dict[str, tuple[bool, list[ast.Call]]], sinks_prefix: str = "harness/sinks/"
) -> list[str]:
    """The units of ``readers`` that read a peer's replies as a client: they start no server, are not
    a sink (the sink row covers those), and do not decode the harness's own bytes."""
    return sorted(
        key
        for key, (server, _calls) in readers.items()
        if not server and not key.startswith(sinks_prefix) and key not in HARNESS_OWN_BYTES_READERS
    )


def uncapped_frame_readers(readers: dict[str, tuple[bool, list[ast.Call]]]) -> list[str]:
    """Every frame-reader call built without a cap keyword, or with it ``None``, outside the files
    :data:`HARNESS_OWN_BYTES_READERS` names."""
    bad: list[str] = []
    for key, (_server, calls) in readers.items():
        if key in HARNESS_OWN_BYTES_READERS:
            continue
        for call in calls:
            cap = next((k.value for k in call.keywords if k.arg in _FRAME_CAP_KEYWORDS), None)
            if cap is None or (isinstance(cap, ast.Constant) and cap.value is None):
                bad.append(f"{key}:{call.lineno} ({_call_name(call)} without a cap)")
    return bad


def harness_sinks(src: Path, root: Path) -> list[str]:
    """Repo-relative path of every module in ``src`` the harness discovers as a sink: exactly what
    ``harness._discover.family_modules`` imports, a public (no leading ``_``) non-package module.
    Whether it sets ``KIND`` is not asked: discovery loads it either way."""
    return [
        path.relative_to(root).as_posix()
        for path in sorted(src.glob("*.py"))
        if not path.name.startswith("_")
    ]


def _cap_hops(path: Path, root: Path, sinks_dir: Path) -> list[Path]:
    """The files of the harness modules ``path`` imports from at top level that may carry its cap:
    a sink module (``remotefile`` reuses ``file``'s scan) or a ``_``-prefixed helper (``_http``,
    ``_sftp_server``, ``drivers._database``). An import resolves only to ``<module>.py`` or
    ``<module>/<name>.py``, never to a package ``__init__``: every sink imports ``harness.sinks``, so a
    cap there would pass every sink at once. The ``viainit`` self-test pins that."""
    hops: list[Path] = []
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if not (isinstance(node, ast.ImportFrom) and node.module):
            continue
        parts = node.module.split(".")
        if parts[0] != "harness":
            continue
        base = root.joinpath(*parts)
        for cand in [base.with_suffix(".py"), *(base / f"{a.name}.py" for a in node.names)]:
            if cand.is_file() and (cand.name.startswith("_") or cand.parent == sinks_dir):
                hops.append(cand)
    return hops


def _caps_used(path: Path) -> set[str]:
    """The :data:`_SINK_CAPS` that ``path`` imports from ``messagefoundry`` at top level and names."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {
        a.asname or a.name
        for n in tree.body
        if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("messagefoundry.")
        for a in n.names
        if a.name in _SINK_CAPS
    }
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id in imported}


def unbounded_sinks(sinks: Iterable[str], root: Path, sinks_dir: Path) -> list[str]:
    """Sinks that bound at none of :data:`_SINK_CAPS`, themselves or through one hop, or that read a
    file whole. A tripwire, not proof that the cap is enforced: naming the constant is what it checks.
    Each refusal is exercised by the sink's own behaviour tests (``tests/test_harness_*.py``). Flags
    each :func:`whole_read` in their own module. A bare ``read()`` is not a file: the stream sinks
    name their ``recv_chunks`` reader so."""
    bad: list[str] = []
    for rel in sinks:
        path = root / rel
        if not any(_caps_used(f) for f in [path, *_cap_hops(path, root, sinks_dir)]):
            bad.append(f"{rel} (bounds at none of {sorted(_SINK_CAPS)})")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for call in (c for c in ast.walk(tree) if isinstance(c, ast.Call)):
            if name := whole_read(call):
                bad.append(f"{rel}:{call.lineno} (reads a file whole: {name})")
    return bad


_WATCHER_CALLS = frozenset({"QFileSystemWatcher"})
#: Calls that read to the end whatever their arguments. ``readlines`` takes only a hint, and one
#: line can still be any length, so it is flagged with or without one.
_WHOLE_FILE_READS = frozenset({"read_text", "read_bytes", "readlines"})


#: What the standard library's readers call their size argument: ``io`` uses ``size``,
#: ``http.client`` uses ``amt``, and some file-likes take ``n``.
_SIZE_KEYWORDS = frozenset({"size", "amt", "n"})


def _unbounded_size(node: ast.expr | None) -> bool:
    """``read``'s size argument means "to the end": absent, ``None``, or a negative literal, which
    ``ast.parse`` writes as a minus sign on a constant."""
    if node is None or (isinstance(node, ast.Constant) and node.value is None):
        return True
    return (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, int)
    )


def whole_read(call: ast.Call, *, bare_read: bool = False) -> str | None:
    """The method name when ``call`` reads a file or stream whole, else None: a call in
    :data:`_WHOLE_FILE_READS`, or ``read()``, ``read(-1)``, ``read(None)`` or ``read(size=-1)``.

    A ``read`` counts only as a method call unless ``bare_read`` is set: the stream sinks name
    their own reader function ``read``, and it is no file. A size held in a variable is taken as a
    bound; this is a tripwire on the shapes that are unbounded on their face (BACKLOG #1127)."""
    name = _call_name(call)
    if name in _WHOLE_FILE_READS:
        return name
    if name != "read" or not (bare_read or isinstance(call.func, ast.Attribute)):
        return None
    if call.args:
        size: ast.expr | None = call.args[0]
    elif call.keywords:
        size = next((k.value for k in call.keywords if k.arg in _SIZE_KEYWORDS), None)
        if size is None:
            return None  # keywords, none of them a size: not a file read's shape
    else:
        size = None
    return name if _unbounded_size(size) else None


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
    used in the unit), or that read a file whole: any :func:`whole_read`, a bare ``read()`` included."""
    bad: list[str] = []
    for key in watchers:
        file, unit = key.split("::")
        path = root / file
        if not _imports_and_uses(path, unit, "messagefoundry.parsing.peek", cap_name):
            bad.append(f"{key} (does not cap at {cap_name})")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        node = next(n for n in tree.body if getattr(n, "name", None) == unit)
        for call in (c for c in ast.walk(node) if isinstance(c, ast.Call)):
            if name := whole_read(call, bare_read=True):
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
        | set(harness_sinks(_SINKS, _ROOT))
        | set(HARNESS_FILE_LOADERS)
        | {key.split("::")[0] for key in harness_clients(harness_frame_readers(_HARNESS, _ROOT))}
        | set(HARNESS_FOREIGN_FILE_READS)
        | set(HARNESS_RIG_API_READS)
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
    client_files = {
        key.split("::")[0] for key in harness_clients(harness_frame_readers(_HARNESS, _ROOT))
    }
    surfaces = (
        files
        | watcher_files
        | set(harness_sinks(_SINKS, _ROOT))
        | set(HARNESS_FILE_LOADERS)
        | client_files
        | set(HARNESS_HAND_KEPT_CLIENTS)
        | set(HARNESS_FOREIGN_FILE_READS)
        | set(HARNESS_RIG_API_READS)
    )
    assert named == surfaces, f"harness rows differ from the code: {sorted(named ^ surfaces)}"
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


def test_every_harness_sink_is_named_in_the_sink_row_and_bounded() -> None:
    """``harness/sinks/`` was not seen by the two tests above: its sinks start their own loopback
    servers and build no ``MLLPDecoder`` and no ``QFileSystemWatcher``. A new sink module fails here
    until the sink row names it, and until it bounds at an engine cap constant."""
    sinks = harness_sinks(_SINKS, _ROOT)
    assert len(sinks) >= 12, f"instrument found too few sinks in harness/sinks/: {sinks}"
    bad = unbounded_sinks(sinks, _ROOT, _SINKS)
    assert not bad, bad
    row = next((r for key, r in _UPLOAD_ROWS.items() if key in sinks), None)
    assert row is not None, "no upload row is KEYED by a harness sink path"
    first_cell = row.split("|")[1]
    for rel in sinks:
        assert f"`{rel}`" in first_cell, f"{rel} is not named in the harness sink row"
    assert dimse_sink.DimseSink().max_object_bytes == DEFAULT_MAX_MESSAGE_BYTES
    assert FileSink(_ROOT).max_file_bytes == DEFAULT_MAX_MESSAGE_BYTES
    assert harness_database.MAX_OUTBOX_PAYLOAD_CHARS == DEFAULT_MAX_MESSAGE_BYTES
    assert email_sink.MAX_DATA_BYTES == 2 * DEFAULT_MAX_MESSAGE_BYTES
    for needle in (
        f"DEFAULT_MAX_MESSAGE_BYTES` = {_size(DEFAULT_MAX_MESSAGE_BYTES)}",
        f"DEFAULT_MAX_INTERCHANGE_BYTES` = {_size(DEFAULT_MAX_INTERCHANGE_BYTES)}",
        f"DEFAULT_MAX_INFLATED_BYTES` = {_size(DEFAULT_MAX_INFLATED_BYTES)}",
        f"MAX_LINE_BYTES` = {email_sink.MAX_LINE_BYTES:,}",
        f"MAX_DATA_BYTES` = {_size(email_sink.MAX_DATA_BYTES)}",
        f"MAX_OUTBOX_PAYLOAD_CHARS` = {harness_database.MAX_OUTBOX_PAYLOAD_CHARS:,}",
        f"default {_size(DEFAULT_MAX_MESSAGE_BYTES)}",
    ):
        assert has_figure(row, needle), f"harness sink row lost or changed `{needle}`"


def test_every_harness_file_loader_keys_a_row_and_is_capped() -> None:
    """A loader reads a capture or an export, many messages to a file, so its cap is a file bound
    rather than the per-message cap. It must default to that bound and never read a file whole."""
    assert compare.DEFAULT_MAX_LOAD_FILE_BYTES == 64 * DEFAULT_MAX_MESSAGE_BYTES
    assert (
        _sig_default(compare.load_messages, "max_file_bytes") == compare.DEFAULT_MAX_LOAD_FILE_BYTES
    )
    trees = {
        rel: ast.parse((_ROOT / rel).read_text(encoding="utf-8")) for rel in HARNESS_FILE_LOADERS
    }
    calls = [
        (rel, c) for rel, tree in trees.items() for c in ast.walk(tree) if isinstance(c, ast.Call)
    ]
    assert len(calls) >= 1, "instrument found no calls at all in the loaders"
    whole = [f"{rel}:{c.lineno}" for rel, c in calls if whole_read(c)]
    assert not whole, f"a loader reads a file whole: {whole}"
    for rel, unit in HARNESS_FILE_LOADERS.items():
        names = {getattr(n, "name", None) for n in trees[rel].body}
        assert unit in names, f"{rel}::{unit} is gone"
        assert "read_capped" in {_call_name(c) for r, c in calls if r == rel}
        assert rel in _UPLOAD_ROWS, f"{rel} has no 5.1.1 upload row keyed by it"
        assert has_figure(
            _UPLOAD_ROWS[rel],
            f"DEFAULT_MAX_LOAD_FILE_BYTES` = {_size(compare.DEFAULT_MAX_LOAD_FILE_BYTES)}",
        )


# --- the harness's clients, and the files the engine or another host writes for it ---------------


def _harness_row_for(path: str) -> str:
    row = _UPLOAD_ROWS.get(path)
    assert row is not None, f"{path} has no 5.1.1 upload row keyed by it"
    return row


def test_every_harness_client_is_named_in_the_client_row_and_capped() -> None:
    """The harness's MLLP clients read the engine's ACKs with no frame cap until a 5.1.1 re-score
    found them. Every frame reader in ``harness/`` must carry a cap, and every client unit that
    builds one must be named in the client row."""
    readers = harness_frame_readers(_HARNESS, _ROOT)
    clients = harness_clients(readers)
    # Positive control: the instrument must see the clients it was written for.
    for known in (
        "harness/drivers/mllp.py::_read_reply",
        "harness/mllp.py::SendWorker",
        "harness/load/sender.py::PersistentConnection",
        "harness/fuzz/transport.py::_read_replies",
        "harness/drivers/tcp.py::TcpDriver",
        "harness/drivers/x12.py::X12Driver",
    ):
        assert known in clients, f"the client walk no longer sees {known}: {clients}"
    bad = uncapped_frame_readers(readers)
    assert not bad, bad
    for key in HARNESS_OWN_BYTES_READERS:
        assert key in readers, f"{key} has no frame reader now"
    row = _harness_row_for("harness/drivers/mllp.py")
    first_cell = row.split("|")[1]
    for rel in {k.split("::")[0] for k in clients} | set(HARNESS_HAND_KEPT_CLIENTS):
        assert f"`{rel}`" in first_cell, f"{rel} is not named in the harness client row"
    assert "`messagefoundry/apiclient/client.py`" in first_cell
    for rel, const in HARNESS_HAND_KEPT_CLIENTS.items():
        tree = ast.parse((_ROOT / rel).read_text(encoding="utf-8"))
        capped = [
            c
            for c in ast.walk(tree)
            if isinstance(c, ast.Call)
            and _call_name(c) == "read"
            and any(isinstance(a, ast.Name) and a.id == const for a in c.args)
        ]
        assert capped, f"{rel} no longer reads through {const}"
    assert http_driver.MAX_REPLY_BYTES == 64 * 1024
    for needle in (
        f"DEFAULT_MAX_FRAME_BYTES` = {_size(DEFAULT_MAX_FRAME_BYTES)}",
        f"_MAX_REPLY_BYTES` = {_size(fuzz_transport._MAX_REPLY_BYTES)}",
        f"_MAX_EXCHANGE_BYTES` = {_size(fuzz_transport._MAX_EXCHANGE_BYTES)}",
        f"DEFAULT_MAX_MESSAGE_BYTES` = {_size(DEFAULT_MAX_MESSAGE_BYTES)}",
        f"DEFAULT_MAX_INTERCHANGE_BYTES` = {_size(DEFAULT_MAX_INTERCHANGE_BYTES)}",
        f"MAX_REPLY_BYTES` = {_size(http_driver.MAX_REPLY_BYTES)}",
        f"MAX_RESPONSE_BYTES` = {_size(APICLIENT_MAX_RESPONSE_BYTES)}",
    ):
        assert has_figure(row, needle), f"harness client row lost or changed `{needle}`"


def test_every_foreign_file_read_is_bounded_and_keys_a_row() -> None:
    """Engine node logs and two-box coordination files were read whole. Each named unit must read
    through ``read_capped`` or read only a tail, and its file must read nothing whole."""
    assert harness_ladder.MAX_NODE_LOG_BYTES == 64 * DEFAULT_MAX_MESSAGE_BYTES
    assert harness_coord.MAX_COORD_MESSAGE_BYTES == 1 << 20
    trees = {
        rel: ast.parse((_ROOT / rel).read_text(encoding="utf-8"))
        for rel in HARNESS_FOREIGN_FILE_READS
    }
    for rel, unit in HARNESS_FOREIGN_FILE_READS.items():
        node = next((n for n in trees[rel].body if getattr(n, "name", None) == unit), None)
        assert node is not None, f"{rel}::{unit} is gone"
        names = {_call_name(c) for c in ast.walk(node) if isinstance(c, ast.Call)}
        if rel == "harness/load/failover.py":
            # The node's log is read only for its tail: a seek to the end, then a sized read.
            assert "seek" in names and "read_capped" not in names, f"{rel}::{unit} changed shape"
        else:
            assert "read_capped" in names, f"{rel}::{unit} does not read through read_capped"
        file_calls = sum(isinstance(c, ast.Call) for c in ast.walk(trees[rel]))
        assert file_calls >= _MIN_FOREIGN_READ_FILE_CALLS, f"{rel}: the call walk found too little"
    calls = [
        (rel, c) for rel, tree in trees.items() for c in ast.walk(tree) if isinstance(c, ast.Call)
    ]
    # Floor under the census taken when this landed (coord.py 28 calls, failover.py 256,
    # shardcert_ladder.py 463), so a walk that sees nothing cannot pass the absence check below.
    assert len(calls) >= len(trees) * _MIN_FOREIGN_READ_FILE_CALLS, "the call walk found too little"
    whole = [f"{rel}:{c.lineno}" for rel, c in calls if whole_read(c)]
    assert not whole, f"reads a file whole: {whole}"
    log_row = _harness_row_for("harness/load/shardcert_ladder.py")
    assert "`harness/load/failover.py`" in log_row.split("|")[1]
    assert has_figure(log_row, f"MAX_NODE_LOG_BYTES` = {_size(harness_ladder.MAX_NODE_LOG_BYTES)}")
    coord_row = _harness_row_for("harness/load/coord.py")
    assert has_figure(
        coord_row, f"MAX_COORD_MESSAGE_BYTES` = {_size(harness_coord.MAX_COORD_MESSAGE_BYTES)}"
    )


def test_every_rig_api_read_is_capped_and_keys_a_row() -> None:
    """The load rig read the engine's API answers, and the DIMSE driver the engine's C-STORE
    responses, with no byte cap until BACKLOG #1127. Each file must load the name that bounds it,
    read no answer whole, and be named in the rig row with each figure."""
    assert rig_admin.MAX_API_REPLY_BYTES == APICLIENT_MAX_RESPONSE_BYTES
    assert rig_failover.MAX_STATUS_REPLY_BYTES == 1 << 20
    assert dimse_driver.MAX_ASSOCIATION_READ_BYTES == 1 << 20
    for rel, bound in HARNESS_RIG_API_READS.items():
        tree = ast.parse((_ROOT / rel).read_text(encoding="utf-8"))
        loads = {
            n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
        }
        assert bound in loads, f"{rel} no longer reads through {bound}"
        assert sum(isinstance(c, ast.Call) for c in ast.walk(tree)) >= _MIN_FOREIGN_READ_FILE_CALLS
        bad = unbounded_api_reads(tree)
        assert not bad, f"{rel}: {bad}"
    # Every other harness file that imports an HTTP client makes none of those reads either: the
    # connscale, estate and ingress-probe runners poll through the capped helpers above.
    http_clients = harness_http_clients(_HARNESS, _ROOT)
    for known in ("harness/load/rigadmin.py", "harness/load/failover.py"):
        assert known in http_clients, f"the import walk no longer sees {known}: {http_clients}"
    for rel in http_clients:
        bad = unbounded_api_reads(ast.parse((_ROOT / rel).read_text(encoding="utf-8")))
        assert not bad, f"{rel}: {bad}"
    row = _harness_row_for("harness/load/rigadmin.py")
    first_cell = row.split("|")[1]
    for rel in HARNESS_RIG_API_READS:
        assert f"`{rel}`" in first_cell, f"{rel} is not named in the rig row"
    for needle in (
        f"MAX_API_REPLY_BYTES` = {_size(rig_admin.MAX_API_REPLY_BYTES)}",
        f"MAX_STATUS_REPLY_BYTES` = {_size(rig_failover.MAX_STATUS_REPLY_BYTES)}",
        f"MAX_ASSOCIATION_READ_BYTES` = {_size(dimse_driver.MAX_ASSOCIATION_READ_BYTES)}",
    ):
        assert has_figure(row, needle), f"rig row lost or changed `{needle}`"
    assert "Not settled" not in _BLOCK, "the rig's API reads are settled; the bullet must stay gone"


def test_self_test_whole_reads_are_flagged_and_bounded_reads_are_not(tmp_path: Path) -> None:
    """Positive control for the whole-read check every harness file axis shares. ``readlines`` and
    ``read(-1)`` read to the end as surely as ``read()``; PR 1968's check missed both."""
    calls = [
        c
        for c in ast.walk(
            ast.parse(
                "fh.read()\nfh.read(-1)\nfh.read(None)\nfh.read(size=-1)\nfh.readlines()\n"
                "fh.readlines(4096)\np.read_text()\np.read_bytes()\n"
                "fh.read(CAP)\nfh.read(4096)\nfh.read(CAP + 1)\nfh.read(size=CAP)\nread()\n"
                "fh.read(timeout=5)\nfh.readline(CAP)\n"
            )
        )
        if isinstance(c, ast.Call)
    ]
    flagged = sorted(c.lineno for c in calls if whole_read(c))
    assert flagged == [1, 2, 3, 4, 5, 6, 7, 8]
    bare = next(c for c in calls if c.lineno == 13)
    assert whole_read(bare) is None and whole_read(bare, bare_read=True) == "read"
    # Through a real axis: a planted sink that bounds at a cap but reads lines whole is caught.
    sinks = tmp_path / "harness" / "sinks"
    sinks.mkdir(parents=True)
    (sinks / "planted.py").write_text(
        "from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES\n"
        "def scan(fh):\n    cap = DEFAULT_MAX_MESSAGE_BYTES\n    return fh.readlines(), fh.read(-1)\n",
        encoding="utf-8",
    )
    assert unbounded_sinks(["harness/sinks/planted.py"], tmp_path, sinks) == [
        "harness/sinks/planted.py:4 (reads a file whole: readlines)",
        "harness/sinks/planted.py:4 (reads a file whole: read)",
    ]


def test_self_test_an_unbounded_api_read_is_flagged() -> None:
    tree = ast.parse(
        "async def a(client):\n    r = await client.get(url)\n    return r.json()\n"
        "def b(reply):\n    return reply.read()\n"
        "async def c(client):\n    async with client.stream('GET', url) as r:\n        pass\n"
        "def d(cfg):\n    return cfg.get('x'), json.loads(raw), reply.read(CAP)\n"
        "def e(self):\n    return self._client.post(url)\n"
    )
    assert unbounded_api_reads(tree) == [
        "2 (reads an answer whole: get)",
        "3 (reads an answer whole: json)",
        "5 (reads an answer whole: read)",
        "12 (reads an answer whole: post)",
    ]


def test_self_test_a_harness_client_is_found_and_an_uncapped_one_flagged(tmp_path: Path) -> None:
    src = tmp_path / "harness"
    (src / "sinks").mkdir(parents=True)
    (src / "cl.py").write_text(
        "def capped(sock):\n    return MLLPDecoder(max_frame_bytes=CAP)\n"
        "def bare(sock):\n    return MLLPDecoder()\n"
        "def none(sock):\n    return X12FrameReader(max_interchange_bytes=None)\n"
        "class Codec:\n    def go(self):\n        return self.codec.decoder()\n"
        "class Rx:\n    def go(self):\n        start_server()\n        MLLPDecoder(max_frame_bytes=CAP)\n",
        encoding="utf-8",
    )
    (src / "sinks" / "s.py").write_text(
        "def sink():\n    return MLLPDecoder(max_frame_bytes=CAP)\n", encoding="utf-8"
    )
    readers = harness_frame_readers(src, tmp_path)
    assert harness_clients(readers) == [
        "harness/cl.py::Codec",
        "harness/cl.py::bare",
        "harness/cl.py::capped",
        "harness/cl.py::none",
    ]
    assert uncapped_frame_readers(readers) == [
        "harness/cl.py::bare:4 (MLLPDecoder without a cap)",
        "harness/cl.py::none:6 (X12FrameReader without a cap)",
        "harness/cl.py::Codec:9 (decoder without a cap)",
    ]


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
    "MAX_LINE_BYTES": email_sink.MAX_LINE_BYTES,
    "MAX_DATA_BYTES": email_sink.MAX_DATA_BYTES,
    "MAX_OUTBOX_PAYLOAD_CHARS": harness_database.MAX_OUTBOX_PAYLOAD_CHARS,
    "DEFAULT_MAX_LOAD_FILE_BYTES": compare.DEFAULT_MAX_LOAD_FILE_BYTES,
    "_MAX_REPLY_BYTES": fuzz_transport._MAX_REPLY_BYTES,
    "_MAX_EXCHANGE_BYTES": fuzz_transport._MAX_EXCHANGE_BYTES,
    "MAX_REPLY_BYTES": http_driver.MAX_REPLY_BYTES,
    "MAX_RESPONSE_BYTES": APICLIENT_MAX_RESPONSE_BYTES,
    "MAX_NODE_LOG_BYTES": harness_ladder.MAX_NODE_LOG_BYTES,
    "MAX_COORD_MESSAGE_BYTES": harness_coord.MAX_COORD_MESSAGE_BYTES,
    "MAX_API_REPLY_BYTES": rig_admin.MAX_API_REPLY_BYTES,
    "MAX_STATUS_REPLY_BYTES": rig_failover.MAX_STATUS_REPLY_BYTES,
    "MAX_ASSOCIATION_READ_BYTES": dimse_driver.MAX_ASSOCIATION_READ_BYTES,
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


def test_self_test_a_harness_sink_is_found_and_an_unbounded_one_flagged(tmp_path: Path) -> None:
    sinks_dir = tmp_path / "harness" / "sinks"
    sinks_dir.mkdir(parents=True)
    (sinks_dir / "__init__.py").write_text(
        "from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES\n"
        "CAP = DEFAULT_MAX_MESSAGE_BYTES\n",
        encoding="utf-8",
    )
    (sinks_dir / "_helper.py").write_text(
        "from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES\n"
        "def cap():\n    return DEFAULT_MAX_MESSAGE_BYTES\n",
        encoding="utf-8",
    )
    (sinks_dir / "capped.py").write_text(
        "from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES\n"
        "KIND = 'capped'\nLIMIT = DEFAULT_MAX_MESSAGE_BYTES\n",
        encoding="utf-8",
    )
    (sinks_dir / "viahelper.py").write_text(
        "from harness.sinks._helper import cap\nKIND: str = 'viahelper'\n", encoding="utf-8"
    )
    (sinks_dir / "viainit.py").write_text(
        "from harness.sinks import CAP\nKIND = 'viainit'\n", encoding="utf-8"
    )
    (sinks_dir / "importonly.py").write_text(
        "from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES\nKIND = 'importonly'\n",
        encoding="utf-8",
    )
    (sinks_dir / "whole.py").write_text(
        "from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES\n"
        "KIND = 'whole'\n"
        "def scan(p):\n    DEFAULT_MAX_MESSAGE_BYTES\n    return p.read_bytes()\n"
        "def pull(read, fh):\n    read()\n    return fh.read()\n",
        encoding="utf-8",
    )
    (sinks_dir / "notasink.py").write_text("X = 1\n", encoding="utf-8")
    (sinks_dir / "_private.py").write_text("KIND = 'hidden'\n", encoding="utf-8")
    sinks = harness_sinks(sinks_dir, tmp_path)
    assert sinks == [
        "harness/sinks/capped.py",
        "harness/sinks/importonly.py",
        "harness/sinks/notasink.py",
        "harness/sinks/viahelper.py",
        "harness/sinks/viainit.py",
        "harness/sinks/whole.py",
    ]
    assert unbounded_sinks(sinks, tmp_path, sinks_dir) == [
        f"harness/sinks/importonly.py (bounds at none of {sorted(_SINK_CAPS)})",
        f"harness/sinks/notasink.py (bounds at none of {sorted(_SINK_CAPS)})",
        f"harness/sinks/viainit.py (bounds at none of {sorted(_SINK_CAPS)})",
        "harness/sinks/whole.py:5 (reads a file whole: read_bytes)",
        "harness/sinks/whole.py:8 (reads a file whole: read)",
    ]
