# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``UnicodeError`` reaches a log line or a wrapping error only through ``safe_exc`` (vault BACKLOG
#3185, from #3033).

``str(UnicodeEncodeError)`` names the character the codec could not encode and
``str(UnicodeDecodeError)`` the byte it could not decode. Both are message content. Engine PR 2106
made :func:`~messagefoundry.redaction.safe_exc` build the text from the error's attributes instead,
and its Builder found three paths that still rendered the raw ``str()``. This module holds one test
per path, and a source scan that keeps a new site from rendering a caught one raw:

1. the traceback a log call renders from ``exc_info``, chained causes included;
2. a ``%s`` (or ``%r``) log argument that is the error object;
3. an error rendered INTO another error's message, as ``f"...{exc}"``.
"""

from __future__ import annotations

import ast
import io
import itertools
import logging
import struct
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.config.code_sets import CodeSetError, load_code_set
from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.wiring import Registry, WiringError
from messagefoundry.corepoint_import import (
    CorepointImportError,
    _assert_encodable,
    import_corepoint,
)
from messagefoundry.lens import LensParseError, parse_module, rewrite_module
from messagefoundry.logging_setup import (
    ControlCharScrubFilter,
    JsonFormatter,
    RedactionFilter,
    _install_phi_filters,
    _make_formatter,
)
from messagefoundry.pipeline._sandbox_codec import SandboxCodecError, decode_frame
from messagefoundry.pipeline.ingress_guards import IngressGuardError, admit_resubmitted_body
from messagefoundry.redaction import codec_safe_str, prepare_log_record, safe_traceback
from messagefoundry.tray.logscrub import TrayLogScrubFilter
from tests._ast_sites import callee_name
from tests._content_free import SECRET_CHAR, escapes
from tests.test_ingress_guard_parity import _inbound

_REPO = Path(__file__).resolve().parents[1]

#: A planted character no ASCII codec can encode, and every spelling a renderer could give it.
_CHAR = SECRET_CHAR
#: Less the bare hex digits "e9", which a traceback's checkout path can carry by chance.
_CHAR_SPELLINGS = [s for s in escapes(_CHAR) if s != f"{ord(_CHAR):x}"]
#: A planted byte UTF-8 cannot decode, and every spelling a renderer could give it.
_BYTE = b"\xfe"
_BYTE_SPELLINGS = ("\\xfe", "0xfe")
_LOGGERS = itertools.count()


def _encode_error() -> UnicodeEncodeError:
    try:
        f"caf{_CHAR}".encode("ascii")
    except UnicodeEncodeError as exc:
        return exc
    raise AssertionError("ascii encoded a non-ASCII character")


def _decode_error() -> UnicodeDecodeError:
    try:
        (b"ok" + _BYTE).decode("utf-8")
    except UnicodeDecodeError as exc:
        return exc
    raise AssertionError("utf-8 decoded an invalid start byte")


def _assert_encode_safe(text: str, position: int | None = 3) -> None:
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in text, (spelling, text)
    assert "UnicodeEncodeError: 'ascii' codec cannot encode at position " in text, text
    if position is not None:
        assert f"position {position}: ordinal not in range(128)" in text, text


def _assert_decode_safe(text: str) -> None:
    for spelling in _BYTE_SPELLINGS:
        assert spelling not in text, (spelling, text)
    expected = "UnicodeDecodeError: 'utf-8' codec cannot decode at position 2: invalid start byte"
    assert expected in text, text


def test_the_raw_errors_and_the_stdlib_renderer_carry_the_planted_value() -> None:
    # The premise every assertion here rests on: the raw str() of each error, and the stdlib
    # traceback this module replaces, DO carry the value. Without it an absent spelling proves nothing.
    assert "\\xe9" in str(_encode_error())
    assert "0xfe" in str(_decode_error())
    exc = _encode_error()
    assert "\\xe9" in logging.Formatter().formatException((type(exc), exc, exc.__traceback__))


# --- path 1: the traceback renderer -----------------------------------------------------------------


def _capture(handler_fmt: str = "text") -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(_make_formatter(handler_fmt))
    _install_phi_filters(handler)
    logger = logging.getLogger(f"test.unicode3185.{handler_fmt}.n{next(_LOGGERS)}")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    return logger, stream


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_an_exc_info_traceback_renders_an_encode_error_from_its_attributes(fmt: str) -> None:
    logger, stream = _capture(fmt)
    try:
        f"caf{_CHAR}".encode("ascii")
    except UnicodeEncodeError:
        logger.exception("encode failed")
    out = stream.getvalue()
    _assert_encode_safe(out)
    assert "Traceback (most recent call last)" in out  # the frames survive; only the line changed


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_an_exc_info_traceback_renders_a_decode_error_from_its_attributes(fmt: str) -> None:
    logger, stream = _capture(fmt)
    try:
        (b"ok" + _BYTE).decode("utf-8")
    except UnicodeDecodeError as exc:
        logger.error("decode failed", exc_info=exc)
    _assert_decode_safe(stream.getvalue())


def test_a_chained_unicode_error_renders_safely_under_cause_and_context() -> None:
    logger, stream = _capture()
    try:
        try:
            (b"ok" + _BYTE).decode("utf-8")
        except UnicodeDecodeError as inner:
            try:
                f"caf{_CHAR}".encode("ascii")
            except UnicodeEncodeError:  # __context__ is the decode error
                raise RuntimeError("frame refused") from inner  # __cause__ is it too
    except RuntimeError:
        logger.exception("worker failed")
    out = stream.getvalue()
    assert "RuntimeError: frame refused" in out  # a non-Unicode line is untouched
    _assert_decode_safe(out)
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


def test_a_unicode_error_inside_an_exception_group_renders_safely() -> None:
    text = safe_traceback((None, ExceptionGroup("batch", [_encode_error(), _decode_error()]), None))
    _assert_encode_safe(text)
    _assert_decode_safe(text)


def test_an_empty_exc_info_renders_as_the_stdlib_renders_it() -> None:
    # exc_info=True outside an except arm hands the renderer (None, None, None).
    assert safe_traceback((None, None, None)) == logging.Formatter().formatException(
        (None, None, None)
    )


def test_a_bare_unicode_error_renders_its_class_only() -> None:
    # A bare UnicodeError's message is free text this renderer cannot vouch for.
    text = safe_traceback((None, UnicodeError(f"bad {_CHAR}"), None))
    assert text == "UnicodeError"


def test_the_json_formatters_defensive_branch_is_safe_without_the_filter_chain() -> None:
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "x", (), None)
    record.exc_info = (UnicodeEncodeError, _encode_error(), None)
    _assert_encode_safe(JsonFormatter().format(record))


def test_the_tray_chain_renders_a_unicode_traceback_and_argument_safely() -> None:
    record = logging.LogRecord(
        "t", logging.ERROR, __file__, 1, "poll: %s", (_decode_error(),), None
    )
    record.exc_info = (UnicodeEncodeError, _encode_error(), None)
    assert TrayLogScrubFilter().filter(record)
    _assert_encode_safe(record.exc_text or "")
    _assert_decode_safe(record.getMessage())


# --- path 2: a %s / %r log argument ------------------------------------------------------------------


@pytest.mark.parametrize("placeholder", ["%s", "%r"])
def test_a_percent_argument_holding_a_unicode_error_renders_from_its_attributes(
    placeholder: str,
) -> None:
    logger, stream = _capture()
    logger.warning(
        f"skipped, unreadable: {placeholder} / {placeholder}", _decode_error(), _encode_error()
    )
    out = stream.getvalue()
    _assert_decode_safe(out)
    _assert_encode_safe(out)


def test_a_mapping_argument_holding_a_unicode_error_renders_safely() -> None:
    logger, stream = _capture()
    logger.warning("skipped: %(err)s", {"err": _decode_error()})
    _assert_decode_safe(stream.getvalue())


def test_a_unicode_error_inside_a_container_argument_renders_safely() -> None:
    # A container renders its items with repr(), and repr(exc) prints .object, the whole input.
    assert "caf" in repr([_encode_error()])  # control: the raw container carries the input
    logger, stream = _capture()
    logger.warning("errors: %s %s", [_encode_error()], {"e": (_decode_error(), 1)})
    out = stream.getvalue()
    _assert_encode_safe(out)
    _assert_decode_safe(out)
    assert "caf" not in out


def test_a_traceback_an_outside_formatter_cached_is_rendered_again() -> None:
    # A plain formatter on a child logger's own handler formats first and caches the stdlib's text
    # in exc_text while exc_info is still set. The chain must not keep that cached text.
    exc = _encode_error()
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "x", (), (type(exc), exc, None))
    assert "\\xe9" in logging.Formatter().format(record)  # the outside formatter runs first
    assert record.exc_info is not None and "\\xe9" in (record.exc_text or "")  # control
    RedactionFilter().filter(record)
    _assert_encode_safe(record.exc_text or "")


def test_a_mixed_arm_keeps_an_os_error_path_whole(tmp_path: Path) -> None:
    # Only the Unicode error carries message content. An OSError's path is what an operator needs,
    # so it is not redacted or cut (codec_safe_str rather than safe_exc).
    missing = tmp_path / "Acme Health 2026-10-07" / "connections.toml"
    with pytest.raises(WiringError) as caught:
        load_connections_file(missing, Registry())
    assert str(missing) in str(caught.value) or repr(str(missing))[1:-1] in str(caught.value)
    assert codec_safe_str(OSError(2, "gone", str(missing))) == str(OSError(2, "gone", str(missing)))
    _assert_decode_safe(codec_safe_str(_decode_error()))


def test_a_unicode_error_logged_as_the_message_itself_renders_safely() -> None:
    logger, stream = _capture()
    logger.warning(_encode_error())
    _assert_encode_safe(stream.getvalue())


def test_a_record_with_nothing_to_replace_keeps_its_args() -> None:
    args = ("fid", 3)
    record = logging.LogRecord("t", logging.WARNING, __file__, 1, "%s %s", args, None)
    prepare_log_record(record)
    assert record.args is args  # nothing to rewrite, nothing copied


def test_the_redaction_filter_alone_rewrites_the_argument() -> None:
    # The chain's first filter does it, so every later filter and the formatter see the safe text.
    record = logging.LogRecord("t", logging.WARNING, __file__, 1, "x %s", (_encode_error(),), None)
    RedactionFilter().filter(record)
    ControlCharScrubFilter().filter(record)
    _assert_encode_safe(record.getMessage())


# --- path 3: an error rendered into another error's message -----------------------------------------


def test_the_sandbox_codec_names_a_malformed_frame_without_the_byte() -> None:
    header = b"ok" + _BYTE
    with pytest.raises(SandboxCodecError) as caught:
        decode_frame(struct.pack(">I", len(header)) + header)
    assert str(caught.value).startswith("malformed sandbox frame: UnicodeDecodeError: ")
    _assert_decode_safe(str(caught.value))


def test_an_ingress_encode_refusal_names_the_position_without_the_character() -> None:
    with pytest.raises(IngressGuardError) as caught:
        admit_resubmitted_body(
            f"MSH|^~\\&|A|B|C|D|20260926||ADT^A01|1|P|2.5\rPID|1||caf{_CHAR}",
            _inbound(encoding="ascii"),
        )
    assert caught.value.reason.startswith("encode error (ascii): UnicodeEncodeError: ")
    _assert_encode_safe(caught.value.reason, position=None)


def test_file_readers_name_a_bad_byte_by_position_only(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"  # load_code_set picks its parser by extension
    bad.write_bytes(b"ok" + _BYTE)
    refusals: list[str] = []
    for call, error in (
        (lambda: parse_module(bad), LensParseError),
        (lambda: rewrite_module(bad, {}), LensParseError),
        (lambda: import_corepoint(bad, tmp_path / "out"), CorepointImportError),
        (lambda: load_code_set(bad), CodeSetError),
        (lambda: load_connections_file(bad, Registry()), WiringError),
    ):
        with pytest.raises(error) as caught:
            call()
        refusals.append(str(caught.value))
    for text in refusals:
        _assert_decode_safe(text)


def test_an_unencodable_corepoint_value_names_its_position_not_its_code_point() -> None:
    with pytest.raises(CorepointImportError) as caught:
        _assert_encodable("ab\ud800", "[x]")
    text = str(caught.value)
    for spelling in ("\ud800", "\\ud800", "ud800"):
        assert spelling not in text
    assert "UnicodeEncodeError: 'utf-8' codec cannot encode at position 2" in text


# --- the guard: a new site cannot render a caught UnicodeError raw ----------------------------------

#: The trees the scan walks. ``harness/`` is a client test tool that sends synthetic data only, and it
#: may not import the engine's redaction module through the client allow-list, so it is not scanned.
_SCANNED = ("messagefoundry", "messagefoundry_webconsole", "messagefoundry_toolkit")
_UNICODE_TYPES = frozenset(
    {"UnicodeError", "UnicodeEncodeError", "UnicodeDecodeError", "UnicodeTranslateError"}
)
#: Attributes that hold the input or a free-text reason. ``.start``, ``.end`` and ``.encoding`` are
#: positions and the caller's codec name, and stay allowed.
_RAW_ATTRS = frozenset({"object", "args", "reason"})
#: Calls that render their argument as text. The scan cannot know what a lowercase helper of the
#: code's own does, so a raw error handed to one passes it: a stated limit, not a check.
_RENDER_CALLS = frozenset(
    {"str", "repr", "format", "print", "format_exception", "format_exception_only"}
    | {"print_exception", "TracebackException"}
)
_LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)
#: The scan must keep finding at least this many handlers, or it has stopped walking the tree.
_MIN_HANDLERS = 15


def _handler_names(node: ast.expr | None) -> set[str]:
    if node is None:
        return set()
    elts = node.elts if isinstance(node, ast.Tuple) else [node]
    return {
        e.id if isinstance(e, ast.Name) else e.attr
        for e in elts
        if isinstance(e, (ast.Name, ast.Attribute))
    }


def _is_raw(node: ast.AST, name: str) -> bool:
    """``node`` is the bound error itself, or one of its raw attributes."""
    if isinstance(node, ast.Name):
        return node.id == name
    return (
        isinstance(node, ast.Attribute)
        and node.attr in _RAW_ATTRS
        and isinstance(node.value, ast.Name)
        and node.value.id == name
    )


def _raw_renders(handler: ast.ExceptHandler) -> Iterator[tuple[int, str]]:
    name = handler.name
    assert name is not None
    for node in (n for stmt in handler.body for n in ast.walk(stmt)):
        if isinstance(node, ast.FormattedValue) and _is_raw(node.value, name):
            yield node.lineno, "f-string interpolation"
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            right = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
            if any(_is_raw(r, name) for r in right):
                yield node.lineno, "% formatting"
        elif isinstance(node, ast.Call):
            yield from _raw_call(node, name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            if _is_raw(node.value, name):  # the raise-after-handler shape carries it out
                yield node.lineno, "aliased out of the handler"
        elif isinstance(node, ast.Attribute) and _is_raw(node, name) and node.attr != "reason":
            yield node.lineno, f".{node.attr} read"


def _raw_call(node: ast.Call, name: str) -> Iterator[tuple[int, str]]:
    # exc_info= is path 1, which the log filter chain renders safely, so it stays allowed.
    values = [*node.args, *(k.value for k in node.keywords if k.arg != "exc_info")]
    if not any(_is_raw(v, name) for v in values):
        return
    callee = callee_name(node) or ""
    if callee in _RENDER_CALLS:
        yield node.lineno, f"{callee}() of the error"
    elif isinstance(node.func, ast.Attribute) and callee in _LOG_METHODS:
        yield node.lineno, "log argument"
    elif callee[:1].isupper():
        yield node.lineno, f"passed into {callee}()"


def _scan_source(source: str, path: str) -> tuple[int, list[str]]:
    handlers = 0
    found: list[str] = []
    for node in ast.walk(ast.parse(source, path)):
        if (
            isinstance(node, ast.ExceptHandler)
            and node.name
            and _handler_names(node.type) & _UNICODE_TYPES
        ):
            handlers += 1
            found.extend(f"{path}:{line}: {what}" for line, what in _raw_renders(node))
    return handlers, found


def _scan_tree() -> tuple[int, list[str]]:
    handlers = 0
    found: list[str] = []
    for root in _SCANNED:
        for path in sorted((_REPO / root).rglob("*.py")):
            rel = path.relative_to(_REPO).as_posix()
            if "/_vendor/" in rel:
                continue
            n, f = _scan_source(path.read_text(encoding="utf-8"), rel)
            handlers += n
            found.extend(f)
    return handlers, found


def test_no_handler_renders_a_caught_unicode_error_raw() -> None:
    handlers, found = _scan_tree()
    assert handlers >= _MIN_HANDLERS, f"the scan found only {handlers} handlers; is it walking?"
    assert not found, "\n".join(found)


_PLANTED = """
import logging
log = logging.getLogger(__name__)
def a(b):
    try:
        b.decode()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read: {exc}") from exc
def c(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        log.warning("unreadable: %s", exc)
def d(b):
    try:
        b.decode()
    except UnicodeError as exc:
        reason = f"bad ({exc.reason})"
def e(b):
    try:
        b.decode()
    except codecs.UnicodeDecodeError as err:
        return "bad: %s" % err
def f(b):
    try:
        b.decode()
    except UnicodeEncodeError as exc:
        raise RuntimeError(exc) from None
def g(b):
    try:
        b.decode()
    except UnicodeEncodeError as exc:
        payload = exc.object
def h(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        raise ValueError("bad: {e}".format(e=exc))
def i(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        saved = exc
def j(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        text = "".join(traceback.format_exception(exc))
"""

_CLEAN = """
from messagefoundry.redaction import safe_exc
def a(b):
    try:
        b.decode()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read: {safe_exc(exc)} at {exc.start}") from exc
def b2(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        log.warning("unreadable", exc_info=exc)
def c(b):
    try:
        b.decode()
    except ValueError as exc:  # not a Unicode handler: out of this scan's scope, by design
        raise RuntimeError(f"{exc}")
"""


def test_the_guard_fires_on_every_planted_shape() -> None:
    handlers, found = _scan_source(_PLANTED, "planted.py")
    assert handlers == 9
    kinds = [line.split(": ", 1)[1] for line in found]
    assert kinds == [
        "f-string interpolation",
        "log argument",
        "f-string interpolation",
        "% formatting",
        "passed into RuntimeError()",
        "aliased out of the handler",  # g: the assignment and the read are both reported
        ".object read",
        "format() of the error",
        "aliased out of the handler",
        "format_exception() of the error",
    ], found


def test_the_guard_passes_the_safe_shapes() -> None:
    assert _scan_source(_CLEAN, "clean.py") == (2, [])
