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

import abc
import ast
import collections
import collections.abc
import configparser
import functools
import io
import itertools
import logging
import struct
import sys
import traceback
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import redaction
from messagefoundry.config.code_sets import CodeSetError, load_code_set
from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.wiring import Registry, Send, WiringError
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
from messagefoundry.pipeline._sandbox_codec import (
    SandboxCodecError,
    _Blobs,
    decode_frame,
    enc_result,
)
from messagefoundry.pipeline.ingress_guards import IngressGuardError, admit_resubmitted_body
from messagefoundry.redaction import codec_safe_str, prepare_log_record, safe_traceback
from messagefoundry.tray.logscrub import TrayLogScrubFilter
from tests._ast_sites import callee_name
from tests._content_free import SECRET_CHAR, escapes
from tests.test_db_lookup import _sandbox_kind, sandbox_run_one  # noqa: F401 - a fixture
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


@pytest.fixture(autouse=True)
def _drop_capture_loggers() -> Iterator[None]:
    yield
    manager = logging.Logger.manager
    for name in [n for n in manager.loggerDict if n.startswith("test.unicode3185.")]:
        logger = manager.loggerDict.pop(name)
        if isinstance(logger, logging.Logger):
            for handler in list(logger.handlers):
                logger.removeHandler(handler)
                handler.close()


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


def test_a_unicode_error_as_a_key_or_in_a_container_subclass_renders_safely() -> None:
    pair = collections.namedtuple("pair", "err n")
    logger, stream = _capture()
    logger.warning(
        "%s %s %s %s",
        {_encode_error(): 1},
        collections.OrderedDict(e=_encode_error()),
        pair(_encode_error(), 1),
        collections.deque([_decode_error()]),
    )
    logger.warning("%(err)s", collections.OrderedDict(err=_decode_error()))
    out = stream.getvalue()
    _assert_encode_safe(out)
    _assert_decode_safe(out)
    assert "caf" not in out


def _nested(leaf: object, levels: int) -> object:
    for _ in range(levels):
        leaf = [leaf]
    return leaf


@pytest.mark.parametrize("levels", [4, 5])
@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_a_unicode_error_deep_inside_nested_containers_renders_safely(
    levels: int, chain: str
) -> None:
    # Round 2 checked the depth cutoff before the error, so an error at the last walked level
    # printed its whole .object again. Four levels is the case the Lander measured.
    arg = _nested(_encode_error(), levels)
    assert "caf" in repr(arg)  # control: the raw nesting carries the input
    record = logging.LogRecord("t", logging.WARNING, __file__, 1, "x %r", (arg,), None)
    (RedactionFilter() if chain == "engine" else TrayLogScrubFilter()).filter(record)
    out = record.getMessage()
    _assert_encode_safe(out)
    assert "caf" not in out


def test_a_unicode_error_deep_inside_a_single_mapping_argument_renders_safely() -> None:
    logger, stream = _capture()
    logger.warning("%(e)r", {"e": _nested(_decode_error(), 5)})
    out = stream.getvalue()
    _assert_decode_safe(out)
    assert "ok\\xfe" not in out


def test_an_exception_group_argument_holding_a_unicode_error_renders_safely() -> None:
    group = ExceptionGroup("batch", [ValueError("x"), ExceptionGroup("inner", [_encode_error()])])
    assert "caf" in repr(group)  # control
    logger, stream = _capture()
    logger.warning("failed: %r", group)
    out = stream.getvalue()
    assert "caf" not in out and "ExceptionGroup" in out
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


class _RaisingMapping(collections.abc.Mapping[str, int]):
    """A Mapping whose reads raise, as a ConfigParser's interpolation or a lazy table's can."""

    def __getitem__(self, key: str) -> int:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(["k"])

    def __len__(self) -> int:
        return 1


class _RaisingIterList(list[object]):
    def __iter__(self) -> Iterator[object]:
        raise RuntimeError("a subclass's own iteration")


def _config_with_a_missing_interpolation() -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser["s"] = {"k": "%(missing)s"}
    return parser


@pytest.mark.parametrize(
    "arg",
    [_config_with_a_missing_interpolation(), _RaisingMapping(), _RaisingIterList([1])],
    ids=["configparser", "raising-mapping", "raising-iter"],
)
def test_a_log_argument_whose_own_code_raises_renders_as_the_stdlib_renders_it(arg: object) -> None:
    # A log call must never raise because of its arguments. Round 2 read any Mapping through its
    # own .items() and any list subclass through its own __iter__, on every record.
    logger, stream = _capture()
    logger.warning("cfg %s %s", arg, 1)
    assert f"cfg {arg} 1" in stream.getvalue()  # what the stdlib's own "%s" renders


def test_a_single_mapping_argument_renders_as_the_stdlib_renders_it() -> None:
    logger, stream = _capture()
    logger.info("%(a)s and %(b)r", {"a": 1, "b": "two"})
    assert "1 and 'two'" in stream.getvalue()


def test_a_defaultdict_holding_a_unicode_error_keeps_its_default() -> None:
    # Round 2 rebuilt it as a plain dict, so "%(b)s" lost its default and raised KeyError.
    logger, stream = _capture()
    args: collections.defaultdict[str, object] = collections.defaultdict(str, a=_encode_error())
    logger.warning("[%(a)s] [%(b)s]", args)
    out = stream.getvalue()
    _assert_encode_safe(out)
    assert "] []" in out


def test_two_unicode_error_keys_that_render_alike_stay_two_keys() -> None:
    first, second = _encode_error(), _encode_error()
    record = logging.LogRecord(
        "t", logging.WARNING, __file__, 1, "%s %s", ({first: 1, second: 2}, {first, second}), None
    )
    prepare_log_record(record)
    safe = repr(redaction.safe_exc(first))
    assert record.getMessage() == f"{{{safe}: 1, {safe}: 2}} {{{safe}, {safe}}}"
    _assert_encode_safe(record.getMessage())


class _HostileDict(dict[str, object]):
    """Every override would write to the caller's own object, or raise, if the walk ran it."""

    def __copy__(self) -> _HostileDict:
        return self

    def clear(self) -> None:
        raise AssertionError("the walk ran the subclass's clear()")

    def __setitem__(self, key: str, value: object) -> None:
        raise AssertionError("the walk ran the subclass's __setitem__()")


def test_a_dict_subclass_is_rebuilt_without_running_its_own_code() -> None:
    err = _encode_error()
    arg = _HostileDict(e=err)
    logger, stream = _capture()
    logger.warning("%s", arg)
    logger.warning("%(e)s", arg)
    out = stream.getvalue()
    _assert_encode_safe(out)
    assert "caf" not in out
    assert dict.__getitem__(arg, "e") is err  # the caller's object still holds its own error


class _Unreprable:
    def __repr__(self) -> str:
        raise ValueError("no repr")


def test_an_argument_that_cannot_be_rendered_is_withheld_alone_never_raised() -> None:
    logger, stream = _capture()
    # The list prints its other elements as it would, and one of them cannot be printed.
    logger.warning("%s / %s", [_encode_error(), _Unreprable()], "kept")
    out = stream.getvalue()
    assert "[withheld: ValueError while scanning it for a codec error] / kept" in out
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


def _cyclic_list() -> list[object]:
    loop: list[object] = [_encode_error()]
    loop.append(loop)
    return loop


def _cyclic_dict() -> dict[str, object]:
    loop: dict[str, object] = {"e": _encode_error()}
    loop["self"] = loop
    return loop


def _groups(levels: int) -> Exception:
    group: Exception = _encode_error()
    for n in range(levels):
        group = ExceptionGroup(f"level {n}", [group])
    return group


@pytest.mark.parametrize(
    "arg",
    [
        _cyclic_list(),
        _cyclic_dict(),
        _nested(_encode_error(), 6),
        _nested(_nested(_encode_error(), 3), 6),
        _groups(3),
        _groups(8),
        collections.UserDict(e=_encode_error()),
        RuntimeError(_encode_error()),
        KeyError(_encode_error()),
        collections.deque([_encode_error()], maxlen=3),
    ],
    ids=[
        "cyclic-list",
        "cyclic-dict",
        "six-deep",
        "nine-deep",
        "three-groups",
        "eight-groups",
        "userdict",
        "runtime-wrap",
        "keyerror-wrap",
        "deque",
    ],
)
@pytest.mark.parametrize("placeholder", ["%s", "%r"])
def test_an_error_past_the_walk_or_wrapped_renders_safely(arg: object, placeholder: str) -> None:
    # Past the depth or round a cycle the walk cannot see, so it fails closed. A wrapping
    # exception prints its .args through str() and repr(), and a group prints its members.
    assert "caf" in repr(arg)  # control: the raw argument carries the input
    logger, stream = _capture()
    logger.warning(f"got {placeholder}", arg)
    out = stream.getvalue()
    assert "caf" not in out
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


def test_the_walk_fails_closed_past_five_levels_and_keeps_a_deques_bound() -> None:
    record = logging.LogRecord(
        "t",
        logging.WARNING,
        __file__,
        1,
        "%r %r",
        (_nested(_encode_error(), 6), collections.deque([_encode_error()], maxlen=3)),
        None,
    )
    prepare_log_record(record)
    out = record.getMessage()
    assert "[holds a codec error, nested too deep to render]" in out
    assert "maxlen=3" in out


def test_a_proxy_that_fakes_its_class_renders_as_the_stdlib_renders_it() -> None:
    # isinstance() believes a Mock(spec=dict), and dict.items() on it then raises.
    from unittest import mock

    proxy = mock.Mock(spec=dict)
    logger, stream = _capture()
    logger.warning("val %s %s", proxy, 5)
    assert f"val {proxy} 5" in stream.getvalue()


class _CaseFolding(dict[str, object]):
    def __getitem__(self, key: str) -> object:
        return dict.__getitem__(self, key.lower())


def test_a_mapping_key_answered_by_the_original_is_walked_too() -> None:
    # The rebuilt mapping asks the original for a key it lacks; what comes back is walked.
    logger, stream = _capture()
    logger.warning("%(E)s %(E)r", _CaseFolding(e=_encode_error()))
    out = stream.getvalue()
    _assert_encode_safe(out)
    assert "caf" not in out


def test_a_withheld_message_takes_its_arguments_with_it() -> None:
    logger, stream = _capture()
    logger.warning([_encode_error(), _Unreprable()], 1)
    assert "[withheld: ValueError while scanning it for a codec error]" in stream.getvalue()


def test_dict_views_holding_a_unicode_error_render_safely() -> None:
    errors = {"e": _encode_error()}
    ordered = collections.OrderedDict(e=_encode_error())
    logger, stream = _capture()
    logger.warning("%s %s %r", errors.values(), errors.items(), errors.keys())
    logger.warning("%s %r", ordered.values(), [ordered.items()])
    out = stream.getvalue()
    _assert_encode_safe(out)
    assert "caf" not in out


class _LoudGroup(ExceptionGroup[Exception]):
    def __str__(self) -> str:
        return f"{self.message}: {self.exceptions!r}"


class _ArgsGroup(ExceptionGroup[Exception]):
    def __str__(self) -> str:
        return repr(self.args)


def test_a_group_subclass_printing_its_members_renders_as_its_class_and_a_note() -> None:
    members: list[Exception] = [ValueError("x")]
    by_args = _ArgsGroup("batch", members)
    members.append(_encode_error())  # in .args, the caller's own list, and not in .exceptions
    assert "caf" in str(by_args)  # control
    logger, stream = _capture()
    logger.warning("%s", _LoudGroup("batch", [_encode_error()]))
    logger.warning("%s", by_args)
    out = stream.getvalue()
    assert "[_LoudGroup holding a codec error, not rendered]" in out
    assert "[_ArgsGroup holding a codec error, not rendered]" in out
    assert "caf" not in out


def test_a_shared_container_is_walked_once() -> None:
    # Thirty references to one list, four levels down, are 30**4 paths and four containers.
    shared: list[object] = [_encode_error()]
    for _ in range(4):
        shared = [shared] * 30
    record = logging.LogRecord("t", logging.WARNING, __file__, 1, "%s", (shared,), None)
    prepare_log_record(record)
    out = record.getMessage()
    assert "caf" not in out and "UnicodeEncodeError" in out


class _UnprintableError(Exception):
    def __str__(self) -> str:
        raise ValueError("no str")


@pytest.mark.parametrize("arg", [_Unreprable(), "%d"], ids=["raising-repr", "bad-format"])
def test_a_record_the_stdlib_could_not_format_is_dropped_never_raised(arg: object) -> None:
    logger, stream = _capture()
    if isinstance(arg, _Unreprable):
        logger.warning("%r", arg)  # the stdlib alone would raise here, from the caller's call
    else:
        logger.warning(arg, "x")
    assert "[log record dropped: " in stream.getvalue()


def test_a_sandboxed_handler_error_that_cannot_be_printed_reports_its_class(
    sandbox_run_one: Any,  # noqa: F811 - the fixture imported above
) -> None:
    kind, error = _sandbox_kind(sandbox_run_one, _UnprintableError())
    assert (kind, error) == ("error", "_UnprintableError")


def test_a_traceback_that_cannot_be_rendered_is_withheld_never_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(ei: object) -> str:
        raise RuntimeError("renderer")

    monkeypatch.setattr(redaction, "safe_traceback", broken)
    logger, stream = _capture()
    try:
        f"caf{_CHAR}".encode("ascii")
    except UnicodeEncodeError:
        logger.exception("encode failed")
    out = stream.getvalue()
    assert "[traceback withheld: RuntimeError while rendering it]" in out
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


def test_a_renamed_private_traceback_line_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A later CPython that drops TracebackException._str must not print the raw line.
    original = traceback.TracebackException.__init__

    def init(self: traceback.TracebackException, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        self.__dict__["_renamed"] = self.__dict__.pop("_str")

    monkeypatch.setattr(traceback.TracebackException, "__init__", init)
    text = safe_traceback((None, _encode_error(), None))
    assert text == "UnicodeEncodeError: 'ascii' codec cannot encode at position 3: " + (
        "ordinal not in range(128)"
    )


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


# --- minimal touch: only the path to an error changes (round 5 of #3185) -----------------------------


def _record(msg: str, args: Any) -> logging.LogRecord:
    return logging.LogRecord("t", logging.WARNING, __file__, 1, msg, args, None)


def _chain_filter(chain: str) -> logging.Filter:
    return RedactionFilter() if chain == "engine" else TrayLogScrubFilter()


class _Hides(Exception):
    """Keeps its arguments out of its message, as a Handler's own error class may."""

    def __str__(self) -> str:
        return "parse failed"


@pytest.mark.parametrize("placeholder", ["%s", "%r"])
@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_an_exception_holding_a_unicode_error_prints_its_class_never_its_other_args(
    chain: str, placeholder: str
) -> None:
    # Round 4 rebuilt it from repr() of its .args, so text its own __str__ kept out reached the log.
    arg = _Hides("RAWSEG|PID|1||DOE^JANE", _encode_error())
    assert _record("before %s after %d", (arg, 7)).getMessage() == "before parse failed after 7"
    record = _record(f"before {placeholder} after %d", (arg, 7))
    _chain_filter(chain).filter(record)
    expected = "before [_Hides holding a codec error, not rendered] after 7"
    assert record.getMessage() == expected


class _Masked(dict[str, object]):
    """Masks one key in its own lookup, as a credential-holding mapping may."""

    def __getitem__(self, key: str) -> object:
        return "***" if key == "password" else dict.__getitem__(self, key)


@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_a_mapping_subclass_holding_a_unicode_error_still_answers_through_its_own_lookup(
    chain: str,
) -> None:
    # Round 4 rebuilt it from the raw dict storage, so the masked value printed in the clear.
    err = _encode_error()
    arg = _Masked(password="hunter2-RAW", e=err)
    record = _record("%(password)s %(e)s", arg)
    _chain_filter(chain).filter(record)
    assert record.getMessage() == f"*** {redaction.safe_exc(err)}"


class _MaskedOrdered(collections.OrderedDict[str, object]):
    """Masks one key in its own lookup. On 3.14 an OrderedDict subclass's repr reads through it."""

    def __getitem__(self, key: str) -> object:
        return "***" if key == "hidden" else super().__getitem__(key)


@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_an_ordered_dict_subclass_holding_a_unicode_error_prints_through_its_own_lookup(
    chain: str,
) -> None:
    # The rebuild printed it from raw storage, so the masked value reached the log.
    err = _encode_error()
    arg = _MaskedOrdered(hidden="planted-hidden-3185", e=err)
    plain = _MaskedOrdered(hidden="planted-hidden-3185")
    assert (
        "planted-hidden-3185" not in _record("%s %s", (plain, 1)).getMessage()
    )  # what main prints
    record = _record("%s %s", (arg, 1))
    _chain_filter(chain).filter(record)
    text = record.getMessage()
    assert "planted-hidden-3185" not in text
    assert "'hidden': '***'" in text
    _assert_encode_safe(text)


class _KeysHidden(collections.OrderedDict[str, object]):
    """Lists one key only. On 3.14 an OrderedDict subclass's repr reads its own keys()."""

    def keys(self) -> Any:
        return [key for key in collections.OrderedDict.keys(self) if key != "hidden"]


@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_an_ordered_dict_subclass_that_hides_a_key_from_its_own_keys_still_hides_it(
    chain: str,
) -> None:
    # The rebuild printed it from raw storage, past the subclass's own keys().
    plain = _KeysHidden(hidden="planted-hidden-3185", e="stand-in")
    assert "planted-hidden-3185" not in _record("%s %s", (plain, 1)).getMessage()  # main
    record = _record("%s %s", (_KeysHidden(hidden="planted-hidden-3185", e=_encode_error()), 1))
    _chain_filter(chain).filter(record)
    text = record.getMessage()
    assert "planted-hidden-3185" not in text
    _assert_encode_safe(text)


def _recursive_list() -> list[object]:
    loop: list[object] = [1, "two"]
    loop.append(loop)
    return loop


def _recursive_dict() -> dict[str, object]:
    loop: dict[str, object] = {"a": 1}
    loop["self"] = loop
    return loop


def _clean_groups(levels: int) -> Exception:
    group: Exception = ValueError("clean")
    for n in range(levels):
        group = ExceptionGroup(f"level {n}", [group])
    return group


_POINT = collections.namedtuple("_POINT", "x y")


class _NoData(collections.UserDict[str, object]):
    """Never sets .data, and prints without it."""

    def __init__(self) -> None:
        pass

    def __len__(self) -> int:
        return 0  # so LogRecord keeps it as an argument rather than reading it as the mapping

    def __repr__(self) -> str:
        return "_NoData()"


#: Arguments holding no UnicodeError. Each must reach the formatter as the same object.
_CLEAN_ARGS = [
    _NoData(),
    _recursive_list(),
    _recursive_dict(),
    _nested("leaf", 9),
    _nested({"k": ("v", 1)}, 12),
    {"a": _nested([1, 2], 8)},
    _clean_groups(4),
    _POINT(1, [2]),
    collections.deque([_nested(3, 7)], maxlen=4),
    collections.OrderedDict(a=_recursive_list()),
]
_CLEAN_IDS = [
    "userdict-that-cannot-be-read",
    "recursive-list",
    "recursive-dict",
    "nine-deep",
    "twelve-deep-dict",
    "deep-dict-value",
    "clean-group-4",
    "namedtuple",
    "deque",
    "ordereddict",
]


@pytest.mark.parametrize("arg", _CLEAN_ARGS, ids=_CLEAN_IDS)
@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_an_argument_holding_no_unicode_error_prints_exactly_as_with_no_filter(
    arg: object, chain: str
) -> None:
    # Round 4 rewrote an error-free recursive list as a cycle note, and anything past five levels
    # as the too-deep note.
    for placeholder in ("%s", "%r"):
        unfiltered = _record(f"got {placeholder} end", (arg,)).getMessage()
        bare = _record(f"got {placeholder} end", (arg,))
        args = bare.args  # LogRecord unwraps a lone mapping into the args itself
        prepare_log_record(bare)
        assert bare.args is args  # the same object, untouched
        record = _record(f"got {placeholder} end", (arg,))
        _chain_filter(chain).filter(record)
        assert record.getMessage() == unfiltered


def test_a_single_mapping_holding_no_unicode_error_is_the_same_object() -> None:
    arg = {"deep": _nested("x", 9), "loop": _recursive_list()}
    record = _record("%(deep)s %(loop)r", arg)
    prepare_log_record(record)
    assert record.args is arg


class _Set(set[object]):
    pass


class _ReversedDeque(collections.deque[object]):
    """The stdlib's deque repr lists a deque through its own __iter__, so this prints reversed."""

    def __iter__(self) -> Iterator[object]:
        return reversed(list(collections.deque.__iter__(self)))


def _cycle_through_namedtuple(err: UnicodeEncodeError) -> object:
    loop: list[object] = [err]
    point = _POINT(loop, 1)
    loop.append(point)
    return point


def _cycle_through_ordered_data(err: UnicodeEncodeError) -> object:
    data: collections.OrderedDict[str, object] = collections.OrderedDict(e=err)
    holder: collections.UserDict[str, object] = collections.UserDict()
    holder.data = data
    data["me"] = holder
    return holder


class _Abstract(abc.ABC):  # noqa: B024 - a class with a metaclass, used only as a factory
    pass


class _Prefixed(list[object]):
    def __repr__(self) -> str:
        return "P" + list.__repr__(self)


def test_a_cycle_through_a_container_with_its_own_repr_prints_a_note_not_a_blowup() -> None:
    # Printing such a container again at each back edge, as the stdlib may, grew as the fifth
    # power of its width before the depth cutoff stopped it.
    err = _encode_error()
    wide = _Prefixed([err])
    wide.extend([wide] * 20)
    for arg in (wide, _cycle_through_namedtuple(err)):
        record = _record("%s", (arg,))
        prepare_log_record(record)
        out = record.getMessage()
        assert "caf" not in out and len(out) < 2000
        assert "[a cycle back to a container that holds a codec error]" in out


def test_a_mapping_value_changed_after_the_filter_is_scanned_when_it_is_formatted() -> None:
    # A handler may format late. The lookup scans what it finds then, not what the filter saw.
    inner: list[object] = [1]
    record = _record("%(a)s", {"a": inner, "b": _encode_error()})
    prepare_log_record(record)
    inner.append(_encode_error())
    out = record.getMessage()
    _assert_encode_safe(out)
    assert "caf" not in out


class _Labelled(dict[str, object]):
    def __repr__(self) -> str:
        return f"_Labelled{dict.__repr__(self)}"


def _cycle_list(err: UnicodeEncodeError) -> list[object]:
    loop: list[object] = [err]
    loop.append(loop)
    return loop


def _cycle_mapping(kind: Any, err: UnicodeEncodeError) -> object:
    loop = kind()
    loop["e"] = err
    loop["self"] = loop
    return loop


def _holders(err: UnicodeEncodeError) -> list[object]:
    clean_loop = _recursive_list()
    return [
        _cycle_list(err),
        _cycle_mapping(dict, err),
        _cycle_mapping(collections.OrderedDict, err),
        _cycle_mapping(lambda: collections.defaultdict(None), err),
        _ReversedDeque([1, err, 2]),
        _cycle_through_ordered_data(err),
        collections.defaultdict[str, object](_Abstract, k=err),
        collections.Counter({err: 1, "ok": 3}),
        _Labelled(e=err, n=1),
        [err, clean_loop],
        (err,),
        {"e": err, "deep": _nested(1, 8)},
        collections.OrderedDict(z=err, a=1),
        collections.defaultdict[str, object](list, e=err),
        collections.deque([err, "x"], maxlen=5),
        {err, "a", "b", "c"},
        frozenset({err, 7}),
        _Set({err, 9}),
        _POINT(err, [1, clean_loop]),
        collections.UserDict(e=err, n=1),
        {"e": err}.items(),
        collections.OrderedDict(e=err).values(),
        [[{"k": (err, 1)}, _nested(0, 7)]],
    ]


_HOLDER_IDS = [
    "cyclic-list",
    "cyclic-dict",
    "cyclic-ordereddict",
    "cyclic-defaultdict",
    "deque-printed-through-its-iter",
    "userdict-cycle-through-ordered-data",
    "defaultdict-with-an-abc-factory",
    "counter",
    "dict-subclass-with-its-own-repr",
    "list-beside-a-clean-cycle",
    "tuple",
    "dict-beside-a-deep-list",
    "ordereddict",
    "defaultdict",
    "deque",
    "set",
    "frozenset",
    "set-subclass",
    "namedtuple",
    "userdict",
    "dict-items",
    "odict-values",
    "nested",
]


@pytest.mark.parametrize("index", range(len(_HOLDER_IDS)), ids=_HOLDER_IDS)
def test_a_container_holding_a_unicode_error_prints_as_it_would_but_for_the_error(
    index: int,
) -> None:
    # Each rebuilt level prints its other elements as the container itself would: its own type
    # name, its order, a clean cycle's [...] and a deep sibling's depth.
    err = _encode_error()
    arg = _holders(err)[index]
    expected = repr(arg).replace(repr(err), repr(redaction.safe_exc(err)))
    assert expected != repr(arg)  # control: the error is in the raw rendering
    for placeholder in ("%s", "%r"):
        record = _record(f"{placeholder}", (arg,))
        prepare_log_record(record)
        assert record.getMessage() == expected


def test_a_shared_container_prints_whole_where_it_is_met_shallower() -> None:
    # The first meeting is at the cutoff, where its error becomes the too-deep note. The second,
    # three levels up, must not reuse that.
    err = _encode_error()
    shared: list[object] = [[err]]
    record = _record("%s", ([_nested(shared, 3), shared],))
    prepare_log_record(record)
    out = record.getMessage()
    assert out.endswith(f", [[{redaction.safe_exc(err)!r}]]]")
    assert "caf" not in out


def test_a_unicode_error_given_as_the_args_themselves_renders_safely() -> None:
    record = logging.makeLogRecord({"msg": "%s", "args": _encode_error()})
    prepare_log_record(record)
    _assert_encode_safe(record.getMessage())


def test_a_mapping_argument_holding_a_unicode_error_is_still_a_safe_mapping() -> None:
    # A later handler may read the args as the mapping the stdlib documents.
    err = _encode_error()
    record = _record("%(e)s", {"e": err, "n": 1})
    prepare_log_record(record)
    args = record.args
    assert isinstance(args, collections.abc.Mapping)
    assert args.get("n") == 1
    _assert_encode_safe(str(args.get("e")))
    _assert_encode_safe(repr(list(args.items())))
    _assert_encode_safe(record.getMessage())


class _Drain(collections.deque[object]):
    """Its own iteration empties it, so a filter that read it that way would change it."""

    def __iter__(self) -> Iterator[object]:
        while self:
            yield self.popleft()


def test_a_deque_whose_iteration_consumes_it_is_not_consumed_by_the_filter() -> None:
    arg = _Drain([1, 2])
    expected = _record("%s %s", (_Drain([1, 2]), 0)).getMessage()
    record = _record("%s %s", (arg, 0))
    TrayLogScrubFilter().filter(record)
    assert record.getMessage() == expected


def test_a_namedtuple_given_as_the_args_formats_field_by_field() -> None:
    record = _record("%s %s", _POINT(_encode_error(), 2))
    prepare_log_record(record)
    assert type(record.args) is _POINT  # the same type, so a later handler can still read .y
    RedactionFilter().filter(record)
    out = record.getMessage()
    _assert_encode_safe(out)
    assert out.endswith(" 2")


def test_a_struct_sequence_given_as_the_args_never_raises() -> None:
    # tuple.__new__ refuses a structseq type, so a rebuild must not try to keep it.
    import time

    args = time.struct_time((_encode_error(), 2, 3, 4, 5, 6, 7, 8, 9))
    record = _record("%s " * 9, args)
    prepare_log_record(record)
    out = record.getMessage()
    _assert_encode_safe(out)
    assert out.endswith(" 2 3 4 5 6 7 8 9 ")


class _Falsy(tuple[object, ...]):
    """A stateless tuple subclass whose own truthiness tells getMessage() not to apply %."""

    __slots__ = ()

    def __bool__(self) -> bool:
        return False


def test_a_stateless_tuple_subclass_given_as_the_args_keeps_its_own_truthiness() -> None:
    unfiltered = _record("t %s", _Falsy((_encode_error(),))).getMessage()
    record = _record("t %s", _Falsy((_encode_error(),)))
    prepare_log_record(record)
    assert record.getMessage() == unfiltered == "t %s"


class _LoudMeta(type):
    held: object = None

    def __repr__(cls) -> str:
        return f"<factory {cls.held!r}>"


class _AgreeableMetaMeta(type):
    """Its classes claim to equal anything, so only an identity test tells them from ``type``."""

    def __eq__(cls, other: object) -> bool:
        return True

    __hash__ = type.__hash__


class _AgreeableLoudMeta(_LoudMeta, metaclass=_AgreeableMetaMeta):
    pass


@pytest.mark.parametrize("meta", [_LoudMeta, _AgreeableLoudMeta], ids=["loud", "claims-equality"])
def test_a_factory_whose_metaclass_prints_what_it_holds_is_not_printed(meta: type[Any]) -> None:
    err = _encode_error()
    factory = meta("_Loud", (), {})
    factory.held = err
    record = _record("%s", (collections.defaultdict[str, object](factory, k=err),))
    prepare_log_record(record)
    out = record.getMessage()
    assert "caf" not in out
    assert "[a default factory, not rendered]" in out


def test_a_default_factory_that_could_print_data_is_not_printed() -> None:
    err = _encode_error()
    factory: Any = functools.partial(list, [err])
    record = _record("%s %s", (collections.defaultdict(factory, k=err), 0))
    prepare_log_record(record)
    out = record.getMessage()
    assert "caf" not in out
    assert out.startswith("defaultdict([a default factory, not rendered], {'k': ")
    clean = collections.defaultdict(factory, k=1)  # no error: untouched, factory and all
    record = _record("%s", (clean,))
    prepare_log_record(record)
    assert record.getMessage() == str(clean)


# --- path 3: an error rendered into another error's message -----------------------------------------


def test_the_sandbox_codec_names_a_malformed_frame_without_the_byte() -> None:
    header = b"ok" + _BYTE
    with pytest.raises(SandboxCodecError) as caught:
        decode_frame(struct.pack(">I", len(header)) + header)
    assert str(caught.value).startswith("malformed sandbox frame: UnicodeDecodeError: ")
    _assert_decode_safe(str(caught.value))


def test_a_sandboxed_handler_raising_a_unicode_error_reports_it_safely(
    sandbox_run_one: Any,  # noqa: F811 - the fixture imported above
) -> None:
    # mode=subprocess reported f"{type(exc).__name__}: {exc}" across the process boundary.
    kind, error = _sandbox_kind(sandbox_run_one, _encode_error())
    assert kind == "error"
    _assert_encode_safe(error)
    kind, error = _sandbox_kind(sandbox_run_one, ValueError("plain"))
    assert error == "ValueError: plain"  # any other error keeps its old text


def test_a_sandbox_bootstrap_unicode_failure_is_reported_without_the_character(
    monkeypatch: pytest.MonkeyPatch,
    sandbox_run_one: Any,  # noqa: F811 - imports the worker without keeping its root handler
) -> None:
    # The bootstrap arm sent the same f"{type(exc).__name__}: {exc}" its sibling arm used to.
    import messagefoundry.config.wiring as wiring
    from messagefoundry.pipeline import _sandbox_codec as codec
    from messagefoundry.pipeline import _sandbox_worker, sandbox

    stdin, stdout = io.BytesIO(), io.BytesIO()
    boot = codec.encode_boot(config_dir=".", forbidden=(), mem_mb=None, code_sets=None)
    sandbox._write_frame(stdin, boot)
    stdin.seek(0)

    def unreadable(config_dir: object) -> object:
        raise _encode_error()

    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(buffer=stdin))
    monkeypatch.setattr(sys, "stdout", types.SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(_sandbox_worker, "_redirect_stdout_to_stderr", lambda: None)
    monkeypatch.setattr(wiring, "load_config", unreadable)
    # Should main() stop reaching the patched load, these must still not touch the test process.
    monkeypatch.setattr(_sandbox_worker, "_apply_resource_caps", lambda mem_mb: None)
    monkeypatch.setattr(_sandbox_worker, "_install_import_guard", lambda forbidden: None)
    assert _sandbox_worker.main() == 1
    stdout.seek(0)
    reply = sandbox._read_frame_bytes(stdout)
    assert reply is not None
    graph, why = codec.decode_boot_reply(reply)
    assert graph is None
    _assert_encode_safe(why)


def test_a_send_whose_message_cannot_encode_is_refused_without_the_character() -> None:
    class _Unencodable:
        def encode(self) -> str:
            f"caf{_CHAR}".encode("ascii")
            return ""

    with pytest.raises(SandboxCodecError) as caught:
        enc_result("transform", Send("OB_A", _Unencodable()), _Blobs())  # type: ignore[arg-type]
    assert str(caught.value).startswith("Send message is not encodable: UnicodeEncodeError: ")
    _assert_encode_safe(str(caught.value))


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
#: Attributes that hold the input or a free-text reason, or render it. ``.start``, ``.end`` and
#: ``.encoding`` are positions and the caller's codec name, and stay allowed.
_RAW_ATTRS = frozenset({"object", "args", "reason", "__str__", "__repr__"})
#: Calls that render the exception being handled without being handed it.
_CURRENT_RENDERS = frozenset({"format_exc", "print_exc"})
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


def _renders_the_handled_error(node: ast.Call) -> bool:
    """``format_exc()``, ``print_exc()``, or ``sys.exc_info()``/``sys.exception()`` handed on: each
    reaches the error being handled with no name bound to it."""
    if callee_name(node) in _CURRENT_RENDERS:
        return True
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr in {"exc_info", "exception"}
        and isinstance(func.value, ast.Name)
        and func.value.id == "sys"
    )


def _raw_renders(handler: ast.ExceptHandler) -> Iterator[tuple[int, str]]:
    name = handler.name
    nodes = [n for stmt in handler.body for n in ast.walk(stmt)]
    # exc_info=sys.exc_info() is path 1, which the log filter chain renders safely.
    exempt = {id(n.value) for n in nodes if isinstance(n, ast.keyword) and n.arg == "exc_info"}
    for node in nodes:
        if isinstance(node, ast.Call) and id(node) in exempt:
            continue
        if isinstance(node, ast.Call) and _renders_the_handled_error(node):
            yield node.lineno, "the handled error reached without its name"
        elif name is None:
            continue  # an unnamed arm can reach the error only through the calls above
        elif isinstance(node, ast.FormattedValue) and _is_raw(node.value, name):
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
        elif isinstance(node, ast.Attribute) and _is_raw(node, name):
            # Any read: idna and punycode put the label in .reason, so concatenation leaks it too.
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
        if isinstance(node, ast.ExceptHandler) and _handler_names(node.type) & _UNICODE_TYPES:
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
def k(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        text = traceback.format_exc()
def n(b):
    try:
        b.decode()
    except UnicodeDecodeError:
        traceback.print_exc()
def o(b):
    try:
        b.decode()
    except UnicodeDecodeError:
        text = "".join(traceback.format_exception(*sys.exc_info()))
def m(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        text = exc.__str__()
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
def b3(b):
    try:
        b.decode()
    except UnicodeDecodeError:
        log.warning("unreadable", exc_info=sys.exc_info())
def c(b):
    try:
        b.decode()
    except ValueError as exc:  # not a Unicode handler: out of this scan's scope, by design
        raise RuntimeError(f"{exc}")
"""


def test_the_guard_fires_on_every_planted_shape() -> None:
    handlers, found = _scan_source(_PLANTED, "planted.py")
    assert handlers == 13
    kinds = [line.split(": ", 1)[1] for line in found]
    assert kinds == [
        "f-string interpolation",
        "log argument",
        "f-string interpolation",
        ".reason read",  # d: the same interpolation, also reported as a raw attribute read
        "% formatting",
        "passed into RuntimeError()",
        "aliased out of the handler",  # g: the assignment and the read are both reported
        ".object read",
        "format() of the error",
        "aliased out of the handler",
        "format_exception() of the error",
        "the handled error reached without its name",  # k: format_exc()
        "the handled error reached without its name",  # n: print_exc(), in an unnamed arm
        "the handled error reached without its name",  # o: sys.exc_info()
        ".__str__ read",
    ], found


def test_the_guard_passes_the_safe_shapes() -> None:
    assert _scan_source(_CLEAN, "clean.py") == (3, [])
