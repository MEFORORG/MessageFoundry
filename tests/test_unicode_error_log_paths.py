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
import codecs
import collections
import collections.abc
import configparser
import dataclasses
import functools
import gc
import io
import itertools
import logging
import random
import struct
import sys
import traceback
import types
import weakref
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import redaction
from messagefoundry.auth import trust_anchors
from messagefoundry.config.code_sets import CodeSetError, load_code_set
from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.snapshot import ConfigSnapshot
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
    boot = codec.encode_boot(
        snapshot=ConfigSnapshot(directory=Path("."), files={}),
        forbidden=(),
        mem_mb=None,
        code_sets=None,
    )
    sandbox._write_frame(stdin, boot)
    stdin.seek(0)

    def unreadable(snapshot: object, **_kw: object) -> object:
        raise _encode_error()

    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(buffer=stdin))
    monkeypatch.setattr(sys, "stdout", types.SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(_sandbox_worker, "_redirect_stdout_to_stderr", lambda: None)
    monkeypatch.setattr(wiring, "load_snapshot", unreadable)
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


# --- residuals engine PR 2150 shipped open (vault BACKLOG #3295) -------------------------------------

_HOLDER = "[holding a codec error, not rendered]"


def _raised(exc: BaseException) -> BaseException:
    try:
        raise exc
    except BaseException as caught:  # noqa: BLE001 - the raised object, with its traceback
        return caught


def _wrappers() -> list[BaseException]:
    err = _encode_error()
    return [
        RuntimeError(err),  # str() is str(err): one character
        ValueError("bad frame", err),  # str() is repr(args): the whole input
        OSError(2, "cannot open", err),  # the error is .filename, which str() prints by repr
        OSError(2, "cannot move", "a.hl7", None, err),  # .filename2
        KeyError(err),
    ]


_WRAPPER_IDS = ["one-arg", "two-args", "os-filename", "os-filename2", "key-error"]


def test_a_wrapper_built_from_a_unicode_error_carries_the_planted_value() -> None:
    # The premise of the wrapper tests below: each wrapper's own str() does print the character.
    for wrapper in _wrappers():
        assert any(spelling in str(wrapper) for spelling in _CHAR_SPELLINGS), wrapper


@pytest.mark.parametrize("index", range(len(_WRAPPER_IDS)), ids=_WRAPPER_IDS)
@pytest.mark.parametrize("fmt", ["text", "json"])
def test_a_wrapper_built_from_a_unicode_error_prints_a_note_in_a_traceback(
    fmt: str, index: int
) -> None:
    wrapper = _raised(_wrappers()[index])
    log, stream = _capture(fmt)
    log.error("failed", exc_info=wrapper)
    out = stream.getvalue()
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out, (spelling, out)
    assert f"{type(wrapper).__name__}: {_HOLDER}" in out
    assert "_raised" in out  # the frames are still printed


def test_a_wrapper_raised_from_its_unicode_error_prints_both_lines_safely() -> None:
    err = _encode_error()
    wrapper = RuntimeError(err)
    wrapper.__cause__ = err
    out = safe_traceback((RuntimeError, _raised(wrapper), None))
    _assert_encode_safe(out)
    assert f"RuntimeError: {_HOLDER}" in out


def test_the_tray_chain_prints_a_wrapper_traceback_as_a_note() -> None:
    record = _record("poll failed", ())
    record.exc_info = (RuntimeError, RuntimeError(_encode_error()), None)
    assert TrayLogScrubFilter().filter(record)
    text = record.exc_text or ""
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in text
    assert f"RuntimeError: {_HOLDER}" in text


@pytest.mark.parametrize("index", range(len(_WRAPPER_IDS)), ids=_WRAPPER_IDS)
def test_safe_exc_prints_a_wrapper_built_from_a_unicode_error_as_a_note(index: int) -> None:
    wrapper = _wrappers()[index]
    assert redaction.safe_exc(wrapper) == f"{type(wrapper).__name__}: {_HOLDER}"
    # The mixed-arm helper too: a ValueError arm receives a wrapper as readily as the error.
    assert codec_safe_str(wrapper) == _HOLDER
    assert redaction.codec_safe_line(wrapper) == f"{type(wrapper).__name__}: {_HOLDER}"


def test_the_mixed_arm_helpers_keep_any_other_error_whole_and_name_the_class_once() -> None:
    assert codec_safe_str(ValueError("plain", 3)) == "('plain', 3)"
    assert redaction.codec_safe_line(ValueError("plain", 3)) == "ValueError: ('plain', 3)"
    line = redaction.codec_safe_line(_decode_error())
    assert line.count("UnicodeDecodeError") == 1
    _assert_decode_safe(line)


def test_a_traceback_or_safe_exc_with_no_unicode_error_is_unchanged() -> None:
    # The negative control: nothing else is rewritten, and a group still prints its own line.
    plain = _raised(ValueError("plain", 3))
    ei = (ValueError, plain, plain.__traceback__)
    assert safe_traceback(ei) == logging.Formatter().formatException(ei)
    assert redaction.safe_exc(plain) == "ValueError: ('plain', 3)"
    assert redaction.safe_exc(OSError(2, "gone", "a.hl7")).startswith(
        "FileNotFoundError: [Errno 2]"
    )
    group = ExceptionGroup("batch failed", [_encode_error()])
    assert redaction.safe_exc(group) == "ExceptionGroup: batch failed (1 sub-exception)"
    out = safe_traceback((ExceptionGroup, group, None))
    assert "ExceptionGroup: batch failed (1 sub-exception)" in out
    _assert_encode_safe(out)


def test_a_group_subclass_that_prints_its_members_is_a_note_in_a_traceback() -> None:
    group = _LoudGroup("batch failed", [_encode_error()])
    assert any(spelling in str(group) for spelling in _CHAR_SPELLINGS)
    out = safe_traceback((type(group), group, None))
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out
    assert f"_LoudGroup: {_HOLDER}" in out


@pytest.mark.parametrize("index", range(len(_WRAPPER_IDS)), ids=_WRAPPER_IDS)
@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_a_wrapper_given_as_a_log_argument_prints_its_class_and_a_note(
    chain: str, index: int
) -> None:
    wrapper = _wrappers()[index]
    for placeholder in ("%s", "%r"):
        record = _record(f"got {placeholder} end", (wrapper,))
        _chain_filter(chain).filter(record)
        name = type(wrapper).__name__
        assert record.getMessage() == f"got [{name} holding a codec error, not rendered] end"


def test_a_sandboxed_handler_raising_a_wrapper_reports_a_note(
    sandbox_run_one: Any,  # noqa: F811 - the fixture imported above
) -> None:
    # The worker printed f"{type(exc).__name__}: {exc}" for anything but the error itself, and a
    # two-argument wrapper prints its args tuple, so the whole input crossed the process boundary.
    kind, error = _sandbox_kind(sandbox_run_one, ValueError("bad frame", _encode_error()))
    assert (kind, error) == ("error", f"ValueError: {_HOLDER}")
    kind, error = _sandbox_kind(sandbox_run_one, RuntimeError(_encode_error()))
    assert (kind, error) == ("error", f"RuntimeError: {_HOLDER}")
    kind, error = _sandbox_kind(sandbox_run_one, ValueError("plain", 3))
    assert error == "ValueError: ('plain', 3)"  # any other error keeps its own text


@dataclasses.dataclass
class _Outcome:
    name: str
    error: object = None


@dataclasses.dataclass(frozen=True, slots=True)
class _SlottedOutcome:
    name: str
    error: object = None


@dataclasses.dataclass
class _QuietOutcome:
    name: str
    error: object = dataclasses.field(default=None, repr=False)


def _attribute_holders(err: UnicodeEncodeError) -> list[tuple[object, str]]:
    """Objects that print what their attributes hold, each with the class name its note carries."""
    return [
        (_Outcome("a", err), "_Outcome"),
        (_Outcome("a", [("deep", err)]), "_Outcome"),
        (_SlottedOutcome("a", err), "_SlottedOutcome"),
        (types.SimpleNamespace(name="a", error=err), "SimpleNamespace"),
        (collections.ChainMap[str, object]({"name": "a"}, {"error": err}), "ChainMap"),
        (collections.UserDict(error=err).items(), "ItemsView"),
        (collections.UserDict(error=err).keys(), "KeysView"),
        (collections.UserDict(error=err).values(), "ValuesView"),
    ]


_ATTRIBUTE_IDS = [
    "dataclass",
    "dataclass-nested",
    "dataclass-slots",
    "namespace",
    "chainmap",
    "userdict-items",
    "userdict-keys",
    "userdict-values",
]


def test_an_object_that_prints_its_attributes_carries_the_planted_value() -> None:
    # The premise: with no filter, each of these prints the error's repr, the whole input.
    for holder, _name in _attribute_holders(_encode_error()):
        assert f"caf{_CHAR}" in repr(holder), holder


@pytest.mark.parametrize("index", range(len(_ATTRIBUTE_IDS)), ids=_ATTRIBUTE_IDS)
@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_an_object_holding_a_unicode_error_in_an_attribute_prints_its_class_and_a_note(
    chain: str, index: int
) -> None:
    holder, name = _attribute_holders(_encode_error())[index]
    note = f"[{name} holding a codec error, not rendered]"
    for placeholder in ("%s", "%r"):
        record = _record(f"got {placeholder} end", (holder,))
        _chain_filter(chain).filter(record)
        assert record.getMessage() == f"got {note} end"
        inside = _record(f"got {placeholder} end", ([1, holder],))
        _chain_filter(chain).filter(inside)
        assert inside.getMessage() == f"got [1, {note}] end"


@dataclasses.dataclass
class _FieldError(Exception):
    cause: object = None


@dataclasses.dataclass
class _FieldDict(dict[str, object]):
    cause: object = None


class _AttributeError(Exception):
    """Keeps the error on an attribute and prints it from its own ``__str__``."""

    def __init__(self, cause: object) -> None:
        super().__init__("bad frame")
        self.cause = cause

    def __str__(self) -> str:
        return f"bad frame: {self.cause}"


def _strerror_holder() -> OSError:
    error = OSError(2, "cannot open")
    error.strerror = _encode_error()  # type: ignore[assignment]
    return error


@pytest.mark.parametrize(
    "make",
    [
        lambda: _FieldError(cause=_encode_error()),
        lambda: _AttributeError(_encode_error()),
        _strerror_holder,
    ],
    ids=["dataclass-exception", "attribute-printed-by-str", "os-strerror"],
)
def test_an_exception_holding_a_unicode_error_outside_its_args_is_a_note(make: Any) -> None:
    error = make()
    assert any(s in f"{error} {error!r}" for s in _CHAR_SPELLINGS)  # control: raw with no filter
    name = type(error).__name__
    assert redaction.safe_exc(error) == f"{name}: {_HOLDER}"
    assert codec_safe_str(error) == _HOLDER
    out = safe_traceback((type(error), error, None))
    assert out.endswith(f"{name}: {_HOLDER}")
    record = _record("got %s and %r", (error, error))
    prepare_log_record(record)
    note = f"[{name} holding a codec error, not rendered]"
    assert record.getMessage() == f"got {note} and {note}"


def test_an_exception_with_clean_attributes_keeps_its_own_message() -> None:
    error = _AttributeError("plain")
    assert redaction.safe_exc(error) == "_AttributeError: bad frame: plain"
    record = _record("got %s", (error,))
    args = record.args
    prepare_log_record(record)
    assert record.args is args


def test_a_dataclass_that_is_a_dict_is_read_by_field_too() -> None:
    held = _FieldDict(cause=_encode_error())
    held["k"] = 1
    assert "caf" in repr(held)  # control
    record = _record("got %r", ([held],))
    prepare_log_record(record)
    assert record.getMessage() == "got [[_FieldDict holding a codec error, not rendered]]"
    record = _record("%(k)s", (held,))  # as the single mapping: its own lookup still answers
    prepare_log_record(record)
    assert record.getMessage() == "1"


@dataclasses.dataclass
class _MappingContext(collections.abc.Mapping[str, object]):
    stored: dict[str, object]

    def __getitem__(self, key: str) -> object:
        return self.stored[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.stored)

    def __len__(self) -> int:
        return len(self.stored)


def test_a_dataclass_mapping_given_as_the_single_mapping_still_formats_by_key() -> None:
    # A bare note in its place is not a mapping, and "%(key)s" would raise from the log call. So
    # it is wrapped as a dict root is: each key asks its own lookup, and "%s" prints the note.
    held = _MappingContext({"a": 1, "e": _encode_error()})
    assert "\\xe9" in _record("%(e)s", (held,)).getMessage()  # control: raw with no filter
    record = _record("%(a)s | %(e)s", (held,))
    prepare_log_record(record)
    assert record.getMessage().startswith("1 | UnicodeEncodeError: 'ascii' codec cannot encode")
    whole = _record("ctx: %s", (held,))
    prepare_log_record(whole)
    assert whole.getMessage() == "ctx: [_MappingContext holding a codec error, not rendered]"
    clean = _MappingContext({"a": 1})
    record = _record("%(a)s", (clean,))
    prepare_log_record(record)
    assert record.args is clean
    inside = _record("got %s end %d", (held, 1))  # as one argument of several it is a note
    prepare_log_record(inside)
    assert inside.getMessage() == "got [_MappingContext holding a codec error, not rendered] end 1"


class _SlotError(Exception):
    __slots__ = ("orig",)

    def __init__(self, orig: object) -> None:
        super().__init__("slot")
        self.orig = orig

    def __str__(self) -> str:
        return f"slot {self.orig}"


def test_a_slot_or_a_syntax_error_holding_a_unicode_error_is_a_note() -> None:
    slotted = _SlotError(_encode_error())
    assert "\\xe9" in str(slotted)  # control
    assert redaction.safe_exc(slotted) == f"_SlotError: {_HOLDER}"
    syntax = SyntaxError(_encode_error())
    assert "\\xe9" in logging.Formatter().formatException((SyntaxError, syntax, None))  # control
    assert redaction.safe_exc(syntax) == f"SyntaxError: {_HOLDER}"
    out = safe_traceback((SyntaxError, syntax, None))
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out
    assert f"SyntaxError: {_HOLDER}" in out
    text: Any = _encode_error()  # .text is the source line; here it is the error itself
    located = SyntaxError("bad token", ("feed.py", 3, 1, text))
    out = safe_traceback((SyntaxError, located, None))
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out
    plain = SyntaxError("bad token", ("feed.py", 3, 1, "x = (\n"))
    ei = (SyntaxError, plain, None)
    assert safe_traceback(ei) == logging.Formatter().formatException(ei)  # a clean one is unchanged


def test_plain_exceptions_do_not_spend_the_attribute_budget() -> None:
    # A builtin exception prints .args alone, so it is not read by attribute and costs nothing.
    # The holder is LAST, which the walk reads last: with the crowd charged it was never reached.
    crowd: list[object] = [RuntimeError(i) for i in range(redaction._ATTRIBUTE_BUDGET + 50)]
    crowd.append(_Outcome("a", _encode_error()))
    record = _record("got %d: %s", (len(crowd), crowd))
    prepare_log_record(record)
    text = record.getMessage()
    assert "[_Outcome holding a codec error, not rendered]" in text
    assert "caf" not in text


def test_a_large_payload_on_an_exception_is_bounded_and_never_raises() -> None:
    # safe_exc runs where errors are stored, so everything under the exception is charged.
    error = _AttributeError("plain")
    error.payload = [[i] for i in range(50_000)] + [_encode_error()]  # type: ignore[attr-defined]
    scan = redaction._Scan(error, charged_root=True)
    assert len(scan.nodes) <= redaction._ATTRIBUTE_BUDGET + 2
    # Past the budget: as with no scan. A stated limit, pinned here.
    assert redaction.safe_exc(error) == "_AttributeError: bad frame: plain"
    wide = [[i] for i in range(50_000)] + [[_encode_error()]]
    record = _record("got %s", (wide,))  # a builtin container's own elements are not charged
    prepare_log_record(record)
    assert "caf" not in record.getMessage()


class _BatchError(Exception):
    """Keeps its rows in ``.args`` and on an attribute, as ``super().__init__(rows)`` does."""

    def __init__(self, rows: object) -> None:
        super().__init__(rows)
        self.rows = rows


@dataclasses.dataclass
class _Context:
    rows: object


@pytest.mark.parametrize("pad", [10, 5000])
@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_what_is_reached_both_plainly_and_by_attribute_is_scanned_without_the_budget(
    chain: str, pad: int
) -> None:
    # The verifier's leak on head 087f1de8e7: the attribute walk met the rows first, spent its
    # budget on the pad, and left the plain walk nothing to visit. Every shape here was a note,
    # or safe text, before any object was read by attribute, at any pad size.
    def held() -> _BatchError:
        return _BatchError([[_encode_error()], [()] * pad])

    note = "[_BatchError holding a codec error, not rendered]"
    for placeholder in ("%s", "%r"):
        record = _record(f"failed: {placeholder}", (held(),))
        _chain_filter(chain).filter(record)
        assert record.getMessage() == f"failed: {note}"
    record = _record("failed: %s", ([held()],))
    _chain_filter(chain).filter(record)
    assert record.getMessage() == f"failed: [{note}]"
    record = _record("failed: %(a)s", ({"a": held()},))
    _chain_filter(chain).filter(record)
    assert record.getMessage() == f"failed: {note}"
    as_message = logging.LogRecord("t", logging.WARNING, __file__, 1, held(), (), None)
    _chain_filter(chain).filter(as_message)
    assert as_message.getMessage() == note


@pytest.mark.parametrize("first", ["rows", "ctx"])
def test_the_order_of_a_dict_does_not_decide_what_is_scanned(first: str) -> None:
    rows = [[_encode_error()], [()] * 5000]
    pair = {"rows": rows, "ctx": _Context(rows)}
    arg = pair if first == "rows" else dict(reversed(pair.items()))
    record = _record("%s", ([arg],))
    prepare_log_record(record)
    text = record.getMessage()
    assert "caf" not in text
    assert "UnicodeEncodeError: 'ascii' codec cannot encode at position 3" in text  # the plain rows
    assert "[_Context holding a codec error, not rendered]" in text


def test_an_exception_whose_str_is_the_builtin_one_keeps_its_own_message() -> None:
    # Only .args can print through BaseException.__str__, so an attribute is not evidence. An
    # AttributeError's .obj is set by the interpreter; reading it replaced the message with a note.
    holder = types.SimpleNamespace(error=_encode_error())
    with pytest.raises(AttributeError) as caught:
        holder.missing  # noqa: B018 - the lookup is the point
    missing = caught.value
    assert missing.obj is holder
    assert not redaction.prints_a_codec_error(missing)
    assert redaction.safe_exc(missing) == f"AttributeError: {redaction.safe_text(str(missing))}"
    ei = (AttributeError, missing, None)
    assert safe_traceback(ei) == logging.Formatter().formatException(ei)
    stored = RuntimeError("failed")
    stored.original = _encode_error()  # type: ignore[attr-defined]
    assert redaction.safe_exc(stored) == "RuntimeError: failed"
    record = _record("got %s", (stored,))
    args = record.args
    prepare_log_record(record)
    assert record.args is args


def test_an_error_read_as_the_budget_runs_out_still_counts() -> None:
    # It was seeded only when popped, and the loop had stopped by then: a large later field
    # starved an error the walk had already read.
    error = _encode_error()
    wrapper = ValueError("bad frame", error)
    wrapper.rows = [0] * 5000  # type: ignore[attr-defined]
    assert redaction.safe_exc(wrapper) == f"ValueError: {_HOLDER}"
    for holder in (
        types.SimpleNamespace(error=error, rows=[0] * 5000),
        _Outcome("a", [error] + [0] * (redaction._ATTRIBUTE_BUDGET - 1)),
    ):
        record = _record("got %r", (holder,))
        prepare_log_record(record)
        assert "caf" not in record.getMessage()
        assert "holding a codec error, not rendered]" in record.getMessage()


class _SlotBase(Exception):
    __slots__ = ("orig",)
    orig: object

    def __str__(self) -> str:
        return f"slot {self.orig}"


@dataclasses.dataclass
class _SlotChild(_SlotBase):
    extra: int = 0


def test_a_dataclass_exception_is_read_through_its_bases_slots_too() -> None:
    child = _SlotChild()
    child.orig = _encode_error()
    assert "\\xe9" in str(child)  # control
    assert redaction.safe_exc(child) == f"_SlotChild: {_HOLDER}"


def test_a_holder_traceback_drops_its_notes_and_a_syntax_errors_line_number() -> None:
    noted = RuntimeError("failed", _encode_error())
    noted.add_note(f"row caf{_CHAR}")
    out = safe_traceback((RuntimeError, noted, None))
    assert "caf" not in out and out.endswith(f"RuntimeError: {_HOLDER}")
    line: Any = _encode_error()
    located = SyntaxError("bad token", ("feed.py", line, 1, "x"))
    out = safe_traceback((SyntaxError, located, None))
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out
    plain = RuntimeError("failed")
    plain.add_note("retry 3")
    ei = (RuntimeError, plain, None)
    assert safe_traceback(ei) == logging.Formatter().formatException(ei)  # a clean one keeps them


def test_a_bare_unicode_error_keeps_only_the_codecs_own_note() -> None:
    # Vault BACKLOG #3340 item 7 is not restored: a caller's text note can be built from the
    # failing input, so only the stdlib's codec note survives, as origin/main dropped the rest.
    try:
        codecs.decode(b"ok" + _BYTE, "utf-8")
    except UnicodeDecodeError as exc:
        error = exc
    error.add_note(f"segment caf{_CHAR!r}")
    error.add_note("while reading feed.csv")
    error.__notes__.append(_encode_error())  # type: ignore[arg-type]
    out = safe_traceback((type(error), error, None))
    _assert_decode_safe(out)
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out
    assert "feed.csv" not in out
    assert out.endswith("invalid start byte\ndecoding with 'utf-8' codec failed"), out


class _NotesRaise(UnicodeDecodeError):
    """Its ``__notes__`` raises a Unicode error, whose ``repr()`` the stdlib puts in a note."""

    @property
    def __notes__(self) -> list[str]:  # type: ignore[override]
        raise _encode_error()


def test_the_stdlibs_note_for_unreadable_notes_is_not_kept() -> None:
    # Review of vault BACKLOG #3340: "Ignored error getting __notes__: <repr>" is plain text the
    # stdlib built, and the repr of the Unicode error it names prints the whole input.
    error = _NotesRaise("utf-8", b"ok" + _BYTE, 2, 3, "invalid start byte")
    ei = (type(error), error, None)
    raw = logging.Formatter().formatException(ei)
    assert "Ignored error getting __notes__" in raw  # control: the stdlib prints it
    assert any(spelling in raw for spelling in _CHAR_SPELLINGS)
    out = safe_traceback(ei)
    assert "Ignored error getting __notes__" not in out
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


class _CollidesWithNotes:
    """A dict key with the hash of ``"__notes__"`` whose ``__eq__`` raises once armed, so a lookup
    of that name in a dict holding it raises. Unarmed, it can be inserted beside the real key."""

    armed = False

    def __hash__(self) -> int:
        return hash("__notes__")

    def __eq__(self, other: object) -> bool:
        if self.armed:
            raise RuntimeError("no compare")
        return False


def test_a_notes_lookup_that_raises_drops_the_notes_and_does_not_crash() -> None:
    # Review of vault BACKLOG #3340: _own_notes looked "__notes__" up in the instance dict outside
    # its try, so a colliding key made safe_traceback raise, and logging_setup calls it directly.
    error = UnicodeDecodeError("utf-8", b"ok" + _BYTE, 2, 3, "invalid start byte")
    key = _CollidesWithNotes()
    error.__dict__[key] = 1  # type: ignore[index]  # first, so a lookup of "__notes__" compares against it
    error.add_note("decoding with 'utf-8' codec failed")  # a note the scan would otherwise keep
    key.armed = True
    with pytest.raises(RuntimeError):  # control: the lookup itself raises
        dict.get(error.__dict__, "__notes__")
    out = safe_traceback((type(error), error, None))
    _assert_decode_safe(out)
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out
    assert "codec failed" not in out  # the notes the read could not vouch for are dropped
    assert "Ignored error getting __notes__" not in out


def test_a_kept_codec_note_names_only_a_codec_safe_exc_would_name() -> None:
    # Review of vault BACKLOG #3340: the stdlib's "decoding with '<name>' codec failed" quotes the
    # name as the caller wrote it, which _names_a_codec declines to print.
    for name, expected in (
        ("utf-8", "decoding with 'utf-8' codec failed"),
        ("UTF_8", "decoding with a codec failed"),
    ):
        try:
            codecs.decode(b"ok" + _BYTE, name)
        except UnicodeDecodeError as exc:
            error = exc
        assert error.__notes__ == [f"decoding with {name!r} codec failed"]  # control
        out = safe_traceback((type(error), error, None))
        assert out.endswith(f"invalid start byte\n{expected}"), out
        assert ("'UTF_8'" in out) is False


def _elements_read(scan: Any) -> int:
    """How many elements a scan copied out of containers and attributes: its own record of it."""
    return sum(len(elements or ()) for _arg, elements, _why in scan.nodes.values())


def test_the_work_done_beneath_an_attribute_is_bounded_whatever_the_argument_holds() -> None:
    # Counted, not timed. On head 087f1de8e7 the budget capped objects followed, and each was
    # still read whole: 400 lists of 5,000 was two million elements for one log call.
    bound = 2 * redaction._ATTRIBUTE_BUDGET + 8
    lists = types.SimpleNamespace(**{f"k{i}": list(range(i, i + 5000)) for i in range(400)})
    assert _elements_read(redaction._Scan(lists)) <= bound
    error = _AttributeError("plain")  # a __str__ of its own, so its attributes are read
    error.table = {i: str(i) for i in range(200_000)}  # type: ignore[attr-defined]
    assert 1000 < _elements_read(redaction._Scan(error)) <= bound  # read, and cut short
    assert _elements_read(redaction._Scan(error, charged_root=True)) <= bound
    wide = RuntimeError(list(range(200_000)))  # in .args, which safe_exc charges too
    assert _elements_read(redaction._Scan(wide, charged_root=True)) <= bound
    assert redaction.safe_exc(error) == "_AttributeError: bad frame: plain"
    for arg in (lists, error):  # and neither is touched: nothing in them is an error
        record = _record("got %s end %d", (arg, 1))
        args = record.args
        prepare_log_record(record)
        assert record.args is args


def test_the_attribute_walk_stops_at_its_budget_and_never_raises() -> None:
    # Past the budget an object is left as it is with no filter: a stated limit, pinned here.
    chain: object = _Outcome("leaf", _encode_error())
    for _ in range(redaction._ATTRIBUTE_BUDGET + 1):
        chain = _Outcome("n", chain)
    record = _record("got %s", (chain,))
    args = record.args
    prepare_log_record(record)
    assert record.args is args
    near: object = _Outcome("leaf", _encode_error())
    for _ in range(3):
        near = _Outcome("n", near)
    record = _record("got %s", (near,))
    prepare_log_record(record)
    assert record.getMessage() == "got [_Outcome holding a codec error, not rendered]"


def test_a_chain_map_rebuilt_as_the_single_mapping_keeps_its_keys_for_a_later_reader() -> None:
    held = collections.ChainMap[str, object]({"a": 1}, {"a": 2, "e": _encode_error()})
    record = _record("%(a)s", (held,))
    prepare_log_record(record)
    stored: Any = record.args
    assert stored is not held
    assert stored.get("a") == 1 and set(stored) == {"a", "e"}  # the first map wins, as it does
    _assert_encode_safe(str(stored.get("e")))


def test_a_dataclass_field_kept_out_of_its_repr_is_still_a_note() -> None:
    # The walk reads the instance's attributes, not the generated repr's field list, so it errs
    # toward the note. Nothing the class hid is printed.
    record = _record("got %s", (_QuietOutcome("a", _encode_error()),))
    prepare_log_record(record)
    assert record.getMessage() == "got [_QuietOutcome holding a codec error, not rendered]"


class _RaisingRepr(types.SimpleNamespace):
    def __repr__(self) -> str:
        raise RuntimeError("no repr")


_CLEAN_ATTRIBUTE_ARGS = [
    _Outcome("a", ["b", {"c": 1}]),
    _SlottedOutcome("a", ("b",)),
    types.SimpleNamespace(name="a", loop=_recursive_list()),
    collections.ChainMap[str, object]({"a": 1}, {"b": [2]}),
    collections.UserDict(a=1).items(),
    types.MappingProxyType({"a": 1}),
]
_CLEAN_ATTRIBUTE_IDS = ["dataclass", "slots", "namespace", "chainmap", "userdict-items", "proxy"]


@pytest.mark.parametrize("arg", _CLEAN_ATTRIBUTE_ARGS, ids=_CLEAN_ATTRIBUTE_IDS)
@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_an_attribute_holder_with_no_unicode_error_prints_exactly_as_with_no_filter(
    arg: object, chain: str
) -> None:
    for placeholder in ("%s", "%r"):
        unfiltered = _record(f"got {placeholder} end %d", (arg, 1)).getMessage()
        bare = _record(f"got {placeholder} end %d", (arg, 1))
        args = bare.args
        prepare_log_record(bare)
        assert bare.args is args  # the same tuple, so the same objects
        record = _record(f"got {placeholder} end %d", (arg, 1))
        _chain_filter(chain).filter(record)
        assert record.getMessage() == unfiltered


def test_an_attribute_holder_whose_own_repr_raises_still_fails_as_the_stdlib_fails() -> None:
    # The walk runs none of the object's code, so a clean one whose repr raises is not withheld
    # by prepare_log_record: the formatter meets the same error it would with no filter.
    arg = _RaisingRepr(name="a")
    record = _record("got %s", (arg,))
    args = record.args
    prepare_log_record(record)
    assert record.args is args
    with pytest.raises(RuntimeError, match="no repr"):
        record.getMessage()


class _Fallback(collections.ChainMap[str, object]):
    def __missing__(self, key: str) -> object:
        return f"<no {key}>"


@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_a_chain_map_given_as_the_single_mapping_argument_still_answers_by_key(chain: str) -> None:
    # "%(key)s" reaches the ChainMap's own lookup, as with no filter; only what it returns is walked.
    arg = collections.ChainMap[str, object]({"name": "a"}, {"count": 3})
    record = _record("%(name)s has %(count)d", (arg,))
    prepare_log_record(record)
    assert record.args is arg
    assert record.getMessage() == "a has 3"
    held = _Fallback({"name": "a"}, {"error": _encode_error(), "all": [_encode_error()]})
    assert "\\xe9" in _record("%(error)s", (held,)).getMessage()  # control: raw with no filter
    record = _record("%(name)s %(other)s | %(error)s | %(all)r", (held,))
    _chain_filter(chain).filter(record)
    text = record.getMessage()
    assert text.startswith("a <no other> | UnicodeEncodeError: 'ascii' codec cannot encode at")
    _assert_encode_safe(text)
    whole = _record("%s", (held,))  # the stdlib unwraps a lone mapping; "%s" prints it whole
    _chain_filter(chain).filter(whole)
    assert whole.getMessage() == "[_Fallback holding a codec error, not rendered]"


# --- the three gaps engine PR 2207 left (vault BACKLOG #3340, items 1 to 3) ----------------------


class _DunderSlotError(Exception):
    """Keeps the error in a slot whose name is a dunder, which Python does not mangle."""

    __slots__ = ("__payload__",)

    def __init__(self, payload: object) -> None:
        super().__init__("bad frame")
        self.__payload__ = payload

    def __str__(self) -> str:
        return f"bad frame: {self.__payload__}"


class _InnerAttributeError(Exception):
    """Prints an attribute of a plain exception it holds, which the plain one never prints."""

    def __init__(self, inner: BaseException) -> None:
        super().__init__("bad frame")
        self.inner = inner

    def __str__(self) -> str:
        return f"bad frame: {self.inner.original}"  # type: ignore[attr-defined]


class _InnerArgError(Exception):
    """The same, with the plain exception in ``.args``."""

    def __str__(self) -> str:
        return f"bad frame: {self.args[0].original}"


class _CauseError(Exception):
    """Prints its own ``__cause__``, or its ``__context__`` when it has no cause."""

    def __str__(self) -> str:
        return f"bad frame: {self.__cause__ or self.__context__}"


def _holding_inner(kind: type[BaseException]) -> BaseException:
    inner = RuntimeError("failed")
    inner.original = _encode_error()  # type: ignore[attr-defined]
    return kind(inner)


def _caused() -> BaseException:
    error = _CauseError("bad frame")
    error.__cause__ = _encode_error()
    return error


def _in_context() -> BaseException:
    try:
        try:
            raise _encode_error()
        except UnicodeEncodeError:
            raise _CauseError("bad frame") from None  # suppressed in a traceback, still printed
    except _CauseError as exc:
        return exc
    raise AssertionError("nothing was raised")


_GAPS = {
    "dunder-slot": lambda: _DunderSlotError(_encode_error()),
    "inner-attribute": lambda: _holding_inner(_InnerAttributeError),
    "inner-in-args": lambda: _holding_inner(_InnerArgError),
    "cause": _caused,
    "context": _in_context,
}


@pytest.mark.parametrize("make", list(_GAPS.values()), ids=list(_GAPS))
@pytest.mark.parametrize("chain", ["engine", "tray"])
def test_an_exception_printing_a_unicode_error_by_its_own_code_is_a_note(
    chain: str, make: Any
) -> None:
    error = make()
    assert "\\xe9" in str(error)  # control: its own __str__ prints the character
    name = type(error).__name__
    assert redaction.prints_a_codec_error(error)
    assert redaction.safe_exc(error) == f"{name}: {_HOLDER}"
    assert codec_safe_str(error) == _HOLDER
    out = safe_traceback((type(error), error, error.__traceback__))
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out
    assert out.endswith(f"{name}: {_HOLDER}")
    note = f"[{name} holding a codec error, not rendered]"
    record = _record("got %s and %r", (error, [error]))
    _chain_filter(chain).filter(record)
    assert record.getMessage() == f"got {note} and [{note}]"


class _PayloadError(Exception):
    """Prints an attribute it holds, which origin/main read by attribute."""

    def __init__(self, payload: object) -> None:
        super().__init__("bad frame")
        self.payload = payload

    def __str__(self) -> str:
        return f"bad frame: {self.payload}"


class _LinkError(Exception):
    """Has a ``__str__`` of its own, so the scan reads its chain."""

    def __str__(self) -> str:
        return "failed"


def test_a_large_chain_cannot_starve_what_origin_main_read() -> None:
    # Review of vault BACKLOG #3340: reading a sibling's chain spent the budget first, so a holder
    # origin/main found by attribute printed raw. What origin/main read is read before any of it.
    first = _LinkError("failed")
    first.__context__ = ExceptionGroup("many", [ValueError(str(n)) for n in range(5000)])
    held = _PayloadError(_encode_error())
    note = "[_PayloadError holding a codec error, not rendered]"
    record = _record("got %r", ([first, held],))
    _chain_filter("engine").filter(record)
    assert record.getMessage() == f"got [_LinkError('failed'), {note}]"


def test_a_long_chain_is_read_about_once_per_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    # Review of vault BACKLOG #3340: each link's scan read the rest of the chain, so a 900-link
    # chain read about 400,000 objects. Counted, not timed, so a slow runner cannot flake it.
    links = 900
    error: BaseException = _LinkError("failed")
    for _ in range(links - 1):
        outer = _LinkError("failed")
        outer.__cause__ = error
        error = outer
    calls = 0
    real = redaction._attribute_values

    def counted(arg: Any, readers: tuple[Any, ...], limit: int) -> list[Any]:
        nonlocal calls
        calls += 1
        return real(arg, readers, limit)

    monkeypatch.setattr(redaction, "_attribute_values", counted)
    out = safe_traceback((type(error), error, None))
    assert out.count("_LinkError: failed") == links
    assert calls <= 4 * links, calls


def test_a_long_chain_ending_in_a_unicode_error_is_a_note_on_every_link() -> None:
    error: BaseException = _CauseError("bad frame")
    error.__cause__ = _encode_error()
    for _ in range(899):
        outer = _CauseError("bad frame")
        outer.__cause__ = error
        error = outer
    out = safe_traceback((type(error), error, None))
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out
    assert out.count(f"_CauseError: {_HOLDER}") == 900


def test_a_plain_exception_holding_an_error_by_attribute_keeps_its_message_on_its_own() -> None:
    # Its own __str__ prints .args alone, so it is read deeply only beneath one that may print more.
    inner = RuntimeError("failed")
    inner.original = _encode_error()  # type: ignore[attr-defined]
    assert redaction.safe_exc(inner) == "RuntimeError: failed"
    record = _record("got %s", ([inner],))
    args = record.args
    prepare_log_record(record)
    assert record.args is args


def test_a_builtin_exception_raised_from_a_unicode_error_keeps_its_own_message() -> None:
    # A builtin __str__, an OSError's or a KeyError's included, never prints the chain.
    for error in (OSError(2, "cannot open"), KeyError("k"), ValueError("bad")):
        error.__cause__ = _encode_error()
        assert not redaction.prints_a_codec_error(error)
        assert redaction.codec_safe_str(error) == str(error)


class _Batch(Exception):
    """Its own ``__str__``, so what it holds is read the deep way beneath it."""

    def __str__(self) -> str:
        return "batch failed"


@dataclasses.dataclass
class _Held:
    err: object


def test_a_deep_re_read_does_not_spend_the_budget_a_later_argument_needs() -> None:
    # Review of vault BACKLOG #3340: re-following a list's scalars beneath an exception's own code
    # charged the budget for each one, so a codec error held by attribute later printed raw.
    batch = _Batch("bad", [f"seg{i}" for i in range(5000)])
    record = _record("got %r", ([batch, _Held(_encode_error())],))
    RedactionFilter().filter(record)
    out = record.getMessage()
    assert "[_Held holding a codec error, not rendered]" in out
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


def test_an_object_read_twice_is_charged_only_for_what_the_second_read_adds() -> None:
    # Read plainly, then again beneath a holder whose own code renders it: the second read charged
    # every attribute again, so a codec error held after both printed raw.
    shared = types.SimpleNamespace(**{f"a{i}": i for i in range(1900)})
    record = _record("got %r", ([_Held(shared), _Batch("bad", shared), _Held(_encode_error())],))
    RedactionFilter().filter(record)
    out = record.getMessage()
    assert "[_Held holding a codec error, not rendered]" in out
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


@pytest.mark.parametrize(
    "element", [types.SimpleNamespace, _Held], ids=["simple-namespace", "dataclass"]
)
def test_an_object_beneath_an_exceptions_own_code_is_charged_once(element: Any) -> None:
    # Review of vault BACKLOG #3340: the first walk met each element plainly, and the second walk
    # charged it again to read it the deep way, so the budget ran out before an error a sibling
    # held was read, and it printed raw where origin/main printed the note.
    batch = _Batch("bad", [element(err=i) for i in range(1400)])
    record = _record("got %r", ([batch, _Held(_encode_error())],))
    RedactionFilter().filter(record)
    out = record.getMessage()
    assert "[_Held holding a codec error, not rendered]" in out
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


class _OwnStrError(Exception):
    """A ``__str__`` of its own and nothing else: no slot, no attribute, no chain."""

    def __str__(self) -> str:
        return "own"


def test_a_crowd_of_own_str_exceptions_with_no_chain_leaves_a_siblings_held_error_found() -> None:
    # Review of vault BACKLOG #3340: each read charged both chain links even when both were None,
    # so 1,500 such exceptions cost three units each where origin/main charged one, and an error a
    # sibling held by attribute printed raw. Sized from the budget: one unit each fits, three do not.
    crowd = [_OwnStrError() for _ in range(redaction._ATTRIBUTE_BUDGET // 2)]
    record = _record("got %r", ([crowd, _Held(_encode_error())],))
    RedactionFilter().filter(record)
    out = record.getMessage()
    assert "[_Held holding a codec error, not rendered]" in out
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


@pytest.mark.parametrize("extra", [-2000, 1000], ids=["under-budget", "over-budget"])
def test_plain_exceptions_beneath_an_exceptions_own_code_leave_a_siblings_held_error_found(
    extra: int,
) -> None:
    # Review of vault BACKLOG #3340: beneath _Batch each RuntimeError is read the deep way. Its two
    # empty chain links were charged, and then the read itself, so more of them than the budget
    # spent it, where origin/main never read a plain exception and printed the note.
    batch = _Batch("bad", [RuntimeError(i) for i in range(redaction._ATTRIBUTE_BUDGET + extra)])
    held = _Held(_encode_error())
    # The scan's own verdict: the rendered line is cut short by its length bound before _Held.
    assert id(held) in redaction._Scan([batch, held]).holds


class _PrintsInnerCause(Exception):
    """Its own ``__str__`` prints the cause of the exception it keeps on ``.inner``."""

    inner: BaseException

    def __str__(self) -> str:
        return f"wrapped: {self.inner.__cause__}"

    __repr__ = __str__  # a list prints its elements' repr()


def test_a_deep_re_read_reads_the_chain_links_a_large_dict_would_crowd_out() -> None:
    # Review of vault BACKLOG #3340: the deep re-read read the whole __dict__ again up to the
    # budget, dropped what the plain read had found, and never reached the chain links after it.
    shared = OSError("cannot open")
    for i in range(3000):
        setattr(shared, f"a{i}", i)
    shared.__cause__ = _encode_error()
    holder = _PrintsInnerCause("bad")
    holder.inner = shared
    assert "\\xe9" in repr([shared, holder])  # control: its own code prints the character
    record = _record("got %s", ([shared, holder],))
    RedactionFilter().filter(record)
    out = record.getMessage()
    assert "[_PrintsInnerCause holding a codec error, not rendered]" in out
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


class _NoDictOwner:
    pass


class _ForeignDictError(Exception):
    """Its class puts another class's ``__dict__`` getset under ``__dict__``, so reading the
    instance dict through it raises ``TypeError``, and the scan fails closed on it."""

    __dict__ = _NoDictOwner.__dict__["__dict__"]

    def __str__(self) -> str:
        return "h"


def test_an_unreadable_dict_withholds_its_own_element_not_the_whole_argument() -> None:
    # Review of vault BACKLOG #3340: the large-__dict__ check read the reader outside the try,
    # so its TypeError ended the scan and the whole argument was withheld, not one element.
    record = _record("got %s", ([_ForeignDictError(), _encode_error()],))
    RedactionFilter().filter(record)
    out = record.getMessage()
    assert "position 3" in out  # the codec error's safe text: its sibling did not take it down
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out


class _ForeignDictPrintsVars(_ForeignDictError):
    """Its own ``__str__`` reads ``vars(self)``, which raises through the foreign reader."""

    def __str__(self) -> str:
        return f"ctx {vars(self)!r}"


def test_a_foreign_dict_reader_still_fails_closed_rather_than_rendering() -> None:
    # Review of vault BACKLOG #3340: reading such a dict through BaseException's own reader let
    # safe_exc reach str(exc), which raised, where origin/main returned the fixed note.
    error = _ForeignDictPrintsVars("bad")
    with pytest.raises(TypeError):  # control: its own str() raises
        str(error)
    assert redaction.safe_exc(error) == f"_ForeignDictPrintsVars: {redaction._HOLDER_TEXT}"
    assert codec_safe_str(error) == redaction._HOLDER_TEXT


@dataclasses.dataclass
class _ForeignDictData:
    """A dataclass whose ``__dict__`` reader is another class's, so reading it raises."""

    value: int = 0
    __dict__ = _NoDictOwner.__dict__["__dict__"]


def test_an_unreadable_object_only_the_added_pass_reaches_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Review of vault BACKLOG #3340: the added pass's own fail-closed arm needs an unreadable object
    # that only it reaches. The dataclass sits behind a __cause__ link, which only the added pass
    # reads.
    data = _ForeignDictData()
    inner = RuntimeError("inner")
    inner.payload = data  # type: ignore[attr-defined]
    holder = _PrintsInnerCause("bad")
    holder.__cause__ = inner
    scan = redaction._Scan(holder, charged_root=True)
    assert scan.nodes[id(data)][1:] == (None, "TypeError")  # marked unreadable
    assert id(holder) in scan.holds
    assert redaction.prints_a_codec_error(holder)
    # Control: with no added pass, nothing reaches it, so the mark above is the added pass's own.
    monkeypatch.setattr(redaction, "_added_pass", lambda *args: (args[-1], [], 0))
    assert id(data) not in redaction._Scan(holder, charged_root=True).nodes


# --- the added pass never undoes the first (vault BACKLOG #3340) -------------------------------
# Five review rounds each found an ordering of the scan's reads under which a codec error the first
# pass found printed raw. The added pass now runs after the first pass, on what it left, and only
# adds, so each scenario below must hold at least where the first pass alone holds. The expected
# sets are the verdicts of the scan with no added pass, at engine commit 68820faf03 (origin/main
# when this was written), computed once by running that commit's redaction.py on these builders.


@dataclasses.dataclass
class _Big:
    data: object


class _SlotThenAttribute(Exception):
    """A slot read before the attribute its own ``__str__`` prints."""

    __slots__ = ("payload",)
    payload: object

    def __str__(self) -> str:
        return f"bad: {self.ctx}"  # type: ignore[attr-defined]


class _PrintsTail(Exception):
    """Prints one attribute that sits at the end of a large ``__dict__``."""

    def __str__(self) -> str:
        return f"bad: {self.z!r}"  # type: ignore[attr-defined]


class _HoldsData(Exception):
    """Prints its own ``__cause__``, and keeps a list of dataclasses on ``.data``."""

    def __str__(self) -> str:
        return f"bad: {self.__cause__}"


type _Scenario = tuple[str, object, dict[str, object]]


def _with_attributes(error: BaseException, count: int, prefix: str = "a") -> BaseException:
    for n in range(count):
        setattr(error, f"{prefix}{n}", n)
    return error


def _repeated_dataclass() -> _Scenario:
    held = _Held(_encode_error())
    arg = [held, _Big(list(range(3000))), _Big(list(range(3000))), held]
    return "arg", arg, {"held": held, "arg": arg}


def _slot_then_attribute(mode: str) -> _Scenario:
    error = _SlotThenAttribute("x")
    error.payload = list(range(5000))
    error.ctx = [_encode_error()]  # type: ignore[attr-defined]
    return mode, ([error] if mode == "arg" else error), {"error": error}


def _dict_tail() -> _Scenario:
    error = _with_attributes(_PrintsTail("x"), 4093)
    error.z = _encode_error()  # type: ignore[attr-defined]
    _with_attributes(error, 50, "b")
    error.__context__ = ValueError("ctx")
    error.__cause__ = ValueError("cause")
    return "exc", error, {"error": error}


def _args_and_large_dict() -> _Scenario:
    error = _with_attributes(_CauseError(*range(10)), 4090)
    error.__cause__ = _encode_error()
    return "exc", error, {"error": error}


def _large_dict_hides_cause() -> _Scenario:
    error = _with_attributes(_CauseError("bad frame"), redaction._ATTRIBUTE_BUDGET + 10)
    error.__cause__ = _encode_error()
    return "exc", error, {"error": error}


def _dataclass_crowd(then_error: bool) -> _Scenario:
    error = _HoldsData("x")
    data: list[object] = [_Held(i) for i in range(1300)]
    if then_error:
        data.append(_encode_error())
    error.data = data  # type: ignore[attr-defined]
    error.__cause__ = RuntimeError(_encode_error())
    return "exc", error, {"error": error}


def _group_context() -> _Scenario:
    first = _LinkError("failed")
    first.__context__ = ExceptionGroup("many", [ValueError(str(n)) for n in range(5000)])
    held = _PayloadError(_encode_error())
    arg = [first, held]
    return "arg", arg, {"first": first, "held": held, "arg": arg}


def _outer_link_starves() -> _Scenario:
    inner = RuntimeError(_encode_error())
    prints = _CauseError("x")
    prints.__cause__ = inner
    large = RuntimeError(list(range(10000)))
    large.__cause__ = prints
    outer = _LinkError("r")
    outer.__cause__ = large
    # In the order safe_traceback scans them: each link, then its cause.
    return "chain", outer, {"outer": outer, "large": large, "prints": prints, "inner": inner}


def _shared_beneath(payload: bool) -> _Scenario:
    if payload:
        shared: BaseException = _PayloadError(_encode_error())
    else:
        shared = RuntimeError("x")
        shared.original = _encode_error()  # type: ignore[attr-defined]
    plain, own = _Held(shared), _Batch(shared)
    arg = [[plain, own]]
    return "arg", arg, {"plain": plain, "own": own, "shared": shared, "arg": arg}


def _hidden_dict_beside_a_holder() -> _Scenario:
    # The first pass reads no instance dict the class hides behind `__dict__ = None`, as on
    # origin/main, so a large one cannot spend the budget a sibling holder needs.
    hidden = _with_attributes(_ShadowedDict("x"), 5000)
    held = _Held(_encode_error())
    error = RuntimeError(hidden, held)
    return "exc", error, {"error": error, "hidden": hidden, "held": held}


_DIFFERENTIAL: dict[str, Any] = {
    "repeated-dataclass": _repeated_dataclass,
    "large-slot-before-dict-value": functools.partial(_slot_then_attribute, "exc"),
    "large-slot-before-dict-value-logged": functools.partial(_slot_then_attribute, "arg"),
    "dict-tail-the-first-pass-reads": _dict_tail,
    "args-and-a-large-dict": _args_and_large_dict,
    "large-dict-hides-cause": _large_dict_hides_cause,
    "1300-dataclasses": functools.partial(_dataclass_crowd, False),
    "1300-dataclasses-then-an-error": functools.partial(_dataclass_crowd, True),
    "group-context-before-a-holder": _group_context,
    "outer-link-starves-a-later-one": _outer_link_starves,
    "shared-by-plain-and-own-code-holder": functools.partial(_shared_beneath, True),
    "shared-plain-exception-holding-by-attribute": functools.partial(_shared_beneath, False),
    "hidden-dict-beside-a-holder": _hidden_dict_beside_a_holder,
}

#: Which targets the scan with no added pass found holding an error (engine commit 68820faf03).
_FIRST_PASS_HOLDS: dict[str, frozenset[str]] = {
    "repeated-dataclass": frozenset({"arg", "held"}),
    "large-slot-before-dict-value": frozenset({"error"}),
    "large-slot-before-dict-value-logged": frozenset({"error"}),
    "dict-tail-the-first-pass-reads": frozenset({"error"}),
    "args-and-a-large-dict": frozenset(),
    "large-dict-hides-cause": frozenset(),
    "1300-dataclasses": frozenset(),
    "1300-dataclasses-then-an-error": frozenset({"error"}),
    "group-context-before-a-holder": frozenset({"arg", "held"}),
    "outer-link-starves-a-later-one": frozenset({"inner"}),
    "shared-by-plain-and-own-code-holder": frozenset({"arg", "own", "plain", "shared"}),
    "shared-plain-exception-holding-by-attribute": frozenset(),
    "hidden-dict-beside-a-holder": frozenset({"error", "held"}),
}


def _verdicts(build: Any) -> set[str]:
    mode, root, targets = build()
    if mode == "chain":  # as safe_traceback asks, one share for the whole traceback
        share = redaction._ScanShare()
        return {
            name
            for name, exc in targets.items()
            if redaction.prints_a_codec_error(exc, share=share)
        }
    holds = redaction._Scan(root, charged_root=mode == "exc").holds
    return {name for name, obj in targets.items() if id(obj) in holds}


@pytest.mark.parametrize("name", list(_DIFFERENTIAL))
def test_the_added_pass_holds_wherever_the_first_pass_alone_holds(name: str) -> None:
    assert _verdicts(_DIFFERENTIAL[name]) >= _FIRST_PASS_HOLDS[name]


def test_the_added_pass_reaches_what_only_it_reads() -> None:
    # A control for the test above: the added pass does find what the first pass never reads.
    assert {"own", "arg"} <= _verdicts(_DIFFERENTIAL["shared-plain-exception-holding-by-attribute"])


class _SlotOnly(Exception):
    """A slot of its own and the builtin ``__str__`` and ``__repr__``."""

    __slots__ = ("code",)
    code: object


def _fuzz_graph(seed: int) -> _Scenario:
    """One random graph of containers, dataclasses and exceptions, some large enough to spend the
    budget, with codec errors among them. Every non-scalar is a target, named in creation order."""
    rng = random.Random(seed)
    named: dict[str, object] = {}

    def keep[T](obj: T) -> T:
        named[f"n{len(named)}"] = obj
        return obj

    def pad(error: BaseException) -> BaseException:
        return _with_attributes(error, rng.choice((0, 0, 3, 2000, 4100)))

    def exc(depth: int) -> BaseException:
        child = value(depth)
        return child if isinstance(child, BaseException) else keep(RuntimeError(child))

    def value(depth: int) -> object:
        roll = rng.random()
        if depth >= 4 or roll < 0.25:
            leaf = rng.random()
            if leaf < 0.3:
                return keep(_encode_error())
            if leaf < 0.6:
                return rng.randrange(100)
            return keep(list(range(rng.choice((3, 60, 3000, 5000)))))
        return node(depth + 1)

    def node(depth: int) -> object:
        kind = rng.randrange(12)
        kids = [value(depth) for _ in range(rng.randrange(1, 4))]
        if kind == 0:
            return keep(kids)
        if kind == 1:
            return keep({f"k{i}": kid for i, kid in enumerate(kids)})
        if kind == 2:
            return keep(_Held(kids[0] if kids else None))
        if kind == 3:
            return keep(pad(RuntimeError(*kids)))
        if kind == 4:
            error = keep(pad(RuntimeError("x")))
            error.original = value(depth)  # type: ignore[attr-defined]
            return error
        if kind == 5:
            return keep(pad(_PayloadError(kids[0] if kids else None)))
        if kind == 6:
            return keep(pad(_Batch(*kids)))
        if kind == 7:
            error = keep(pad(_CauseError("x")))
            error.__cause__ = exc(depth)
            return error
        if kind == 8:
            hidden = keep(_ShadowedDict("x"))
            pad(hidden)
            hidden.payload = kids[0] if kids else None
            return hidden
        if kind == 9:
            slotted = keep(_Slotted("x"))
            slotted.payload = kids[0] if kids else None
            return slotted
        if kind == 10:
            only = keep(_SlotOnly("x"))
            only.code = kids[0] if kids else None
            return only
        error = keep(pad(_LinkError("x")))
        error.__context__ = exc(depth)
        return error

    mode = rng.choice(("arg", "arg", "exc", "chain"))
    if mode == "arg":
        root = node(0)
        return "arg", root, named
    root = exc(0)
    if mode == "exc":
        return "exc", root, named
    # The links in the order safe_traceback scans them: each link, then its context, then its
    # cause, each once.
    links: dict[str, object] = {}
    pending: list[BaseException | None] = [root]
    seen: set[int] = set()
    while pending:
        link = pending.pop()
        if link is None or id(link) in seen:
            continue
        seen.add(id(link))
        links[f"n{list(map(id, named.values())).index(id(link))}"] = link
        pending.append(link.__cause__)
        pending.append(link.__context__)
    return "chain", root, links


_FUZZ_SEED = 3340
_FUZZ_GRAPHS = 300
#: For each graph whose verdicts on engine commit 68820faf03 hold anything, the targets they hold,
#: worked out by running that commit's redaction.py on the same graphs. A graph not listed holds none.
_FUZZ_MAIN_HOLDS: dict[int, frozenset[str]] = {
    4: frozenset({"n0", "n21", "n22"}),
    5: frozenset({"n31", "n32", "n86"}),
    6: frozenset({"n15"}),
    10: frozenset({"n18"}),
    26: frozenset({"n0"}),
    27: frozenset({"n0", "n1", "n2", "n3", "n8", "n9", "n32", "n33"}),
    41: frozenset({"n0"}),
    52: frozenset({"n3"}),
    59: frozenset({"n37"}),
    68: frozenset({"n0", "n5"}),
    69: frozenset({"n0", "n3", "n4"}),
    77: frozenset({"n8", "n9"}),
    82: frozenset({"n0", "n2", "n3", "n12", "n25", "n26"}),
    83: frozenset({"n0", "n1", "n22"}),
    86: frozenset({"n0", "n11", "n12", "n13"}),
    101: frozenset({"n0", "n2", "n5", "n19", "n20"}),
    104: frozenset({"n0"}),
    110: frozenset({"n0"}),
    112: frozenset({"n4"}),
    121: frozenset({"n0"}),
    130: frozenset({"n1", "n2", "n7", "n8", "n32"}),
    131: frozenset({"n0", "n17"}),
    133: frozenset({"n23", "n24", "n43", "n44"}),
    134: frozenset({"n11"}),
    135: frozenset({"n4", "n5", "n6", "n7"}),
    137: frozenset({"n8", "n9", "n12"}),
    149: frozenset({"n0", "n21"}),
    158: frozenset({"n0", "n34", "n47", "n48", "n49"}),
    163: frozenset({"n0", "n29", "n30", "n31"}),
    171: frozenset({"n10", "n11", "n18", "n19", "n21", "n22"}),
    180: frozenset({"n36"}),
    184: frozenset({"n0", "n1"}),
    193: frozenset({"n24"}),
    198: frozenset({"n25", "n26", "n27", "n28"}),
    208: frozenset({"n0", "n3", "n16", "n29", "n30", "n31"}),
    213: frozenset({"n0", "n2", "n15", "n16"}),
    221: frozenset({"n0", "n6"}),
    229: frozenset({"n10", "n11"}),
    237: frozenset({"n0", "n1"}),
    241: frozenset({"n54", "n62", "n63", "n71", "n72"}),
    245: frozenset({"n5"}),
    246: frozenset({"n3", "n4", "n5", "n6", "n14", "n19"}),
    251: frozenset({"n52"}),
    255: frozenset({"n9"}),
    256: frozenset({"n0", "n1", "n20", "n21"}),
    264: frozenset({"n0", "n1", "n2"}),
    267: frozenset({"n0", "n1"}),
    273: frozenset({"n51"}),
    274: frozenset({"n0"}),
    285: frozenset({"n31"}),
    291: frozenset({"n0", "n2", "n10", "n13", "n15", "n32", "n48", "n49"}),
    293: frozenset({"n0", "n2", "n3", "n4", "n5", "n20", "n40"}),
    295: frozenset({"n0", "n1", "n2", "n4", "n8", "n9", "n32", "n33"}),
    297: frozenset({"n30"}),
}


@pytest.mark.parametrize("index", range(_FUZZ_GRAPHS))
def test_the_added_pass_holds_wherever_the_first_pass_alone_holds_on_random_graphs(
    index: int,
) -> None:
    graph = functools.partial(_fuzz_graph, _FUZZ_SEED * 1000 + index)
    assert _verdicts(graph) >= _FUZZ_MAIN_HOLDS.get(index, frozenset())


def test_the_random_graphs_reach_both_verdicts() -> None:
    # A control for the test above: the graphs are neither all holding nor all empty.
    assert 0 < len(_FUZZ_MAIN_HOLDS) < _FUZZ_GRAPHS


def _scanned_class() -> weakref.ref[type[BaseException]]:
    class Slotted(Exception):
        __slots__ = ("code",)
        code: object

    error = Slotted("y")
    error.code = 1
    redaction.safe_exc(error)
    redaction.prints_a_codec_error(error)
    safe_traceback((Slotted, error, None))
    return weakref.ref(Slotted)


def test_a_scanned_exception_class_is_not_kept_alive_past_the_scan() -> None:
    # Review of vault BACKLOG #3340: the added pass's readers were cached with the first pass's,
    # and a slot's descriptor holds its class, so an exception class origin/main let go stayed
    # alive until the cache filled.
    alive = _scanned_class()
    gc.collect()
    assert alive() is None


class _CountedRow(collections.namedtuple("_CountedRow", "value")):  # noqa: PYI024 - a subclass
    """Counts each time its own ``__repr__`` runs."""

    calls = 0

    def __repr__(self) -> str:
        type(self).calls += 1
        return "row"


def test_an_exception_holder_renders_none_of_what_it_holds() -> None:
    # Review of vault BACKLOG #3340: a holder exception's elements, now including what the added
    # pass read from its attributes, were each rendered, a container subclass by its own __repr__,
    # and the text thrown away for the fixed note.
    plain = ValueError("x")
    plain.row = _CountedRow(_encode_error())  # type: ignore[attr-defined]
    own = _LinkError("y")
    own.inner = plain  # type: ignore[attr-defined]
    _CountedRow.calls = 0
    record = _record("got %r", ([plain, own],))
    RedactionFilter().filter(record)
    out = record.getMessage()
    assert out == f"got [[ValueError {_HOLDER[1:]}, [_LinkError {_HOLDER[1:]}]"
    assert _CountedRow.calls == 0


class _Slotted(Exception):
    """Prints its last slot; the slots before it are never assigned."""

    __slots__ = ("a", "b", "c", "d", "payload")
    payload: object

    def __str__(self) -> str:
        return f"slotted: {self.payload}"


@pytest.mark.parametrize("pad", [4085, 4086, 4087, 4088])
def test_a_verdict_is_not_handed_on_from_a_read_cut_short_by_unassigned_slots(pad: int) -> None:
    # Review of vault BACKLOG #3340: the outer link's scan tried the four unassigned slots, ran
    # out of limit before .payload, still had budget left, and handed on "holds none" to the
    # inner link, whose own first pass reads .payload and finds the error.
    inner = _Slotted("x")
    inner.payload = _encode_error()
    outer = _with_attributes(_LinkError("failed"), pad)
    outer.__cause__ = inner
    out = safe_traceback((type(outer), outer, None))
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out
    assert f"_Slotted: {_HOLDER}" in out


def test_a_long_chain_with_a_large_payload_is_not_read_once_per_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Review of vault BACKLOG #3340: each link's scan ran out on the payload and handed nothing on,
    # so 900 links each read the rest of the chain. Counted, not timed.
    links = 900
    error: BaseException = _LinkError("failed")
    error.payload = list(range(5000))  # type: ignore[attr-defined]
    for _ in range(links - 1):
        outer = _LinkError("failed")
        outer.__cause__ = error
        error = outer
    calls = 0
    real = redaction._children

    def counted(arg: Any, kind: type[Any], limit: int | None = None) -> list[Any]:
        nonlocal calls
        calls += 1
        return real(arg, kind, limit)

    monkeypatch.setattr(redaction, "_children", counted)
    out = safe_traceback((type(error), error, None))
    assert out.count("_LinkError: failed") == links
    assert calls <= 8 * links, calls


class _ManySlots(Exception):
    """Its own ``__str__`` and 200 slots it never assigns, beside the one it prints."""

    __slots__ = (*(f"s{i}" for i in range(200)), "payload")
    payload: object

    def __str__(self) -> str:
        return f"many: {self.payload}"


def test_the_added_readers_are_worked_out_once_per_class_not_once_per_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Review of vault BACKLOG #3340: the readers each added read takes beyond the reads before it
    # were worked out twice for every object, in time quadratic in the slots, though they depend
    # only on the class. Counted, not timed.
    calls = 0
    real = redaction._added_readers

    def counted(had: tuple[Any, ...], target: tuple[Any, ...]) -> tuple[Any, ...]:
        nonlocal calls
        calls += 1
        return real(had, target)

    monkeypatch.setattr(redaction, "_added_readers", counted)
    crowd = []
    for i in range(500):
        one = _ManySlots("x")
        one.payload = i
        crowd.append(one)
    held = _ManySlots("y")
    held.payload = _encode_error()
    scan = redaction._Scan([crowd, held])
    assert id(held) in scan.holds  # the verdict the cache must not change
    assert not any(id(one) in scan.holds for one in crowd)
    assert calls <= 3, calls  # the three a class's record holds, whatever the instance count


class _ShadowedDict(Exception):
    """A class attribute named ``__dict__`` hides the descriptor, not the instance dict."""

    __dict__ = None  # type: ignore[assignment]
    payload: object

    def __str__(self) -> str:
        return f"bad: {self.payload}"


def test_a_class_attribute_named_dict_does_not_hide_an_exceptions_attributes() -> None:
    # Review of vault BACKLOG #3340: the instance dict's reader was looked up by name on the
    # class, so `__dict__ = None` made the walk skip every instance attribute.
    exc = _ShadowedDict("x")
    exc.payload = _encode_error()
    assert "payload" in redaction._EXC_DICT.__get__(exc)  # the control: it really holds it
    out = redaction.safe_exc(exc)
    for spelling in _CHAR_SPELLINGS:
        assert spelling not in out
    assert out == f"_ShadowedDict: {_HOLDER}"


class _UnreadableClass:
    """Reading its ``__class__``, as ``isinstance`` does for an object that is not a class, raises."""

    @property  # type: ignore[misc]
    def __class__(self) -> type[Any]:
        raise RuntimeError("no class")


def test_a_builtins_value_whose_class_raises_is_skipped_not_raised() -> None:
    # Review of vault BACKLOG #3340: built with isinstance(), a value put into builtins whose
    # __class__ raises would have made `import messagefoundry.redaction` raise.
    odd = _UnreadableClass()
    with pytest.raises(RuntimeError):
        isinstance(odd, type)  # the control: the old comprehension's test raises on it
    found = redaction._builtin_exc_renders({"odd": odd, "KeyError": KeyError})
    assert found == {id(KeyError.__dict__["__str__"])}


async def test_an_unreadable_trust_anchor_refusal_names_no_byte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The arm catches (OSError, ValueError), so the scan does not see it: the read is in a callee.
    # Since BACKLOG #3091 that arm is in _preflight_one, around the file read alone, and its text
    # names the setting (BACKLOG #3105, item 6). The read fails before any store call.
    def unreadable(*args: object, **kwargs: object) -> None:
        raise _decode_error()

    monkeypatch.setattr(trust_anchors, "evaluate_anchor", unreadable)
    spec = trust_anchors.AnchorSpec("ad", "[auth].ad_tls_ca_cert_file", "ca.pem", None)
    store: Any = None
    preflight = trust_anchors.make_settings_anchor_preflight([spec], store, enforcing=True)
    assert preflight is not None
    with pytest.raises(WiringError) as caught:
        await preflight()
    assert str(caught.value).startswith(
        "a settings trust anchor was refused: [auth].ad_tls_ca_cert_file: could not read"
    )
    _assert_decode_safe(str(caught.value))


def test_a_non_utf8_code_set_csv_is_refused_by_name_without_the_byte(tmp_path: Path) -> None:
    # It escaped load_code_set as a raw UnicodeDecodeError, past every caller's CodeSetError arm.
    bad = tmp_path / "diets.csv"
    bad.write_bytes(b"code,label\nA,ok" + _BYTE + b"\n")
    with pytest.raises(CodeSetError) as caught:
        load_code_set(bad)
    text = str(caught.value)
    assert text == "code set 'diets.csv': invalid CSV \u2014 the file is not valid UTF-8"
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    good = tmp_path / "ok.csv"
    good.write_text("code,label\nA,café\n", encoding="utf-8")
    assert load_code_set(good)["A"] == "café"
    wide = tmp_path / "wide.csv"  # the csv module's own refusal escaped the same way
    wide.write_text("code,label\nA," + "x" * 131073 + "\n", encoding="utf-8")
    with pytest.raises(CodeSetError, match="code set 'wide.csv': invalid CSV \u2014 field larger"):
        load_code_set(wide)
    with pytest.raises(CodeSetError, match="code set 'gone.csv': invalid CSV"):
        load_code_set(tmp_path / "gone.csv")  # as a missing .toml one already was


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
#: Calls that render their argument as text.
_RENDER_CALLS = frozenset(
    {"str", "repr", "format", "print", "format_exception", "format_exception_only"}
    | {"print_exception", "TracebackException"}
)
#: The only calls a raw error may be handed to (vault BACKLOG #3295). The scan cannot know what any
#: other callee does with it, so a helper of the code's own, a constructor and ``errors.append(exc)``
#: are all refused until the callee is read and named here. ``_decode_refusal`` in
#: pipeline/ingress_guards.py renders it through ``safe_exc``.
_SAFE_CALLS = frozenset(
    {"safe_exc", "codec_safe_str", "codec_safe_line", "type", "isinstance", "_decode_refusal"}
)
#: An arm that names one of these also receives a Unicode error, which is a ``ValueError``.
_BROAD_TYPES = frozenset({"ValueError", "Exception", "BaseException"})
#: Method calls that encode or decode where they stand. A ``try`` body that makes one can raise a
#: Unicode error into its own broad arm, so that arm is scanned as if it named the type. A codec
#: call made inside a callee is not seen: about a thousand broad arms stay outside this scan, and
#: no source scan can say which of them a Unicode error reaches.
_CODEC_METHODS = frozenset({"decode", "encode", "read_text", "write_text"})
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


def _holds_raw(node: ast.AST, name: str) -> bool:
    """``node`` is the raw error, or a tuple, list, set or dict literal that holds it."""
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return any(_holds_raw(element, name) for element in node.elts)
    if isinstance(node, ast.Dict):
        return any(_holds_raw(part, name) for part in (*node.keys, *node.values) if part)
    if isinstance(node, ast.Starred):
        return _holds_raw(node.value, name)
    return _is_raw(node, name)


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
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value:
            if _holds_raw(node.value, name):  # the raise-after-handler shape carries it out
                yield node.lineno, "aliased out of the handler"
        elif isinstance(node, (ast.Return, ast.Yield)) and node.value is not None:
            if _holds_raw(node.value, name):
                yield node.lineno, "returned out of the handler"
        elif isinstance(node, ast.Attribute) and _is_raw(node, name):
            # Any read: idna and punycode put the label in .reason, so concatenation leaks it too.
            yield node.lineno, f".{node.attr} read"


def _raw_call(node: ast.Call, name: str) -> Iterator[tuple[int, str]]:
    # exc_info= is path 1, which the log filter chain renders safely, so it stays allowed.
    values = [*node.args, *(k.value for k in node.keywords if k.arg != "exc_info")]
    if not any(_holds_raw(v, name) for v in values):
        return
    callee = callee_name(node) or ""
    if callee in _RENDER_CALLS:
        yield node.lineno, f"{callee}() of the error"
    elif isinstance(node.func, ast.Attribute) and callee in _LOG_METHODS:
        yield node.lineno, "log argument"
    elif callee[:1].isupper():
        yield node.lineno, f"passed into {callee}()"
    elif callee not in _SAFE_CALLS:
        yield node.lineno, f"handed to {callee}()"


def _makes_a_codec_call(body: list[ast.stmt]) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _CODEC_METHODS
        for stmt in body
        for node in ast.walk(stmt)
    )


def _receives_a_unicode_error(handler: ast.ExceptHandler, codec_call: bool) -> bool:
    names = _handler_names(handler.type)
    if names & _UNICODE_TYPES:
        return True
    return codec_call and (handler.type is None or bool(names & _BROAD_TYPES))


def _scan_source(source: str, path: str) -> tuple[int, list[str]]:
    handlers = 0
    found: list[str] = []
    for node in ast.walk(ast.parse(source, path)):
        if not isinstance(node, (ast.Try, ast.TryStar)):
            continue
        codec_call = _makes_a_codec_call(node.body)
        for handler in node.handlers:
            if _receives_a_unicode_error(handler, codec_call):
                handlers += 1
                found.extend(f"{path}:{line}: {what}" for line, what in _raw_renders(handler))
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
def p(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        text = describe(exc)
def q(b, errors):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        errors.append(exc)
def r(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        return exc
def s(b):
    try:
        b.decode()
    except ValueError as exc:
        raise RuntimeError(f"{exc}")
def t(path):
    try:
        path.read_text(encoding="utf-8")
    except Exception as exc:
        return str(exc)
def u(b):
    try:
        b.encode("ascii")
    except:
        traceback.print_exc()
def v(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        return None, exc
def w(b, errors):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        errors += [exc]
def x(b):
    try:
        b.decode()
    except UnicodeDecodeError as exc:
        report({"error": exc})
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
        int(b)
    except ValueError as exc:  # no codec call in the try body: outside this scan, a stated limit
        raise RuntimeError(f"{exc}")
def d(b):
    try:
        b.decode()
    except KeyError as exc:  # a codec call, but an arm no Unicode error reaches
        raise RuntimeError(f"{exc}")
def e(b, encoding):
    try:
        b.decode(encoding)
    except UnicodeDecodeError as exc:
        refused = _decode_refusal(encoding, exc)
        kind = type(exc).__name__ if isinstance(exc, ValueError) else ""
def f(b):
    try:
        b.decode()
    except Exception as exc:
        raise RuntimeError(f"cannot read: {codec_safe_str(exc)}") from None
"""


def test_the_guard_fires_on_every_planted_shape() -> None:
    handlers, found = _scan_source(_PLANTED, "planted.py")
    assert handlers == 22
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
        "handed to describe()",  # p: a helper of the code's own
        "handed to append()",  # q
        "returned out of the handler",  # r
        "f-string interpolation",  # s: a ValueError arm under a decode call
        "str() of the error",  # t: an Exception arm under read_text
        "the handled error reached without its name",  # u: a bare arm under an encode call
        "returned out of the handler",  # v: inside a tuple
        "aliased out of the handler",  # w: += a list that holds it
        "handed to report()",  # x: inside a dict literal
    ], found


def test_the_guard_passes_the_safe_shapes() -> None:
    assert _scan_source(_CLEAN, "clean.py") == (5, [])
