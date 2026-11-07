# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Which code raised an exception, read from its traceback (vault BACKLOG #3765 item 5).

The config loader, ``messagefoundry check-privileges`` and the CLI each read this to decide whether
to print an exception's text. All three share :func:`raised_by_the_engine`'s frame rule. The loader
also takes the narrower :func:`worded_by_the_engine`, and so does :func:`engine_worded_text`, which
the store's cipher build and PostgreSQL TLS context refusals and the AD probe's guard refusal read
(the sixth hold on engine PR 2818); a builtin's text in engine code can still print elsewhere. A leaf that imports only the standard library:
``privilege_probes`` calls it inside exception handlers without loading ``config.wiring``, and
``__main__`` without loading anything else.

The rule reads the innermost frame's compiled file name and its module name, and needs both. A
module can rebind ``__name__``, so the name alone is a claim. A config directory can sit inside the
package, and its modules and helpers run as ``mefor_config_*``, so the file alone is not enough. The
file name is fixed when code is compiled, so a module that compiles text under an engine path, and
sets the name to match, still passes. This tells most accidents from engine wording: it does not
stop code that sets out to forge a frame.

The innermost frame says where a traceback ends, not who raised what is on it. ``raise
X(text).with_traceback(exc.__traceback__)``, an ordinary idiom rather than a forgery, keeps the
engine's frame innermost. So the loader also reads where the raise happened:
:func:`raised_only_by_the_engine`. That cannot tell the idiom from a module's ``raise exc`` of the
refusal it caught, so that is withheld too, which is the cheaper failure. The CLI and the probes' other
texts keep the frame rule alone, because a library raising an engine exception again, as
``concurrent.futures`` does, must not cost them an engine refusal's text. The callers of
:func:`engine_worded_text` accept that cost: such a refusal reads as their fixed text.

A frame says who raised an instance, not what it prints. A module can catch a refusal and assign its
``__class__``, which leaves the engine's frame on it and prints through that class's ``__str__``, so
the loader also reads the real class (``wiring._is_engine_text``). No frame rule here reads
``args``, so a module that rewrites them, with text or with an object whose own ``__str__`` holds
the value, still passes.

:func:`engine_worded_text` is that rule applied to text: it reads ``args`` through
``BaseException``'s own descriptor, and only for an instance whose constructor and ``__str__``
are those of the base the caller names, so a caller can take an engine refusal's text without
running any of the error's code."""

from __future__ import annotations

import opcode
import os
from collections.abc import Iterator
from types import CodeType, TracebackType
from typing import Any, Final

__all__ = [
    "ExceptionChainTooLong",
    "engine_worded_text",
    "exception_chain",
    "raise_statement_file",
    "raised_by_the_engine",
    "raised_only_by_the_engine",
    "raised_through",
    "worded_by_the_engine",
]

_RAISE_STATEMENT: Final = opcode.opmap["RAISE_VARARGS"]

#: The builtin descriptor. A config module's exception class can define its own ``__traceback__``.
_TRACEBACK_OF: Final[Any] = BaseException.__dict__["__traceback__"]

#: This package's directory, spelled as it was imported, so not resolved or normalized: a code
#: object holds that same spelling, which a ``sys.path`` entry such as ``a/b/..`` can leave unusual.
_ENGINE_DIR: Final = os.path.dirname(__file__) + os.sep

#: Third-party code shipped inside the package. A ``raise`` there is not the engine's wording.
_VENDORED_DIR: Final = f"{_ENGINE_DIR}_vendor{os.sep}"

#: Far past any real chain. A class's ``reason`` property can return a new exception on every read,
#: and with no limit a walk of that never ends.
_CHAIN_LIMIT: Final = 1024


class ExceptionChainTooLong(Exception):
    """:func:`exception_chain` passed :data:`_CHAIN_LIMIT` links, so what it read is not all there is."""


def exception_chain(exc: BaseException) -> Iterator[BaseException]:
    """``exc`` and at least these it wraps: its cause and context, an exception group's members, and
    the exceptions urllib3 and requests keep in ``args``, ``reason`` and ``original_error``. Each is
    visited once.

    Past :data:`_CHAIN_LIMIT` links this raises :class:`ExceptionChainTooLong` rather than stop
    quietly, because a caller judging the chain would judge the part it saw as the whole of it."""
    seen: set[int] = set()
    todo: list[BaseException] = [exc]
    while todo:
        e = todo.pop()
        if id(e) in seen:
            continue
        if len(seen) >= _CHAIN_LIMIT:
            raise ExceptionChainTooLong
        seen.add(id(e))
        yield e
        inner: list[object] = [e.__cause__, e.__context__, *e.args]
        inner += [getattr(e, "reason", None), getattr(e, "original_error", None)]
        if isinstance(e, BaseExceptionGroup):
            inner += e.exceptions
        todo += [i for i in inner if isinstance(i, BaseException)]


def _in_the_engine(tb: TracebackType) -> bool:
    """Whether this traceback entry's frame is a ``messagefoundry`` module and not a vendored one."""
    file = tb.tb_frame.f_code.co_filename
    if not file.startswith(_ENGINE_DIR) or file.startswith(_VENDORED_DIR):
        return False
    module = tb.tb_frame.f_globals.get("__name__", "")
    return isinstance(module, str) and module.split(".")[0] == "messagefoundry"


def _stopped_on_a_raise(tb: TracebackType) -> bool:
    return tb.tb_frame.f_code.co_code[tb.tb_lasti] == _RAISE_STATEMENT


def _entries(exc: BaseException) -> list[TracebackType]:
    """``exc``'s traceback, outermost entry first. An exception never raised has none."""
    entries: list[TracebackType] = []
    tb: TracebackType | None = _TRACEBACK_OF.__get__(exc)
    while tb is not None:
        entries.append(tb)
        tb = tb.tb_next
    return entries


def raised_by_the_engine(exc: BaseException) -> bool:
    """Whether the innermost frame of ``exc``'s traceback is this package's own code.

    That frame also holds a C builtin's failure: ``int(value)`` in engine code ends in the engine's
    frame, and its text quotes ``value``. Use :func:`worded_by_the_engine` where that matters."""
    entries = _entries(exc)
    return bool(entries) and _in_the_engine(entries[-1])


def raised_through(exc: BaseException, code: CodeType) -> bool:
    """Whether a frame of ``exc``'s traceback runs ``code``, so ``exc`` was raised while that
    function ran (BACKLOG #4883). Read by code object, so a function of the same name elsewhere
    does not count, and an exception never raised has no frame and answers ``False``."""
    return any(tb.tb_frame.f_code is code for tb in _entries(exc))


#: The builtin descriptor, so reading the arguments runs none of a subclass's code.
_ARGS_OF: Final[Any] = BaseException.__dict__["args"]
#: ``type``'s own descriptors, so reading a class's MRO and dict runs no metaclass code.
_TYPE_MRO: Final[Any] = vars(type)["__mro__"]
_TYPE_DICT: Final[Any] = vars(type)["__dict__"]
#: What a class must not define for its arguments to be what ``raise`` passed and ``str`` prints.
_TEXT_HOOKS: Final = ("__init__", "__new__", "__str__")


def engine_worded_text(exc: BaseException, kind: type[BaseException]) -> str | None:
    """``exc``'s one ``str`` argument when ``exc`` is a ``kind`` that :func:`worded_by_the_engine`,
    and its ``__init__``, ``__new__`` and ``__str__`` each resolve to ``kind`` or a class above it,
    else ``None``, read with none of ``exc``'s own code run (the sixth hold on engine PR 2818). This
    is the one statement of the rule; the store's and the AD probe's refusals link here.

    ``kind`` must be a class whose ``__init__`` and ``__str__`` are ``BaseException``'s, such as
    ``ValueError`` or ``InsecureHopRefused``: then the arguments are what the engine ``raise``
    passed, and what ``str(exc)`` prints. A constructor or ``__str__`` of any other class, a mixin
    after ``kind`` in the MRO included, could write or print a byte the arguments do not show, so
    such an error is never read. The class is read with ``type`` and its MRO and dicts through
    ``type``'s own descriptors.

    It proves less than that the engine wrote the text. Like :func:`worded_by_the_engine`, it does
    not see what the text holds, since an engine ``raise`` can interpolate another error's text. Nor
    does it see arguments reassigned after the raise by code that caught the error and raised it
    again with a bare ``raise``, which adds no frame, or rewritten by a metaclass ``__call__``. A
    caller that gets ``None`` says something fixed instead."""
    mro = _TYPE_MRO.__get__(type(exc))
    if not any(base is kind for base in mro):
        return None
    allowed = _TYPE_MRO.__get__(kind)
    for name in _TEXT_HOOKS:
        owner = next((base for base in mro if name in _TYPE_DICT.__get__(base)), None)
        if not any(owner is base for base in allowed):
            return None
    if not worded_by_the_engine(exc):
        return None
    args = _ARGS_OF.__get__(exc)
    if len(args) == 1 and type(args[0]) is str:
        return str(args[0])
    return None


def raise_statement_file(exc: BaseException) -> str | None:
    """The compiled file name of the ``raise`` statement the innermost frame of ``exc``'s traceback
    stopped on, or ``None`` when it stopped on anything else. A signal that Python's own handler
    turned into an exception does not stop on a ``raise``, so a file here can prove code and ``None``
    can never prove a signal."""
    entries = _entries(exc)
    if not entries or not _stopped_on_a_raise(entries[-1]):
        return None
    return entries[-1].tb_frame.f_code.co_filename


def raised_only_by_the_engine(exc: BaseException) -> bool:
    """:func:`raised_by_the_engine`, and no code outside the engine raised ``exc`` onto a traceback
    it already had.

    Every traceback entry but the innermost normally stopped on a call. A bare ``raise`` adds no
    entry, so one that stopped on a ``raise`` is usually ``raise exc`` or ``raise
    X().with_traceback(tb)``, whose instance need not be the one the frames below it raised. It can
    also be ``raise Cls`` whose constructor failed, which is withheld too. This reads only that
    instruction, so it does not see a traceback put on by ``gen.throw`` or by assigning
    ``__traceback__`` before a bare ``raise``."""
    return raised_by_the_engine(exc) and not any(
        _stopped_on_a_raise(tb) and not _in_the_engine(tb) for tb in _entries(exc)[:-1]
    )


def worded_by_the_engine(exc: BaseException) -> bool:
    """Whether a ``raise`` statement in this package's own code raised ``exc``, so an engine author
    wrote its text.

    It reads the instruction the innermost frame stopped on, because a builtin called from engine
    code leaves the same frame with a call there instead, and it holds to
    :func:`raised_only_by_the_engine`. It proves who wrote the text, not what the text holds: a
    ``raise`` can interpolate a value or another exception's text. Nor does it prove what prints:
    the module docstring says why."""
    return raised_only_by_the_engine(exc) and _stopped_on_a_raise(_entries(exc)[-1])
