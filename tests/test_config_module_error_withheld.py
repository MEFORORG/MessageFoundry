# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A config module's own exception text is withheld from the loader's diagnostic (vault BACKLOG #3249).

``_exec_module`` used to wrap whatever a config module raised as ``error loading config module
<file>: <exception text>``, and pass a ``WiringError`` the module raised itself through untouched. That
text is author code's, and can carry any value the module held, and it reaches at least
``messagefoundry validate`` and ``check`` output (so CI logs), the reload WARNING and the
``POST /connections/{name}/flag`` 409. The loader now names the exception TYPE and the line in the
config module instead. A ``WiringError`` raised inside ``messagefoundry`` is the engine's own wording
and keeps its text, less the whole text of any foreign exception it wraps (vault BACKLOG #3765).

Every planted string is assembled at run time, so no committed literal looks like a secret."""

from __future__ import annotations

import inspect
import logging
import signal
import subprocess
import sys
import textwrap
from collections.abc import AsyncIterator, Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType

import httpx
import pytest

import messagefoundry
from messagefoundry.config import wiring
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import WiringError, load_config, validate_config
from messagefoundry.exception_origin import raised_by_the_engine, worded_by_the_engine
from messagefoundry.pipeline import Engine

#: Assembled at run time: the text a config module raises, which must never be echoed.
NEEDLE = "-".join(["planted", "module", "text", "7f3a"])


def _write(d: Path, name: str, body: str) -> Path:
    path = d / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def _messages(d: Path) -> list[str]:
    return [x.message for x in validate_config(d, allow_empty=True)]


@pytest.mark.parametrize("exc_type", ["RuntimeError", "KeyError", "ValueError"])
def test_a_module_exception_names_its_type_and_line_not_its_text(
    tmp_path: Path, exc_type: str
) -> None:
    _write(tmp_path, "feed.py", f"x = 1\n\nraise {exc_type}({NEEDLE!r})\n")
    (msg,) = _messages(tmp_path)
    assert NEEDLE not in msg
    assert msg.startswith("error loading config module feed.py: ")
    assert exc_type in msg and "line 3" in msg and "withheld" in msg


def test_a_syntax_error_names_its_line(tmp_path: Path) -> None:
    _write(tmp_path, "feed.py", f"a = 1\nb = (\nc = {NEEDLE!r}\n")
    (msg,) = _messages(tmp_path)
    assert NEEDLE not in msg
    assert "SyntaxError at line 2" in msg  # the unclosed "(" opens on line 2


def test_a_wiring_error_the_module_raises_itself_is_withheld(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "feed.py",
        f"""
        from messagefoundry.config.wiring import WiringError

        raise WiringError({NEEDLE!r})
        """,
    )
    (msg,) = _messages(tmp_path)
    assert NEEDLE not in msg
    assert "WiringError" in msg and "line 4" in msg


def test_an_exception_from_a_helper_module_is_withheld_and_names_the_helper(
    tmp_path: Path,
) -> None:
    # The deepest frame in the config directory is the helper's, so the helper is the file named.
    _write(tmp_path, "_helper.py", f"def boom():\n    raise RuntimeError({NEEDLE!r})\n")
    _write(tmp_path, "feed.py", "from _helper import boom\n\nboom()\n")
    (msg,) = _messages(tmp_path)
    assert NEEDLE not in msg
    assert "feed.py: RuntimeError in _helper.py at line 2" in msg


def test_a_relative_config_dir_still_names_the_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The import machinery records an absolute filename; the loader compares resolved paths.
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    _write(cfg, "feed.py", f"x = 1\nraise RuntimeError({NEEDLE!r})\n")
    monkeypatch.chdir(tmp_path)
    (msg,) = _messages(Path("cfg"))
    assert "RuntimeError at line 2" in msg


@pytest.mark.parametrize(
    ("body", "names"),
    [
        ("import mefor_no_such_module_3249\n", "'mefor_no_such_module_3249'"),
        ("from json import mefor_no_such_name_3249\n", "'json', 'mefor_no_such_name_3249'"),
        ("x = mefor_undefined_3249\n", "'mefor_undefined_3249'"),
        ("from _hh import mefor_missing_3249\n", "'_hh', 'mefor_missing_3249'"),
    ],
    ids=["module", "from-import", "name", "helper-from-import"],
)
def test_an_import_or_name_error_keeps_the_identifier(
    tmp_path: Path, body: str, names: str
) -> None:
    # An identifier from the SOURCE is not a value, and it is the actionable half.
    _write(tmp_path, "_hh.py", "X = 1\n")
    _write(tmp_path, "feed.py", body)
    (msg,) = _messages(tmp_path)
    assert f"naming {names}" in msg and "line 1" in msg


def test_the_withheld_text_is_not_chained_either(tmp_path: Path) -> None:
    # A rendered traceback (a log.exception on a reload) would print a chained cause in full.
    _write(tmp_path, "feed.py", f"raise RuntimeError({NEEDLE!r})\n")
    with pytest.raises(WiringError) as ei:
        load_config(tmp_path)
    assert ei.value.__cause__ is None and ei.value.__context__ is None


def test_an_engine_wiring_error_passes_through_unchanged(tmp_path: Path) -> None:
    # Raised inside messagefoundry, so the wording is the engine's: it names the connection, which is
    # the diagnostic an author needs, and nothing the module computed.
    _write(
        tmp_path,
        "feed.py",
        """
        from messagefoundry import MLLP, outbound

        outbound("OB_DUP", MLLP(host="127.0.0.1", port=2575))
        outbound("OB_DUP", MLLP(host="127.0.0.1", port=2575))
        """,
    )
    (msg,) = _messages(tmp_path)
    assert "OB_DUP" in msg and "withheld" not in msg


def test_load_config_withholds_the_text_too(tmp_path: Path) -> None:
    # The route the reload WARNING and the flag write's validate-before-persist go through.
    _write(tmp_path, "feed.py", f"raise RuntimeError({NEEDLE!r})\n")
    with pytest.raises(WiringError) as ei:
        load_config(tmp_path)
    assert NEEDLE not in str(ei.value)
    assert "RuntimeError" in str(ei.value) and "line 1" in str(ei.value)


# --- the connection-flag 409 (vault PR 2297's amendment to #3249) -----------------------------------

_LOGIC_PY = """
import pathlib

from messagefoundry import Send, handler, router

# Trips only once the test drops the marker, so the engine loads clean and the flag write's own
# validate-before-persist is the load that fails.
if (pathlib.Path(__file__).parent / "_trip").exists():
    raise RuntimeError({needle!r})

@router("r")
def route(msg):
    return ["h"]

@handler("h")
def handle(msg):
    return Send("OB_TOML", msg)
"""

_CONNECTIONS_TOML = """
[[inbound]]
name = "IB_TOML"
transport = "mllp"
router = "r"
[inbound.settings]
port = 2611

[[outbound]]
name = "OB_TOML"
transport = "mllp"
[outbound.settings]
host = "127.0.0.1"
port = 2711
"""


@pytest.fixture
async def toml_engine(tmp_path: Path) -> AsyncIterator[Engine]:
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    _write(cfg, "logic.py", _LOGIC_PY.format(needle=NEEDLE))
    _write(cfg, "connections.toml", _CONNECTIONS_TOML)
    eng = await Engine.create(
        tmp_path / "flag.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    eng.add_registry(load_config(cfg))
    try:
        yield eng
    finally:
        await eng.stop()


async def test_the_flag_route_409_withholds_the_module_text(
    toml_engine: Engine, tmp_path: Path
) -> None:
    from messagefoundry.api import create_app
    from tests.test_connection_audit_writes import _deployer, _login

    service = await _deployer(toml_engine)
    (tmp_path / "cfg" / "_trip").write_text("", encoding="utf-8")
    transport = httpx.ASGITransport(app=create_app(toml_engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c)
        r = await c.post(
            "/connections/OB_TOML/flag", json={"direction": "outbound", "flagged": True}, headers=h
        )
    assert r.status_code == 409, r.text
    assert NEEDLE not in r.text
    assert "RuntimeError" in r.text


def test_a_name_computed_at_run_time_is_withheld(tmp_path: Path) -> None:
    # getattr/import_module put a RUNTIME value in .name, which the source line does not spell.
    _write(tmp_path, "feed.py", f"import os\nv = {NEEDLE.replace('-', '_')!r}\ngetattr(os, v)\n")
    (msg,) = _messages(tmp_path)
    assert "AttributeError at line 3" in msg
    assert NEEDLE.replace("-", "_") not in msg and "naming" not in msg


def test_an_odd_syntax_error_does_not_escape(tmp_path: Path) -> None:
    # A module can raise SyntaxError itself, with a non-str filename and a non-int line.
    _write(tmp_path, "feed.py", f"raise SyntaxError('x', (123, {NEEDLE!r}, 1, 't'))\n")
    (msg,) = _messages(tmp_path)
    assert NEEDLE not in msg and "SyntaxError at line 1" in msg


# --- the Lander's send-back of PR 2370 (01:19Z): each path that still leaked or lost a name ---------

#: Assembled at run time, and an identifier, so it can sit in ``.name`` and in source.
IDENT = "_".join(["mefor", "planted", "ident", "3249"])


def _runtime_spelling(ident: str) -> str:
    """A Python expression that builds ``ident`` at run time, spelling it in no single token."""
    head, tail = ident[:6], ident[6:]
    return f"{head!r} + {tail!r}"


def test_a_stale_cached_source_line_does_not_vouch_for_a_run_time_name(tmp_path: Path) -> None:
    # The first load spells the identifier on line 3, so it is named, and its line is cached. After
    # an edit the same line computes it; a stale line must not vouch for the run-time value.
    _write(tmp_path, "feed.py", f"import os\nv = 1\nos.{IDENT}\n")
    (first,) = _messages(tmp_path)
    assert f"naming {IDENT!r}" in first
    _write(tmp_path, "feed.py", f"import os\nv = {_runtime_spelling(IDENT)}\ngetattr(os, v)\n")
    (second,) = _messages(tmp_path)
    assert "AttributeError at line 3" in second
    assert IDENT not in second


def test_the_textless_cause_carries_no_name_either(tmp_path: Path) -> None:
    # import_module puts a RUN-TIME value in .name; the message withholds it, so must the cause.
    _write(
        tmp_path,
        "feed.py",
        f"import importlib\nimportlib.import_module({_runtime_spelling(IDENT)})\n",
    )
    with pytest.raises(WiringError) as ei:
        load_config(tmp_path)
    assert IDENT not in str(ei.value)
    cause = ei.value.__cause__
    assert isinstance(cause, ModuleNotFoundError)
    assert cause.name is None and IDENT not in repr(cause) and not cause.args


@pytest.mark.parametrize(
    "line",
    [
        f"{IDENT}x = getattr(os, v)",  # inside a longer identifier
        f"x = getattr(os, v) if {IDENT!r} else 0",  # inside a string literal
        f"x = getattr(os, v)  # {IDENT}",  # inside a comment
    ],
    ids=["identifier", "string", "comment"],
)
def test_a_run_time_name_inside_another_token_is_withheld(tmp_path: Path, line: str) -> None:
    _write(tmp_path, "feed.py", f"import os\nv = {_runtime_spelling(IDENT)}\n{line}\n")
    (msg,) = _messages(tmp_path)
    assert "AttributeError at line 3" in msg
    assert "naming" not in msg


def test_a_dotted_attribute_spelled_on_the_line_is_still_named(tmp_path: Path) -> None:
    _write(tmp_path, "feed.py", f"import os\nx = os.{IDENT}\n")
    (msg,) = _messages(tmp_path)
    assert f"naming {IDENT!r}" in msg


def test_a_helper_preload_reraise_names_the_helper_and_its_missing_module(tmp_path: Path) -> None:
    # feed_a guards the optional helper, so its failure is recorded; feed_b imports it unguarded,
    # and the preload re-raises the recorded failure. Main named the missing module here.
    _write(tmp_path, "_opt.py", f"import {IDENT}\n")
    _write(
        tmp_path,
        "feed_a.py",
        """
        def f():
            try:
                import _opt
            except ImportError:
                return None
        """,
    )
    _write(tmp_path, "feed_b.py", "def g():\n    import _opt\n")
    msgs = _messages(tmp_path)
    (msg,) = [m for m in msgs if "feed_b" in m or "_opt" in m]
    assert "_opt.py" in msg and "feed_b.py" in msg
    assert f"naming {IDENT!r}" in msg and "line 1" in msg
    with pytest.raises(WiringError) as ei:
        load_config(tmp_path)
    # The engine-shard preflight reads the cause's type for its helper advice.
    assert isinstance(ei.value.__cause__, ImportError)
    assert ei.value.__cause__.name is None


@pytest.mark.parametrize("pseudo", ["<string>", "<frozen mefor_3249>"])
def test_a_pseudo_filename_frame_is_never_resolved_against_the_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pseudo: str
) -> None:
    # Run from the config dir, `<string>` resolved to a file in it and was named as the failing file.
    _write(
        tmp_path,
        "feed.py",
        f"x = 1\nexec(compile('raise RuntimeError(1)', {pseudo!r}, 'exec'))\n",
    )
    monkeypatch.chdir(tmp_path)
    (msg,) = _messages(Path("."))
    assert pseudo not in msg
    assert "RuntimeError at line 2" in msg


def test_a_name_on_a_later_line_of_a_parenthesized_import_is_named(tmp_path: Path) -> None:
    # ruff format wraps a long import, and the traceback reports the statement's first line.
    _write(tmp_path, "feed.py", f"from json import (\n    dumps,\n    {IDENT},\n)\n")
    (msg,) = _messages(tmp_path)
    assert f"naming 'json', {IDENT!r}" in msg


def test_a_symlinked_helper_keeps_its_line_and_name(tmp_path: Path) -> None:
    # The Kubernetes ConfigMap layout: every config file is a symlink into a dated folder.
    real = tmp_path / "data"
    real.mkdir()
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    _write(real, "_opt.py", f"import {IDENT}\n")
    _write(
        real,
        "feed_a.py",
        "def f():\n    try:\n        import _opt\n    except ImportError:\n        pass\n",
    )
    _write(real, "feed_b.py", "def g():\n    import _opt\n")
    try:
        for name in ("_opt.py", "feed_a.py", "feed_b.py"):
            (cfg / name).symlink_to(real / name)
    except OSError:
        pytest.skip("this account cannot create symlinks")
    msgs = _messages(cfg)
    assert any(f"at line 1 naming {IDENT!r}" in m and "_opt.py" in m for m in msgs), msgs


def test_a_helper_symlinked_from_another_folder_is_named(tmp_path: Path) -> None:
    # A real config module beside one shared helper linked in from elsewhere.
    shared = tmp_path / "shared"
    shared.mkdir()
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    _write(shared, "_common.py", "x = 1\nraise RuntimeError(1)\n")
    _write(cfg, "feed.py", "import _common\n")
    try:
        (cfg / "_common.py").symlink_to(shared / "_common.py")
    except OSError:
        pytest.skip("this account cannot create symlinks")
    (msg,) = _messages(cfg)
    assert "RuntimeError in _common.py at line 2" in msg


# --- what is left of the withholding (vault BACKLOG #3765) ------------------------------------------


def _load_error(d: Path) -> WiringError:
    with pytest.raises(WiringError) as ei:
        load_config(d)
    return ei.value


# Item 2: a factory typo names the bad keyword, and only a keyword the source spells.


@pytest.mark.parametrize(
    ("call", "line"),
    [
        ("MLLP(prot=2575)", 3),
        ("MLLP(\n    host='h',\n    prot=2575,\n)", 3),
    ],
    ids=["one-line", "wrapped"],
)
def test_a_factory_keyword_typo_names_the_keyword(tmp_path: Path, call: str, line: int) -> None:
    _write(tmp_path, "feed.py", f"from messagefoundry import MLLP\n\n{call}\n")
    (msg,) = _messages(tmp_path)
    assert f"TypeError at line {line} naming 'prot'" in msg


def test_a_keyword_given_twice_is_named(tmp_path: Path) -> None:
    _write(tmp_path, "feed.py", "def f(a):\n    pass\n\nf(1, a=2)\n")
    (msg,) = _messages(tmp_path)
    assert "TypeError at line 4 naming 'a'" in msg


def test_a_run_time_keyword_is_withheld(tmp_path: Path) -> None:
    # The call's text is the real one, and its keyword is a value the source never spells.
    _write(
        tmp_path,
        "feed.py",
        f"from messagefoundry import MLLP\n\nk = {_runtime_spelling(IDENT)}\nMLLP(**{{k: 1}})\n",
    )
    (msg,) = _messages(tmp_path)
    assert "TypeError at line 4" in msg
    assert IDENT not in msg and "naming" not in msg


@pytest.mark.parametrize(
    "line",
    [
        f"raise TypeError(\"f() got an unexpected keyword argument '{IDENT}'\")",
        f"class T(TypeError):\n    pass\n\n{IDENT} = 1\nraise T(\"argument '{IDENT}'\", {IDENT})",
    ],
    ids=["in-a-string", "subclass"],
)
def test_a_type_error_the_module_words_itself_names_nothing(tmp_path: Path, line: str) -> None:
    _write(tmp_path, "feed.py", f"{line}\n")
    (msg,) = _messages(tmp_path)
    assert IDENT not in msg and "naming" not in msg


# Item 1: a refusal keeps only what a `raise` in the engine wrote.

_ENGINE_SOURCE = """
from messagefoundry.config.wiring import WiringError

def wraps_a_builtin(value):
    try:
        int(value)
    except ValueError as exc:
        raise WiringError(f"inbound 'IB_3765': {exc}") from exc

def wraps_its_repr(value):
    try:
        int(value)
    except ValueError as exc:
        raise ValueError(f"knob: {exc!r}") from exc

def calls_a_builtin(value):
    return int(value)

def hides_a_builtin(value):
    try:
        int(value)
    except ValueError:
        raise WiringError("knob is not a number (value withheld)") from None

def wraps_author_code(fn):
    try:
        fn()
    except Exception as exc:
        raise WiringError(f"callback failed: {exc}") from exc

def wraps_a_failed_import():
    raise WiringError("an extra is missing") from ModuleNotFoundError("planted")

def wraps_a_held_error(value):
    try:
        int(value)
    except ValueError as exc:
        held = exc
    carrier = RuntimeError("dial failed")
    carrier.reason = held
    raise WiringError(f"wrapped: {held}") from carrier

def words_its_own():
    raise ValueError("engine wording 3765")

def wraps_its_own():
    try:
        words_its_own()
    except ValueError as exc:
        raise WiringError(f"wrapped: {exc}") from exc

def refuses():
    raise WiringError("engine refusal 3765")

def wraps_a_group_member(value):
    try:
        int(value)
    except ValueError as exc:
        member = exc
    raise WiringError(f"wrapped: {member}") from ExceptionGroup("several", [member])

def wraps_a_noted_one(note):
    try:
        try:
            refuses()
        except WiringError as inner:
            inner.add_note(note)
            raise
    except WiringError as exc:
        raise WiringError(f"wrapped: {exc}") from exc

def raises_this_type(kind):
    raise kind()
"""

#: Where the frame rule looks. The probe has no file on disk: only its code's file name is read.
_ENGINE_DIR = Path(messagefoundry.__file__).parent


@pytest.fixture
def engine_probe(monkeypatch: pytest.MonkeyPatch) -> str:
    """A module whose frames count as the engine's, to call with a planted value. The rule reads
    its compiled file name and its module name, so it needs no file under ``messagefoundry``."""
    name = "messagefoundry._probe_3765"
    module = ModuleType(name)
    exec(compile(_ENGINE_SOURCE, str(_ENGINE_DIR / "_probe_3765.py"), "exec"), module.__dict__)
    monkeypatch.setitem(sys.modules, name, module)
    return name


def _calling(name: str, call: str) -> str:
    return f"import {name} as probe\n\nprobe.{call}\n"


@pytest.mark.parametrize(
    ("call", "kept"),
    [
        (f"wraps_a_builtin({NEEDLE!r})", "inbound 'IB_3765': [ValueError text withheld]"),
        (
            f"wraps_its_repr({NEEDLE!r})",
            "error loading config module feed.py: knob: [ValueError text withheld]",
        ),
    ],
    ids=["wiring-error", "plain-error"],
)
def test_a_refusal_wrapping_a_builtin_loses_the_builtins_text(
    tmp_path: Path, engine_probe: str, call: str, kept: str
) -> None:
    _write(tmp_path, "feed.py", _calling(engine_probe, call))
    err = _load_error(tmp_path)
    assert str(err) == kept
    assert err.__cause__ is None and err.__context__ is None


def test_a_builtin_failing_in_engine_code_is_withheld(tmp_path: Path, engine_probe: str) -> None:
    # int() ends in the engine's frame, and its text is the runtime's, quoting the value.
    _write(tmp_path, "feed.py", _calling(engine_probe, f"calls_a_builtin({NEEDLE!r})"))
    err = _load_error(tmp_path)
    assert NEEDLE not in str(err)
    assert "ValueError at line 3" in str(err) and "withheld" in str(err)
    assert err.__cause__ is None and err.__context__ is None


def test_a_refusal_hiding_a_builtin_with_from_none_drops_it_from_the_chain(
    tmp_path: Path, engine_probe: str
) -> None:
    # `from None` hides the context from the printer. A reader of __context__ still gets the value.
    _write(tmp_path, "feed.py", _calling(engine_probe, f"hides_a_builtin({NEEDLE!r})"))
    err = _load_error(tmp_path)
    assert str(err) == "knob is not a number (value withheld)"
    assert err.__cause__ is None and err.__context__ is None


def test_a_refusal_wrapping_author_code_loses_the_authors_text(
    tmp_path: Path, engine_probe: str
) -> None:
    body = f"def boom():\n    raise KeyError({NEEDLE!r})\n\nprobe.wraps_author_code(boom)\n"
    _write(tmp_path, "feed.py", f"import {engine_probe} as probe\n\n{body}")
    assert str(_load_error(tmp_path)) == "callback failed: [KeyError text withheld]"


def test_an_author_str_that_raises_withholds_the_whole_refusal(
    tmp_path: Path, engine_probe: str
) -> None:
    # The wrap itself runs __str__, so the failing str is what the loader finds, with a value on it.
    body = (
        "class Bad(Exception):\n"
        "    def __str__(self):\n"
        f"        raise RuntimeError({NEEDLE!r})\n\n"
        "def boom():\n"
        "    raise Bad()\n\n"
        "probe.wraps_author_code(boom)\n"
    )
    _write(tmp_path, "feed.py", f"import {engine_probe} as probe\n\n{body}")
    assert NEEDLE not in str(_load_error(tmp_path))


@pytest.mark.parametrize(
    "member",
    [
        f"def __str__(self):\n        raise BaseException({NEEDLE!r})",
        f"@property\n    def reason(self):\n        raise RuntimeError({NEEDLE!r})",
        f"def __getattr__(self, name):\n        raise LookupError({NEEDLE!r})",
    ],
    ids=["str-base-exception", "reason-property", "getattr"],
)
def test_a_foreign_context_that_faults_when_read_withholds_the_refusal(
    tmp_path: Path, engine_probe: str, member: str
) -> None:
    # Reading the chain runs the author's code, on an exception the module was merely handling.
    body = (
        f"class Bad(Exception):\n    {member}\n\n"
        "try:\n    raise Bad()\nexcept Bad:\n    probe.words_its_own()\n"
    )
    _write(tmp_path, "feed.py", f"import {engine_probe} as probe\n\n{body}")
    err = _load_error(tmp_path)
    assert NEEDLE not in str(err)
    assert err.__cause__ is None and err.__context__ is None


def test_a_rebuilt_refusal_keeps_a_textless_import_cause(tmp_path: Path, engine_probe: str) -> None:
    # The engine-shard preflight reads the cause's type for its helper advice.
    _write(tmp_path, "feed.py", _calling(engine_probe, "wraps_a_failed_import()"))
    err = _load_error(tmp_path)
    assert str(err) == "an extra is missing"
    assert isinstance(err.__cause__, ModuleNotFoundError)
    assert not err.__cause__.args


@pytest.mark.parametrize(
    ("call", "text"),
    [
        ("words_its_own()", "error loading config module feed.py: engine wording 3765"),
        ("wraps_its_own()", "wrapped: engine wording 3765"),
    ],
    ids=["own-text", "own-wrap"],
)
def test_engine_wording_is_kept_with_its_chain(
    tmp_path: Path, engine_probe: str, call: str, text: str
) -> None:
    _write(tmp_path, "feed.py", _calling(engine_probe, call))
    err = _load_error(tmp_path)
    assert str(err) == text
    assert isinstance(err.__cause__, ValueError)


#: Connection factories, read whole below: a parameter added later is read too.
_FACTORIES = [
    "DatabasePoll",
    "MLLP",
    "Tcp",
    "X12",
    "Http",
    "File",
    "Timer",
    "Loopback",
    "PassThrough",
    "Rest",
    "Direct",
    "Email",
    "SMTP",
    "FHIR",
    "DICOM",
    "DICOMweb",
    "Database",
    "Soap",
    "Sftp",
    "Ftp",
    "FileRef",
    "DatabaseRef",
    "FhirToken",
]

#: A dict KEY the refusal names. ``body_secrets`` keys are template tokens, and the refusal is about
#: the value under one, which it does not quote.
_QUOTES_A_NAME: frozenset[tuple[str, str, type]] = frozenset({("Soap", "body_secrets", dict)})


def _required_arguments(factory: Callable[..., object]) -> dict[str, object]:
    samples: dict[str, object] = {
        "port": 2575,
        "host": "127.0.0.1",
        "statement": "select 1",
        "poll_statement": "select a from t",
    }
    return {
        p.name: samples.get(p.name, "x")
        for p in inspect.signature(factory).parameters.values()
        if p.default is inspect.Parameter.empty and p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL)
    }


@pytest.mark.parametrize("factory_name", _FACTORIES)
def test_no_factory_refusal_quotes_a_planted_value(factory_name: str) -> None:
    # A refusal that sits behind another one is not reached here, so the first refusal is the floor
    # of what this reads, and the control call shows the required arguments raise no refusal of it.
    factory = getattr(messagefoundry, factory_name)
    required = _required_arguments(factory)
    factory(**required)
    for parameter in inspect.signature(factory).parameters.values():
        if parameter.kind in (parameter.VAR_KEYWORD, parameter.VAR_POSITIONAL):
            continue
        for value in (NEEDLE, NEEDLE.encode(), [NEEDLE], {NEEDLE: [NEEDLE]}):
            if (factory_name, parameter.name, type(value)) in _QUOTES_A_NAME:
                continue
            try:
                factory(**{**required, parameter.name: value})
            except (ValueError, TypeError) as exc:
                assert NEEDLE not in str(exc), (parameter.name, type(value))


@pytest.mark.parametrize(
    ("call", "wording"),
    [
        (f"Http(port=1, intake_auth={NEEDLE!r})", "Http intake_auth must be one of"),
        (f"Http(port=1, intake_auth_health={NEEDLE!r})", "must be 'require' or 'allow'"),
        (f"Rest(url='https://x.example/', tls_ca_pin={NEEDLE!r})", "must be a SHA-256 hex digest"),
        (
            f"Rest(url='https://x.example/', tls_ca_pin='md5{NEEDLE}:ab')",
            "names a digest this release does not support",
        ),
        (
            f"Http(port=1, intake_client_subjects={{{NEEDLE!r}: ['x']}})",
            "is not an RFC 4514 distinguished name",
        ),
        (
            f"inbound('IB', MLLP(port=1), router='r', source_ip_allowlist=[{NEEDLE!r}])",
            "source_ip_allowlist entry 0 is not a valid",
        ),
        (
            f"inbound('IB', MLLP(port=1), router='r', content_type={NEEDLE!r})",
            "invalid content_type, value withheld",
        ),
        (
            f"outbound('OB', Soap(url='https://x.example/', ws_password_type={NEEDLE!r}))",
            "ws_password_type must be 'text'",
        ),
        (
            f"Http(port=1, reply_from='OB', reply_on_timeout={NEEDLE!r})",
            "reply_on_timeout must be '504' or '202'",
        ),
        (
            f"Http(port=1, reply_from='OB', reply_on_empty={NEEDLE!r})",
            "reply_on_empty must be '204' or '200'",
        ),
        (
            f"Http(port=1, reply_from='OB', reply_content_type={NEEDLE!r})",
            "reply_content_type must be 'passthrough' or a MIME type",
        ),
        (
            "Http(port=1, tls=True, tls_ca_file='ca', intake_auth='mtls_subject', "
            f"intake_client_subjects={{'CN=Acme CA': [{NEEDLE!r}]}})",
            "entries must be qualified",
        ),
    ],
    ids=[
        "intake-auth",
        "intake-auth-health",
        "pin-shape",
        "pin-digest",
        "issuer",
        "allowlist",
        "content-type",
        "ws-password-type",
        "reply-on-timeout",
        "reply-on-empty",
        "reply-content-type",
        "unqualified-subject",
    ],
)
def test_a_measured_refusal_fires_without_its_value(
    tmp_path: Path, call: str, wording: str
) -> None:
    _write(
        tmp_path,
        "feed.py",
        f"from messagefoundry import Http, MLLP, Rest, Soap, inbound, outbound\n\n{call}\n",
    )
    (msg,) = _messages(tmp_path)
    assert wording in msg and NEEDLE not in msg


@pytest.mark.parametrize(
    ("call", "wording"),
    [
        (f"_check_source_ip_allowlist('IB', True, [{NEEDLE!r}])", "entry 0 is not a valid"),
        (f"_coerce_content_type('IB', {NEEDLE!r})", "invalid content_type"),
    ],
    ids=["allowlist", "content-type"],
)
def test_a_refusal_shared_with_toml_keeps_the_value_off_its_chain(call: str, wording: str) -> None:
    # connections.toml reaches these without `_exec_module`, so nothing strips the chain for it.
    with pytest.raises(WiringError, match=wording) as ei:
        eval(call, vars(wiring))
    assert ei.value.__cause__ is None and ei.value.__context__ is None


def test_a_missing_code_set_is_named_and_nothing_is_on_the_chain(tmp_path: Path) -> None:
    # The refusal names the set on purpose, so no lookup's KeyError may sit under it to be replaced.
    _write(tmp_path, "feed.py", "from messagefoundry import code_set\n\ncode_set('nope')\n")
    err = _load_error(tmp_path)
    assert "no such code set 'nope'" in str(err) and "withheld" not in str(err)


def test_an_inner_error_a_library_holds_as_an_attribute_is_foreign_too(
    tmp_path: Path, engine_probe: str
) -> None:
    # urllib3 keeps one in `reason`, where neither __cause__ nor __context__ points at it.
    _write(tmp_path, "feed.py", _calling(engine_probe, f"wraps_a_held_error({NEEDLE!r})"))
    assert str(_load_error(tmp_path)) == "wrapped: [ValueError text withheld]"


def test_a_refusal_quoting_an_exception_group_member_loses_its_text(
    tmp_path: Path, engine_probe: str
) -> None:
    _write(tmp_path, "feed.py", _calling(engine_probe, f"wraps_a_group_member({NEEDLE!r})"))
    err = _load_error(tmp_path)
    assert str(err) == "wrapped: [ValueError text withheld]"
    assert err.__cause__ is None and err.__context__ is None


def test_a_note_a_module_adds_to_a_refusal_does_not_ride_out(
    tmp_path: Path, engine_probe: str
) -> None:
    # A printed traceback shows a note and str() does not, so a check of the text alone would pass.
    body = (
        "try:\n    probe.refuses()\n"
        f"except Exception as e:\n    e.add_note({NEEDLE!r})\n    raise\n"
    )
    _write(tmp_path, "feed.py", f"import {engine_probe} as probe\n\n{body}")
    err = _load_error(tmp_path)
    assert str(err) == "engine refusal 3765"
    assert not hasattr(err, "__notes__")
    assert err.__cause__ is None and err.__context__ is None


def test_a_note_on_a_link_of_a_kept_chain_does_not_ride_out(
    tmp_path: Path, engine_probe: str
) -> None:
    _write(tmp_path, "feed.py", _calling(engine_probe, f"wraps_a_noted_one({NEEDLE!r})"))
    err = _load_error(tmp_path)
    assert str(err) == "wrapped: engine refusal 3765"
    assert err.__cause__ is None and err.__context__ is None


#: Classes whose instance faults when the loader reads it. isinstance() falls back to ``__class__``.
_FAULTS_WHEN_READ = {
    "getattribute": "class Bad(Exception):\n    def __getattribute__(self, name):\n"
    f"        raise RuntimeError({NEEDLE!r})\n",
    "class-property": "class Bad(Exception):\n    @property\n    def __class__(self):\n"
    f"        raise RuntimeError({NEEDLE!r})\n",
    "import-error": "class Bad(ImportError):\n    def __getattribute__(self, name):\n"
    f"        raise RuntimeError({NEEDLE!r})\n",
}

#: Classes that fault, or hold text, only where ``type(exc).__name__`` or its result is used.
_FAULTS_IN_THE_NAME = {
    "metaclass": "class Meta(type):\n    def __getattribute__(cls, name):\n"
    f"        raise RuntimeError({NEEDLE!r})\n\n"
    "class Bad(Exception, metaclass=Meta):\n    pass\n",
    "metaclass-name": "class Meta(type):\n    @property\n    def __name__(cls):\n"
    f"        return {NEEDLE!r}\n\n"
    "class Bad(Exception, metaclass=Meta):\n    pass\n",
    "str-subclass-name": "class Name(str):\n"
    f"    def __format__(self, spec):\n        raise RuntimeError({NEEDLE!r})\n"
    f"    def __add__(self, other):\n        raise RuntimeError({NEEDLE!r})\n\n"
    "Bad = type(Name('Bad'), (Exception,), {})\n",
}


def _assert_no_needle_on(err: WiringError) -> None:
    assert NEEDLE not in str(err)
    assert err.__context__ is None
    assert err.__cause__ is None or not err.__cause__.args


@pytest.mark.parametrize(
    "bad_class",
    [*_FAULTS_WHEN_READ.values(), *_FAULTS_IN_THE_NAME.values()],
    ids=[*_FAULTS_WHEN_READ, *_FAULTS_IN_THE_NAME],
)
def test_a_module_class_that_faults_when_read_cannot_escape_the_loader(
    tmp_path: Path, bad_class: str
) -> None:
    _write(tmp_path, "feed.py", f"{bad_class}\nraise Bad()\n")
    err = _load_error(tmp_path)
    _assert_no_needle_on(err)
    assert "feed.py: Bad" in str(err) and "withheld" in str(err)


@pytest.mark.parametrize("bad_class", _FAULTS_WHEN_READ.values(), ids=_FAULTS_WHEN_READ.keys())
def test_an_engine_raised_class_that_faults_when_read_cannot_escape_the_loader(
    tmp_path: Path, engine_probe: str, bad_class: str
) -> None:
    body = f"import {engine_probe} as probe\n\n{bad_class}\nprobe.raises_this_type(Bad)\n"
    _write(tmp_path, "feed.py", body)
    err = _load_error(tmp_path)
    _assert_no_needle_on(err)
    assert "feed.py: Bad" in str(err) and "withheld" in str(err)


@pytest.mark.parametrize("bad_class", _FAULTS_IN_THE_NAME.values(), ids=_FAULTS_IN_THE_NAME.keys())
def test_an_engine_raised_class_keeps_its_wording_when_only_its_name_faults(
    tmp_path: Path, engine_probe: str, bad_class: str
) -> None:
    # An engine `raise` of a class with no text: the loader keeps that, and never reads the name.
    body = f"import {engine_probe} as probe\n\n{bad_class}\nprobe.raises_this_type(Bad)\n"
    _write(tmp_path, "feed.py", body)
    assert str(_load_error(tmp_path)) == "error loading config module feed.py: "


def test_a_class_answering_as_a_wiring_error_is_not_one(tmp_path: Path, engine_probe: str) -> None:
    bad_class = (
        "from messagefoundry.config.wiring import WiringError\n\n"
        "class Bad(Exception):\n    __class__ = WiringError\n"
    )
    body = f"import {engine_probe} as probe\n\n{bad_class}\nprobe.raises_this_type(Bad)\n"
    _write(tmp_path, "feed.py", body)
    assert type(_load_error(tmp_path)) is WiringError


#: A refusal a module caught, given the module's class. The frame stays the engine's raise, so this
#: needs no probe, and what prints is that class's text.
_RECLASSED = (
    "from messagefoundry import Http\n"
    "from messagefoundry.config.wiring import WiringError\n\n"
    "class Bad(WiringError):\n    def __str__(self):\n        {str_body}\n\n"
    "try:\n"
    "    Http(port=8080, reply_from='OB_X', reply_on_timeout='500')\n"
    "except WiringError as exc:\n"
    "    exc.__class__ = Bad\n"
    "    raise\n"
)


@pytest.mark.parametrize(
    "str_body",
    [f"return {NEEDLE!r}", f"raise OSError({NEEDLE!r})", f"raise BaseException({NEEDLE!r})"],
    ids=["returns-the-value", "faults", "faults-as-base-exception"],
)
def test_a_caught_refusal_given_a_class_with_its_own_str_is_withheld(
    tmp_path: Path, str_body: str
) -> None:
    # The class's __str__ writes what prints, whoever raised the instance, so it cannot stand.
    _write(tmp_path, "feed.py", _RECLASSED.format(str_body=str_body))
    (msg,) = _messages(tmp_path)
    assert NEEDLE not in msg
    assert "feed.py: Bad at line" in msg and "withheld" in msg
    err = _load_error(tmp_path)
    assert type(err) is WiringError
    assert err.__cause__ is None and err.__context__ is None


@pytest.mark.parametrize("base", ["WiringError", "ValueError", "MemoryError"], ids=str.lower)
def test_an_engine_raised_class_with_its_own_str_is_withheld(
    tmp_path: Path, engine_probe: str, base: str
) -> None:
    # MemoryError because a runtime limit is kept by its frame, no reason to read a class's text.
    bad_class = (
        "from messagefoundry.config.wiring import WiringError\n\n"
        f"class Bad({base}):\n    def __str__(self):\n        return {NEEDLE!r}\n"
    )
    body = f"import {engine_probe} as probe\n\n{bad_class}\nprobe.raises_this_type(Bad)\n"
    _write(tmp_path, "feed.py", body)
    err = _load_error(tmp_path)
    _assert_no_needle_on(err)
    assert "feed.py: Bad" in str(err) and "withheld" in str(err)


def test_a_context_with_its_own_str_is_foreign_even_from_an_engine_frame(
    tmp_path: Path, engine_probe: str
) -> None:
    # Left on the chain, a printed traceback would run that __str__.
    bad_class = f"class Bad(Exception):\n    def __str__(self):\n        return {NEEDLE!r}\n"
    body = (
        f"import {engine_probe} as probe\n\n{bad_class}\n"
        "try:\n    probe.raises_this_type(Bad)\nexcept Bad:\n    probe.words_its_own()\n"
    )
    _write(tmp_path, "feed.py", body)
    err = _load_error(tmp_path)
    assert str(err) == "error loading config module feed.py: engine wording 3765"
    assert err.__cause__ is None and err.__context__ is None


def test_a_class_with_its_own_format_cannot_write_the_diagnostic(
    tmp_path: Path, engine_probe: str
) -> None:
    bad_class = (
        f"class Bad(Exception):\n    def __format__(self, spec):\n        return {NEEDLE!r}\n"
    )
    body = f"import {engine_probe} as probe\n\n{bad_class}\nprobe.raises_this_type(Bad)\n"
    _write(tmp_path, "feed.py", body)
    assert NEEDLE not in str(_load_error(tmp_path))


def test_an_engine_subclass_of_wiring_error_stands_as_raised(
    tmp_path: Path, engine_probe: str
) -> None:
    # No __str__ of its own, so nothing prints but the builtin: an except clause can read the class.
    body = (
        "from messagefoundry.config.wiring import PortConflictError\n"
        f"import {engine_probe} as probe\n\nprobe.raises_this_type(PortConflictError)\n"
    )
    _write(tmp_path, "feed.py", body)
    assert type(_load_error(tmp_path)) is wiring.PortConflictError


def test_a_helper_left_to_its_guard_is_logged_by_its_real_type_name(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _write(
        tmp_path,
        "_opt.py",
        "class Meta(type):\n    @property\n    def __name__(cls):\n"
        f"        return {NEEDLE!r}\n\n"
        "class Bad(ImportError, metaclass=Meta):\n    pass\n\nraise Bad()\n",
    )
    body = "def later():\n    try:\n        import _opt\n    except ImportError:\n        pass\n"
    _write(tmp_path, "feed.py", body)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        assert _messages(tmp_path) == []
    assert "failed to load (Bad)" in caplog.text
    assert NEEDLE not in caplog.text


def test_an_engine_raised_class_whose_str_faults_cannot_escape_the_loader(
    tmp_path: Path, engine_probe: str
) -> None:
    # Text the engine would keep, so it is read outside any chain walk.
    bad_class = (
        f"class Bad(Exception):\n    def __str__(self):\n        raise OSError({NEEDLE!r})\n"
    )
    body = f"import {engine_probe} as probe\n\n{bad_class}\nprobe.raises_this_type(Bad)\n"
    _write(tmp_path, "feed.py", body)
    err = _load_error(tmp_path)
    assert NEEDLE not in str(err) and "withheld" in str(err)
    assert err.__cause__ is None and err.__context__ is None


def test_a_fault_reading_a_failure_is_logged_with_no_text(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    body = (
        "class Bad(Exception):\n    def __getattr__(self, name):\n"
        f"        raise BaseException({NEEDLE!r})\n\nraise Bad()\n"
    )
    _write(tmp_path, "feed.py", body)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        (msg,) = _messages(tmp_path)
    assert NEEDLE not in msg
    records = [r for r in caplog.records if "reading its failure raised" in r.getMessage()]
    assert records and "BaseException" in records[0].getMessage()
    assert NEEDLE not in caplog.text
    assert all(r.exc_info is None for r in records)


@pytest.mark.parametrize(
    "body",
    [
        f"__name__ = 'messagefoundry.x'\nraise ValueError({NEEDLE!r})\n",
        "from messagefoundry.config.wiring import WiringError\n"
        f"__name__ = 'messagefoundry.x'\nraise WiringError({NEEDLE!r})\n",
    ],
    ids=["value-error", "wiring-error"],
)
def test_a_module_that_renames_itself_is_not_engine_wording(tmp_path: Path, body: str) -> None:
    _write(tmp_path, "feed.py", body)
    (msg,) = _messages(tmp_path)
    assert NEEDLE not in msg and "withheld" in msg


# Item 4: whatever else a config module raises is a failed module, and carries no text.


@pytest.mark.parametrize(
    ("raised", "name"),
    [
        (f"BaseException({NEEDLE!r})", "BaseException"),
        (f"GeneratorExit({NEEDLE!r})", "GeneratorExit"),
        (f"asyncio.CancelledError({NEEDLE!r})", "CancelledError"),
        (f"Mine({NEEDLE!r})", "Mine"),
        (f"BaseExceptionGroup({NEEDLE!r}, [KeyboardInterrupt()])", "BaseExceptionGroup"),
        (f"Stop({NEEDLE!r})", "Stop"),
    ],
    ids=["plain", "generator-exit", "cancelled", "subclass", "group", "interrupt-subclass"],
)
def test_a_base_exception_is_a_refused_module_with_no_text(
    tmp_path: Path, raised: str, name: str
) -> None:
    _write(
        tmp_path,
        "feed.py",
        "import asyncio\n\nclass Mine(BaseException):\n    pass\n\n"
        f"class Stop(KeyboardInterrupt):\n    pass\n\nraise {raised}\n",
    )
    before = set(sys.modules)
    err = _load_error(tmp_path)
    assert NEEDLE not in str(err)
    assert f"feed.py: {name} at line 9" in str(err) and "withheld" in str(err)
    assert err.__cause__ is None and err.__context__ is None
    added = (sys.modules[m] for m in set(sys.modules) - before)
    assert not [m for m in added if getattr(m, "__file__", None) == str(tmp_path / "feed.py")]


def test_a_base_exception_from_a_helper_names_the_helper(tmp_path: Path) -> None:
    _write(tmp_path, "_helper.py", f"raise BaseException({NEEDLE!r})\n")
    _write(tmp_path, "feed.py", "import _helper\n")
    (msg,) = _messages(tmp_path)
    assert NEEDLE not in msg and "BaseException in _helper.py at line 1" in msg


def test_a_base_exception_does_not_stop_validate_reading_the_next_module(tmp_path: Path) -> None:
    _write(tmp_path, "a_feed.py", f"raise BaseException({NEEDLE!r})\n")
    _write(tmp_path, "b_feed.py", "raise RuntimeError('second')\n")
    assert [m.split(":")[0] for m in _messages(tmp_path)] == [
        "error loading config module a_feed.py",
        "error loading config module b_feed.py",
    ]


@pytest.mark.parametrize(
    "body",
    [
        "class Bad(Exception):\n"
        f"    def __getattr__(self, name):\n        raise BaseException({NEEDLE!r})\n\n"
        "raise Bad()\n",
        "class Bad(Exception):\n"
        f"    @property\n    def __traceback__(self):\n        raise RuntimeError({NEEDLE!r})\n\n"
        "raise Bad()\n",
    ],
    ids=["getattr-base-exception", "traceback-property"],
)
def test_a_module_cannot_carry_text_out_past_the_loaders_own_reads(
    tmp_path: Path, body: str
) -> None:
    _write(tmp_path, "feed.py", body)
    (msg,) = _messages(tmp_path)
    assert NEEDLE not in msg and "withheld" in msg


def _assert_bare(exc: BaseException) -> None:
    assert not exc.args and not hasattr(exc, "__notes__")
    assert exc.__cause__ is None and exc.__context__ is None


@pytest.mark.parametrize(
    "body",
    [
        "raise KeyboardInterrupt\n",
        f"raise KeyboardInterrupt({NEEDLE!r})\n",
        f"raise KeyboardInterrupt from ValueError({NEEDLE!r})\n",
        f"try:\n    raise ValueError({NEEDLE!r})\nexcept ValueError:\n    raise KeyboardInterrupt\n",
        f"e = KeyboardInterrupt()\ne.add_note({NEEDLE!r})\nraise e\n",
    ],
    ids=["bare", "with-text", "from", "in-handler", "with-note"],
)
def test_an_interrupt_stops_the_load_with_nothing_on_it(tmp_path: Path, body: str) -> None:
    # On the main thread code cannot be told from a signal, so all of these stop, with no text.
    _write(tmp_path, "feed.py", body)
    with pytest.raises(KeyboardInterrupt) as ei:
        load_config(tmp_path)
    _assert_bare(ei.value)


@pytest.mark.parametrize(
    "body",
    ["raise KeyboardInterrupt\n", f"raise KeyboardInterrupt({NEEDLE!r})\n"],
    ids=["bare", "with-text"],
)
def test_an_interrupt_off_the_main_thread_is_a_refused_module(tmp_path: Path, body: str) -> None:
    # No signal reaches a reload's worker thread, and one leaving it would stop the event loop.
    _write(tmp_path, "feed.py", body)

    def outcome() -> BaseException | None:
        try:
            load_config(tmp_path)
        except BaseException as exc:  # noqa: BLE001 - what crosses the thread is the assertion
            return exc
        return None

    with ThreadPoolExecutor(max_workers=1) as pool:
        left = pool.submit(outcome).result()
    assert isinstance(left, WiringError), repr(left)
    assert NEEDLE not in str(left) and "KeyboardInterrupt at line 1" in str(left)


#: The two places the loader reads a failed module's exception: the withheld diagnostic, on a class
#: the module raised itself, and the judgement of an engine refusal, on a context it was handling.
_READ_WINDOWS = {
    "module-failure": (
        "class Bad(Exception):\n    def __getattr__(self, name):\n        {fault}\n\nraise Bad()\n"
    ),
    "refusal": (
        "import {probe} as probe\n\n"
        "class Bad(Exception):\n    def __str__(self):\n        {fault}\n\n"
        "try:\n    raise Bad()\nexcept Bad:\n    probe.words_its_own()\n"
    ),
}


@pytest.mark.parametrize("window", _READ_WINDOWS.values(), ids=_READ_WINDOWS.keys())
def test_an_interrupt_in_the_loaders_read_stops_the_load(
    tmp_path: Path, engine_probe: str, window: str
) -> None:
    # Reading a failed module runs code, so an interrupt can land in that read. It is Ctrl-C, not a
    # config error, and it leaves as a new, bare one with no module exception on it.
    fault = f"raise KeyboardInterrupt({NEEDLE!r})"
    _write(tmp_path, "feed.py", window.format(fault=fault, probe=engine_probe))
    with pytest.raises(KeyboardInterrupt) as ei:
        load_config(tmp_path)
    _assert_bare(ei.value)


@pytest.mark.parametrize("window", _READ_WINDOWS.values(), ids=_READ_WINDOWS.keys())
def test_a_real_interrupt_in_the_loaders_read_stops_the_load(
    tmp_path: Path, engine_probe: str, window: str
) -> None:
    # A real signal, delivered while the loader reads. Sent in a loop for the reason given above.
    fault = "import signal\n        while True:\n            signal.raise_signal(signal.SIGINT)"
    _write(tmp_path, "feed.py", window.format(fault=fault, probe=engine_probe))
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with pytest.raises(KeyboardInterrupt) as ei:
            load_config(tmp_path)
    finally:
        signal.signal(signal.SIGINT, previous)
    _assert_bare(ei.value)


@pytest.mark.parametrize("window", _READ_WINDOWS.values(), ids=_READ_WINDOWS.keys())
def test_an_exit_in_the_loaders_read_leaves_with_no_module_exception_on_it(
    tmp_path: Path, engine_probe: str, window: str
) -> None:
    # As a module's own SystemExit leaves: the loader does not handle one.
    _write(tmp_path, "feed.py", window.format(fault="raise SystemExit(3)", probe=engine_probe))
    with pytest.raises(SystemExit) as ei:
        load_config(tmp_path)
    assert ei.value.code == 3
    assert ei.value.__context__ is None and ei.value.__cause__ is None


@pytest.mark.parametrize("window", _READ_WINDOWS.values(), ids=_READ_WINDOWS.keys())
def test_a_class_answering_as_an_exit_in_the_loaders_read_is_absorbed(
    tmp_path: Path, engine_probe: str, window: str
) -> None:
    # Only the real class is an exit. Raised, this one would leave with its text.
    fault = (
        "class Liar(BaseException):\n            __class__ = SystemExit\n"
        f"        raise Liar({NEEDLE!r})"
    )
    _write(tmp_path, "feed.py", window.format(fault=fault, probe=engine_probe))
    assert NEEDLE not in str(_load_error(tmp_path))


@pytest.mark.parametrize("window", _READ_WINDOWS.values(), ids=_READ_WINDOWS.keys())
@pytest.mark.parametrize("stop", ["KeyboardInterrupt", "SystemExit"], ids=["interrupt", "exit"])
def test_a_stop_in_the_loaders_read_off_the_main_thread_is_absorbed(
    tmp_path: Path, engine_probe: str, window: str, stop: str
) -> None:
    # No signal reaches a reload's worker, so a stop there is code, and it would end the event loop.
    fault = f"raise {stop}({NEEDLE!r})"
    _write(tmp_path, "feed.py", window.format(fault=fault, probe=engine_probe))

    def outcome() -> BaseException | None:
        try:
            load_config(tmp_path)
        except BaseException as exc:  # noqa: BLE001 - what crosses the thread is the assertion
            return exc
        return None

    with ThreadPoolExecutor(max_workers=1) as pool:
        left = pool.submit(outcome).result()
    assert isinstance(left, WiringError), repr(left)
    assert NEEDLE not in str(left)
    assert left.__cause__ is None and left.__context__ is None


def test_the_frame_rule_holds_under_an_unnormalized_import_path() -> None:
    # A code object keeps the sys.path entry's spelling, so a normalized prefix would miss it.
    root = _ENGINE_DIR.parent
    program = (
        "import sys\n"
        f"sys.path.insert(0, {f'{root}/docs/..'!r})\n"
        "from messagefoundry.config import wiring\n"
        "from messagefoundry.exception_origin import worded_by_the_engine\n"
        "assert '..' in wiring.__file__, wiring.__file__\n"
        "try:\n"
        "    wiring._cast_bool('nope')\n"
        "except ValueError as exc:\n"
        "    print(worded_by_the_engine(exc))\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, timeout=120, check=False
    )
    assert done.stdout.strip() == "True", done.stderr


def test_a_real_interrupt_inside_a_handler_stops_the_load(tmp_path: Path) -> None:
    # Python sets a signal's KeyboardInterrupt's __context__ to whatever was being handled. Sent in a
    # loop because the handler can run inside a weakref callback, which swallows the interrupt.
    body = (
        "import signal\n\n"
        f"try:\n    raise ValueError({NEEDLE!r})\n"
        "except ValueError:\n    while True:\n        signal.raise_signal(signal.SIGINT)\n"
    )
    _write(tmp_path, "feed.py", body)
    # A pytest-xdist worker can run with SIGINT ignored.
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with pytest.raises(KeyboardInterrupt) as ei:
            load_config(tmp_path)
    finally:
        signal.signal(signal.SIGINT, previous)
    _assert_bare(ei.value)


# Item 3: a harness graph's knob refusal reaches its reader, through the node's captured output.


@pytest.mark.parametrize(
    ("graph", "knob"),
    [
        ("load", "MEFOR_LOAD_TRANSFORM"),
        ("estate", "MEFOR_ESTATE_TRANSFORM"),
        ("connscale", "MEFOR_CONNSCALE_TRANSFORM"),
        ("shardcert", "MEFOR_SHARDCERT_TRANSFORM"),
    ],
)
def test_a_harness_knob_refusal_is_printed_while_the_loader_withholds_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], graph: str, knob: str
) -> None:
    monkeypatch.setenv(knob, "no-such-transform")
    messages = _messages(Path(__file__).parent.parent / "harness" / "config" / graph)
    assert any("ValueError" in m and "withheld" in m and knob not in m for m in messages), messages
    assert knob in capsys.readouterr().err


# Item 5: one rule, in one place.


def _raised_in(module_name: str, file: Path, source: str) -> BaseException:
    namespace: dict[str, object] = {"__name__": module_name}
    with pytest.raises(Exception) as ei:  # noqa: PT011 - each caller's source picks the type
        exec(compile(source, str(file), "exec"), namespace)
    return ei.value


_IN_THE_ENGINE = _ENGINE_DIR / "x.py"
_IN_A_CONFIG_DIR = _ENGINE_DIR.parent / "config" / "feed.py"
_RAISE = "raise ValueError('text')"


@pytest.mark.parametrize(
    ("module", "file", "source", "raised", "worded"),
    [
        pytest.param("messagefoundry.x", _IN_THE_ENGINE, _RAISE, True, True, id="raise"),
        pytest.param(
            "messagefoundry", _ENGINE_DIR / "__init__.py", _RAISE, True, True, id="package"
        ),
        pytest.param("messagefoundry.x", _IN_THE_ENGINE, "int('x')", True, False, id="builtin"),
        pytest.param("messagefoundry.x", _IN_THE_ENGINE, "{}['k']", True, False, id="lookup"),
        pytest.param("mefor_config_a", _IN_A_CONFIG_DIR, _RAISE, False, False, id="config-module"),
        pytest.param(
            "messagefoundry_lookalike",
            _ENGINE_DIR.parent / "messagefoundry_lookalike" / "x.py",
            _RAISE,
            False,
            False,
            id="lookalike-package",
        ),
        pytest.param(
            "messagefoundry.x", _IN_A_CONFIG_DIR, _RAISE, False, False, id="named-like-the-engine"
        ),
        pytest.param(
            "mefor_config_a", _IN_THE_ENGINE, _RAISE, False, False, id="config-dir-in-the-package"
        ),
        pytest.param(
            "messagefoundry._vendor.x",
            _ENGINE_DIR / "_vendor" / "x.py",
            _RAISE,
            False,
            False,
            id="vendored",
        ),
    ],
)
def test_who_raised_an_exception(
    module: str, file: Path, source: str, raised: bool, worded: bool
) -> None:
    exc = _raised_in(module, file, source)
    assert raised_by_the_engine(exc) is raised
    assert worded_by_the_engine(exc) is worded


def test_an_exception_never_raised_has_no_origin() -> None:
    assert not raised_by_the_engine(ValueError("x"))
    assert not worded_by_the_engine(ValueError("x"))
