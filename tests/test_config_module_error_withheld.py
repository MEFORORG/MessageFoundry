# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A config module's own exception text is withheld from the loader's diagnostic (vault BACKLOG #3249).

``_exec_module`` used to wrap whatever a config module raised as ``error loading config module
<file>: <exception text>``, and pass a ``WiringError`` the module raised itself through untouched. That
text is author code's, and can carry any value the module held, and it reaches at least
``messagefoundry validate`` and ``check`` output (so CI logs), the reload WARNING and the
``POST /connections/{name}/flag`` 409. The loader now names the exception TYPE and the line in the
config module instead. A ``WiringError`` raised inside ``messagefoundry`` is the engine's own wording
and still passes through unchanged.

Every planted string is assembled at run time, so no committed literal looks like a secret."""

from __future__ import annotations

import inspect
import sys
import textwrap
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from types import ModuleType

import httpx
import pytest

import messagefoundry
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
"""


@pytest.fixture
def engine_probe(monkeypatch: pytest.MonkeyPatch) -> str:
    """A module whose frames count as the engine's, to call with a planted value. Its name is what
    the rule reads, so it needs no file under ``messagefoundry``."""
    name = "messagefoundry._probe_3765"
    module = ModuleType(name)
    exec(compile(_ENGINE_SOURCE, name, "exec"), module.__dict__)
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
    samples: dict[str, object] = {"port": 2575, "host": "127.0.0.1"}
    return {
        p.name: samples.get(p.name, "x")
        for p in inspect.signature(factory).parameters.values()
        if p.default is inspect.Parameter.empty and p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL)
    }


@pytest.mark.parametrize("factory_name", _FACTORIES)
def test_no_factory_refusal_quotes_a_planted_value(factory_name: str) -> None:
    factory = getattr(messagefoundry, factory_name)
    required = _required_arguments(factory)
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


# Item 4: whatever else a config module raises is a failed module, and carries no text.


@pytest.mark.parametrize(
    ("raised", "name"),
    [
        (f"BaseException({NEEDLE!r})", "BaseException"),
        (f"GeneratorExit({NEEDLE!r})", "GeneratorExit"),
        (f"asyncio.CancelledError({NEEDLE!r})", "CancelledError"),
        (f"Mine({NEEDLE!r})", "Mine"),
        (f"BaseExceptionGroup({NEEDLE!r}, [KeyboardInterrupt()])", "BaseExceptionGroup"),
        (f"KeyboardInterrupt({NEEDLE!r})", "KeyboardInterrupt"),
    ],
    ids=["plain", "generator-exit", "cancelled", "subclass", "group", "interrupt-with-text"],
)
def test_a_base_exception_is_a_refused_module_with_no_text(
    tmp_path: Path, raised: str, name: str
) -> None:
    _write(
        tmp_path,
        "feed.py",
        f"import asyncio\n\nclass Mine(BaseException):\n    pass\n\nraise {raised}\n",
    )
    before = set(sys.modules)
    err = _load_error(tmp_path)
    assert NEEDLE not in str(err)
    assert f"feed.py: {name} at line 6" in str(err) and "withheld" in str(err)
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


def test_a_real_interrupt_still_propagates(tmp_path: Path) -> None:
    # What a signal raises: no arguments, so no text. Refusing it would make Ctrl-C a config error.
    _write(tmp_path, "feed.py", "raise KeyboardInterrupt\n")
    with pytest.raises(KeyboardInterrupt):
        load_config(tmp_path)


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


def _raised_in(module_name: str, source: str) -> BaseException:
    namespace: dict[str, object] = {"__name__": module_name}
    with pytest.raises(Exception) as ei:  # noqa: PT011 - each caller's source picks the type
        exec(compile(source, module_name, "exec"), namespace)
    return ei.value


@pytest.mark.parametrize(
    ("module", "source", "raised", "worded"),
    [
        ("messagefoundry.x", "raise ValueError('ours')", True, True),
        ("messagefoundry", "raise ValueError('ours')", True, True),
        ("messagefoundry.x", "int('x')", True, False),
        ("messagefoundry.x", "{}['k']", True, False),
        ("mefor_config_feed_abc", "raise ValueError('theirs')", False, False),
        ("messagefoundry_lookalike", "raise ValueError('theirs')", False, False),
    ],
    ids=["raise", "package", "builtin", "lookup", "config-module", "lookalike-package"],
)
def test_who_raised_an_exception(module: str, source: str, raised: bool, worded: bool) -> None:
    exc = _raised_in(module, source)
    assert raised_by_the_engine(exc) is raised
    assert worded_by_the_engine(exc) is worded


def test_an_exception_never_raised_has_no_origin() -> None:
    assert not raised_by_the_engine(ValueError("x"))
    assert not worded_by_the_engine(ValueError("x"))
