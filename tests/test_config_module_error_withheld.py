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

import textwrap
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import WiringError, load_config, validate_config
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
