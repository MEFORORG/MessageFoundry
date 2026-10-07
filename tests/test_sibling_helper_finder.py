# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How a config module's ``import _helpers`` resolves, and what the loader treats as config.

SEC-019 (CWE-427): only the documented ``_``-prefixed helper convention is served, so a config-dir
file named after a real stdlib/installed module cannot shadow it. Vault BACKLOG #2780: helpers are
served only to config modules, never process-wide, and a helper named after a real module is
refused. Vault BACKLOG #2783: a helper imported inside a Router or Handler body resolves at run
time. Vault BACKLOG #2781: a dot-named ``*.py`` is not config."""

from __future__ import annotations

import importlib
import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.fingerprint import config_fingerprint
from messagefoundry.config.wiring import (
    WiringError,
    _assert_safe_config_source,
    _enforce_windows_config_source,
    _HelperImporter,
    _WinConfigSourceProbes,
    _WinPathSecurity,
    load_config,
    validate_config,
)
from messagefoundry.parsing.message import Message

_OUTBOUND = "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n"

_MSG = Message.parse("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5\r")


def _write(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source), encoding="utf-8")


def test_underscore_sibling_still_imports(tmp_path: Path) -> None:
    """The ``import _helpers`` feature is intact: a ``_``-prefixed sibling resolves and is usable."""
    (tmp_path / "_shared.py").write_text("ARCHIVE = 'arch_out'\n", encoding="utf-8")
    _write(
        tmp_path / "cfg.py",
        """
        import _shared
        from messagefoundry import outbound, File

        outbound(_shared.ARCHIVE, File(directory="./out"))
        """,
    )
    registry = load_config(tmp_path)
    # The outbound's name came from the _shared sibling helper — proves the import resolved.
    assert "arch_out" in registry.outbound


def test_nonunderscore_sibling_does_not_shadow_stdlib(tmp_path: Path) -> None:
    """A hostile ``json.py`` in the config dir must NOT shadow the real stdlib ``json`` during load."""
    (tmp_path / "json.py").write_text("SHADOWED = True\n", encoding="utf-8")
    _write(
        tmp_path / "cfg.py",
        """
        import json
        from messagefoundry import outbound, File

        # The REAL stdlib json must win: it has dumps and no SHADOWED attribute.
        assert hasattr(json, "dumps"), "config-dir json.py shadowed the stdlib json"
        assert getattr(json, "SHADOWED", False) is False, "config-dir json.py shadowed stdlib"
        outbound("o", File(directory="./out"))
        """,
    )
    # load_config raising would mean the assert tripped (i.e. shadowing happened) -> a WiringError.
    registry = load_config(tmp_path)
    assert "o" in registry.outbound
    # Sanity: the real json in THIS process is also untouched after the load.
    assert not getattr(json, "SHADOWED", False)


def test_importer_serves_only_underscore_helpers(tmp_path: Path) -> None:
    """Unit-test the importer: it serves ``_h`` from the dir, never a bare ``os`` or ``shared``."""
    (tmp_path / "os.py").write_text("SHADOWED = True\n", encoding="utf-8")
    (tmp_path / "shared.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "_h.py").write_text("VALUE = 1\n", encoding="utf-8")
    importer = _HelperImporter(tmp_path)
    do_import = importer.builtins["__import__"]
    # A real-module name (not '_'-prefixed) goes to the normal import even though os.py exists.
    assert do_import("os") is os
    assert not hasattr(do_import("os"), "SHADOWED")
    # A non-'_' sibling is not served at all (SEC-019): the normal import does not find it.
    with pytest.raises(ModuleNotFoundError):
        do_import("shared")
    # The documented '_'-prefixed helper is served, from the config dir.
    helper = do_import("_h")
    assert helper.VALUE == 1
    assert helper.__file__ == str(tmp_path / "_h.py")
    # A dotted name is never a helper.
    with pytest.raises(ModuleNotFoundError):
        do_import("_h.sub")


def test_helpers_are_not_served_process_wide_during_a_load(tmp_path: Path) -> None:
    """Vault BACKLOG #2780. An import that does not go through a config module's own ``import``
    statement -- here ``importlib.import_module``, which is what any other code in the process (or
    another thread) uses -- must not see the config dir, even while the load is running. The finder
    this replaced sat on ``sys.meta_path`` for the whole load and served it."""
    (tmp_path / "_mefor_probe_helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    _write(
        tmp_path / "cfg.py",
        """
        import importlib
        import sys

        import _mefor_probe_helper  # resolves for this module, through its own import statement

        try:
            importlib.import_module("_mefor_probe_helper")
        except ModuleNotFoundError:
            pass
        else:
            raise AssertionError("the config dir was served process-wide during the load")
        assert "_mefor_probe_helper" not in sys.modules
        assert _mefor_probe_helper.VALUE == 1
        from messagefoundry import outbound, File

        outbound("o", File(directory="./out"))
        """,
    )
    meta_path_before = list(sys.meta_path)
    assert "o" in load_config(tmp_path).outbound
    assert sys.meta_path == meta_path_before
    assert "_mefor_probe_helper" not in sys.modules


# Pure-Python stdlib modules with a ``_`` name that this suite has no reason to import first.
_UNIMPORTED_STDLIB_CANDIDATES = ("_pydecimal", "_pydatetime", "_pyio", "_pylong", "_osx_support")


def test_stdlib_underscore_module_is_not_shadowed_by_an_unimported_helper(tmp_path: Path) -> None:
    """A first import of a real ``_`` stdlib module during the load gets the real module, even with a
    same-named file in the config dir that no config module imports. Under the old finder it got the
    config file (the first ``import csv`` failed with "cannot import name 'Error' from '_csv'").

    The name must not be in ``sys.modules`` yet, or the import never reaches a finder and the test
    cannot tell the two designs apart -- ``csv``/``_csv`` are, because the loader imports them."""
    name = next((n for n in _UNIMPORTED_STDLIB_CANDIDATES if n not in sys.modules), None)
    if name is None:
        pytest.skip("every candidate stdlib module is already imported in this process")
    assert name in sys.stdlib_module_names
    (tmp_path / f"{name}.py").write_text("SHADOWED = True\n", encoding="utf-8")
    _write(
        tmp_path / "cfg.py",
        f"""
        import importlib

        real = importlib.import_module("{name}")
        assert not hasattr(real, "SHADOWED"), "the config dir shadowed a stdlib module"
        from messagefoundry import outbound, File

        outbound("o", File(directory="./out"))
        """,
    )
    try:
        assert "o" in load_config(tmp_path).outbound
    finally:
        sys.modules.pop(name, None)


@pytest.mark.parametrize(
    ("helper", "clash"),
    [
        ("_csv", "a standard library module"),
        ("_json", "a standard library module"),
        ("_pytest", "a module this process has already imported"),
    ],
)
def test_helper_named_after_a_real_module_is_refused(
    tmp_path: Path, helper: str, clash: str
) -> None:
    """Vault BACKLOG #2780: importing a helper whose name is a real module's fails the load, naming
    the file, rather than quietly meaning one module here and another everywhere else."""
    (tmp_path / f"{helper}.py").write_text("VALUE = 1\n", encoding="utf-8")
    _write(tmp_path / "cfg.py", f"import {helper}\n" + _OUTBOUND)
    with pytest.raises(WiringError) as excinfo:
        load_config(tmp_path)
    message = str(excinfo.value)
    assert f"config helper {helper}.py" in message
    assert clash in message
    # check (validate_config) reports the same refusal as a diagnostic, against the importing module.
    diags = validate_config(tmp_path)
    assert any(f"config helper {helper}.py" in d.message for d in diags)


def test_helper_named_after_an_installed_module_is_refused(tmp_path: Path) -> None:
    """The installed-package arm: a name ``sys.path`` resolves, though nothing has imported it."""
    site = tmp_path / "site"
    site.mkdir()
    (site / "_mefor_installed_probe.py").write_text("VALUE = 0\n", encoding="utf-8")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "_mefor_installed_probe.py").write_text("VALUE = 1\n", encoding="utf-8")
    _write(cfg / "cfg.py", "import _mefor_installed_probe\n" + _OUTBOUND)
    sys.path.insert(0, str(site))
    try:
        with pytest.raises(WiringError, match="an installed module"):
            load_config(cfg)
    finally:
        sys.path.remove(str(site))
        sys.path_importer_cache.pop(str(site), None)


def test_helper_found_on_sys_path_at_its_own_path_is_not_a_clash(tmp_path: Path) -> None:
    """The config dir itself on ``sys.path`` (the engine started from it) finds the helper at its own
    path. That is the helper, not a clash, so it loads."""
    (tmp_path / "_mefor_self_probe.py").write_text("DEST = 'o'\n", encoding="utf-8")
    _write(tmp_path / "cfg.py", "import _mefor_self_probe\n" + _OUTBOUND)
    sys.path.insert(0, str(tmp_path))
    try:
        assert "o" in load_config(tmp_path).outbound
    finally:
        sys.path.remove(str(tmp_path))
        sys.path_importer_cache.pop(str(tmp_path), None)


_IN_BODY_HANDLER = """
from messagefoundry import outbound, File, handler, Send

outbound("o", File(directory="./out"))


@handler("h")
def handle(msg):
    import _route_helper  # the lazy-import habit: only inside the body

    return Send(_route_helper.DEST, msg)
"""


def test_helper_imported_inside_a_handler_body_resolves_at_run_time(tmp_path: Path) -> None:
    """Vault BACKLOG #2783: the in-body import works after the load is over, every time."""
    (tmp_path / "_route_helper.py").write_text("DEST = 'o'\n", encoding="utf-8")
    _write(tmp_path / "cfg.py", _IN_BODY_HANDLER)
    registry = load_config(tmp_path)
    for _ in range(2):
        result = registry.handlers["h"](_MSG)
        assert result.to == "o"  # type: ignore[union-attr]
    assert "_route_helper" not in sys.modules


def test_helper_imported_inside_a_router_body_resolves_at_run_time(tmp_path: Path) -> None:
    """The same for a Router, and for a helper that imports another helper inside its own body."""
    (tmp_path / "_names.py").write_text(
        "def target():\n    import _leaf\n\n    return _leaf.HANDLER\n", encoding="utf-8"
    )
    (tmp_path / "_leaf.py").write_text("HANDLER = 'h'\n", encoding="utf-8")
    _write(
        tmp_path / "cfg.py",
        """
        from messagefoundry import inbound, router, handler, MLLP

        inbound("in", MLLP(port=2575), router="r")


        @router("r")
        def route(msg):
            from _names import target

            return [target()]


        @handler("h")
        def handle(msg):
            return None
        """,
    )
    registry = load_config(tmp_path)
    assert registry.routers["r"](_MSG) == ["h"]


def test_an_in_body_helper_that_fails_to_import_fails_the_load(tmp_path: Path) -> None:
    """The in-body helper is loaded at load time, so its failure is a load and ``check`` error, not
    a dead-lettered message per run."""
    (tmp_path / "_route_helper.py").write_text("raise RuntimeError('helper broke')\n")
    _write(tmp_path / "cfg.py", _IN_BODY_HANDLER)
    with pytest.raises(WiringError, match="helper broke"):
        load_config(tmp_path)
    diags = validate_config(tmp_path)
    assert any("helper broke" in d.message and (d.file or "").endswith("cfg.py") for d in diags)


def test_after_the_load_no_helper_file_is_run(tmp_path: Path) -> None:
    """The run-time path serves only what the load imported. A helper present at load time that no
    import statement names, reached by a dynamic ``__import__`` after the load, is not run: nothing
    executes at run time that the load did not."""
    (tmp_path / "_late_helper.py").write_text("raise RuntimeError('late helper ran')\n")
    _write(
        tmp_path / "cfg.py",
        """
        from messagefoundry import outbound, File, handler, Send

        outbound("o", File(directory="./out"))


        @handler("h")
        def handle(msg):
            name = "_late_helper"
            return __import__(name)
        """,
    )
    registry = load_config(tmp_path)
    with pytest.raises(ModuleNotFoundError):
        registry.handlers["h"](_MSG)


def test_each_load_keeps_its_own_helpers(tmp_path: Path) -> None:
    """A reload's helpers do not replace the ones an earlier load's handlers run with."""
    (tmp_path / "_route_helper.py").write_text("DEST = 'o'\n", encoding="utf-8")
    _write(tmp_path / "cfg.py", _IN_BODY_HANDLER)
    first = load_config(tmp_path)
    (tmp_path / "_route_helper.py").write_text("DEST = 'changed'\n", encoding="utf-8")
    importlib.invalidate_caches()
    second = load_config(tmp_path)
    assert first.handlers["h"](_MSG).to == "o"  # type: ignore[union-attr]
    assert second.handlers["h"](_MSG).to == "changed"  # type: ignore[union-attr]


# --- vault BACKLOG #2781: a dot-named *.py is not config ----------------------------------------


def _with_dotfiles(directory: Path) -> None:
    # An editor or manual backup, and a macOS AppleDouble file (binary, with NULs) from an SMB copy.
    (directory / ".IB_OLD.py").write_text("raise RuntimeError('dotfile executed')\n")
    (directory / "._cfg.py").write_bytes(b"\x00\x05\x16\x07\x00\x02\x00\x00Mac OS X")
    (directory / "cfg.py").write_text(_OUTBOUND, encoding="utf-8")


def test_dot_named_modules_are_not_loaded(tmp_path: Path) -> None:
    _with_dotfiles(tmp_path)
    assert set(load_config(tmp_path).outbound) == {"o"}
    assert validate_config(tmp_path) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_dot_named_modules_are_outside_the_posix_trust_check(tmp_path: Path) -> None:
    """A file the loader never runs is not a reason to refuse the load; a module it runs still is."""
    _with_dotfiles(tmp_path)
    (tmp_path / ".IB_OLD.py").chmod(0o666)
    _assert_safe_config_source(tmp_path)  # no refusal
    (tmp_path / "cfg.py").chmod(0o666)  # positive control: the same check on a module that runs
    with pytest.raises(WiringError, match="group/world-writable"):
        _assert_safe_config_source(tmp_path)


def test_dot_named_modules_are_outside_the_windows_trust_check(tmp_path: Path) -> None:
    _with_dotfiles(tmp_path)
    (tmp_path / "_helper.py").write_text("X = 1\n", encoding="utf-8")
    seen: list[Path] = []
    sid = "S-1-5-21-1-2-3-1001"

    def _read_path(path: Path) -> _WinPathSecurity:
        seen.append(path)
        return _WinPathSecurity(owner_sid=sid, aces=())

    probes = _WinConfigSourceProbes(
        self_sid=sid, read_path=_read_path, owner_in_admins=lambda _sid: False
    )
    _enforce_windows_config_source(tmp_path, probes)
    assert seen == [tmp_path, tmp_path / "_helper.py", tmp_path / "cfg.py"]


def test_dot_named_modules_are_not_fingerprinted(tmp_path: Path) -> None:
    (tmp_path / "cfg.py").write_text(_OUTBOUND, encoding="utf-8")
    before = config_fingerprint(tmp_path)
    _with_dotfiles(tmp_path)
    assert config_fingerprint(tmp_path) == before
    (tmp_path / "_helper.py").write_text("X = 1\n", encoding="utf-8")  # control: a helper counts
    assert config_fingerprint(tmp_path) != before


def test_top_level_guarded_and_conditional_helper_imports_keep_their_control_flow(
    tmp_path: Path,
) -> None:
    """Top-level statements already ran with their real control flow, so a skipped optional or
    typing-only top-level import stays skipped: the preload looks only inside function bodies."""
    (tmp_path / "_optional.py").write_text("import mefor_no_such_package\n", encoding="utf-8")
    (tmp_path / "_types_only.py").write_text("raise RuntimeError('typing-only helper ran')\n")
    _write(
        tmp_path / "cfg.py",
        """
        from typing import TYPE_CHECKING

        try:
            import _optional
        except ImportError:
            _optional = None
        if TYPE_CHECKING:
            import _types_only
        from messagefoundry import outbound, File

        outbound("o", File(directory="./out"))
        """,
    )
    assert "o" in load_config(tmp_path).outbound


def test_a_guarded_in_body_helper_that_fails_leaves_the_guard_to_decide(tmp_path: Path) -> None:
    """An optional helper imported under ``try`` in a body does not fail the load when it fails; at
    run time the import raises ``ModuleNotFoundError`` and the body's own ``except`` takes it."""
    (tmp_path / "_optional.py").write_text("import mefor_no_such_package\n", encoding="utf-8")
    _write(
        tmp_path / "cfg.py",
        """
        from messagefoundry import outbound, File, handler, Send

        outbound("o", File(directory="./out"))


        @handler("h")
        def handle(msg):
            try:
                import _optional
            except ImportError:
                return Send("o", msg)
            return None
        """,
    )
    registry = load_config(tmp_path)
    assert registry.handlers["h"](_MSG).to == "o"  # type: ignore[union-attr]


def test_a_refused_helper_name_is_refused_even_under_a_guard(tmp_path: Path) -> None:
    (tmp_path / "_json.py").write_text("VALUE = 1\n", encoding="utf-8")
    _write(
        tmp_path / "cfg.py",
        """
        from messagefoundry import outbound, File, handler

        outbound("o", File(directory="./out"))


        @handler("h")
        def handle(msg):
            try:
                import _json
            except ImportError:
                return None
            return None
        """,
    )
    with pytest.raises(WiringError, match="config helper _json.py"):
        load_config(tmp_path)


def test_an_in_body_import_that_breaks_a_cycle_still_breaks_it(tmp_path: Path) -> None:
    """``_b`` imports ``_c`` inside a body precisely so ``_c`` (which needs ``_a.X``) runs after ``_a``
    finished. The preload waits for the config module that started the chain, so it does too."""
    (tmp_path / "_a.py").write_text("import _b\n\nX = 1\n", encoding="utf-8")
    (tmp_path / "_b.py").write_text(
        "def f():\n    from _c import g\n\n    return g()\n", encoding="utf-8"
    )
    (tmp_path / "_c.py").write_text("from _a import X\n\n\ndef g():\n    return X\n")
    _write(
        tmp_path / "cfg.py",
        """
        import _a
        from messagefoundry import outbound, File

        outbound("o", File(directory="./out"))
        assert _a._b.f() == 1
        """,
    )
    assert "o" in load_config(tmp_path).outbound


def test_a_failed_load_leaves_no_helper_in_sys_modules(tmp_path: Path) -> None:
    (tmp_path / "_ok.py").write_text("VALUE = 1\n", encoding="utf-8")
    _write(tmp_path / "cfg.py", "import _ok\nraise RuntimeError('boom')\n")
    before = set(sys.modules)
    with pytest.raises(WiringError, match="boom"):
        load_config(tmp_path)
    assert not {name for name in set(sys.modules) - before if "__ok_" in name}


def test_a_dot_named_backup_does_not_take_a_rename(tmp_path: Path) -> None:
    """The rename planner edits the module the loader runs, never a dot-named backup of it."""
    from messagefoundry.config.impact import plan_rename

    module = textwrap.dedent(
        """
        from messagefoundry import File, FileRef, Reference, outbound

        Reference("providers", source=FileRef(path="providers.csv"))
        outbound("o", File(directory="./out"))
        """
    )
    (tmp_path / "providers.csv").write_text("key,value\nx,1\n", encoding="utf-8")
    (tmp_path / "cfg.py").write_text(module, encoding="utf-8")
    (tmp_path / ".cfg.py").write_text(module, encoding="utf-8")  # sorts first
    registry = load_config(tmp_path)
    plan = plan_rename(registry, tmp_path, "reference", "providers", "prov2")
    assert plan.edits
    assert all(Path(edit.file).name == "cfg.py" for edit in plan.edits)


def test_a_dot_named_backup_is_not_linted_by_check(tmp_path: Path) -> None:
    """``check``'s static handler-security lint reads the files the loader runs, not a backup."""
    from messagefoundry.checks import _check_handler_security

    risky = textwrap.dedent(
        """
        import subprocess

        from messagefoundry import handler


        @handler("old")
        def handle(msg):
            subprocess.run(["true"])
        """
    )
    (tmp_path / "cfg.py").write_text(_OUTBOUND, encoding="utf-8")
    (tmp_path / ".IB_OLD.py").write_text(risky, encoding="utf-8")
    clean = _check_handler_security(tmp_path, strict=True)
    assert clean.ok, clean.detail
    # Positive control: the same file under a name the loader runs.
    (tmp_path / "IB_OLD.py").write_text(risky, encoding="utf-8")
    assert not _check_handler_security(tmp_path, strict=True).ok


def test_a_failed_reload_keeps_the_live_graphs_helpers(tmp_path: Path) -> None:
    """A failed load of the same files gives each ``sys.modules`` name back to the live graph's module,
    and the live graph's in-body helper import still works."""
    from messagefoundry.config.wiring import _config_module_name

    (tmp_path / "_route_helper.py").write_text("DEST = 'o'\n", encoding="utf-8")
    _write(tmp_path / "cfg.py", _IN_BODY_HANDLER)
    live = load_config(tmp_path)
    helper_name = _config_module_name(tmp_path / "_route_helper.py")
    live_helper = sys.modules[helper_name]

    cfg_name = _config_module_name(tmp_path / "cfg.py")
    live_cfg = sys.modules[cfg_name]
    # The broken reload imports the helper at top level, so it registers the same names, then fails.
    (tmp_path / "cfg.py").write_text(
        "import _route_helper\n"
        + textwrap.dedent(_IN_BODY_HANDLER)
        + "\nraise RuntimeError('broken reload')\n",
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="broken reload"):
        load_config(tmp_path)
    assert sys.modules[helper_name] is live_helper
    assert sys.modules[cfg_name] is live_cfg
    assert live.handlers["h"](_MSG).to == "o"  # type: ignore[union-attr]


def test_an_except_that_cannot_catch_an_import_error_is_not_a_guard(tmp_path: Path) -> None:
    (tmp_path / "_optional.py").write_text("import mefor_no_such_package\n", encoding="utf-8")
    _write(
        tmp_path / "cfg.py",
        """
        from messagefoundry import outbound, File, handler

        outbound("o", File(directory="./out"))


        @handler("h")
        def handle(msg):
            try:
                import _optional
            except KeyError:
                return None
            return None
        """,
    )
    with pytest.raises(WiringError, match="mefor_no_such_package"):
        load_config(tmp_path)


def test_a_guarded_helper_that_fails_with_another_error_fails_the_load(tmp_path: Path) -> None:
    """``except ImportError`` would not catch a ``NameError`` from the helper, so neither does the load."""
    (tmp_path / "_optional.py").write_text("VALUE = undefined_name\n", encoding="utf-8")
    _write(
        tmp_path / "cfg.py",
        """
        from messagefoundry import outbound, File, handler

        outbound("o", File(directory="./out"))


        @handler("h")
        def handle(msg):
            try:
                import _optional
            except ImportError:
                return None
            return None
        """,
    )
    with pytest.raises(WiringError, match="undefined_name"):
        load_config(tmp_path)


def test_a_guarded_helper_failure_is_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "_optional.py").write_text("import mefor_no_such_package\n", encoding="utf-8")
    _write(
        tmp_path / "cfg.py",
        """
        from messagefoundry import outbound, File, handler

        outbound("o", File(directory="./out"))


        @handler("h")
        def handle(msg):
            try:
                import _optional
            except ImportError:
                return None
            return None
        """,
    )
    with caplog.at_level("WARNING", logger="messagefoundry.config.wiring"):
        load_config(tmp_path)
    warnings = [r for r in caplog.records if "ImportError guard" in r.getMessage()]
    assert len(warnings) == 1
    assert "ModuleNotFoundError" in warnings[0].getMessage()
    assert "mefor_no_such_package" not in warnings[0].getMessage()  # names only, never the text


def test_a_failed_module_leaves_no_queued_scan_for_the_next(tmp_path: Path) -> None:
    """validate_config: a module that fails after importing a helper must not hand that helper's body
    scan to the next module, whose diagnostic would then name the wrong file."""
    (tmp_path / "_h.py").write_text("def f():\n    import _bad\n", encoding="utf-8")
    (tmp_path / "_bad.py").write_text("raise RuntimeError('bad helper')\n", encoding="utf-8")
    (tmp_path / "a_cfg.py").write_text("import _h\nraise RuntimeError('a broke')\n")
    (tmp_path / "b_cfg.py").write_text(_OUTBOUND, encoding="utf-8")
    diags = validate_config(tmp_path)
    assert any("a broke" in d.message for d in diags), diags  # positive control
    assert all(not (d.file or "").endswith("b_cfg.py") for d in diags), diags


def _guarded_handler(name: str, guard: str, *, guarded: bool = True) -> str:
    body = (
        f"    try:\n        import _optional\n    except {guard}:\n        return None\n"
        if guarded
        else "    import _optional\n"
    )
    return (
        "from messagefoundry import outbound, File, handler\n\n"
        f"outbound('o_{name}', File(directory='./out'))\n\n\n"
        f"@handler('{name}')\ndef handle(msg):\n{body}    return None\n"
    )


def test_an_unguarded_site_of_a_helper_that_failed_under_a_guard_fails_the_load(
    tmp_path: Path,
) -> None:
    """One helper, imported under a guard in one module and bare in another: the bare site would fail
    on every message, so the load fails, whichever module runs first."""
    (tmp_path / "_optional.py").write_text("import mefor_no_such_package\n", encoding="utf-8")
    (tmp_path / "a_cfg.py").write_text(_guarded_handler("ha", "ImportError"), encoding="utf-8")
    (tmp_path / "b_cfg.py").write_text(
        _guarded_handler("hb", "ImportError", guarded=False), encoding="utf-8"
    )
    with pytest.raises(WiringError, match="mefor_no_such_package"):
        load_config(tmp_path)


@pytest.mark.parametrize("guard", ["Exception", "BaseException", "(ValueError, ImportError)"])
def test_a_broader_except_is_a_guard(tmp_path: Path, guard: str) -> None:
    (tmp_path / "_optional.py").write_text("import mefor_no_such_package\n", encoding="utf-8")
    (tmp_path / "cfg.py").write_text(_guarded_handler("h", guard), encoding="utf-8")
    assert load_config(tmp_path).handlers["h"](_MSG) is None


def test_a_module_not_found_guard_does_not_cover_a_plain_import_error(tmp_path: Path) -> None:
    """``from json import missing`` raises ImportError, which ``except ModuleNotFoundError`` lets
    through at run time, so the load fails rather than taking the fallback on every message."""
    (tmp_path / "_optional.py").write_text("from json import mefor_no_such_name\n")
    (tmp_path / "cfg.py").write_text(_guarded_handler("h", "ModuleNotFoundError"), encoding="utf-8")
    with pytest.raises(WiringError, match="mefor_no_such_name"):
        load_config(tmp_path)


def test_reloads_do_not_keep_earlier_generations_alive(tmp_path: Path) -> None:
    """Each module's builtins point at its load's importer for the graph's life; the importer must not
    hold the module it replaced in sys.modules, or every reload keeps the one before it."""
    import gc
    import weakref

    from messagefoundry.config.wiring import _config_module_name

    (tmp_path / "_route_helper.py").write_text("DEST = 'o'\n", encoding="utf-8")
    _write(tmp_path / "cfg.py", _IN_BODY_HANDLER)
    cfg_name = _config_module_name(tmp_path / "cfg.py")
    load_config(tmp_path)
    first = weakref.ref(sys.modules[cfg_name])
    for _ in range(3):
        load_config(tmp_path)
    gc.collect()
    assert first() is None
