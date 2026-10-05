# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The anonymizer's publish-guard loader looks in ONE folder and searches no other (BACKLOG #2344).

Both ``leak.py`` copies load ``scripts/security/scan_forbidden.py`` by path and run it. Each used to
try every folder above its own file and run the first match, so a file at that path above an
installed copy would have run. Each now builds a single path, under the folder that holds its
package.

Every planted guard here lives under ``tmp_path``. It writes a marker beside itself when it runs,
so "it ran" is read from the disk and never inferred from what the loader returned.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry.anon import leak as engine_leak
from tee.anon import leak as tee_leak

_GUARD_PARTS = ("scripts", "security", "scan_forbidden.py")
_CHECKOUT_GUARD = Path(__file__).resolve().parents[1].joinpath(*_GUARD_PARTS)
_MESSAGE = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1"

# A stand-in guard. The marker write is its first statement, so the marker records the run even
# if a caller later rejects the module.
_PLANTED = (
    "from pathlib import Path\n"
    'Path(__file__).with_name("RAN").write_text("ran", encoding="utf-8")\n'
    "TOKENS_PRESENT = False\n"
    "def scan_text(text, *, include_estate=False):\n"
    "    return []\n"
)

# A place is ``module_file.parents[n]``. The module sits at ``<root>/<package>/anon/leak.py``, so
# 2 is the import root, the one place a guard may load from.
_IMPORT_ROOT = 2
_WRONG_PLACES = [
    pytest.param(0, id="the anon folder"),
    pytest.param(1, id="the package folder"),
    pytest.param(3, id="one folder above the import root"),
    pytest.param(4, id="two folders above the import root"),
]


def _module_file(tmp_path: Path, package: str) -> Path:
    """A stand-in ``leak.py`` under a made-up import root, with two folders above that root."""
    path = tmp_path / "above2" / "above1" / "root" / package / "anon" / "leak.py"
    path.parent.mkdir(parents=True)
    path.write_text("", encoding="utf-8")
    return path


def _plant(folder: Path) -> Path:
    """Plant the stand-in guard under ``folder`` and return the marker it would write."""
    guard = folder.joinpath(*_GUARD_PARTS)
    guard.parent.mkdir(parents=True)
    guard.write_text(_PLANTED, encoding="utf-8")
    return guard.with_name("RAN")


def _engine_load(monkeypatch: pytest.MonkeyPatch, module_file: Path) -> ModuleType:
    """Run the engine loader as if ``leak.py`` lived at ``module_file``.

    ``__wrapped__`` goes round the ``lru_cache``, so the session's real scanner is neither replaced
    nor reloaded by this test."""
    monkeypatch.setattr(engine_leak, "__file__", str(module_file))
    return engine_leak._scanner.__wrapped__()


@pytest.mark.parametrize("depth", _WRONG_PLACES)
def test_the_engine_loader_does_not_run_a_guard_planted_anywhere_but_the_import_root(
    depth: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_file = _module_file(tmp_path, "messagefoundry")
    marker = _plant(module_file.parents[depth])
    with pytest.raises(engine_leak.LeakCheckUnavailable):
        _engine_load(monkeypatch, module_file)
    assert not marker.exists()


@pytest.mark.parametrize("depth", _WRONG_PLACES)
def test_the_tee_loader_does_not_run_a_guard_planted_anywhere_but_the_import_root(
    depth: int, tmp_path: Path
) -> None:
    module_file = _module_file(tmp_path, "tee")
    marker = _plant(module_file.parents[depth])
    assert tee_leak._load_publish_guard(module_file) is None
    assert not marker.exists()


def test_the_engine_loader_runs_the_guard_at_the_import_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the tests above: the marker does appear when a guard runs."""
    module_file = _module_file(tmp_path, "messagefoundry")
    marker = _plant(module_file.parents[_IMPORT_ROOT])
    loaded = _engine_load(monkeypatch, module_file)
    assert marker.exists()
    assert loaded.__file__ == str(marker.with_name("scan_forbidden.py"))


def test_the_tee_loader_runs_the_guard_at_the_import_root(tmp_path: Path) -> None:
    """The control for the tee tests above."""
    module_file = _module_file(tmp_path, "tee")
    marker = _plant(module_file.parents[_IMPORT_ROOT])
    assert tee_leak._load_publish_guard(module_file) is not None
    assert marker.exists()


def test_the_guard_at_the_import_root_wins_over_one_planted_above_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_file = _module_file(tmp_path, "messagefoundry")
    ours = _plant(module_file.parents[_IMPORT_ROOT])
    planted = _plant(module_file.parents[_IMPORT_ROOT + 1])
    _engine_load(monkeypatch, module_file)
    assert ours.exists()
    assert not planted.exists()


def test_the_leak_check_still_refuses_when_no_guard_is_at_the_import_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail-closed: with a guard planted above and none at the root, the check raises. It does
    not report the text clean."""
    module_file = _module_file(tmp_path, "messagefoundry")
    marker = _plant(module_file.parents[_IMPORT_ROOT + 1])
    monkeypatch.setattr(engine_leak, "__file__", str(module_file))
    monkeypatch.setattr(engine_leak, "_scanner", engine_leak._scanner.__wrapped__)
    with pytest.raises(engine_leak.LeakCheckUnavailable):
        engine_leak.leak_check(_MESSAGE)
    with pytest.raises(engine_leak.LeakCheckUnavailable):
        engine_leak.leak_report(_MESSAGE)
    assert not marker.exists()


@pytest.mark.skipif(
    not _CHECKOUT_GUARD.is_file(),
    reason="needs scripts/security/scan_forbidden.py beside tests/ (absent outside a checkout)",
)
def test_both_loaders_resolve_to_this_checkout() -> None:
    """In a source checkout the one path each loader builds is the repository's own guard."""
    assert Path(str(engine_leak._scanner().__file__)) == _CHECKOUT_GUARD
    # ``_GUARD`` is what the tee loaded at import, which is the call that matters there.
    assert isinstance(tee_leak._GUARD, ModuleType)
    assert Path(str(tee_leak._GUARD.__file__)) == _CHECKOUT_GUARD


def _loops_over_parents(source: str) -> list[int]:
    """Line numbers of every ``for`` loop or comprehension that iterates a ``.parents`` attribute."""
    iterables = [
        node.iter
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.For | ast.AsyncFor | ast.comprehension)
    ]
    return [
        inner.lineno
        for iterable in iterables
        for inner in ast.walk(iterable)
        if isinstance(inner, ast.Attribute) and inner.attr == "parents"
    ]


@pytest.mark.parametrize("module", [engine_leak, tee_leak], ids=["engine", "tee"])
def test_neither_leak_module_loops_over_its_parents(module: ModuleType) -> None:
    """A cheap tripwire for the old loop's shape only. The planted-file tests above are the real
    check: any search that tries the nearest folder first runs one of their guards."""
    source = Path(str(module.__file__)).read_text(encoding="utf-8")
    assert _loops_over_parents(source) == []


def test_the_parents_loop_detector_fires() -> None:
    assert _loops_over_parents("for p in here.parents:\n    pass\n") == [1]
    assert _loops_over_parents("x = [p for p in Path(f).resolve().parents]\n") == [1]
    assert _loops_over_parents("root = here.parents[2]\nfor p in (1, 2):\n    pass\n") == []
