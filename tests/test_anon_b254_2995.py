# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The site-code token loader reads ONE file path and searches no other folder (BACKLOG #2995).

Both ``surrogates.py`` copies read the git-ignored ``scripts/security/scan-tokens.local.txt`` when
``MEFOR_FORBIDDEN_TOKENS`` is unset. Each used to try every folder above its own file and read the
first match, so a file at that path above an installed copy would have set the site-code prefixes.
Each now builds a single path, under the folder that holds its package.

Every planted token file here lives under ``tmp_path`` and holds a made-up two-digit prefix. "It was
read" is taken from the text the loader returns, because reading a text file leaves no marker.

``MEFOR_FORBIDDEN_TOKENS`` wins over the file, and a developer machine usually sets it. Every test
here unsets it first. Without that, each planted-file case would pass on the old search too.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry.anon import surrogates as engine_surrogates
from tee.anon import surrogates as tee_surrogates

_TOKEN_PARTS = ("scripts", "security", "scan-tokens.local.txt")
_REPO_ROOT = Path(__file__).resolve().parents[1]

# A place is ``module_file.parents[n]``. The module sits at ``<root>/<package>/anon/surrogates.py``,
# so 2 is the import root, the one place a token file may be read from.
_IMPORT_ROOT = 2
_WRONG_PLACES = [
    pytest.param(0, id="the anon folder"),
    pytest.param(1, id="the package folder"),
    pytest.param(3, id="one folder above the import root"),
    pytest.param(4, id="two folders above the import root"),
]

_BOTH = pytest.mark.parametrize(
    "module", [engine_surrogates, tee_surrogates], ids=["engine", "tee"]
)


@pytest.fixture(autouse=True)
def no_token_variable(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Unset the variable for the test, then put the real source back and recompute from it.

    The undo comes BEFORE the reload, as in ``tests/test_anon_core.py``: a reload under the patched
    state would leave both modules' prefixes stale for the rest of the session."""
    monkeypatch.delenv("MEFOR_FORBIDDEN_TOKENS", raising=False)
    yield
    monkeypatch.undo()
    engine_surrogates.reload_site_prefixes()
    tee_surrogates.reload_site_prefixes()


def _stand_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: ModuleType) -> Path:
    """Make ``module`` believe it lives under a made-up import root with two folders above it."""
    package = "tee" if module is tee_surrogates else "messagefoundry"
    path = tmp_path / "above2" / "above1" / "root" / package / "anon" / "surrogates.py"
    path.parent.mkdir(parents=True)
    path.write_text("", encoding="utf-8")
    monkeypatch.setattr(module, "__file__", str(path))
    return path


def _plant(folder: Path, prefix: str) -> str:
    """Plant a token file naming ``prefix`` under ``folder`` and return its text."""
    token_file = folder.joinpath(*_TOKEN_PARTS)
    token_file.parent.mkdir(parents=True)
    text = f"[site_prefix]\n{prefix}\n"
    token_file.write_text(text, encoding="utf-8")
    return text


@_BOTH
@pytest.mark.parametrize("depth", _WRONG_PLACES)
def test_a_token_file_planted_anywhere_but_the_import_root_is_not_read(
    module: ModuleType, depth: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_file = _stand_in(tmp_path, monkeypatch, module)
    _plant(module_file.parents[depth], "88")
    assert module._resolve_token_text() is None


@_BOTH
def test_the_token_file_at_the_import_root_is_read(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the test above: a planted file is returned when the loader reads it."""
    module_file = _stand_in(tmp_path, monkeypatch, module)
    ours = _plant(module_file.parents[_IMPORT_ROOT], "77")
    assert module._resolve_token_text() == ours


@_BOTH
def test_the_import_root_wins_over_a_token_file_planted_nearer(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A nearest-first search reads the package folder's file. The one built path does not."""
    module_file = _stand_in(tmp_path, monkeypatch, module)
    _plant(module_file.parents[1], "88")
    ours = _plant(module_file.parents[_IMPORT_ROOT], "77")
    assert module._resolve_token_text() == ours


@_BOTH
def test_a_token_file_above_the_import_root_sets_no_site_prefix(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same refusal read where it matters: the detector a planted file would have armed."""
    module_file = _stand_in(tmp_path, monkeypatch, module)
    _plant(module_file.parents[_IMPORT_ROOT + 1], "88")
    module.reload_site_prefixes()
    assert module._SITE_PREFIXES == ()
    assert module.SITE_CODE_RE.fullmatch("881234") is None


@_BOTH
def test_the_token_file_at_the_import_root_sets_the_site_prefix(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the test above: the detector does arm from a file the loader reads."""
    module_file = _stand_in(tmp_path, monkeypatch, module)
    _plant(module_file.parents[_IMPORT_ROOT], "77")
    module.reload_site_prefixes()
    assert module._SITE_PREFIXES == ("77",)
    assert module.SITE_CODE_RE.fullmatch("771234") is not None


@_BOTH
def test_a_module_path_too_short_to_have_an_import_root_yields_no_source(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``reload_site_prefixes`` runs at import and promises never to raise. A file directly under
    the drive or filesystem root has one parent, so ``parents[2]`` is an ``IndexError`` there."""
    shallow = Path(tmp_path.anchor) / "surrogates.py"
    assert len(shallow.parents) <= _IMPORT_ROOT
    monkeypatch.setattr(module, "__file__", str(shallow))
    assert module._resolve_token_text() is None
    module.reload_site_prefixes()
    assert module._SITE_PREFIXES == ()


@_BOTH
def test_the_variable_still_wins_over_the_token_file(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Why every other test here unsets the variable: set, it hides the file from the loader."""
    module_file = _stand_in(tmp_path, monkeypatch, module)
    _plant(module_file.parents[_IMPORT_ROOT], "77")
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", "[site_prefix]\n66\n")
    assert module._resolve_token_text() == "[site_prefix]\n66"
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", "")
    assert module._resolve_token_text() is None


@_BOTH
def test_the_import_root_of_each_module_is_this_checkout(module: ModuleType) -> None:
    """In a source checkout the one path each loader builds sits under the repository root, beside
    the scanner that reads the same file. Nothing here opens the token file itself."""
    assert Path(str(module.__file__)).resolve().parents[_IMPORT_ROOT] == _REPO_ROOT
    assert _REPO_ROOT.joinpath(*_TOKEN_PARTS[:-1], "scan_forbidden.py").is_file()
