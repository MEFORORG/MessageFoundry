# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The coordination root resolver: ``scripts/coord/coord-root.ps1`` and its twin ``coord_root.py``.

Every case runs through BOTH, and asserts they give one answer. Two resolvers that disagree are two
registries, which is the cross-PC split this resolver exists to end (docs/COORD-SHARED-ROOT.md).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
PS = ROOT / "scripts" / "coord" / "coord-root.ps1"
PY = ROOT / "scripts" / "coord" / "coord_root.py"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="coord-root.ps1 needs pwsh on Windows",
)

# TEST-NET-1 (RFC 5737): never routed, so a connect to it can only time out.
_DEAD_UNC = r"\\192.0.2.1\nothing\mefor-coord"


def _load_py() -> ModuleType:
    spec = importlib.util.spec_from_file_location("coord_root_under_test", PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


coord_root = _load_py()


@pytest.fixture(autouse=True)
def _no_inherited_root(monkeypatch: pytest.MonkeyPatch) -> None:
    # An owner shell with the variable set must not steer these tests into the live shared root.
    monkeypatch.delenv("MEFOR_COORD_ROOT", raising=False)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "-C", str(r), "init", "-q"], check=True, capture_output=True)
    return r


def _local(repo: Path) -> Path:
    common = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return Path(common) / "mefor-coord"


def _ps(repo: Path, kind: str) -> dict[str, object]:
    script = (
        f". '{PS}'; $r = Resolve-CoordDir -From '{repo}' -Kind '{kind}'; "
        "[pscustomobject]@{ Path = $r.Path; Shared = $r.Shared; Source = $r.Source; Error = $r.Error } "
        "| ConvertTo-Json -Compress"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    out: dict[str, object] = json.loads(proc.stdout)
    return out


def _both(repo: Path, kind: str) -> tuple[dict[str, object], Any]:
    ps = _ps(repo, kind)
    py = coord_root.resolve(kind, repo)
    assert ps["Shared"] == py.shared
    assert ps["Source"] == py.source
    assert (ps["Error"] is None) == (py.error is None), (ps, py)
    if py.path is None:
        assert ps["Path"] is None
    else:
        assert Path(str(ps["Path"])) == py.path
    return ps, py


def _norm(p: object) -> str:
    return str(p).replace("\\", "/").rstrip("/").lower()


def test_shared_kind_lists_agree() -> None:
    text = PS.read_text(encoding="utf-8")
    m = re.search(r"\$script:CoordSharedKinds = @\(([^)]*)\)", text)
    assert m, "CoordSharedKinds not found in coord-root.ps1"
    ps_kinds = tuple(re.findall(r"'([^']+)'", m.group(1)))
    assert ps_kinds == coord_root.SHARED_KINDS


def test_nothing_configured_is_todays_local_path(repo: Path) -> None:
    for kind in ("seats", "overlap-cache"):
        ps, py = _both(repo, kind)
        assert py.error is None
        assert py.source == "local"
        assert _norm(py.path) == _norm(_local(repo) / kind)


def test_env_moves_shared_kinds_only(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setenv("MEFOR_COORD_ROOT", str(shared))
    ps, py = _both(repo, "mail")
    assert py.source == "env"
    assert _norm(py.path) == _norm(shared / "mail")
    ps, py = _both(repo, "announce")
    assert py.source == "local"
    assert _norm(py.path) == _norm(_local(repo) / "announce")


def test_root_toml_literal_string(repo: Path, tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    local = _local(repo)
    local.mkdir(parents=True)
    (local / "root.toml").write_text(
        f"# the PC's share\nshared_root = '{shared}'  # comment\n", encoding="utf-8"
    )
    ps, py = _both(repo, "claims")
    assert py.source == "file"
    assert _norm(py.path) == _norm(shared / "claims")


@pytest.mark.parametrize(
    "body",
    [
        'shared_root = "C:\\\\x"\n',  # a basic string: refused, never half-parsed
        "shared_root = ''\n",
        "# only a comment\n",
        "other = 'x'\n",
    ],
)
def test_bad_root_toml_is_an_error_not_a_fallback(repo: Path, body: str) -> None:
    local = _local(repo)
    local.mkdir(parents=True)
    (local / "root.toml").write_text(body, encoding="utf-8")
    ps, py = _both(repo, "seats")
    assert py.error is not None
    assert py.path is None
    # A local kind is unaffected by a broken shared setting.
    ps, py = _both(repo, "test-slots")
    assert py.error is None


def test_missing_shared_dir_is_an_error(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MEFOR_COORD_ROOT", str(tmp_path / "absent"))
    ps, py = _both(repo, "alloc")
    assert py.error is not None and "does not exist" in py.error


def test_dead_unc_fails_fast_and_caches_the_verdict(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MEFOR_COORD_ROOT", _DEAD_UNC)
    start = time.monotonic()
    py = coord_root.resolve("claims", repo)
    first = time.monotonic() - start
    assert py.error is not None and "unreachable" in py.error
    assert first < 10
    down = _local(repo) / "coord-root-down.json"
    assert down.is_file()
    start = time.monotonic()
    ps = _ps(repo, "claims")
    assert ps["Error"] is not None and "cached" in str(ps["Error"])
    py2 = coord_root.resolve("claims", repo)
    assert py2.error is not None and "cached" in py2.error
    assert time.monotonic() - start < 30


# Regressions from the adversarial review of 2026-10-21. Each one reproduced a twin disagreement, an
# unbounded probe, or a cache that answered for the wrong root.


def test_utf16_root_toml_agrees(repo: Path, tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    local = _local(repo)
    local.mkdir(parents=True)
    # What Windows PowerShell 5.1 writes with `>`: UTF-16LE with a BOM.
    (local / "root.toml").write_bytes(f"shared_root = '{shared}'\r\n".encode("utf-16"))
    ps, py = _both(repo, "mail")
    assert py.error is None
    assert _norm(py.path) == _norm(shared / "mail")


def test_non_utf8_root_toml_is_an_error_on_both(repo: Path) -> None:
    local = _local(repo)
    local.mkdir(parents=True)
    (local / "root.toml").write_bytes("shared_root = 'C:/caf\xe9'\n".encode("cp1252"))
    ps, py = _both(repo, "mail")
    assert py.error is not None and ps["Error"] is not None


@pytest.mark.parametrize(
    "body",
    ["shared_root = 'C:\\a'\nshared_root = 'C:\\b'\n", "shared_root = 'C:\\a'\njunk\n"],
)
def test_every_line_of_root_toml_is_checked(repo: Path, body: str) -> None:
    local = _local(repo)
    local.mkdir(parents=True)
    (local / "root.toml").write_text(body, encoding="utf-8")
    ps, py = _both(repo, "seats")
    assert py.error is not None


def test_a_root_toml_directory_is_an_error_not_a_fallback(repo: Path) -> None:
    (_local(repo) / "root.toml").mkdir(parents=True)
    ps, py = _both(repo, "seats")
    assert py.error is not None and "not a file" in py.error


def test_a_non_ascii_whitespace_char_is_not_trimmed_on_either_side(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setenv("MEFOR_COORD_ROOT", str(shared) + "\x1c")
    ps, py = _both(repo, "seats")
    assert py.error is not None


def test_the_down_cache_answers_only_for_its_own_root(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    down = _local(repo) / "coord-root-down.json"
    down.parent.mkdir(parents=True)
    down.write_text(json.dumps({"root": r"\elsewhere\x", "at": "now"}), encoding="utf-8")
    monkeypatch.setenv("MEFOR_COORD_ROOT", _DEAD_UNC)
    py = coord_root.resolve("claims", repo)
    assert py.error is not None and "cached" not in py.error


def test_a_future_stamped_down_cache_is_ignored(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    down = _local(repo) / "coord-root-down.json"
    down.parent.mkdir(parents=True)
    down.write_text(json.dumps({"root": _DEAD_UNC, "at": "later"}), encoding="utf-8")
    future = time.time() + 86400
    os.utime(down, (future, future))
    monkeypatch.setenv("MEFOR_COORD_ROOT", _DEAD_UNC)
    py = coord_root.resolve("claims", repo)
    assert py.error is not None and "cached" not in py.error
    os.utime(down, (future, future))
    ps = _ps(repo, "claims")
    assert ps["Error"] is not None and "cached" not in str(ps["Error"])


def test_an_unresolvable_host_is_bounded_in_python(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A single-label name for a PC that is off: getaddrinfo is NOT covered by a socket timeout.
    monkeypatch.setenv("MEFOR_COORD_ROOT", r"\meforprobezzq\share\mefor-coord")
    start = time.monotonic()
    py = coord_root.resolve("claims", repo)
    assert py.error is not None
    assert time.monotonic() - start < 3


def test_missing_kind_does_not_throw_in_powershell(repo: Path) -> None:
    script = f". '{PS}'; $r = Resolve-CoordDir -From '{repo}'; $r.Error"
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "needs -Kind" in proc.stdout
