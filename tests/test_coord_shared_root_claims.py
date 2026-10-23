# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Claims, allocations, lanes and the owner log follow the shared coordination root, and read HOST.

docs/COORD-SHARED-ROOT.md moves the fleet-wide part of ``mefor-coord/`` onto one shared root. Two
things have to hold for that to be safe, and this file pins both for the group of scripts that own
claims, allocations, lanes and the owner log:

* **Where.** With ``MEFOR_COORD_ROOT`` set, a claim or an allocation lands under the shared root and
  nothing lands in the local copy. A root that does not answer REFUSES an exclusive writer; it never
  falls back to the local path, which would split the fleet into two registries.
* **Whose.** A record carries ``host``. A record from another machine names a path on THAT machine's
  disk, so a missing path here proves nothing: it must never read as HOLDER GONE, never be released by
  a sweep, and never count as this tree's. A record with no ``host`` is this machine's, which keeps
  every legacy record judged exactly as before. Every such test pairs the two.

The two Python git hooks load ``coord_root.py`` by path rather than carry a copy, so the last section
checks that an installed gate finds it beside itself and refuses when it is missing.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
HOOKS = ROOT / "scripts" / "hooks"
TIMEOUT = 45
OTHER = "OTHER-PC"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the coordination scripts need pwsh on Windows",
)

# Copied into each sandbox: the scripts anchor on where they LIVE (BACKLOG #1060), so the copies are
# what run. coord-root.ps1 rides along, so the sandbox resolves exactly as the real tree does.
SCRIPTS = (
    "claim.ps1",
    "claim-reconcile.ps1",
    "claim-adjudicate.ps1",
    "alloc.ps1",
    "lane.ps1",
    "mail-key.ps1",
    "coord-root.ps1",
    "occupancy.ps1",
    "session-registry.ps1",
)


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


coord_root = _load(COORD / "coord_root.py", "coord_root_for_shared_claims")
claim_check = _load(HOOKS / "claim_check.py", "claim_check_for_shared_claims")
ledger_check = _load(HOOKS / "ledger_check.py", "ledger_check_for_shared_claims")


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    (r / "docs" / "adr").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    for name in SCRIPTS:
        shutil.copy2(COORD / name, r / "scripts" / "coord" / name)
    (r / "docs" / "adr" / "0001-first.md").write_text("# First\n", encoding="utf-8")
    # claim-adjudicate.ps1 refuses to run over a backlog namespace it could not read.
    (r / "docs" / "BACKLOG.md").write_text("# Backlog\n", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base", "--no-verify")
    return r


@pytest.fixture
def shared(tmp_path: Path) -> Path:
    d = tmp_path / "shared-root"
    d.mkdir()
    return d


def local_coord(repo: Path) -> Path:
    local = coord_root.local_root(repo)
    assert local is not None
    return Path(local)


def run(
    repo: Path, script: str, *args: str, root: Path | None = None
) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "MEFOR_COORD_ROOT"}
    if root is not None:
        env["MEFOR_COORD_ROOT"] = str(root)
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / script),
            *args,
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=TIMEOUT,
    )


def this_host() -> str:
    return str(coord_root.host())


def write_claim(claims: Path, key: str, holder: Path | str, branch: str, host: str | None) -> Path:
    """A claim the way claim.ps1 writes one, with or without the ``host`` field."""
    claims.mkdir(parents=True, exist_ok=True)
    rec: dict[str, str] = {
        "key": key,
        "note": "n",
        "branch": branch,
        "worktree": str(holder).replace("\\", "/"),
        "claimed": "2026-08-01T00:00:00.0000000-05:00",
    }
    if host is not None:
        rec["host"] = host
    p = claims / f"{key}.json"
    p.write_bytes(json.dumps(rec).encode("utf-8"))
    return p


# --------------------------------------------------------------------------------------------------
# WHERE: claims, allocations, lanes and the owner log land under the shared root
# --------------------------------------------------------------------------------------------------


def test_a_claim_lands_under_the_shared_root_and_carries_host(repo: Path, shared: Path) -> None:
    proc = run(repo, "claim.ps1", "-Take", "k1", "-Note", "w", root=shared)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    rec = json.loads((shared / "claims" / "k1.json").read_text(encoding="utf-8"))
    assert rec["host"].casefold() == this_host().casefold()
    assert not (local_coord(repo) / "claims" / "k1.json").exists(), "a shared kind landed locally"

    # The release reads and records in the same shared registry.
    proc = run(repo, "claim.ps1", "-Release", "k1", root=shared)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (shared / "claims" / "k1.json").exists()
    history = (shared / "claims" / ".history").read_text(encoding="utf-8").strip().splitlines()
    assert json.loads(history[-1])["host"].casefold() == this_host().casefold()


def test_nothing_configured_keeps_todays_local_registry(repo: Path) -> None:
    proc = run(repo, "claim.ps1", "-Take", "k1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (local_coord(repo) / "claims" / "k1.json").is_file()


def test_an_unanswering_root_refuses_take_and_writes_nowhere(repo: Path, tmp_path: Path) -> None:
    missing = tmp_path / "no-such-root"
    proc = run(repo, "claim.ps1", "-Take", "k1", root=missing)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "REFUSED" in proc.stderr
    assert str(missing) in proc.stderr, "the refusal must name what did not answer"
    assert not (local_coord(repo) / "claims").exists(), "it fell back to the local registry"
    assert not missing.exists()


@pytest.mark.parametrize("configured", [True, False], ids=["root-configured", "nothing-configured"])
@pytest.mark.parametrize(
    "script", ["claim.ps1", "alloc.ps1", "claim-reconcile.ps1", "claim-adjudicate.ps1", "lane.ps1"]
)
def test_a_copy_without_the_resolver_refuses_loudly(
    repo: Path, shared: Path, script: str, configured: bool
) -> None:
    """coord-root.ps1 is the one definition of where. A copy without it refuses, configured or not.

    It used to run at the local path when nothing was configured, which needed a second copy of the
    "is anything configured" rule in every script. That copy is gone, so the unconfigured case is
    the one that proves it: a fallback would exit 0 there.
    """
    (repo / "scripts" / "coord" / "coord-root.ps1").unlink()
    args = {
        "claim.ps1": ["-Take", "k1"],
        "alloc.ps1": ["-Kind", "adr", "-Title", "T", "-NoFetch"],
        "claim-reconcile.ps1": [],
        "claim-adjudicate.ps1": [],
        "lane.ps1": ["-Show"],
    }[script]
    proc = run(repo, script, *args, root=shared if configured else None)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "REFUSED" in proc.stderr and "coord-root.ps1 is missing" in proc.stderr, proc.stderr
    assert not any(shared.iterdir()), "it wrote to the shared root"
    assert not (local_coord(repo) / "claims").exists(), "it fell back to the local registry"
    assert not (local_coord(repo) / "alloc").exists(), "it fell back to the local registry"


def test_an_allocation_lands_under_the_shared_root_and_carries_host(
    repo: Path, shared: Path
) -> None:
    proc = run(repo, "alloc.ps1", "-Kind", "adr", "-Title", "T", "-NoFetch", root=shared)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    records = list((shared / "alloc" / "adr").glob("*.json"))
    assert len(records) == 1
    rec = json.loads(records[0].read_text(encoding="utf-8"))
    assert rec["host"].casefold() == this_host().casefold()
    assert not (local_coord(repo) / "alloc").exists(), "a shared kind landed locally"


def test_an_unanswering_root_refuses_an_allocation(repo: Path, tmp_path: Path) -> None:
    proc = run(repo, "alloc.ps1", "-Kind", "adr", "-Title", "T", "-NoFetch", root=tmp_path / "gone")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "REFUSED" in proc.stderr
    assert not (local_coord(repo) / "alloc").exists()


def test_another_machines_allocation_at_this_path_is_not_handed_back(
    repo: Path, shared: Path
) -> None:
    """Re-entrancy keys on the owner. The same path on another PC is another owner."""
    top = git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    adr = shared / "alloc" / "adr"
    adr.mkdir(parents=True)
    (adr / "0002.json").write_bytes(
        json.dumps(
            {
                "number": "0002",
                "kind": "adr",
                "title": "T",
                "branch": "main",
                "worktree": top,
                "host": OTHER,
            }
        ).encode("utf-8")
    )
    proc = run(repo, "alloc.ps1", "-Kind", "adr", "-Title", "T", "-NoFetch", root=shared)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "REUSING" not in proc.stdout
    assert "ALLOCATED ADR 0003" in proc.stdout, proc.stdout


def test_a_lane_level_lands_under_the_shared_root(repo: Path, shared: Path) -> None:
    proc = run(repo, "lane.ps1", "-Free", "1", "-InFlight", "2", "-Note", "n", root=shared)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    records = list((shared / "lanes").glob("*.json"))
    assert len(records) == 1
    rec = json.loads(records[0].read_text(encoding="utf-8-sig"))
    assert rec["host"].casefold() == this_host().casefold()
    assert not (local_coord(repo) / "lanes").exists()


def _box_key(path: Path, host: str) -> str:
    """The box key from the real mail-key.ps1, for any host."""
    lib = COORD / "mail-key.ps1"
    script = f". '{lib}'; ConvertTo-BoxKey -Path $env:BK_PATH -HostName $env:BK_HOST"
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
        env=dict(os.environ, BK_PATH=str(path), BK_HOST=host),
    ).stdout.strip()


def test_another_machines_lane_at_the_same_path_is_its_own_file(repo: Path, shared: Path) -> None:
    # The box key hashes the host as well as the path (docs/COORD-SHARED-ROOT.md, step 4), so the
    # other PC's lane at this path has its own file, and a write here neither refuses nor touches it.
    lanes = shared / "lanes"
    lanes.mkdir()
    theirs = lanes / f"{_box_key(repo, OTHER)}.json"
    theirs.write_text(
        json.dumps({"v": 1, "host": OTHER, "worktree": str(repo), "statedFree": 2}),
        encoding="utf-8",
    )
    before = theirs.read_bytes()

    proc = run(repo, "lane.ps1", "-Free", "0", "-InFlight", "3", root=shared)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert theirs.read_bytes() == before
    mine = json.loads(
        (lanes / f"{_box_key(repo, this_host())}.json").read_text(encoding="utf-8-sig")
    )
    assert mine["statedFree"] == 0
    assert mine["host"].casefold() == this_host().casefold()


def test_a_lane_record_naming_another_machine_is_not_overwritten(repo: Path, shared: Path) -> None:
    # The host-keyed box key keeps another PC's lane in its own file, so a record at THIS key that
    # names another host is a copied, hand-made or colliding record. A write still refuses it and
    # leaves it alone rather than taking it over; -Show only reads.
    assert run(repo, "lane.ps1", "-Free", "1", "-InFlight", "2", root=shared).returncode == 0
    (record,) = list((shared / "lanes").glob("*.json"))
    rec = json.loads(record.read_text(encoding="utf-8-sig"))
    rec["host"] = OTHER
    record.write_text(json.dumps(rec), encoding="utf-8")
    before = record.read_bytes()

    proc = run(repo, "lane.ps1", "-Free", "0", "-InFlight", "3", root=shared)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert OTHER in proc.stderr
    assert record.read_bytes() == before
    assert run(repo, "lane.ps1", "-Show", root=shared).returncode == 0


def test_asked_does_not_take_over_another_machines_lane_record(repo: Path, shared: Path) -> None:
    # -Asked writes a stamp, so it meets the same refusal as a stated level.
    assert run(repo, "lane.ps1", "-Free", "1", "-InFlight", "2", root=shared).returncode == 0
    (record,) = list((shared / "lanes").glob("*.json"))
    rec = json.loads(record.read_text(encoding="utf-8-sig"))
    rec["host"] = OTHER
    record.write_text(json.dumps(rec), encoding="utf-8")
    before = record.read_bytes()

    proc = run(repo, "lane.ps1", "-Asked", root=shared)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert OTHER in proc.stderr
    assert record.read_bytes() == before


def test_the_owner_log_follows_the_shared_root(
    repo: Path, shared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MEFOR_OWNER_LOG", raising=False)
    monkeypatch.setenv("MEFOR_COORD_ROOT", str(shared))
    monkeypatch.chdir(repo)
    owner_log = _load(COORD / "owner_log.py", "owner_log_for_shared_claims")
    assert Path(owner_log.ledger_path()) == shared / "owner-log" / "OWNER-ITEMS.md"

    monkeypatch.delenv("MEFOR_COORD_ROOT")
    assert Path(owner_log.ledger_path()) == local_coord(repo) / "owner-log" / "OWNER-ITEMS.md"

    monkeypatch.setenv("MEFOR_COORD_ROOT", str(repo / "no-such-root"))
    with pytest.raises(SystemExit) as exc:
        owner_log.ledger_path()
    assert exc.value.code == 2


# --------------------------------------------------------------------------------------------------
# WHOSE: a record from another machine is never gone, never reaped, never this tree's
# --------------------------------------------------------------------------------------------------


def test_list_reads_another_machines_vanished_holder_as_not_checkable(
    repo: Path, shared: Path, tmp_path: Path
) -> None:
    write_claim(shared / "claims", "k-other", tmp_path / "vanished-a", "b", OTHER)
    write_claim(shared / "claims", "k-legacy", tmp_path / "vanished-b", "b", None)

    out = run(repo, "claim.ps1", "-List", root=shared).stdout
    lines = out.splitlines()

    def held_line(key: str) -> str:
        i = next(n for n, line in enumerate(lines) if line.strip().startswith(key))
        return lines[i + 1]

    assert "ON OTHER-PC -- not checkable here" in held_line("k-other"), out
    assert "HOLDER GONE" not in held_line("k-other"), "another PC's claim read as gone"
    # The legacy record has no host, so it is this machine's and its vanished holder is GONE.
    assert "HOLDER GONE" in held_line("k-legacy"), out


def test_take_blocked_by_another_machine_never_suggests_force(
    repo: Path, shared: Path, tmp_path: Path
) -> None:
    write_claim(shared / "claims", "k", tmp_path / "vanished", "b", OTHER)
    proc = run(repo, "claim.ps1", "-Take", "k", root=shared)
    assert proc.returncode == 1
    assert "HOLDER IS ON OTHER-PC" in proc.stdout
    assert "HOLDER GONE" not in proc.stdout
    assert "-Release k -Force" not in proc.stdout


def test_the_same_path_on_another_machine_is_not_mine(repo: Path, shared: Path) -> None:
    """Two PCs can both have the path. Without the host check this release would need no -Force."""
    top = git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    claim = write_claim(shared / "claims", "k", top, "main", OTHER)
    proc = run(repo, "claim.ps1", "-Release", "k", root=shared)
    assert proc.returncode == 1, proc.stdout
    assert "REFUSING" in proc.stdout
    assert claim.exists()


def test_reconcile_never_releases_another_machines_claim(
    repo: Path, shared: Path, tmp_path: Path
) -> None:
    git(repo, "branch", "landed", "main")  # carries nothing main lacks: work that merged
    other = write_claim(shared / "claims", "k-other", tmp_path / "vanished-a", "landed", OTHER)
    legacy = write_claim(shared / "claims", "k-legacy", tmp_path / "vanished-b", "landed", None)

    proc = run(repo, "claim-reconcile.ps1", "-Json", "-NoPullRequests", root=shared)
    assert proc.returncode == 0, proc.stderr
    verdicts = {c["key"]: c["verdict"] for c in json.loads(proc.stdout)["claims"]}
    assert verdicts == {"k-other": "ELSEWHERE", "k-legacy": "RELEASABLE"}

    proc = run(repo, "claim-reconcile.ps1", "-Apply", "-NoPullRequests", root=shared)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert other.exists(), "a sweep released another PC's claim"
    assert not legacy.exists(), "control: this machine's releasable claim is released"


def test_adjudicate_reports_another_machines_claim_as_elsewhere(
    repo: Path, shared: Path, tmp_path: Path
) -> None:
    write_claim(shared / "claims", "k-other", tmp_path / "vanished-a", "b", OTHER)
    write_claim(shared / "claims", "k-legacy", tmp_path / "vanished-b", "b", None)

    proc = run(repo, "claim-adjudicate.ps1", "-Json", root=shared)
    assert proc.returncode == 0, proc.stderr
    verdicts = {c["key"]: c["verdict"] for c in json.loads(proc.stdout)["claims"]}
    assert verdicts["k-other"] == "ELSEWHERE"
    assert verdicts["k-legacy"] == "NO-ITEM", "control: a legacy record is still adjudicated here"


# --------------------------------------------------------------------------------------------------
# The hooks themselves: shared registry, and another machine's record is never this tree's
# --------------------------------------------------------------------------------------------------


def _commit_msg(repo: Path, message: str, root: Path | None) -> subprocess.CompletedProcess[str]:
    msg = repo / "COMMIT_MSG.tmp"
    msg.write_text(message, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "MEFOR_COORD_ROOT"}
    if root is not None:
        env["MEFOR_COORD_ROOT"] = str(root)
    return subprocess.run(
        [sys.executable, str(HOOKS / "claim_check.py"), str(msg)],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
        timeout=TIMEOUT,
    )


def test_the_claim_gate_reads_the_shared_registry_and_checks_host(repo: Path, shared: Path) -> None:
    (repo / "code.py").write_text("x = 1\n", encoding="utf-8")
    git(repo, "add", "code.py")
    top = git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    subject = "feat: thing (BACKLOG #42)\n"

    # Unclaimed under the shared root, even though the LOCAL registry holds a claim.
    write_claim(local_coord(repo) / "claims", "42", top, "main", None)
    proc = _commit_msg(repo, subject, shared)
    assert proc.returncode == 1 and "NOT CLAIMED" in proc.stderr, proc.stderr

    # The same path, claimed on another machine: not this tree's, and no -Force remedy.
    write_claim(shared / "claims", "42", top, "main", OTHER)
    proc = _commit_msg(repo, subject, shared)
    assert proc.returncode == 1, proc.stderr
    assert "ANOTHER machine" in proc.stderr
    assert "-Force" not in proc.stderr

    # Control: this machine's claim at the shared root passes.
    write_claim(shared / "claims", "42", top, "main", this_host())
    assert _commit_msg(repo, subject, shared).returncode == 0

    # An unanswering root refuses rather than read the local copy that would pass.
    proc = _commit_msg(repo, subject, repo / "no-such-root")
    assert proc.returncode == 1
    assert "could not be resolved" in proc.stderr


def test_the_ledger_gate_never_grants_another_machines_number(
    repo: Path, shared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    top = git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    adr = shared / "alloc" / "adr"
    adr.mkdir(parents=True)
    monkeypatch.setenv("MEFOR_COORD_ROOT", str(shared))
    monkeypatch.chdir(repo)

    def record(number: str, host: str | None) -> None:
        rec = {"number": number, "kind": "adr", "title": "t", "branch": "main", "worktree": top}
        if host is not None:
            rec["host"] = host
        (adr / f"{number}.json").write_bytes(json.dumps(rec).encode("utf-8"))

    record("0002", OTHER)
    record("0003", None)
    record("0004", this_host())
    ledger = ledger_check.Ledger(ci=False)
    assert ledger.alloc == adr.parent
    assert not ledger.owns("adr", "0002"), "the same path and branch on another PC is not this tree"
    assert ledger.owns("adr", "0003"), "control: a legacy record is this machine's"
    assert ledger.owns("adr", "0004")

    monkeypatch.setenv("MEFOR_COORD_ROOT", str(repo / "no-such-root"))
    ledger = ledger_check.Ledger(ci=False)
    assert ledger.alloc is None and ledger.alloc_error
    assert not ledger.owns("adr", "0003"), "an unresolved registry grants nothing"


def _gate_copy(tmp_path: Path, with_resolver: bool) -> Path:
    """claim_check.py laid out as install-git-hooks.ps1 lays it out, with or without coord_root.py."""
    hooks = tmp_path / "installed-hooks"
    hooks.mkdir()
    shutil.copy2(HOOKS / "claim_check.py", hooks / "claim_check.py")
    if with_resolver:
        shutil.copy2(COORD / "coord_root.py", hooks / "coord_root.py")
    return hooks / "claim_check.py"


@pytest.mark.parametrize("with_resolver", [True, False], ids=["beside", "missing"])
def test_an_installed_claim_gate_loads_the_resolver_beside_it_or_refuses(
    repo: Path, shared: Path, tmp_path: Path, with_resolver: bool
) -> None:
    (repo / "code.py").write_text("x = 1\n", encoding="utf-8")
    git(repo, "add", "code.py")
    top = git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    write_claim(shared / "claims", "42", top, "main", this_host())
    gate = _gate_copy(tmp_path, with_resolver)
    msg = repo / "COMMIT_MSG.tmp"
    msg.write_text("feat: thing (BACKLOG #42)\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "MEFOR_COORD_ROOT"}
    env["MEFOR_COORD_ROOT"] = str(shared)
    proc = subprocess.run(
        [sys.executable, str(gate), str(msg)],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
        timeout=TIMEOUT,
    )
    if with_resolver:
        assert proc.returncode == 0, proc.stderr
    else:
        assert proc.returncode == 1, proc.stderr
        assert "coord_root.py could not be loaded" in proc.stderr
