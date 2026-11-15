# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0050 — single project-root config anchoring.

Covers the pure anchor helpers (resolve_project_root / anchor_under_root / graph_references_env) and
the end-to-end precedence + scoped fail-loud trigger exercised through the offline ``validate``
subcommand (the smallest CLI surface that runs the anchor resolver without starting a server).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.anchor import (
    anchor_under_root,
    graph_references_env,
    referenced_env_keys_in_graph,
    resolve_project_root,
)
from messagefoundry.config.wiring import load_config
from tests.test_audit_keyless_chain_flagged import _AT_REST_ENV

# A graph that references env() (an outbound host) — the AC-3 precondition.
_ENV_GRAPH = """
    from messagefoundry import inbound, outbound, MLLP, router, handler, Send, env

    inbound("IB_T", MLLP(port=2599), router="r")
    outbound("OB_T", MLLP(host=env("peer_host"), port=6000))

    @router(name="r")
    def r(msg):
        return ["h"]

    @handler(name="h")
    def h(msg):
        return [Send("OB_T", msg.raw)]
"""

# A graph with ZERO env() references — a legitimate deployment that ships no value file.
_NO_ENV_GRAPH = """
    from messagefoundry import inbound, outbound, MLLP, router, handler, Send

    inbound("IB_T", MLLP(port=2599), router="r")
    outbound("OB_T", MLLP(host="10.0.0.1", port=6000))

    @router(name="r")
    def r(msg):
        return ["h"]

    @handler(name="h")
    def h(msg):
        return [Send("OB_T", msg.raw)]
"""


def _config_dir(parent: Path, body: str, *, name: str = "config") -> Path:
    d = parent / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "feed.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return d


# --- pure anchor helpers ------------------------------------------------------------------------


def test_resolve_project_root_empty_is_none(tmp_path: Path) -> None:
    # No root -> None, so every member keeps its CWD-relative default (today's behavior).
    assert resolve_project_root(None, cwd=tmp_path) is None
    assert resolve_project_root("", cwd=tmp_path) is None


def test_resolve_project_root_relative_is_under_cwd(tmp_path: Path) -> None:
    assert resolve_project_root("repo", cwd=tmp_path) == tmp_path / "repo"


def test_resolve_project_root_absolute_wins(tmp_path: Path) -> None:
    abs_root = (tmp_path / "abs_repo").resolve()
    assert resolve_project_root(str(abs_root), cwd=tmp_path / "elsewhere") == abs_root


def test_anchor_under_root_relative_follows_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    # A relative member resolves under the root, regardless of cwd.
    assert anchor_under_root("messagefoundry.db", root, cwd=tmp_path / "wd") == str(
        root / "messagefoundry.db"
    )


def test_anchor_under_root_absolute_bypasses_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    abs_db = str((tmp_path / "fastvol" / "store.db").resolve())
    # AC-7: an explicit absolute path is honored as-is even when a root is set.
    assert anchor_under_root(abs_db, root, cwd=tmp_path) == abs_db


def test_anchor_under_root_no_root_passes_value_through(tmp_path: Path) -> None:
    # With no root the value is returned UNCHANGED (byte-for-byte back-compat) — the CWD-relative
    # resolution happens downstream exactly as before, so the stored string is not rewritten.
    assert anchor_under_root("db.sqlite", None, cwd=tmp_path) == "db.sqlite"


def test_anchor_under_root_none_passes_through(tmp_path: Path) -> None:
    # An unset flag (None) stays None so it falls through to its own default downstream.
    assert anchor_under_root(None, tmp_path, cwd=tmp_path) is None


def test_graph_references_env_detects_env_outbound(tmp_path: Path) -> None:
    reg = load_config(_config_dir(tmp_path, _ENV_GRAPH))
    assert graph_references_env(reg) is True
    assert referenced_env_keys_in_graph(reg) == ["peer_host"]


def test_graph_references_env_false_for_zero_env_graph(tmp_path: Path) -> None:
    reg = load_config(_config_dir(tmp_path, _NO_ENV_GRAPH))
    assert graph_references_env(reg) is False
    assert referenced_env_keys_in_graph(reg) == []


# --- AC-3: scoped fail-loud through the offline `validate` subcommand ----------------------------


def test_explicit_root_with_env_refs_missing_file_fails_loud(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Explicit root + env()-referencing graph + absent <env>.toml -> hard fail (non-zero exit) naming
    # the resolved path. The single new hard failure (AC-3).
    cfg = _config_dir(tmp_path, _ENV_GRAPH)
    rc = main(["validate", "--project-root", str(tmp_path), "--config", str(cfg), "--env", "prod"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "references env()" in err
    assert "prod.toml" in err


def test_no_env_refs_missing_file_stays_silent_empty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Zero-env() graph: a missing value file is NOT an error even under an explicit root (AC-3's
    # never-regress clause). validate returns 0 with no problems.
    cfg = _config_dir(tmp_path, _NO_ENV_GRAPH)
    rc = main(
        [
            "validate",
            "--project-root",
            str(tmp_path),
            "--config",
            str(cfg),
            "--env",
            "prod",
            "--json",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert out.strip() == "[]"


def test_env_refs_with_present_file_does_not_fail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Same env()-referencing graph, but the value file EXISTS under the root -> no fail-loud.
    cfg = _config_dir(tmp_path, _ENV_GRAPH)
    envdir = tmp_path / "environments"
    envdir.mkdir()
    (envdir / "prod.toml").write_text('peer_host = "10.0.0.9"\n', encoding="utf-8")
    rc = main(
        [
            "validate",
            "--project-root",
            str(tmp_path),
            "--config",
            str(cfg),
            "--env",
            "prod",
            "--json",
        ]
    )
    assert rc == 0
    assert capsys.readouterr().out.strip() == "[]"


def test_env_refs_missing_file_without_root_does_not_fail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # env()-referencing graph + --env but NO --project-root -> the silent-empty default is preserved
    # (the fail-loud is scoped to an EXPLICIT root). No hard failure.
    cfg = _config_dir(tmp_path, _ENV_GRAPH)
    rc = main(["validate", "--config", str(cfg), "--env", "prod", "--json"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "[]"


# --- precedence: relative --config resolves under the root ---------------------------------------


def test_relative_config_resolves_under_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The graph lives under <root>/config, but serve/validate is launched from an unrelated CWD with a
    # RELATIVE --config. Anchored under --project-root, it is still found (the split-anchor fix).
    _config_dir(tmp_path, _NO_ENV_GRAPH, name="config")
    elsewhere = tmp_path / "launch-wd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    rc = main(["validate", "--project-root", str(tmp_path), "--config", "config", "--json"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "[]"


def test_relative_config_without_root_uses_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Back-compat: with NO root, a relative --config resolves against the CWD exactly as before — so a
    # launch from an unrelated dir does NOT find the graph (the documented pre-anchor behavior).
    _config_dir(tmp_path, _NO_ENV_GRAPH, name="config")
    elsewhere = tmp_path / "launch-wd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    # config/ does not exist under the launch dir -> load fails (config dir not found).
    rc = main(["validate", "--config", "config", "--json"])
    assert rc != 0  # a missing config dir is reported (not a clean empty graph)


# --- AC-1 / AC-7: the store DB anchors under the root at serve (relative follows, absolute bypasses) ---


def _serve_capturing_store_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> str:
    """Drive _serve far enough to capture the store path passed to create_managed_app, stubbing the
    server so nothing binds. Uses a `dev` env (synthetic/non-prod posture) so no PHI gating fires.

    GIVEN 1 (ADR 0148): dev derives PHI now, so the synthetic posture is declared explicitly via the
    [security].handles_real_patient_data=false env opt-out — keeping these anchoring tests focused on
    path resolution, with no PHI-gate noise."""
    import messagefoundry.api as api_mod

    # The PER-GATE provisions a keyless dev serve needs since BACKLOG #1279 retired the one-line
    # synthetic declaration these tests used to lean on: egress declared, and the at-rest gate
    # acknowledged twice (ADR 0140 -- keyless PHI under `enforce` is never one flag away). Keeps
    # this module focused on path resolution with no PHI-gate noise, as it always was.
    monkeypatch.setenv("MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUND", "true")
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI", "true")
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI_UNDER_STRICT_ENFORCEMENT", "true")
    monkeypatch.setenv("MEFOR_ALERTS_SECURITY_NOTIFICATIONS_REQUIRED", "false")
    captured: dict[str, object] = {}

    def _fake_app(*, store_settings: object, **_kw: object) -> object:
        captured["store_path"] = store_settings.path  # type: ignore[attr-defined]
        return object()

    def _fake_run(*_a: object, **_kw: object) -> None:
        return None

    import uvicorn

    monkeypatch.setattr(api_mod, "create_managed_app", _fake_app)
    monkeypatch.setattr(uvicorn, "run", _fake_run)
    monkeypatch.setattr("messagefoundry.last_resort.install_excepthook", lambda: None, raising=True)
    assert main(argv) == 0
    return str(captured["store_path"])


def test_relative_db_resolves_under_root_at_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _config_dir(tmp_path, _NO_ENV_GRAPH)
    store_path = _serve_capturing_store_path(
        tmp_path,
        monkeypatch,
        [
            "serve",
            "--project-root",
            str(tmp_path),
            "--config",
            str(cfg),
            "--env",
            "dev",
            "--db",
            "mf.db",
        ],
    )
    # AC-1/AC-7: a relative --db follows the root.
    assert store_path == str(tmp_path / "mf.db")


def test_absolute_db_bypasses_root_at_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _config_dir(tmp_path, _NO_ENV_GRAPH)
    abs_db = str((tmp_path / "fastvol" / "store.db").resolve())
    store_path = _serve_capturing_store_path(
        tmp_path,
        monkeypatch,
        [
            "serve",
            "--project-root",
            str(tmp_path),
            "--config",
            str(cfg),
            "--env",
            "dev",
            "--db",
            abs_db,
        ],
    )
    # AC-7: an absolute --db is honored as-is, ignoring the root.
    assert store_path == abs_db


def test_no_root_keeps_db_default_at_serve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Back-compat: with no root, a relative --db is CWD-relative as before (not rewritten).
    # Run from tmp_path: a CWD-relative store puts the default log spool (BACKLOG #1966) beside it,
    # and from the repository root that left a `log-spool/` directory in the checkout.
    monkeypatch.chdir(tmp_path)
    cfg = _config_dir(tmp_path, _NO_ENV_GRAPH)
    store_path = _serve_capturing_store_path(
        tmp_path,
        monkeypatch,
        ["serve", "--config", str(cfg), "--env", "dev", "--db", "mf.db"],
    )
    assert store_path == "mf.db"  # unchanged: exactly the string passed, CWD-relative downstream


def test_file_set_base_dir_anchors_db_without_project_root_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ADR §1 "the same merged value": a root set ONLY via [environments].base_dir in messagefoundry.toml
    # (no --project-root flag) anchors a relative [store].path under it exactly like the CLI flag — not a
    # half-anchored bundle where env values move but the DB stays at CWD.
    root = tmp_path / "repo"
    root.mkdir()
    cfg = _config_dir(root, _NO_ENV_GRAPH, name="config")
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text(
        f'[environments]\nbase_dir = "{root.as_posix()}"\n\n[store]\npath = "mf.db"\n',
        encoding="utf-8",
    )
    elsewhere = tmp_path / "wd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    store_path = _serve_capturing_store_path(
        tmp_path,
        monkeypatch,
        ["serve", "--config", str(cfg), "--service-config", str(svc), "--env", "dev"],
    )
    # The relative [store].path follows the file-set base_dir root, not the (unrelated) CWD.
    assert store_path == str(root / "mf.db")


def _run_serve_stubbed(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    """Drive _serve to the create_managed_app boundary (server stubbed) and return its exit code,
    so a test can assert on the rc AND on the emitted startup diagnostics without binding anything.

    Note: _serve calls configure_logging(), which REPLACES the root logger's handlers (so caplog's
    handler is removed). The diagnostics therefore reach the configured stdout StreamHandler, captured
    by ``capsys`` — these tests assert on capsys stdout, not caplog records.

    GIVEN 1 (ADR 0148): dev derives PHI now, so declare the synthetic posture explicitly (the
    [security].handles_real_patient_data=false env opt-out) so no PHI gate fires — these tests probe
    anchoring diagnostics, not the security posture."""
    import messagefoundry.api as api_mod

    # The PER-GATE provisions a keyless dev serve needs since BACKLOG #1279 retired the one-line
    # synthetic declaration these tests used to lean on: egress declared, and the at-rest gate
    # acknowledged twice (ADR 0140 -- keyless PHI under `enforce` is never one flag away). Keeps
    # this module focused on path resolution with no PHI-gate noise, as it always was.
    monkeypatch.setenv("MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUND", "true")
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI", "true")
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI_UNDER_STRICT_ENFORCEMENT", "true")
    monkeypatch.setenv("MEFOR_ALERTS_SECURITY_NOTIFICATIONS_REQUIRED", "false")
    monkeypatch.setattr(api_mod, "create_managed_app", lambda **_kw: object())
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *_a, **_kw: None)
    monkeypatch.setattr("messagefoundry.last_resort.install_excepthook", lambda: None, raising=True)
    return main(argv)


# --- AC-2: no project root -> every member resolves against CWD (back-compat) --------------------


def test_no_root_preserves_cwd_behavior(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # No --project-root: a relative --config resolves under CWD and a relative --db is left CWD-relative,
    # exactly as before — and no AC-4/AC-5 warning fires for a launch FROM the repo root (config under CWD).
    _config_dir(tmp_path, _NO_ENV_GRAPH, name="config")
    monkeypatch.chdir(tmp_path)
    store_path = _serve_capturing_store_path(
        tmp_path, monkeypatch, ["serve", "--config", "config", "--env", "dev", "--db", "mf.db"]
    )
    assert store_path == "mf.db"  # relative, unchanged (CWD-relative downstream)


# --- AC-4: project root set, CWD != root -> single WARNING naming the resolved members -----------


def test_cwd_mismatch_warns_with_resolved_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _config_dir(tmp_path, _NO_ENV_GRAPH)
    elsewhere = tmp_path / "launch-wd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    rc = _run_serve_stubbed(
        monkeypatch,
        [
            "serve",
            "--project-root",
            str(tmp_path),
            "--config",
            str(cfg),
            "--env",
            "dev",
            "--db",
            "mf.db",
        ],
    )
    assert rc == 0
    out = capsys.readouterr().out
    mismatch = [ln for ln in out.splitlines() if "differs from the working directory" in ln]
    assert len(mismatch) == 1  # a single cross-root WARNING
    msg = mismatch[0]
    # Names the resolved root, the env value file, and the store db (paths only, PHI-safe).
    assert str(tmp_path) in msg
    assert "dev.toml" in msg
    assert str(tmp_path / "mf.db") in msg


# --- AC-5: NSSM silent miss -> WARNING even with an ABSOLUTE --config (the flagship dead-branch) --


def test_nssm_silent_miss_warns_once_at_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The canonical NSSM case: env()-referencing graph, NO --project-root, an ABSOLUTE --config that
    # EXISTS, launched from an unrelated CWD, and no <env>.toml -> env values resolve empty. The warning
    # MUST fire (regression guard for the launch_is_config_root dead branch, where an absolute --config
    # that exists used to suppress it).
    cfg = _config_dir(tmp_path, _ENV_GRAPH)
    elsewhere = tmp_path / "nssm-wd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    rc = _run_serve_stubbed(monkeypatch, ["serve", "--config", str(cfg), "--env", "dev"])
    assert rc == 0  # no hard fail without an explicit root (AC-5 is advisory)
    nssm = [
        ln
        for ln in capsys.readouterr().out.splitlines()
        if "does not look like a config root" in ln
    ]
    assert len(nssm) == 1  # fired exactly once at boot
    assert "--project-root" in nssm[0]


def test_no_nssm_warning_when_launched_from_repo_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Counterpart: launched FROM the repo root (config + environments/ under CWD), no warning fires even
    # with empty env values, because the CWD *is* a config root.
    _config_dir(tmp_path, _ENV_GRAPH, name="config")
    (tmp_path / "environments").mkdir()  # dir present -> CWD looks like a config root
    monkeypatch.chdir(tmp_path)
    rc = _run_serve_stubbed(monkeypatch, ["serve", "--config", "config", "--env", "dev"])
    assert rc == 0
    assert "does not look like a config root" not in capsys.readouterr().out


# --- AC-8: a drive-relative MEMBER under a root warns and is kept under the root (not escaped) ----


def test_drive_relative_member_warns_and_stays_under_root(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import sys

    if sys.platform != "win32":
        pytest.skip("drive-relative paths are a Windows-only footgun")
    root = Path("C:/repo")
    with caplog.at_level("WARNING"):
        anchored = anchor_under_root("/data/mf.db", root, cwd=Path("C:/elsewhere"))
    # Kept UNDER the root (tail anchored), never escaped onto the launch drive root (C:\data\mf.db).
    assert anchored == str(root / "data" / "mf.db")
    assert any("drive-relative" in r.getMessage() for r in caplog.records)


# --- regression: a malformed <env>.toml yields a clean error, not a raw traceback ----------------


def test_malformed_env_file_fails_cleanly_not_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The eager env_values() at serve startup reads <env>.toml; a malformed file makes tomllib raise.
    # It must be routed to a clean `error:` + exit 2 (like every other serve gate), NOT propagate as an
    # uncaught TOMLDecodeError traceback (the pre-fix regression vs the old lazy-lifespan path).
    cfg = _config_dir(tmp_path, _NO_ENV_GRAPH)
    envdir = tmp_path / "environments"
    envdir.mkdir()
    # The DUPLICATE-INLINE-KEY shape, for the reason recorded once at the guard itself
    # (messagefoundry/__main__.py, the env_values() provider): it is the one malformed shape whose
    # tomllib message quotes text FROM the file. An unterminated string quotes nothing, so a redaction
    # assertion over it would pass for a renderer that leaks. The token is deliberately not
    # credential-shaped: a real-looking one would trip the gitleaks gate for nothing this test needs.
    (envdir / "dev.toml").write_text(
        'a = {peer_host = "never-print-this-value", peer_host = 2}\n', encoding="utf-8"
    )
    rc = _run_serve_stubbed(
        monkeypatch,
        ["serve", "--project-root", str(tmp_path), "--config", str(cfg), "--env", "dev"],
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "could not read environment values" in err
    assert "dev.toml" in err
    # No configured VALUE travels -- the contract.
    assert "never-print-this-value" not in err
    # The positive control: the offending KEY is echoed, which proves the assertion above can see
    # file text rather than merely being handed a shape with nothing to leak.
    assert "peer_host" in err


# --- AC-6 / BACKLOG #1062: the build check must READ values from the root it VALIDATED -------------


def _root_with_values(root: Path, peer_host: str, *, env: str = "prod") -> Path:
    """A project root carrying a config, a service toml, and one environment value file."""
    _config_dir(root, _ENV_GRAPH)
    (root / "messagefoundry.toml").write_text(f'[ai]\nenvironment = "{env}"\n', encoding="utf-8")
    envdir = root / "environments"
    envdir.mkdir(exist_ok=True)
    (envdir / f"{env}.toml").write_text(f'peer_host = "{peer_host}"\n', encoding="utf-8")
    return root


def test_build_check_reads_values_from_the_root_not_the_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1062. ``check --project-root R`` hard-fails when ``R/<env_dir>/<env>.toml`` is absent,
    then used to DROP R and read the values from the process directory -- so the ADR 0092 posture-keyed
    insecure-hop refusal could be decided against a different environment's hosts and schemes than the
    one the operator named. ``serve`` never had this: it writes the root into ``[environments].base_dir``
    before ``load_settings``.

    Asserted by the DIVERGENCE, which is the only shape that can fail: the process directory holds its
    OWN value file with a different host. A test run from inside the root passes with the bug present,
    because both anchors agree there -- the same masking that hid the rule 3d defect on Windows.
    """
    root = _root_with_values(tmp_path / "R", "10.0.0.9")
    elsewhere = _root_with_values(tmp_path / "W", "192.168.1.1")
    monkeypatch.chdir(elsewhere)  # the process directory is NOT the root

    seen: list[str] = []
    import messagefoundry.checks as checks_mod
    import messagefoundry.config.environments as env_mod

    # `_check_build` imports this inside the function, so the patch must land on the SOURCE module.
    real = env_mod.load_environment_values

    def _spy(*, base_dir: Path, **kw: object) -> object:
        seen.append(str(base_dir))
        return real(base_dir=base_dir, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(env_mod, "load_environment_values", _spy)

    checks_mod.run_checks(
        root / "config",
        run_lint=False,
        service_config=str(root / "messagefoundry.toml"),
        suppress_service_toml_search=True,
        project_root=str(root),
    )

    assert seen, "the build check never resolved environment values -- the test proves nothing"
    assert seen[0] == str(root), f"values were read from {seen[0]}, not the supplied root {root}"
    assert str(elsewhere) not in seen


def test_without_a_root_the_build_check_still_falls_back_to_the_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half, and the one that makes the fix a correction rather than a widening: with no
    ``--project-root`` the resolution is unchanged and still anchors on the process directory, so the
    documented ``messagefoundry check --config config`` invocation is untouched."""
    here = _root_with_values(tmp_path / "here", "10.0.0.9")
    monkeypatch.chdir(here)

    seen: list[str] = []
    import messagefoundry.checks as checks_mod
    import messagefoundry.config.environments as env_mod

    # `_check_build` imports this inside the function, so the patch must land on the SOURCE module.
    real = env_mod.load_environment_values

    def _spy(*, base_dir: Path, **kw: object) -> object:
        seen.append(str(base_dir))
        return real(base_dir=base_dir, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(env_mod, "load_environment_values", _spy)

    checks_mod.run_checks(
        here / "config",
        run_lint=False,
        service_config=str(here / "messagefoundry.toml"),
        suppress_service_toml_search=True,
    )

    assert seen, "the build check never resolved environment values -- the test proves nothing"
    assert seen[0] == str(here)


# BACKLOG #1967: this file's serve fixtures test other gates, so they bound the two warn-only
# retention tiers that ship with no window (tests/conftest.py, bounded_warn_only_retention).
pytestmark = pytest.mark.usefixtures("bounded_warn_only_retention", "verified_log_forwarding")


# --- BACKLOG #5926 / #5927: the offline store commands anchor [store].path the way serve does ------
#
# Each command below loads the service settings and then tests or opens [store].path. Run from a
# directory that is not the root, a relative path must name the store serve would open, under
# [environments].base_dir, and not one beside the working directory. At least these commands; the
# list is the ones this change covers, not a census of every command that reads the store.

_OFFLINE_AT_REST_ENV = (
    *_AT_REST_ENV,
    "MEFOR_STORE_PATH",
    "MEFOR_STORE_BACKEND",
    "MEFOR_ENVIRONMENTS_BASE_DIR",
)


@pytest.fixture
def away_from_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A root holding nothing yet, a service config naming it as base_dir with a relative
    [store].path, and a working directory that is somewhere else. Returns (root, service config)."""
    for name in _OFFLINE_AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text(
        f'[environments]\nbase_dir = "{root.as_posix()}"\n\n[store]\npath = "mf.db"\n',
        encoding="utf-8",
    )
    elsewhere = tmp_path / "wd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    return root, svc


def test_anchored_store_path_follows_the_root(tmp_path: Path) -> None:
    from messagefoundry.config.anchor import anchored_store_path

    root = tmp_path / "repo"
    assert anchored_store_path("mf.db", root, cwd=tmp_path / "wd") == str(root / "mf.db")


def test_anchored_store_path_keeps_an_absolute_path(tmp_path: Path) -> None:
    from messagefoundry.config.anchor import anchored_store_path

    abs_db = str((tmp_path / "fastvol" / "store.db").resolve())
    assert anchored_store_path(abs_db, tmp_path / "repo", cwd=tmp_path) == abs_db


def test_anchored_store_path_with_no_root_is_unchanged(tmp_path: Path) -> None:
    from messagefoundry.config.anchor import anchored_store_path

    assert anchored_store_path("mf.db", None, cwd=tmp_path) == "mf.db"


def test_the_in_memory_sentinel_is_never_joined_under_the_root(tmp_path: Path) -> None:
    from messagefoundry.config.anchor import anchored_store_path

    # Joined, `:memory:` would become a durable file (an NTFS stream on Windows). The guard sits in
    # anchor_under_root, so serve's and supervise's pre-load --db join keeps it too.
    root = tmp_path / "repo"
    assert anchored_store_path(":memory:", root, cwd=tmp_path) == ":memory:"
    assert anchor_under_root(":memory:", root, cwd=tmp_path) == ":memory:"


def test_anchored_store_path_keeps_a_drive_relative_path_under_the_root(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The same AC-8 rule anchor_under_root applies to every other member: warn, stay under root.
    from messagefoundry.config.anchor import anchored_store_path

    root = tmp_path / "repo"
    anchored = anchored_store_path("/data/mf.db", root, cwd=tmp_path)
    if Path("/data/mf.db").is_absolute():  # POSIX: a leading slash is absolute and stays put
        assert anchored == "/data/mf.db"
    else:
        assert anchored == str(root / "data" / "mf.db")
        assert "drive-relative" in caplog.text


def test_anchor_settings_store_path_tolerates_no_settings(tmp_path: Path) -> None:
    from messagefoundry.config.anchor import anchor_settings_store_path

    anchor_settings_store_path(None, cwd=tmp_path)  # support-bundle's unloaded case: no raise


def _names(output: str, path: Path) -> bool:
    # A repr or a JSON string doubles a Windows backslash; undo that before the substring test.
    return str(path) in output.replace("\\\\", "\\")


@pytest.mark.parametrize(
    ("argv", "via_db", "code"),
    [
        pytest.param(["admin-unlock", "--username", "site-admin"], False, 2, id="admin-unlock"),
        pytest.param(["audit-verify"], False, 2, id="audit-verify"),
        pytest.param(["audit-anchor"], False, 2, id="audit-anchor"),
        pytest.param(["rotate-key"], False, 2, id="rotate-key"),
        pytest.param(["backup", "--destination", "BACKUP_DIR"], False, 2, id="backup"),
        pytest.param(["cipher-audit"], False, 2, id="cipher-audit"),
        # A SQLite store has no server principal to probe, so this one reports and exits 0.
        pytest.param(["check-privileges"], False, 0, id="check-privileges"),
        # A relative --db merges into [store].path before the anchor, so two commands suffice to
        # pin that it is anchored too: one through the shared host gate, one with its own guards.
        pytest.param(["admin-unlock", "--username", "site-admin"], True, 2, id="admin-unlock-db"),
        pytest.param(["rotate-key"], True, 2, id="rotate-key-db"),
    ],
)
def test_offline_store_command_names_the_store_under_the_root(
    away_from_root: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    via_db: bool,
    code: int,
) -> None:
    """With no store yet, every one of these refuses or reports naming the path it tested. That
    path must be the root's, for a file-set relative [store].path and for a relative --db alike
    (ADR 0050 AC-1: a relative --db follows the root), and no store may appear in the working
    directory."""
    from messagefoundry.store.crypto import generate_key

    root, svc = away_from_root
    if argv[0] == "rotate-key":  # it refuses for a missing key before it reaches the store check
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    argv = [str(root.parent / "bk") if a == "BACKUP_DIR" else a for a in argv]
    argv = [*argv, "--service-config", str(svc)]
    if via_db:
        argv += ["--db", "mf.db"]
    rc = main(argv)
    out = capsys.readouterr()
    assert rc == code, out.out + out.err
    assert _names(out.out + out.err, root / "mf.db"), out.out + out.err
    assert not (Path.cwd() / "mf.db").exists()


def test_cert_inventory_reports_the_generated_pair_beside_the_anchored_store(
    away_from_root: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    root, svc = away_from_root
    assert main(["cert", "inventory", "--service-config", str(svc), "--json"]) == 0
    api_tls = json.loads(capsys.readouterr().out)["api_tls"]
    assert api_tls["source"] == "generated"
    assert Path(api_tls["cert"]).parent == root


def test_provision_admin_creates_the_store_under_the_root(
    away_from_root: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_provision_first_administrator import _PASSWORD, _tty

    root, svc = away_from_root
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI", "true")
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI_UNDER_STRICT_ENFORCEMENT", "true")
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    rc = main(
        [
            "provision-admin",
            "--username",
            "site-admin",
            "--email",
            "ops@example.invalid",
            "--service-config",
            str(svc),
            "--json",
        ]
    )
    assert rc == 0
    assert (root / "mf.db").exists()
    assert not (Path.cwd() / "mf.db").exists()


def test_restore_verify_hands_the_anchored_store_settings_on(
    away_from_root: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    import messagefoundry.pipeline.dr_backup as dr_backup
    from messagefoundry.store.keyprovider import KeyProviderError

    root, svc = away_from_root
    archive = root.parent / "a.mfbak"
    archive.write_bytes(b"not an archive")
    seen: list[str] = []

    async def _spy(_archive: str, *, store_settings: object, full: bool) -> object:
        seen.append(store_settings.path)  # type: ignore[attr-defined]
        # A refusal the command already handles, as "could not start", so the run stops here.
        raise KeyProviderError("stop after the capture")

    monkeypatch.setattr(dr_backup, "run_restore_verify", _spy)
    assert main(["restore-verify", str(archive), "--service-config", str(svc), "--full"]) == 2
    assert seen == [str(root / "mf.db")]


def test_support_bundle_reads_the_anchored_store(
    away_from_root: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    import messagefoundry.support as support_mod

    root, svc = away_from_root
    seen: list[str] = []

    def _spy(_out: str, *, settings: object, **_kw: object) -> object:
        seen.append(settings.store.path)  # type: ignore[attr-defined]
        raise OSError("stop after the capture")

    monkeypatch.setattr(support_mod, "build_bundle", _spy)
    assert main(["support-bundle", "--service-config", str(svc), "--out", "b.zip"]) == 2
    assert seen == [str(root / "mf.db")]


def test_restore_resolves_keys_beside_the_anchored_store(
    away_from_root: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    import messagefoundry.pipeline.dr_backup as dr_backup
    from messagefoundry.store.keyprovider import KeyProviderError

    root, svc = away_from_root
    seen: list[str] = []

    async def _spy(_archive: str, *, store_settings: object, **_kw: object) -> object:
        seen.append(store_settings.path)  # type: ignore[attr-defined]
        raise KeyProviderError("stop after the capture")

    monkeypatch.setattr(dr_backup, "run_restore", _spy)
    main(["restore", "a.mfbak", "--to", "new.db", "--service-config", str(svc)])
    assert seen == [str(root / "mf.db")]


def test_verify_checks_the_anchored_store(away_from_root: tuple[Path, Path]) -> None:
    from messagefoundry.verify.runner import _load_settings, _writable_dir

    root, svc = away_from_root
    settings, error = _load_settings(str(svc))
    assert error is None and settings is not None
    assert settings.store.path == str(root / "mf.db")
    assert _writable_dir(settings) == root.resolve()
