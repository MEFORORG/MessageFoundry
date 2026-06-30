# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Structural regression tests for the frozen console installer (ADR 0032 Phase B, BACKLOG #39).

These assert the *static* wiring of the packaging assets — the actual ~150 MB freeze + install runs on
the Windows CI leg (the `release-console-installer` job in `.github/workflows/release.yml`), not here.
They cover the AC-B1/B2/B3/B6/B8 acceptance criteria that can be verified without a Windows runner:

  AC-B1  the job runs PyInstaller `--onedir` against the spec,
  AC-B2  it builds the Inno Setup installer (ISCC) and uploads it as a release asset,
  AC-B3  the signing step is gated on the cert secret (no secret -> no failure, unsigned artifact),
  AC-B6  the PyInstaller spec excludes QtWebEngine / QtMultimedia / Qt3D,
  AC-B8  the .iss declares Desktop + Start-Menu shortcuts and an Add/Remove-Programs uninstall entry.

The installer build is a job INSIDE release.yml (with `needs: release`), not a standalone workflow —
that ordering is what guarantees the GitHub release exists before `gh release upload` runs (ADR 0032
§(d) "isolated `needs: release`, like `release-harness`"). The tests target that job by name.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "release.yml"
_JOB_NAME = "release-console-installer"
_PKG_DIR = _REPO_ROOT / "packaging" / "console-installer"
_SPEC = _PKG_DIR / "messagefoundry-console.spec"
_ISS = _PKG_DIR / "messagefoundry-console.iss"


def _workflow() -> dict:
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


def _job() -> dict:
    """The `release-console-installer` job in release.yml (the frozen-installer build leg)."""
    job = _workflow()["jobs"].get(_JOB_NAME)
    assert job is not None, f"no `{_JOB_NAME}` job in release.yml"
    return job


def _job_steps() -> list[dict]:
    return _job()["steps"]


def _all_run_bodies() -> str:
    return "\n".join(s.get("run", "") for s in _job_steps())


def test_release_yml_runs_pyinstaller_onedir() -> None:
    """AC-B1: the workflow freezes the console via PyInstaller against the --onedir spec."""
    bodies = _all_run_bodies()
    assert "pyinstaller" in bodies, "no pyinstaller invocation in the installer workflow"
    assert "messagefoundry-console.spec" in bodies, "pyinstaller is not pointed at the spec file"
    # The spec itself is what pins --onedir (COLLECT); assert the spec uses COLLECT, not a one-file EXE.
    spec = _SPEC.read_text(encoding="utf-8")
    assert "COLLECT(" in spec, "spec is not --onedir (no COLLECT — would be a one-file build)"


def test_release_yml_builds_and_uploads_installer() -> None:
    """AC-B2: the workflow builds the Inno Setup installer and uploads it as a release asset."""
    bodies = _all_run_bodies()
    assert "ISCC" in bodies, "no ISCC (Inno Setup) invocation"
    assert "messagefoundry-console.iss" in bodies, "ISCC is not pointed at the .iss script"
    # Tag-gated release-asset upload via gh release upload.
    upload = next(
        (s for s in _job_steps() if "gh release upload" in s.get("run", "")),
        None,
    )
    assert upload is not None, (
        "no `gh release upload` step (installer is never attached to a release)"
    )
    assert "refs/tags/" in upload.get("if", ""), "release upload is not tag-gated"


def test_signing_step_is_secret_gated() -> None:
    """AC-B3: the Authenticode signing step is `if:`-gated on the cert secret, so a missing secret
    yields an UNSIGNED installer without failing the build.

    The gate is the canonical two-step form: a job-level ``env.SIGN_CONFIGURED`` derived from
    ``secrets.WINDOWS_SIGN_CERT_BASE64 != ''`` (``secrets`` is not allowed directly in a step ``if:``),
    and the sign step's ``if: env.SIGN_CONFIGURED == 'true'``.
    """
    sign = next(
        (s for s in _job_steps() if "signtool" in s.get("run", "").lower()),
        None,
    )
    assert sign is not None, "no signtool signing step found"
    cond = sign.get("if", "")
    assert "SIGN_CONFIGURED" in cond, "signing step is not gated on the SIGN_CONFIGURED env"
    assert "== 'true'" in cond, "signing gate must require SIGN_CONFIGURED == 'true'"
    # The job-level env that derives SIGN_CONFIGURED from the secret (empty/absent secret -> skip).
    job_env = _job().get("env", {})
    sign_src = str(job_env.get("SIGN_CONFIGURED", ""))
    assert "secrets.WINDOWS_SIGN_CERT_BASE64" in sign_src, (
        "SIGN_CONFIGURED is not derived from the cert secret"
    )
    assert "!= ''" in sign_src, (
        "signing gate must be false when the secret is empty/absent (no hard fail)"
    )


def test_pyinstaller_spec_excludes_heavy_qt_modules() -> None:
    """AC-B6: the spec excludes QtWebEngine, QtMultimedia, and Qt3D to bound the bundle size."""
    spec = _SPEC.read_text(encoding="utf-8")
    for mod in ("QtWebEngine", "QtMultimedia", "Qt3D"):
        assert mod in spec, f"spec does not exclude a heavy Qt module: {mod}"
    # And it must be a windowed (no-console) freeze, like Phase A's pythonw gui-script.
    assert "console=False" in spec, "spec is not windowed (console=False missing)"


def test_pyinstaller_spec_bundles_console_resource_and_icon_trees() -> None:
    """The freeze must carry BOTH console data trees the GUI reads at runtime, or it ships visibly broken:
    - resources/*  -> app.ico (the window/taskbar badge, AC-B5),
    - icons/*      -> the left-nav line icons + the header logo-lockup.svg (console/shell.py loads these
                      from <package>/icons/; collect_data_files `includes` is a WHITELIST, so omitting
                      icons/* drops every nav icon + the brand lockup in the FROZEN build only).
    """
    spec = _SPEC.read_text(encoding="utf-8")
    assert 'collect_data_files("messagefoundry.console"' in spec, (
        "spec does not collect the console package's data files"
    )
    assert "resources/*" in spec, "spec does not bundle console/resources/* (app.ico badge)"
    assert "icons/*" in spec, (
        "spec does not bundle console/icons/* — the frozen console would lose every nav icon + the "
        "header brand lockup (the wheel ships them, so this breakage is frozen-only)"
    )


def test_iss_declares_shortcuts_and_uninstall() -> None:
    """AC-B8: the .iss declares Desktop + Start-Menu shortcuts and an ARP uninstall entry, and is
    per-user-default with an opt-in all-users mode."""
    iss = _ISS.read_text(encoding="utf-8")
    assert "[Icons]" in iss
    assert "{autodesktop}" in iss, "no Desktop shortcut declared"
    assert "{group}" in iss, "no Start-Menu (program group) shortcut declared"
    # ARP uninstall: Inno auto-registers one; assert the uninstall identity wiring is present.
    assert "UninstallDisplayName" in iss
    assert "{uninstallexe}" in iss, "no uninstall entry/shortcut"
    # Per-user default with opt-in elevation.
    assert "PrivilegesRequired=lowest" in iss, "installer is not per-user-default"
    assert "PrivilegesRequiredOverridesAllowed" in iss, "no opt-in all-users override"


def test_version_is_single_sourced_not_hardcoded() -> None:
    """The installer AppVersion comes from __version__ via /DAppVersion=, never a literal in the .iss."""
    iss = _ISS.read_text(encoding="utf-8")
    assert "AppVersion={#AppVersion}" in iss, ".iss does not use the injected AppVersion define"
    bodies = _all_run_bodies()
    assert "/DAppVersion=" in bodies, "the workflow does not inject AppVersion into ISCC"
    assert "__version__" in bodies, "the workflow does not read the single-sourced __version__"


def test_installer_workflow_is_not_required_on_prs() -> None:
    """The expensive ~150 MB freeze must not run on every PR: release.yml triggers are tag-push +
    workflow_dispatch only (never `pull_request`)."""
    doc = _workflow()
    on = (
        doc[True] if True in doc else doc["on"]
    )  # PyYAML parses the bare `on:` key as the bool True
    assert "pull_request" not in on, "the installer leg must NOT trigger on pull_request"
    assert "workflow_dispatch" in on
    assert "push" in on and "tags" in on["push"], "the installer leg should run on tag pushes"


def test_installer_job_needs_release_for_upload_ordering() -> None:
    """ADR 0032 §(d): the installer build is a job INSIDE release.yml with `needs: release` (like
    `release-harness`), so `release`'s `gh release create` provably runs before this job's
    `gh release upload` — a standalone workflow on the same tag would race release creation."""
    job = _job()
    needs = job.get("needs")
    needs_list = [needs] if isinstance(needs, str) else list(needs or [])
    assert "release" in needs_list, (
        "release-console-installer must `needs: release` so the GitHub release exists before upload"
    )


def test_installer_freezes_from_the_just_built_wheel() -> None:
    """ADR 0032 §(d): the console is frozen from the just-built wheel (downloaded from the `release`
    job's artifact), not from the source tree, so the frozen console and the published wheel are
    byte-identical packaging."""
    steps = _job_steps()
    # The wheel arrives via actions/download-artifact of the release job's `release-artifacts`.
    dl = next((s for s in steps if "download-artifact" in str(s.get("uses", ""))), None)
    assert dl is not None, "installer job does not download the just-built wheel artifact"
    assert dl.get("with", {}).get("name") == "release-artifacts", (
        "installer job must download the `release-artifacts` produced by the release job"
    )
    bodies = _all_run_bodies()
    assert ".whl" in bodies, (
        "installer job does not pip-install the built wheel (no .whl reference)"
    )
