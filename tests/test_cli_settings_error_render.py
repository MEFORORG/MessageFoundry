# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CLI arms that print a whole-file ``load_settings`` failure render it, never stringify it.

Vault BACKLOG #2760 (review findings H-3 and F-4). ``str(ValidationError)`` carries ``input_value=``
for each failing field, and for an ``after``-mode section validator that is the whole section's input
mapping, environment-supplied secrets included: a ``[store]`` missing ``server`` with
``MEFOR_STORE_PASSWORD`` set would print the store password. A scheduled ``backup`` or ``rotate-key``
writes its output to a job log, so on a first deployment that line would be persisted.

TWO LAYERS, AND THIS FILE HOLDS THE SECOND. Since BACKLOG #296 the settings models hide their own
input (``tests/test_settings_errors_echo_no_input.py``), so a real ``[store]`` failure no longer
carries the password even through ``str(exc)``. That is why the real-config leg below cannot fail on
its own and is not the control: it proves the output stays USEFUL. The leg that can fail patches
``load_settings`` to raise a ``ValidationError`` from a plain model that DOES carry the secret -- the
shape a section added later outside ``_InputHidingModel`` would raise -- and asserts its control
first: the planted secret is in ``str(exc)``. Each arm must then render it through
``settings_error_detail`` and print the field and message without the value.

``_ARMS`` holds at least the operator commands vault BACKLOG #2760 moved onto the renderer and
the ones that already used it, except ``serve`` and ``supervise``, which start the engine. A new
CLI arm that loads the whole settings file belongs in it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.__main__ import main
from messagefoundry.config import security_edit
from messagefoundry.config import settings as settings_module

#: Synthetic, never a real credential, and deliberately low-entropy so the secret scanner does not
#: read it as one (no allowlist entry needed). Short, so pydantic's middle abbreviation of a long
#: input repr cannot hide it from the control.
_CANARY = "canary-canary-canary"
_MESSAGE = "postgres backend requires: server, database, username"
_FAILING_STORE = '[store]\nbackend = "postgres"\n'


def _leaky_error() -> ValidationError:
    """The failure a section outside ``_InputHidingModel`` would raise: input still attached."""
    return ValidationError.from_exception_data(
        "ServiceSettings",
        [
            {
                "type": "value_error",
                "loc": ("store",),
                "input": {"backend": "postgres", "password": _CANARY},
                "ctx": {"error": ValueError(_MESSAGE)},
            }
        ],
    )


def _archive(tmp: Path) -> str:
    # restore-verify checks the archive exists before it loads settings.
    path = tmp / "x.mfbak"
    path.write_bytes(b"not an archive")
    return str(path)


#: (id, argv builder). Each argv names the settings file at ``cfg``; ``tmp`` is a scratch directory.
_ARMS: list[tuple[str, Callable[[Path, Path], list[str]]]] = [
    ("cert-inventory", lambda cfg, tmp: ["cert", "inventory", "--service-config", str(cfg)]),
    (
        "admin-unlock",
        lambda cfg, tmp: ["admin-unlock", "--username", "a", "--service-config", str(cfg)],
    ),
    (
        "admin-set-notify-email",
        lambda cfg, tmp: [
            "admin-set-notify-email",
            "--username",
            "a",
            "--email",
            "a@example.test",
            "--service-config",
            str(cfg),
        ],
    ),
    (
        "provision-admin",
        lambda cfg, tmp: ["provision-admin", "--username", "a", "--service-config", str(cfg)],
    ),
    ("rotate-key", lambda cfg, tmp: ["rotate-key", "--service-config", str(cfg)]),
    ("audit-verify", lambda cfg, tmp: ["audit-verify", "--service-config", str(cfg)]),
    ("audit-anchor", lambda cfg, tmp: ["audit-anchor", "--service-config", str(cfg)]),
    ("ai-policy", lambda cfg, tmp: ["ai-policy", "--service-config", str(cfg)]),
    ("cluster-vip", lambda cfg, tmp: ["cluster-vip", "--service-config", str(cfg)]),
    (
        "backup",
        lambda cfg, tmp: ["backup", "--service-config", str(cfg), "--destination", str(tmp / "b")],
    ),
    (
        "restore-verify",
        lambda cfg, tmp: ["restore-verify", _archive(tmp), "--service-config", str(cfg)],
    ),
    (
        "restore",
        lambda cfg, tmp: [
            "restore",
            _archive(tmp),
            "--to",
            str(tmp / "restored.db"),
            "--service-config",
            str(cfg),
        ],
    ),
    (
        "connection-upsert",
        lambda cfg, tmp: [
            "connection",
            "upsert",
            "--config",
            str(tmp),
            "--service-config",
            str(cfg),
            "--data",
            '{"name": "IB_X", "direction": "inbound", "type": "mllp"}',
        ],
    ),
    (
        "support-bundle",
        lambda cfg, tmp: [
            "support-bundle",
            "--config",
            str(tmp),
            "--service-config",
            str(cfg),
            "--out",
            str(tmp / "bundle.zip"),
        ],
    ),
    (
        "security-set",
        lambda cfg, tmp: [
            "security",
            "set",
            "--service-config",
            str(cfg),
            "--data",
            '{"require_mfa": true}',
        ],
    ),
    (
        "alert-add",
        lambda cfg, tmp: [
            "alert",
            "add",
            "--service-config",
            str(cfg),
            "--data",
            '{"event_type": "connection_stopped"}',
        ],
    ),
    (
        "alert-remove",
        lambda cfg, tmp: ["alert", "remove", "--service-config", str(cfg), "--index", "0"],
    ),
]

#: The file each arm starts from. ``alert remove`` needs a rule to remove before it reloads.
_STARTING_FILE = {"alert-remove": '[[alerts.rules]]\nevent_type = "connection_stopped"\n'}

#: The arms whose load is the post-write check of an edit, which must also roll the edit back.
_EDIT_ARMS = {"security-set", "alert-add", "alert-remove"}

#: How ``settings_error_detail`` names the failing section. Pydantic's own text puts the location on
#: a line of its own, and a bare ``store`` would also match a temporary path.
_FIELD = "store: "


def _run(
    arm: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    body: str,
) -> tuple[int, str, Path, str]:
    argv_for = dict(_ARMS)[arm]
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(body, encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()
    code = main(argv_for(cfg, work))
    captured = capsys.readouterr()
    return code, captured.out + captured.err, cfg, body


def _patch_leaky_load(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []

    def leaky(*_args: Any, **_kwargs: Any) -> Any:
        calls.append(1)
        raise _leaky_error()

    # Every arm imports load_settings from the settings module at call time, so the patch reaches it.
    monkeypatch.setattr(settings_module, "load_settings", leaky)
    return calls


def test_the_planted_secret_is_in_the_raw_rendering() -> None:
    """The control: ``str`` of the patched failure DOES carry the secret, so the sweep can fail."""
    exc = _leaky_error()
    assert _CANARY in str(exc)
    assert _CANARY not in settings_module.settings_error_detail(exc)


@pytest.mark.parametrize("arm", [arm for arm, _ in _ARMS])
def test_an_arm_renders_a_load_failure_without_its_input(
    arm: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_leaky_load(monkeypatch)
    code, out, cfg, body = _run(arm, tmp_path, capsys, _STARTING_FILE.get(arm, ""))

    assert calls, f"{arm} never reached load_settings, so this case proves nothing"
    assert _CANARY not in out, f"{arm} printed the input of a settings load failure: {out!r}"
    # Useful, not just quiet: the section and the reason are still named.
    assert _FIELD in out and _MESSAGE in out, out
    if arm == "support-bundle":
        # A broken settings file does not block the bundle; it is reported as a warning.
        assert code == 0
    else:
        assert code != 0
    if arm in _EDIT_ARMS:
        # The post-write check refused, not an earlier read (`security set` also loads the file to
        # report loosenings), and the edit was rolled back.
        assert "the edit was not saved" in out, out
        assert cfg.read_text(encoding="utf-8") == body


@pytest.mark.parametrize("arm", [arm for arm, _ in _ARMS])
def test_a_real_store_failure_names_the_field_and_never_the_env_secret(
    arm: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The unpatched load: the env-supplied password is in the refused ``[store]`` input."""
    monkeypatch.setenv("MEFOR_STORE_PASSWORD", _CANARY)
    assert settings_module._env_overrides({"MEFOR_STORE_PASSWORD": _CANARY})["store"] == {
        "password": _CANARY
    }
    body = _FAILING_STORE + _STARTING_FILE.get(arm, "")
    code, out, cfg, _ = _run(arm, tmp_path, capsys, body)

    assert _CANARY not in out, f"{arm} printed an env-supplied secret: {out!r}"
    assert _FIELD in out and "server, database, username" in out, out
    assert "input_value" not in out and "errors.pydantic.dev" not in out, out
    if arm != "support-bundle":
        assert code != 0
    if arm in _EDIT_ARMS:
        assert "the edit was not saved" in out, out
        assert cfg.read_text(encoding="utf-8") == body


def test_a_json_caller_still_gets_a_json_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``backup --json`` is what a scheduler parses; the rendered failure is its ``error``."""
    _patch_leaky_load(monkeypatch)
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("", encoding="utf-8")
    code = main(["backup", "--service-config", str(cfg), "--destination", str(tmp_path), "--json"])
    out = capsys.readouterr().out
    assert code != 0
    error = str(json.loads(out)["error"])
    assert _CANARY not in error and _MESSAGE in error


@pytest.mark.parametrize("existed", [True, False], ids=["file-existed", "file-created"])
def test_security_edit_rolls_back_when_the_callback_refuses_in_its_own_type(
    tmp_path: Path, existed: bool
) -> None:
    """A callback that raises ``SecurityEditError`` -- what the CLI's rendering callback now raises --
    still rolls the write back. It used to be re-raised before the rollback, leaving the refused
    text on disk."""
    path = tmp_path / "messagefoundry.toml"
    original = "# keep me\n[security]\nrequire_mfa = false\n"
    if existed:
        path.write_text(original, encoding="utf-8")

    def refuse(_: Path) -> None:
        raise security_edit.SecurityEditError("refused by the callback")

    with pytest.raises(security_edit.SecurityEditError, match="refused by the callback"):
        security_edit.set_security(path, {"require_mfa": True}, validate=refuse)
    if existed:
        assert path.read_text(encoding="utf-8") == original
    else:
        assert not path.exists()


#: The commands whose settings refusal is "could not start", exit 2. `audit-verify` and
#: `audit-anchor` have the same case in `tests/test_audit_integrity.py`'s `_BAD_SETTINGS`.
_DIRECTORY_ARMS = [
    ["rotate-key"],
    ["admin-unlock", "--username", "a", "--json"],
    ["admin-set-notify-email", "--username", "a", "--email", "a@example.org", "--json"],
    ["admin-reset-totp", "--username", "a", "--json"],
    # BACKLOG #2337: the transit-bound commands share the admin commands' host gate.
    ["store", "attest-transit-bound", "--reason", "r", "--json"],
    ["store", "withdraw-transit-bound", "--json"],
]


@pytest.mark.parametrize(
    "argv",
    _DIRECTORY_ARMS,
    ids=[argv[1] if argv[0] == "store" else argv[0] for argv in _DIRECTORY_ARMS],
)
def test_a_directory_named_as_the_service_config_exits_2(
    argv: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Vault BACKLOG #3110, item 4. A directory named as ``--service-config`` passes the load's
    existence check and raises an ``OSError`` at the open, which ``_load_service_settings`` catches
    (#2760). These commands then exit 2, could not start, with one rendered line. ``rotate-key``
    exited 1 at the dispatch floor before #2760, and the admin commands' shared host gate exited 1,
    the code they give a refusal about the account."""
    code = main([*argv, "--service-config", str(tmp_path), "--db", str(tmp_path / "x.db")])
    captured = capsys.readouterr()
    assert code == 2, (captured.out, captured.err)
    if "--json" in argv:
        assert "error" in json.loads(captured.out), captured.out
    else:
        assert captured.err.startswith("error: "), captured.err
    assert "Traceback" not in captured.out + captured.err


def test_support_bundle_refuses_an_explicit_settings_path_it_cannot_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A directory named as ``--service-config`` is a user error like a missing file, not a warning
    beside an incomplete bundle that exits 0."""
    code = main(
        [
            "support-bundle",
            "--config",
            str(tmp_path),
            "--service-config",
            str(tmp_path),
            "--out",
            str(tmp_path / "bundle.zip"),
        ]
    )
    err = capsys.readouterr().err
    assert code == 2
    assert "cannot read --service-config" in err
    assert not (tmp_path / "bundle.zip").exists()
