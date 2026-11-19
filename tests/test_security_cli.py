# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``security show|set`` CLI (ADR 0118): the comment-preserving backend the VS Code ``[security]``
editor shells. Mirrors the ``alert`` CLI — validate-before-persist + roll-back, offline, applies on the
next engine restart."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import _ENV_PREFIX, _REMOVED_KEYS


def _show(path: Path, capsys: pytest.CaptureFixture[str]) -> dict:
    assert main(["security", "show", "--service-config", str(path), "--json"]) == 0
    return json.loads(capsys.readouterr().out)


def _set(path: Path, updates: dict, capsys: pytest.CaptureFixture[str]) -> tuple[int, dict]:
    rc = main(
        ["security", "set", "--service-config", str(path), "--data", json.dumps(updates), "--json"]
    )
    out = capsys.readouterr().out
    return rc, (json.loads(out) if out.strip() else {})


def test_show_defaults_when_absent(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    toml = tmp_path / "mf.toml"
    data = _show(toml, capsys)
    assert data["set"] == [] and data["loosenings"] == []
    assert data["values"]["require_mfa"] is True and data["values"]["local_access_only"] is True
    assert data["defaults"]["block_unlisted_outbound"] is True
    #  sat beside this and is retired (BACKLOG #1279); the model no longer
    # carries the field, so  cannot report it and must not invent it.
    assert "handles_real_patient_data" not in data["values"]
    assert data["values"]["production_instance"] is None  # unset → derived from environment


def test_set_writes_security_and_preserves_other_sections(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = tmp_path / "mf.toml"
    toml.write_text("# my config\n[api]\nport = 9000\n", encoding="utf-8")
    rc, res = _set(toml, {"require_mfa": False}, capsys)
    assert rc == 0 and res["keys"] == ["require_mfa"]
    # the loosening is reported so the editor can warn in place
    assert any(lo["switch"] == "require_mfa" for lo in res["loosenings"])
    text = toml.read_text(encoding="utf-8")
    assert "# my config" in text and "port = 9000" in text  # other sections byte-stable
    assert "[security]" in text and "require_mfa = false" in text
    # show now reflects it
    data = _show(toml, capsys)
    assert data["set"] == ["require_mfa"] and data["values"]["require_mfa"] is False


def test_null_value_resets_to_default_and_drops_emptied_table(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = tmp_path / "mf.toml"
    _set(toml, {"require_mfa": False}, capsys)
    rc, _ = _set(toml, {"require_mfa": None}, capsys)  # null → reset to secure default
    assert rc == 0
    text = toml.read_text(encoding="utf-8")
    assert "[security]" not in text and "require_mfa" not in text  # emptied table dropped


def test_null_reset_of_an_unknown_key_is_refused_and_leaves_the_loosening(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5327: a null reset of a misspelled key changed nothing, yet the CLI exited 0 and
    reported the key as set, so the loosening the operator meant to reset stayed on disk."""
    toml = tmp_path / "mf.toml"
    _set(toml, {"require_mfa": False}, capsys)
    before = toml.read_bytes()
    rc = main(
        [
            "security",
            "set",
            "--service-config",
            str(toml),
            "--data",
            json.dumps({"require_mfx": None}),
        ]
    )
    err = capsys.readouterr().err
    assert rc != 0
    assert "require_mfx" in err and "did you mean 'require_mfa'" in err
    assert toml.read_bytes() == before  # nothing written; the loosening is still there


def test_set_security_reports_a_reset_that_finds_nothing_as_unchanged(tmp_path: Path) -> None:
    """BACKLOG #5327, the editor itself: a reset that finds nothing is reported apart from a key
    it wrote, and the edit is still validated like any other."""
    from messagefoundry.config import security_edit

    seen: list[Path] = []
    toml = tmp_path / "mf.toml"
    result = security_edit.set_security(toml, {"require_mfa": None}, validate=seen.append)
    # No file and no key changed: none is created, nothing is checked, and the result says the
    # file was not written rather than claim a rewrite.
    assert result == {
        "op": "unchanged",
        "keys": [],
        "unchanged": ["require_mfa"],
        "rewritten": False,
        "detail": "no key changed; mf.toml does not exist, so no settings file was created",
    }
    assert not toml.exists() and seen == []
    # No edit lock either: its file would be the edit's only trace.
    assert list(tmp_path.iterdir()) == []
    # A file that is there goes through the validated replace like any set, and says so.
    toml.write_text("[security]\nrequire_mfa = false\n", encoding="utf-8")
    result = security_edit.set_security(toml, {"require_mfa": False}, validate=seen.append)
    assert result == {
        "op": "unchanged",
        "keys": [],
        "unchanged": ["require_mfa"],
        "rewritten": True,
        "detail": "no key changed; file rewritten by the validated replace every set uses, which "
        "restricts it, on POSIX to its owner afterwards (the editing account unless root keeps the "
        "previous owner), on Windows to the editing account or, where another account owned it, to "
        "that account and the editing account, and logs a warning where it cannot",
    }
    assert len(seen) == 1 and seen[0] != toml and seen[0].name == toml.name
    # A value equal in Python but of another type is a change, not the value the file holds.
    toml.write_text("[security]\nsign_out_after_idle_minutes = 1\n", encoding="utf-8")
    result = security_edit.set_security(
        toml, {"sign_out_after_idle_minutes": True}, validate=lambda _c: None
    )
    assert result["op"] == "set"


def test_null_reset_of_a_removed_key_offers_no_spelling(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A removed [security] key is refused like any unknown one, with no nearest spelling: for
    require_sign_in that would be require_mfa, a different switch (vault BACKLOG #2719)."""
    assert ("security", "require_sign_in") in _REMOVED_KEYS
    toml = tmp_path / "mf.toml"
    rc = main(
        [
            "security",
            "set",
            "--service-config",
            str(toml),
            "--data",
            json.dumps({"require_sign_in": None}),
        ]
    )
    err = capsys.readouterr().err
    assert rc != 0 and "[security].require_sign_in was REMOVED" in err
    # Neither a nearest spelling nor advice to check the spelling of a key that is not misspelled.
    assert "did you mean" not in err and "Check the spelling" not in err
    assert not toml.exists()


def test_null_reset_refusal_names_every_unknown_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = tmp_path / "mf.toml"
    rc = main(
        [
            "security",
            "set",
            "--service-config",
            str(toml),
            "--data",
            json.dumps({"require_mfx": None, "block_unlisted_outbund": None}),
        ]
    )
    err = capsys.readouterr().err
    assert rc != 0
    # Joined as the loader joins unknown keys.
    assert (
        "[security].require_mfx (did you mean 'require_mfa'?), [security].block_unlisted_outbund"
        in err
    )


def test_an_edit_that_changes_nothing_still_refuses_a_file_the_engine_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An edit that changes nothing must not report a file the whole-file load refuses as fine:
    before BACKLOG #5327 every set ran that load, and it still does."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[auth]\nenabled = false\n", encoding="utf-8")
    before = toml.read_bytes()
    rc, _ = _set(toml, {"require_mfa": None}, capsys)
    assert rc == 1 and toml.read_bytes() == before


def test_a_value_the_file_already_holds_is_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = tmp_path / "mf.toml"
    _set(toml, {"require_mfa": False}, capsys)
    before = toml.read_bytes()
    rc, res = _set(toml, {"require_mfa": False}, capsys)
    assert rc == 0 and res["op"] == "unchanged" and res["unchanged"] == ["require_mfa"]
    assert toml.read_bytes() == before
    # The loosening the file still carries is still reported.
    assert "require_mfa" in [lo["switch"] for lo in res["loosenings"]]


def test_every_ide_security_field_is_a_security_setting() -> None:
    """The IDE editor sends null for each field at its default, and a null reset of a key
    [security] does not define is refused (BACKLOG #5327), so a field the model dropped would
    block every IDE save. TypeScript cannot import the Python, so this reads the source."""
    import re

    from messagefoundry.config.settings import SecuritySettings

    source = (
        Path(__file__).resolve().parent.parent / "ide" / "src" / "securityEditorWebview.ts"
    ).read_text(encoding="utf-8")
    block = source.split("export const FIELDS", 1)[1].split("\n];", 1)[0]
    keys = re.findall(r'\{\s*key\s*:\s*"([^"]+)"', block)
    assert len(keys) > 5  # the parse found the entries
    assert set(keys) <= set(SecuritySettings.model_fields)


def test_null_reset_of_an_unknown_key_the_file_carries_removes_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Removing a key the file does carry is a real change, and the repair for a file the
    whole-file load refuses, so it is not refused."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\nrequire_mfx = false\n", encoding="utf-8")
    rc, res = _set(toml, {"require_mfx": None}, capsys)
    assert rc == 0 and res["op"] == "set" and res["keys"] == ["require_mfx"]
    assert "require_mfx" not in toml.read_text(encoding="utf-8")


def test_null_reset_in_a_missing_folder_is_refused_and_creates_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5327: a reset whose folder does not exist is a mistyped path, so it exits non-zero
    and creates nothing rather than read as a successful reset. An absent file in a folder that
    exists still exits 0 and creates nothing, the edit lock's file included."""
    toml = tmp_path / "missing" / "mf.toml"
    rc, err = _set(toml, {"require_mfa": None}, capsys)
    assert rc != 0
    assert "does not exist" in err["error"] and "missing" in err["error"]
    assert list(tmp_path.iterdir()) == []
    # In a folder that exists, no lock file is left beside the absent settings file.
    toml = tmp_path / "mf.toml"
    rc, res = _set(toml, {"require_mfa": None}, capsys)
    assert rc == 0 and res["rewritten"] is False
    assert list(tmp_path.iterdir()) == []


def test_null_reset_where_the_stat_is_refused_is_not_reported_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5327: a failed stat is not "nothing there". Where the editors' shared stat gate
    refuses the path, as for a file behind an unreachable share, the reset is refused rather than
    reported as finding no file."""
    from messagefoundry.config import atomic_edit, security_edit

    def refuse(path: Path, *, refused_error: object) -> bool:
        raise security_edit.SecurityEditError(f"could not stat {path.name}")

    monkeypatch.setattr(atomic_edit, "is_file", refuse)
    with pytest.raises(security_edit.SecurityEditError, match="could not stat"):
        security_edit.set_security(
            tmp_path / "mf.toml", {"require_mfa": None}, validate=lambda _c: None
        )


def test_null_reset_under_a_regular_file_is_not_reported_absent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5327: a path under a regular file is a mistyped path, not a missing settings
    file, so a reset there fails rather than exit 0 as finding no file."""
    notes = tmp_path / "notes.txt"
    notes.write_text("x", encoding="utf-8")
    rc, _res = _set(notes / "mf.toml", {"require_mfa": None}, capsys)
    assert rc != 0
    assert sorted(tmp_path.iterdir()) == [notes]


def test_null_reset_of_an_absent_known_key_reports_nothing_changed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5327: resetting a known key the file does not set changes nothing, so the result
    says so instead of reporting it as set, and the file's text is as it was."""
    toml = tmp_path / "mf.toml"
    toml.write_text("# keep\n[api]\nport = 9000\n", encoding="utf-8")
    before = toml.read_bytes()
    rc, res = _set(toml, {"require_mfa": None}, capsys)
    assert rc == 0
    assert res["op"] == "unchanged" and res["keys"] == [] and res["unchanged"] == ["require_mfa"]
    assert toml.read_bytes() == before
    # Mixed: the reset that found nothing is named apart from the key that was written.
    rc, res = _set(toml, {"require_mfa": None, "max_session_hours": 13}, capsys)
    assert rc == 0 and res["op"] == "set"
    assert res["keys"] == ["max_session_hours"] and res["unchanged"] == ["require_mfa"]


def test_ac3_contradiction_is_rejected_and_rolled_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = tmp_path / "mf.toml"
    toml.write_text("[api]\nport = 9000\n", encoding="utf-8")
    rc, _ = _set(toml, {"local_access_only": True, "listen_address": "0.0.0.0"}, capsys)
    assert rc == 1  # the contradiction (AC-3) fails validation on write
    assert "[security]" not in toml.read_text(encoding="utf-8")  # rolled back, original intact
    assert "port = 9000" in toml.read_text(encoding="utf-8")


def test_set_rejects_a_file_that_still_has_a_relocated_legacy_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A file still carrying a refused key ([auth].enabled, removed by vault BACKLOG #2719) fails
    # validation on write → rolled back.
    toml = tmp_path / "mf.toml"
    toml.write_text("[auth]\nenabled = false\n", encoding="utf-8")
    rc, res = _set(toml, {"require_mfa": False}, capsys)
    assert rc == 1


@pytest.mark.parametrize(
    ("switch", "looser"), [("sign_out_after_idle_minutes", 31), ("max_session_hours", 13)]
)
def test_set_preview_reads_the_session_limits_after_the_edit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], switch: str, looser: int
) -> None:
    """Vault BACKLOG #2600: the two [security] session limits are reported off their [auth] copies,
    so the preview must name a limit the edit sets looser (the first assertion) and drop one the
    edit removes (the second), as the saved file reads back. Before the fix it paired the edited
    [security] with the [auth] loaded before the edit and did neither. The pairing with the
    pre-edit load itself is guarded by test_set_preview_scope_is_read_after_the_edit."""
    toml = tmp_path / "mf.toml"
    rc, res = _set(toml, {switch: looser}, capsys)
    assert rc == 0
    assert switch in [lo["switch"] for lo in res["loosenings"]]
    # Agrees with what `show` reads back from the saved file.
    assert switch in [lo["switch"] for lo in _show(toml, capsys)["loosenings"]]
    rc, res = _set(toml, {switch: None}, capsys)
    assert rc == 0
    assert switch not in [lo["switch"] for lo in res["loosenings"]]


def _entries(res: dict, switch: str) -> list[dict]:
    return [lo for lo in res["loosenings"] if lo["switch"] == switch]


def test_the_session_limits_are_reported_as_the_file_sets_them(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both commands print the file's [security] in `values`, so a session limit the file sets
    looser is named once, as the file's, even while a shell variable tightens it (vault BACKLOG
    #2600). The variable is a valid one, so the load succeeds and nothing reads as partial."""
    toml = tmp_path / "mf.toml"
    monkeypatch.setenv(f"{_ENV_PREFIX}SECURITY_MAX_SESSION_HOURS", "12")
    rc, res = _set(toml, {"max_session_hours": 24}, capsys)
    assert rc == 0 and res["loosenings_partial"] is False
    (entry,) = _entries(res, "max_session_hours")
    assert "MEFOR_SECURITY" not in entry["risk"]


@pytest.mark.parametrize(
    ("switch", "looser"), [("max_session_hours", "48"), ("sign_out_after_idle_minutes", "240")]
)
def test_a_session_limit_only_the_environment_loosens_is_named_as_the_environments(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    switch: str,
    looser: str,
) -> None:
    """The file leaves the limit at its default and a MEFOR_SECURITY_* variable in this shell sets
    it looser. `show` and the `set` preview still name it, as origin/main did, labelled with the
    variable, since `values` prints the file's default (vault BACKLOG #2600). The control is the
    same file with no variable: nothing is named."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\nrequire_mfa = true\n", encoding="utf-8")
    assert _entries(_show(toml, capsys), switch) == []
    variable = f"{_ENV_PREFIX}SECURITY_{switch.upper()}"
    monkeypatch.setenv(variable, looser)
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is False
    assert data["values"][switch] == data["defaults"][switch]
    rc, res = _set(toml, {"block_unlisted_outbound": True}, capsys)
    assert rc == 0 and res["loosenings_partial"] is False
    for report in (data, res):
        (entry,) = _entries(report, switch)
        assert entry["risk"].startswith(f"set by {variable} in this command's environment")


def test_a_variable_looser_than_a_loose_file_is_named_beside_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file sets the limit looser and the variable looser still: both values are named, the
    file's unlabelled and the variable's labelled, so the looser one this shell loads is not hidden
    behind the file's (vault BACKLOG #2600)."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\nmax_session_hours = 24\n", encoding="utf-8")
    monkeypatch.setenv(f"{_ENV_PREFIX}SECURITY_MAX_SESSION_HOURS", "48")
    authored, from_env = _entries(_show(toml, capsys), "max_session_hours")
    assert "MEFOR_SECURITY" not in authored["risk"]
    assert from_env["risk"].startswith(f"set by {_ENV_PREFIX}SECURITY_MAX_SESSION_HOURS")


def test_two_reads_that_disagree_with_no_variable_are_not_blamed_on_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no variable set, a loaded limit that differs from the [security] read, as a concurrent
    edit between the two reads leaves it, is still named but not labelled as a variable that does
    not exist (vault BACKLOG #2600)."""
    from messagefoundry.config import security_edit

    monkeypatch.delenv(f"{_ENV_PREFIX}SECURITY_MAX_SESSION_HOURS", raising=False)
    monkeypatch.setattr(security_edit, "read_security", lambda service_config: {})
    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\nmax_session_hours = 48\n", encoding="utf-8")
    (entry,) = _entries(_show(toml, capsys), "max_session_hours")
    assert entry["risk"].startswith("read differently by the whole-file load")


def _clear_security_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every spelling of a MEFOR_SECURITY_* variable from this test's environment, so a
    developer shell's own cannot change what the test reads."""
    import os

    for name in list(os.environ):
        if name.upper().startswith(f"{_ENV_PREFIX}SECURITY_"):
            monkeypatch.delenv(name)


def test_a_variable_equal_to_the_file_adds_no_entry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A MEFOR_SECURITY_* variable that sets a session limit to the file's own value adds nothing:
    the limit is named once, as the file's, unlabelled (vault BACKLOG #2600). The control is the
    same file with the variable one hour looser: a second, labelled entry appears."""
    _clear_security_env(monkeypatch)
    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\nmax_session_hours = 48\n", encoding="utf-8")
    variable = f"{_ENV_PREFIX}SECURITY_MAX_SESSION_HOURS"
    monkeypatch.setenv(variable, "48")
    (entry,) = _entries(_show(toml, capsys), "max_session_hours")
    assert not _is_labelled(entry), entry
    monkeypatch.setenv(variable, "49")
    authored, labelled = _entries(_show(toml, capsys), "max_session_hours")
    assert not _is_labelled(authored) and labelled["risk"].startswith(f"set by {variable}")


def test_set_on_a_new_file_names_the_variable_show_on_an_absent_one_does_not(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`show` on a file that does not exist runs no load, so a variable that loosens a session
    limit is not named there; `set` on that path writes a new file and loads it, so its preview
    names the variable (vault BACKLOG #2600). Each arm is the other's control."""
    _clear_security_env(monkeypatch)
    toml = tmp_path / "mf.toml"
    variable = f"{_ENV_PREFIX}SECURITY_MAX_SESSION_HOURS"
    monkeypatch.setenv(variable, "48")
    assert _entries(_show(toml, capsys), "max_session_hours") == []
    rc, res = _set(toml, {"block_unlisted_outbound": True}, capsys)
    assert rc == 0 and toml.exists()
    (entry,) = _entries(res, "max_session_hours")
    assert entry["risk"].startswith(f"set by {variable} in this command's environment")


@pytest.mark.parametrize(
    ("names", "read_by_the_load"),
    [
        (("MEFOR_security_max_session_hours",), True),
        (("mefor_SECURITY_MAX_SESSION_HOURS",), False),
        (("MEFOR_SECURITY_MAX_SESSION_HOURS", "MEFOR_security_max_session_hours"), True),
    ],
)
def test_the_label_names_a_variable_by_the_loaders_rule(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    names: tuple[str, ...],
    read_by_the_load: bool,
) -> None:
    """The label names a variable only as the loader reads one: the MEFOR_ prefix matched as
    written, the rest in any case (vault BACKLOG #2600). The environment is a plain mapping, as a
    case-sensitive platform's is, so this runs the same on Windows. The [security] read is emptied,
    so the two reads disagree whether or not the variable is read.

    A name the loader reads is named as written. One whose prefix is lower case the loader skips,
    so the label must not blame it; an upper-casing lookup did. Of two spellings the loader reads,
    the later one in the environment takes effect, and the label names that one alone: the earlier
    is set to a stricter 12, so a label naming it would carry the wrong value."""
    import os

    from messagefoundry.config import security_edit

    environ = {k: v for k, v in os.environ.items() if not k.upper().startswith("MEFOR_SECURITY_")}
    for name in names[:-1]:
        environ[name] = "12"
    name = names[-1]
    environ[name] = "49"
    monkeypatch.setattr(os, "environ", environ)
    monkeypatch.setattr(security_edit, "read_security", lambda service_config: {})
    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\nmax_session_hours = 48\n", encoding="utf-8")
    (entry,) = _entries(_show(toml, capsys), "max_session_hours")
    if read_by_the_load:
        assert entry["risk"].startswith(f"set by {name} in this command's environment,"), entry
        assert "49 hour" in entry["risk"], entry
        assert all(other not in entry["risk"] for other in names[:-1]), entry
    else:
        assert entry["risk"].startswith("read differently by the whole-file load"), entry
        assert "48 hour" in entry["risk"], entry


@pytest.mark.parametrize("error", ["security_edit", "os", "validation"])
def test_set_preview_does_not_refuse_an_edit_whose_candidate_read_raises(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    error: str,
) -> None:
    """The preview's read of the candidate is for the report only, so a SecurityEditError, an
    OSError or a ValidationError from it falls back to the pre-check view rather than refusing an
    edit the whole-file load accepted (vault BACKLOG #2600). Only the candidate's read raises; the
    live file reads.

    The fallback logs a WARNING naming the exception's type and nothing of its text, which can
    quote the file's values, and the report says it is partial and why, so the pre-check view
    never reads as complete. The control is an edit whose candidate
    reads: it logs no such line, and its report is not partial. The handler sits on the module's
    logger, since `--json` replaces the root's handlers."""
    import logging

    from messagefoundry.config import security_edit

    real = security_edit.read_security
    toml = tmp_path / "mf.toml"
    marker = "could not be re-read for the report"
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collect(logging.WARNING)
    logger = logging.getLogger("messagefoundry.__main__")
    logger.addHandler(handler)
    try:
        rc, control = _set(toml, {"require_mfa": True}, capsys)
        assert rc == 0 and not [r for r in records if marker in r.getMessage()]
        assert control["loosenings_partial"] is False
        assert control["loosenings_partial_reason"] is None

        def failing_candidate(service_config: str | Path) -> dict:
            if Path(service_config) != toml:
                if error == "validation":  # as a concurrent edit before the lock can leave it
                    return {"require_mfa": "secret-sentinel-0451"}
                if error == "os":
                    raise OSError("secret-sentinel-0451")
                raise security_edit.SecurityEditError("secret-sentinel-0451")
            return real(service_config)

        monkeypatch.setattr(security_edit, "read_security", failing_candidate)
        rc, res = _set(toml, {"max_session_hours": 48}, capsys)
    finally:
        logger.removeHandler(handler)
    assert rc == 0, res
    assert "max_session_hours = 48" in toml.read_text(encoding="utf-8")
    assert _entries(res, "max_session_hours")
    (record,) = [r for r in records if marker in r.getMessage()]
    assert record.levelno == logging.WARNING and record.exc_info is None
    expected = {"os": "OSError", "validation": "ValidationError"}.get(error, "SecurityEditError")
    assert f"({expected})" in record.getMessage()
    assert all("secret-sentinel-0451" not in r.getMessage() for r in records)
    assert res["loosenings_partial"] is True
    reason = res["loosenings_partial_reason"]
    assert marker in reason and f"({expected})" in reason
    assert "secret-sentinel-0451" not in json.dumps(res)


def test_an_unset_session_limit_reads_the_auth_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The load copies a [security] switch into [auth] only when the file sets it, so an unset
    session limit stays at the [auth] field's own default. The two defaults are separate literals,
    so a [security] default moved alone must not make `show` name a limit the engine would not
    (vault BACKLOG #2600). The control is the set limit: the same moved default, authored, is named."""
    from messagefoundry.config import settings

    class _MovedDefault(settings.SecuritySettings):
        max_session_hours: int = 24

    monkeypatch.setattr(settings, "SecuritySettings", _MovedDefault)
    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\nrequire_mfa = true\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert data["values"]["max_session_hours"] == 24 and data["loosenings_partial"] is False
    assert "max_session_hours" not in [lo["switch"] for lo in data["loosenings"]]
    toml.write_text("[security]\nmax_session_hours = 24\n", encoding="utf-8")
    assert "max_session_hours" in [lo["switch"] for lo in _show(toml, capsys)["loosenings"]]


def _is_labelled(entry: dict) -> bool:
    """Whether a loosening entry is one the whole-file load added, not an authored one."""
    return entry["risk"].startswith(("set by ", "read differently by the whole-file load"))


@pytest.mark.parametrize("candidate_read", ["fresh", "stale"])
def test_set_preview_reads_the_security_it_saved(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    candidate_read: str,
) -> None:
    """The preview's [security] is the one in the candidate the edit lock validated, not the
    pre-check read taken before the lock (vault BACKLOG #2600). The first read is made stale, as a
    concurrent edit landing between it and the lock would leave it, and the saved file's looser
    session limit is named exactly once, as the file's, with no entry labelled as the load's.

    The `stale` arm is the control: the candidate's read is made stale too, as a preview that kept
    the pre-check view would leave it. The limit is then named only by the load, labelled, so the
    assertion on the `fresh` arm cannot pass on a stale view."""
    from messagefoundry.config import security_edit

    _clear_security_env(monkeypatch)
    real = security_edit.read_security
    calls: list[str] = []

    def stale_first(service_config: str | Path) -> dict:
        calls.append(str(service_config))
        if len(calls) == 1 or candidate_read == "stale":
            return {}
        return real(service_config)

    monkeypatch.setattr(security_edit, "read_security", stale_first)
    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\nmax_session_hours = 48\n", encoding="utf-8")
    rc, res = _set(toml, {"block_unlisted_outbound": True}, capsys)
    assert rc == 0 and len(calls) >= 2
    assert "max_session_hours = 48" in toml.read_text(encoding="utf-8")
    (entry,) = _entries(res, "max_session_hours")
    assert _is_labelled(entry) is (candidate_read == "stale"), entry


@pytest.mark.parametrize(
    ("switch", "field"),
    [
        ("sign_out_after_idle_minutes", "session_idle_timeout_minutes"),
        ("max_session_hours", "session_absolute_hours"),
    ],
)
def test_the_session_limit_defaults_agree(switch: str, field: str) -> None:
    """`show` prints the [security] default, the IDE marks a value above it, and the engine names a
    value above the [auth] default. They are separate literals, so this pins them equal."""
    from messagefoundry.config.settings import AuthSettings, SecuritySettings

    assert SecuritySettings.model_fields[switch].default == AuthSettings.model_fields[field].default


def test_set_preview_does_not_refuse_a_saved_edit_over_its_own_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The preview's read of the saved [security] must not refuse an edit the whole-file load
    accepted (vault BACKLOG #2600). A file value that fails on its own while a MEFOR_SECURITY_*
    variable overrides it loads; the stale first read stands in for the concurrent edit that put it
    there after the pre-check."""
    from messagefoundry.config import security_edit

    real = security_edit.read_security
    calls: list[str] = []

    def stale_first(service_config: str | Path) -> dict:
        calls.append(str(service_config))
        return {} if len(calls) == 1 else real(service_config)

    monkeypatch.setattr(security_edit, "read_security", stale_first)
    monkeypatch.setenv(f"{_ENV_PREFIX}SECURITY_MAX_SESSION_HOURS", "12")
    toml = tmp_path / "mf.toml"
    toml.write_text('[security]\nmax_session_hours = "x"\n', encoding="utf-8")
    rc, res = _set(toml, {"block_unlisted_outbound": True}, capsys)
    assert rc == 0, res
    assert "block_unlisted_outbound = true" in toml.read_text(encoding="utf-8")


def test_set_preview_scope_is_read_after_the_edit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An edit that repairs the only reason the whole file would not load reports a complete
    preview, not the pre-edit partial marker: the preview and its scope come from one post-edit
    read. The pre-edit `show` is the control: the same file is partial before the edit.

    A one-minute idle limit is shorter than the [auth] second-factor floor, a cross-section
    refusal that [security] alone does not see, so the whole file will not load until the edit."""
    toml = tmp_path / "mf.toml"
    toml.write_text(
        "[security]\nsign_out_after_idle_minutes = 1\n[auth]\nmfa_verify_min_elapsed_seconds = 120\n",
        encoding="utf-8",
    )
    assert _show(toml, capsys)["loosenings_partial"] is True
    rc, res = _set(toml, {"sign_out_after_idle_minutes": 31}, capsys)
    assert rc == 0
    assert res["loosenings_partial"] is False and res["loosenings_partial_reason"] is None
    assert "sign_out_after_idle_minutes" in [lo["switch"] for lo in res["loosenings"]]


def test_set_rejects_bad_value_type(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    toml = tmp_path / "mf.toml"
    rc, _ = _set(toml, {"max_session_hours": "not-an-int"}, capsys)
    assert rc == 1
    assert not toml.exists()  # never created a broken file


def test_set_round_trips_a_string_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # allowed_client_networks (ADR 0151) is the first LIST-valued [security] switch: tomlkit must emit a
    # native TOML array, and `show` must read it back unchanged.
    toml = tmp_path / "mf.toml"
    rc, _ = _set(toml, {"allowed_client_networks": ["10.20.0.0/16", "fd00::/8"]}, capsys)
    assert rc == 0
    assert 'allowed_client_networks = ["10.20.0.0/16", "fd00::/8"]' in toml.read_text(
        encoding="utf-8"
    )
    assert _show(toml, capsys)["values"]["allowed_client_networks"] == ["10.20.0.0/16", "fd00::/8"]


def test_set_rejects_a_malformed_network_and_rolls_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = tmp_path / "mf.toml"
    assert _set(toml, {"allowed_client_networks": ["10.20.0.0/16"]}, capsys)[0] == 0
    rc, _ = _set(toml, {"allowed_client_networks": ["not-a-cidr"]}, capsys)
    assert rc == 1
    # The good value survives — a rejected edit never lands.
    assert 'allowed_client_networks = ["10.20.0.0/16"]' in toml.read_text(encoding="utf-8")


def test_set_rejects_the_allowlist_beside_a_broad_trusted_proxies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The cross-section refusal fires through the CLI's validate-before-persist path too: a range of
    # trusted spoofers would silently nullify the allow-list being set.
    toml = tmp_path / "mf.toml"
    # The terminator is declared so the ONLY refusal left is the broad range: BACKLOG #2055 refuses a
    # non-empty trusted_proxies without one, which would return 1 for the wrong reason.
    toml.write_text(
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.0/8"]\n',
        encoding="utf-8",
    )
    rc, res = _set(toml, {"allowed_client_networks": ["10.20.0.0/16"]}, capsys)
    assert rc == 1
    assert "single host" in res["error"], res
    assert "[security]" not in toml.read_text(encoding="utf-8")  # rolled back


def test_show_declares_that_it_cannot_see_connection_scoped_deviations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`security show` reads a SETTINGS file and never loads the connection graph, so it cannot see the
    ADR 0153 per-connection ``cleartext_accepted`` declarations.

    The marker is the whole mitigation: without it this subcommand reports a settings-only list that
    READS as the complete posture, which under "one posture, loosen only" is exactly how a deviation
    stops being visible. Nothing else pins it, so it could otherwise be dropped silently."""
    toml = tmp_path / "mf.toml"
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is False
    assert "cleartext_accepted" in data["loosenings_scope"]
    assert "update_url_form" in data["loosenings_scope"]
    assert "messagefoundry check" in data["loosenings_scope"]


def test_show_declares_that_it_cannot_see_a_cli_bind_override(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The fourth gap, for the same reason as the three above (BACKLOG #1852).

    ``load_settings`` folds an off-box ``serve --host`` into the ``[security]`` view, so a running
    engine's ``GET /security/posture`` reports ``local_access_only = false`` while this command, which
    reads the AUTHORED file, still shows ``true``. Both are right for what they describe. An unmarked
    disagreement between two operator surfaces on one host reads as a defect in one of them, which is
    what sends an auditor hunting."""
    data = _show(tmp_path / "mf.toml", capsys)
    assert "--host" in data["loosenings_scope"]


def test_show_declares_that_the_config_source_escape_is_read_from_its_own_environment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fifth gap (vault BACKLOG #2599). The escape is an environment variable, so this command
    reports the shell it runs in, which may not be the service's. With both variables in that shell
    and an empty file, the list names the escape beside a file that says ``enforce``, and the scope
    marker is what says why."""
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_CONFIG_SOURCE", "1")
    monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    data = _show(tmp_path / "mf.toml", capsys)
    assert data["values"]["enforcement"] == "enforce"
    assert "MEFOR_ALLOW_INSECURE_CONFIG_SOURCE" in [row["switch"] for row in data["loosenings"]]
    assert "MEFOR_ALLOW_INSECURE_CONFIG_SOURCE" in data["loosenings_scope"]
    assert "environment of THIS command" in data["loosenings_scope"]


def test_show_reports_store_and_auth_deviations_from_the_whole_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The registry reaches into [store]/[auth], so this subcommand must resolve the WHOLE file rather
    than [security] alone — otherwise it under-reports the posture it exists to display."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[store]\naad_bind = false\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert "aad_bind" in [entry["switch"] for entry in data["loosenings"]]


def test_show_reports_the_plaintext_upstream_hop_acknowledgement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #1179: [api] is resolved from the whole file too, so the acknowledgement is listed."""
    api = (
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n'
        "plaintext_upstream_hop_acknowledged = true\n"
    )
    toml = tmp_path / "mf.toml"
    toml.write_text(api, encoding="utf-8")
    data = _show(toml, capsys)
    assert "plaintext_upstream_hop_acknowledged" in [e["switch"] for e in data["loosenings"]]
    # Negative control: the same file with an operator certificate serves that hop over TLS, so the
    # acknowledgement is inert and not listed. The cert paths are never opened by `security show`.
    toml.write_text(
        api + 'tls_cert_file = "operator-cert.pem"\ntls_key_file = "operator-key.pem"\n',
        encoding="utf-8",
    )
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is False
    assert "plaintext_upstream_hop_acknowledged" not in [e["switch"] for e in data["loosenings"]]


def test_show_reports_a_shortened_approval_dwell(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #2489: [approvals] is resolved from the whole file too, so a shortened dwell is
    listed. The same floor at its default is the control, so the entry comes from the value."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[approvals]\nenabled = true\nmin_dwell_seconds = 0.5\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is False
    assert "min_dwell_seconds" in [e["switch"] for e in data["loosenings"]]
    toml.write_text("[approvals]\nenabled = true\nmin_dwell_seconds = 2.0\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert "min_dwell_seconds" not in [e["switch"] for e in data["loosenings"]]


def test_show_reports_a_default_operation_left_out_of_dual_control(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Vault BACKLOG #3123: a list that omits a default operation is listed, and the entry names
    the one left out. The same section with no list is the control."""
    toml = tmp_path / "mf.toml"
    toml.write_text(
        '[approvals]\nenabled = true\noperations = ["dead_letter_replay"]\n', encoding="utf-8"
    )
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is False
    risks = {e["switch"]: e["risk"] for e in data["loosenings"]}
    assert "the default operation connection_purge. " in risks["approvals.operations"]
    toml.write_text("[approvals]\nenabled = true\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert "approvals.operations" not in [e["switch"] for e in data["loosenings"]]


def test_show_reports_the_credential_reminders_turned_off(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #2227: [cert_monitor] is resolved from the whole file, like [secret_rotation], so
    each warn_days = 0 is listed. The shipped values are the control."""
    toml = tmp_path / "mf.toml"
    toml.write_text(
        "[cert_monitor]\nwarn_days = 0\n[secret_rotation]\nwarn_days = 0\n", encoding="utf-8"
    )
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is False
    switches = [e["switch"] for e in data["loosenings"]]
    assert "cert_monitor.warn_days" in switches and "secret_rotation.warn_days" in switches
    toml.write_text("[cert_monitor]\nwarn_days = 30\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert "cert_monitor.warn_days" not in [e["switch"] for e in data["loosenings"]]


def test_show_reports_the_backup_cleartext_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Vault BACKLOG #2302: [backup] is resolved from the whole file too, so the cleartext-archive
    escape is listed. The same key at its shipped value is the control."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[backup]\nallow_unencrypted = true\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is False
    assert "backup.allow_unencrypted" in [e["switch"] for e in data["loosenings"]]
    assert "[backup]" in data["loosenings_scope"]
    toml.write_text("[backup]\nallow_unencrypted = false\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert "backup.allow_unencrypted" not in [e["switch"] for e in data["loosenings"]]


def test_show_declares_a_partial_report_when_the_file_will_not_load(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A file invalid OUTSIDE [security] must not break `security show` — but the degraded report has to
    SAY it is degraded, not quietly fall back to shipped defaults and look complete."""
    toml = tmp_path / "mf.toml"
    # Valid TOML, invalid SETTINGS, and invalid entirely outside [security]: an explicit
    # ad_session_recheck_seconds with no ad_enabled is the ADR 0079 cross-field refusal.
    toml.write_text("[auth]\nad_session_recheck_seconds = 300\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is True
    # ...and it still prints a usable [security] view rather than failing the subcommand.
    assert data["values"]["require_mfa"] is True
    # ...and it says WHY (vault BACKLOG #2600), naming the setting that refused.
    assert "ad_session_recheck_seconds" in data["loosenings_partial_reason"]


def test_show_gives_no_partial_reason_when_the_file_loads(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control for the reason: a report that is not partial carries none."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[auth]\nlockout_minutes = 15\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is False
    assert data["loosenings_partial_reason"] is None


@pytest.mark.parametrize("scheme", ["https", "sftp", "s3a"])
@pytest.mark.parametrize(
    ("table", "key"),
    [
        ("backup", "destination"),
        ("dr", "seed_archive"),
        ("dr", "seed_dir"),
        ("dr", "restore_token"),
    ],
)
def test_a_cloud_url_refusal_in_the_partial_reason_quotes_no_part_of_the_url(
    table: str, key: str, scheme: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A URL can carry a credential, and the reason prints each validator's message. The cloud-URL
    refusals refuse the ``<scheme>://`` shape ``_looks_like_url`` reads (vault BACKLOG #2600) and
    quote no part of the URL, the scheme included (vault BACKLOG #2850)."""
    planted = "canary-canary-canary"
    toml = tmp_path / "mf.toml"
    toml.write_text(
        f'[{table}]\n{key} = "{scheme}://svc:{planted}@blob.example/x?sig=SYNTHTOKEN"\n',
        encoding="utf-8",
    )
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is True
    reason = data["loosenings_partial_reason"]
    assert f"{table}.{key}" in reason and "not a URL" in reason
    assert scheme not in reason
    dumped = json.dumps(data)
    assert planted not in dumped and "SYNTHTOKEN" not in dumped


@pytest.mark.parametrize("path", ["D:/mefor-backups", "C://mefor-backups", r"\\\\nas\\share\\x"])
def test_a_local_or_unc_path_is_not_read_as_a_url(path: str) -> None:
    """The control: a drive letter is one character, so ``C://`` is a path, and a UNC path has
    no scheme."""
    from messagefoundry.config.settings import BackupSettings

    assert BackupSettings(destination=path).destination == path


def test_show_names_the_stray_variable_that_made_the_report_partial(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mistyped ``MEFOR_<SECTION>_<KEY>`` in the shell refuses the whole-file load, so the report
    falls back to shipped defaults. The marker alone sent the reader to a file that was fine. The
    reason names the variable and never its value."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[auth]\nlockout_minutes = 15\n", encoding="utf-8")
    monkeypatch.setenv("MEFOR_STORE_REQUIRE_ENCRYPTON", "SYNTHETIC-VALUE-9f3c")
    out_data = _show(toml, capsys)
    assert out_data["loosenings_partial"] is True
    reason = out_data["loosenings_partial_reason"]
    assert "MEFOR_STORE_REQUIRE_ENCRYPTON" in reason
    assert "SYNTHETIC-VALUE-9f3c" not in json.dumps(out_data)


# --- a removed key the environment may still set (vault BACKLOG #3350) ------------------------


#: ``security show`` builds only ``[security]`` straight from the file's table, so only these keys
#: reach the direct-build refusal through it. It reports every other removed key through the
#: loader's refusal.
_SECURITY_REMOVED_KEYS = sorted(key for section, key in _REMOVED_KEYS if section == "security")
# An empty list would turn both tests below into a silent skip.
assert _SECURITY_REMOVED_KEYS, "no removed [security] key left to test"


def _show_refusal(path: Path, capsys: pytest.CaptureFixture[str]) -> str:
    assert main(["security", "show", "--service-config", str(path), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert isinstance(error, str)
    return error


@pytest.mark.parametrize("key", _SECURITY_REMOVED_KEYS)
def test_show_makes_no_claim_about_where_a_removed_key_was_not_set(
    key: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The key is in the file, and the run is repeated with the environment setting it too.

    The refusal is built from the file's table alone, so it is the same text in both runs. It used
    to add "no environment variable set it", which would send an operator away from a variable the
    service would still refuse at start. The removal step is pinned whole, so a provenance claim
    placed before it, inside it or after it fails."""
    toml = tmp_path / "mf.toml"
    toml.write_text(f"[security]\n{key} = false\n", encoding="utf-8")
    file_only = _show_refusal(toml, capsys)
    monkeypatch.setenv(f"{_ENV_PREFIX}SECURITY_{key.upper()}", "false")
    file_and_env = _show_refusal(toml, capsys)
    assert file_and_env == file_only
    assert file_only.startswith("invalid [security]")
    assert (
        f"{_REMOVED_KEYS['security', key]}. Remove `{key}` from the arguments or the file table "
        "the section was built from (see docs/CONFIGURATION.md)."
    ) in file_only
    assert "environment variable" not in file_only.lower()


@pytest.mark.parametrize("key", _SECURITY_REMOVED_KEYS)
def test_show_names_the_variable_that_set_a_removed_key(
    key: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the key in the environment only, the file builds and the partial reason is the
    loader's refusal, which names the variable to unset."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[auth]\nlockout_minutes = 15\n", encoding="utf-8")
    variable = f"{_ENV_PREFIX}SECURITY_{key.upper()}"
    monkeypatch.setenv(variable, "false")
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is True
    assert variable in data["loosenings_partial_reason"]


# --- operator JSON that nests past the decoder (BACKLOG #1855) --------------------------------
#
# `json.loads` guards its own decode depth and raises `RecursionError`, which is a `RuntimeError` --
# NOT a `JSONDecodeError` and not a `ValueError` -- so the `except json.JSONDecodeError` arm beside
# every operator-JSON decode in `__main__.py` structurally cannot reach it. The reasoning, and why
# the catch is scoped to the `json.loads` call rather than to the wide `try` around it, is stated
# once on `_load_operator_json`; this module carries the anchor test for the behaviour.


def _raise_recursion(*_args: object, **_kwargs: object) -> object:
    raise RecursionError("simulated deep nesting")


def test_cli_set_reports_security_json_nested_past_the_decoder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Deeply nested `--data` escaped `security set` uncaught before this arm existed.

    Measured on a real subprocess at engine 40ee1a9cd: exit 1 with **stdout EMPTY**, the whole report
    redacted by the last-resort excepthook (BACKLOG #1674) to one CRITICAL line naming only the
    exception type. That breaks `_emit_error`'s contract that under `--json` the error object IS the
    command's machine-readable output, and it never said which input was at fault.

    THE TRIGGER IS MANUFACTURED, NOT REAL NESTING, AND MUST STAY THAT WAY (BACKLOG #1222): the depth
    where `json`'s C accelerator gives out measures the runner, not this code. Do not "improve" it
    back to real nesting. The argument, the measurements and the type facts
    (`RecursionError` is a `RuntimeError`, not a `ValueError`) are pinned once, in
    `tests/test_sandbox_codec.py::test_recursion_error_is_not_a_value_error`.

    RED when: `_load_operator_json`'s `except RecursionError` arm is dropped, or `_security`'s
    `except _OperatorJsonError` arm is dropped -- the decode escapes to `main`'s dispatch floor
    (BACKLOG #1863), whose JSON error names only the exception type, not the input at fault."""
    monkeypatch.setattr(json, "loads", _raise_recursion)
    rc = main(
        ["security", "set", "--service-config", str(tmp_path / "mf.toml"), "--data", "[]", "--json"]
    )
    out = capsys.readouterr().out
    monkeypatch.undo()  # restore json.loads before parsing the captured payload with it

    assert rc == 1
    error = json.loads(out)["error"]
    assert "is nested too deeply to parse" in error
    # Named per site, so the report says WHICH input was at fault -- the half the CRITICAL line lost.
    assert error.startswith("security update JSON")
    assert not (tmp_path / "mf.toml").exists()  # refused before any write


def test_cli_set_reports_a_malformed_edit_as_json_on_stdout_in_a_real_subprocess(
    tmp_path: Path,
) -> None:
    """`_emit_error`'s `--json` contract, end-to-end in a real process: the error object is the
    command's machine-readable output, on STDOUT, with exit 1 -- so a consumer piping to `jq` reads
    the reason there instead of getting a parse failure on an empty stream.

    A real subprocess measures the real process streams rather than pytest's capture. Before BACKLOG
    #1863 that was the only place an escaping exception's empty stdout was visible; `main` now
    catches the escape at the dispatch and prints a JSON error, so this test pins the ordinary path.

    Driven with ORDINARY malformed JSON, not deep nesting: a subprocess cannot be monkeypatched, and
    real nesting measures the runner rather than the code (BACKLOG #1222 -- see the manufactured
    trigger above). The contract under test does not need a `RecursionError` to demonstrate.

    RED when: `security set` stops routing a decode failure through `_emit_error` -- the payload then
    leaves stdout empty and the reason lands on stderr, if anywhere."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "messagefoundry",
            "security",
            "set",
            "--service-config",
            str(tmp_path / "mf.toml"),
            "--data",
            "{not json",
            "--json",
        ],
        cwd=tmp_path,  # away from the repo, so no stray ./messagefoundry.toml is picked up
        capture_output=True,
        text=True,
        # Well under the pytest-timeout watchdog, so a hang is reported HERE, by a readable
        # `TimeoutExpired` naming the CLI, rather than by the watchdog's thread dump. `addopts` sets
        # `--timeout=60` and CI overrides it per leg (60s ubuntu, 120s Windows), so 60 here would tie
        # the ubuntu watchdog and lose that race -- the watchdog's timer starts at test setup.
        timeout=20,
    )
    assert proc.returncode == 1, f"rc={proc.returncode}\n{proc.stderr}"
    assert proc.stdout.strip(), f"stdout was empty; stderr={proc.stderr}"
    assert json.loads(proc.stdout)["error"].startswith("invalid security update JSON:")
    assert "Traceback" not in proc.stderr, "a raw traceback reached the operator"


# --- BACKLOG #5327: an edit that changes no key still restricts the file to its owner -----------


def test_a_reset_that_finds_nothing_on_an_absent_file_creates_none(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the CLI: no 0-byte file appears, and the result says nothing was written. With no
    file there is no whole-file load, so the report is the one ``show`` gives for an absent file,
    and its scope text says such a set names no session-limit variable."""
    toml = tmp_path / "mf.toml"
    monkeypatch.setenv(f"{_ENV_PREFIX}SECURITY_MAX_SESSION_HOURS", "99")
    rc, res = _set(toml, {"require_mfa": None}, capsys)
    assert rc == 0 and res["op"] == "unchanged" and res["rewritten"] is False
    assert "does not exist" in res["detail"]
    assert not toml.exists()
    shown = _show(toml, capsys)
    assert (res["loosenings"], res["loosenings_partial"]) == (
        shown["loosenings"],
        shown["loosenings_partial"],
    )
    assert "a `set` that changed no key where no file exists" in res["loosenings_scope"]


def test_a_reset_that_finds_nothing_on_a_directory_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a path with nothing at it skips the replace; a directory there fails the replace as it
    does for any set (Windows answers access denied, POSIX a raw IsADirectoryError, both of which
    the CLI reports as an error), never reported as a file that does not exist."""
    import messagefoundry.restricted_file as restricted_mod
    from messagefoundry.config import security_edit

    # Windows retries an access-denied replace for a held file; a directory is never released.
    monkeypatch.setattr(restricted_mod, "_HELD_RETRY_S", 0.0)
    toml = tmp_path / "mf.toml"
    toml.mkdir()
    with pytest.raises((security_edit.SecurityEditError, OSError)):
        security_edit.set_security(toml, {"require_mfa": None}, validate=lambda _c: None)
    assert toml.is_dir()


def test_a_security_table_holding_only_comments_is_kept(tmp_path: Path) -> None:
    """The emptied-table drop is for a table the edit emptied, not one that held only comments
    when the edit removed nothing."""
    from messagefoundry.config import security_edit

    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\n# require_mfa = false  (kept for later)\n", encoding="utf-8")
    before = toml.read_bytes()
    result = security_edit.set_security(toml, {"require_mfa": None}, validate=lambda _c: None)
    assert result["op"] == "unchanged" and result["rewritten"] is True
    assert toml.read_bytes() == before


def _unchanged_set(toml: Path) -> None:
    from messagefoundry.config import security_edit

    result = security_edit.set_security(toml, {"require_mfa": False}, validate=lambda _c: None)
    assert result["op"] == "unchanged" and result["rewritten"] is True


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_an_edit_that_changes_no_key_still_narrows_a_loose_file_on_posix(tmp_path: Path) -> None:
    """Every set goes through the validated replace, which restricts the settings file to its
    owner, so a file left at 0644 is narrowed to 0600 by a set that changes no key."""
    import os
    import stat

    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\nrequire_mfa = false\n", encoding="utf-8")
    os.chmod(toml, 0o644)
    _unchanged_set(toml)
    assert stat.S_IMODE(toml.stat().st_mode) == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_an_edit_that_changes_no_key_but_is_refused_keeps_the_mode_on_posix(
    tmp_path: Path,
) -> None:
    """The control: a refused replace never touches the live file."""
    import os
    import stat

    from messagefoundry.config import security_edit

    def refuse(_candidate: Path) -> None:
        raise ValueError("refused")

    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\nrequire_mfa = false\n", encoding="utf-8")
    os.chmod(toml, 0o644)
    with pytest.raises(security_edit.SecurityEditError):
        security_edit.set_security(toml, {"require_mfa": False}, validate=refuse)
    assert stat.S_IMODE(toml.stat().st_mode) == 0o644


@pytest.mark.skipif(sys.platform != "win32", reason="a Windows access list")
def test_an_edit_that_changes_no_key_still_narrows_a_loose_file_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Windows half: a file whose inherited list also grants SYSTEM is left with its owner's
    entry alone by a set that changes no key, as by any set."""
    import messagefoundry.store.store as store_mod
    from messagefoundry.auth.anchor_path import SYSTEM_SID
    from messagefoundry.config import atomic_edit
    from messagefoundry.store.store import _read_dacl_sddl
    from tests._win_acl import assert_owner_only, folder_granting

    token = store_mod._current_user_sid()
    assert token is not None
    toml = folder_granting(tmp_path / "config", token, SYSTEM_SID) / "mf.toml"
    toml.write_text("[security]\nrequire_mfa = false\n", encoding="utf-8")
    owner = atomic_edit._owner_of(toml)
    assert owner is not None
    # The token seam reports the file's real owner, so the test means the same on every runner.
    monkeypatch.setattr(store_mod, "_current_user_sid", lambda: owner)
    # The positive control: the file starts with SYSTEM's inherited entry beside its owner's.
    before = _read_dacl_sddl(toml, owner=False)
    assert before is not None and ";SY)" in before, before
    _unchanged_set(toml)
    assert_owner_only(toml, owner)


def test_a_bare_security_header_is_dropped_by_a_full_reset(tmp_path: Path) -> None:
    """A bare ``[security]`` header with no comment is still dropped by a set that changes no
    key, so a full reset-to-defaults leaves no header behind."""
    from messagefoundry.config import security_edit

    toml = tmp_path / "mf.toml"
    toml.write_text("[security]\n\n[api]\nport = 9000\n", encoding="utf-8")
    result = security_edit.set_security(toml, {"require_mfa": None}, validate=lambda _c: None)
    assert result["op"] == "unchanged"
    assert "[security]" not in toml.read_text(encoding="utf-8")
