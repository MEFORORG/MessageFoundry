# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""`messagefoundry codeset` — the CSV-first code-set editor the VS Code grid shells.

Covers the writer module (:mod:`messagefoundry.config.codeset_edit`) and the CLI handler: CSV
round-trip (scalar vs dict, pinned by re-loading via ``load_code_sets``), every §4 validation rule
(duplicate key, missing value column, name-safety, stem collision), atomic rollback (a failed edit
leaves the prior file byte-identical; a brand-new failing file is not left behind), rename, remove,
and the read paths (list/show, including a read-only TOML code set).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config import codeset_edit
from messagefoundry.config.code_sets import load_code_set, load_code_sets
from messagefoundry.config.wiring import WiringError


def _validate(path: Path) -> None:
    """The real post-write check the CLI injects: prove the written file loads as a CodeSet."""
    load_code_set(path)


def _codesets(config_dir: Path) -> Path:
    return config_dir / "codesets"


# --- CSV round-trip ----------------------------------------------------------


def test_upsert_single_value_column_is_scalar(tmp_path: Path) -> None:
    result = codeset_edit.upsert_code_set(
        tmp_path,
        "diets",
        ["code", "value"],
        [["A", "Apple"], ["B", "Banana"]],
        validate=_validate,
    )
    assert result == {"op": "upsert", "name": "diets", "format": "csv", "entries": 2}
    # Pin the loader contract: one value column → scalar str.
    sets = load_code_sets(_codesets(tmp_path))
    assert dict(sets["diets"]) == {"A": "Apple", "B": "Banana"}


def test_upsert_multi_value_column_is_dict(tmp_path: Path) -> None:
    codeset_edit.upsert_code_set(
        tmp_path,
        "facility",
        ["code", "name", "mnemonic"],
        [["ACME", "Acme Hospital", "ACMEHOSP"]],
        validate=_validate,
    )
    sets = load_code_sets(_codesets(tmp_path))
    # Two value columns → dict {header: cell}.
    assert sets["facility"]["ACME"] == {"name": "Acme Hospital", "mnemonic": "ACMEHOSP"}


def test_upsert_quotes_special_cells(tmp_path: Path) -> None:
    # A cell with a comma/quote/newline must round-trip (default csv dialect quotes it).
    codeset_edit.upsert_code_set(
        tmp_path,
        "notes",
        ["code", "text"],
        [["A", 'a, "b", c'], ["B", "line1\nline2"]],
        validate=_validate,
    )
    sets = load_code_sets(_codesets(tmp_path))
    assert sets["notes"]["A"] == 'a, "b", c'
    assert sets["notes"]["B"] == "line1\nline2"


def test_upsert_replaces_in_place(tmp_path: Path) -> None:
    codeset_edit.upsert_code_set(
        tmp_path, "diets", ["code", "value"], [["A", "Apple"]], validate=_validate
    )
    codeset_edit.upsert_code_set(
        tmp_path, "diets", ["code", "value"], [["A", "Avocado"]], validate=_validate
    )
    sets = load_code_sets(_codesets(tmp_path))
    assert sets["diets"]["A"] == "Avocado"


def test_upsert_drops_fully_blank_rows(tmp_path: Path) -> None:
    # A content-free row (every cell "") is a harmless empty grid row — dropped on write.
    result = codeset_edit.upsert_code_set(
        tmp_path,
        "diets",
        ["code", "value"],
        [["A", "Apple"], ["", ""], ["B", "Banana"]],
        validate=_validate,
    )
    assert result["entries"] == 2
    sets = load_code_sets(_codesets(tmp_path))
    assert dict(sets["diets"]) == {"A": "Apple", "B": "Banana"}


def test_upsert_rejects_blank_key_with_values(tmp_path: Path) -> None:
    # A row carrying a value under a blank key is real data — reject it (fail loud), never silently
    # drop it (it would otherwise vanish, or via the loader land under an empty-string key).
    with pytest.raises(WiringError, match="row 1 has values but a blank 'code' key column"):
        codeset_edit.upsert_code_set(
            tmp_path,
            "diets",
            ["code", "value"],
            [["A", "Apple"], ["", "ghost"]],
            validate=_validate,
        )
    # Nothing was written.
    assert not (_codesets(tmp_path) / "diets.csv").exists()


def test_upsert_pads_short_rows(tmp_path: Path) -> None:
    # A row shorter than columns is right-padded with "".
    codeset_edit.upsert_code_set(
        tmp_path,
        "facility",
        ["code", "name", "mnemonic"],
        [["ACME", "Acme"]],
        validate=_validate,
    )
    sets = load_code_sets(_codesets(tmp_path))
    assert sets["facility"]["ACME"] == {"name": "Acme", "mnemonic": ""}


# --- structural rejections ---------------------------------------------------


def test_duplicate_key_rejected(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="duplicate key 'A'"):
        codeset_edit.upsert_code_set(
            tmp_path,
            "diets",
            ["code", "value"],
            [["A", "Apple"], ["A", "Avocado"]],
            validate=_validate,
        )
    # Nothing was written.
    assert not (_codesets(tmp_path) / "diets.csv").exists()


def test_missing_value_column_rejected(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="key column plus at least one value column"):
        codeset_edit.upsert_code_set(tmp_path, "diets", ["code"], [["A"]], validate=_validate)


def test_duplicate_header_rejected(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="duplicate column header 'code'"):
        codeset_edit.upsert_code_set(
            tmp_path, "diets", ["code", "code"], [["A", "B"]], validate=_validate
        )


def test_empty_header_rejected(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="column headers must be non-empty strings"):
        codeset_edit.upsert_code_set(
            tmp_path, "diets", ["code", ""], [["A", "B"]], validate=_validate
        )


def test_non_string_cell_rejected(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="every cell must be a string"):
        codeset_edit.upsert_code_set(
            tmp_path, "diets", ["code", "value"], [["A", 1]], validate=_validate
        )


def test_row_too_wide_rejected(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="row 0 has more cells than columns"):
        codeset_edit.upsert_code_set(
            tmp_path, "diets", ["code", "value"], [["A", "B", "C"]], validate=_validate
        )


def test_empty_name_rejected(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="'name' must be a non-empty string"):
        codeset_edit.upsert_code_set(
            tmp_path, "", ["code", "value"], [["A", "B"]], validate=_validate
        )


# --- name-safety -------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "match"),
    [
        ("a/b", "must not contain a path separator"),
        ("a\\b", "must not contain a path separator"),
        ("..", "must not contain '..'"),
        ("../evil", "must not contain a path separator"),  # separator caught first
        ("a..b", "must not contain '..'"),
        ("diets.csv", "no .csv/.toml extension"),
        ("diets.toml", "no .csv/.toml extension"),
        ("   ", "must be a non-empty string"),
    ],
)
def test_name_safety_rejections(tmp_path: Path, name: str, match: str) -> None:
    with pytest.raises(WiringError, match=match):
        codeset_edit.upsert_code_set(
            tmp_path, name, ["code", "value"], [["A", "B"]], validate=_validate
        )


def test_absolute_name_rejected(tmp_path: Path) -> None:
    # An absolute path (POSIX leading slash is also a separator) or a drive-prefixed name.
    with pytest.raises(WiringError):
        codeset_edit.upsert_code_set(
            tmp_path, "C:evil", ["code", "value"], [["A", "B"]], validate=_validate
        )


def test_name_with_extension_does_not_write(tmp_path: Path) -> None:
    with pytest.raises(WiringError):
        codeset_edit.upsert_code_set(
            tmp_path, "diets.csv", ["code", "value"], [["A", "B"]], validate=_validate
        )
    # The unsafe name must not have created a file under codesets/.
    cs_dir = _codesets(tmp_path)
    assert not cs_dir.exists() or list(cs_dir.iterdir()) == []


def test_control_char_name_rejected(tmp_path: Path) -> None:
    # A NUL/control char in the name must be rejected cleanly: an embedded NUL would otherwise make
    # Path.resolve() raise a bare ValueError (not a WiringError) and crash the caller.
    with pytest.raises(WiringError, match="must not contain control characters"):
        codeset_edit.upsert_code_set(
            tmp_path, "die\x00ts", ["code", "value"], [["A", "B"]], validate=_validate
        )
    cs_dir = _codesets(tmp_path)
    assert not cs_dir.exists() or list(cs_dir.iterdir()) == []


# --- stem collision ----------------------------------------------------------


def test_upsert_collides_with_existing_toml(tmp_path: Path) -> None:
    cs_dir = _codesets(tmp_path)
    cs_dir.mkdir()
    (cs_dir / "diets.toml").write_text('A = "Apple"\n', encoding="utf-8")
    with pytest.raises(WiringError, match="two files .different"):
        codeset_edit.upsert_code_set(
            tmp_path, "diets", ["code", "value"], [["A", "Apple"]], validate=_validate
        )
    # The .csv was not written (collision rejected pre-write).
    assert not (cs_dir / "diets.csv").exists()


# --- atomic rollback ---------------------------------------------------------


def test_rollback_leaves_prior_file_byte_identical(tmp_path: Path) -> None:
    codeset_edit.upsert_code_set(
        tmp_path, "diets", ["code", "value"], [["A", "Apple"]], validate=_validate
    )
    path = _codesets(tmp_path) / "diets.csv"
    before = path.read_bytes()

    # A validate that always fails (e.g. the loader rejected the candidate) must restore the prior
    # bytes exactly. Build a structurally-valid grid so the rollback is driven by `validate`, not the
    # pre-write structural checks.
    def failing(_: Path) -> None:
        raise WiringError("boom")

    with pytest.raises(WiringError, match="boom"):
        codeset_edit.upsert_code_set(
            tmp_path, "diets", ["code", "value"], [["A", "Avocado"]], validate=failing
        )
    assert path.read_bytes() == before


def test_rollback_does_not_leave_new_file(tmp_path: Path) -> None:
    def failing(_: Path) -> None:
        raise WiringError("boom")

    with pytest.raises(WiringError, match="boom"):
        codeset_edit.upsert_code_set(
            tmp_path, "fresh", ["code", "value"], [["A", "Apple"]], validate=failing
        )
    # A brand-new file that failed post-write validation must be unlinked, not left behind.
    assert not (_codesets(tmp_path) / "fresh.csv").exists()


# --- show --------------------------------------------------------------------


def test_show_csv_grid(tmp_path: Path) -> None:
    codeset_edit.upsert_code_set(
        tmp_path,
        "facility",
        ["code", "name", "mnemonic"],
        [["ACME", "Acme", "AH"], ["BETA", "Beta", "BH"]],
        validate=_validate,
    )
    detail = codeset_edit.show_code_set(tmp_path, "facility")
    assert detail["name"] == "facility"
    assert detail["format"] == "csv"
    assert detail["columns"] == ["code", "name", "mnemonic"]
    assert detail["rows"] == [["ACME", "Acme", "AH"], ["BETA", "Beta", "BH"]]
    assert detail["shape"] == "dict"


def test_show_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="no such code set 'nope'"):
        codeset_edit.show_code_set(tmp_path, "nope")


def test_show_rejects_traversal_name_without_reading_outside_dir(tmp_path: Path) -> None:
    # A traversal name on the (public, documented) read path must be rejected BEFORE any filesystem
    # touch, or `show` becomes an arbitrary-read of any .csv/.toml on disk (a PHI/secret-leak vector).
    secret = tmp_path / "secret.csv"
    secret.write_text("code,value\nX,leak\n", encoding="utf-8")
    _codesets(tmp_path).mkdir()
    with pytest.raises(WiringError, match="must not contain a path separator"):
        codeset_edit.show_code_set(tmp_path, "../secret")
    # The out-of-dir file was never read (and certainly never returned).
    assert secret.read_text(encoding="utf-8") == "code,value\nX,leak\n"


def test_show_toml_is_read_only_grid(tmp_path: Path) -> None:
    cs_dir = _codesets(tmp_path)
    cs_dir.mkdir()
    (cs_dir / "legacy.toml").write_text('A = "Apple"\nB = "Banana"\n', encoding="utf-8")
    detail = codeset_edit.show_code_set(tmp_path, "legacy")
    assert detail["format"] == "toml"
    assert detail["columns"] == ["key", "value"]
    assert ["A", "Apple"] in detail["rows"]


# --- list --------------------------------------------------------------------


def test_list_empty_when_no_dir(tmp_path: Path) -> None:
    assert codeset_edit.list_code_sets(tmp_path) == []


def test_list_summaries_sorted(tmp_path: Path) -> None:
    codeset_edit.upsert_code_set(
        tmp_path, "zeta", ["code", "value"], [["A", "1"]], validate=_validate
    )
    codeset_edit.upsert_code_set(
        tmp_path, "alpha", ["code", "v1", "v2"], [["A", "1", "2"]], validate=_validate
    )
    summaries = codeset_edit.list_code_sets(tmp_path)
    assert [s["name"] for s in summaries] == ["alpha", "zeta"]
    by_name = {s["name"]: s for s in summaries}
    assert by_name["alpha"]["shape"] == "dict"
    assert by_name["alpha"]["value_columns"] == ["v1", "v2"]
    assert by_name["zeta"]["shape"] == "scalar"
    assert by_name["zeta"]["key"] == "code"


def test_list_fails_loud_on_stem_collision(tmp_path: Path) -> None:
    cs_dir = _codesets(tmp_path)
    cs_dir.mkdir()
    (cs_dir / "diets.csv").write_text("code,value\nA,Apple\n", encoding="utf-8")
    (cs_dir / "diets.toml").write_text('A = "Apple"\n', encoding="utf-8")
    with pytest.raises(WiringError, match="two files .different"):
        codeset_edit.list_code_sets(tmp_path)


# --- rename ------------------------------------------------------------------


def test_rename_moves_file(tmp_path: Path) -> None:
    codeset_edit.upsert_code_set(
        tmp_path, "diets", ["code", "value"], [["A", "Apple"]], validate=_validate
    )
    result = codeset_edit.rename_code_set(tmp_path, "diets", "diet_map", validate=_validate)
    assert result == {"op": "rename", "name": "diets", "to": "diet_map"}
    cs_dir = _codesets(tmp_path)
    assert not (cs_dir / "diets.csv").exists()
    assert (cs_dir / "diet_map.csv").exists()


def test_rename_missing_source_raises(tmp_path: Path) -> None:
    _codesets(tmp_path).mkdir()
    with pytest.raises(WiringError, match="no such code set 'nope'"):
        codeset_edit.rename_code_set(tmp_path, "nope", "other", validate=_validate)


def test_rename_to_unsafe_name_raises(tmp_path: Path) -> None:
    codeset_edit.upsert_code_set(
        tmp_path, "diets", ["code", "value"], [["A", "Apple"]], validate=_validate
    )
    with pytest.raises(WiringError, match="must not contain a path separator"):
        codeset_edit.rename_code_set(tmp_path, "diets", "a/b", validate=_validate)


def test_rename_collision_raises(tmp_path: Path) -> None:
    codeset_edit.upsert_code_set(
        tmp_path, "diets", ["code", "value"], [["A", "Apple"]], validate=_validate
    )
    codeset_edit.upsert_code_set(
        tmp_path, "other", ["code", "value"], [["B", "Banana"]], validate=_validate
    )
    with pytest.raises(WiringError, match="two files .different"):
        codeset_edit.rename_code_set(tmp_path, "diets", "other", validate=_validate)


def test_rename_missing_args(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="--name is required"):
        codeset_edit.rename_code_set(tmp_path, "", "x", validate=_validate)
    with pytest.raises(WiringError, match="--to is required"):
        codeset_edit.rename_code_set(tmp_path, "x", "", validate=_validate)


# --- remove ------------------------------------------------------------------


def test_remove_deletes_file(tmp_path: Path) -> None:
    codeset_edit.upsert_code_set(
        tmp_path, "diets", ["code", "value"], [["A", "Apple"]], validate=_validate
    )
    result = codeset_edit.remove_code_set(tmp_path, "diets", validate=_validate)
    assert result == {"op": "remove", "name": "diets"}
    assert not (_codesets(tmp_path) / "diets.csv").exists()


def test_remove_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="no such code set 'nope'"):
        codeset_edit.remove_code_set(tmp_path, "nope", validate=_validate)


def test_remove_missing_name_raises(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="--name is required"):
        codeset_edit.remove_code_set(tmp_path, "", validate=_validate)


def test_remove_rejects_traversal_name_without_deleting_outside_dir(tmp_path: Path) -> None:
    # A traversal name on the delete path must be rejected BEFORE any filesystem touch, or `remove`
    # becomes an arbitrary unlink of any file on disk.
    secret = tmp_path / "secret.csv"
    secret.write_text("code,value\nX,leak\n", encoding="utf-8")
    _codesets(tmp_path).mkdir()
    with pytest.raises(WiringError, match="must not contain a path separator"):
        codeset_edit.remove_code_set(tmp_path, "../secret", validate=_validate)
    # The out-of-dir file still exists (was never unlinked).
    assert secret.exists()


# --- CLI ---------------------------------------------------------------------


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    rc = main(args)
    return rc, capsys.readouterr().out


def test_cli_upsert_then_list_then_show(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    detail = {
        "name": "diets",
        "format": "csv",
        "columns": ["code", "value"],
        "rows": [["A", "Apple"], ["B", "Banana"]],
    }
    rc, out = _run(
        ["codeset", "upsert", "--config", str(tmp_path), "--data", json.dumps(detail), "--json"],
        capsys,
    )
    assert rc == 0
    assert json.loads(out) == {"op": "upsert", "name": "diets", "format": "csv", "entries": 2}

    rc, out = _run(["codeset", "list", "--config", str(tmp_path), "--json"], capsys)
    assert rc == 0
    summaries = json.loads(out)
    assert summaries[0]["name"] == "diets" and summaries[0]["shape"] == "scalar"

    rc, out = _run(
        ["codeset", "show", "--config", str(tmp_path), "--name", "diets", "--json"], capsys
    )
    assert rc == 0
    assert json.loads(out)["rows"] == [["A", "Apple"], ["B", "Banana"]]


def test_cli_upsert_reads_stdin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import io

    detail = {"name": "diets", "columns": ["code", "value"], "rows": [["A", "Apple"]]}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(detail)))
    rc, out = _run(["codeset", "upsert", "--config", str(tmp_path), "--json"], capsys)
    assert rc == 0
    assert json.loads(out)["entries"] == 1


def test_cli_upsert_bad_json_emits_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, out = _run(
        ["codeset", "upsert", "--config", str(tmp_path), "--data", "{not json", "--json"], capsys
    )
    assert rc == 1
    assert json.loads(out)["error"].startswith("invalid code set JSON:")


def test_cli_upsert_non_csv_format_emits_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    detail = {"name": "diets", "format": "toml", "columns": ["a", "b"], "rows": []}
    rc, out = _run(
        ["codeset", "upsert", "--config", str(tmp_path), "--data", json.dumps(detail), "--json"],
        capsys,
    )
    assert rc == 1
    assert "only CSV code sets are editable here" in json.loads(out)["error"]


def test_cli_upsert_duplicate_key_emits_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    detail = {"name": "diets", "columns": ["code", "value"], "rows": [["A", "1"], ["A", "2"]]}
    rc, out = _run(
        ["codeset", "upsert", "--config", str(tmp_path), "--data", json.dumps(detail), "--json"],
        capsys,
    )
    assert rc == 1
    assert "duplicate key 'A'" in json.loads(out)["error"]


def test_cli_upsert_control_char_name_emits_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A control char in the name must surface as a JSON {"error": ...} for the IDE, not crash the CLI
    # with a bare ValueError (embedded NUL) and no stdout.
    detail = {"name": "die\x00ts", "columns": ["code", "value"], "rows": [["A", "B"]]}
    rc, out = _run(
        ["codeset", "upsert", "--config", str(tmp_path), "--data", json.dumps(detail), "--json"],
        capsys,
    )
    assert rc == 1
    assert "must not contain control characters" in json.loads(out)["error"]


def test_cli_post_write_reload_failure_emits_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post-write reload rejection (the loader's own ``CodeSetError``) must surface as a JSON
    ``{"error": ...}`` for the IDE, not crash the CLI with no stdout.

    The handler's validate callback calls ``load_code_set`` directly, which raises ``CodeSetError`` —
    a *sibling* of ``WiringError`` (both subclass ``ValueError``), not a subclass. Patch the loader to
    fail on reload (a divergence the writer's pre-write checks can't always pre-empt) and assert the
    handler catches it and the failed write rolled back (no file left behind)."""
    from messagefoundry.config.code_sets import CodeSetError

    def _reject(path: Path) -> object:
        raise CodeSetError("simulated post-write reload failure")

    monkeypatch.setattr("messagefoundry.config.code_sets.load_code_set", _reject)
    detail = {"name": "diets", "columns": ["code", "value"], "rows": [["A", "Apple"]]}
    rc, out = _run(
        ["codeset", "upsert", "--config", str(tmp_path), "--data", json.dumps(detail), "--json"],
        capsys,
    )
    assert rc == 1
    assert json.loads(out)["error"] == "simulated post-write reload failure"
    # The rollback unlinks the brand-new file that failed validation.
    assert not (tmp_path / "codesets" / "diets.csv").exists()


def test_cli_show_missing_name(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc, out = _run(["codeset", "show", "--config", str(tmp_path), "--json"], capsys)
    assert rc == 1
    assert json.loads(out)["error"] == "--name is required for `codeset show`"


def test_cli_show_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc, out = _run(
        ["codeset", "show", "--config", str(tmp_path), "--name", "nope", "--json"], capsys
    )
    assert rc == 1
    assert json.loads(out)["error"].startswith("no such code set 'nope'")


def test_cli_rename(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    detail = {"name": "diets", "columns": ["code", "value"], "rows": [["A", "Apple"]]}
    _run(
        ["codeset", "upsert", "--config", str(tmp_path), "--data", json.dumps(detail), "--json"],
        capsys,
    )
    rc, out = _run(
        [
            "codeset",
            "rename",
            "--config",
            str(tmp_path),
            "--name",
            "diets",
            "--to",
            "dmap",
            "--json",
        ],
        capsys,
    )
    assert rc == 0
    assert json.loads(out) == {"op": "rename", "name": "diets", "to": "dmap"}


def test_cli_rename_missing_to(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    detail = {"name": "diets", "columns": ["code", "value"], "rows": [["A", "Apple"]]}
    _run(
        ["codeset", "upsert", "--config", str(tmp_path), "--data", json.dumps(detail), "--json"],
        capsys,
    )
    rc, out = _run(
        ["codeset", "rename", "--config", str(tmp_path), "--name", "diets", "--json"], capsys
    )
    assert rc == 1
    assert json.loads(out)["error"] == "--to is required for `codeset rename`"


def test_cli_remove(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    detail = {"name": "diets", "columns": ["code", "value"], "rows": [["A", "Apple"]]}
    _run(
        ["codeset", "upsert", "--config", str(tmp_path), "--data", json.dumps(detail), "--json"],
        capsys,
    )
    rc, out = _run(
        ["codeset", "remove", "--config", str(tmp_path), "--name", "diets", "--json"], capsys
    )
    assert rc == 0
    assert json.loads(out) == {"op": "remove", "name": "diets"}


def test_cli_remove_missing_name(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc, out = _run(["codeset", "remove", "--config", str(tmp_path), "--json"], capsys)
    assert rc == 1
    assert json.loads(out)["error"] == "--name is required for `codeset remove`"


def test_cli_list_empty(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc, out = _run(["codeset", "list", "--config", str(tmp_path), "--json"], capsys)
    assert rc == 0
    assert json.loads(out) == []
