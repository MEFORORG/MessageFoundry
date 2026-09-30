# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0076 E.9: templated arguments are counted in a bucket of their own (BACKLOG #237).

`scripts/quality/lens_coverage.py` measures the #1764 coverage figure over rows. E.9 requires the
new writable templated mode to be counted separately, "so this amendment cannot flatter the #1764
coverage figure without converting anything". These tests pin both halves: the argument bucket
counts what the lens reports, and the editable row figure does not move with it.

The corpus is built here rather than read from samples/config, because the samples carry no action
rows with a templated or dynamic argument (PR 1170 measured this), so a corpus-wide assertion over
them would pass over an empty set.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry import lens

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "quality" / "lens_coverage.py"

_MODULE = """from messagefoundry import Send, handler, set_field, copy_field


@handler("h")
def h(msg):
    set_field(msg, "PID-5.1", "SMITH")
    set_field(msg, "PID-5.2", f"MRN {msg['PID-3.1']}")
    set_field(msg, "PID-5.3", msg["PID-5.1"] + "x")
    copy_field(msg, "PID-5.1", "PID-5.4")
    return Send("OB", msg)
"""


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lens_coverage", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cov() -> ModuleType:
    return _load()


def _run(cov: ModuleType, config: Path, capsys: pytest.CaptureFixture[str], *extra: str) -> dict:
    assert (
        cov.main([str(config), "--json", "--cwd", str(_ROOT), "--python", sys.executable, *extra])
        == 0
    )
    out: dict = json.loads(capsys.readouterr().out)
    return out


@pytest.fixture
def config(tmp_path: Path) -> Path:
    (tmp_path / "h.py").write_text(_MODULE, encoding="utf-8")
    return tmp_path


def test_the_tally_reads_the_lens_modes_and_nothing_else(cov: ModuleType) -> None:
    rows = lens.parse_source(_MODULE, contract=2)[0]["rows"]
    total: Counter[str] = Counter()
    for row in rows:
        total.update(cov.tally_argument_modes(row))
    # Four action rows of two arguments each, counted from the lens's own param_modes, so this is the
    # lens's classification and not a second one.
    expected: Counter[str] = Counter()
    for row in rows:
        expected.update((row.get("param_modes") or {}).values())
    assert total == expected
    assert total == Counter({"static": 6, "templated": 1, "dynamic": 1})


def test_a_row_without_modes_counts_nothing(cov: ModuleType) -> None:
    assert cov.tally_argument_modes({"kind": "action", "params": {"a": "1"}}) == Counter()
    assert cov.tally_argument_modes({"kind": "code"}) == Counter()
    assert cov.tally_argument_modes({"kind": "action", "param_modes": "static"}) == Counter()


def test_contract_2_reports_the_bucket_and_the_editable_figure_does_not_move(
    cov: ModuleType, config: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    v2 = _run(cov, config, capsys, "--contract", "2")
    assert v2["argument_modes"] == {"static": 6, "templated": 1, "dynamic": 1}
    # The editable figure counts ROWS by kind: four action rows and one send. The templated argument
    # is not added to it, and the dynamic one does not take a row out of it.
    assert v2["editable_rows"] == 5
    assert v2["row_kinds"].get("action") == 4
    # The same estate at contract 1 has no bucket, and the same editable figure: the modes changed
    # nothing about which rows are editable.
    v1 = _run(cov, config, capsys)
    assert v1["argument_modes"] is None
    assert v1["contract"] == 1
    # This corpus has no comments or routers, so contract 2 adds no note/route rows and the row
    # figures agree. They need not in general, and the report says so.
    assert v1["comparable_with_contract_1"] is True
    assert v2["comparable_with_contract_1"] is False
    assert v1["editable_rows"] == v2["editable_rows"]
    assert v1["editable_pct"] == v2["editable_pct"]


def test_a_measured_estate_with_no_typed_arguments_reports_zeros(
    cov: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Measured and empty is a zero bucket, never the "not measured" None of contract 1.
    (tmp_path / "h.py").write_text(
        'from messagefoundry import Send, handler\n\n\n@handler("h")\ndef h(msg):\n'
        '    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    v2 = _run(cov, tmp_path, capsys, "--contract", "2")
    assert v2["argument_modes"] == {"static": 0, "templated": 0, "dynamic": 0}


def test_an_unknown_mode_is_reported_not_dropped(cov: ModuleType) -> None:
    report = cov._argument_mode_report(Counter({"templated": 2, "future": 1}))
    assert report == {"static": 0, "templated": 2, "dynamic": 0, "future": 1}


def test_the_text_report_names_the_bucket_as_separate(
    cov: ModuleType,
    config: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This test is about the printed report, not the parse, so the lens runs in-process here; the real
    # subprocess path is covered by the JSON test above.
    def in_process(py: Path, _python: str, _cwd: Path, contract: int = 1) -> tuple[dict, str]:
        source = py.read_text(encoding="utf-8")
        return {"handlers": lens.parse_source(source, contract=contract)}, ""

    monkeypatch.setattr(cov, "parse_module", in_process)
    assert cov.main([str(config), "--contract", "2"]) == 0
    text = capsys.readouterr().out
    assert "argument modes (a bucket of its own, never in the EDITABLE figure" in text
    assert "templated" in text
    assert cov.main([str(config)]) == 0
    assert "not measured at --contract 1" in capsys.readouterr().out
