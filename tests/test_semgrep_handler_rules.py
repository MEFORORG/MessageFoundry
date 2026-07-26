# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The packaged Semgrep handler-security rules ship in the wheel and are well-formed (ADR 0144 Inc 3).

Semgrep is NOT a project dependency, so authoritative rule-syntax/behaviour validation is the
``security.yml`` semgrep job (``--validate``/``--test``). This is the dep-free local guard: presence at
the packaged path (the wheel guard, mirroring the common-password corpus) + structural well-formedness.
PyYAML is in ``requirements.lock`` so the deep parse runs where the full lock is installed; a bare env
skips it (``importorskip``) and keeps the substring smoke.
"""

from __future__ import annotations

import pytest

from messagefoundry.security import handler_semgrep_rules

_EXPECTED = {
    "mf-handler-phi-to-log",
    "mf-handler-sqli-db-lookup",
    "mf-handler-phi-to-file",
    "mf-handler-ambient-subprocess",
    "mf-handler-ambient-os-exec",
    "mf-handler-ambient-eval-exec",
    "mf-handler-ambient-deserialization",
}
_TAINT = {"mf-handler-phi-to-log", "mf-handler-sqli-db-lookup", "mf-handler-phi-to-file"}


def test_rules_file_ships_in_the_package() -> None:
    assert (
        handler_semgrep_rules().is_file()
    )  # importlib.resources resolves it => packaged in the wheel
    text = handler_semgrep_rules().read_text(encoding="utf-8")
    assert "rules:" in text and "mode: taint" in text
    for rid in _EXPECTED:
        assert rid in text  # stdlib-only substring smoke (no yaml needed)


def test_rules_are_wellformed_yaml() -> None:
    yaml = pytest.importorskip("yaml")  # in requirements.lock; NO new dep
    doc = yaml.safe_load(handler_semgrep_rules().read_text(encoding="utf-8"))
    rules = {r["id"]: r for r in doc["rules"]}
    assert set(rules) >= _EXPECTED
    for r in doc["rules"]:
        assert r["languages"] == ["python"] and r["message"].strip()
        assert r["severity"] in {"WARNING", "ERROR", "INFO"}
    for tid in _TAINT:
        assert rules[tid]["mode"] == "taint"
        assert rules[tid]["pattern-sources"] and rules[tid]["pattern-sinks"]
