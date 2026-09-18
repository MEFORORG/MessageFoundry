# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Semgrep handler-security rules resolve through the package and are well-formed (ADR 0144 Inc 3).

Semgrep is NOT a project dependency, so authoritative rule-syntax/behaviour validation is the
``security.yml`` semgrep job (``--validate``/``--test``). This is the dep-free local guard: the rules
file resolves at its packaged path, and its structure is well-formed. PyYAML is in
``requirements.lock`` so the deep parse runs where the full lock is installed; a bare env skips it
(``importorskip``) and keeps the substring smoke.

WHAT THIS FILE DOES NOT CHECK (BACKLOG #1716): whether a BUILT WHEEL carries the rules. Nothing here
builds one, and a source tree resolves the path regardless of what the packaging config would
include, so reading the resolution as a wheel guard would be a control resting on a false premise.
The shipped-install guarantee is ``messagefoundry/integrity.py``, whose ``_ATTESTED_ASSETS`` names
``security/semgrep/handler-security.yml`` (BACKLOG #1432).
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
    # BACKLOG #1716: what this assertion proves is that the rules file RESOLVES THROUGH THE PACKAGE
    # -- `handler_semgrep_rules()` finds it under `messagefoundry/security/`, so an import path that
    # has gone stale or a file that has been moved out from under it reds here. It is NOT evidence
    # about a built wheel: nothing in this suite builds one, and a source tree resolves the path
    # whether or not the packaging config would carry the file. The packaging guarantee is a
    # different control in a different place -- `messagefoundry/integrity.py` names
    # `security/semgrep/handler-security.yml` in `_ATTESTED_ASSETS`, so a shipped install that lacks
    # it, or carries an edited copy, fails startup attestation (BACKLOG #1432).
    assert handler_semgrep_rules().is_file()
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
