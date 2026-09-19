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

WHAT STANDS IN ITS PLACE IS WEAKER THAN A TEST, AND THAT IS THE POINT OF SAYING SO.
``messagefoundry/integrity.py`` names ``security/semgrep/handler-security.yml`` in
``_ATTESTED_ASSETS`` (BACKLOG #1432), so an install missing the file, or carrying an edited copy,
records attestation drift at engine startup. Three limits travel with that: it is **alert-only by
default** (``[integrity].fail_closed_on_drift`` is opt-in), it runs on an INSTALLED engine rather
than in CI, and it is a no-op on an editable checkout. So a packaging regression here would red no
test and no CI leg -- it would surface as a startup log line on a site that had opted in. Calling it
a guarantee would overstate it.

``pyproject.toml`` grades the same mechanism the other way for the sibling common-password corpus,
saying an ``importlib.resources`` test IS the guard against a build-config change that dropped it.
Both cannot be right, and the disagreement is recorded here rather than settled here: hatchling does
package every file under ``messagefoundry/``, which makes resolution good evidence against the whole
directory going missing and no evidence at all against a narrower ``exclude``. Whether a built wheel
carries this file is BACKLOG #1701's question, and answering it here would mean building a wheel in
this suite -- slow, and network-dependent.
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


def test_rules_file_resolves_through_the_package() -> None:
    # BACKLOG #1716: what this assertion proves is that the rules file RESOLVES THROUGH THE PACKAGE
    # -- `handler_semgrep_rules()` finds it under `messagefoundry/security/`, so an import path that
    # has gone stale or a file that has been moved out from under it reds here. It is NOT evidence
    # about a built wheel; the module docstring carries that reasoning and what stands in its place.
    #
    # The NAME carries the claim, which is why it moved with the comment: a CI failure line, a
    # coverage row and `pytest -k` all surface the identifier and none of them surface this block, so
    # `test_rules_file_ships_in_the_package` would have gone on asserting the retracted reading to
    # every reader who never opened the file.
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
