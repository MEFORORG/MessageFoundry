# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The shipped VS Code snippet bodies must be code the engine actually accepts.

A snippet is generated source: the user tabs through it and the result runs in a Handler. Nothing
before this module checked a BODY -- ``ide/src/test/suite/insert-element.test.ts`` only JSON-parses
the file and asserts that named prefixes and descriptions exist, so a body could drift to an API the
engine had removed and every gate stayed green. That is exactly what happened to the FHIR-lookup
snippet: it kept teaching the flat ``"Patient?identifier=..."`` search after BACKLOG #1243 deleted
that path, so expanding it produced a Handler that raised on its first run.

So these tests check the body against the ENGINE, not against itself: expand the tabstops, parse the
result as Python, and put every ``fhir_lookup`` query through the engine's own URL resolver.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.fhirsearch import resolve_search_pairs
from messagefoundry.transports.fhir import _resolve_read_url

_SNIPPETS = (
    Path(__file__).resolve().parents[1] / "ide" / "snippets" / "messagefoundry.code-snippets"
)

# VS Code tabstops: ${N:default}, ${N} and $N. Expanding ${N:default} to its DEFAULT is what makes the
# body checkable -- the default is the text the extension actually inserts, so it is the text the
# engine would receive from a user who tabbed straight through.
_TABSTOP = re.compile(r"\$\{(\d+):([^{}]*)\}|\$\{\d+\}|\$\d+")

_FHIR_BASE = "https://fhir.example.org/fhir"


def _load() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(_SNIPPETS.read_text(encoding="utf-8"))
    return data


def _expand(text: str) -> str:
    return _TABSTOP.sub(lambda m: m.group(2) if m.group(2) is not None else "_x", text)


def _body_source(snippet: Any) -> str:
    body = snippet["body"]
    return _expand("\n".join(body) if isinstance(body, list) else str(body))


def _fhir_lookup_calls(tree: ast.AST) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "fhir_lookup"
    ]


def test_snippets_file_is_strict_json_and_non_empty() -> None:
    # The extension contributes snippets by JSON.parse; a malformed file loses ALL of them silently
    # (the extension still activates). No JSONC -- comments would break it.
    snippets = _load()
    assert len(snippets) >= 30, f"suspiciously few snippets parsed: {len(snippets)}"
    assert "MEFOR FHIR lookup" in snippets


def test_every_snippet_body_parses_as_python() -> None:
    failures: list[str] = []
    for name, snippet in _load().items():
        try:
            ast.parse(_body_source(snippet))
        except SyntaxError as exc:  # pragma: no cover - only on a regression
            failures.append(f"{name}: {exc.msg}")
    assert not failures, f"snippet bodies do not parse as Python: {failures}"


def test_no_snippet_teaches_the_removed_fhir_flat_query() -> None:
    """Every ``fhir_lookup`` query a snippet generates must be one the engine accepts (#1243).

    The check is the engine's own ``_resolve_read_url``, not a ``?`` substring match, so it also
    catches a bad resource-type/id grammar and stays correct if the accepted shapes change again.
    """
    checked = 0
    for name, snippet in _load().items():
        for call in _fhir_lookup_calls(ast.parse(_body_source(snippet))):
            checked += 1
            assert len(call.args) >= 2, f"{name}: fhir_lookup needs at least (connection, query)"
            query_node = call.args[1]
            # A concatenated / f-string query is the injection shape #1243 removed (and what
            # `messagefoundry check` flags as unsafe-db-lookup): the attacker-influenced value would
            # ride the URL unencoded. Search fields belong in params=, where the engine encodes them.
            assert isinstance(query_node, ast.Constant) and isinstance(query_node.value, str), (
                f"{name}: the fhir_lookup query must be a plain string literal, not "
                f"{type(query_node).__name__} -- put search fields in the params= mapping"
            )
            try:
                _resolve_read_url(_FHIR_BASE, query_node.value)
            except ValueError as exc:
                pytest.fail(f"{name}: the engine refuses the generated query: {exc}")
    # Positive control: a snippet renamed or deleted must not turn this into a vacuous pass.
    assert checked >= 1, (
        "no fhir_lookup call found in any snippet body -- the check scanned nothing"
    )


def test_fhir_lookup_snippet_expands_to_the_structured_search_form() -> None:
    # The concrete replacement, pinned: path in `query`, fields in `params`.
    source = _body_source(_load()["MEFOR FHIR lookup"])
    assert 'fhir_lookup("connection", "Patient", {"identifier":' in source
    call = _fhir_lookup_calls(ast.parse(source))[0]
    assert len(call.args) == 3, "the search form passes structured params as the third argument"
    assert isinstance(call.args[2], ast.Dict)


def test_no_snippet_teaches_a_refused_fhir_search_value() -> None:
    """The params VALUE is checked against the engine too, not only the query (#1243 limb B).

    This file exists because the FHIR snippet once drifted to an API the engine had removed, and its
    method is to check the body against the ENGINE rather than against itself. Until limb B the only
    argument that could drift was the query, so only ``args[1]`` was checked. The taught idiom now
    lives in ``args[2]``: a plain ``str`` value carrying ``,`` ``|`` or ``$`` is refused at run time,
    and re-teaching ``{"identifier": "MRN|" + ...}`` would otherwise pass every gate in this file."""
    inspected = 0
    for name, snippet in _load().items():
        for call in _fhir_lookup_calls(ast.parse(_body_source(snippet))):
            if len(call.args) < 3 or not isinstance(call.args[2], ast.Dict):
                continue
            for key, value in zip(call.args[2].keys, call.args[2].values, strict=True):
                inspected += 1
                assert isinstance(key, ast.Constant), f"{name}: a params key must be a literal"
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    # A literal value is data by kind, so ask the engine's own resolver.
                    try:
                        resolve_search_pairs({str(key.value): value.value})
                    except ValueError as exc:
                        pytest.fail(f"{name}: the engine refuses the generated value: {exc}")
                    continue
                if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
                    assert value.func.id in {"FhirToken", "FhirRaw"}, (
                        f"{name}: a params value built by a call must be an explicit search-value "
                        f"kind, not {value.func.id}(...)"
                    )
                    continue
                # A concatenation or f-string is the ONE-STRING-TWO-PROVENANCES idiom #1243 abolished:
                # an author literal welded to message data, which no encoder can tell apart.
                assert not isinstance(value, ast.JoinedStr | ast.BinOp), (
                    f"{name}: a params value must not be concatenated or interpolated -- that welds "
                    f"author syntax to message data. Say which half is which with FhirToken(...)"
                )
    # Positive control: this must not become vacuous if the snippet stops passing structured params.
    assert inspected >= 1, "no fhir_lookup params value found -- the check scanned nothing"
