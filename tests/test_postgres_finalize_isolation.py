# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5674: every Postgres transaction that runs the finalizer pins READ COMMITTED.

``_maybe_finalize_message`` reads its message's queue rows after taking the finalize advisory lock,
and only under READ COMMITTED does that read see a sibling's commit. A transaction that names no
isolation takes the server, database or role default, so each one that calls the finalizer names
it. Read from the source, so it needs no server; the live suite's role-default test is the
behavioural half.
"""

from __future__ import annotations

import ast
from pathlib import Path

from messagefoundry.store import postgres

_SOURCE = Path(postgres.__file__)


def _finalizing_methods() -> dict[str, ast.AsyncFunctionDef | ast.FunctionDef]:
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    [cls] = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "PostgresStore"]
    found: dict[str, ast.AsyncFunctionDef | ast.FunctionDef] = {}
    for node in cls.body:
        if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        if node.name == "_maybe_finalize_message":
            continue
        for sub in ast.walk(node):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and sub.func.attr == "_maybe_finalize_message"
            ):
                found[node.name] = node
                break
    return found


def _names_read_committed(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg != "isolation":
            continue
        value = kw.value
        if isinstance(value, ast.Name) and value.id == "_FINALIZE_ISOLATION":
            return True
        return isinstance(value, ast.Constant) and value.value == "read_committed"
    return False


def test_the_pinned_level_is_read_committed() -> None:
    assert postgres._FINALIZE_ISOLATION == "read_committed"


def test_every_transaction_that_finalizes_requests_read_committed() -> None:
    methods = _finalizing_methods()
    # CONTROL: the census sees the finalizer's callers at all, so an empty walk cannot pass.
    assert {"mark_done", "mark_failed", "ingress_handoff", "cancel_queued"} <= set(methods)
    unpinned: list[str] = []
    for name, node in methods.items():
        opened = [
            sub
            for sub in ast.walk(node)
            if isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "transaction"
        ]
        assert opened, f"{name} finalizes without opening a transaction this census can see"
        unpinned += [f"{name}:{c.lineno}" for c in opened if not _names_read_committed(c)]
    assert not unpinned, unpinned
