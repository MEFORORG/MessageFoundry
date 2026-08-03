"""Structural gate for ADR 0157's H1 epoch-fence scope on ``store/postgres.py``.

**Deliberately NOT env-gated.** Every other Postgres test needs ``MEFOR_TEST_POSTGRES`` and a live
server, so on a developer laptop they silently skip — 147 tests that prove nothing about a laptop run.
This file parses source, so it runs on *every* leg and is the only thing standing between "the fence
covers every write it must" and a silent regression.

**Why AST and not a source regex (ADR 0157 D3).** ``claim_fifo_heads`` splits its claim across two
adjacent string literals with an inline ``# STEP 5`` comment between them::

    " UPDATE queue q"       # STEP 5: claim exactly the kept prefixes
    " SET status=$6, attempts=attempts+1, ..."

A raw-slice regex for ``UPDATE queue (?:q )?SET status`` **cannot see** that site — the one site C5's
whole argument depends on. CPython folds implicit concatenation at parse time, so reconstructing from
the AST makes it visible.

**Why this file keys on the EMITTED SQL, not on a name reference.** The first version of this gate
asked "does this method mention ``_EPOCH_GUARD_CLAIM``?". Deleting ``{epoch_guard}`` from
``claim_fifo_heads``' SQL — the precise regression it exists to catch — left that mention intact
(``epoch_guard`` is still *computed*, just no longer *interpolated*), and the gate stayed green. So the
disposition below is derived from the reconstructed statement text: the guard must appear in the same
SQL expression as the write it gates. That mutation now fails, which is the only reason to trust it.
"""

from __future__ import annotations

import ast
import pathlib
import re

from messagefoundry.store.postgres import _EPOCH_GUARD_CLAIM, _EPOCH_GUARD_RESOLVE

_SOURCE = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "store" / "postgres.py"

#: The write this gate is about: any statement that moves a ``queue`` row's ``status``.
_STATUS_WRITE = re.compile(r"UPDATE queue (?:q )?SET status")

#: How a spliced guard shows up in a reconstructed SQL expression: ``{epoch_guard}`` for the f-string
#: claim sites, ``{guard}`` for the ``"..." + guard`` terminal-resolve sites.
_SPLICED = ("{epoch_guard}", "{guard}")


def _sql_text(node: ast.AST) -> str | None:
    """Reconstruct a string-valued expression, marking interpolated/concatenated parts as ``{expr}``.

    Returns ``None`` for anything that is not a string expression, which is what lets the caller pick
    *maximal* SQL expressions and skip their descendants — so one ``UPDATE`` is counted once.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        out: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                out.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                out.append("{" + ast.unparse(value.value) + "}")
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _sql_text(node.left), _sql_text(node.right)
        if left is None and right is None:
            return None
        return (left if left is not None else "{" + ast.unparse(node.left) + "}") + (
            right if right is not None else "{" + ast.unparse(node.right) + "}"
        )
    return None


def _sql_expressions(fn: ast.AST) -> list[str]:
    """Every maximal string expression in ``fn``, so each SQL statement is one entry."""
    found: list[str] = []

    def visit(node: ast.AST) -> None:
        text = _sql_text(node)
        if text is not None:
            found.append(text)
            return  # maximal: do not descend into the pieces of this same expression
        for child in ast.iter_child_nodes(node):
            visit(child)

    for child in ast.iter_child_nodes(fn):
        visit(child)
    return found


def _calls_self(fn: ast.AST, method: str) -> bool:
    """True if ``fn`` contains a ``self.<method>(...)`` call."""
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == method
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
        for node in ast.walk(fn)
    )


def _observed() -> dict[str, tuple[int, int]]:
    """``{method: (status_writes, of_which_carry_a_spliced_guard)}``."""
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    found: dict[str, tuple[int, int]] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        writes = [sql for sql in _sql_expressions(fn) if _STATUS_WRITE.search(sql)]
        if not writes:
            continue
        guarded = sum(1 for sql in writes if any(marker in sql for marker in _SPLICED))
        found[fn.name] = (len(writes), guarded)
    return found


#: THE PINNED CLASSIFICATION (ADR 0157 §2.2). ``{method: (status_writes, guarded_writes)}``.
#:
#: This map IS the test. Adding an ``UPDATE queue ... SET status`` anywhere in ``postgres.py`` without a
#: row here fails, which is the point: the failure mode this guards against is a *new* terminal write
#: added later that silently escapes the fence. Every method with an unguarded write must appear in
#: :data:`_UNGUARDED_REASONS` — an unexplained hole is indistinguishable from an oversight six months on.
_EXPECTED: dict[str, tuple[int, int]] = {
    # --- CLAIM paths: fail-CLOSED. A superseded ex-leader claims nothing. ---
    "claim_ready": (1, 1),
    # 3 writes = the guarded claim + the in-claim cross-owner reclaim + the H2 skip-and-complete.
    # Only the CLAIM carries the guard: the reclaim and the H2 completion are deliberately unguarded
    # (ADR 0157 §2.2 — the H2 row is non-None only because the guarded claim already matched).
    "claim_next_fifo": (3, 1),
    "claim_next_fifo_batch": (2, 1),
    # The split-literal site (D3): the one a source-slice regex cannot see.
    "claim_fifo_heads": (3, 1),
    # --- Writes that return a row to PENDING: deliberately UNGUARDED (C1). ---
    "release_claimed": (1, 0),
    "reschedule_claimed": (1, 0),
    "reset_stale_inflight": (1, 0),
    "reclaim_expired_leases": (1, 0),
    "recover_inflight_on_promotion": (1, 0),
    # --- TERMINAL resolves: fail-OPEN guarded, spliced via the _resolve_guard helper. ---
    "dead_letter_now": (1, 1),
    "mark_done": (1, 1),
    "mark_batch_done": (1, 1),
    "complete_with_response": (1, 1),
    # Both DEAD branches guarded; the success path deliberately is not (it ADMITS a message, and
    # fencing it would convert a permitted duplicate into a LOST re-ingress).
    "ingress_handoff": (2, 2),
    # ONE statement with a conditional suffix: the guard is "" on the retry branch, which re-pends.
    "mark_failed": (1, 1),
    "mark_batch_failed": (1, 1),
    "dead_letter_batch": (1, 1),
    # --- Bring-up sweeps + operator paths: unguarded, allowlisted. ---
    "dead_letter_missing_destinations": (1, 0),
    "dead_letter_missing_handlers": (1, 0),
    "replay": (1, 0),
    "replay_dead": (1, 0),
    "cancel_queued": (1, 0),
}

#: The methods whose TERMINAL resolves are fenced. Kept separate from :data:`_EXPECTED` because the
#: guard being *spliced* and the rowcount being *inspected* are two different facts, and a resolve that
#: has the first without the second is a guard that can never fire.
_RESOLVE_FENCED = frozenset(
    {
        "dead_letter_now",
        "mark_done",
        "mark_batch_done",
        "complete_with_response",
        "ingress_handoff",
        "mark_failed",
        "mark_batch_failed",
        "dead_letter_batch",
    }
)

#: Every unguarded status write needs a reason, in words, here. C1's invariant is that fencing a write
#: which returns a row to PENDING converts a *permitted duplicate* into a *forbidden strand*, so several
#: of these are unguarded on purpose and must never "grow" a guard.
_UNGUARDED_REASONS: dict[str, str] = {
    "release_claimed": (
        "C1: re-pends an INFLIGHT row. Fencing it would leave the row INFLIGHT instead — a strand. It is"
        " also the write _after_fenced_write itself uses to recover (D1), so guarding it would make the"
        " fence's own residue unrecoverable."
    ),
    "reschedule_claimed": (
        "C1: same as release_claimed, with a durable backoff deadline instead of an unchanged one."
    ),
    "reset_stale_inflight": "Startup/DR recovery. Runs before any epoch is armed.",
    "reclaim_expired_leases": (
        "Owner-BLIND periodic recovery, by its own docstring. Bounded to already-expired row leases."
    ),
    "recover_inflight_on_promotion": "Runs on the successor, at promotion, by definition un-fenced.",
    "dead_letter_missing_destinations": (
        "ADR 0157 D11: also writes over PENDING rows, where D1's re-pend fallback is meaningless. Runs"
        " only from _start_graph, and the successor re-runs the identical sweep. Flagged for the owner,"
        " not silently skipped."
    ),
    "dead_letter_missing_handlers": "ADR 0157 D11: the twin of dead_letter_missing_destinations.",
    "replay": "Operator action. Guarding it would leave an operator on a standby unable to act.",
    "replay_dead": (
        "Operator action, as replay: it revives a DEAD row to PENDING, which is re-pend direction, not a"
        " terminal resolve."
    ),
    "cancel_queued": "Operator action; binds PENDING rows only, never a claimed row.",
    # The three claim methods below each carry unguarded writes ALONGSIDE their guarded claim.
    "claim_next_fifo": (
        "Carries 2 unguarded writes beside its guarded claim: the in-claim cross-owner lease reclaim"
        " (re-pend direction, ADR 0157 Consequence 9) and the H2 skip-and-complete, which is reachable"
        " only because the guarded claim UPDATE already matched."
    ),
    "claim_next_fifo_batch": "The in-claim cross-owner lease reclaim, as claim_next_fifo.",
    "claim_fifo_heads": (
        "The in-claim cross-owner lease reclaim and the H2 skip-and-complete, as claim_next_fifo."
    ),
}


def test_every_queue_status_write_is_classified() -> None:
    """The pinned table equals reality — no site added, removed or re-scoped without this diff.

    Compared whole rather than key-by-key so a *new* unclassified write fails just as loudly as a
    changed one.
    """
    assert _observed() == _EXPECTED


def test_every_unguarded_status_write_carries_a_written_reason() -> None:
    """An unexplained hole in the fence is indistinguishable from an oversight later."""
    unguarded = {name for name, (writes, guarded) in _EXPECTED.items() if guarded < writes}
    assert unguarded == set(_UNGUARDED_REASONS)
    assert all(len(reason) > 40 for reason in _UNGUARDED_REASONS.values())


def test_every_fenced_terminal_resolve_actually_inspects_the_rowcount() -> None:
    """Splicing the guard is only half of it — an unchecked guard is a guard that cannot fire.

    ``_exec_terminal`` is the only place the rowcount is read, so a resolve that renders the suffix but
    calls ``conn.execute`` directly would look fenced in a diff and silently let every superseded write
    land. It must also CATCH its own sentinel, or ``_FencedWrite`` escapes the store as an exception
    instead of becoming a counted, re-pended no-op (ADR 0157 C3/D1). Pinned as a triple, not as three
    independent facts.
    """
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    seen: set[str] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if fn.name not in _RESOLVE_FENCED:
            continue
        seen.add(fn.name)
        assert _calls_self(fn, "_resolve_guard"), f"{fn.name} does not splice the resolve guard"
        assert _calls_self(fn, "_exec_terminal"), f"{fn.name} never inspects the rowcount"
        handlers = [
            handler
            for node in ast.walk(fn)
            if isinstance(node, ast.Try)
            for handler in node.handlers
            if isinstance(handler.type, ast.Name) and handler.type.id == "_FencedWrite"
        ]
        assert handlers, f"{fn.name} can raise _FencedWrite but never catches it"
    assert seen == set(_RESOLVE_FENCED)


def test_the_claim_guard_is_referenced_only_by_the_claim_paths() -> None:
    """C2's explicit ask: the two polarities are opposite, so using the wrong one is the hazard."""
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    referrers: dict[str, set[str]] = {"_EPOCH_GUARD_CLAIM": set(), "_EPOCH_GUARD_RESOLVE": set()}
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Name) and node.id in referrers:
                referrers[node.id].add(fn.name)
    assert referrers["_EPOCH_GUARD_CLAIM"] == {
        "claim_ready",
        "claim_next_fifo",
        "claim_next_fifo_batch",
        "claim_fifo_heads",
    }
    # The resolve guard is spliced through exactly one helper, so every terminal resolve inherits the
    # fail-open polarity from a single place and cannot drift site by site.
    assert referrers["_EPOCH_GUARD_RESOLVE"] == {"_resolve_guard"}
    assert referrers["_EPOCH_GUARD_CLAIM"] & referrers["_EPOCH_GUARD_RESOLVE"] == set()


def test_guard_polarity_is_pinned() -> None:
    """The inversion IS the design (ADR 0157 §2.1), and it reads like a copy-paste slip.

    CLAIM is fail-closed: a missing lease row yields NULL, ``NULL <= $h`` is false, the claim declines
    — free, because the row stays PENDING and any node may take it. RESOLVE is fail-open: COALESCE
    resolves a missing row to "current" so the write LANDS, because *rejecting* a resolve strands an
    INFLIGHT row. Pasting the claim guard onto a resolve site mass-strands every in-flight row the
    moment the lease row vanishes.
    """
    assert "COALESCE" in _EPOCH_GUARD_RESOLVE
    assert "COALESCE" not in _EPOCH_GUARD_CLAIM
    # Neither guard may carry a status conjunct: reclaim_expired_leases is owner-blind and can re-pend
    # the CURRENT leader's own long-running row, where a status conjunct would fire and the epoch cannot.
    assert "status" not in _EPOCH_GUARD_CLAIM
    assert "status" not in _EPOCH_GUARD_RESOLVE


def test_extracting_the_claim_guard_changed_no_emitted_sql() -> None:
    """The extraction to a shared constant must be a pure refactor.

    Pinned against the literal exactly as it stood before ADR 0157, at all three placeholder numberings
    the claim sites use. If this drifts, shipped claim paths changed behaviour under cover of a tidy-up.
    """
    assert (
        _EPOCH_GUARD_CLAIM.format(k=8, h=9)
        == " AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=$8) <= $9"
    )
    assert (
        _EPOCH_GUARD_CLAIM.format(k=9, h=10)
        == " AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=$9) <= $10"
    )
    assert (
        _EPOCH_GUARD_CLAIM.format(k=10, h=11)
        == " AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=$10) <= $11"
    )


def test_the_resolve_guard_binds_its_epoch_placeholder_twice() -> None:
    """COALESCE's fallback and the comparand must be the SAME placeholder.

    ``COALESCE(ll.leader_epoch, $h) <= $h`` is what makes a missing row fail *open*. Binding two
    different placeholders would type-check, run, and quietly compare an epoch against the lease key.
    """
    rendered = _EPOCH_GUARD_RESOLVE.format(k=4, h=5)
    assert rendered.count("$5") == 2
    assert rendered.count("$4") == 1
    assert rendered.endswith("$5")


def test_the_split_literal_claim_site_is_still_split() -> None:
    """Guards D3's premise, not just its conclusion.

    ``claim_fifo_heads``' claim is written as two adjacent literals with a comment between. If a later
    tidy-up joins them, the AST route above still works — but the *reason* this file exists stops being
    demonstrable, and a reviewer would rightly ask why it is not a two-line regex. Fail loudly instead,
    so the choice is re-made deliberately.
    """
    source = _SOURCE.read_text(encoding="utf-8")
    assert re.search(r'" UPDATE queue q"\s*#[^\n]*\n\s*" SET status=\$6', source) is not None
