# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``audit-verify --expected-row`` / ``--expected-rows-file`` (vault BACKLOG #2612, closing step 3).

The off-box tee forwards ``seq`` and ``row_hash`` for every audit row, so the collector holds a
witness per row. These pin that a set of those pairs is checked against the store, that a pair the
chain no longer carries is a broken chain (exit 1), that a malformed pair is "could not start"
(exit 2), and that K pairs cost ONE walk of the chain, not K: under ``vault_transit`` each row MAC is
a Transit round trip, so a walk per pair would multiply them.
"""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.store.store as store_mod
from messagefoundry.__main__ import main
from messagefoundry.store import MessageStore
from tests._phi_gate_provisions import setenv_at_rest_opt_out


@pytest.fixture(autouse=True)
def _keyless_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    # The seeded stores are keyless, so they are verified as a keyless engine would, under the audited
    # opt-out (as `keyless_verify` in tests/test_audit_integrity.py does, and for the same reason).
    setenv_at_rest_opt_out(monkeypatch)


def _seed(db: Path, n: int) -> list[tuple[int, str]]:
    """Write ``n`` audit rows and return every row's ``(seq, row_hash)``, as the tee forwards them."""

    async def run() -> None:
        s = await MessageStore.open(db)
        for i in range(n):
            await s.record_audit(f"act{i}", actor="x")
        await s.close()

    asyncio.run(run())
    with contextlib.closing(sqlite3.connect(db)) as conn:
        return [
            (int(r[0]), str(r[1]))
            for r in conn.execute("SELECT seq, row_hash FROM audit_log ORDER BY seq")
        ]


def _args(db: Path, pairs: Sequence[tuple[int, str]]) -> list[str]:
    argv = ["audit-verify", "--db", str(db)]
    for seq, head in pairs:
        argv += ["--expected-row", f"{seq}:{head}"]
    return argv


def test_a_set_of_witnessed_rows_verifies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "a.db"
    pairs = _seed(db, 5)
    assert main(_args(db, [pairs[0], pairs[2], pairs[4]])) == 0
    assert capsys.readouterr().out.startswith("OK: ")


def test_pairs_stay_valid_as_the_chain_grows(tmp_path: Path) -> None:
    # Unlike the exact anchor: a pair witnessed earlier still matches after more rows are appended.
    db = tmp_path / "grow.db"
    early = _seed(db, 2)
    _seed(db, 3)
    assert main(_args(db, early)) == 0


def test_a_pair_with_a_wrong_hash_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "b.db"
    pairs = _seed(db, 4)
    wrong = (pairs[1][0], pairs[2][1])  # a real hash, at the wrong seq
    assert main(_args(db, [pairs[0], wrong, pairs[3]])) == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL: ") and "1 of 3 distinct expected audit row(s)" in out, out


def test_a_pair_beyond_the_head_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The truncation case: the collector witnessed row 6, the store now ends at row 4.
    db = tmp_path / "c.db"
    pairs = _seed(db, 6)
    with contextlib.closing(sqlite3.connect(db)) as conn:
        conn.execute("DELETE FROM audit_log WHERE seq > 4")
        conn.commit()
    assert main(["audit-verify", "--db", str(db)]) == 0  # the bare walk cannot see it
    capsys.readouterr()
    assert main(_args(db, [pairs[5]])) == 1
    out = capsys.readouterr().out
    assert "FAIL: " in out and "is past the chain's end" in out, out


@pytest.mark.parametrize(
    "value",
    ["garbage", "3", "x:" + "a" * 64, "3:" + "a" * 12, "0:", "0:" + "a" * 64, "-1:" + "a" * 64],
)
def test_a_malformed_pair_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    db = tmp_path / "d.db"
    _seed(db, 2)
    assert main(["audit-verify", "--db", str(db), "--expected-row", value]) == 2
    err = capsys.readouterr().err
    assert "malformed audit row pair" in err and "SEQ:ROW_HASH" in err, err


def test_the_rows_file_round_trips_and_refuses_a_bad_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "e.db"
    pairs = _seed(db, 3)
    good = tmp_path / "rows.txt"
    # A BOM and a blank line, as PowerShell 5.1's `Set-Content -Encoding utf8` and an export leave.
    good.write_text("\ufeff" + "\n".join(f"{s}:{h}" for s, h in pairs) + "\n\n", encoding="utf-8")
    assert main(["audit-verify", "--db", str(db), "--expected-rows-file", str(good)]) == 0
    capsys.readouterr()

    bad = tmp_path / "bad.txt"
    bad.write_text(f"{pairs[0][0]}:{pairs[0][1]}\nSECRETMARKER\n", encoding="utf-8")
    assert main(["audit-verify", "--db", str(db), "--expected-rows-file", str(bad)]) == 2
    err = capsys.readouterr().err
    # The line number and the reason, never the line: the path may point at another file.
    assert "line 2" in err and "SECRETMARKER" not in err, err

    # A numeric line too: the reason quotes no number from it (round-one review finding).
    numeric = tmp_path / "numeric.txt"
    numeric.write_text("987654321:\n-55555:" + "a" * 64 + "\n", encoding="utf-8")
    assert main(["audit-verify", "--db", str(db), "--expected-rows-file", str(numeric)]) == 2
    err = capsys.readouterr().err
    assert "line 1" in err and "987654321" not in err, err


@pytest.mark.parametrize("content", [b"", b"\n\n", "1:abc".encode("utf-16")])
def test_an_empty_or_unreadable_rows_file_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: bytes
) -> None:
    # An empty export must not read as "nothing to compare": that would be a pass checking nothing.
    db = tmp_path / "f.db"
    _seed(db, 2)
    path = tmp_path / "rows.txt"
    path.write_bytes(content)
    assert main(["audit-verify", "--db", str(db), "--expected-rows-file", str(path)]) == 2
    assert "--expected-rows-file" in capsys.readouterr().err


def test_k_pairs_cost_one_walk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the single walk. Each per-row MAC is what a Transit round trip costs under
    ``vault_transit``, so it is counted directly, along with the walks and the row reads."""
    db = tmp_path / "g.db"
    pairs = _seed(db, 6)
    walks: list[int] = []
    macs: list[int] = []
    reads: list[int] = []
    real_walk = store_mod.verify_audit_rows
    real_mac = store_mod._audit_row_mac
    real_rows = MessageStore._audit_rows

    def counting_walk(rows: Sequence[Mapping[str, Any]], **kw: Any) -> store_mod.AuditVerdict:
        walks.append(len(rows))
        return real_walk(rows, **kw)

    def counting_mac(*a: Any, **kw: Any) -> str | None:
        macs.append(1)
        return real_mac(*a, **kw)

    async def counting_rows(self: MessageStore, **kw: Any) -> list[Mapping[str, Any]]:
        reads.append(1)
        return await real_rows(self, **kw)

    monkeypatch.setattr(store_mod, "verify_audit_rows", counting_walk)
    monkeypatch.setattr(store_mod, "_audit_row_mac", counting_mac)

    def measure(selected: Sequence[tuple[int, str]]) -> int:
        walks.clear()
        macs.clear()
        assert main(_args(db, selected)) == 0
        assert walks == [6], walks  # one walk over the six rows, however many pairs
        return len(macs)

    baseline = measure(pairs[:1])
    monkeypatch.setattr(MessageStore, "_audit_rows", counting_rows)
    assert measure(pairs) == baseline  # six pairs cost exactly what one does
    assert reads == [1], reads
    # Positive control: the instrument does count per row, so equal counts are not two zeros.
    assert baseline >= 6, baseline


# --- the shared walk, below the CLI -------------------------------------------------------------


async def _rows(db: Path) -> list[Mapping[str, Any]]:
    s = await MessageStore.open(db)
    try:
        return await s._audit_rows()
    finally:
        await s.close()


def _walk(db: Path, **kw: Any) -> store_mod.AuditVerdict:
    return store_mod.verify_audit_rows(
        asyncio.run(_rows(db)), mac_keys={}, mac_fn=None, capable=False, **kw
    )


def test_the_prefix_alone_keeps_its_own_message(tmp_path: Path) -> None:
    # The engine routes a prefix failure on its marker (BACKLOG #328); merging the prefix into the
    # witness set must not change the message it reads.
    db = tmp_path / "h.db"
    pairs = _seed(db, 3)
    ok, msg = _walk(db, expected_prefix=(5, pairs[0][1]))
    assert not ok and msg is not None and store_mod.AUDIT_PREFIX_BREAK_MARKER in msg
    assert "expected audit row" not in msg, msg


def test_an_anchor_failure_does_not_hide_a_row_failure(tmp_path: Path) -> None:
    db = tmp_path / "i.db"
    pairs = _seed(db, 3)
    stale_anchor = (2, pairs[1][1])
    ok, msg = _walk(db, expected_anchor=stale_anchor, expected_rows=[(1, pairs[2][1])])
    assert not ok and msg is not None
    assert "diverges from recorded anchor" in msg and "1 of 1 distinct expected" in msg, msg


def test_a_pair_may_be_a_list_and_below_1_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "j.db"
    pairs = _seed(db, 2)
    as_lists: Any = [list(p) for p in pairs]  # as a decoded JSON tee record would give them
    assert _walk(db, expected_rows=as_lists)[0]
    with pytest.raises(ValueError, match="below 1"):
        _walk(db, expected_rows=[(0, pairs[0][1])])


def test_parse_audit_row_pair_shares_the_anchor_head_rule() -> None:
    head = "A" * 64
    assert store_mod.parse_audit_row_pair(f" 7:{head} ") == (7, head.lower())
    assert store_mod.parse_audit_row_pair("7:vault:v1:abc") == (7, "vault:v1:abc")
    for bad in ("7:", "0:" + head, "7:" + "a" * 12, "7:zz", "seven:" + head):
        with pytest.raises(store_mod.AuditRowPairError) as exc:
            store_mod.parse_audit_row_pair(bad)
        assert bad.strip() not in exc.value.reason, exc.value.reason


def test_one_seq_with_two_hashes_is_refused_not_reported_as_tampering(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "k.db"
    pairs = _seed(db, 2)
    assert main(_args(db, [pairs[0], (pairs[0][0], pairs[1][1])])) == 2
    assert "two different row_hash values" in capsys.readouterr().err


@pytest.mark.parametrize("seq", ["1_0", "+3", "３", "9" * 20, "9223372036854775808"])
def test_a_seq_no_store_can_emit_is_malformed(seq: str) -> None:
    with pytest.raises(store_mod.AuditRowPairError):
        store_mod.parse_audit_row_pair(f"{seq}:" + "a" * 64)


def test_space_either_side_of_the_colon_reads_alike() -> None:
    """Review finding: space after the ':' was stripped and space before it was refused."""
    head = "a" * 64
    assert store_mod.parse_audit_row_pair(f"7 :{head}") == store_mod.parse_audit_row_pair(
        f"7: {head}"
    )


def test_a_refusal_names_the_line_a_text_editor_shows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``str.splitlines`` also breaks on form feed, NEL and U+2028, so a stray one in an earlier
    line moved the line number a refusal names. Only CRLF, CR and LF end a line now, as in an
    editor. The stray characters trail a valid pair, which reads as valid since the hash is
    stripped, and the refused line comes after it."""
    db = tmp_path / "l.db"
    pairs = _seed(db, 2)
    rows = tmp_path / "rows.txt"
    good = [f"{s}:{h}" for s, h in pairs]
    rows.write_bytes(
        (good[0] + "\r\n" + good[1] + "\x0c\x85\u2028" + "\r" + "BADLINE\n").encode("utf-8")
    )
    assert main(["audit-verify", "--db", str(db), "--expected-rows-file", str(rows)]) == 2
    err = capsys.readouterr().err
    assert "line 3" in err, err
    lines = store_mod.read_bounded_utf8_lines(rows, 1 << 20, too_large="x")
    assert lines == [good[0], good[1] + "\x0c\x85\u2028", "BADLINE"]


def test_a_bare_cr_still_ends_the_first_anchor_line(tmp_path: Path) -> None:
    """An anchor file mispointed at an HL7 message, whose segments end in a bare CR, yields the
    first segment alone, so the line a refusal names is the first line an editor shows."""
    path = tmp_path / "msg.hl7"
    path.write_bytes(b"MSH|A|B\rPID|1||SYNTHETIC^PERSON\r")
    assert store_mod.read_audit_anchor_file(path) == "MSH|A|B"


def test_an_anchor_file_refusal_names_the_line_and_quotes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Pointed at an MLLP capture, whose first line starts with the 0x0B frame byte, the refusal
    must name the line and a reason, never the segment (vault BACKLOG #2612). ``str.splitlines``
    split on that byte and so quoted an empty line; the universal-newline reader keeps the segment
    on line 1, so the refusal must not quote line 1 either."""
    db = tmp_path / "m.db"
    _seed(db, 1)
    anchor = tmp_path / "capture.mllp"
    anchor.write_bytes(b"\x0bMSH|^~\\&|SYNTHAPP|SYNTHFAC\rPID|1||SYNTHETIC^PERSON\r\x1c\r")
    rc = main(["audit-verify", "--db", str(db), "--expected-anchor-file", str(anchor)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--expected-anchor-file line 1" in err and "no ':' separator" in err, err
    assert "MSH" not in err and "SYNTH" not in err and "\\x0b" not in err, err


def test_a_typed_anchor_refusal_still_quotes_the_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The control for the test above: the operator typed this one, so seeing it is how they fix it.
    db = tmp_path / "n.db"
    _seed(db, 1)
    assert main(["audit-verify", "--db", str(db), "--expected-anchor", "TYPED-VALUE"]) == 2
    assert "TYPED-VALUE" in capsys.readouterr().err


def test_a_contradictory_pair_refusal_names_lines_not_the_seq(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The seq is the file's content, so the refusal names the two lines and never the seq."""
    db = tmp_path / "o.db"
    _seed(db, 1)
    rows = tmp_path / "rows.txt"
    rows.write_text(f"987654:{'a' * 64}\n\n987654:{'b' * 64}\n", encoding="utf-8")
    rc = main(["audit-verify", "--db", str(db), "--expected-rows-file", str(rows)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "two different row_hash values" in err, err
    assert "--expected-rows-file line 1 and --expected-rows-file line 3" in err, err
    assert "987654" not in err, err


def test_a_contradictory_pair_across_flags_names_both_places(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "p.db"
    _seed(db, 1)
    rows = tmp_path / "rows.txt"
    rows.write_text(f"5:{'b' * 64}\n", encoding="utf-8")
    argv = ["audit-verify", "--db", str(db), "--expected-row", f"5:{'a' * 64}"]
    assert main([*argv, "--expected-rows-file", str(rows)]) == 2
    assert "--expected-row 1 and --expected-rows-file line 1" in capsys.readouterr().err
