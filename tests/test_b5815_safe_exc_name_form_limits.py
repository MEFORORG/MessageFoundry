# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``safe_exc``'s file-name swap covers the limits engine PR 3070's review named (BACKLOG #5815).

Finding 3 of that review: a POSIX or SFTP name holding a backslash kept its head, a cp1252 bytes
path was not replaced, a JSON escape written with uppercase hex was kept, and sequential replacement
could match across a label it had just written. Every name here is synthetic.
"""

from __future__ import annotations

import pytest

from messagefoundry.redaction import safe_exc, safe_name

BS = "\\"


def test_a_posix_name_holding_a_backslash_is_swapped_out_whole() -> None:
    """A backslash is an ordinary character in a POSIX or SFTP name, so the name's head is the
    partner's too, and stays out of the message."""
    name = f"Zqxdoe{BS}MRN4455667.hl7"
    out = safe_exc(OSError(2, "No such file or directory", f"/drops/{name}"), file_name=name)
    assert "Zqxdoe" not in out and "MRN4455667" not in out, out
    assert safe_name(name) in out


def test_a_posix_name_ending_in_a_backslash_is_swapped_out() -> None:
    """Its last backslash-separated component is empty, so the whole name is what is swapped."""
    name = f"Zqxdoe{BS}MRN4455667{BS}"
    out = safe_exc(OSError(2, "No such file or directory", f"/drops/{name}"), file_name=name)
    assert "Zqxdoe" not in out and "MRN4455667" not in out, out


def test_a_cp1252_bytes_path_is_swapped_out() -> None:
    """A bytes path from a tool writing the Windows ANSI code page renders a character as that
    page's byte, which no UTF-8 form holds."""
    name = "MRN4455667_Zqxdo\u2019s.hl7"
    exc = OSError(2, "No such file or directory", f"/drops/{name}".encode("cp1252"))
    out = safe_exc(exc, file_name=name)
    assert "MRN4455667" not in out and "Zqxdo" not in out, out


@pytest.mark.parametrize(
    "escaped",
    [
        f"MRN4455667_Zqxdo{BS}u00E9.hl7",  # a JSON encoder writing uppercase hex
        f"MRN4455667{BS}u200B_ADT.hl7",
        f"MRN4455667{BS}x7F_ADT.hl7",
    ],
)
def test_an_uppercase_hex_escape_is_swapped_out(escaped: str) -> None:
    name = escaped.replace(f"{BS}u00E9", "\u00e9").replace(f"{BS}u200B", "\u200b")
    name = name.replace(f"{BS}x7F", "\x7f")
    out = safe_exc(RuntimeError(f'drop refused: "C:/drops/{escaped}"'), file_name=name)
    assert "MRN4455667" not in out, out
    assert safe_name(name) in out


def test_a_swap_never_matches_across_a_label_it_wrote() -> None:
    """The forms are swapped in one pass, so a shorter form cannot match the end of a label a longer
    one left plus the text after it."""
    name = "]Zqx\t"
    label = safe_name(name)
    assert label.endswith("]")
    # The repr form of the name, then the rest of the name as written after it.
    out = safe_exc(RuntimeError(f"drop refused: ]Zqx{BS}tZqx\t"), file_name=name)
    assert out.count("[name:") == 1, out
    assert label in out


def test_a_longer_form_wins_over_a_shorter_one_that_starts_earlier() -> None:
    """Where two forms overlap, the longer is swapped, as one replacement per form in length order
    did: a shorter form starting earlier does not leave the longer one's escaped tail in view. The
    shorter one's other characters stay, which ``_swap_forms`` states."""
    name = "x\x01x"
    out = safe_exc(RuntimeError(f"bad: x\x01x{BS}x01x"), file_name=name)
    assert f"{BS}x01x" not in out, out
