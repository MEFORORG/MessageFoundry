# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``safe_exc`` swaps out a partner-chosen file name in its repr-escaped forms too (BACKLOG #5815).

An ``OSError`` renders its path with ``repr()``, so a name holding a control character, a
non-printable character or an apostrophe appears ESCAPED in ``str(exc)``. Replacing only the raw
basename matched nothing there, and the name reached a stored ``last_error``, a connection event or a
log line past the control built to hide it. Every name here is synthetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.redaction import safe_exc, safe_name

#: Each carries an identifier-shaped stem plus a character repr() escapes or quotes differently.
NAMES = [
    "MRN4455667\u200b_ADT.hl7",  # a non-printable: rendered \u200b
    "MRN4455667\t_ADT.hl7",  # a control: rendered \t
    "MRN4455667\x7f_ADT.hl7",  # DEL: rendered \x7f
    "O'Zqxdoe_MRN4455667.hl7",  # an apostrophe: rendered \' or kept, by the whole path's quote
    "O'Zqxdoe\u200b_MRN4455667.hl7",  # both
]


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("directory", ["C:/drops", "C:/drops/it's", "C:/dr\"ops/it's"])
def test_an_escaped_name_in_a_real_oserror_is_swapped_out(name: str, directory: str) -> None:
    """The exception is built the way the OS raises it, so its text is the interpreter's own."""
    path = f"{directory}/{name}"
    exc = FileNotFoundError(2, "No such file or directory", path)
    out = safe_exc(exc, file_name=name)
    assert "MRN4455667" not in out, out
    assert "Zqxdoe" not in out, out
    assert safe_name(name) in out
    assert out.startswith("FileNotFoundError:") and "No such file or directory" in out


def test_a_real_open_failure_on_an_escaped_name_is_swapped_out(tmp_path: Path) -> None:
    name = "MRN4455667\u200b_ADT.hl7"
    try:
        (tmp_path / "missing" / name).open()
    except OSError as exc:
        out = safe_exc(exc, file_name=name)
    else:  # pragma: no cover - the directory does not exist
        pytest.fail("open() succeeded")
    assert "MRN4455667" not in out and safe_name(name) in out


def test_a_plain_name_still_renders_as_before() -> None:
    """Control: a name repr() leaves alone takes the raw-name swap alone, exactly as before."""
    name = "MRN4455667_ADT.hl7"
    exc = FileNotFoundError(2, "No such file or directory", f"C:/drops/{name}")
    out = safe_exc(exc, file_name=name)
    assert (
        out
        == f"FileNotFoundError: [Errno 2] No such file or directory: 'C:/drops/{safe_name(name)}'"
    )
