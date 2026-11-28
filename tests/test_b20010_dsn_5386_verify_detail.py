# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5386's remainder (batch 20010) in a verify detail: ``verify_leaf.safe_detail_text`` and
the entry points that call it, which read the DSN passes as they were before that batch.

Synthetic values only. ``safe_detail_text`` hides a word holding a copy of a fragment a pass hid.
Where one of the batch's three DSN readings, the JDBC member-tail pass and the widened pass's
``more_at`` and ``host_lead`` readings, hid or masked the last such copy, the word printed where
``origin/main`` printed one placeholder: the member-tail pass at ``4384e10afcb`` (the Lander's
hold on engine PR 3397), and the two widened readings once a first draft of the repair left that
pass alone out (code review). Each of the ``_DETAIL_SHAPES`` fails on ``4384e10afcb`` at least on
its exact output. In its own file because ``tests/test_b20010_dsn_5386_remainder.py`` is meant to
collect on commits that hold no ``verify_leaf``.
"""

from __future__ import annotations

import pytest

from messagefoundry.secretscrub import scrub_credentials, scrub_credentials_without_tails
from messagefoundry.verify_leaf import safe_detail_text, safe_exc_detail, safe_exc_text

#: Each line, the output ``origin/main`` gives for it, and a word of the password that must not
#: print. At ``4384e10afcb`` the first printed ``...@Passw0rd:0000;`` and the second
#: ``...@Passw0rd:xxx;``. The last two printed ``...@xx_xxx0;x;postgres://ops@srv:@[redacted]@h``
#: and ``...@xxx0;x;postgres://a@b@srv:[redacted]@h`` there, the scheme and host ``origin/main``
#: hid, and ``...@ss_Sec9;...`` and ``...@Sec5;...`` in the first draft that left the member-tail
#: pass alone out; their word checks guard that draft's reading.
_DETAIL_SHAPES = (
    ("jdbc:sqlserver://db:1433;sslpassword=P@Passw0rd:1433;", "[redacted]", "Passw0rd"),
    (
        "password=abc jdbc:sqlserver://db:1433;sslpassword=P@Passw0rd:abc;",
        "password=[redacted] [redacted]",
        "Passw0rd",
    ),
    (
        "jdbc:sqlserver://h:2024;sslpassword=P@Passw0rd=2024; x 2024",
        "[redacted] x [redacted]",
        "Passw0rd",
    ),
    (
        "login 2024 then jdbc:postgresql://srv.invalid:2024;Pwd2=P@Tokenish=2024; x port 2024",
        "login [redacted] then [redacted] x port [redacted]",
        "Tokenish",
    ),
    (
        "jdbc:sqlserver://db:1433;sslpassword=P@ss_Sec9;x;postgres://ops@srv:@P@h",
        "[redacted]",
        "Sec9",
    ),
    ("jdbc:sqlserver://db:1433;Pwd2=Kv9@Sec5;x;postgres://a@b@srv:Kv9@h", "[redacted]", "Sec5"),
)


@pytest.mark.parametrize(("line", "expected", "word"), _DETAIL_SHAPES)
def test_a_verify_detail_prints_no_password_word_main_hid(
    line: str, expected: str, word: str
) -> None:
    assert safe_detail_text(line) == expected
    for out in (
        safe_detail_text("store failed:" + line),
        safe_detail_text(line + ";refused"),
        safe_exc_detail(RuntimeError(line)),
        safe_exc_text(RuntimeError(line), before="dsn="),
    ):
        assert word not in out, out


#: KNOWN RESIDUALS, pinned as printed: the batch's own shapes, each value hidden by
#: ``scrub_credentials`` and printed in a verify detail, as on ``origin/main``. A red means the
#: detail's reading changed, and the comment above ``secretscrub._WIDE_DSN_PASSWORD`` and the
#: changelog fragment for BACKLOG #5386 must change with it.
_DETAIL_RESIDUALS = (
    ("connect postgres://ops@corp.example@srv:Kv9Sec@srv.example.invalid/x failed", "Kv9Sec"),
    ("postgres://a@b@srv:Kv9_Az@srv.example.invalid/x", "Kv9_Az"),
    ("x postgres://ops@srv:@Kv9x@db.invalid", "Kv9x"),
    ("jdbc:sqlserver://db.invalid:1433;user=svc;sslpassword=P@ss_Sec9;", "ss_Sec9"),
)


@pytest.mark.parametrize(("line", "value"), _DETAIL_RESIDUALS)
def test_known_residual_the_batch_shapes_print_in_a_verify_detail_as_on_main(
    line: str, value: str
) -> None:
    assert value in safe_detail_text(line)
    assert value in scrub_credentials_without_tails(line, new_dsn_readings=False)
    # Control: the other callers of the reading without tails keep the batch's readings.
    assert value not in scrub_credentials_without_tails(line)
    assert value not in scrub_credentials(line)
