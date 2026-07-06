# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""summarize(): the search-facing one-line summary built from a Peek."""

from __future__ import annotations

from messagefoundry.parsing import Peek, summarize

ADT = "MSH|^~\\&|APP|FAC|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100001^^^HOSP^MR||DOE^JANE\r"

ORU = (
    "MSH|^~\\&|APP|FAC|R|RF|20260604||ORU^R01|MSG2|P|2.5.1\r"
    "PID|1||200002^^^HOSP^MR||SMITH^JOHN\r"
    "ORC|RE|PLACER123|FILLER456\r"
    "OBR|1|PLACER123|ACC789|CBC\r"
)


def test_summarize_adt_has_mrn_and_name() -> None:
    assert summarize(Peek.parse(ADT)) == "MRN 100001 · DOE, JANE"


def test_summarize_oru_adds_order_and_accession() -> None:
    s = summarize(Peek.parse(ORU))
    assert "MRN 200002" in s
    assert "SMITH, JOHN" in s
    assert "Order PLACER123" in s  # ORC-2 placer order number
    assert "Acc ACC789" in s  # OBR-3 filler/accession


def test_summarize_omits_missing_fields() -> None:
    # MSH-only message: no PID -> empty summary (tolerant).
    assert summarize(Peek.parse("MSH|^~\\&|A|B|C|D|20260604||ADT^A01|M3|P|2.5.1\r")) == ""
