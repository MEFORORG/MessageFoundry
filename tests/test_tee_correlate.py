# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the hybrid parity correlation (tee/correlate.py, D2)."""

from __future__ import annotations

from tee.correlate import CorepointOutput, CorrelateConfig, MeforOutput, correlate


def _msg(
    *,
    sendapp: str = "APP",
    recvapp: str = "DOWN",
    recvfac: str = "DFAC",
    dt: str = "20260604120000",
    msgtype: str = "ADT^A01",
    ctrl: str = "CTRL",
    pid3: str = "100^^^H^MR",
    name: str = "DOE^JANE",
    mrg1: str | None = None,
) -> str:
    msh = f"MSH|^~\\&|{sendapp}|SFAC|{recvapp}|{recvfac}|{dt}||{msgtype}|{ctrl}|P|2.5.1"
    segs = [msh, f"PID|1||{pid3}||{name}"]
    if mrg1 is not None:
        segs.append(f"MRG|{mrg1}")
    return "\r".join(segs) + "\r"


def test_primary_match_by_control_id() -> None:
    mefor = [MeforOutput("m1", "SRC1", "OB", _msg(sendapp="MEFOR", ctrl="SRC1"))]
    corepoint = [CorepointOutput("SRC1", _msg(sendapp="COREPOINT", ctrl="SRC1"))]
    [pair] = correlate(mefor, corepoint)
    assert pair.method == "control_id"
    assert pair.mefor is mefor[0] and pair.corepoint is corepoint[0]
    assert pair.source_control_id == "SRC1"


def test_content_fallback_on_rewritten_control_id() -> None:
    # Source control id (SRC1) is not preserved by Corepoint (CORE-9) -> fall back to the content key.
    mefor = [MeforOutput("m1", "SRC1", "OB", _msg(ctrl="MEF-1"))]
    corepoint = [CorepointOutput("CORE-9", _msg(sendapp="COREPOINT", ctrl="CORE-9"))]
    [pair] = correlate(mefor, corepoint)
    assert pair.method == "content_key"
    assert pair.corepoint is corepoint[0]


def test_msh7_matches_on_whole_seconds() -> None:
    # Fractional seconds + timezone offset are dropped; the whole second matches.
    mefor = [MeforOutput("m1", "SRC1", "OB", _msg(ctrl="MEF", dt="20260604120000.000"))]
    corepoint = [CorepointOutput("CORE", _msg(ctrl="CORE", dt="20260604120000.789-0500"))]
    [pair] = correlate(mefor, corepoint)
    assert pair.method == "content_key"


def test_msh7_differs_at_seconds_does_not_match() -> None:
    mefor = [MeforOutput("m1", "SRC1", "OB", _msg(ctrl="MEF", dt="20260604120000"))]
    corepoint = [CorepointOutput("CORE", _msg(ctrl="CORE", dt="20260604120001"))]
    pairs = correlate(mefor, corepoint)
    assert {p.method for p in pairs} == {"unmatched"}
    assert len(pairs) == 2  # missing-on-corepoint + missing-on-mefor


def test_fanout_disambiguated_by_destination() -> None:
    # One input (SRC1) fans out to two destinations; both Corepoint copies preserve SRC1, so the
    # control id alone is ambiguous and destination (MSH-5/6) breaks the tie.
    m_a = MeforOutput("m1", "SRC1", "OB_A", _msg(ctrl="SRC1", recvapp="ALPHA", recvfac="AF"))
    m_b = MeforOutput("m1", "SRC1", "OB_B", _msg(ctrl="SRC1", recvapp="BETA", recvfac="BF"))
    c_a = CorepointOutput("SRC1", _msg(sendapp="CORE", ctrl="SRC1", recvapp="ALPHA", recvfac="AF"))
    c_b = CorepointOutput("SRC1", _msg(sendapp="CORE", ctrl="SRC1", recvapp="BETA", recvfac="BF"))
    pairs = correlate([m_a, m_b], [c_a, c_b])
    by_dest = {p.destination: p for p in pairs if p.mefor is not None}
    assert by_dest[("ALPHA", "AF")].corepoint is c_a
    assert by_dest[("BETA", "BF")].corepoint is c_b
    assert all(p.method == "control_id" for p in pairs)


def test_a40_merge_correlates_across_mrn_order() -> None:
    # A40 patient merge: control ids rewritten -> content fallback. MEFOR keeps survivor M2 in PID-3
    # (prior M1 in MRG-1); Corepoint swaps them. The unordered {M1,M2} union still correlates.
    mefor = [
        MeforOutput(
            "m1",
            "SRC1",
            "OB",
            _msg(ctrl="MEF", msgtype="ADT^A40", pid3="M2^^^H^MR", mrg1="M1^^^H^MR"),
        )
    ]
    corepoint = [
        CorepointOutput(
            "CORE", _msg(ctrl="CORE", msgtype="ADT^A40", pid3="M1^^^H^MR", mrg1="M2^^^H^MR")
        )
    ]
    [pair] = correlate(mefor, corepoint)
    assert pair.method == "content_key"


def test_non_merge_type_does_not_union_mrg() -> None:
    # Same swapped MRNs but as a non-merge A01: PID-3 alone differs (M2 vs M1), so it must NOT match —
    # proving the MRG-1 union is gated to the merge trigger.
    mefor = [
        MeforOutput(
            "m1",
            "SRC1",
            "OB",
            _msg(ctrl="MEF", msgtype="ADT^A01", pid3="M2^^^H^MR", mrg1="M1^^^H^MR"),
        )
    ]
    corepoint = [
        CorepointOutput(
            "CORE", _msg(ctrl="CORE", msgtype="ADT^A01", pid3="M1^^^H^MR", mrg1="M2^^^H^MR")
        )
    ]
    assert {p.method for p in correlate(mefor, corepoint)} == {"unmatched"}


def test_primary_takes_precedence_over_content() -> None:
    # c_x matches m_a by control id AND m_b by content (same patient/type/second); the control-id pass
    # must claim c_x first, leaving m_b missing-on-Corepoint.
    m_a = MeforOutput("a", "SRC1", "OB", _msg(ctrl="MEFA", pid3="100^^^H^MR"))
    m_b = MeforOutput("b", "OTHER", "OB", _msg(ctrl="MEFB", pid3="100^^^H^MR"))
    c_x = CorepointOutput("SRC1", _msg(ctrl="SRC1", pid3="100^^^H^MR"))
    pairs = correlate([m_a, m_b], [c_x])
    pa = next(p for p in pairs if p.mefor is m_a)
    pb = next(p for p in pairs if p.mefor is m_b)
    assert pa.method == "control_id" and pa.corepoint is c_x
    assert pb.method == "unmatched" and pb.corepoint is None


def test_unique_control_id_matches_despite_relabeled_destination() -> None:
    # A single output whose source control id is preserved but whose receiver the other engine
    # relabelled still correlates — an unambiguous 1:1 tolerates the destination relabel.
    mefor = [MeforOutput("m1", "SRC1", "OB", _msg(ctrl="SRC1", recvapp="ALPHA"))]
    corepoint = [CorepointOutput("SRC1", _msg(ctrl="SRC1", recvapp="ALPHA_CP"))]
    [pair] = correlate(mefor, corepoint)
    assert pair.method == "control_id" and pair.corepoint is corepoint[0]


def test_recycled_control_id_different_patient_not_paired() -> None:
    # A reused/colliding source MSH-10 across two DIFFERENT patients must NOT manufacture a pair.
    mefor = [MeforOutput("m1", "SRC1", "OB", _msg(ctrl="SRC1", pid3="100^^^H^MR"))]
    corepoint = [CorepointOutput("SRC1", _msg(ctrl="SRC1", pid3="999^^^H^MR"))]
    pairs = correlate(mefor, corepoint)
    assert {p.method for p in pairs} == {"unmatched"}
    assert len(pairs) == 2


def test_fanout_partial_id_preservation_assigns_correctly() -> None:
    # One input fans out to ALPHA and BETA (different patients); Corepoint preserved SRC1 only on the
    # BETA copy and rewrote ALPHA's. Despite reversed Corepoint order, both resolve correctly — BETA by
    # control id, ALPHA by content — never cross-paired.
    m_alpha = MeforOutput(
        "m1", "SRC1", "OB_A", _msg(ctrl="SRC1", recvapp="ALPHA", pid3="100^^^H^MR")
    )
    m_beta = MeforOutput("m1", "SRC1", "OB_B", _msg(ctrl="SRC1", recvapp="BETA", pid3="200^^^H^MR"))
    c_alpha = CorepointOutput("REW", _msg(ctrl="REW", recvapp="ALPHA", pid3="100^^^H^MR"))
    c_beta = CorepointOutput("SRC1", _msg(ctrl="SRC1", recvapp="BETA", pid3="200^^^H^MR"))
    pairs = correlate([m_alpha, m_beta], [c_beta, c_alpha])  # Corepoint order reversed on purpose
    by_mefor = {p.mefor: p for p in pairs if p.mefor is not None}
    assert by_mefor[m_beta].method == "control_id" and by_mefor[m_beta].corepoint is c_beta
    assert by_mefor[m_alpha].method == "content_key" and by_mefor[m_alpha].corepoint is c_alpha


def test_ambiguous_same_key_same_destination_left_unmatched() -> None:
    # Two distinct outputs share patient + type + whole-second + destination (control ids rewritten),
    # delivered reversed. The key cannot disambiguate, so the matcher must NOT guess by input order —
    # it leaves them unmatched rather than manufacture two false mismatches.
    m_a = MeforOutput("m1", "SRC1", "OB", _msg(ctrl="MEFA"))
    m_b = MeforOutput("m2", "SRC2", "OB", _msg(ctrl="MEFB"))
    c_a = CorepointOutput("CORA", _msg(ctrl="CORA"))
    c_b = CorepointOutput("CORB", _msg(ctrl="CORB"))
    pairs = correlate([m_a, m_b], [c_b, c_a])
    assert {p.method for p in pairs} == {"unmatched"}
    assert len(pairs) == 4


def test_routing_divergence_reported_as_missing_not_mismatch() -> None:
    # Engines agree on ALPHA but diverge on the second destination (MEFOR -> GAMMA, Corepoint -> BETA).
    # The ALPHA pair correlates; the divergent outputs are each missing-on-a-side, NOT cross-paired
    # (which compare() would otherwise tally as a false mismatch, hiding the real routing difference).
    m_alpha = MeforOutput("m1", "SRC1", "OB_A", _msg(ctrl="SRC1", recvapp="ALPHA"))
    m_gamma = MeforOutput("m1", "SRC1", "OB_G", _msg(ctrl="SRC1", recvapp="GAMMA"))
    c_alpha = CorepointOutput("SRC1", _msg(ctrl="SRC1", recvapp="ALPHA"))
    c_beta = CorepointOutput("SRC1", _msg(ctrl="SRC1", recvapp="BETA"))
    pairs = correlate([m_alpha, m_gamma], [c_alpha, c_beta])
    matched = [p for p in pairs if p.method == "control_id"]
    assert len(matched) == 1 and matched[0].mefor is m_alpha and matched[0].corepoint is c_alpha
    assert any(
        p.method == "unmatched" and p.mefor is m_gamma and p.corepoint is None for p in pairs
    )
    assert any(p.method == "unmatched" and p.corepoint is c_beta and p.mefor is None for p in pairs)


def test_destination_alias_realigns_relabeled_receiver() -> None:
    # Corepoint labels one receiver differently (CP_DOWN vs DOWN). A dest-alias canonicalising
    # CP_DOWN -> DOWN lets the fan-out align by destination so both pairs correlate.
    m_a = MeforOutput("m1", "SRC1", "OB_A", _msg(ctrl="SRC1", recvapp="DOWN"))
    m_b = MeforOutput("m1", "SRC1", "OB_B", _msg(ctrl="SRC1", recvapp="OTHER"))
    c_a = CorepointOutput("SRC1", _msg(ctrl="SRC1", recvapp="CP_DOWN"))
    c_b = CorepointOutput("SRC1", _msg(ctrl="SRC1", recvapp="OTHER"))
    cfg = CorrelateConfig(destination_aliases={("CP_DOWN", "DFAC"): ("DOWN", "DFAC")})
    pairs = correlate([m_a, m_b], [c_a, c_b], cfg)
    by_dest = {p.destination: p for p in pairs if p.mefor is not None}
    assert by_dest[("DOWN", "DFAC")].corepoint is c_a  # CP_DOWN canonicalised to DOWN
    assert by_dest[("OTHER", "DFAC")].corepoint is c_b
    assert all(p.method == "control_id" for p in pairs)


def test_missing_on_corepoint() -> None:
    mefor = [MeforOutput("m1", "SRC1", "OB", _msg(ctrl="SRC1"))]
    [pair] = correlate(mefor, [])
    assert pair.method == "unmatched"
    assert pair.mefor is mefor[0] and pair.corepoint is None


def test_missing_on_mefor() -> None:
    corepoint = [CorepointOutput("X", _msg(ctrl="X"))]
    [pair] = correlate([], corepoint)
    assert pair.method == "unmatched"
    assert pair.corepoint is corepoint[0] and pair.mefor is None


def test_empty_bodies_do_not_spuriously_match() -> None:
    # An empty/unparseable body has no meaningful key and must not pair with another empty one.
    pairs = correlate([MeforOutput("m1", "", "OB", "")], [CorepointOutput(None, "")])
    assert {p.method for p in pairs} == {"unmatched"}
    assert len(pairs) == 2
