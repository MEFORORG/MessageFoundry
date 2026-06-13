"""The harness coverage fixture (``harness/config``) reaches every disposition.

Loads the graph and dry-runs generated messages, asserting the routing decisions documented in
``coverage.py`` so the harness always has something wired to exercise each engine outcome. Dry-run
classifies a routed+delivered message as RECEIVED (the live engine promotes it to PROCESSED only
after delivery), so that's what the PROCESSED rows assert here.
"""

from __future__ import annotations

from messagefoundry.config.wiring import load_config
from messagefoundry.generators import _core, all_types  # noqa: F401  (registers message types)
from messagefoundry.parsing import Peek, normalize
from messagefoundry.pipeline.dryrun import DryRunResult, dry_run
from messagefoundry.store import MessageStatus

_CONFIG = "harness/config"
# A valid 2.5.1 message declared as 2.3 — the strict inbound must reject it (version mismatch).
_WRONG_VERSION = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.3\rEVN|A01|20260101\r"


def _disp(inbound: str, code: str, trigger: str) -> DryRunResult:
    registry = load_config(_CONFIG)
    registry.validate()
    return dry_run(registry, _core.generate_message(code, trigger, 1), inbound=inbound)


def test_fanout_is_processed_with_two_sends_and_a_transform() -> None:
    result = _disp("IB_Coverage_MLLP", "ADT", "A01")
    assert result.disposition == MessageStatus.RECEIVED
    assert sorted(d.to for d in result.deliveries) == ["FILE-OUT_Coverage", "OB_Coverage_Echo"]
    assert all("HARNESS" in d.payload for d in result.deliveries)  # the handler's transform applied


def test_other_adt_is_processed_with_one_send() -> None:
    result = _disp("IB_Coverage_MLLP", "ADT", "A05")
    assert result.disposition == MessageStatus.RECEIVED
    assert [d.to for d in result.deliveries] == ["FILE-OUT_Coverage"]


def test_a02_is_filtered() -> None:
    result = _disp("IB_Coverage_MLLP", "ADT", "A02")
    assert result.disposition == MessageStatus.FILTERED
    assert result.deliveries == []


def test_a03_is_error() -> None:
    result = _disp("IB_Coverage_MLLP", "ADT", "A03")
    assert result.disposition == MessageStatus.ERROR


def test_non_adt_is_unrouted() -> None:
    result = _disp("IB_Coverage_MLLP", "ORU", "R01")
    assert result.disposition == MessageStatus.UNROUTED
    assert result.deliveries == []


def test_control_id_helper_matches_embedded_msh10() -> None:
    # The harness labels rows + matches engine records with _core.control_id; it must equal what
    # generate_message actually bakes into MSH-10, or scenario verification silently false-FAILs.
    msg = _core.generate_message("ADT", "A05", 7)
    assert Peek.parse(normalize(msg)).control_id == _core.control_id("ADT", "A05", 7)


def test_strict_inbound_accepts_valid_and_rejects_wrong_version() -> None:
    registry = load_config(_CONFIG)
    valid = dry_run(registry, _core.generate_message("ADT", "A05", 1), inbound="IB_Coverage_Strict")
    assert valid.disposition == MessageStatus.RECEIVED
    bad = dry_run(registry, _WRONG_VERSION, inbound="IB_Coverage_Strict")
    assert bad.disposition == MessageStatus.ERROR
