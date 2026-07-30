"""Regression tests for the bundled IB_DEMO_ORU transform helper.

``samples/config`` is the worked example the docs point a new adopter at, and ``messagefoundry check``
runs its dryrun over the sample corpus. The visit-carry step used to write ``PV1-18``/``PV1-19``
unconditionally: reads of an absent segment return empty, but a **write** raises "cannot set absent
segment", so any ORU without a PV1 dead-lettered on a field that was never there. Two messages in the
bundled corpus hit it, and nothing caught it because the check gate ran in no workflow.

These pin the guard directly, so the behaviour survives independently of the corpus contents.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry import Message
from messagefoundry.config.code_sets import activated
from messagefoundry.config.wiring import load_config

SAMPLES_CONFIG = Path(__file__).resolve().parent.parent / "samples" / "config"
if str(SAMPLES_CONFIG) not in sys.path:  # a config bundle, not an installed package
    sys.path.insert(0, str(SAMPLES_CONFIG))

# Loaded dynamically rather than with a plain `from _demo_oru_transforms import ...`: the bundle is
# reached through sys.path above, so a module-level import here would sit after code (E402) and could
# not be resolved by mypy from the package roots it type-checks. importlib is how the loader itself
# reaches these `_`-prefixed sibling helpers.
apply_demo_oru_transforms = importlib.import_module(
    "_demo_oru_transforms"
).apply_demo_oru_transforms


@pytest.fixture(autouse=True)
def _sample_code_sets() -> Iterator[None]:
    """The transform looks up ``code_set("facility_mnemonics")`` at call time.

    Code sets resolve only while a bundle is loaded or its graph is running, which is what the engine
    provides around a Handler. Activate the real sample bundle's tables so these tests exercise the
    same lookup path the engine takes rather than a stub.
    """
    with activated(load_config(SAMPLES_CONFIG).code_sets):
        yield


# An ORU^R01 carrying a PV1 — the visit-carry step has something to work with.
ORU_WITH_PV1 = "\r".join(
    [
        "MSH|^~\\&|LAB|MEMORIAL|EHR|MEMORIAL|20260101120000||ORU^R01|MSG0001|P|2.5.1",
        "PID|1||123456^^^MEMORIAL^MR||DOE^JANE||19700101|F",
        "PV1|1|I|ICU^101^A||||||||||||||||V0001",
        "OBR|1||LAB0001|CBC^Complete Blood Count",
        "OBX|1|NM|WBC^White Blood Cell||7.2|10*3/uL|4.0-11.0|N|||F",
    ]
)

# The same result with NO PV1 — an unsolicited result with no visit context. Legal in ORU^R01.
ORU_WITHOUT_PV1 = "\r".join(
    [
        "MSH|^~\\&|LAB|MEMORIAL|EHR|MEMORIAL|20260101120000||ORU^R01|MSG0002|P|2.5.1",
        "PID|1||123456^^^MEMORIAL^MR||DOE^JANE||19700101|F",
        "OBR|1||LAB0002|CBC^Complete Blood Count",
        "OBX|1|NM|WBC^White Blood Cell||7.2|10*3/uL|4.0-11.0|N|||F",
    ]
)


def test_visit_carry_populates_pv1_when_the_segment_is_present() -> None:
    """The transform still does its job: patient class carried to PV1-18, visit number blanked."""
    msg = Message.parse(ORU_WITH_PV1)

    apply_demo_oru_transforms(msg)

    assert msg["PV1-18"] == "I", "original PV1-2 patient class should be carried into PV1-18"
    # An emptied field reads back as None, not "" — assert it carries no value either way.
    assert not msg["PV1-19"], "PV1-19 visit number should be blanked"


def test_message_without_pv1_is_transformed_instead_of_raising() -> None:
    """No PV1 means nothing to carry — skip the step rather than dead-letter the message."""
    msg = Message.parse(ORU_WITHOUT_PV1)

    apply_demo_oru_transforms(msg)  # must not raise "cannot set absent segment 'PV1'"

    assert "PV1" not in msg.segments(), "the guard must skip the write, never synthesize a PV1"


def test_the_other_steps_still_run_when_pv1_is_absent() -> None:
    """The PV1 guard must skip only the visit carry, not short-circuit the whole transform."""
    msg = Message.parse(ORU_WITHOUT_PV1)

    apply_demo_oru_transforms(msg)

    assert msg["PID-3.5"] == "MR", "the MRN identifier-type stamp runs before the visit carry"


@pytest.mark.parametrize("raw", [ORU_WITH_PV1, ORU_WITHOUT_PV1])
def test_transform_is_idempotent_across_a_re_run(raw: str) -> None:
    """At-least-once delivery re-runs a transform; the second pass must match the first."""
    once = Message.parse(raw)
    apply_demo_oru_transforms(once)

    twice = Message.parse(raw)
    apply_demo_oru_transforms(twice)
    apply_demo_oru_transforms(twice)

    assert str(twice) == str(once)
