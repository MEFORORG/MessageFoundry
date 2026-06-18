# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Generate a corpus of conformant HL7 v2.5.1 **ADT** messages for testing.

For every ADT trigger event defined in 2.5.1 (A01–A62, excluding the query event A19 and
reserved A56–A59) this emits ``--count`` messages of fabricated-but-realistic data, one
``.hl7`` file each, laid out under ``--out`` as ``<TRIGGER>/0001.hl7``. The reference-driven
machinery lives in [_core.py](_core.py); this module supplies ADT's trigger→structure map,
its own segment builders (MRG/NPU/DB1/IAM), and a two-block validation fallback.

The 57 ADT trigger events share **25** message structures (e.g. A04/A08/A13 are all
``ADT_A01``); hl7apy keys validation by structure, so MSH-9.3 is set to the structure id
(CLAUDE.md §8). ``ADT_A17``/``ADT_A24``/``ADT_A37`` have two *ungrouped* PID blocks that
hl7apy cannot validate whole, so each patient block is validated independently as an
``ADT_A01`` superset (see :func:`_gate_two_block`). All data is synthetic — no real PHI.

Usage::

    python -m messagefoundry.generators.adt                 # all triggers, 50 each
    python messagefoundry/generators/adt.py --triggers A01,A04 --count 5
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from messagefoundry.parsing import HL7PeekError, Peek, normalize, validate
from messagefoundry.generators import _core
from messagefoundry.generators import _hl7data as d
from messagefoundry.generators._core import Ctx, MessageSpec, next_seq, seg

DEFAULT_SEED = _core.DEFAULT_SEED
DEFAULT_OUT = "samples/messages/adt"

# Trigger event -> 2.5.1 message structure (HL7 Chapter 3). Every value is one of hl7apy's
# 25 ADT structures; shared triggers (e.g. A04->ADT_A01) carry the structure in MSH-9.3.
TRIGGER_TO_STRUCTURE: dict[str, str] = {
    "A01": "ADT_A01",
    "A04": "ADT_A01",
    "A08": "ADT_A01",
    "A13": "ADT_A01",
    "A02": "ADT_A02",
    "A03": "ADT_A03",
    "A05": "ADT_A05",
    "A14": "ADT_A05",
    "A28": "ADT_A05",
    "A31": "ADT_A05",
    "A06": "ADT_A06",
    "A07": "ADT_A06",
    "A09": "ADT_A09",
    "A10": "ADT_A09",
    "A11": "ADT_A09",
    "A12": "ADT_A12",
    "A15": "ADT_A15",
    "A16": "ADT_A16",
    "A17": "ADT_A17",
    "A18": "ADT_A18",
    "A20": "ADT_A20",
    "A21": "ADT_A21",
    "A22": "ADT_A21",
    "A23": "ADT_A21",
    "A25": "ADT_A21",
    "A26": "ADT_A21",
    "A27": "ADT_A21",
    "A29": "ADT_A21",
    "A32": "ADT_A21",
    "A33": "ADT_A21",
    "A24": "ADT_A24",
    "A30": "ADT_A30",
    "A34": "ADT_A30",
    "A35": "ADT_A30",
    "A36": "ADT_A30",
    "A46": "ADT_A30",
    "A47": "ADT_A30",
    "A48": "ADT_A30",
    "A49": "ADT_A30",
    "A37": "ADT_A37",
    "A38": "ADT_A38",
    "A39": "ADT_A39",
    "A40": "ADT_A39",
    "A41": "ADT_A39",
    "A42": "ADT_A39",
    "A43": "ADT_A43",
    "A44": "ADT_A43",
    "A45": "ADT_A45",
    "A50": "ADT_A50",
    "A51": "ADT_A50",
    "A52": "ADT_A52",
    "A53": "ADT_A52",
    "A54": "ADT_A54",
    "A55": "ADT_A54",
    "A60": "ADT_A60",
    "A61": "ADT_A61",
    "A62": "ADT_A61",
}

ALL_TRIGGERS: list[str] = sorted(TRIGGER_TO_STRUCTURE)

# Optional segments we know how to build and will sprinkle in for realism where a structure
# permits them. Required segments are always emitted regardless of this set.
OPTIONAL_SEGMENT_ALLOWLIST: frozenset[str] = frozenset(
    {"PD1", "PV1", "PV2", "NK1", "AL1", "DG1", "OBX", "DB1", "IAM"}
)

# Structures with two ungrouped PID blocks that hl7apy cannot validate as a whole.
TWO_BLOCK_STRUCTURES: frozenset[str] = frozenset({"ADT_A17", "ADT_A24", "ADT_A37"})


# --- ADT-specific segment builders -------------------------------------------


def _build_mrg(rng: random.Random, ctx: Ctx) -> str:
    return seg("MRG", {1: d.cx(str(rng.randint(1_000_000, 9_999_999)))})


def _build_npu(rng: random.Random, ctx: Ctx) -> str:
    status = rng.choice(d.BED_STATUSES)[0]
    location = d.pl(
        rng.choice(d.POINTS_OF_CARE),
        rng.choice(d.ROOMS),
        rng.choice(d.BEDS),
        rng.choice(d.FACILITIES),
    )
    return seg("NPU", {1: location, 2: status})


def _build_db1(rng: random.Random, ctx: Ctx) -> str:
    return seg("DB1", {1: str(next_seq(ctx, "DB1")), 2: "PT"})


def _build_iam(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.ALLERGENS)
    sev_code, sev_text = rng.choice(d.ALLERGY_SEVERITIES)
    return seg(
        "IAM",
        {
            1: str(next_seq(ctx, "IAM")),
            2: d.cwe("DA", "Drug allergy", "HL70127"),
            3: d.cwe(code, text, "L"),
            6: d.cwe(sev_code, sev_text, "HL70128"),
        },
    )


_ADT_BUILDERS = {"MRG": _build_mrg, "NPU": _build_npu, "DB1": _build_db1, "IAM": _build_iam}


# --- compliance gate (with the two-block fallback) ---------------------------


def _gate(msg: str, structure: str) -> tuple[bool, list[str]]:
    if structure in TWO_BLOCK_STRUCTURES:
        return _gate_two_block(msg)
    return _core.default_gate(msg, structure)


def _gate_two_block(msg: str) -> tuple[bool, list[str]]:
    """Validate each patient block of an A17/A24/A37 message independently.

    hl7apy cannot validate two ungrouped PID blocks at once. Each block (PID + its encounter
    segments) is a valid subset of ``ADT_A01``, so we wrap each as a minimal ADT_A01 and
    validate that — proving field/segment conformance of both blocks.
    """
    try:
        peek = Peek.parse(msg)
    except HL7PeekError as exc:
        return False, [f"peek parse error: {exc}"]

    segment_ids = peek.segments()
    pid_at = [i for i, s in enumerate(segment_ids) if s == "PID"]
    if len(pid_at) != 2:
        return False, [f"expected exactly 2 PID segments, found {len(pid_at)}"]

    # normalize first: a message read back via Path.read_text has \r translated to \n.
    lines = normalize(msg).strip("\r").split("\r")
    blocks = (lines[pid_at[0] : pid_at[1]], lines[pid_at[1] :])
    errors: list[str] = []
    for n, block in enumerate(blocks, start=1):
        wrapper = "\r".join(
            [
                r"MSH|^~\&|S|F|R|D|20260101000000||ADT^A08^ADT_A01|MEFORWRAP|P|2.5.1",
                "EVN|A08|20260101000000",
                *block,
            ]
        )
        result = validate(wrapper, expected_version="2.5.1")
        if not result.ok:
            errors.extend(f"block{n}: {e}" for e in result.errors)
    return (not errors), errors


def _force(structure: str) -> frozenset[str]:
    # Guarantee a PV1 in each two-block patient section so each validates as an ADT_A01.
    return frozenset({"PV1"}) if structure in TWO_BLOCK_STRUCTURES else frozenset()


_core.register(
    MessageSpec(
        code="ADT",
        trigger_to_structure=TRIGGER_TO_STRUCTURE,
        builders=_ADT_BUILDERS,
        optional_allowlist=OPTIONAL_SEGMENT_ALLOWLIST,
        force=_force,
        gate=_gate,
    )
)


# --- ADT-flavoured back-compat surface (used by tests / the CLI) -------------


def generate_message(trigger: str, index: int, *, seed: str = DEFAULT_SEED) -> str:
    """Build one ``\\r``-delimited ADT message for ``trigger`` (deterministic given seed)."""
    return _core.generate_message("ADT", trigger, index, seed=seed)


def gate(msg: str, structure: str) -> tuple[bool, list[str]]:
    """Return ``(ok, errors)`` from strict hl7apy validation (with the two-block fallback)."""
    return _core.gate("ADT", msg, structure)


# --- CLI ---------------------------------------------------------------------


def _parse_triggers(raw: str) -> list[str]:
    if not raw:
        return ALL_TRIGGERS
    chosen = [t.strip().upper() for t in raw.split(",") if t.strip()]
    unknown = [t for t in chosen if t not in TRIGGER_TO_STRUCTURE]
    if unknown:
        raise SystemExit(f"unknown ADT trigger(s): {', '.join(unknown)}")
    return chosen


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate conformant HL7 v2.5.1 ADT messages.")
    parser.add_argument("--out", default=DEFAULT_OUT, help=f"output root (default {DEFAULT_OUT})")
    parser.add_argument("--count", type=int, default=50, help="messages per trigger (default 50)")
    parser.add_argument("--triggers", default="", help="comma-separated subset (default: all)")
    parser.add_argument("--seed", default=DEFAULT_SEED, help="RNG seed for reproducible output")
    parser.add_argument("--quiet", action="store_true", help="suppress per-trigger progress")
    parser.add_argument(
        "--show-message",
        action="store_true",
        help="on validation failure, print the offending message to stderr (off by default)",
    )
    args = parser.parse_args(argv)

    triggers = _parse_triggers(args.triggers)
    out_root = Path(args.out)
    total = 0

    for trigger in triggers:
        structure = TRIGGER_TO_STRUCTURE[trigger]
        # Generate + strict-validate + write via the shared corpus writer: its cleanup is scoped
        # to its own NNNN.hl7 files, never an arbitrary *.hl7 a user placed in the dir (low-19).
        try:
            result = _core.write_corpus(
                "ADT", triggers=[trigger], count=args.count, out=args.out, seed=args.seed
            )
        except _core.GenerationError as exc:
            print(f"VALIDATION FAILED: {trigger} #{exc.index} ({structure})", file=sys.stderr)
            for err in exc.errors:
                print(f"  - {err}", file=sys.stderr)
            # Even though these are synthetic, don't dump a whole message to stderr by default —
            # the pattern leaks if ever adapted to real data (docs/PHI.md §7). Opt in to debug.
            if args.show_message:
                print("--- offending message ---", file=sys.stderr)
                print(exc.message.replace("\r", "\n"), file=sys.stderr)
            else:
                print("(re-run with --show-message to print it)", file=sys.stderr)
            return 1
        total += result.total
        if not args.quiet:
            print(f"{trigger} -> {structure}: {result.total} messages")

    if not args.quiet:
        print(f"\nGenerated {total} messages across {len(triggers)} triggers into {out_root}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
