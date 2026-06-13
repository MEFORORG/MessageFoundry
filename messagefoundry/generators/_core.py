"""Shared, reference-driven machinery for the HL7 message generators.

Each message type (ADT, ORM, …) registers a :class:`MessageSpec` describing its
trigger→structure map, its segment builders, and which optional segments to sprinkle in.
Generation walks hl7apy's own 2.5.1 reference tree (``MESSAGES[structure]``): for each
structure we emit required segments in order plus a valid random subset of allow-listed
optionals, then gate every message through the engine's strict validator before it counts.

A type module contributes builders only for its *own* segments; the broadly shared ones
(MSH/EVN/PID/PV1/…) live here in :data:`SHARED_BUILDERS`. All data is synthetic — no real PHI.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from hl7apy import v2_5_1 as _ref

from messagefoundry.parsing import validate
from messagefoundry.generators import _hl7data as d

_MESSAGES = _ref.MESSAGES
_SEGMENTS = _ref.SEGMENTS

DEFAULT_SEED = "messagefoundry-hl7-2.5.1"
# Fixed epoch so a given seed reproduces identical bytes (no wall-clock nondeterminism).
BASE_DT = datetime(2026, 1, 1, 0, 0, 0)

SegmentBuilder = Callable[[random.Random, "Ctx"], str]
GateFn = Callable[[str, str], tuple[bool, list[str]]]


# --- per-message state -------------------------------------------------------


@dataclass
class Patient:
    """A fabricated patient identity, shared across a message's PID/PV1/etc."""

    mrn: str
    family: str
    given: str
    middle: str
    dob: str
    sex: str
    street: str
    city: str
    state: str
    zip_code: str
    phone: str
    patient_class: str
    visit_no: str


@dataclass
class Ctx:
    """Mutable per-message context threaded through the segment builders."""

    message_code: str
    trigger: str
    structure: str
    control_id: str
    msg_dt: datetime
    sending_app: str
    sending_fac: str
    receiving_app: str
    receiving_fac: str
    current: Patient | None = None
    seq: dict[str, int] = field(default_factory=dict)


def next_seq(ctx: Ctx, name: str) -> int:
    """Monotonic set-id per segment type within a message (PID-1, NK1-1, …)."""
    ctx.seq[name] = ctx.seq.get(name, 0) + 1
    return ctx.seq[name]


def seg(name: str, fields: dict[int, str]) -> str:
    """Assemble a segment, placing each value at its 1-based field index, gaps empty."""
    high = max(fields) if fields else 0
    return "|".join([name, *(fields.get(i, "") for i in range(1, high + 1))])


# --- synthetic patient -------------------------------------------------------


def _birthdate(rng: random.Random) -> str:
    age = rng.randint(0, 95)
    return f"{2026 - age:04d}{rng.randint(1, 12):02d}{rng.randint(1, 28):02d}"


def make_patient(rng: random.Random) -> Patient:
    city, state, zip_code = rng.choice(d.CITIES)
    return Patient(
        mrn=str(rng.randint(1_000_000, 9_999_999)),
        family=rng.choice(d.FAMILY_NAMES),
        given=rng.choice(d.GIVEN_NAMES),
        middle=rng.choice(d.MIDDLE_INITIALS),
        dob=_birthdate(rng),
        sex=rng.choice(d.SEXES),
        street=rng.choice(d.STREETS),
        city=city,
        state=state,
        zip_code=zip_code,
        # NANP reserved fictional range (exchange 555, subscriber 0100-0199) — never diallable
        # even though the synthetic data is otherwise realistic (low-22).
        phone=f"({rng.randint(200, 989)})555-{rng.randint(100, 199):04d}",
        patient_class=rng.choice(d.PATIENT_CLASSES),
        visit_no=f"V{rng.randint(1_000_000, 9_999_999)}",
    )


def patient(ctx: Ctx, rng: random.Random) -> Patient:
    """The message's current patient, creating one on first use (shared by PID/PV1/etc.)."""
    if ctx.current is None:
        ctx.current = make_patient(rng)
    return ctx.current


# --- broadly shared segment builders -----------------------------------------


def _build_msh(rng: random.Random, ctx: Ctx) -> str:
    tail = "|".join(
        [
            ctx.sending_app,
            ctx.sending_fac,
            ctx.receiving_app,
            ctx.receiving_fac,
            d.ts(ctx.msg_dt),
            "",
            f"{ctx.message_code}^{ctx.trigger}^{ctx.structure}",
            ctx.control_id,
            "P",
            "2.5.1",
        ]
    )
    return rf"MSH|^~\&|{tail}"


def _build_evn(rng: random.Random, ctx: Ctx) -> str:
    reason = rng.choice(d.EVENT_REASONS)[0]
    return seg("EVN", {1: ctx.trigger, 2: d.ts(ctx.msg_dt), 4: reason, 6: d.ts(ctx.msg_dt)})


def _build_pid(rng: random.Random, ctx: Ctx) -> str:
    p = make_patient(rng)
    ctx.current = p
    return seg(
        "PID",
        {
            1: str(next_seq(ctx, "PID")),
            3: d.cx(p.mrn),
            5: d.xpn(p.family, p.given, p.middle),
            7: p.dob,
            8: p.sex,
            11: d.xad(p.street, p.city, p.state, p.zip_code),
            13: p.phone,
            18: d.cx(p.visit_no, id_type="AN"),
        },
    )


def _build_pd1(rng: random.Random, ctx: Ctx) -> str:
    return seg(
        "PD1", {3: f"{rng.choice(d.FACILITIES)} CLINIC", 4: d.xcn(*rng.choice(d.CLINICIANS))}
    )


def _build_pv1(rng: random.Random, ctx: Ctx) -> str:
    p = patient(ctx, rng)
    return seg(
        "PV1",
        {
            1: str(next_seq(ctx, "PV1")),
            2: p.patient_class,
            3: d.pl(
                rng.choice(d.POINTS_OF_CARE),
                rng.choice(d.ROOMS),
                rng.choice(d.BEDS),
                rng.choice(d.FACILITIES),
            ),
            7: d.xcn(*rng.choice(d.CLINICIANS)),
            10: rng.choice(d.HOSPITAL_SERVICES),
            17: d.xcn(*rng.choice(d.CLINICIANS)),
            19: d.cx(p.visit_no, id_type="VN"),
            44: d.ts(ctx.msg_dt),
        },
    )


def _build_pv2(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.DIAGNOSES)
    return seg("PV2", {3: d.cwe(code, text, "I10")})


def _build_nk1(rng: random.Random, ctx: Ctx) -> str:
    rel_code, rel_text = rng.choice(d.RELATIONSHIPS)
    return seg(
        "NK1",
        {
            1: str(next_seq(ctx, "NK1")),
            2: d.xpn(rng.choice(d.FAMILY_NAMES), rng.choice(d.GIVEN_NAMES)),
            3: d.cwe(rel_code, rel_text, "HL70063"),
        },
    )


def _build_al1(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.ALLERGENS)
    severity = rng.choice(d.ALLERGY_SEVERITIES)[0]
    return seg(
        "AL1",
        {
            1: str(next_seq(ctx, "AL1")),
            2: d.cwe("DA", "Drug allergy", "HL70127"),
            3: d.cwe(code, text, "L"),
            4: severity,
        },
    )


def _build_dg1(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.DIAGNOSES)
    return seg(
        "DG1",
        {
            1: str(next_seq(ctx, "DG1")),
            3: d.cwe(code, text, "I10"),
            6: rng.choice(d.DIAGNOSIS_TYPES),
        },
    )


def _build_obx(rng: random.Random, ctx: Ctx) -> str:
    code, text, value_type, value, units = rng.choice(d.OBSERVATIONS)
    return seg(
        "OBX",
        {
            1: str(next_seq(ctx, "OBX")),
            2: value_type,
            3: d.cwe(code, text, "LN"),
            5: value,
            6: units,
            11: "F",
        },
    )


def _build_orc(rng: random.Random, ctx: Ctx) -> str:
    return seg(
        "ORC",
        {
            1: rng.choice(d.ORDER_CONTROLS),
            2: d.ei(str(rng.randint(100_000, 999_999))),  # placer order number
            3: d.ei(str(rng.randint(100_000, 999_999)), "FILLER"),
            5: rng.choice(d.ORDER_STATUSES),
            9: d.ts(ctx.msg_dt),
            12: d.xcn(*rng.choice(d.CLINICIANS)),
        },
    )


def _build_obr(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.SERVICES)
    return seg(
        "OBR",
        {
            1: str(next_seq(ctx, "OBR")),
            2: d.ei(str(rng.randint(100_000, 999_999))),
            3: d.ei(str(rng.randint(100_000, 999_999)), "FILLER"),
            4: d.cwe(code, text, "LN"),  # universal service id (required)
            7: d.ts(ctx.msg_dt),
        },
    )


def _build_ft1(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.PROCEDURES)
    return seg(
        "FT1",
        {
            1: str(next_seq(ctx, "FT1")),
            4: d.ts(ctx.msg_dt),  # transaction date (required)
            6: rng.choice(d.TRANSACTION_TYPES),  # transaction type (required)
            7: d.cwe(code, text, "CPT"),  # transaction code (required)
        },
    )


def _build_pr1(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.PROCEDURES)
    return seg(
        "PR1",
        {
            1: str(next_seq(ctx, "PR1")),
            3: d.cwe(code, text, "C4"),  # procedure code (required)
            5: d.ts(ctx.msg_dt),  # procedure date/time (required)
        },
    )


def _build_gt1(rng: random.Random, ctx: Ctx) -> str:
    return seg(
        "GT1",
        {
            1: str(next_seq(ctx, "GT1")),
            3: d.xpn(rng.choice(d.FAMILY_NAMES), rng.choice(d.GIVEN_NAMES)),  # guarantor (required)
        },
    )


def _build_in1(rng: random.Random, ctx: Ctx) -> str:
    company_id, company = rng.choice(d.INSURANCE_COMPANIES)
    code, text = rng.choice(d.INSURANCE_PLANS)
    return seg(
        "IN1",
        {
            1: str(next_seq(ctx, "IN1")),
            2: d.cwe(code, text, "L"),  # insurance plan id (required)
            3: d.cx(company_id, authority=company, id_type="NI"),  # company id (required)
            4: company,
        },
    )


def _build_rxa(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.VACCINES)
    return seg(
        "RXA",
        {
            1: "0",  # give sub-id counter (required)
            2: "1",  # administration sub-id counter (required)
            3: d.ts(ctx.msg_dt),  # date/time start (required)
            4: d.ts(ctx.msg_dt),  # date/time end (required)
            5: d.cwe(code, text, "CVX"),  # administered code (required)
            6: "0.5",  # administered amount (required)
        },
    )


def _build_rxr(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.ROUTES)
    return seg("RXR", {1: d.cwe(code, text, "HL70162")})  # route (required)


SHARED_BUILDERS: dict[str, SegmentBuilder] = {
    "MSH": _build_msh,
    "EVN": _build_evn,
    "PID": _build_pid,
    "PD1": _build_pd1,
    "PV1": _build_pv1,
    "PV2": _build_pv2,
    "NK1": _build_nk1,
    "AL1": _build_al1,
    "DG1": _build_dg1,
    "OBX": _build_obx,
    "ORC": _build_orc,
    "OBR": _build_obr,
    "FT1": _build_ft1,
    "PR1": _build_pr1,
    "GT1": _build_gt1,
    "IN1": _build_in1,
    "RXA": _build_rxa,
    "RXR": _build_rxr,
}


# --- message-type registry ---------------------------------------------------


def _no_force(structure: str) -> frozenset[str]:
    return frozenset()


@dataclass(frozen=True)
class MessageSpec:
    """How to generate one HL7 message family.

    ``builders`` are this type's own segments (merged over :data:`SHARED_BUILDERS`);
    ``force`` names optional segments to always emit for a given structure; ``gate`` overrides
    strict validation (e.g. ADT's two-block fallback).
    """

    code: str
    trigger_to_structure: dict[str, str]
    builders: Mapping[str, SegmentBuilder] = field(default_factory=dict)
    optional_allowlist: frozenset[str] = frozenset()
    force: Callable[[str], frozenset[str]] = _no_force
    gate: GateFn | None = None
    # Optional groups to recurse into, matched by name *suffix* (e.g. "_PATIENT") so one spec
    # covers every structure of its type (ORM_O01_PATIENT, SIU_S12_PATIENT, …).
    group_suffixes: frozenset[str] = frozenset()


_REGISTRY: dict[str, MessageSpec] = {}


def register(spec: MessageSpec) -> None:
    _REGISTRY[spec.code] = spec


def message_codes() -> list[str]:
    """Registered message types (e.g. ``["ADT", "ORM", …]``) — drives the harness GUI."""
    return sorted(_REGISTRY)


def triggers_for(code: str) -> list[str]:
    return sorted(_REGISTRY[code].trigger_to_structure)


def structure_for(code: str, trigger: str) -> str:
    return _REGISTRY[code].trigger_to_structure[trigger]


def control_id(code: str, trigger: str, index: int) -> str:
    """The deterministic synthetic control id embedded in MSH-10 by :func:`generate_message`.

    Single source of truth so the harness (which labels rows and matches the engine's recorded
    control ids against it) and the generator never drift apart."""
    return f"MEFOR{code}{trigger}{index:05d}"


# --- reference-driven assembly ----------------------------------------------


def _emit(
    children: list[Any],
    rng: random.Random,
    ctx: Ctx,
    spec: MessageSpec,
    force: frozenset[str],
    out: list[str],
) -> None:
    """Walk an hl7apy reference child list, appending built segment strings to ``out``.

    Required children (min>=1) are always emitted; optional segments are emitted only if
    allow-listed (a random 0..N for repeating ones), or if named in ``force``. Groups recurse
    only when the group itself is required.
    """
    for child in children:
        name = child[0]
        child_ref = child[1]
        min_card, max_card = child[2][0], child[2][1]

        if name in _SEGMENTS:
            builder = spec.builders.get(name) or SHARED_BUILDERS.get(name)
            if min_card >= 1 or name in force:
                if builder is None:
                    raise RuntimeError(f"no builder for required/forced segment {name}")
                out.append(builder(rng, ctx))
            elif name in spec.optional_allowlist and builder is not None:
                max_reps = 1 if max_card == 1 else 3
                for _ in range(rng.randint(0, max_reps)):
                    out.append(builder(rng, ctx))
        elif min_card >= 1 or any(name.endswith(s) for s in spec.group_suffixes):
            _emit(child_ref[1], rng, ctx, spec, force, out)


def generate_message(code: str, trigger: str, index: int, *, seed: str = DEFAULT_SEED) -> str:
    """Build one ``\\r``-delimited HL7 message (deterministic given ``code``/``trigger``/``seed``)."""
    spec = _REGISTRY[code]
    structure = spec.trigger_to_structure[trigger]
    rng = random.Random(f"{seed}|{code}|{trigger}|{index}")
    sending_app, sending_fac = rng.choice(d.SENDING_APPS)
    receiving_app, receiving_fac = rng.choice(d.RECEIVING_APPS)
    ctx = Ctx(
        message_code=code,
        trigger=trigger,
        structure=structure,
        control_id=control_id(code, trigger, index),
        msg_dt=BASE_DT + timedelta(minutes=rng.randint(0, 525_600)),
        sending_app=sending_app,
        sending_fac=sending_fac,
        receiving_app=receiving_app,
        receiving_fac=receiving_fac,
    )
    out: list[str] = []
    _emit(_MESSAGES[structure][1], rng, ctx, spec, spec.force(structure), out)
    return "\r".join(out) + "\r"


# --- compliance gate ---------------------------------------------------------


def default_gate(msg: str, structure: str) -> tuple[bool, list[str]]:
    """Strict hl7apy validation (the default for types with no special-casing)."""
    result = validate(msg, expected_version="2.5.1")
    return result.ok, list(result.errors)


def gate(code: str, msg: str, structure: str) -> tuple[bool, list[str]]:
    """Return ``(ok, errors)`` using the type's gate override, else strict validation."""
    spec = _REGISTRY[code]
    if spec.gate is not None:
        return spec.gate(msg, structure)
    return default_gate(msg, structure)


# --- corpus writer (shared by the CLI and the per-type modules) --------------


class GenerationError(RuntimeError):
    """A generated message failed strict validation — a generator bug, never a user error."""

    def __init__(
        self, code: str, trigger: str, index: int, structure: str, errors: list[str], message: str
    ) -> None:
        self.code = code
        self.trigger = trigger
        self.index = index
        self.structure = structure
        self.errors = errors
        self.message = message
        super().__init__(
            f"{code}^{trigger} #{index} ({structure}) failed validation: {'; '.join(errors)}"
        )


@dataclass(frozen=True)
class CorpusResult:
    """What :func:`write_corpus` produced."""

    code: str
    out_dir: str
    by_trigger: dict[str, int]  # trigger -> messages written
    total: int


def write_corpus(
    code: str,
    *,
    triggers: list[str] | None = None,
    count: int = 50,
    out: str | Path,
    seed: str = DEFAULT_SEED,
    corpus_root: str | Path | None = None,
) -> CorpusResult:
    """Generate + strict-validate ``count`` messages per trigger and write them as
    ``<out>/<TRIGGER>/NNNN.hl7`` (all-or-nothing per trigger; stale generated files are cleared first).

    ``triggers`` defaults to every trigger of ``code``. The cleanup is **scoped**: it deletes only
    its own ``NNNN.hl7`` files, never arbitrary ``*.hl7`` a user placed there (GEN-1). When
    ``corpus_root`` is given, ``out`` must resolve **within** it — a containment guard for
    programmatic callers (the CLI writes the user's explicit ``--out``). Raises :class:`ValueError`
    for an out-of-root path, :class:`KeyError` for an unknown type/trigger, and
    :class:`GenerationError` if any message fails validation.
    """
    if code not in _REGISTRY:
        raise KeyError(f"unknown message type {code!r}; registered: {', '.join(message_codes())}")
    chosen = list(triggers) if triggers else triggers_for(code)
    unknown = [t for t in chosen if t not in _REGISTRY[code].trigger_to_structure]
    if unknown:
        raise KeyError(f"unknown {code} trigger(s): {', '.join(unknown)}")

    out_root = Path(out).resolve()
    if corpus_root is not None:
        root = Path(corpus_root).resolve()
        if out_root != root and root not in out_root.parents:
            raise ValueError(f"refusing to write corpus outside {root}: {out_root}")
    by_trigger: dict[str, int] = {}
    total = 0
    for trigger in chosen:
        structure = structure_for(code, trigger)
        # Build + validate the whole batch before writing (all-or-nothing per trigger).
        messages: list[str] = []
        for index in range(1, count + 1):
            msg = generate_message(code, trigger, index, seed=seed)
            ok, errors = gate(code, msg, structure)
            if not ok:
                raise GenerationError(code, trigger, index, structure, errors, msg)
            messages.append(msg)
        trigger_dir = out_root / trigger
        trigger_dir.mkdir(parents=True, exist_ok=True)
        # Only clear our own generated files (NNNN.hl7), not arbitrary *.hl7 a user may have placed.
        for stale in trigger_dir.glob("[0-9][0-9][0-9][0-9].hl7"):
            stale.unlink()
        for index, msg in enumerate(messages, start=1):
            (trigger_dir / f"{index:04d}.hl7").write_bytes(msg.encode("utf-8"))
        by_trigger[trigger] = len(messages)
        total += len(messages)
    return CorpusResult(code=code, out_dir=str(out_root), by_trigger=by_trigger, total=total)
