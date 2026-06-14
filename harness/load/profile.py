"""Load profiles — a run shape authored as **data** (TOML), parsed into frozen dataclasses.

A profile names the targets to drive, the message-type mix, a sequence of phases (warmup → ramp →
sustained → spike → soak), and the SLO thresholds that decide pass/fail. Phases choose a loop model:
``open`` holds an offered rate (to measure latency at a fixed load) and ``closed`` holds a fixed
in-flight concurrency (to find max sustainable throughput). Per-phase ``mix`` / ``slo`` inline tables
override the run defaults.

Parsing fails loud on a missing/typo'd/wrong-typed key (mirroring ``connections.toml``), so a broken
profile is rejected before any traffic is sent rather than silently mis-running. All numbers are
generic and synthetic; profiles never name a real partner/site/host — see ``docs/LOAD-TESTING.md``.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Phase shapes. ``measured`` phases (sustained/soak) are the ones SLOs are evaluated on; warmup/ramp/
#: spike are transient and excluded from the steady-state verdict.
PHASE_KINDS = frozenset({"warmup", "ramp", "sustained", "spike", "soak"})
_MEASURED_KINDS = frozenset({"sustained", "soak"})
LOOP_MODES = frozenset({"open", "closed"})

PROFILES_DIR = Path(__file__).parent / "profiles"

_LOAD_KEYS = frozenset(
    {
        "name",
        "description",
        "pool_size",
        "corpus_count_per_trigger",
        "poll_interval_s",
        "drain_timeout_s",
        "seed",
        "correlator_capacity",
        "target",
        "mix",
        "slo",
        "phase",
    }
)
_TARGET_KEYS = frozenset({"name", "host", "port", "types", "weight", "expect_ack", "ack_timeout_s"})
_PHASE_KEYS = frozenset(
    {"name", "kind", "loop", "rate_start", "rate_end", "concurrency", "duration_s", "mix", "slo"}
)
_SLO_KEYS = frozenset(
    {
        "min_sustained_msg_s",
        "max_ack_p99_ms",
        "max_e2e_p99_ms",
        "max_error_rate",
        "max_nak_rate",
        "max_dup_rate",
        "max_dead_letters",
        "max_drain_seconds",
        "zero_loss",
    }
)


class LoadProfileError(ValueError):
    """A malformed or self-inconsistent load profile."""


@dataclass(frozen=True)
class TypeMix:
    """Weighted message-type/trigger mix. Keys are ``"ADT"`` (any trigger) or ``"ADT^A01"``."""

    weights: dict[str, float]

    def normalized(self) -> dict[str, float]:
        total = sum(self.weights.values())
        if total <= 0.0:
            raise LoadProfileError("mix weights must sum to a positive number")
        return {k: v / total for k, v in self.weights.items()}

    def codes(self) -> set[str]:
        """The distinct message-type codes (the part before ``^``) the mix references."""
        return {key.split("^", 1)[0] for key in self.weights}


@dataclass(frozen=True)
class Slo:
    """Pass/fail thresholds. ``None`` fields are not checked; ``zero_loss`` defaults off."""

    min_sustained_msg_s: float | None = None
    max_ack_p99_ms: float | None = None
    max_e2e_p99_ms: float | None = None
    max_error_rate: float | None = None
    max_nak_rate: float | None = None
    max_dup_rate: float | None = None
    max_dead_letters: int | None = None
    max_drain_seconds: float | None = None
    zero_loss: bool = False


@dataclass(frozen=True)
class Target:
    """An inbound MLLP endpoint to drive. ``types`` restricts which message-type codes route here
    (empty = any); ``weight`` splits offered load across targets."""

    name: str
    host: str = "127.0.0.1"
    port: int = 2575
    types: tuple[str, ...] = ()
    weight: float = 1.0
    expect_ack: bool = True
    ack_timeout_s: float = 10.0


@dataclass(frozen=True)
class Phase:
    """One stage of the run. ``open`` loop uses ``rate_start``→``rate_end`` (msg/s, interpolated);
    ``closed`` loop holds ``concurrency`` in flight."""

    name: str
    kind: str
    loop: str
    duration_s: float
    rate_start: float = 0.0
    rate_end: float | None = None
    concurrency: int | None = None
    mix: TypeMix | None = None
    slo: Slo | None = None

    @property
    def measured(self) -> bool:
        return self.kind in _MEASURED_KINDS

    def rate_at(self, t_in_phase: float) -> float:
        """Offered rate (msg/s) at ``t_in_phase`` seconds into the phase, linearly interpolated for a
        ramp. Meaningful only for ``open`` loop."""
        end = self.rate_start if self.rate_end is None else self.rate_end
        if self.duration_s <= 0.0 or end == self.rate_start:
            return self.rate_start
        frac = max(0.0, min(1.0, t_in_phase / self.duration_s))
        return self.rate_start + (end - self.rate_start) * frac


@dataclass(frozen=True)
class LoadProfile:
    """A complete, validated run definition."""

    name: str
    description: str
    targets: tuple[Target, ...]
    phases: tuple[Phase, ...]
    default_mix: TypeMix
    default_slo: Slo = field(default_factory=Slo)
    pool_size: int = 8
    corpus_count_per_trigger: int = 50
    poll_interval_s: float = 1.0
    drain_timeout_s: float = 120.0
    seed: str = "messagefoundry-load"
    correlator_capacity: int = 1_000_000

    def mix_for(self, phase: Phase) -> TypeMix:
        return phase.mix if phase.mix is not None else self.default_mix

    def slo_for(self, phase: Phase) -> Slo:
        return phase.slo if phase.slo is not None else self.default_slo

    def codes(self) -> set[str]:
        """Every message-type code any phase may send — what the corpus must cover."""
        out = set(self.default_mix.codes())
        for phase in self.phases:
            if phase.mix is not None:
                out |= phase.mix.codes()
        return out


# --- loading -----------------------------------------------------------------


def load_profile(path: Path | str) -> LoadProfile:
    """Parse a profile TOML file. Raises :class:`LoadProfileError` on any problem."""
    p = Path(path)
    try:
        with open(p, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise LoadProfileError(f"cannot read {p.name}: {exc}") from exc
    return _profile_from_data(data, where=p.name)


def load_profile_text(text: str, *, where: str = "<text>") -> LoadProfile:
    """Parse a profile from a TOML string (for tests)."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise LoadProfileError(f"{where}: {exc}") from exc
    return _profile_from_data(data, where=where)


def list_profiles() -> dict[str, str]:
    """Built-in profile name → description, read from ``harness/load/profiles/*.toml``."""
    out: dict[str, str] = {}
    for path in sorted(PROFILES_DIR.glob("*.toml")):
        try:
            out[load_profile(path).name] = load_profile(path).description
        except LoadProfileError:
            out[path.stem] = "(invalid profile)"
    return out


def get_profile(name_or_path: str) -> LoadProfile:
    """Resolve a built-in profile name or a filesystem path to a :class:`LoadProfile`."""
    candidate = Path(name_or_path)
    if candidate.exists():
        return load_profile(candidate)
    builtin = PROFILES_DIR / f"{name_or_path}.toml"
    if builtin.exists():
        return load_profile(builtin)
    choices = ", ".join(sorted(list_profiles())) or "(none)"
    raise LoadProfileError(f"unknown profile {name_or_path!r}; built-ins: {choices}")


def _profile_from_data(data: dict[str, Any], *, where: str) -> LoadProfile:
    extra = set(data) - {"load"}
    if extra:
        raise LoadProfileError(f"{where}: unknown top-level key(s) {', '.join(sorted(extra))}")
    load = data.get("load")
    if not isinstance(load, dict):
        raise LoadProfileError(f"{where}: missing [load] table")
    _reject_unknown(load, _LOAD_KEYS, f"{where} [load]")

    name = _req_str(load, "name", f"{where} [load]")
    targets = _targets_from(load.get("target", []), where)
    phases = _phases_from(load.get("phase", []), where)
    default_mix = _mix_from(load.get("mix"), f"{where} [load.mix]", required=True)
    assert default_mix is not None  # _mix_from(required=True) raises rather than returning None
    default_slo = _slo_from(load.get("slo"), f"{where} [load.slo]") or Slo()

    profile = LoadProfile(
        name=name,
        description=_opt_str(load, "description", f"{where} [load]") or "",
        targets=targets,
        phases=phases,
        default_mix=default_mix,
        default_slo=default_slo,
        pool_size=_opt_int(load, "pool_size", f"{where} [load]", default=8, minimum=1),
        corpus_count_per_trigger=_opt_int(
            load, "corpus_count_per_trigger", f"{where} [load]", default=50, minimum=1
        ),
        poll_interval_s=_opt_float(
            load, "poll_interval_s", f"{where} [load]", default=1.0, minimum=0.05
        ),
        drain_timeout_s=_opt_float(
            load, "drain_timeout_s", f"{where} [load]", default=120.0, minimum=0.0
        ),
        seed=_opt_str(load, "seed", f"{where} [load]") or "messagefoundry-load",
        correlator_capacity=_opt_int(
            load, "correlator_capacity", f"{where} [load]", default=1_000_000, minimum=1
        ),
    )
    _validate_cross_refs(profile, where)
    return profile


def _targets_from(raw: Any, where: str) -> tuple[Target, ...]:
    tables = _as_tables(raw, f"{where} [[load.target]]")
    if not tables:
        raise LoadProfileError(f"{where}: at least one [[load.target]] is required")
    targets = []
    for table in tables:
        name = _req_str(table, "name", f"{where} [[load.target]]")
        ctx = f"{where} target {name!r}"
        _reject_unknown(table, _TARGET_KEYS, ctx)
        targets.append(
            Target(
                name=name,
                host=_opt_str(table, "host", ctx) or "127.0.0.1",
                port=_opt_int(table, "port", ctx, default=2575, minimum=1, maximum=65535),
                types=_opt_str_tuple(table, "types", ctx),
                weight=_opt_float(table, "weight", ctx, default=1.0, minimum=0.0),
                expect_ack=_opt_bool(table, "expect_ack", ctx, default=True),
                ack_timeout_s=_opt_float(table, "ack_timeout_s", ctx, default=10.0, minimum=0.1),
            )
        )
    return tuple(targets)


def _phases_from(raw: Any, where: str) -> tuple[Phase, ...]:
    tables = _as_tables(raw, f"{where} [[load.phase]]")
    if not tables:
        raise LoadProfileError(f"{where}: at least one [[load.phase]] is required")
    phases = []
    for table in tables:
        name = _req_str(table, "name", f"{where} [[load.phase]]")
        ctx = f"{where} phase {name!r}"
        _reject_unknown(table, _PHASE_KEYS, ctx)
        kind = _req_str(table, "kind", ctx)
        if kind not in PHASE_KINDS:
            raise LoadProfileError(f"{ctx}: kind {kind!r} not in {sorted(PHASE_KINDS)}")
        loop = _req_str(table, "loop", ctx)
        if loop not in LOOP_MODES:
            raise LoadProfileError(f"{ctx}: loop {loop!r} not in {sorted(LOOP_MODES)}")
        phase = Phase(
            name=name,
            kind=kind,
            loop=loop,
            duration_s=_req_float(table, "duration_s", ctx, minimum=0.0, exclusive_min=True),
            rate_start=_opt_float(table, "rate_start", ctx, default=0.0, minimum=0.0),
            rate_end=_opt_float_or_none(table, "rate_end", ctx, minimum=0.0),
            concurrency=_opt_int_or_none(table, "concurrency", ctx, minimum=1),
            mix=_mix_from(table.get("mix"), f"{ctx} mix", required=False),
            slo=_slo_from(table.get("slo"), f"{ctx} slo"),
        )
        if phase.loop == "closed" and phase.concurrency is None:
            raise LoadProfileError(f"{ctx}: a closed-loop phase requires 'concurrency'")
        if phase.loop == "open":
            if phase.rate_start <= 0.0 and (phase.rate_end or 0.0) <= 0.0:
                raise LoadProfileError(f"{ctx}: an open-loop phase requires a positive rate")
            # 'concurrency' is only consumed by the closed loop; the open loop is rate-shaped. Reject
            # it rather than silently ignore (a no-op key reads as a load cap that does nothing).
            if phase.concurrency is not None:
                raise LoadProfileError(
                    f"{ctx}: 'concurrency' has no effect on an open-loop phase (it is rate-shaped); "
                    "remove it or use loop = 'closed'"
                )
        phases.append(phase)
    return tuple(phases)


def _validate_cross_refs(profile: LoadProfile, where: str) -> None:
    profile.default_mix.normalized()  # raises if weights are non-positive
    target_codes: set[str] = set()
    for target in profile.targets:
        target_codes |= set(target.types)
    # Every code the mix can emit must have at least one target that accepts it (a target with no
    # 'types' accepts all). Otherwise generated traffic would have nowhere to go.
    accepts_all = any(not t.types for t in profile.targets)
    if not accepts_all:
        missing = profile.codes() - target_codes
        if missing:
            raise LoadProfileError(
                f"{where}: mix emits {sorted(missing)} but no target accepts those types"
            )


# --- decoding helpers --------------------------------------------------------


def _mix_from(raw: Any, where: str, *, required: bool) -> TypeMix | None:
    if raw is None:
        if required:
            raise LoadProfileError(f"{where}: a [load.mix] table is required")
        return None
    if not isinstance(raw, dict) or not raw:
        raise LoadProfileError(f"{where}: must be a non-empty table of type→weight")
    weights: dict[str, float] = {}
    for key, value in raw.items():
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise LoadProfileError(f"{where}: weight for {key!r} must be a non-negative number")
        weights[key] = float(value)
    if sum(weights.values()) <= 0.0:
        raise LoadProfileError(f"{where}: weights must sum to a positive number")
    return TypeMix(weights)


def _slo_from(raw: Any, where: str) -> Slo | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise LoadProfileError(f"{where}: must be a table")
    _reject_unknown(raw, _SLO_KEYS, where)
    return Slo(
        min_sustained_msg_s=_opt_float_or_none(raw, "min_sustained_msg_s", where, minimum=0.0),
        max_ack_p99_ms=_opt_float_or_none(raw, "max_ack_p99_ms", where, minimum=0.0),
        max_e2e_p99_ms=_opt_float_or_none(raw, "max_e2e_p99_ms", where, minimum=0.0),
        max_error_rate=_opt_float_or_none(raw, "max_error_rate", where, minimum=0.0, maximum=1.0),
        max_nak_rate=_opt_float_or_none(raw, "max_nak_rate", where, minimum=0.0, maximum=1.0),
        max_dup_rate=_opt_float_or_none(raw, "max_dup_rate", where, minimum=0.0, maximum=1.0),
        max_dead_letters=_opt_int_or_none(raw, "max_dead_letters", where, minimum=0),
        max_drain_seconds=_opt_float_or_none(raw, "max_drain_seconds", where, minimum=0.0),
        zero_loss=_opt_bool(raw, "zero_loss", where, default=False),
    )


def _as_tables(value: Any, where: str) -> list[dict[str, Any]]:
    if value == []:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise LoadProfileError(f"{where}: must be an array of tables")
    return value


def _reject_unknown(table: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    extra = set(table) - allowed
    if extra:
        raise LoadProfileError(
            f"{where}: unknown key(s) {', '.join(sorted(extra))} (allowed: {', '.join(sorted(allowed))})"
        )


def _req_str(table: dict[str, Any], key: str, where: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise LoadProfileError(f"{where}: {key!r} must be a non-empty string")
    return value


def _opt_str(table: dict[str, Any], key: str, where: str) -> str | None:
    if key not in table:
        return None
    value = table[key]
    if not isinstance(value, str):
        raise LoadProfileError(f"{where}: {key!r} must be a string")
    return value


def _opt_str_tuple(table: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    if key not in table:
        return ()
    value = table[key]
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise LoadProfileError(f"{where}: {key!r} must be a list of non-empty strings")
    return tuple(value)


def _opt_bool(table: dict[str, Any], key: str, where: str, *, default: bool) -> bool:
    if key not in table:
        return default
    value = table[key]
    if not isinstance(value, bool):
        raise LoadProfileError(f"{where}: {key!r} must be true or false")
    return value


def _num(value: Any, key: str, where: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise LoadProfileError(f"{where}: {key!r} must be a number")
    return float(value)


def _bounded(
    value: float,
    key: str,
    where: str,
    *,
    minimum: float | None,
    maximum: float | None,
    exclusive_min: bool,
) -> float:
    if minimum is not None and (value <= minimum if exclusive_min else value < minimum):
        rel = ">" if exclusive_min else ">="
        raise LoadProfileError(f"{where}: {key!r} must be {rel} {minimum}")
    if maximum is not None and value > maximum:
        raise LoadProfileError(f"{where}: {key!r} must be <= {maximum}")
    return value


def _req_float(
    table: dict[str, Any],
    key: str,
    where: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
    exclusive_min: bool = False,
) -> float:
    if key not in table:
        raise LoadProfileError(f"{where}: missing required key {key!r}")
    return _bounded(
        _num(table[key], key, where),
        key,
        where,
        minimum=minimum,
        maximum=maximum,
        exclusive_min=exclusive_min,
    )


def _opt_float(
    table: dict[str, Any],
    key: str,
    where: str,
    *,
    default: float,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if key not in table:
        return default
    return _bounded(
        _num(table[key], key, where),
        key,
        where,
        minimum=minimum,
        maximum=maximum,
        exclusive_min=False,
    )


def _opt_float_or_none(
    table: dict[str, Any],
    key: str,
    where: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float | None:
    if key not in table or table[key] is None:
        return None
    return _bounded(
        _num(table[key], key, where),
        key,
        where,
        minimum=minimum,
        maximum=maximum,
        exclusive_min=False,
    )


def _opt_int(
    table: dict[str, Any],
    key: str,
    where: str,
    *,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if key not in table:
        return default
    return _int_value(table[key], key, where, minimum=minimum, maximum=maximum)


def _opt_int_or_none(
    table: dict[str, Any], key: str, where: str, *, minimum: int | None = None
) -> int | None:
    if key not in table or table[key] is None:
        return None
    return _int_value(table[key], key, where, minimum=minimum, maximum=None)


def _int_value(
    value: Any, key: str, where: str, *, minimum: int | None, maximum: int | None
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise LoadProfileError(f"{where}: {key!r} must be an integer")
    if minimum is not None and value < minimum:
        raise LoadProfileError(f"{where}: {key!r} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise LoadProfileError(f"{where}: {key!r} must be <= {maximum}")
    return value
