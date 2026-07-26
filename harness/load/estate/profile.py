# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Estate run profiles — authored as **data** (TOML), parsed into a frozen dataclass (#216).

An estate profile names the connection count, the simple/hub split, the hub fan-out, and the
per-connection **event** rate the driver calibrates to (with the total event rate derivable from
``per_conn_event_rate × count``), plus the hold/connect/drain timings.

The two calibration constants — ``simple_fraction`` and ``hub_fanout`` — describe the *shape* of the
estate and MUST come from the estate recon, not a guess; the profile documents their provenance and the
demo is owner-signed-off before it is run. Parsing only proves the numbers are internally CONSISTENT
(the event-rate ↔ count × per-conn-rate identity, the fraction/fanout bounds); it can never prove the
real-world shape. Parsing fails loud on a missing/typo'd/wrong-typed key (mirroring the connscale + load
profiles), so a broken profile is rejected before any engine is spawned.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROFILES_DIR = Path(__file__).resolve().parents[1] / "profiles"

#: How close ``total_event_rate`` and ``per_conn_event_rate × count`` must agree (relative) when BOTH
#: are given — a hand-authored profile that states both must be self-consistent, else it is rejected.
_EVENT_RATE_CONSISTENCY_REL = 0.01

_ESTATE_KEYS = frozenset(
    {
        "name",
        "description",
        "count",
        "simple_fraction",
        "hub_fanout",
        "per_conn_event_rate",
        "total_event_rate",
        "hold_seconds",
        "connect_batch",
        "connect_batch_pause_s",
        "poll_interval_s",
        "drain_timeout_s",
        "base_port",
        "transform",
        "store_backend",
        "corpus_count_per_trigger",
        "correlator_capacity",
        "seed",
        "slo",
    }
)
_SLO_KEYS = frozenset({"zero_loss", "max_drain_seconds"})


class EstateProfileError(ValueError):
    """A malformed or self-inconsistent estate profile."""


@dataclass(frozen=True)
class EstateSlo:
    """Pass/fail thresholds for an estate run. ``None``/``False`` fields are not checked."""

    zero_loss: bool = True  # every sent message must be received + delivered, backlog drained
    max_drain_seconds: float | None = None


@dataclass(frozen=True)
class EstateProfile:
    """A complete, validated estate run definition."""

    name: str
    description: str
    count: int  # total inbound connections
    simple_fraction: float  # fraction of connections that are simple pass-through (rest are hubs)
    hub_fanout: int  # outbound destinations each hub fans to
    per_conn_event_rate: float  # target events/sec/connection (the calibration budget)
    hold_seconds: float  # steady-state hold (where the achieved shape is read)
    connect_batch: int  # connections opened per batch (avoid a connect storm)
    connect_batch_pause_s: float  # pause between connect batches
    poll_interval_s: float  # engine sampling cadence
    drain_timeout_s: float
    base_port: int  # first inbound MLLP port (conn i binds base_port + i)
    transform: str  # cheap | edit (the engine graph's MEFOR_ESTATE_TRANSFORM)
    store_backend: str | None  # None=sqlite (CI smoke), "postgres"|"sqlserver" for a real run
    corpus_count_per_trigger: int
    correlator_capacity: int
    seed: str
    slo: EstateSlo = field(default_factory=EstateSlo)

    @property
    def total_event_rate(self) -> float:
        """The target aggregate event rate — ``per_conn_event_rate × count``. This is the demo target
        (e.g. ~520 ev/s); the driver's offered *message* rate is derived separately from the topology."""
        return self.per_conn_event_rate * self.count

    def simple_count(self) -> int:
        """Connections that are simple (the rest are hubs) — the topology-by-COUNT split, from the SAME
        rounding rule the served graph uses."""
        from harness.config.estate._shape import simple_count

        return simple_count(self.count, self.simple_fraction)

    def hub_count(self) -> int:
        return self.count - self.simple_count()


def load_estate_profile(path: Path | str) -> EstateProfile:
    """Parse an estate profile TOML file. Raises :class:`EstateProfileError` on a problem. Tolerant of a
    leading UTF-8 BOM (PowerShell ``Set-Content -Encoding utf8`` prepends one, which bare ``tomllib``
    rejects with an opaque parse error)."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise EstateProfileError(f"cannot read {p.name}: {exc}") from exc
    try:
        text = raw.decode("utf-8-sig")  # strips a UTF-8 BOM if present; still enforces UTF-8
    except UnicodeDecodeError as exc:
        raise EstateProfileError(f"cannot read {p.name}: not valid UTF-8 ({exc})") from exc
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise EstateProfileError(f"cannot read {p.name}: {exc}") from exc
    return _profile_from_data(data, where=p.name)


def load_estate_profile_text(text: str, *, where: str = "<text>") -> EstateProfile:
    """Parse a profile from a TOML string (for tests). Tolerates a leading BOM character."""
    try:
        data = tomllib.loads(text.removeprefix("﻿"))
    except tomllib.TOMLDecodeError as exc:
        raise EstateProfileError(f"{where}: {exc}") from exc
    return _profile_from_data(data, where=where)


def list_estate_profiles() -> dict[str, str]:
    """Built-in profile name → description, read from the estate profile TOMLs (``estate*.toml``). Keep
    the glob in step with ``tests/test_load_config.py::test_all_shipped_profiles_parse`` (which EXCLUDES
    the same set — an estate-schema profile is not a [load] profile)."""
    out: dict[str, str] = {}
    for path in sorted(PROFILES_DIR.glob("estate*.toml")):
        try:
            prof = load_estate_profile(path)
            out[prof.name] = prof.description
        except EstateProfileError:
            out[path.stem] = "(invalid profile)"
    return out


def get_estate_profile(name_or_path: str) -> EstateProfile:
    """Resolve a built-in profile name or a filesystem path to an :class:`EstateProfile`."""
    candidate = Path(name_or_path)
    if candidate.exists():
        return load_estate_profile(candidate)
    builtin = PROFILES_DIR / f"{name_or_path}.toml"
    if builtin.exists():
        return load_estate_profile(builtin)
    choices = ", ".join(sorted(list_estate_profiles())) or "(none)"
    raise EstateProfileError(f"unknown estate profile {name_or_path!r}; built-ins: {choices}")


def _profile_from_data(data: dict[str, Any], *, where: str) -> EstateProfile:
    extra = set(data) - {"estate"}
    if extra:
        raise EstateProfileError(f"{where}: unknown top-level key(s) {', '.join(sorted(extra))}")
    es = data.get("estate")
    if not isinstance(es, dict):
        raise EstateProfileError(f"{where}: missing [estate] table")
    _reject_unknown(es, _ESTATE_KEYS, f"{where} [estate]")

    name = _req_str(es, "name", f"{where} [estate]")
    count = _opt_int(es, "count", f"{where} [estate]", default=1500, minimum=1, maximum=5000)
    simple_fraction = _opt_float(
        es, "simple_fraction", f"{where} [estate]", default=0.72, minimum=0.0, maximum=1.0
    )
    hub_fanout = _opt_int(es, "hub_fanout", f"{where} [estate]", default=3, minimum=1, maximum=256)
    per_conn_event_rate = _opt_float(
        es, "per_conn_event_rate", f"{where} [estate]", default=0.347, minimum=0.0
    )
    transform = (_opt_str(es, "transform", f"{where} [estate]") or "cheap").strip().lower()
    if transform not in ("cheap", "edit"):
        raise EstateProfileError(
            f"{where} [estate]: transform {transform!r} must be 'cheap' or 'edit'"
        )
    store_backend = _opt_str(es, "store_backend", f"{where} [estate]")
    if store_backend is not None:
        store_backend = store_backend.strip().lower()
        if store_backend not in ("sqlite", "postgres", "sqlserver"):
            raise EstateProfileError(
                f"{where} [estate]: store_backend {store_backend!r} must be sqlite|postgres|sqlserver"
            )
        if store_backend == "sqlite":
            store_backend = (
                None  # None == sqlite (the default); normalize so the runner branches once
            )

    profile = EstateProfile(
        name=name,
        description=_opt_str(es, "description", f"{where} [estate]") or "",
        count=count,
        simple_fraction=simple_fraction,
        hub_fanout=hub_fanout,
        per_conn_event_rate=per_conn_event_rate,
        hold_seconds=_opt_float(es, "hold_seconds", f"{where} [estate]", default=60.0, minimum=0.1),
        connect_batch=_opt_int(es, "connect_batch", f"{where} [estate]", default=50, minimum=1),
        connect_batch_pause_s=_opt_float(
            es, "connect_batch_pause_s", f"{where} [estate]", default=0.05, minimum=0.0
        ),
        poll_interval_s=_opt_float(
            es, "poll_interval_s", f"{where} [estate]", default=1.0, minimum=0.05
        ),
        drain_timeout_s=_opt_float(
            es, "drain_timeout_s", f"{where} [estate]", default=120.0, minimum=0.0
        ),
        base_port=_opt_int(
            es, "base_port", f"{where} [estate]", default=2600, minimum=1, maximum=65535
        ),
        transform=transform,
        store_backend=store_backend,
        corpus_count_per_trigger=_opt_int(
            es, "corpus_count_per_trigger", f"{where} [estate]", default=20, minimum=1
        ),
        correlator_capacity=_opt_int(
            es, "correlator_capacity", f"{where} [estate]", default=2_000_000, minimum=1
        ),
        seed=_opt_str(es, "seed", f"{where} [estate]") or "messagefoundry-estate",
        slo=_slo_from(es.get("slo"), f"{where} [estate.slo]"),
    )
    _validate(profile, es, where)
    return profile


def _validate(profile: EstateProfile, es: dict[str, Any], where: str) -> None:
    # The inbound port block [base_port, base_port + count) must fit in the port space.
    top = profile.base_port + profile.count - 1
    if top > 65535:
        raise EstateProfileError(
            f"{where}: base_port {profile.base_port} + count {profile.count} runs past port 65535 "
            f"(highest inbound port would be {top})"
        )
    if profile.per_conn_event_rate <= 0.0:
        raise EstateProfileError(f"{where}: per_conn_event_rate must be positive")
    # If the author ALSO states total_event_rate, it must agree with per_conn_event_rate × count —
    # otherwise the profile carries two contradictory targets and one would silently win. Parsing can
    # only prove this internal consistency, never the real-world shape (owner sign-off, see the docstring).
    if "total_event_rate" in es:
        stated = _opt_float(es, "total_event_rate", where, default=0.0, minimum=0.0)
        derived = profile.total_event_rate
        if derived <= 0.0 or abs(stated - derived) > _EVENT_RATE_CONSISTENCY_REL * derived:
            raise EstateProfileError(
                f"{where}: total_event_rate {stated} is inconsistent with per_conn_event_rate "
                f"{profile.per_conn_event_rate} × count {profile.count} = {derived:.3f} "
                f"(must agree within {_EVENT_RATE_CONSISTENCY_REL:.0%}); drop one, or fix the other"
            )


def _slo_from(raw: Any, where: str) -> EstateSlo:
    if raw is None:
        return EstateSlo()
    if not isinstance(raw, dict):
        raise EstateProfileError(f"{where}: must be a table")
    _reject_unknown(raw, _SLO_KEYS, where)
    return EstateSlo(
        zero_loss=_opt_bool(raw, "zero_loss", where, default=True),
        max_drain_seconds=_opt_float_or_none(raw, "max_drain_seconds", where, minimum=0.0),
    )


# --- decoding helpers (mirror harness/load/connscale/profile.py's fail-loud style) ------


def _reject_unknown(table: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    extra = set(table) - allowed
    if extra:
        raise EstateProfileError(
            f"{where}: unknown key(s) {', '.join(sorted(extra))} (allowed: {', '.join(sorted(allowed))})"
        )


def _req_str(table: dict[str, Any], key: str, where: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise EstateProfileError(f"{where}: {key!r} must be a non-empty string")
    return value


def _opt_str(table: dict[str, Any], key: str, where: str) -> str | None:
    if key not in table:
        return None
    value = table[key]
    if not isinstance(value, str):
        raise EstateProfileError(f"{where}: {key!r} must be a string")
    return value


def _opt_bool(table: dict[str, Any], key: str, where: str, *, default: bool) -> bool:
    if key not in table:
        return default
    value = table[key]
    if not isinstance(value, bool):
        raise EstateProfileError(f"{where}: {key!r} must be true or false")
    return value


def _num(value: Any, key: str, where: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise EstateProfileError(f"{where}: {key!r} must be a number")
    return float(value)


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
    value = _num(table[key], key, where)
    if minimum is not None and value < minimum:
        raise EstateProfileError(f"{where}: {key!r} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise EstateProfileError(f"{where}: {key!r} must be <= {maximum}")
    return value


def _opt_float_or_none(
    table: dict[str, Any], key: str, where: str, *, minimum: float | None = None
) -> float | None:
    if key not in table or table[key] is None:
        return None
    value = _num(table[key], key, where)
    if minimum is not None and value < minimum:
        raise EstateProfileError(f"{where}: {key!r} must be >= {minimum}")
    return value


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
    value = table[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise EstateProfileError(f"{where}: {key!r} must be an integer")
    if minimum is not None and value < minimum:
        raise EstateProfileError(f"{where}: {key!r} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise EstateProfileError(f"{where}: {key!r} must be <= {maximum}")
    return value
