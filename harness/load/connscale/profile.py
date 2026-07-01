# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale run profiles — authored as **data** (TOML), parsed into a frozen dataclass (B11).

A connection-scale profile names the connection counts to sweep (500 / 1000 / 1500, or the CI smoke's
50 / 100), the per-connection / aggregate rate, the sweep mode(s), and the hold/ramp/drain timings.
Both sweep modes run by default:

* ``fixed_aggregate`` — the SAME aggregate rate ``R`` at every N (per-connection rate falls as N
  rises). Isolates the *cost of idle connection count* — and IS the thundering-herd measurement: at a
  constant aggregate rate the only thing rising with N is workers-woken-but-idle, so the
  wake-fanout empty-claim slope vs N is the per-commit herd cost.
* ``fixed_per_conn`` — the SAME per-connection rate at every N (aggregate rises with N). Isolates the
  *combined* load+scale wall (pool-wait, executor-queue depth under real work).

Parsing fails loud on a missing/typo'd/wrong-typed key (mirroring the load profile + connections.toml),
so a broken profile is rejected before any engine is spawned. All numbers are generic and synthetic.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROFILES_DIR = Path(__file__).resolve().parents[1] / "profiles"

#: Sweep modes. ``both`` runs ``fixed_aggregate`` then ``fixed_per_conn``.
FIXED_AGGREGATE = "fixed_aggregate"
FIXED_PER_CONN = "fixed_per_conn"
SWEEP_MODES = frozenset({FIXED_AGGREGATE, FIXED_PER_CONN, "both"})

_CONNSCALE_KEYS = frozenset(
    {
        "name",
        "description",
        "counts",
        "per_conn_rate",
        "aggregate_rate",
        "sweep_mode",
        "hold_seconds",
        "connect_batch",
        "connect_batch_pause_s",
        "poll_interval_s",
        "drain_timeout_s",
        "base_port",
        "transform",
        "reload_probe",
        "store_backend",
        "corpus_count_per_trigger",
        "correlator_capacity",
        "seed",
        "slo",
    }
)
_SLO_KEYS = frozenset(
    {
        "zero_loss",
        "max_drain_seconds",
        "fd_monotonic",
        "empty_claims_monotonic",
    }
)


class ConnScaleProfileError(ValueError):
    """A malformed or self-inconsistent connection-scale profile."""


@dataclass(frozen=True)
class ConnScaleSlo:
    """Pass/fail thresholds for a connection-scale run. ``None``/``False`` fields are not checked."""

    zero_loss: bool = True  # every sent message must be received + delivered, backlog drained
    max_drain_seconds: float | None = None
    # Loose monotonicity smokes (CI): FD count and empty-claims/sec at a larger N must be >= a smaller
    # N (the wall exists and scales). A `>=` check, not a tight threshold (CI runners are noisy).
    fd_monotonic: bool = False
    empty_claims_monotonic: bool = False


@dataclass(frozen=True)
class ConnScaleProfile:
    """A complete, validated connection-scale run definition."""

    name: str
    description: str
    counts: tuple[int, ...]  # the connection-count sweep (e.g. 500, 1000, 1500)
    per_conn_rate: float  # target msg/s per connection (used by fixed_per_conn)
    aggregate_rate: float  # target total msg/s held constant across N (used by fixed_aggregate)
    sweep_mode: str  # fixed_aggregate | fixed_per_conn | both
    hold_seconds: float  # steady-state hold per N (where the curve is read)
    connect_batch: int  # connections opened per batch (avoid a connect storm)
    connect_batch_pause_s: float  # pause between connect batches
    poll_interval_s: float  # engine + FD sampling cadence
    drain_timeout_s: float
    base_port: int  # first inbound MLLP port (conn i binds base_port + i)
    transform: str  # cheap | edit (the engine graph's MEFOR_CONNSCALE_TRANSFORM)
    reload_probe: bool  # time a grow-reload (wall #5)
    store_backend: str | None  # None=sqlite (CI smoke), "postgres"|"sqlserver" for the real walls
    corpus_count_per_trigger: int
    correlator_capacity: int
    seed: str
    slo: ConnScaleSlo = field(default_factory=ConnScaleSlo)

    def modes(self) -> tuple[str, ...]:
        """The sweep modes to run (``both`` expands to both, in a stable order)."""
        if self.sweep_mode == "both":
            return (FIXED_AGGREGATE, FIXED_PER_CONN)
        return (self.sweep_mode,)

    def aggregate_rate_for(self, mode: str, count: int) -> float:
        """The offered aggregate rate (msg/s) for ``mode`` at connection count ``count``.

        ``fixed_aggregate`` holds ``aggregate_rate`` constant across N (per-conn rate falls);
        ``fixed_per_conn`` scales the aggregate with N (``per_conn_rate × count``)."""
        if mode == FIXED_AGGREGATE:
            return self.aggregate_rate
        return self.per_conn_rate * count


def load_connscale_profile(path: Path | str) -> ConnScaleProfile:
    """Parse a connection-scale profile TOML file. Raises :class:`ConnScaleProfileError` on a problem."""
    p = Path(path)
    try:
        with open(p, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConnScaleProfileError(f"cannot read {p.name}: {exc}") from exc
    return _profile_from_data(data, where=p.name)


def load_connscale_profile_text(text: str, *, where: str = "<text>") -> ConnScaleProfile:
    """Parse a profile from a TOML string (for tests)."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConnScaleProfileError(f"{where}: {exc}") from exc
    return _profile_from_data(data, where=where)


def list_connscale_profiles() -> dict[str, str]:
    """Built-in profile name → description, read from ``harness/load/profiles/connscale*.toml``."""
    out: dict[str, str] = {}
    for path in sorted(PROFILES_DIR.glob("connscale*.toml")):
        try:
            prof = load_connscale_profile(path)
            out[prof.name] = prof.description
        except ConnScaleProfileError:
            out[path.stem] = "(invalid profile)"
    return out


def get_connscale_profile(name_or_path: str) -> ConnScaleProfile:
    """Resolve a built-in profile name or a filesystem path to a :class:`ConnScaleProfile`."""
    candidate = Path(name_or_path)
    if candidate.exists():
        return load_connscale_profile(candidate)
    builtin = PROFILES_DIR / f"{name_or_path}.toml"
    if builtin.exists():
        return load_connscale_profile(builtin)
    choices = ", ".join(sorted(list_connscale_profiles())) or "(none)"
    raise ConnScaleProfileError(f"unknown connscale profile {name_or_path!r}; built-ins: {choices}")


def _profile_from_data(data: dict[str, Any], *, where: str) -> ConnScaleProfile:
    extra = set(data) - {"connscale"}
    if extra:
        raise ConnScaleProfileError(f"{where}: unknown top-level key(s) {', '.join(sorted(extra))}")
    cs = data.get("connscale")
    if not isinstance(cs, dict):
        raise ConnScaleProfileError(f"{where}: missing [connscale] table")
    _reject_unknown(cs, _CONNSCALE_KEYS, f"{where} [connscale]")

    name = _req_str(cs, "name", f"{where} [connscale]")
    counts = _counts_from(cs.get("counts"), f"{where} [connscale]")
    sweep_mode = (_opt_str(cs, "sweep_mode", f"{where} [connscale]") or "both").strip().lower()
    if sweep_mode not in SWEEP_MODES:
        raise ConnScaleProfileError(
            f"{where} [connscale]: sweep_mode {sweep_mode!r} not in {sorted(SWEEP_MODES)}"
        )
    transform = (_opt_str(cs, "transform", f"{where} [connscale]") or "cheap").strip().lower()
    if transform not in ("cheap", "edit"):
        raise ConnScaleProfileError(
            f"{where} [connscale]: transform {transform!r} must be 'cheap' or 'edit'"
        )
    store_backend = _opt_str(cs, "store_backend", f"{where} [connscale]")
    if store_backend is not None:
        store_backend = store_backend.strip().lower()
        if store_backend not in ("sqlite", "postgres", "sqlserver"):
            raise ConnScaleProfileError(
                f"{where} [connscale]: store_backend {store_backend!r} must be sqlite|postgres|sqlserver"
            )
        if store_backend == "sqlite":
            store_backend = (
                None  # None == sqlite (the default); normalize so the runner branches once
            )

    profile = ConnScaleProfile(
        name=name,
        description=_opt_str(cs, "description", f"{where} [connscale]") or "",
        counts=counts,
        per_conn_rate=_opt_float(
            cs, "per_conn_rate", f"{where} [connscale]", default=0.35, minimum=0.0
        ),
        aggregate_rate=_opt_float(
            cs, "aggregate_rate", f"{where} [connscale]", default=521.0, minimum=0.0
        ),
        sweep_mode=sweep_mode,
        hold_seconds=_opt_float(
            cs, "hold_seconds", f"{where} [connscale]", default=30.0, minimum=0.1
        ),
        connect_batch=_opt_int(cs, "connect_batch", f"{where} [connscale]", default=50, minimum=1),
        connect_batch_pause_s=_opt_float(
            cs, "connect_batch_pause_s", f"{where} [connscale]", default=0.05, minimum=0.0
        ),
        poll_interval_s=_opt_float(
            cs, "poll_interval_s", f"{where} [connscale]", default=1.0, minimum=0.05
        ),
        drain_timeout_s=_opt_float(
            cs, "drain_timeout_s", f"{where} [connscale]", default=120.0, minimum=0.0
        ),
        base_port=_opt_int(
            cs, "base_port", f"{where} [connscale]", default=2600, minimum=1, maximum=65535
        ),
        transform=transform,
        reload_probe=_opt_bool(cs, "reload_probe", f"{where} [connscale]", default=False),
        store_backend=store_backend,
        corpus_count_per_trigger=_opt_int(
            cs, "corpus_count_per_trigger", f"{where} [connscale]", default=20, minimum=1
        ),
        correlator_capacity=_opt_int(
            cs, "correlator_capacity", f"{where} [connscale]", default=1_000_000, minimum=1
        ),
        seed=_opt_str(cs, "seed", f"{where} [connscale]") or "messagefoundry-connscale",
        slo=_slo_from(cs.get("slo"), f"{where} [connscale.slo]"),
    )
    _validate(profile, where)
    return profile


def _validate(profile: ConnScaleProfile, where: str) -> None:
    if profile.aggregate_rate <= 0.0 and profile.per_conn_rate <= 0.0:
        raise ConnScaleProfileError(
            f"{where}: at least one of aggregate_rate / per_conn_rate must be positive"
        )
    # The inbound port block [base_port, base_port + max(counts)) must fit in the port space.
    top = profile.base_port + max(profile.counts) - 1
    if top > 65535:
        raise ConnScaleProfileError(
            f"{where}: base_port {profile.base_port} + max count {max(profile.counts)} runs past "
            f"port 65535 (highest inbound port would be {top})"
        )


def _counts_from(raw: Any, where: str) -> tuple[int, ...]:
    if not isinstance(raw, list) or not raw:
        raise ConnScaleProfileError(f"{where}: 'counts' must be a non-empty list of integers")
    counts: list[int] = []
    for item in raw:
        if not isinstance(item, int) or isinstance(item, bool) or item < 1:
            raise ConnScaleProfileError(f"{where}: every 'counts' entry must be an integer >= 1")
        counts.append(item)
    return tuple(counts)


def _slo_from(raw: Any, where: str) -> ConnScaleSlo:
    if raw is None:
        return ConnScaleSlo()
    if not isinstance(raw, dict):
        raise ConnScaleProfileError(f"{where}: must be a table")
    _reject_unknown(raw, _SLO_KEYS, where)
    return ConnScaleSlo(
        zero_loss=_opt_bool(raw, "zero_loss", where, default=True),
        max_drain_seconds=_opt_float_or_none(raw, "max_drain_seconds", where, minimum=0.0),
        fd_monotonic=_opt_bool(raw, "fd_monotonic", where, default=False),
        empty_claims_monotonic=_opt_bool(raw, "empty_claims_monotonic", where, default=False),
    )


# --- decoding helpers (mirror harness/load/profile.py's fail-loud style) ------


def _reject_unknown(table: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    extra = set(table) - allowed
    if extra:
        raise ConnScaleProfileError(
            f"{where}: unknown key(s) {', '.join(sorted(extra))} (allowed: {', '.join(sorted(allowed))})"
        )


def _req_str(table: dict[str, Any], key: str, where: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ConnScaleProfileError(f"{where}: {key!r} must be a non-empty string")
    return value


def _opt_str(table: dict[str, Any], key: str, where: str) -> str | None:
    if key not in table:
        return None
    value = table[key]
    if not isinstance(value, str):
        raise ConnScaleProfileError(f"{where}: {key!r} must be a string")
    return value


def _opt_bool(table: dict[str, Any], key: str, where: str, *, default: bool) -> bool:
    if key not in table:
        return default
    value = table[key]
    if not isinstance(value, bool):
        raise ConnScaleProfileError(f"{where}: {key!r} must be true or false")
    return value


def _num(value: Any, key: str, where: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConnScaleProfileError(f"{where}: {key!r} must be a number")
    return float(value)


def _opt_float(
    table: dict[str, Any], key: str, where: str, *, default: float, minimum: float | None = None
) -> float:
    if key not in table:
        return default
    value = _num(table[key], key, where)
    if minimum is not None and value < minimum:
        raise ConnScaleProfileError(f"{where}: {key!r} must be >= {minimum}")
    return value


def _opt_float_or_none(
    table: dict[str, Any], key: str, where: str, *, minimum: float | None = None
) -> float | None:
    if key not in table or table[key] is None:
        return None
    value = _num(table[key], key, where)
    if minimum is not None and value < minimum:
        raise ConnScaleProfileError(f"{where}: {key!r} must be >= {minimum}")
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
        raise ConnScaleProfileError(f"{where}: {key!r} must be an integer")
    if minimum is not None and value < minimum:
        raise ConnScaleProfileError(f"{where}: {key!r} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ConnScaleProfileError(f"{where}: {key!r} must be <= {maximum}")
    return value
