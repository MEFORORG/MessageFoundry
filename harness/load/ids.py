"""The control-id ↔ sequence-number scheme shared by the sender, sink, and corpus.

Each sent message gets a dense, monotonic sequence number encoded into MSH-10 as
``f"{prefix}{seq:0{width}d}"``. The prefix is run-scoped (so a re-run against a long-lived DB can't
collide with a prior run's ids) and restricted to ASCII alphanumerics — safe in an MSH-10 field and
never an HL7 separator. Dense integer sequences let the correlator use an O(1) ring instead of a hash
map, and make the id trivially reversible at the sink.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ControlIds:
    """Format/parse run-unique control ids from a dense sequence number."""

    prefix: str
    width: int = 12

    def __post_init__(self) -> None:
        if not self.prefix or not self.prefix.isascii() or not self.prefix.isalnum():
            raise ValueError(
                f"control-id prefix must be non-empty ASCII alphanumerics: {self.prefix!r}"
            )
        if self.width < 1:
            raise ValueError("control-id width must be >= 1")

    def format(self, seq: int) -> str:
        return f"{self.prefix}{seq:0{self.width}d}"

    def parse(self, control_id: str | None) -> int | None:
        """Recover the sequence number from a control id, or ``None`` if it isn't one of ours."""
        if not control_id or not control_id.startswith(self.prefix):
            return None
        tail = control_id[len(self.prefix) :]
        if not tail.isdigit():
            return None
        return int(tail)
