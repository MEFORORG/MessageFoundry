# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Platform memory-encryption **read-out** — report-only, and NOT evidence (ADR 0152, Phase 1).

READ THIS BEFORE CITING ANYTHING THIS MODULE PRODUCES.

ASVS 11.7.1 asks for *full memory encryption ... that protects sensitive data while it is in use*.
Nothing in this module satisfies it, contributes to satisfying it, or may be quoted as though it
did. What this module does is read what the local platform **says about itself** and hand that
back, labelled, so an operator or assessor can see the deployment they believe they have.

**Why a self-report is not evidence.** ``/proc/cpuinfo``, sysfs entries and device-node presence are
all produced by the operating system — the very component whose integrity a confidential-computing
control exists to protect against. A compromised kernel or hypervisor forges every one of them at no
cost. Only a **CPU-signed attestation report verified against the silicon vendor's root PKI** (AMD
SEV-SNP ``SNP_GET_REPORT`` verified through the VCEK/ASK/ARK chain, Intel TDX quote verification) is
evidence rather than assertion, and that is ADR 0152 rung 3 — deliberately **not built here**.

**Capability and activation are different facts and are reported as different fields.** A CPU flag
says the silicon *can* encrypt memory. It says nothing whatsoever about whether *this* guest is
running inside an encrypted VM — a SEV-capable host runs unencrypted guests all day. The guest
device node (``/dev/sev-guest``, ``/dev/tdx_guest``) is the signal that this guest is attached to a
confidential-computing platform. Conflating the two is the single most likely way this read-out gets
misused, so :class:`MemoryEncryptionReadout` refuses to fuse them into one boolean, and no code path
here ever infers activation from a CPU model or a CPU flag.

**Windows reports nothing.** ADR 0152 makes the Windows in-guest attestation path a time-boxed spike
that has not landed. Rather than guess, every field is ``None`` (undeterminable) there. That is the
honest answer on the platform this engine primarily ships on, and it is deliberately *not* softened.

Pure and stdlib-only: no engine state, no configuration, no network, and no I/O beyond reading the
platform files named above. Never raises — an unreadable platform yields ``None``, never an
exception and never a default of ``False`` dressed up as a measurement.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from functools import cache
from pathlib import Path

__all__ = [
    "GUEST_ATTESTABLE_MECHANISMS",
    "GUEST_DEVICES",
    "MEMORY_ENCRYPTION_FLAGS",
    "READOUT_DISCLAIMER",
    "MemoryEncryptionReadout",
    "platform_memory_encryption_readout",
]

#: The single sentence that must travel WITH every surface this feature produces — the posture body,
#: the startup strings, the console. Kept as one constant for the same reason
#: :data:`~messagefoundry.crashdump.RESIDUAL_MACHINE_POLICY` is: a disclaimer that lives only in a
#: docstring, an ADR or a comment reaches nobody who reads the output. ADR 0152 designates
#: ``GET /security/posture`` the evidence artifact for this control, so the artifact carries its own
#: limits rather than relying on the reader having read the ADR.
READOUT_DISCLAIMER = (
    "This is a self-report from the host OS plus, where set, an unverified operator declaration. "
    "Neither is attestation and neither satisfies ASVS 11.7.1 at any value: only a CPU-signed "
    "attestation report verified against the silicon vendor's root PKI would, and that is ADR 0152 "
    "rung 3, which is not built."
)

#: Linux ``/proc/cpuinfo`` flags that advertise a memory-encryption *capability*, mapped to the
#: mechanism name reported. Ordered strongest-first: SEV-SNP (integrity-protected, attestable) beats
#: SEV-ES beats SEV beats SME (host-side transparent encryption, no guest isolation). ``tdx_guest`` is
#: the guest-visible Intel TDX flag. NONE of these implies the flagged feature is IN USE here.
MEMORY_ENCRYPTION_FLAGS: tuple[tuple[str, str], ...] = (
    ("sev_snp", "amd-sev-snp"),
    ("tdx_guest", "intel-tdx"),
    ("sev_es", "amd-sev-es"),
    ("sev", "amd-sev"),
    ("sme", "amd-sme"),
)

#: Guest device nodes whose presence indicates THIS guest is attached to a confidential-computing
#: platform (and is the interface rung 3 would later use to request a signed attestation report).
#: Mapped to the mechanism they belong to, strongest-first.
GUEST_DEVICES: tuple[tuple[str, str], ...] = (
    ("/dev/sev-guest", "amd-sev-snp"),
    ("/dev/tdx_guest", "intel-tdx"),
)

#: The mechanisms that HAVE a guest interface at all, so their absence is a fact rather than a
#: silence. SEV-SNP and TDX isolate a *guest* and expose a device node for it; AMD SME and Intel TME
#: encrypt all DRAM at the memory controller and have **no guest-visible activation signal whatever**
#: — which makes SME/TME simultaneously the most literal reading of 11.7.1's "full memory encryption"
#: and the mechanism this read-out can never confirm. Absence of a device node therefore means
#: "not there" ONLY when the host advertised a mechanism that would have one; everywhere else it
#: means "we cannot tell", and :attr:`MemoryEncryptionReadout.contradicts_declaration` says ``None``.
GUEST_ATTESTABLE_MECHANISMS: frozenset[str] = frozenset({"amd-sev-snp", "intel-tdx"})

#: ``/proc/cpuinfo`` "flags" / "Features" lines split on whitespace. Compiled once; the file is read
#: at most once per posture request.
_FLAGS_LINE = re.compile(r"^(?:flags|Features)\s*:\s*(.*)$", re.MULTILINE)

_CPUINFO = "/proc/cpuinfo"


@dataclass(frozen=True, slots=True)
class MemoryEncryptionReadout:
    """What the local platform SAYS about memory encryption. A self-report, not an attestation.

    Three deliberately separate facts, because collapsing them is how a read-out becomes a false
    compliance claim:

    * :attr:`capability` — the CPU advertises a memory-encryption feature. ``True`` means the silicon
      *can*; it does **not** mean this guest is encrypted. ``None`` = undeterminable.
    * :attr:`active` — a confidential-guest device node is present, i.e. this guest *is* attached to
      such a platform. ``None`` = undeterminable (Windows, or a platform we do not read).
    * :attr:`mechanism` — the strongest mechanism observed, e.g. ``"amd-sev-snp"``; ``None`` when
      nothing was observed.

    :attr:`source` records where the facts came from, so a reader can tell "we looked and saw
    nothing" from "we did not look".

    **A fully-positive readout does not satisfy ASVS 11.7.1.** Every field here is derived from
    output the host OS controls, and the requirement exists precisely because the host may be
    hostile. Treat it as configuration confirmation, never as evidence. See ADR 0152.
    """

    capability: bool | None
    active: bool | None
    mechanism: str | None
    source: str

    @property
    def contradicts_declaration(self) -> bool | None:
        """Does this read-out contradict an operator declaration of memory encryption? Tri-state.

        * ``None`` — **nothing was measured that could contradict anything.** Either :attr:`active`
          is ``None`` (Windows, or a platform we do not read), or it is ``False`` on a host that
          never advertised a mechanism *having* a guest interface (:data:`GUEST_ATTESTABLE_MECHANISMS`)
          — an AMD SME / Intel TME host, a container whose ``/dev`` does not map the node, or a host
          whose ``/proc/cpuinfo`` we could not read. A missing device node is not evidence of absence
          there, and publishing it as one would accuse honest deployments.
        * ``False`` — a confidential-guest interface **is** present; the declaration is corroborated
          by the self-report (which is still not evidence — see :data:`READOUT_DISCLAIMER`).
        * ``True`` — the host advertises a guest-attestable mechanism (SEV-SNP / TDX) and yet exposes
          **no** guest device node. That is the one shape where absence is informative.

        DELIBERATELY UNDER-REPORTS. ``True`` is narrow on purpose: this is a self-report the ADR has
        already declared non-evidentiary, so the cost of a false ``True`` (accusing a correct
        deployment on the endpoint an assessor reads) is higher than the cost of a ``None``. Even the
        narrow case has a known benign cause — a SEV-SNP guest whose ``sev-guest`` driver is not
        loaded, or a container without the node mapped — which is why every consumer treats it as a
        warning and never as a refusal.

        Note this describes the READ-OUT only; whether anyone declared anything lives in
        ``[security].memory_encryption_operator_declared``, and callers combine the two."""
        if self.active is None:
            return None
        if self.active:
            return False
        return True if self.mechanism in GUEST_ATTESTABLE_MECHANISMS else None


def _read_cpuinfo_flags() -> frozenset[str] | None:
    """The union of every CPU's flag set from ``/proc/cpuinfo``; ``None`` if it cannot be read.

    ``None`` is load-bearing: a container that masks ``/proc``, or a kernel that omits the file, must
    report *undeterminable* rather than an absence of flags, which would read as a measured negative."""
    try:
        text = Path(_CPUINFO).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    flags: set[str] = set()
    for match in _FLAGS_LINE.finditer(text):
        flags.update(match.group(1).split())
    return frozenset(flags)


@cache
def platform_memory_encryption_readout() -> MemoryEncryptionReadout:
    """Read what this platform reports about memory encryption. Report-only; claims nothing.

    **Cached for the life of the process** (``functools.cache``): the CPU's feature flags and the
    guest device nodes are fixed at boot, and without the cache every ``GET /security/posture`` —
    which the console status page polls — would re-read ``/proc/cpuinfo`` (hundreds of KB on a large
    host) and re-stat two paths to reach the same answer. Tests that vary the underlying platform
    call ``platform_memory_encryption_readout.cache_clear()``.

    Linux reads two independent sources — ``/proc/cpuinfo`` flags for *capability* and the guest
    device nodes for *activation* — and never derives one from the other. Every other platform,
    Windows included, returns all-``None``: ADR 0152 makes the Windows in-guest path a spike that has
    not landed, and inventing an answer there would be worse than admitting we do not know.

    **Known false negatives, stated rather than hidden:** a SEV-SNP guest whose ``sev-guest`` kernel
    driver is not loaded, a container whose ``/dev`` does not map the node, and an Azure Linux
    confidential VM (whose paravisor runs SNP in vTOM mode and hides the native interface) all have
    no ``/dev/sev-guest``, so :attr:`~MemoryEncryptionReadout.active` reads ``False`` while memory
    genuinely is encrypted. This is why the read-out is advisory, why
    :attr:`~MemoryEncryptionReadout.contradicts_declaration` under-reports on purpose, and why no
    consumer may refuse on it: a non-evidentiary signal must never halt a clinical interface engine.

    Never raises."""
    if sys.platform != "linux":
        # Not "no memory encryption" — "this build does not know how to look". Windows is the ADR
        # 0152 spike; macOS/BSD are not deployment targets. Either way, None, never False.
        return MemoryEncryptionReadout(
            capability=None,
            active=None,
            mechanism=None,
            source=f"unsupported-platform:{sys.platform}",
        )

    flags = _read_cpuinfo_flags()
    capability: bool | None = None
    capability_mechanism: str | None = None
    if flags is not None:
        capability = False
        for flag, mechanism in MEMORY_ENCRYPTION_FLAGS:
            if flag in flags:
                capability = True
                capability_mechanism = mechanism
                break

    # Activation is a SEPARATE observation from a SEPARATE source. The node is STAT-ed, never opened,
    # so this stays a read-out with no side effect on the guest driver and no ioctl (that is rung 3,
    # not built). is_char_device(), NOT exists(): a guest attestation interface is a character
    # device, and exists() is equally true of a zero-byte regular file — so anything that can write
    # /dev (a bad container image, a bind-mount, an entrypoint script) could otherwise manufacture a
    # positive activation read-out by touching a file.
    active = False
    active_mechanism: str | None = None
    for path, mechanism in GUEST_DEVICES:
        try:
            present = Path(path).is_char_device()
        except OSError:  # pragma: no cover - a stat that raises is a hostile/odd /dev
            present = False
        if present:
            active = True
            active_mechanism = mechanism
            break

    # The reported mechanism prefers the ACTIVE one: "which mechanism is this guest actually using"
    # is the more useful answer than "which does the silicon list". Falls back to the capability
    # mechanism so a capable-but-inactive host still names what it could do.
    return MemoryEncryptionReadout(
        capability=capability,
        active=active,
        mechanism=active_mechanism or capability_mechanism,
        source="linux:proc-cpuinfo+guest-devices"
        if flags is not None
        else "linux:guest-devices-only",
    )
