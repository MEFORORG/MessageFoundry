# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared SSH (SFTP) algorithm floor -- the SSH sibling of ``tls_policy.harden_cipher_suites``.

**The asymmetry this closes.** The engine asserts a cipher floor wherever it builds a TLS context --
measured 2026-08-10, seven :func:`~messagefoundry.config.tls_policy.harden_cipher_suites` call sites
across five files (the API/UI listener, MLLP in both directions, both DICOM contexts, FTPS, and the
SMTP alert sink). The SSH hop had no equivalent: ``disabled_algorithms`` appeared zero times anywhere
in the package on that date, so whatever paramiko happened to offer was whatever the engine would
negotiate. Driven against a live paramiko server, the SFTP client accepted ``hmac-md5``,
``hmac-sha1`` and ``3des-cbc`` without complaint -- a partner, or an on-path attacker steering the
negotiation, could pick any of them and nothing would say so. This module is the missing assertion.

**Where the floor comes from -- it is the TLS floor, re-expressed, not a second opinion.** The
constants below are derived cell by cell from what the shipped TLS contexts *actually negotiate*, so
the two hops enforce one policy. Measured on CPython 3.14 / OpenSSL 3.5.7, both the client- and
server-default contexts resolve to 17 suites whose properties are:

=========  ==================================================  ============================
TLS cell   Measured effective set                              SSH floor it maps to
=========  ==================================================  ============================
``Kx=``    ``ECDH``, ``DH``, ``any`` (TLS 1.3, always ECDHE)   forward-secret kex only
``Enc=``   ``AES(128/256)``, ``AESGCM(128/256)``, ``CHACHA20``  no 64-bit-block, no broken
``Mac=``   ``AEAD``, ``SHA256``, ``SHA384``                    no MD5, no SHA-1, no 64-bit
=========  ==================================================  ============================

The ``Kx`` row is the property ``harden_cipher_suites`` asserts explicitly. The other two rows are
properties OpenSSL's default cipher string already guarantees for free on the TLS side -- there is no
3DES and no MD5/SHA-1 MAC in that 17-suite set -- but which paramiko's defaults do *not* guarantee,
which is why the SSH side has to name them. Mapping them across is what makes the floor the same
policy rather than an independently-invented one.

**Two operations, deliberately separated** (each mirrors a property of the TLS side):

* ``BELOW``-floor names are *disabled* (paramiko ``disabled_algorithms``). SSH negotiates from the
  offer, so pruning the offer IS the enforcement -- unlike TLS, where the context already resolves to
  a forward-secret set and ``harden_cipher_suites`` therefore only has to check it.
* Everything that survives is *asserted* to be recognisably above the floor. An unrecognised name
  raises rather than being trusted, exactly as ``_is_forward_secret`` treats an unknown ``Kx``.

The split is why an unknown name is never silently pruned: a paramiko release that adds a new modern
algorithm the allow-side does not yet know would fail LOUD at connect, naming the algorithm, instead
of being quietly dropped from the offer and narrowing reachability with no signal.

**There is deliberately NO operator override.** The floor prunes 3DES and the MD5/SHA-1 MACs, all of
which every SSH server still under support has offered alternatives to for well over a decade, so
nothing plausible needs loosening; and a loosening switch nobody asked for is a second posture by the
back door. If a partner ever does force the question, the override belongs in
``config.settings.security_loosenings`` as a REQUIRED parameter, the way the TLS deviations do -- an
optional one there is a detector that silently fails to fire. Note the difference from BACKLOG #178's
other half (an operator-configurable cipher/KEX/MAC allow-list), which stays DEMAND-GATED: this
module has no configuration surface at all.

Pure and stdlib-only: this module never imports paramiko. The caller passes the offer in, so the
``[sftp]`` extra stays optional and lazily imported (an install without paramiko behaves exactly as
it does today), and the policy stays unit-testable with no SSH library present.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence

__all__ = [
    "SSH_ALGORITHM_CATEGORIES",
    "FloorVerdict",
    "ssh_algorithm_verdict",
    "ssh_disabled_algorithms",
    "ssh_floor_refusal",
]

#: The paramiko ``disabled_algorithms`` keys this floor governs, in the order an operator reads them.
#: ``keys``/``pubkeys`` (host-key and public-key *authentication* algorithms) are deliberately absent:
#: they are a signature-algorithm question, not a confidentiality one, and paramiko 5.0 already dropped
#: SHA-1 RSA from both (the ``[sftp]`` extra floors paramiko at >=5.0 for exactly that reason).
SSH_ALGORITHM_CATEGORIES = ("kex", "ciphers", "macs")

#: The substring paramiko puts in an ``IncompatiblePeer`` message for each category, so a negotiation
#: failure can be attributed to the right half of the floor. Written out rather than derived from the
#: category name: the mapping is not mechanical (``kex`` -> "kex algorithm", ``ciphers`` -> "ciphers"),
#: and a clever derivation would be one more thing to get silently wrong on a paramiko reword.
_PEER_MESSAGE_TOKENS = {
    "kex": "no acceptable kex",
    "ciphers": "no acceptable ciphers",
    "macs": "no acceptable macs",
}

#: How each category is named to an operator. The paramiko key is a wire-protocol abbreviation; the
#: refusal an operator has to act on should read like the SSH server config they will go and edit.
_CATEGORY_LABELS = {"kex": "key-exchange algorithm", "ciphers": "cipher", "macs": "MAC"}


class FloorVerdict(enum.Enum):
    """Where one SSH algorithm name sits relative to the floor.

    ``ABOVE`` -- recognised and at or above the mapped TLS floor; offer it. ``BELOW`` -- recognised and
    beneath it; disable it. ``UNKNOWN`` -- not recognised, so the floor cannot vouch for it; it is left
    in the offer and the assertion raises on it, which is the loud half of the fail-closed posture."""

    ABOVE = "above"
    BELOW = "below"
    UNKNOWN = "unknown"


# --- kex: the forward-secrecy cell (TLS ``Kx=ECDH``/``DH``) -------------------------------------
#
# Forward-secret SSH key-exchange families. Each performs an ephemeral Diffie-Hellman (classical,
# elliptic-curve, or a PQ hybrid that carries an X25519/NIST-curve ECDH alongside the KEM), so a later
# compromise of the host key cannot decrypt recorded traffic -- the same property the TLS side asserts.
_FORWARD_SECRET_KEX_PREFIXES = (
    "curve25519-",
    "curve448-",
    "ecdh-sha2-",
    "diffie-hellman-group",
    "sntrup761x25519-",
    "mlkem768x25519-",
    "mlkem1024nistp384-",
    "mlkem768nistp256-",
    "gss-group",
    "gss-curve25519-",
    "gss-nistp",
)
#: RFC 4432 RSA key TRANSPORT. The client encrypts the session secret to a transient RSA key, with no
#: Diffie-Hellman anywhere -- the SSH analogue of a static-RSA TLS suite, and the one kex family that is
#: below the forward-secrecy floor outright. paramiko 5.0 implements neither; naming them keeps the
#: floor a statement about the policy rather than about one library version.
_RSA_TRANSPORT_KEX_PREFIXES = ("rsa1024-", "rsa2048-")


# --- ciphers: the bulk-encryption cell (TLS ``Enc=AES``/``AESGCM``/``CHACHA20``) ------------------
#
# AES-CBC survives deliberately. ``harden_cipher_suites`` measured and REJECTED a narrowing that would
# have dropped the CBC-SHA2 TLS suites real hospital peers still speak; dropping SSH's AES-CBC here
# would re-introduce on the SSH hop exactly the interop regression the TLS side declined to take.
_ALLOWED_CIPHER_PREFIXES = ("aes", "chacha20-poly1305")
#: Below-floor bulk ciphers: 64-bit block sizes (Sweet32-class birthday collisions on a long-lived
#: session), broken stream ciphers, and the null cipher. ``aes`` names are screened separately below so
#: a hypothetical weak AES mode cannot ride in on the prefix.
_BELOW_FLOOR_CIPHERS = frozenset(
    {
        "3des-cbc",
        "3des-ctr",
        "des-cbc",
        "des",
        "blowfish-cbc",
        "blowfish-ctr",
        "cast128-cbc",
        "cast128-ctr",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "idea-cbc",
        "serpent128-cbc",
        "twofish128-cbc",
        "none",
    }
)


# --- macs: the integrity cell (TLS ``Mac=AEAD``/``SHA256``/``SHA384``) ---------------------------
#
# SHA-2 HMACs and umac-128 only. hmac-sha1 is included in the refusal even though it is not yet
# practically forgeable, because the TLS side's effective set contains no SHA-1 MAC either and the
# point of this module is that the two hops agree.
_ALLOWED_MAC_PREFIXES = ("hmac-sha2-256", "hmac-sha2-512", "umac-128")
#: Matched as SUBSTRINGS, not whole names: ``hmac-md5-96`` and a hypothetical ``hmac-none`` are as
#: much below the floor as ``hmac-md5`` and ``none``, and a whole-name set would have to enumerate
#: every truncation and vendor spelling to say so.
_BELOW_FLOOR_MAC_TOKENS = ("md5", "sha1", "ripemd", "umac-64", "none")


def ssh_algorithm_verdict(category: str, name: str) -> FloorVerdict:
    """Classify one SSH algorithm ``name`` in ``category`` against the floor.

    ``category`` is one of :data:`SSH_ALGORITHM_CATEGORIES`. Names are compared with their
    ``@domain`` vendor suffix (``@openssh.com``, ``@libssh.org``) stripped, since that suffix names the
    originating implementation and never changes the cryptography. An unrecognised ``category`` is
    itself :attr:`FloorVerdict.UNKNOWN` -- a new paramiko algorithm class must be classified here
    deliberately, not admitted by falling off the end of a chain of ``if``\\ s."""
    bare = name.split("@", 1)[0].strip().lower()
    if category == "kex":
        return _kex_verdict(bare)
    if category == "ciphers":
        return _cipher_verdict(bare)
    if category == "macs":
        return _mac_verdict(bare)
    return FloorVerdict.UNKNOWN


def _kex_verdict(bare: str) -> FloorVerdict:
    if bare.startswith(_RSA_TRANSPORT_KEX_PREFIXES):
        return FloorVerdict.BELOW  # RSA key transport: no ephemeral DH, so no forward secrecy
    if not bare.startswith(_FORWARD_SECRET_KEX_PREFIXES):
        return FloorVerdict.UNKNOWN
    # Forward-secret family, but the exchange hash must clear the MAC cell too: the TLS side's 17
    # suites hash with SHA-256 or better, so a SHA-1 exchange hash is below the same floor.
    if bare.endswith(("-sha1", "-md5")):
        return FloorVerdict.BELOW
    return FloorVerdict.ABOVE


def _cipher_verdict(bare: str) -> FloorVerdict:
    if bare in _BELOW_FLOOR_CIPHERS:
        return FloorVerdict.BELOW
    if not bare.startswith(_ALLOWED_CIPHER_PREFIXES):
        return FloorVerdict.UNKNOWN
    return FloorVerdict.ABOVE


def _mac_verdict(bare: str) -> FloorVerdict:
    # Token test first: it must beat the allow-prefixes, so a name like ``hmac-sha2-256-md5`` cannot
    # be admitted by its prefix. Order is load-bearing.
    if any(token in bare for token in _BELOW_FLOOR_MAC_TOKENS):
        return FloorVerdict.BELOW
    if not bare.startswith(_ALLOWED_MAC_PREFIXES):
        return FloorVerdict.UNKNOWN
    return FloorVerdict.ABOVE


def ssh_disabled_algorithms(
    offer: Mapping[str, Sequence[str]], *, connector: str
) -> dict[str, list[str]]:
    """Derive paramiko's ``disabled_algorithms`` from ``offer``, and **assert** what survives.

    ``offer`` maps each :data:`SSH_ALGORITHM_CATEGORIES` key to the algorithm names the SSH library
    would propose (paramiko's ``Transport._preferred_kex`` / ``_preferred_ciphers`` /
    ``_preferred_macs``). Returns the mapping to hand to ``SSHClient.connect(disabled_algorithms=...)``:
    every name this floor rates :attr:`FloorVerdict.BELOW`, so it can never be negotiated.

    Raises :class:`ValueError` -- the same class the sibling TLS hardening raises, so it surfaces
    through the existing connector error handling rather than as a wire-time surprise -- when

    * a surviving name is :attr:`FloorVerdict.UNKNOWN`: the floor cannot vouch for it, and admitting
      an algorithm nobody classified is how an inherited property stops being a checked one; or
    * a category is missing from ``offer``, or the floor would empty it: a client that can offer no
      key exchange at all would otherwise fail at the wire with a message about the peer, blaming the
      partner for a floor that is ours.

    Measured against paramiko 5.0.0 (the version the lock resolves): 7 kex, all above the floor;
    9 ciphers, ``3des-cbc`` below; 8 macs, ``hmac-md5``, ``hmac-md5-96``, ``hmac-sha1`` and
    ``hmac-sha1-96`` below. So the floor prunes 5 of 24 offered names, leaving intact at least the
    AES-CTR/GCM/CBC ciphers and the SHA-2 MACs that current OpenSSH releases offer by default -- which
    is the point: it asserts a floor rather than maximising strictness."""
    disabled: dict[str, list[str]] = {}
    for category in SSH_ALGORITHM_CATEGORIES:
        names = offer.get(category)
        if names is None:
            raise ValueError(
                f"{connector}: the SSH library offered no {category!r} algorithm list, so the "
                f"algorithm floor cannot be applied to it. Refusing to connect with an unchecked "
                f"key exchange, cipher or MAC rather than inheriting whatever is negotiated."
            )
        verdicts = [(n, ssh_algorithm_verdict(category, n)) for n in names]
        below = [n for n, v in verdicts if v is FloorVerdict.BELOW]
        unknown = [n for n, v in verdicts if v is FloorVerdict.UNKNOWN]
        if unknown:
            raise ValueError(
                f"{connector}: the SSH library offers {category} algorithm(s) "
                f"{', '.join(sorted(unknown))} that the MessageFoundry algorithm floor does not "
                f"recognise, so it cannot confirm they meet the forward-secrecy / no-MD5 / no-SHA-1 "
                f"floor asserted on every other transport hop. Classify them in "
                f"messagefoundry/config/ssh_policy.py before this connection can be used."
            )
        if len(below) == len(verdicts):
            raise ValueError(
                f"{connector}: every {category} algorithm the SSH library offers "
                f"({', '.join(names)}) is below the MessageFoundry algorithm floor, so the client "
                f"would offer none at all. This is a library/policy mismatch, not a partner fault."
            )
        if below:
            disabled[category] = below
    return disabled


def ssh_floor_refusal(
    peer_message: str,
    *,
    connector: str,
    host: str,
    port: int,
    disabled: Mapping[str, Sequence[str]],
    offered: Mapping[str, Sequence[str]],
) -> str | None:
    """Explain an SSH negotiation failure that the floor is responsible for -- or return ``None``.

    A floor that fails closed must not fail *silently*: a partner this floor now refuses would
    otherwise surface as paramiko's bare ``Incompatible ssh server (no acceptable macs)``, which names
    neither the algorithms the engine refused nor the ones the partner could enable instead, and reads
    like a partner defect. Given paramiko's own ``peer_message``, this returns an operator-actionable
    replacement naming the category, what was refused and why, and what the server must offer.

    Returns ``None`` when ``peer_message`` names an incompatibility outside this floor's remit (a host
    key, an SSH protocol version), so the caller keeps its existing generic message rather than
    blaming a floor that had nothing to do with it. Some negotiation failures are genuinely the
    partner's; only the ones the floor could have caused are re-described here."""
    lowered = peer_message.lower()
    for category, token in _PEER_MESSAGE_TOKENS.items():
        # paramiko's phrasing is "Incompatible ssh peer (no acceptable kex algorithm)" and
        # "Incompatible ssh server (no acceptable ciphers|macs)". The live negotiation tests drive
        # real refusals through here, so a paramiko release that renames these fails loud rather
        # than quietly degrading this explanation back to the generic message.
        if token not in lowered:
            continue
        refused = list(disabled.get(category, ()))
        if not refused:
            return None  # the floor pruned nothing here, so it cannot be the cause
        pruned = set(refused)
        surviving = [n for n in offered.get(category, ()) if n not in pruned]
        label = _CATEGORY_LABELS[category]
        return (
            f"{connector}: {host}:{port} offered no {label} this engine will accept "
            f"({peer_message}). The MessageFoundry algorithm floor refuses {', '.join(refused)} on "
            f"the SSH hop -- below the forward-secrecy / no-MD5 / no-SHA-1 floor asserted on every "
            f"other transport hop, so a recorded session protected by one of them would be readable "
            f"or forgeable on a later key compromise. Enable one of {', '.join(surviving)} on the "
            f"server, or move the feed to a partner endpoint that supports them."
        )
    return None
