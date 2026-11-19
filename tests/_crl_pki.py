# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A throwaway CA and its empty CRL, for the revocation-guard tests. All synthetic.

Several revocation-guard test files built this pair by hand (vault BACKLOG #2977 item 12). Those
that import this module share it now, and each still writes the shapes it needs; other test files
may still build their own. EC keys, because nothing that uses this pair needs RSA and EC key
generation is cheap."""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_DAY = datetime.timedelta(days=1)


def throwaway_ca(cn: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """A self-signed CA named ``cn``, valid from yesterday until a year from now."""
    now = datetime.datetime.now(datetime.UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _DAY)
        .not_valid_after(now + 365 * _DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def empty_crl(
    key: ec.EllipticCurvePrivateKey, ca: x509.Certificate
) -> x509.CertificateRevocationList:
    """A CRL from ``ca`` that lists nothing, issued two days ago and in effect for thirty more."""
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(now - 2 * _DAY)
        .next_update(now + 30 * _DAY)
        .sign(key, hashes.SHA256())
    )
