# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Doc-drift guard for ``docs/CLOUD-PHI-HIPAA.md`` (ADR 0047 deliverable 5).

The cloud PHI/HIPAA posture doc leans on concrete engine knobs — env vars
(``MEFOR_<SECTION>_<KEY>``) and TOML settings (``[section].key``). If a future doc edit invents a
knob that does not exist, or a ``ServiceSettings`` field is renamed out from under the doc, an
operator following the guide silently mis-configures a PHI deployment. This is a **name-drift
tripwire**: every setting/env token the doc cites must resolve to a real field on a fresh
``ServiceSettings()`` today, or the test fails naming the offending token.

Scope (matching DEPLOY-27): env/setting **names** only. Connector kwargs (``tls=True``), guard
function names (``check_mllp_tls_exposure``), and CLI verbs (``gen-key`` / ``rotate-key``) are real
but are not ``ServiceSettings`` attributes, so they are intentionally out of this guard's scope.

A name-existence guard structurally cannot catch a *false-negative prose claim* (an assertion that
"X does not exist" when X was later built). The stale "``SyslogProtocol`` has no TLS variant" wording
is corrected in the doc directly (native RFC 5425 TLS-syslog shipped under ADR 0080); this guard
additionally pins that ``SyslogProtocol.TLS`` and the ``forward_tls_*`` fields exist so the wording
cannot silently regress.
"""

from __future__ import annotations

import re
from pathlib import Path

from messagefoundry.config.settings import (
    _SECTIONS,
    INSECURE_CONFIG_SOURCE_ESCAPE_ENV,
    INSECURE_TLS_ESCAPE_ENV,
    ServiceSettings,
    SyslogProtocol,
)

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "CLOUD-PHI-HIPAA.md"
_ENV_PREFIX = "MEFOR_"

# MEFOR_* escape envs are module-level constants, not fields on any section model — whitelist them.
_ESCAPE_ENVS = frozenset({INSECURE_TLS_ESCAPE_ENV, INSECURE_CONFIG_SOURCE_ESCAPE_ENV})

# Every MEFOR_<SECTION>_<KEY> token (regex stops at '=', '*', '`', etc. — not in [A-Z_]).
_ENV_TOKEN_RE = re.compile(r"MEFOR_[A-Z_]+")
# Every [section].key token; the key stops before a glob '*' so `[logging].forward_*` -> forward.
_TOML_TOKEN_RE = re.compile(r"\[([a-z_]+)\]\.([a-z_]+)")


def _doc_text() -> str:
    return _DOC.read_text(encoding="utf-8")


def _section_model_fields(section: str) -> frozenset[str] | None:
    """Return the field-name set of ``[section]``'s model, or None if the section is unknown."""
    settings = ServiceSettings()
    model = getattr(settings, section, None)
    if model is None:
        return None
    return frozenset(type(model).model_fields)


def _key_resolves(section: str, key: str) -> bool:
    """A ``[section].key`` resolves if ``key`` is a field, or a **stem** of a field family.

    The doc cites glob families as stems — ``[logging].forward_*``, ``MEFOR_EGRESS_ALLOWED_*`` — so a
    stem that prefixes at least one real field (``forward_enabled``, ``allowed_mllp``) resolves.
    """
    fields = _section_model_fields(section)
    if fields is None:
        return False
    key = key.strip("_")  # a glob stem like `forward_*` is captured as `forward_`
    return any(f == key or f.startswith(key + "_") for f in fields)


def _resolve_env_token(token: str) -> bool:
    """Whether a ``MEFOR_...`` token resolves to a known escape env or a real section field."""
    if token in _ESCAPE_ENVS:
        return True
    body = token[len(_ENV_PREFIX) :].lower()
    # Longest section-prefix wins (sections are distinct, but be defensive).
    for section in sorted(_SECTIONS, key=len, reverse=True):
        if body.startswith(section + "_"):
            key = body[len(section) + 1 :].strip("_")
            return _key_resolves(section, key)
    return False


def test_doc_env_tokens_resolve_to_settings_fields() -> None:
    """Every ``MEFOR_*`` env token in the doc maps to a real ServiceSettings field (or escape env)."""
    text = _doc_text()
    tokens = sorted(set(_ENV_TOKEN_RE.findall(text)))
    assert tokens, "no MEFOR_* env tokens found — regex or doc changed unexpectedly"
    unresolved = sorted(t for t in tokens if not _resolve_env_token(t))
    assert not unresolved, (
        f"CLOUD-PHI-HIPAA.md cites env var(s) with no matching ServiceSettings field: {unresolved}"
    )


def test_doc_toml_tokens_resolve_to_settings_fields() -> None:
    """Every ``[section].key`` token in the doc maps to a real ServiceSettings field."""
    text = _doc_text()
    tokens = sorted(set(_TOML_TOKEN_RE.findall(text)))
    assert tokens, "no [section].key tokens found — regex or doc changed unexpectedly"
    unresolved = sorted(f"[{sec}].{key}" for sec, key in tokens if not _key_resolves(sec, key))
    assert not unresolved, (
        f"CLOUD-PHI-HIPAA.md cites [section].key setting(s) with no matching field: {unresolved}"
    )


def test_syslog_tls_variant_and_forward_tls_fields_exist() -> None:
    """Pin the built native TLS-syslog surface (ADR 0080) so the doc's corrected wording can't regress.

    The doc previously asserted ``SyslogProtocol`` had no TLS variant; that is false — RFC 5425
    TLS-syslog shipped natively. This guard fails if the TLS variant or its trust-anchor fields are
    removed, which would resurrect the stale "syslog is plaintext-only" premise.
    """
    assert hasattr(SyslogProtocol, "TLS"), "SyslogProtocol.TLS (RFC 5425 native TLS-syslog) removed"
    logging_fields = _section_model_fields("logging")
    assert logging_fields is not None
    for field in ("forward_tls_ca_file", "forward_tls_verify", "forward_tls_client_cert"):
        assert field in logging_fields, (
            f"[logging].{field} (native TLS-syslog trust anchor) removed"
        )
