# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``vault`` SecretProvider — HashiCorp Vault **KV v2** read of a connector credential (ADR 0019 §5).

The connector-secret twin of [store/keyprovider_vault.py](../store/keyprovider_vault.py): the base
``secretprovider.py`` dispatch imports this module **by name** (``_load_external_provider`` imports
``messagefoundry.config.secretprovider_<name>`` and calls its ``build_provider``) with **no edit to
secretprovider.py**. Where the store's Vault provider uses **Transit** to envelope-*decrypt* the store DEK,
a connector credential (an AD bind password, an SMTP password) is a plain secret **stored in Vault**, so
this provider does a **KV v2 read** and returns the field value.

**Reference syntax:** ``resolve("<path>#<field>")`` reads the KV secret at ``<path>`` under the configured
mount and returns key ``<field>`` from it. ``<field>`` is optional and defaults to ``value`` (i.e.
``resolve("mefor/ad")`` reads field ``value`` at path ``mefor/ad``). The mount point is
``MEFOR_SECRETS_VAULT_KV_MOUNT`` (default ``secret``, Vault's conventional KV v2 mount).

**Fail-closed (mirrors ADR 0019 §4):** a missing ``hvac`` extra, missing Vault address/token config, an
absent path/field, or any KV/transport failure raises
:class:`~messagefoundry.config.secretprovider.SecretProviderError` — the credential point propagates it so
the subsystem refuses to come up rather than binding with a blank credential. **The secret value is NEVER
logged or placed in an exception message**; only the reference/path label and the failure TYPE are.

``hvac`` (the official HashiCorp client, Apache-2.0) is **lazy-imported** in :func:`_import_hvac`, behind
the **same** optional ``[vault]`` extra the store's Vault KeyProvider already declares — so the base
install pulls **zero** Vault SDK and **no new dependency** is added. It ships no type stubs, so the client
is contained as a typed ``Any`` local here (never a repo-wide ignore).
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from messagefoundry.config.secretprovider import SecretProviderError
from messagefoundry.config.tls_policy import (
    InsecureHopRefused,
    assert_hvac_tls_suites,
    vault_client_verify_kwargs,
    vault_hop_refusal_text,
)
from messagefoundry.engine_secrets import SecretsDirectoryError, secret_setting

if TYPE_CHECKING:
    from messagefoundry.config.settings import SecretsSettings
    from messagefoundry.config.tls_policy import HopPosture

#: The optional extra that carries ``hvac`` — named in every fail-closed message. Deliberately the SAME
#: extra the store's Vault KeyProvider uses (no second Vault dependency).
_EXTRA = "vault"

#: Operator-recognisable label for this hop, carried into the TLS suite assertion's error so a refusal
#: names the connection rather than the helper that raised it.
_VAULT_KV_CONNECTOR = "Vault KV secret provider"

# Vault connection config comes from the environment (never the config file): the address/token are
# host-specific/secret. The token may come from the secrets directory instead (ADR 0214).
#
# BACKLOG #2851: both are REQUIRED and always handed to hvac. Given None, hvac reads VAULT_ADDR,
# VAULT_TOKEN and then ~/.vault-token, which in an operator's shell are the operator's own Vault and
# token. So an unset or empty variable refuses, with the fixed text below, rather than fall back.
# The twin of store/keyprovider_vault.py's.
_ENV_ADDR = "MEFOR_SECRETS_VAULT_ADDR"
_ENV_TOKEN = "MEFOR_SECRETS_VAULT_TOKEN"  # nosec B105 — the env-var NAME, not a token value
#: KV v2 mount point the connector secrets live under (Vault's conventional default is ``secret``).
_ENV_KV_MOUNT = "MEFOR_SECRETS_VAULT_KV_MOUNT"
#: PEM path to the CA that issued the Vault server's certificate (#1180, ASVS 12.3.4). A PATH, not a
#: secret. The twin of the store KeyProvider's ``MEFOR_STORE_VAULT_CA_FILE``, kept separate for the
#: same reason the address and token are: the two providers may point at different Vaults. Unset =
#: hvac's own default, which is ``requests``' PUBLIC certifi bundle.
#: (:func:`~messagefoundry.config.tls_policy.vault_client_verify_kwargs` records why ``[tls]`` does
#: not reach this hop yet.)
_ENV_CA_FILE = "MEFOR_SECRETS_VAULT_CA_FILE"

#: The refusals for an unset address or token: fixed text naming the variable, never a value. One
#: text each, for the provider and ``check-privileges`` alike (BACKLOG #2851).
_ADDR_UNSET = (
    f"{_ENV_ADDR} is not set or is empty, so the connector-secret Vault is not known. The engine "
    f"sends its token only to the address named there, never to VAULT_ADDR. Set it in the "
    f"service's environment, and run check-privileges with that environment"
)
_TOKEN_UNSET = (
    f"{_ENV_TOKEN} is not set or is empty, in the secrets directory or the environment, so the "
    f"connector-secret token is not known. The engine reads only the token named there, never "
    f"VAULT_TOKEN or ~/.vault-token. Supply it to the service in one of those two places, and "
    f"run check-privileges with the service's environment"
)
#: The Windows twin, as in ``store/keyprovider_vault.py``: on Windows the token goes in the
#: secrets directory only, never in the service's environment (owner ruling 2026-10-01).
_TOKEN_UNSET_WINDOWS = (
    f"{_ENV_TOKEN} is not set or is empty, so the connector-secret token is not known. On "
    f"Windows, supply it only as the file named {_ENV_TOKEN} in the secrets directory "
    f"MEFOR_SECRETS_DIRECTORY names, never in the service's environment. The engine never reads "
    f"VAULT_TOKEN or ~/.vault-token in its place. Run check-privileges with "
    f"MEFOR_SECRETS_DIRECTORY set as the service has it"
)


def _token_unset(platform: str | None = None) -> str:
    """The unset-token refusal for ``platform``, this process's when ``None``. Fixed text."""
    return _TOKEN_UNSET_WINDOWS if (platform or sys.platform) == "win32" else _TOKEN_UNSET


#: Default field read from a KV secret when a reference omits ``#<field>``.
_DEFAULT_FIELD = "value"


def _import_hvac() -> Any:
    """Lazily import ``hvac`` (the optional ``[vault]`` extra), failing closed with a
    :class:`SecretProviderError` naming the extra. ``ImportError`` (not just ``ModuleNotFoundError``) is
    caught so a partially-broken install also fails closed."""
    try:
        # hvac ships no type stubs; the targeted ignore is contained here (never a repo-wide ignore).
        import hvac  # type: ignore[import-untyped]  # noqa: PLC0415  (lazy — base install pulls no SDK)
    except ImportError as exc:
        raise SecretProviderError(
            f"[secrets].provider={_EXTRA!r} requires the optional {_EXTRA!r} extra (hvac not "
            f"importable): install 'messagefoundry[{_EXTRA}]'."
        ) from exc
    return hvac


def _vault_ca_kwargs(addr: str | None) -> dict[str, str]:
    """This Vault hop's ``verify=`` keyword arguments — ``{}`` when no anchor is configured.

    #1180 (ASVS 12.3.4) — the twin of ``store/keyprovider_vault.py``'s, sharing
    :func:`~messagefoundry.config.tls_policy.vault_client_verify_kwargs`. This client reads connector
    credentials out of Vault KV, so the anchor that verifies the server is the only thing standing
    between a spoofed Vault and every partner credential the engine holds.

    Fails closed here rather than in the shared helper, because the error type and cell name are this
    module's: ``requests`` would otherwise raise deep inside the first KV read, surfacing as an opaque
    resolution failure that names no cause."""
    ca = os.environ.get(_ENV_CA_FILE) or None
    if ca is not None and not os.path.isfile(ca):
        raise SecretProviderError(
            f"[secrets].provider={_EXTRA!r}: {_ENV_CA_FILE} names {ca!r}, which is not a readable "
            f"file — point it at the PEM of the CA that issued the Vault server certificate."
        )
    return vault_client_verify_kwargs(ca_file=ca, addr=addr, cell=f"[secrets].provider={_EXTRA!r}")


def _build_client(
    addr: str,
    token: str,
    *,
    revocation_attested: bool,
    posture: HopPosture | None = None,
    revocation_reason: str | None = None,
) -> Any:
    """Construct an ``hvac.Client``. Factored out so tests can substitute a fake KV backend without a live
    Vault. ``addr`` and ``token`` are REQUIRED and always passed to hvac (BACKLOG #2851): take them
    from :func:`secrets_vault_address` and :func:`secrets_vault_token`. An empty one is refused here
    too, with the same text, because hvac reads ``VAULT_ADDR`` for an empty address.

    ``revocation_attested`` is ``[secrets].vault_revocation_attested`` (vault BACKLOG #2983). It is
    REQUIRED, so no caller builds this client without saying whether the hop is attested. Pass the
    setting, or ``False`` where no settings are in scope, which fails closed.

    ``posture`` is the instance posture the caller was handed, or ``None``. ``None`` counts as
    enforcing, so leaving it out is the strict answer. ``revocation_reason`` is the attestation's
    reason, for the one line an attested crossing logs."""
    # The backstop for a caller that did not read through those two functions.
    if not addr:
        raise SecretProviderError(_ADDR_UNSET)
    if not token:
        raise SecretProviderError(_token_unset())
    hvac = _import_hvac()
    # allow_redirects=False (BACKLOG #1042, ASVS 15.3.2/1.3.6): hvac's default is True, and this was
    # one of the three clients that did not carry the no-redirect policy every other shipped HTTP
    # egress does. `token` rides as an `X-Vault-Token` header on every KV read, so a 3xx from an
    # on-path attacker (absent TLS integrity) or a spoofed Vault would otherwise relocate the
    # request carrying it. See store/keyprovider_vault.py's twin for the measurement.
    #
    # ONE dict feeds both the assertion and the construction, deliberately. The LDAPS site had to
    # grow a second test to prove its asserted arguments were the ones its bind used, because the two
    # lived in different methods; here they cannot drift, because they are the same object.
    #
    # #1180 (ASVS 12.3.4) rides in the SAME dict: narrow the trust anchor when the operator named
    # one, omitting the keyword when they did not so the stock construction is unchanged. Putting it
    # here rather than at the call means the operator's CA is inside what the assertion below sees.
    kwargs: dict[str, object] = {
        "url": addr,
        "token": token,
        "allow_redirects": False,
        **_vault_ca_kwargs(addr),
    }
    # ASVS 12.1.2 (BACKLOG #1317, ADR 0180; BACKLOG #300): hvac exposes no SSLContext, so the
    # assertion returns a factory that BUILDS this hop's context, narrows it to the approved suites
    # and asserts it, once per connection. It runs it once here, so a bad list raises ValueError at
    # construction.
    context_factory = assert_hvac_tls_suites(kwargs, connector=_VAULT_KV_CONNECTOR)
    client: Any = hvac.Client(**kwargs)
    # BACKLOG #2053 (ASVS 4.2.1): read every KV reply through bounded_read rather than urllib3's
    # lenient body reader. Mounted AFTER construction, so the arguments asserted above are still
    # the ones the hop uses. The adapter also gives every connection a context from the factory
    # (BACKLOG #300). Imported lazily: requests is on the [vault] extra, like hvac.
    from messagefoundry.transports.strict_requests import mount_strict_reply_adapter

    try:
        mount_strict_reply_adapter(
            client,
            connector=_VAULT_KV_CONNECTOR,
            ssl_context_factory=context_factory,
            revocation_attested=revocation_attested,
            attestation_section="secrets",
            posture=posture,
            revocation_reason=revocation_reason,
        )
    except InsecureHopRefused as exc:
        # BACKLOG #2317: the mount refuses an address that would send the token in cleartext,
        # before any I/O. Vault BACKLOG #2983: it also refuses an off-box https:// Vault whose
        # revocation nothing checks and nobody attested. Raised as this provider's own
        # fail-closed type, which every caller handles. Only the hop's own marked refusal keeps
        # its fixed text whole; any other hop refusal keeps its type name (BACKLOG #3471).
        raise SecretProviderError(vault_hop_refusal_text(exc, _VAULT_KV_CONNECTOR)) from exc
    return client


def _kv_mount() -> str:
    """The KV v2 mount every read goes to: ``MEFOR_SECRETS_VAULT_KV_MOUNT``, else ``secret``."""
    return os.environ.get(_ENV_KV_MOUNT) or "secret"


def _split_ref(ref: str) -> tuple[str, str]:
    """Split a ``<path>#<field>`` reference into ``(path, field)``; ``field`` defaults to ``value``."""
    path, sep, field = ref.partition("#")
    path = path.strip()
    field = field.strip() if sep else _DEFAULT_FIELD
    if not path or not field:
        raise SecretProviderError(
            f"[secrets].provider={_EXTRA!r}: malformed secret reference {ref!r} — expected "
            f"'<kv-path>' or '<kv-path>#<field>'."
        )
    return path, field


def _token_setting() -> str | None:
    """``MEFOR_SECRETS_VAULT_TOKEN`` through the one accessor: its file in the secrets directory,
    else the environment (vault BACKLOG #2595). A directory that cannot be used raises
    :class:`SecretProviderError`, so the subsystem fails closed as it does for any other bad Vault
    setting."""
    # The refusal is raised outside the handler and carries only the message, so nothing the
    # directory read held rides along on its chain (BACKLOG #2307 states the rule).
    try:
        return secret_setting(_ENV_TOKEN)
    except SecretsDirectoryError as exc:
        refusal = str(exc)
    raise SecretProviderError(refusal)


class VaultSecretProvider:
    """``vault`` — read a connector credential from Vault KV v2 (ADR 0019 §5)."""

    def __init__(self, settings: SecretsSettings, *, posture: HopPosture | None = None) -> None:
        self._settings = settings
        # The instance posture the caller holds, for the revocation guard on this hop (vault
        # BACKLOG #2983). Kept, because the provider dials on every `resolve`, long after it was
        # built. `None` counts as enforcing.
        self._posture = posture

    def resolve(self, ref: str) -> str:
        path, field = _split_ref(ref)
        mount = _kv_mount()
        # BACKLOG #2851: an unset address or token refuses here, rather than let hvac fall back.
        # Read on every resolve, so a token file replaced in the secrets directory is what the
        # next read uses.
        addr, token = secrets_vault_hop()
        # OUTSIDE the try on purpose. The TLS suite assertion inside `_build_client` raises
        # ValueError, and the `except Exception` below would relabel it "could not read secret ...
        # from Vault KV" — turning a configuration refusal into what reads as a connectivity failure,
        # the same mistake ADR 0180 records for the LDAPS site. Fail-closed is unchanged either way:
        # both paths propagate and the subsystem refuses to come up.
        client = _build_client(
            addr,
            token,
            revocation_attested=self._settings.vault_revocation_attested,
            posture=self._posture,
            revocation_reason=self._settings.vault_revocation_attested_reason,
        )
        try:
            # read_secret_version returns {'data': {'data': {<field>: <value>, ...}, 'metadata': {...}}}.
            response: Any = client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount)
            data = response["data"]["data"]
        except SecretProviderError:
            raise
        except Exception as exc:
            # Fail closed on ANY KV/transport/shape failure. Include ONLY the exception TYPE + the
            # reference path (not the value) — a backend error could otherwise echo secret material.
            # The hop's own refusals are the one exception: their text is fixed, so it is kept
            # (BACKLOG #2318). Lazy, like the import in _build_client.
            from messagefoundry.transports.strict_requests import vault_failure_text

            raise SecretProviderError(
                f"[secrets].provider={_EXTRA!r} could not read secret {path!r} (field {field!r}) from "
                f"Vault KV: {vault_failure_text(exc)}."
            ) from exc
        if not isinstance(data, dict) or field not in data:
            raise SecretProviderError(
                f"[secrets].provider={_EXTRA!r}: Vault KV secret {path!r} has no field {field!r}."
            )
        value = data[field]
        if not isinstance(value, str) or not value:
            raise SecretProviderError(
                f"[secrets].provider={_EXTRA!r}: Vault KV secret {path!r} field {field!r} is empty or "
                f"not a string."
            )
        return value


def build_provider(
    settings: SecretsSettings, *, posture: HopPosture | None = None
) -> VaultSecretProvider:
    """The dispatch entrypoint ``secretprovider._load_external_provider`` imports and calls by name."""
    return VaultSecretProvider(settings, posture=posture)


# --- what this hop's token must be able to do (BACKLOG #305, ASVS 13.2.2) ---------------------------


def secrets_vault_token() -> str:
    """The connector-secret token named in ``MEFOR_SECRETS_VAULT_TOKEN``: its file in the secrets
    directory, else the environment, for ``check-privileges``. The provider reads it with the
    address, through :func:`secrets_vault_hop`, with the same refusal.

    **It refuses when that setting is unset or empty** (BACKLOG #2851). Given no token, hvac reads
    ``VAULT_TOKEN`` and then ``~/.vault-token``: in an operator's shell that is the operator's own
    token, which the engine would read secrets with, and the check would judge, as the engine's.
    Raises :class:`SecretProviderError`, which the probe reports as not observed."""
    token = _token_setting()
    if not token:
        raise SecretProviderError(_token_unset())
    return token


def secrets_vault_hop() -> tuple[str, str]:
    """The connector-secret Vault's address and token, for :meth:`VaultSecretProvider.resolve`.
    Each is read as :func:`secrets_vault_address` and :func:`secrets_vault_token` read it, but both
    are read before either refuses, so one refusal names every unset variable, or the secrets
    directory's own refusal beside an unset address (BACKLOG #2851)."""
    refusals: list[str] = []
    addr: str | None = None
    token: str | None = None
    try:
        addr = secrets_vault_address()
    except SecretProviderError as exc:
        refusals.append(str(exc))
    try:
        token = secrets_vault_token()
    except SecretProviderError as exc:
        refusals.append(str(exc))
    # Raised outside the handlers, so nothing a read held rides along on the chain (BACKLOG #2307).
    # Either is None exactly when its read refused.
    if addr is None or token is None:
        raise SecretProviderError(". ".join(refusals))
    return addr, token


def secrets_vault_address() -> str:
    """The connector-secret Vault named in ``MEFOR_SECRETS_VAULT_ADDR``, for ``check-privileges``.
    The provider reads it with the token, through :func:`secrets_vault_hop`, with the same refusal.

    **It refuses when that variable is unset or empty** (BACKLOG #2851). Given no address, hvac
    reads ``VAULT_ADDR``: in an operator's shell that may be another Vault, which would then
    receive the engine's token. Raises :class:`SecretProviderError`, which the probe reports as not
    observed."""
    addr = os.environ.get(_ENV_ADDR)
    if not addr:
        raise SecretProviderError(_ADDR_UNSET)
    return addr


def secrets_vault_client(
    address: str,
    token: str,
    *,
    revocation_attested: bool,
    posture: HopPosture | None = None,
    revocation_reason: str | None = None,
) -> Any:
    """The connector-secret hop's Vault client, built by the same :func:`_build_client`
    :meth:`VaultSecretProvider.resolve` uses: same TLS narrowing, same anchor, no redirects, and the
    same cleartext-address refusal (BACKLOG #2317). For ``check-privileges``, which reads the token's
    own grants through it and changes nothing. Take ``address`` from :func:`secrets_vault_address`
    and ``token`` from :func:`secrets_vault_token`; both refuse an unset variable, and the client
    uses exactly the values they returned.

    **The same revocation rule too** (vault BACKLOG #2983). ``revocation_attested`` is
    ``[secrets].vault_revocation_attested`` and is REQUIRED, with ``revocation_reason`` beside it
    and the caller's ``posture``. So this client crosses an off-box ``https://`` Vault where
    :meth:`VaultSecretProvider.resolve` would, and its refusal names the pair this path reads."""
    return _build_client(
        address,
        token,
        revocation_attested=revocation_attested,
        posture=posture,
        revocation_reason=revocation_reason,
    )


def kv_required_capabilities(refs: Iterable[str]) -> dict[str, frozenset[str]]:
    """The KV v2 path each reference in ``refs`` reads, with the one capability it needs.

    hvac's ``read_secret_version`` is a GET of ``<mount>/data/<path>``, so that path and ``read`` are
    the whole grant; kept beside :meth:`VaultSecretProvider.resolve` so the two cannot drift. A
    malformed reference raises :class:`SecretProviderError`, as resolving it would."""
    mount = _kv_mount()
    return {f"{mount}/data/{_split_ref(ref)[0]}": frozenset({"read"}) for ref in refs}
