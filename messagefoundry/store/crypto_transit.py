# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``vault_transit`` store cipher — bulk at-rest crypto INSIDE Vault/OpenBao Transit (ADR 0138).

This is a :class:`~messagefoundry.store.crypto.Cipher`, **not** a KeyProvider. The ADR 0019 KeyProvider
seam only *sources* the DEK bytes — ``make_cipher`` then feeds them to an **in-process** ``AESGCM``, so the
plaintext DEK lands in engine heap for the bulk work (the ASVS 13.3.3 residual). ``TransitCipher`` replaces
the cipher object itself: every ``encrypt``/``decrypt`` is a Transit ``encrypt_data``/``decrypt_data`` call,
so **the data-encryption key never leaves the isolated module** and never enters this process. ASVS 5.0's
13.3.3 names "a vault" as a qualifying isolated security module; sibling 13.3.1's L3 *hardware* clause still
wants the vault itself HSM-sealed (deployment tier — see the ADR).

**At-rest form.** Values are stored as ``mfenc:v3:`` + Transit's own ``vault:v1:…`` ciphertext (a new
marker version — the in-process ``mfenc:v1`` / ``mfenc:v2`` / ``mfenc:v4`` values are our-nonce AES-GCM and
stay unchanged). ``is_encrypted`` / the stores' ``mfenc:%`` find-all scans recognise it; only ``TransitCipher``
decodes it.

**Cell-binding (ASVS 11.3.3) for free.** The store passes ``aad=cell_aad(table, column, *pk)`` at every
call; we forward it as Transit's ``associated_data``, so a v3 blob cut-and-pasted into another cell fails
the tag inside Transit → :class:`CipherError` (verified against OpenBao 2.6.0). Encrypt and decrypt of the
same cell see the same stable AAD, so binding is symmetric by construction.

**Audit chain (keyed IN Transit).** :meth:`audit_mac_key` returns ``None`` — there is no in-heap DEK to
HKDF a raw HMAC key from — but the chain is **not** keyless: :meth:`audit_mac_fn` hands the store a
Transit-backed MAC (:meth:`audit_hmac` → Transit ``generate_hmac``), so every audit row's MAC is computed
INSIDE the isolated module and the key never enters heap. This lifts the audit chain from keyless SHA-256
(tamper-evident) to forgery-**resistant** (ADR 0138 §To-resolve, closing the ASVS 16.4.2 residual for this
mode). The MAC key defaults to the data key and is overridable to a dedicated Transit key via
``MEFOR_STORE_TRANSIT_AUDIT_KEY`` for domain separation.

**Fail-closed (ADR 0138).** Missing config, an unreachable/unknown Transit key, or a key whose TYPE
cannot run the operation asked of it (BACKLOG #1166) raises
:class:`~messagefoundry.store.keyprovider.KeyProviderError` at construction (``open_store`` propagates it
→ ``serve`` refuses to start, never an in-process fallback). A per-operation Transit failure raises :class:`CipherError` — the
store's existing at-rest error discipline. On ``encrypt`` and ``decrypt``, a failure that gave no verdict
on the value (Transit unreachable, or answering that it cannot serve now) raises its subclass
:class:`~messagefoundry.store.crypto.CipherUnavailableError` instead (BACKLOG #3734). **No plaintext/PHI is EVER placed in a message** (only the
exception TYPE): the base64 plaintext handed to Transit is the message body. The one exception is a
refusal of the Vault hop or its reply, whose text is fixed and is kept whole (BACKLOG #2318; see
:func:`~messagefoundry.store.keyprovider_vault.vault_failure_text`).

``hvac`` is the optional ``[vault]`` extra, lazy-imported via
:func:`~messagefoundry.store.keyprovider_vault._build_client` (shared with the KEK-unwrap provider so there
is ONE Vault client-construction path); the base install pulls zero Vault SDK.
"""

from __future__ import annotations

import base64
import contextlib
import logging
import os
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from messagefoundry.redaction import json_loads_or_refusal
from messagefoundry.store.crypto import (
    _V3_PREFIX,
    AUDIT_TRANSIT_HASH_ALGO,
    BATCH_MAX_CHARS,
    BATCH_MAX_ITEMS,
    MARKER_PREFIX,
    AuditKeyVersionRefusedError,
    AuditKeyVersionUnverifiedError,
    AuditMacFn,
    CipherError,
    CipherItem,
    CipherUnavailableError,
    TransitSealRefused,
    _UnmarkedPolicy,
    b64_chars,
    batch_chars,
    decrypt_or_error,
)
from messagefoundry.store.keyprovider import KeyProviderError
from messagefoundry.store.keyprovider_vault import (
    _EXTRA,
    TRANSIT_KEY_TYPES_AUDIT,
    TRANSIT_KEY_TYPES_DATA,
    TRANSIT_MOUNT,
    _build_client,
    checked_transit_key_name,
    is_vault_bad_request,
    is_vault_forbidden,
    is_vault_unavailable,
    require_transit_key_type,
    store_vault_hop,
    vault_failure_text,
)

if TYPE_CHECKING:
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.config.tls_policy import HopPosture

log = logging.getLogger(__name__)

#: The `[store].cipher_provider` value that selects this cipher.
PROVIDER_NAME = "vault_transit"

# Connection reuses the shared Vault wiring (a deployment runs one Vault): the address and token are read
# through keyprovider_vault.store_vault_hop, which refuses either one unset rather
# than let hvac fall back to VAULT_ADDR, VAULT_TOKEN or ~/.vault-token (BACKLOG #2851), and the token goes
# through the one accessor (vault BACKLOG #2595). The DATA key is distinct from keyprovider_vault's KEK
# (that unwraps a DEK; this one encrypts the data directly), so it has its own name.
#: The Transit key the store data is encrypted/decrypted under (the isolated-module data key).
_ENV_TRANSIT_KEY = "MEFOR_STORE_TRANSIT_KEY"
#: The Transit key the audit-chain HMAC is computed under (ADR 0138 §To-resolve follow-up). Optional —
#: unset ⇒ reuse the data key (``_ENV_TRANSIT_KEY``): Transit ``generate_hmac`` works on the AEAD key
#: types (verified against an ``aes256-gcm96`` key), so the audit chain is keyed-in-Transit out of the
#: box in ``vault_transit`` mode. Set it to a DEDICATED Transit key for domain separation from the data
#: key. Either way the type is CHECKED at startup against
#: :data:`~messagefoundry.store.keyprovider_vault.TRANSIT_KEY_TYPES_AUDIT` (BACKLOG #1166); a shared key
#: is held to the narrower data-key set, because it has to do both jobs.
_ENV_AUDIT_KEY = "MEFOR_STORE_TRANSIT_AUDIT_KEY"
#: Texts Transit's ``hmac`` endpoint answers a refused key VERSION with, lower-cased (BACKLOG #6707).
#: Read on 2026-11-10 from Vault ``builtin/logical/transit/path_hmac.go`` and
#: ``sdk/helper/keysutil/policy.go`` (``HMACKey``, ``safeGetKeyEntry``) at commit cbc874e2358f, and
#: from OpenBao, which says the same, at 80e208bf4f83 and 79e101fe2e59. They never decide whether
#: the row is a break, and are read only inside an ``errors`` value that is a list
#: (:func:`_names_no_version_reason`): a list entry holding one keeps the refused-version label,
#: even beside a reason in :data:`_NOT_VERSION_TEXTS`. One anywhere else, such as in a bare JSON
#: list or a string ``errors`` value, is not read.
_VERSION_REFUSAL_TEXTS = (
    "key version does not exist",
    "no such key version",
    "version is too old (disallowed by policy)",
    "no hmac key exists for that key version",
)
#: Whole Vault error texts, lower-cased, that say a pinned ``hmac`` 400 is NOT about the version
#: (BACKLOG #6707), from the same Vault source. Matched whole once stripped and lower-cased, never
#: as a substring. Kept short on purpose: :meth:`TransitCipher.audit_hmac` sends base64 it encoded
#: and a fixed algorithm, so at least the input-encoding and algorithm 400s are not reachable from
#: it.
_NOT_VERSION_TEXTS = frozenset({"missing input for hmac", "encryption key not found"})
#: The longest reply body, in characters, that :func:`_names_no_version_reason` parses when hvac
#: parsed none (BACKLOG #6707). Vault's own refusal is far shorter. Without a bound, a very large
#: body would be parsed whole on the audit walk, and a MemoryError there would turn a row's break
#: into a walk that could not run. A longer body is not read as a version refusal.
_REPARSED_BODY_MAX_CHARS = 64 * 1024


def _names_no_version_reason(exc: Exception) -> bool:
    """Whether a pinned ``hmac`` 400 is NOT read as a version refusal (BACKLOG #6707). Only an
    ``errors`` value that is a list is read. With none, this is True whatever the reply says: at
    least a proxy or WAF page, text that is not JSON, a bare JSON list, and a string or object
    ``errors`` value. A list is True only when it is non-empty, every entry is text whose whole
    value, stripped and lower-cased, is in :data:`_NOT_VERSION_TEXTS`, and no entry holds a
    :data:`_VERSION_REFUSAL_TEXTS` text; any other list, an empty one, one with a non-text entry
    and unknown Vault wording included, is False. A True 400 may still be a refusal of the version, so this chooses only the
    error's text: :class:`~messagefoundry.store.crypto.AuditKeyVersionUnverifiedError` rather than
    its parent.

    When hvac raised ``InvalidRequest`` at all, it fills ``exc.errors`` only when the reply's
    Content-Type is exactly ``application/json``, so a proxy that adds a charset leaves the same
    JSON in ``exc.text``; that is read the same way, but only when hvac parsed no JSON
    (``exc.json`` is None) and the body is at most :data:`_REPARSED_BODY_MAX_CHARS` long. A longer
    body is True, unparsed."""
    errors: object = getattr(exc, "errors", None)
    body: object = getattr(exc, "text", None)
    if errors is None and getattr(exc, "json", None) is None and isinstance(body, str):
        if len(body) > _REPARSED_BODY_MAX_CHARS:
            # Too long to be Vault's own refusal, and never parsed (BACKLOG #6707).
            log.warning(
                "a pinned audit MAC got a 400 whose %d-character body is past the %d-character "
                "bound; not read as a version refusal",
                len(body),
                _REPARSED_BODY_MAX_CHARS,
            )
            return True
        parsed, refused = json_loads_or_refusal(body)
        if refused is None and isinstance(parsed, dict):
            errors = parsed.get("errors")
    if not isinstance(errors, list):
        return True  # no errors list, so nothing in the reply is read
    texts = [text.strip().lower() for text in errors if isinstance(text, str)]
    if any(known in text for text in texts for known in _VERSION_REFUSAL_TEXTS):
        return False
    return (
        bool(errors) and len(texts) == len(errors) and all(t in _NOT_VERSION_TEXTS for t in texts)
    )


def _batches(costs: Sequence[int]) -> list[list[int]]:
    """The item indexes, in order, cut into runs under
    :data:`~messagefoundry.store.crypto.BATCH_MAX_ITEMS` and
    :data:`~messagefoundry.store.crypto.BATCH_MAX_CHARS`; an item over the character bound is a
    run of its own (BACKLOG #6706)."""
    runs: list[list[int]] = []
    run: list[int] = []
    size = 0
    for index, cost in enumerate(costs):
        if run and (len(run) >= BATCH_MAX_ITEMS or size + cost > BATCH_MAX_CHARS):
            runs.append(run)
            run, size = [], 0
        run.append(index)
        size += cost
    if run:
        runs.append(run)
    return runs


def _batch_replies(response: Any, sent: int) -> list[Mapping[str, Any]] | None:
    """Transit's ``batch_results``, when it is a list of ``sent`` objects whose ``reference`` is
    each one's own place in the request, as sent (BACKLOG #6706); ``None`` otherwise, and the
    caller then refuses every value of the batch. Vault echoes ``reference`` on every result, so
    a reply that drops, adds or reorders one is caught here rather than zipped."""
    data = response.get("data") if isinstance(response, dict) else None
    replies = data.get("batch_results") if isinstance(data, dict) else None
    if not isinstance(replies, list) or len(replies) != sent:
        return None
    if not all(
        isinstance(reply, dict) and reply.get("reference") == str(place)
        for place, reply in enumerate(replies)
    ):
        return None
    return replies


def _unasked(failure: CipherError, count: int) -> list[str | CipherError]:
    """``count`` copies of a failure that gave no verdict on any value of a batch, for values
    Transit was not asked for, or not answered for, alone. Each carries ``failure``'s cause, as
    ``raise ... from`` sets it, which is what a reader that tells an outage from a refusal reads."""
    copies: list[str | CipherError] = []
    for _ in range(count):
        error = type(failure)(str(failure))
        error.__cause__ = failure.__cause__
        copies.append(error)
    return copies


def _plaintext(value: object) -> str | None:
    """Transit's base64 ``plaintext`` as text, or ``None`` when it is not base64 of UTF-8. Never
    raises, so no error carries the decrypted bytes (BACKLOG #2085)."""
    # binascii.Error and UnicodeDecodeError are ValueErrors; TypeError is a value that is not text.
    with contextlib.suppress(ValueError, TypeError):
        return base64.b64decode(value).decode("utf-8")  # type: ignore[arg-type]
    return None


#: The fixed input of the probe that tells a refused key version from an outage (BACKLOG #2337).
#: Base64, as Transit takes it. It carries no row data, so no row can decide the probe's answer.
_VERSION_PROBE_INPUT = base64.b64encode(b"messagefoundry audit key version probe").decode("ascii")


def _transit_failure(op: str, key: str, exc: Exception) -> CipherError:
    """The error an ``encrypt`` or ``decrypt`` raises for ``exc``: :class:`CipherUnavailableError`
    where Transit gave no verdict on the value, else plain :class:`CipherError` (BACKLOG #3734).
    The audit HMAC keeps plain :class:`CipherError`; this split is for the data key alone.

    The outage's text is the key id and ``exc``'s type name only, a reply refusal's fixed text
    left out, because the upload routes log it; a refusal keeps :func:`vault_failure_text`.

    Runs inside the caller's ``except``, so a classifier fault must not replace the type-only
    error: anything it raises reads as a refusal, the side the split keeps when it cannot tell."""
    try:
        unavailable = is_vault_unavailable(exc)
    except Exception as fault:  # noqa: BLE001 -- see the docstring; the caller raises CipherError
        log.warning("Transit failure classifier raised %s; read as a refusal", type(fault).__name__)
        unavailable = False
    if unavailable:
        return CipherUnavailableError(f"Transit {op} failed (key={key!r}): {type(exc).__name__}")
    return CipherError(f"Transit {op} failed (key={key!r}): {vault_failure_text(exc)}")


class TransitCipher(_UnmarkedPolicy):
    """Bulk at-rest cipher whose crypto runs inside Vault/OpenBao Transit — the DEK never enters heap."""

    encrypts = True

    def __init__(
        self,
        client: Any,
        key_name: str,
        audit_key: str | None = None,
        *,
        allow_unmarked: bool = False,
    ) -> None:
        self._client = client
        self._key = key_name
        # The same unmarked-value refusal as the in-process cipher (BACKLOG #1169, ASVS 11.3.3).
        self._init_unmarked_policy(allow_unmarked)
        # The Transit key the audit-chain HMAC runs under. Defaults to the data key (Transit HMAC works
        # on any key type) so the chain is keyed-in-Transit by default; a dedicated key domain-separates.
        self._audit_key = audit_key or key_name

    @property
    def transit_key_name(self) -> str:
        """The Transit data key's NAME, never key material. ``serve`` checks that a recorded
        attestation names it (BACKLOG #2337), because the engine counts no AES-GCM invocations here."""
        return self._key

    def _associated_data(self, aad: bytes | None) -> str | None:
        # Transit's associated_data is base64; None → omit it (symmetric with a None-aad encrypt).
        return base64.b64encode(aad).decode("ascii") if aad is not None else None

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        pt_b64 = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        assoc = self._associated_data(aad)
        try:
            kwargs: dict[str, Any] = {"name": self._key, "plaintext": pt_b64}
            if assoc is not None:
                kwargs["associated_data"] = assoc
            response: Any = self._client.secrets.transit.encrypt_data(**kwargs)
            ciphertext = response["data"]["ciphertext"]  # "vault:v1:…" — no plaintext, no key
        except Exception as exc:
            # Type-only message: the plaintext going in is PHI; never surface it or the key material.
            raise _transit_failure("encrypt", self._key, exc) from exc
        return self._stored(ciphertext)

    def _stored(self, ciphertext: object) -> str:
        """Transit's ciphertext as the store keeps it, refused when it is not non-empty text."""
        if not isinstance(ciphertext, str) or not ciphertext:
            raise CipherError(f"Transit returned an empty ciphertext (key={self._key!r})")
        return f"{_V3_PREFIX}{ciphertext}"

    def decrypt(
        self, stored: str, *, aad: bytes | None = None, allow_unmarked: bool = False
    ) -> str:
        if not stored.startswith(MARKER_PREFIX):
            # A purged '' passes; any other unmarked value is refused unless policy allows it
            # (BACKLOG #1169) -- the byte-identical twin of the in-process cipher's seam.
            return self._pass_unmarked(stored, aad, allow_unmarked)
        if not stored.startswith(_V3_PREFIX):
            # An mfenc:v1/v2/v4 value is in-process AES-GCM; Transit holds no key that can read it. Fail
            # closed, never mis-decrypt. No command moves such a value into Transit (BACKLOG #2109), so
            # the refusal names none.
            raise CipherError(
                "value was encrypted in-process (mfenc:v1, v2 or v4); the Transit cipher cannot read it, "
                "and no command moves it into Transit (BACKLOG #2109)"
            )
        ciphertext = stored[len(_V3_PREFIX) :]  # the full "vault:v1:…" blob (may contain ':')
        assoc = self._associated_data(aad)
        try:
            kwargs: dict[str, Any] = {"name": self._key, "ciphertext": ciphertext}
            if assoc is not None:
                kwargs["associated_data"] = assoc
            response: Any = self._client.secrets.transit.decrypt_data(**kwargs)
            plaintext_b64 = response["data"]["plaintext"]
        except Exception as exc:
            # Covers a failed AEAD tag (wrong cell AAD / corrupt blob) AND transport failure — both fail
            # closed, and only the second is CipherUnavailableError (BACKLOG #3734). Type-only: a
            # Transit error can echo ciphertext, and we never surface key material.
            raise _transit_failure("decrypt", self._key, exc) from exc
        # Refused OUTSIDE the handler: a UnicodeDecodeError's .object is the decrypted plaintext, so
        # chaining it would put the PHI this cipher protects on the error (BACKLOG #2085).
        plaintext = _plaintext(plaintext_b64)
        if plaintext is None:
            raise self._malformed_plaintext()
        return plaintext

    def _malformed_plaintext(self) -> CipherError:
        return CipherError(f"Transit returned malformed plaintext (key={self._key!r})")

    def _batch_input(self, field: str, values: Sequence[CipherItem]) -> list[dict[str, str]]:
        """Transit's ``batch_input``: each value under ``field``, its AAD as ``associated_data``
        when it has one, and its place in the request as ``reference`` (BACKLOG #6706)."""
        batch_input: list[dict[str, str]] = []
        for place, (value, aad) in enumerate(values):
            item = {field: value, "reference": str(place)}
            assoc = self._associated_data(aad)
            if assoc is not None:
                item["associated_data"] = assoc
            batch_input.append(item)
        return batch_input

    def decrypt_many(self, items: Sequence[CipherItem]) -> list[str | CipherError]:
        """Each ``(stored, aad)`` of ``items`` opened, in order, in as few Transit ``decrypt``
        requests as the batch bounds allow (BACKLOG #6706). Each result is the plaintext or a
        :class:`CipherError` for that value; one value's failure is never another's result.

        A value that is not ``mfenc:v3`` goes to :meth:`decrypt`, which answers it without Transit.
        Vault's HTTP 400 to a batch, its answer when one value in it fails, sends each value of that
        batch alone, so each gets the verdict :meth:`decrypt` gives it. Any other failure of a batch
        request gave no verdict on any value: every value of the batch fails with it, and no later
        batch is sent. So does a reply :func:`_batch_replies` does not match to the request, as
        :class:`CipherUnavailableError`. A batch of one is a single request."""
        results: dict[int, str | CipherError] = {}
        sealed: list[int] = []
        for index, (stored, aad) in enumerate(items):
            if stored.startswith(_V3_PREFIX):
                sealed.append(index)
            else:
                results[index] = decrypt_or_error(self, stored, aad)
        down: CipherError | None = None
        for run in _batches([batch_chars(*items[i]) for i in sealed]):
            picked = [sealed[i] for i in run]
            if down is not None:
                opened = _unasked(down, len(picked))
            else:
                opened, stopped = self._decrypt_batch([items[i] for i in picked])
                if stopped and isinstance(opened[-1], CipherError):
                    down = opened[-1]
            for index, result in zip(picked, opened, strict=True):
                results[index] = result
        return [results[index] for index in range(len(items))]

    def _decrypt_batch(self, batch: list[CipherItem]) -> tuple[list[str | CipherError], bool]:
        """One run of :meth:`decrypt_many`, every value ``mfenc:v3``: the results in its order,
        and whether a failure that gave no verdict stops the runs after it."""
        if len(batch) == 1:
            one = decrypt_or_error(self, *batch[0])
            return [one], isinstance(one, CipherUnavailableError)
        sent = [(stored[len(_V3_PREFIX) :], aad) for stored, aad in batch]
        response: Any = None
        failure: CipherError | None = None
        ask_alone = False
        try:
            response = self._client.secrets.transit.decrypt_data(
                name=self._key, batch_input=self._batch_input("ciphertext", sent)
            )
        except Exception as exc:
            if is_vault_bad_request(exc):
                # Vault's 400 body is the whole batch_results, the other values' plaintext
                # included, and hvac makes it the error's message. So nothing keeps it, and each
                # value is asked for alone OUTSIDE this handler, where no error it returns can
                # carry the 400 on its chain (BACKLOG #2085).
                ask_alone = True
            else:
                failure = _transit_failure("decrypt", self._key, exc)
                failure.__cause__ = exc
        if ask_alone:
            alone: list[str | CipherError] = []
            for stored, aad in batch:
                result = decrypt_or_error(self, stored, aad)
                alone.append(result)
                if isinstance(result, CipherUnavailableError):
                    alone.extend(_unasked(result, len(batch) - len(alone)))
                    return alone, True
            return alone, False
        if failure is not None:
            return _unasked(failure, len(batch)), True
        replies = _batch_replies(response, len(batch))
        if replies is None:
            mismatch = CipherUnavailableError(
                f"Transit's batch decrypt reply does not match the request (key={self._key!r})"
            )
            return _unasked(mismatch, len(batch)), True
        opened: list[str | CipherError] = []
        for reply in replies:
            if reply.get("error"):
                # Vault's own text is not quoted: it is a reply this process did not write.
                opened.append(CipherError(f"Transit refused the value (key={self._key!r})"))
                continue
            plaintext = _plaintext(reply.get("plaintext"))
            opened.append(plaintext if plaintext is not None else self._malformed_plaintext())
        return opened, False

    def encrypt_many(self, items: Sequence[CipherItem]) -> list[str]:
        """Each ``(plaintext, aad)`` of ``items`` sealed, in order, in as few Transit ``encrypt``
        requests as the batch bounds allow (BACKLOG #6706). Any failure raises as :meth:`encrypt`
        does, so no value is returned unless all sealed. A batch request Transit could not serve
        raises :class:`CipherUnavailableError`; one it refused, a proxy's request-size bound among
        them, seals each value of that batch alone. A reply :func:`_batch_replies` does not match
        to the request raises :class:`CipherError`. A batch of one is a single request."""
        costs = [
            b64_chars(len(plaintext.encode("utf-8"))) + batch_chars("", aad)
            for plaintext, aad in items
        ]
        sealed: list[str] = []
        for run in _batches(costs):
            if len(run) == 1:
                plaintext, aad = items[run[0]]
                sealed.append(self.encrypt(plaintext, aad=aad))
            else:
                sealed.extend(self._encrypt_batch([items[i] for i in run]))
        return sealed

    def _encrypt_batch(self, batch: list[CipherItem]) -> list[str]:
        """One run of :meth:`encrypt_many`, the sealed values in its order."""
        sent = [
            (base64.b64encode(plaintext.encode("utf-8")).decode("ascii"), aad)
            for plaintext, aad in batch
        ]
        response: Any = None
        refused = False
        try:
            response = self._client.secrets.transit.encrypt_data(
                name=self._key, batch_input=self._batch_input("plaintext", sent)
            )
        except Exception as exc:
            # Type-only message: the plaintext going in is PHI; never surface it or the key material.
            failure = _transit_failure("encrypt", self._key, exc)
            if isinstance(failure, CipherUnavailableError):
                raise failure from exc
            refused = True  # sealed alone below, outside this handler
        if refused:
            return [self.encrypt(plaintext, aad=aad) for plaintext, aad in batch]
        replies = _batch_replies(response, len(batch))
        if replies is None:
            raise CipherError(
                f"Transit's batch encrypt reply does not match the request (key={self._key!r})"
            )
        out: list[str] = []
        for reply in replies:
            if reply.get("error"):
                raise CipherError(f"Transit refused a value (key={self._key!r})")
            out.append(self._stored(reply.get("ciphertext")))
        return out

    def is_encrypted(self, stored: str) -> bool:
        return stored.startswith(MARKER_PREFIX)

    def audit_mac_key(self) -> None:
        """No in-heap DEK to HKDF a raw HMAC key from — so there is NO in-process key. The chain is still
        keyed, but the MAC runs inside Transit via :meth:`audit_mac_fn` / :meth:`audit_hmac`, NOT here.
        Returning ``None`` keeps this the honest signal 'no in-heap key material'."""
        return None

    def audit_mac_keyring(self) -> Mapping[str, bytes]:
        """No in-heap audit keys. Transit versions its own audit key, so the engine sees one range."""
        return {}

    def authz_root(self) -> None:
        """No in-heap DEK, so no in-process authorization root (BACKLOG #2592). Row seals under this
        provider are Transit's own HMAC under the audit key: the store's
        :class:`~messagefoundry.store.row_seal.TransitRowSealer` (ADR 0217 slice 1b-iii), which
        ``row_sealer_for_cipher`` builds for this cipher, not a sealer keyed from this root."""
        return None

    def row_seal_backend(self) -> TransitCipher:
        """This cipher: it makes the Transit ``hmac`` and ``verify`` calls the store's
        :class:`~messagefoundry.store.row_seal.TransitRowSealer` seals authority rows through, under
        the audit key (ADR 0217 slice 1b-iii, item 3.7)."""
        return self

    def retired_authz_roots(self) -> Sequence[bytes]:
        """No in-heap DEK, so no retired roots either (BACKLOG #2592)."""
        return ()

    def audit_hmac(self, data: bytes, *, key_version: int | None = None) -> str:
        """Compute the audit-chain row MAC INSIDE Transit (``generate_hmac``) — no key ever enters heap.

        Returns Transit's own ``vault:v1:…`` HMAC string (deterministic for a given input+key+version, so
        the chain round-trips at :meth:`~messagefoundry.store.store.MessageStore.verify_audit_chain`; a
        different input yields a different MAC → tamper/forgery is detected). ADR 0138 §To-resolve: this
        moves the audit chain from keyless SHA-256 to forgery-**resistant** without an in-heap key,
        closing the ASVS 16.4.2 residual for ``vault_transit`` mode. Fail-closed: any Transit error raises
        :class:`CipherError` (type-only — the canonical row bytes are PHI-derived and never surfaced).

        ``key_version`` pins the Transit key version; ``None`` means Transit's latest. A check of a
        stored MAC passes the version that MAC names (BACKLOG #2337), so a key rotation does not make
        an older row read as forged. A pinned call that gets an HTTP 400 that hvac raises as
        ``InvalidRequest``, while a probe under the latest version answers with a string that does
        not start ``vault:v<pinned>:``, raises :class:`AuditKeyVersionRefusedError` (see
        :meth:`_refuses_only_version`); Transit refusing the version is one cause, not the only one.
        It raises the subclass :class:`AuditKeyVersionUnverifiedError` when
        :func:`_names_no_version_reason` does not read the 400 as Vault's own refusal, for example a
        proxy's page, or when reading it runs out of memory or stack (BACKLOG #6707).

        A 400 on which hvac raises an exception other than ``InvalidRequest`` raises neither of
        those (BACKLOG #6707). For example, these
        exact 400 bodies with the Content-Type exactly ``application/json``: ``[]``, ``null``,
        ``{"errors":[{"message":"x"}]}``, ``{"errors":[1]}``, ``{"errors":5}`` and
        ``{"errors":true}``. On each, hvac 2.4.0 raises ``AttributeError`` or ``TypeError`` in
        place of ``InvalidRequest``. A ``MemoryError`` that hvac raises while it joins a truthy
        ``errors`` value, before it raises any ``InvalidRequest``, is not read as a refusal either.
        Each raises plain :class:`CipherError`, so the walk could not run and no tamper alert
        fires."""
        inp = base64.b64encode(data).decode("ascii")
        kwargs: dict[str, Any] = {
            "name": self._audit_key,
            "hash_input": inp,
            "algorithm": AUDIT_TRANSIT_HASH_ALGO,
        }
        if key_version is not None:
            kwargs["key_version"] = key_version
        try:
            response: Any = self._client.secrets.transit.generate_hmac(**kwargs)
            mac = response["data"]["hmac"]  # "vault:v1:…" — no key, no plaintext
        except Exception as exc:
            if key_version is not None and self._refuses_only_version(exc, key_version):
                # The same flow, labelled apart (BACKLOG #6707). A reply that runs out of memory or
                # stack while it is read, such as a huge errors list, is not read as a refusal:
                # escaping here, the error would make the walk "could not run" and drop the row's
                # break and its alert.
                unreadable: str | None = None
                try:
                    unverified = _names_no_version_reason(exc)
                except (MemoryError, RecursionError) as read_exc:
                    unverified, unreadable = True, type(read_exc).__name__
                if unreadable is not None:  # logged once the handler has freed what it held
                    log.warning(
                        "could not read the 400 for audit key version %d (%s); labelled "
                        "unconfirmed (key=%r)",
                        key_version,
                        unreadable,
                        self._audit_key,
                    )
                if unverified:
                    raise AuditKeyVersionUnverifiedError(key_version) from exc
                raise AuditKeyVersionRefusedError(key_version) from exc
            raise CipherError(
                f"Transit audit HMAC failed (key={self._audit_key!r}): {vault_failure_text(exc)}"
            ) from exc
        if not isinstance(mac, str) or not mac:
            raise CipherError(f"Transit returned an empty audit HMAC (key={self._audit_key!r})")
        return mac

    def _refuses_only_version(self, exc: Exception, key_version: int) -> bool:
        """Whether ``exc``, raised by a call pinned to ``key_version``, is Transit refusing that
        version rather than an outage (BACKLOG #2337).

        Transit answers a version above the latest, or below the policy minimum, with HTTP 400,
        which hvac raises as ``InvalidRequest``. A dropped connection, a rate limit or a sealed node
        raises another class, so none of those reads as a refused version. A 400 can also mean the
        key itself is missing, so a probe under the latest version, over FIXED input, must succeed
        too. Fixed input keeps a row's own content from deciding the answer. The probe must also
        answer with a string that does not start ``vault:v<pinned>:``; an empty string or one
        naming no version passes too.

        This infers the cause from the reply; it does not read the key's version range. So a node
        whose copy of the key lags a rotation can refuse a real, newer version and still pass."""
        if not is_vault_bad_request(exc):
            return False
        try:
            probe: Any = self._client.secrets.transit.generate_hmac(
                name=self._audit_key,
                hash_input=_VERSION_PROBE_INPUT,
                algorithm=AUDIT_TRANSIT_HASH_ALGO,
            )
            answered = probe["data"]["hmac"]
        except Exception as probe_exc:  # the latest version fails too: not a version refusal
            log.warning(
                "Transit refused audit key version %d, and the probe under the latest version failed "
                "too (key=%r): %s",
                key_version,
                self._audit_key,
                vault_failure_text(probe_exc),
            )
            return False
        return isinstance(answered, str) and not answered.startswith(f"vault:v{key_version}:")

    # --- The row seal backend (ADR 0217; TransitSealBackend in store/row_seal.py) -----------------

    @property
    def seal_key_name(self) -> str:
        """The Transit key row seals are made under: the audit key, which is the data key when no
        audit key is set. Transit receives only a 32-byte digest per seal, so a seal stays apart from
        the key's other MACs only while no other caller MACs a bare 32-byte value under it; the
        seal's label sits inside the digest's preimage and plays no part in that (ADR 0217)."""
        return self._audit_key

    @property
    def seal_mount(self) -> str:
        """The Transit mount every call here reaches (hvac's default)."""
        return TRANSIT_MOUNT

    def _seal_generate(self, hash_input: str, what: str) -> object:
        """One Transit ``hmac`` under the active audit key's latest version, for a row seal or its
        probe. Returns Transit's raw value; the sealer checks its shape. Any failure raises
        :class:`CipherError` naming the key and Vault's failure text, never the input."""
        try:
            response: Any = self._client.secrets.transit.generate_hmac(
                name=self._audit_key, hash_input=hash_input, algorithm=AUDIT_TRANSIT_HASH_ALGO
            )
            return response["data"]["hmac"]
        except Exception as exc:
            raise CipherError(
                f"Transit row seal {what} failed (key={self._audit_key!r}): "
                f"{vault_failure_text(exc)}"
            ) from exc

    def seal_hmac(self, digest: bytes) -> object:
        """Transit's ``hmac`` of a row seal input's 32-byte ``digest`` under the latest version.
        Blocking."""
        return self._seal_generate(base64.b64encode(digest).decode("ascii"), "HMAC")

    def seal_probe(self) -> object:
        """Transit's ``hmac`` over fixed input under the active audit key's latest version: the
        probe that tells an unverifiable seal from an outage. Fixed input, so no row decides it.
        Blocking."""
        return self._seal_generate(_VERSION_PROBE_INPUT, "probe")

    def verify_seal_hmac(self, key_name: str, digest: bytes, mac: str) -> object:
        """Transit's ``verify`` of ``mac`` over ``digest`` under ``key_name``, at the version ``mac``
        names; it never regenerates and compares, since a MAC under a newer version differs from
        every stored one. Returns Transit's raw ``valid`` (``False`` is ``valid: false``); the sealer
        checks its shape. An HTTP 400 or 403 raises
        :class:`~messagefoundry.store.crypto.TransitSealRefused` with that status, raised outside the
        handler so no chain carries Vault's reply; anything else raises :class:`CipherError`.
        Blocking."""
        hash_input = base64.b64encode(digest).decode("ascii")
        refused = 0
        try:
            response: Any = self._client.secrets.transit.verify_signed_data(
                name=key_name,
                hash_input=hash_input,
                hmac=mac,
                hash_algorithm=AUDIT_TRANSIT_HASH_ALGO,
            )
            return response["data"]["valid"]
        except Exception as exc:
            refused = 400 if is_vault_bad_request(exc) else 403 if is_vault_forbidden(exc) else 0
            if not refused:
                raise CipherError(
                    f"Transit row seal verify failed (key={key_name!r}): {vault_failure_text(exc)}"
                ) from exc
        raise TransitSealRefused(refused)

    def audit_mac_fn(self) -> AuditMacFn:
        """The audit-chain MAC provider: route each row's MAC through Transit (:meth:`audit_hmac`). The
        store uses this INSTEAD of an in-heap ``hmac.new(key, …)`` when present, so the audit chain is
        keyed even though :meth:`audit_mac_key` is ``None`` (the key stays inside the isolated module)."""
        return self.audit_hmac


def _key_names() -> tuple[str, str]:
    """The Transit data key and audit key from the environment, read in one place for the cipher
    and for :func:`transit_cipher_required_capabilities`. Raises :class:`KeyProviderError` when the
    data-key name is not set, and when either name is not a Transit key name (BACKLOG #6010): both
    go into Transit request paths, so each is checked here, before any client is built."""
    key_name = os.environ.get(_ENV_TRANSIT_KEY)
    if not key_name:
        raise KeyProviderError(
            f"[store].cipher_provider={PROVIDER_NAME!r} is selected but {_ENV_TRANSIT_KEY} is not set — "
            f"supply the Transit data-key name via the environment."
        )
    key_name = checked_transit_key_name(key_name, selector=_ENV_TRANSIT_KEY)
    # Optional dedicated audit-HMAC key; unset ⇒ reuse the data key. Either way the type is checked
    # at build — see the _ENV_AUDIT_KEY comment above for which types each use admits and why.
    audit_key = os.environ.get(_ENV_AUDIT_KEY)
    return key_name, (
        checked_transit_key_name(audit_key, selector=_ENV_AUDIT_KEY) if audit_key else key_name
    )


def build_transit_cipher(
    settings: StoreSettings, *, posture: HopPosture | None = None
) -> TransitCipher:
    """Construct the Transit cipher from the environment, failing **closed** at startup.

    ``posture`` is the instance posture the caller holds, for the revocation guard on this hop
    (vault BACKLOG #2983). ``None`` counts as enforcing.

    ``settings`` is accepted for signature parity with ``make_cipher``/``build_store_cipher`` (the Vault
    address/token/key are env-only secrets/provisioning outputs, like the KEK-unwrap provider). A missing
    key name, a missing extra, or an unreachable/unknown Transit key raises :class:`KeyProviderError` so
    ``open_store`` refuses to start rather than degrading to plaintext."""
    key_name, audit_key = _key_names()
    # Read once, so this cipher's client keeps the token it was built with for the life of the
    # process. A token replaced afterwards, in the environment or the secrets directory, is not
    # seen until the store is opened again.
    addr, token = store_vault_hop()
    # OUTSIDE the try on purpose. `_build_client` asserts this hop's TLS suites (ADR 0180) and raises
    # ValueError; the `except Exception` below would relabel that "could not reach a Vault Transit
    # key", turning a configuration refusal into what reads as a connectivity failure. Fail-closed is
    # unchanged either way: both paths propagate and the cipher provider refuses to come up.
    # lazy hvac import; fails closed naming the [vault] extra
    client = _build_client(
        addr,
        token,
        revocation_attested=settings.vault_revocation_attested,
        posture=posture,
        revocation_reason=settings.vault_revocation_attested_reason,
    )
    try:
        # Startup connectivity + key-existence + key-TYPE check: read the key metadata (no crypto, no
        # secrets). This turns a mis-provisioned Vault into a refuse-to-start rather than a first-write
        # dead-letter. BACKLOG #1166, owner ruling 2026-08-22: the round trip was already being paid for
        # and the ANSWER was thrown away, so an operator could back every at-rest PHI encrypt with a
        # signing-only, MAC-only or sub-128-bit key and nothing objected. The answer is now read.
        require_transit_key_type(
            client,
            key_name,
            allowed=TRANSIT_KEY_TYPES_DATA,
            use="at-rest PHI encryption (Transit encrypt/decrypt with cell associated_data)",
            selector=_ENV_TRANSIT_KEY,
            # This key encrypts the cells themselves, so unlike the KEK there is nothing to re-wrap,
            # and `rotate-key` does not re-encrypt between two Transit keys. Say so, rather than let
            # a store that holds data be repointed into one no key can fully read.
            after_switch=(
                "Only a store with no data yet can switch this way: cells already encrypted under "
                "the old key, and audit rows MACed under it while "
                f"{_ENV_AUDIT_KEY} is unset, would not read or verify under the new one, and no "
                "command moves Transit ciphertext between keys."
            ),
        )
        # Same fail-closed existence + type check for a DEDICATED audit key (skip the redundant read
        # when it is the data key we just verified) — a mis-set audit key must refuse to start, not
        # dead-letter the first audit-row append. A SHARED key therefore lands on the narrower
        # data-key set, which is correct: it has to do both jobs.
        if audit_key != key_name:
            require_transit_key_type(
                client,
                audit_key,
                allowed=TRANSIT_KEY_TYPES_AUDIT,
                use="the audit-chain MAC (Transit generate_hmac)",
                selector=_ENV_AUDIT_KEY,
                after_switch=(
                    "Vault's `hmac` type is the dedicated choice for this key. Audit rows already "
                    "MACed under the old key would not verify under the new one."
                ),
            )
    except KeyProviderError:
        raise
    except Exception as exc:
        raise KeyProviderError(
            f"[store].cipher_provider={PROVIDER_NAME!r} could not reach a Vault transit key "
            f"(data={key_name!r}, audit={audit_key!r}, extra {_EXTRA!r}): {vault_failure_text(exc)}."
        ) from exc
    return TransitCipher(
        client, key_name, audit_key=audit_key, allow_unmarked=settings.allow_unmarked_ciphertext
    )


def transit_cipher_required_capabilities() -> dict[str, frozenset[str]]:
    """Every Vault path the Transit cipher calls, with the capability each call needs (BACKLOG #305).

    Kept beside the calls so the two cannot drift. :func:`build_transit_cipher` reads each key's
    metadata (``transit/keys/<key>``, read); :meth:`TransitCipher.encrypt` and
    :meth:`TransitCipher.decrypt` update ``transit/encrypt/<data key>`` and
    ``transit/decrypt/<data key>``; :meth:`TransitCipher.audit_hmac` updates
    ``transit/hmac/<audit key>``, which is the data key when no audit key is set, and the row seal
    check (:meth:`TransitCipher.verify_seal_hmac`, ADR 0217) updates
    ``transit/verify/<audit key>``. Raises
    :class:`KeyProviderError` when the data-key name is not set, as the cipher itself does."""
    key_name, audit_key = _key_names()
    read, update = frozenset({"read"}), frozenset({"update"})
    return {
        f"{TRANSIT_MOUNT}/keys/{key_name}": read,
        f"{TRANSIT_MOUNT}/encrypt/{key_name}": update,
        f"{TRANSIT_MOUNT}/decrypt/{key_name}": update,
        f"{TRANSIT_MOUNT}/keys/{audit_key}": read,
        f"{TRANSIT_MOUNT}/hmac/{audit_key}": update,
        f"{TRANSIT_MOUNT}/verify/{audit_key}": update,
    }
