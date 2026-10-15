# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every call that can lead to a Vault hop, and the posture it passes (vault BACKLOG #2983).

The revocation guard on the three Vault hops is keyed on the instance posture. The providers hold
no ``[security]`` section, so the posture is handed down a chain of calls, from ``open_store`` and
``resolve_secret_provider`` to the guard in ``transports/strict_requests.py``. Each link takes it as
an optional argument, and **leaving it out is the strict answer**: an unknown posture counts as
enforcing.

So no caller can loosen the guard by forgetting the argument. What could loosen it is a caller that
passes a posture it made up, or a new link that drops the one it was handed. This file lists every
call to a link of that chain under ``messagefoundry/`` and ``harness/``, with the expression it
passes. A new call, or a changed expression, turns
:func:`test_every_link_of_the_posture_chain_is_listed` red, and a person then decides what that
caller should pass.

**A caller listed with** ``-`` **passes no posture, on purpose.** It is at least every command that
opens a store with no posture in scope, and it is judged like an enforcing instance.

**What the scan cannot see.** It reads the expression a call passes, not where that value came
from. A caller that builds a posture, binds it to a local named ``posture`` and passes that reads
as handed down. Two more lists narrow that, and neither closes it:

* :func:`test_every_place_a_posture_is_built_is_listed` lists every place the name
  ``HopPosture`` is used as a value.
* :func:`test_every_posture_derivation_reads_the_instances_own_dial` lists every call to
  ``hop_posture_from_ai``, with the dial it is given.

A posture reached some other way is still unseen: at least ``dataclasses.replace``, an import
under another name, or ``current_hop_posture()``. A link this file does not name is not scanned
either. So read these lists as at least the chain as it stood when this was written (SDS-3.6),
and read a new caller's posture in review.

The scan reads source, so it holds with no Vault extra installed.
"""

from __future__ import annotations

import ast
import functools
from collections import Counter
from collections.abc import Callable, Iterable

import pytest

from tests._ast_sites import callee_name, parse_source

# One walk of the package, and one floor on how many modules it must find, for both censuses.
from tests.test_vault_revocation_attestation import _PACKAGE, _modules

#: Passed where a call names no posture at all.
_NONE = "-"
#: A link used as a value and called somewhere this scan cannot follow.
_BY_REFERENCE = "by reference"

#: Each link of the chain, by the name a call spells, with the position its posture takes when
#: it is not a keyword. ``None`` means the link takes it by keyword only.
_LINKS: dict[str, int | None] = {
    # the store side
    "open_store": None,
    "build_store_cipher": None,
    "_build_store_cipher": 1,
    "resolve_active_key": None,
    "resolve_decrypt_keys": None,
    "resolve_key_provider": None,
    "build_transit_cipher": None,
    "VaultKeyProvider": None,
    # the secrets side
    "resolve_secret_provider": None,
    "VaultSecretProvider": None,
    # both dispatches, and both providers' entry points
    "_load_external_provider": 2,
    "build_provider": None,
    # the client build and the guard
    "_build_client": None,
    "mount_strict_reply_adapter": None,
    "StrictReplyAdapter": None,
    "_refuse_an_unrevoked_vault_hop": None,
    # check-privileges
    "probe_vault": None,
    "store_vault_client": None,
    "secrets_vault_client": None,
    # the DR backup runner, which resolves the key on every pass, and the restore family
    "BackupRunner": None,
    "_BackupRunner": None,
    "_verify_archive_blocking": None,
    "_verify_in_staging": None,
    "_full_open_check": None,
    "_decrypt_check": None,
    "run_restore_verify": None,
    "run_restore": None,
    "DrCoordinator": None,
    # the engine, which hands its posture to the backup runner and the DR coordinator
    "Engine": None,
    # the offline commands' security notifier, which resolves an SMTP secret
    "_offline_security_notifier": 1,
}
_KEYWORDS = ("posture", "hop_posture")

#: The one name that builds a posture. Any use of it as a value is a row: a call, or a
#: ``HopPosture.fail_closed(...)``, which reads the name first. An annotation is not a use.
_BUILDERS: dict[str, int | None] = {"HopPosture": None}

#: The expressions a caller may pass: a posture it was handed or holds, and nothing it built.
_HANDED_DOWN = frozenset(
    {_NONE, "posture", "hop_posture", "_hop_posture", "self._posture", "self._hop_posture"}
)

Row = tuple[str, str, str, str]

#: The one expression ``serve`` derives its posture with, where it is written inline.
_SERVE_DERIVATION = (
    "hop_posture_from_ai(ai_settings, enforcement=(security_settings or "
    "SecuritySettings()).enforcement) if ai_settings else None"
)
#: Each listed call that passes something other than a name it was handed, and why that is right.
#: A new one must be argued here, in review.
_NOT_HANDED_DOWN: dict[Row, str] = {
    ("api/app.py", "create_managed_app.lifespan", "Engine", _SERVE_DERIVATION): (
        "derived on the spot from the instance's own [ai] and [security] settings, by the same "
        "function as the lifespan's _hop_posture"
    ),
    (
        "harness/load/connscale/runner.py",
        "_store_reader._read",
        "open_store",
        "HopPosture(enforcing=False)",
    ): (
        "a synthetic load rig. It holds no instance settings and declares a warn posture for its "
        "own rig store (vault BACKLOG #2354). If its settings ever named a Vault provider, an "
        "unattested off-box Vault would be warned there, not refused"
    ),
}


class _Scan(ast.NodeVisitor):
    """One row per call to a link: module, enclosing function by qualified name, link, posture."""

    def __init__(
        self,
        relative: str,
        links: dict[str, int | None],
        shape: Callable[[ast.Call, int | None], str] | None = None,
    ) -> None:
        self.relative = relative
        self.links = links
        #: What a row records about a call. The posture it passes, unless a caller says otherwise.
        self.shape = shape or _posture_of
        self.scope: list[str] = []
        self.rows: list[Row] = []
        #: The nodes already counted as a call, so they are not counted again as a reference.
        self.seen: set[int] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """The defaults and the body. Annotations are skipped: a link named as a type is not a
        use of it."""
        self.scope.append(node.name)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        for statement in node.body:
            self.visit(statement)
        self.scope.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)

    def _row(self, name: str, shape: str) -> None:
        self.rows.append((self.relative, ".".join(self.scope) or "<module>", name, shape))

    def visit_Call(self, node: ast.Call) -> None:
        name = callee_name(node)
        if name is not None and name in self.links:
            self.seen.add(id(node.func))
            self._row(name, self.shape(node, self.links[name]))
        # A link handed to a runner as its first argument, with the link's own keywords after it:
        # `asyncio.to_thread(link, ..., posture=...)` or `functools.partial(link, posture=...)`.
        target = _link_named(node.args[0], self.links) if node.args else None
        if target is not None:
            self.seen.add(id(node.args[0]))
            self._row(target, _posture_of(node, None))
        self.generic_visit(node)

    def _reference(self, node: ast.Name | ast.Attribute) -> None:
        """Any other use of a link's name as a value, such as a callback argument. The caller
        that finally calls it is out of this scan's sight, so the row says so."""
        if isinstance(node.ctx, ast.Load) and id(node) not in self.seen:
            name = _link_named(node, self.links)
            if name is not None:
                self._row(name, _BY_REFERENCE)
        self.generic_visit(node)

    visit_Name = _reference
    visit_Attribute = _reference


def _link_named(node: ast.expr, links: dict[str, int | None]) -> str | None:
    name = node.id if isinstance(node, ast.Name) else getattr(node, "attr", None)
    return name if isinstance(node, ast.Name | ast.Attribute) and name in links else None


def _posture_of(call: ast.Call, position: int | None) -> str:
    for keyword in call.keywords:
        if keyword.arg in _KEYWORDS:
            return ast.unparse(keyword.value)
    if position is not None and len(call.args) > position:
        return ast.unparse(call.args[position])
    return _NONE


def _scan(source: str, relative: str, links: dict[str, int | None] = _LINKS) -> list[Row]:
    scan = _Scan(relative, links)
    scan.visit(parse_source(source))
    return scan.rows


_HARNESS = _PACKAGE.parent / "harness"


def _sources() -> list[tuple[str, str]]:
    """Each module to scan, as its listed name and its source. A module under ``messagefoundry/``
    is named from there, as the attestation census names it; one under ``harness/`` keeps that
    prefix. The harness is a client, but its load rigs open a store themselves."""
    rigs = sorted(_HARNESS.rglob("*.py"))
    assert len(rigs) >= 20, f"the walk found only {len(rigs)} module(s) under {_HARNESS}"
    named = [(path.relative_to(_PACKAGE).as_posix(), path) for path in _modules()]
    named += [(path.relative_to(_PACKAGE.parent).as_posix(), path) for path in rigs]
    return [(relative, path.read_text(encoding="utf-8")) for relative, path in named]


def _rows(links: dict[str, int | None]) -> tuple[Row, ...]:
    rows: list[Row] = []
    for relative, source in _sources():
        # Code that calls a link has to spell its name, so a file that spells none is not parsed.
        if any(name in source for name in links):
            rows.extend(_scan(source, relative, links))
    return tuple(sorted(rows))


@functools.cache
def _found() -> tuple[Row, ...]:
    """Every call to a link under ``messagefoundry/`` and ``harness/``, sorted. Scanned once."""
    return _rows(_LINKS)


#: Every call to a link, at the commit that last changed this list. Sorted, and a list, so two
#: calls in one function are two rows and neither can hide behind the other.
_CENSUS: list[Row] = sorted(
    [
        ("__main__.py", "_admin_reset_totp.opened", "open_store", "-"),
        ("__main__.py", "_admin_set_notify_email.run", "open_store", "-"),
        ("__main__.py", "_admin_unlock.run", "open_store", "-"),
        ("__main__.py", "_audit_anchor.run", "open_store", "-"),
        ("__main__.py", "_audit_verify.run", "open_store", "-"),
        ("__main__.py", "_backup.run", "_BackupRunner", "-"),
        ("__main__.py", "_backup.run", "open_store", "-"),
        ("__main__.py", "_build_provision_auth_service", "resolve_secret_provider", "posture"),
        ("__main__.py", "_check_privileges", "probe_vault", "posture"),
        ("__main__.py", "_admin_reset_totp.notice", "_offline_security_notifier", "-"),
        ("__main__.py", "_offline_security_notifier", "resolve_secret_provider", "posture"),
        ("__main__.py", "_provision_admin.run", "_offline_security_notifier", "posture"),
        ("__main__.py", "_restore", "run_restore", "-"),
        ("__main__.py", "_restore_verify", "run_restore_verify", "-"),
        ("__main__.py", "_provision_admin", "build_store_cipher", "posture"),
        ("__main__.py", "_provision_admin.administrator_exists", "open_store", "posture"),
        ("__main__.py", "_provision_admin.run", "open_store", "posture"),
        ("__main__.py", "_renew_api_tls_before_spawning._audit", "open_store", "posture"),
        ("__main__.py", "_rotate_key", "resolve_active_key", "-"),
        ("__main__.py", "_rotate_key.run", "open_store", "-"),
        ("__main__.py", "_store_transit_bound.run", "open_store", "-"),
        ("api/app.py", "create_app", "build_store_cipher", "posture"),
        ("api/app.py", "create_managed_app.lifespan", "Engine", _SERVE_DERIVATION),
        (
            "harness/load/connscale/runner.py",
            "_store_reader._read",
            "open_store",
            "HopPosture(enforcing=False)",
        ),
        ("pipeline/dr.py", "DrCoordinator._verify_seed", "run_restore_verify", "self._hop_posture"),
        ("pipeline/engine.py", "Engine.dr_coordinator", "DrCoordinator", "self._hop_posture"),
        ("api/app.py", "create_managed_app.lifespan", "open_store", "_hop_posture"),
        ("api/app.py", "create_managed_app.lifespan", "resolve_secret_provider", "_hop_posture"),
        ("config/secretprovider.py", "_load_external_provider", "build_provider", "posture"),
        (
            "config/secretprovider.py",
            "resolve_secret_provider",
            "_load_external_provider",
            "posture",
        ),
        (
            "config/secretprovider_vault.py",
            "VaultSecretProvider.resolve",
            "_build_client",
            "self._posture",
        ),
        (
            "config/secretprovider_vault.py",
            "_build_client",
            "mount_strict_reply_adapter",
            "posture",
        ),
        ("config/secretprovider_vault.py", "build_provider", "VaultSecretProvider", "posture"),
        ("config/secretprovider_vault.py", "secrets_vault_client", "_build_client", "posture"),
        (
            "pipeline/dr_backup.py",
            "BackupRunner._resolve_key",
            "resolve_active_key",
            "self._hop_posture",
        ),
        (
            "pipeline/dr_backup.py",
            "BackupRunner._verify_and_publish",
            "_verify_archive_blocking",
            "self._hop_posture",
        ),
        ("pipeline/dr_backup.py", "_decrypt_check", "build_store_cipher", "posture"),
        ("pipeline/dr_backup.py", "_full_open_check", "_decrypt_check", "posture"),
        ("pipeline/dr_backup.py", "_full_open_check._open", "open_store", "posture"),
        ("pipeline/dr_backup.py", "_verify_archive_blocking", "_verify_in_staging", "posture"),
        ("pipeline/dr_backup.py", "_verify_in_staging", "_full_open_check", "posture"),
        ("pipeline/dr_backup.py", "run_restore", "resolve_decrypt_keys", "-"),
        ("pipeline/dr_backup.py", "run_restore_verify", "_verify_archive_blocking", "posture"),
        ("pipeline/dr_backup.py", "run_restore_verify", "resolve_decrypt_keys", "posture"),
        ("pipeline/engine.py", "Engine.start", "BackupRunner", "self._hop_posture"),
        ("privilege_probes.py", "probe_vault", "secrets_vault_client", "posture"),
        ("privilege_probes.py", "probe_vault", "store_vault_client", "posture"),
        ("privilege_probes.py", "read_ldap_bind", "resolve_secret_provider", "posture"),
        ("store/base.py", "_build_store_cipher", "build_transit_cipher", "posture"),
        ("store/base.py", "_build_store_cipher", "resolve_active_key", "posture"),
        ("store/base.py", "build_store_cipher", "_build_store_cipher", "posture"),
        ("store/base.py", "open_store", "build_store_cipher", "posture"),
        ("store/base.py", "resolve_active_key", "resolve_key_provider", "posture"),
        ("store/base.py", "resolve_decrypt_keys", "resolve_key_provider", "posture"),
        ("store/crypto_transit.py", "build_transit_cipher", "_build_client", "posture"),
        ("store/keyprovider.py", "_load_external_provider", "build_provider", "posture"),
        ("store/keyprovider.py", "resolve_key_provider", "_load_external_provider", "posture"),
        (
            "store/keyprovider_vault.py",
            "VaultKeyProvider.active_key",
            "_build_client",
            "self._posture",
        ),
        ("store/keyprovider_vault.py", "_build_client", "mount_strict_reply_adapter", "posture"),
        ("store/keyprovider_vault.py", "build_provider", "VaultKeyProvider", "posture"),
        ("store/keyprovider_vault.py", "store_vault_client", "_build_client", "posture"),
        ("support/bundle.py", "_db_info", "open_store", "-"),
        # The adapter keeps the posture it was built with. Its one method runs the guard for the
        # mount and for each send, so the guard has one caller.
        (
            "transports/strict_requests.py",
            "StrictReplyAdapter.refuse_an_unrevoked_hop",
            "_refuse_an_unrevoked_vault_hop",
            "self._posture",
        ),
        (
            "transports/strict_requests.py",
            "mount_strict_reply_adapter",
            "StrictReplyAdapter",
            "posture",
        ),
        ("verify/checks.py", "check_lockable_accounts._census", "open_store", "-"),
        # Strict on purpose; `_client_credential_row`'s docstring says why.
        ("verify/federation.py", "_client_credential_row", "resolve_secret_provider", "-"),
        ("verify/smoke.py", "check_smoke_disposition._poll", "open_store", "-"),
        ("verify/smoke.py", "check_store_connectivity._open_close", "open_store", "-"),
        ("verify/smoke.py", "newest_message_id._newest", "open_store", "-"),
    ]
)


def _difference(found: Iterable[Row]) -> tuple[list[Row], list[Row]]:
    """The rows found and not listed, and the rows listed and not found. Counted, not as sets, so a
    second identical call is a difference."""
    have, want = Counter(found), Counter(_CENSUS)
    return sorted((have - want).elements()), sorted((want - have).elements())


def test_every_link_of_the_posture_chain_is_listed() -> None:
    """A new caller, or a caller that changed what it passes, must be read by a person. Add its
    row to ``_CENSUS`` once it passes the posture it was handed, or ``-`` where it holds none.

    Mutation: drop ``posture=posture`` from the ``build_store_cipher`` call in ``open_store``."""
    unlisted, stale = _difference(_found())
    assert unlisted == [], "a call to a link of the posture chain is not in _CENSUS"
    assert stale == [], "a row in _CENSUS matches no call any more"


def test_no_caller_passes_a_posture_it_built() -> None:
    """The one way a caller could turn the guard off is to pass a posture of its own making, such
    as ``HopPosture(enforcing=False)``. Every listed expression is a name the caller was handed
    or holds, except the rows :data:`_NOT_HANDED_DOWN` argues one by one.

    This judges the expression, not where its value came from; the next test covers that."""
    built = [row for row in _CENSUS if row[3] not in _HANDED_DOWN]
    assert sorted(built) == sorted(_NOT_HANDED_DOWN)
    assert all(_NOT_HANDED_DOWN.values())


#: Every place a posture is built, in ``messagefoundry/`` and ``harness/``: module and function.
#: A caller that built one, bound it to a local and passed the local would read as handed down
#: in the census above, so it must show up here instead.
_POSTURES_BUILT = sorted(
    [
        # The one derivation from an instance's settings.
        ("config/settings.py", "hop_posture_from_ai"),
        # An enforcing default for a connector built with no posture stamped. It cannot relax.
        ("transports/rest.py", "_current_hop_posture_fail_closed"),
        # The synthetic load rigs, which declare a warn posture for their own rig stores. Only
        # the `open_store` one reaches a link of this chain; `_NOT_HANDED_DOWN` argues it.
        ("harness/load/connscale/runner.py", "_reset_server_store"),
        ("harness/load/connscale/runner.py", "_reset_server_store"),
        ("harness/load/connscale/runner.py", "_store_reader._read"),
        ("harness/load/shardcert.py", "_queue_breakdown"),
        ("harness/load/shardcert.py", "_reset_store"),
    ]
)


def test_every_place_a_posture_is_built_is_listed() -> None:
    """The engine derives its posture in one function, from the loaded settings, and one more
    builds an enforcing default. Neither can relax a hop the instance did not relax. A new place
    that builds one turns this red.

    Mutation: add ``posture = HopPosture(enforcing=False)`` to any function in ``messagefoundry/``."""
    found = sorted((relative, where) for relative, where, _, _ in _rows(_BUILDERS))
    assert found == _POSTURES_BUILT
    planted = "def _a_new_command():\n    posture = HopPosture(enforcing=False)\n"
    assert [(r, w) for r, w, _, _ in _scan(planted, "planted.py", _BUILDERS)] == [
        ("planted.py", "_a_new_command")
    ]
    # The control that the planted caller is what the census alone would miss.
    passed = "def _a_new_command():\n    open_store(settings, posture=posture)\n"
    assert _scan(passed, "planted.py")[0][3] in _HANDED_DOWN


#: The dial ``serve`` reads: its ``[security]`` section, or that section's shipped default.
_SERVE_DIAL = "(security_settings or SecuritySettings()).enforcement"
#: Every call that derives a posture from settings, with the ``enforcement`` it is given. Each
#: reads the dial off the instance's own ``[security]`` settings, never a constant.
_DERIVATIONS = sorted(
    [
        ("__main__.py", "_check_privileges", "settings.security.enforcement"),
        ("__main__.py", "_connection.validate", "settings.security.enforcement"),
        ("__main__.py", "_provision_admin", "settings.security.enforcement"),
        ("__main__.py", "_renew_api_tls_before_spawning", "settings.security.enforcement"),
        ("__main__.py", "_start_logging", "settings.security.enforcement"),
        ("__main__.py", "_store_provision_schema", "settings.security.enforcement"),
        ("api/app.py", "create_app", _SERVE_DIAL),
        ("api/app.py", "create_app", "_phi_read_enforcement"),
        ("api/app.py", "create_managed_app.lifespan", _SERVE_DIAL),
        ("api/app.py", "create_managed_app.lifespan", _SERVE_DIAL),
        ("checks.py", "_check_build", "settings.security.enforcement"),
        ("verify/federation.py", "_revocation_row", "settings.security.enforcement"),
    ]
)
#: How a derivation may spell the dial: the loaded settings' own field, or a local read from it.
_OWN_DIAL = (
    "settings.security.enforcement",
    _SERVE_DIAL,
    # `create_app` reads the serve dial into this local one line above the call.
    "_phi_read_enforcement",
)


def _dial_of(call: ast.Call, _position: int | None) -> str:
    return next((ast.unparse(k.value) for k in call.keywords if k.arg == "enforcement"), _NONE)


def _derivations(source: str, relative: str) -> list[tuple[str, str, str]]:
    scan = _Scan(relative, {"hop_posture_from_ai": None}, shape=_dial_of)
    scan.visit(parse_source(source))
    return [(module, where, dial) for module, where, _, dial in scan.rows]


def test_every_posture_derivation_reads_the_instances_own_dial() -> None:
    """A caller could relax the guard without building a ``HopPosture`` itself, by deriving one
    from a constant: ``hop_posture_from_ai(ai, enforcement=SecurityEnforcement.WARN)``. Every
    derivation is listed with its dial, and every dial is the loaded settings' own.

    Mutation: pass ``enforcement=SecurityEnforcement.WARN`` at any call of the derivation."""
    found: list[tuple[str, str, str]] = []
    for relative, source in _sources():
        if "hop_posture_from_ai" in source:
            found.extend(_derivations(source, relative))
    assert sorted(found) == _DERIVATIONS
    assert [row for row in _DERIVATIONS if row[2] not in _OWN_DIAL] == []
    planted = (
        "def _a_new_command():\n"
        "    posture = hop_posture_from_ai(settings.ai, enforcement=SecurityEnforcement.WARN)\n"
    )
    assert _derivations(planted, "planted.py") == [
        ("planted.py", "_a_new_command", "SecurityEnforcement.WARN")
    ]


_PLANTED = """
async def _a_new_command(args):
    store = await open_store(settings.store)
    provider = resolve_secret_provider(settings.secrets, posture=HopPosture(enforcing=False))

class NewProvider:
    def active_key(self):
        return _build_client(a, t, revocation_attested=self._settings.vault_revocation_attested)

cipher = build_store_cipher(settings)
"""


def test_the_census_fires_on_a_planted_caller() -> None:
    """The control. Four planted calls: a new command that opens a store, a caller that builds
    its own non-enforcing posture, a new client build inside a method, and a call outside any
    function. Each is a row the census does not hold, and the built posture is named as one."""
    planted = _scan(_PLANTED, "planted.py")
    assert planted == [
        ("planted.py", "_a_new_command", "open_store", _NONE),
        (
            "planted.py",
            "_a_new_command",
            "resolve_secret_provider",
            "HopPosture(enforcing=False)",
        ),
        ("planted.py", "NewProvider.active_key", "_build_client", _NONE),
        ("planted.py", "<module>", "build_store_cipher", _NONE),
    ]
    unlisted, stale = _difference(sorted([*_found(), *planted]))
    assert sorted(unlisted) == sorted(planted)
    assert stale == []
    assert [row for row in planted if row[3] not in _HANDED_DOWN] == [planted[1]]
    assert planted[1] not in _NOT_HANDED_DOWN


def test_a_second_identical_call_is_a_difference() -> None:
    """Two calls in one function with one shape are two rows. A set would hide the second."""
    assert _CENSUS, "the census is empty"
    unlisted, stale = _difference(sorted([*_found(), _CENSUS[0]]))
    assert unlisted == [_CENSUS[0]]
    assert stale == []


@pytest.mark.parametrize(
    ("call", "position", "shape"),
    [
        ("open_store(settings)", None, _NONE),
        ("open_store(settings, posture=posture)", None, "posture"),
        ("Engine(store, hop_posture=_hop_posture)", None, "_hop_posture"),
        ("_load_external_provider(name, settings, posture)", 2, "posture"),
        ("_load_external_provider(name, settings)", 2, _NONE),
        ("_build_store_cipher(settings, None)", 1, "None"),
    ],
)
def test_the_scan_reads_a_keyword_or_the_links_own_position(
    call: str, position: int | None, shape: str
) -> None:
    (node,) = [n for n in ast.walk(parse_source(call)) if isinstance(n, ast.Call)]
    assert _posture_of(node, position) == shape
