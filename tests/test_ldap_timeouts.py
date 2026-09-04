# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 13.1.3 regression: every ``ldap3`` object the AD authenticator builds carries a FINITE
network timeout.

Before this landed, ``messagefoundry/auth/ldap.py`` constructed one ``ldap3.Server`` and two
``ldap3.Connection``s with **no** ``connect_timeout`` / ``receive_timeout``. ldap3's own defaults are
``None`` on both, the engine never calls ``socket.setdefaulttimeout``, and
:class:`~messagefoundry.auth.service.AuthService` dispatches every LDAP call through a bare
``asyncio.to_thread`` with no ``asyncio.wait_for`` — so an unresponsive domain controller pinned a
thread-pool worker **indefinitely** rather than failing the login, and the documented per-hop timeout
table could not honestly carry an AD row.

Two complementary guards, because either alone has a hole:

* **Runtime** — recording fakes replace ``ldap3.Server`` / ``ldap3.Connection``; both public entry
  points are driven and EVERY captured construction must carry a finite, non-``None`` timeout sourced
  from the new settings. The construction **counts** are asserted too, so a refactor that adds a
  fourth construction on the login path fails instead of slipping through untested.
* **Static** — the AST of **every module in the ``messagefoundry`` package** is walked for both call
  forms, ``ldap3.Server(...)`` / ``ldap3.Connection(...)`` **and** a bare ``Server(...)`` /
  ``Connection(...)`` resolved through that module's own ``from ldap3 import …``. So a NEW
  construction site that no test happens to exercise still fails the build — including one in a
  module other than ``auth/ldap.py`` (a reconciler path, a future SPNEGO/LDAP helper, a new
  federation module), which a single-file walk would have missed entirely while advertising full
  coverage. The static half also rejects an explicitly unbounded literal (``receive_timeout=None``
  or ``=0``), which a keyword-presence check alone would accept; a non-literal value (a settings
  attribute) is covered by the runtime half's finiteness assertions.

  *Disclosed limit:* an aliased module import (``import ldap3 as l3``) or a factory that returns a
  ``Connection`` from elsewhere is not resolved. Those forms do not exist at HEAD and the runtime
  fakes still cover both public entry points.

PHI-free: synthetic directory names only, no real principal or network address.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.ldap import AdPrincipal, LdapAuthenticator
from messagefoundry.config.settings import AuthSettings

_CONNECT_TIMEOUT = 7.5  # deliberately not the default, so a hardcoded literal cannot pass
_RECEIVE_TIMEOUT = 9.25


def _ad_settings(**over: Any) -> AuthSettings:
    base: dict[str, Any] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.example.com",
        "ad_domain": "example.com",
        "ad_user_search_base": "OU=Users,DC=example,DC=com",
        "ad_group_search_base": "OU=Groups,DC=example,DC=com",
        "ad_bind_dn": "CN=svc,DC=example,DC=com",
        "ad_bind_password": "synthetic-bind-pw",
        "ad_connect_timeout": _CONNECT_TIMEOUT,
        "ad_receive_timeout": _RECEIVE_TIMEOUT,
    }
    base.update(over)
    return AuthSettings(**base)


# --- recording ldap3 doubles --------------------------------------------------------------------


class _FakeAttr:
    def __init__(self, value: str) -> None:
        self.value = value
        self.values = [value]


class _FakeEntry:
    """The minimal ``ldap3`` entry surface ``_find_user`` / ``_resolve_groups`` touch."""

    def __init__(self, dn: str, attrs: dict[str, str]) -> None:
        self.entry_dn = dn
        self._attrs = attrs

    def __contains__(self, name: str) -> bool:
        return name in self._attrs

    def __getitem__(self, name: str) -> _FakeAttr:
        return _FakeAttr(self._attrs[name])


class _Recorder:
    def __init__(self) -> None:
        self.servers: list[dict[str, Any]] = []
        self.connections: list[dict[str, Any]] = []
        # One entry per bind/unbind ROUND TRIP (see the #1140 section below for why constructions
        # are not enough), each holding the DN it was issued as — which is what makes the "never
        # aim the decoy at a real principal" assertion expressible at all.
        self.binds: list[str | None] = []
        self.unbinds: list[str | None] = []


def _install_fakes(monkeypatch: pytest.MonkeyPatch, *, bind_ok: bool = True) -> _Recorder:
    """Install recording ``ldap3`` doubles. ``bind_ok=False`` makes every EXPLICIT bind fail, which
    is how the valid-user-wrong-password branch is driven (the service-account connection is built
    with ``auto_bind=True``, which these doubles do not honour, so it is never an explicit bind)."""
    import ldap3

    rec = _Recorder()

    class FakeServer:
        def __init__(self, host: Any = None, **kwargs: Any) -> None:
            rec.servers.append({"host": host, **kwargs})

    class FakeConnection:
        def __init__(self, server: Any = None, **kwargs: Any) -> None:
            rec.connections.append({"server": server, **kwargs})
            self.entries: list[_FakeEntry] = []
            self._bind_dn: str | None = kwargs.get("user")

        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def search(self, **kwargs: Any) -> bool:
            base = str(kwargs.get("search_base", ""))
            if base.startswith("OU=Groups"):
                self.entries = [
                    _FakeEntry(
                        "CN=Operators,OU=Groups,DC=example,DC=com",
                        {"sAMAccountName": "Operators"},
                    )
                ]
            else:
                self.entries = [
                    _FakeEntry(
                        "CN=alice,OU=Users,DC=example,DC=com",
                        {
                            "sAMAccountName": "alice",
                            "displayName": "Alice Example",
                            "mail": "alice@example.com",
                            "memberOf": "CN=Nurses,OU=Groups,DC=example,DC=com",
                            "userAccountControl": "512",
                        },
                    )
                ]
            return True

        def bind(self) -> bool:
            rec.binds.append(self._bind_dn)
            return bind_ok

        def unbind(self) -> None:
            rec.unbinds.append(self._bind_dn)

    monkeypatch.setattr(ldap3, "Server", FakeServer)
    monkeypatch.setattr(ldap3, "Connection", FakeConnection)
    return rec


def _assert_all_finite(rec: _Recorder) -> None:
    for i, kwargs in enumerate(rec.servers):
        value = kwargs.get("connect_timeout")
        assert value is not None, f"ldap3.Server #{i} built with NO connect_timeout (waits forever)"
        assert isinstance(value, int | float) and 0 < float(value) < float("inf"), (
            f"ldap3.Server #{i} connect_timeout is not a finite positive number: {value!r}"
        )
        assert float(value) == _CONNECT_TIMEOUT, (
            f"ldap3.Server #{i} connect_timeout {value!r} is not [auth].ad_connect_timeout — it is "
            "hardcoded or read from the wrong setting"
        )
    for i, kwargs in enumerate(rec.connections):
        value = kwargs.get("receive_timeout")
        assert value is not None, (
            f"ldap3.Connection #{i} built with NO receive_timeout (every response read waits forever)"
        )
        assert isinstance(value, int | float) and 0 < float(value) < float("inf"), (
            f"ldap3.Connection #{i} receive_timeout is not a finite positive number: {value!r}"
        )
        assert float(value) == _RECEIVE_TIMEOUT, (
            f"ldap3.Connection #{i} receive_timeout {value!r} is not [auth].ad_receive_timeout"
        )


# --- runtime guard ------------------------------------------------------------------------------


def test_authenticate_builds_only_finitely_timed_ldap_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rec = _install_fakes(monkeypatch)
    principal = LdapAuthenticator(_ad_settings()).authenticate("alice", "synthetic-user-pw")

    assert principal is not None and principal.username == "alice"
    # The login path is: service-account bind (Server+Connection) then the password-verifying user
    # bind (a SECOND Server+Connection). Pin the counts so a future refactor that adds an untimed
    # third construction reds here rather than shipping an unbounded wait.
    assert len(rec.servers) == 2, f"expected 2 ldap3.Server constructions, got {len(rec.servers)}"
    assert len(rec.connections) == 2, (
        f"expected 2 ldap3.Connection constructions, got {len(rec.connections)}"
    )
    _assert_all_finite(rec)


def test_resolve_principal_builds_only_finitely_timed_ldap_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rec = _install_fakes(monkeypatch)
    principal = LdapAuthenticator(_ad_settings()).resolve_principal("alice")

    assert principal is not None and principal.dn.startswith("CN=alice")
    # The Kerberos / session-reconciler path: the service-account bind only.
    assert len(rec.servers) == 1
    assert len(rec.connections) == 1
    _assert_all_finite(rec)


# --- BACKLOG #1140 (ASVS 6.3.8): the AD leg must not leak account existence by response TIME ------


def _shape_search(monkeypatch: pytest.MonkeyPatch, *, uac: str | None) -> None:
    """Make every user search return no match (``uac=None``) or one with that userAccountControl."""
    import ldap3

    patched = ldap3.Connection  # the FakeConnection installed by _install_fakes

    class Shaped(patched):  # type: ignore[misc, valid-type]
        def search(self, **kwargs: Any) -> bool:
            super().search(**kwargs)
            if str(kwargs.get("search_base", "")).startswith("OU=Groups"):
                return True
            self.entries = (
                []
                if uac is None
                else [
                    _FakeEntry(
                        "CN=ghost,OU=Users,DC=example,DC=com",
                        {"sAMAccountName": "ghost", "userAccountControl": uac},
                    )
                ]
            )
            return True

    monkeypatch.setattr(ldap3, "Connection", Shaped)


def test_equalizing_the_bind_did_not_move_the_disabled_check_off_the_kerberos_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE HAZARD GUARD for #1140, and the reason the fix equalizes the CALLER instead of relocating
    the check. ``_find_user`` rejects ACCOUNTDISABLE and has two callers: ``authenticate`` binds, and
    ``resolve_principal`` (Kerberos/SSO) does not. Moving that check into the bind path would have
    equalized the timing and let a DISABLED ACCOUNT AUTHENTICATE OVER SSO -- a bypass, traded for a
    timing leak. This asserts the SSO leg still refuses.
    """
    _install_fakes(monkeypatch)
    _shape_search(monkeypatch, uac="514")  # present, ACCOUNTDISABLE set

    assert LdapAuthenticator(_ad_settings()).resolve_principal("ghost") is None


# --- #1140, the round trip itself: counting CONSTRUCTIONS cannot see a decoy that never binds ----
#
# The tests above pin how many ldap3 objects the ACCEPTED path builds. Pinning the same numbers for
# the rejection branches was the original #1140 guard, and it was blind to the failure that item
# names as its own trap: "a decoy that constructs a connection object and never binds -- the round
# trip is the cost". Measured on the shipped code by deleting `conn.bind()` from `_equalizing_bind`:
# every test in this file stayed GREEN, because a built-and-unbound connection still counts as one
# construction. The parity claim was resting on a guard that could not see it being withdrawn.
#
# What follows replaces that guard, and asserts the round trips rather than the allocations.


def _drive(
    *, uac: str | None, bind_ok: bool, username: str = "ghost"
) -> tuple[_Recorder, AdPrincipal | None]:
    """Run one login branch against fresh doubles; return what the directory was asked to do, and
    the outcome. Each branch gets its own ``MonkeyPatch`` context so one test can drive several and
    compare them to EACH OTHER rather than to a number repeated once per branch."""
    with pytest.MonkeyPatch.context() as mp:
        rec = _install_fakes(mp, bind_ok=bind_ok)
        _shape_search(mp, uac=uac)
        principal = LdapAuthenticator(_ad_settings()).authenticate(username, "synthetic-user-pw")
    return rec, principal


def test_no_login_can_be_told_from_another_by_the_directory_work_it_costs() -> None:
    """ASVS 6.3.8 on the AD leg: every outcome must cost the same connects, binds and releases.

    Three failures share one response, so any of these counts differing between them is a username
    oracle that the sign-in limiter rate-bounds and never removes. The accepted branch is driven as
    the CONTROL and must match: successes are deliberately not padded (a valid credential already
    tells the attacker the account exists), but a success must not be CHEAPER than a failure either,
    which would leak in the other direction. Matching the control is also what makes these numbers
    an equality claim rather than four pinned constants.

    ``binds`` is the assertion construction counts could not make -- a connection built and never
    bound costs no network round trip. ``unbinds`` is its resource-release twin: a rejection path
    that skipped the release would leak a connection per attempt, under exactly the flood of
    nonexistent usernames this control exists to blunt (ASVS 13.1.3).
    """
    branches: list[tuple[str, str | None, bool]] = [
        ("no such principal", None, True),
        ("present but ACCOUNTDISABLE (512|0x2)", "514", True),
        ("present and enabled, wrong password", "512", False),
        ("present and enabled, correct password (the CONTROL)", "512", True),
    ]
    measured: dict[str, tuple[int, int, int, int]] = {}
    for why, uac, bind_ok in branches:
        rec, principal = _drive(uac=uac, bind_ok=bind_ok)
        assert (principal is not None) is (uac == "512" and bind_ok), (
            f"{why}: the branch did not reach the outcome it names, so the counts below measure "
            "some other code path"
        )
        _assert_all_finite(rec)  # the equalizing connection is not exempt from the timeout rule
        measured[why] = (len(rec.servers), len(rec.connections), len(rec.binds), len(rec.unbinds))

    assert len(set(measured.values())) == 1, (
        "the login branches do not cost the same directory work, so a failed challenge tells an "
        "attacker which usernames exist -- (servers, connections, binds, unbinds) per branch: "
        f"{measured}"
    )
    # The equality above is satisfied by four identical ZEROES, which would mean the doubles were
    # never driven. Only the bind/release pair is pinned here: the construction counts are already
    # owned by test_authenticate_builds_only_finitely_timed_ldap_objects, and a second copy of that
    # number is a second place to update.
    _, _, binds, unbinds = next(iter(measured.values()))
    assert (binds, unbinds) == (1, 1), (
        f"expected every branch to issue exactly one bind and release it once; got {measured}"
    )


def test_the_equalizing_bind_is_never_aimed_at_a_principal_the_caller_named() -> None:
    """THE INVERSION GUARD. The decoy must bind as a fixed DN of the engine's own choosing.

    #1140's live trap: a decoy aimed at a REAL principal sends failed binds at that account, so
    under the site's own lockout policy the account locks. After that the decoy branch answers
    instantly, the oracle INVERTS, and nothing in the engine can detect it -- the control has become
    the attack. Deriving the decoy DN from the attempted username is the natural-looking change that
    would do it ("bind as what they typed"), and it would hand an attacker the aim.

    There is no lab to measure a controller's real lockout behaviour against (owner ruling
    2026-08-20), which is exactly why this is asserted structurally instead: the engine must never
    let attacker-supplied input choose who gets the failed binds.
    """
    a, _ = _drive(uac=None, bind_ok=True, username="victim-a")
    b, _ = _drive(uac=None, bind_ok=True, username="victim-b")

    assert a.binds == b.binds, (
        f"the decoy bind DN moved with the attempted username ({a.binds} vs {b.binds}) -- an "
        "attacker can aim the engine's failed binds at any account and lock it out"
    )
    (dn,) = a.binds
    assert dn is not None
    assert "victim-a" not in dn and "victim-b" not in dn, (
        f"the decoy bind DN {dn!r} carries caller-supplied text"
    )

    # The other way to aim it at a real principal: reuse the DN the directory just returned. On the
    # disabled branch the search DOES yield one, so this branch is where that mistake is reachable.
    disabled, _ = _drive(uac="514", bind_ok=True)
    (disabled_dn,) = disabled.binds
    assert disabled_dn == dn, (
        f"the disabled branch bound as {disabled_dn!r} rather than the fixed decoy {dn!r} -- it is "
        "sending failed binds at the real, findable account it just refused"
    )


# --- static guard: no construction site can escape the runtime tests -----------------------------

_REQUIRED_KWARG = {"Server": "connect_timeout", "Connection": "receive_timeout"}


def _ldap3_construction_sites() -> list[tuple[str, str, int, dict[str, ast.expr]]]:
    """``(ldap3 attribute, module, line number, {keyword: value node})`` for every ldap3 ``Server`` /
    ``Connection`` construction anywhere in the ``messagefoundry`` package.

    Walks the whole package, not just ``auth/ldap.py``: today ldap3 appears in no other module, so a
    single-file walk is correct at HEAD but not DURABLE — a construction site added elsewhere would
    ship with ldap3's ``None`` default (wait forever) and be invisible to both the runtime fakes and
    this guard.

    **Both call forms are covered**, which the attribute-only walk this replaces was not: a future
    ``from ldap3 import Connection`` followed by a bare ``Connection(server, user=…)`` was invisible
    to it while the docstring advertised full coverage. Each module's ``ImportFrom`` statements are
    scanned first, so a bare ``Server``/``Connection`` name counts only where it really is ldap3's.
    """
    import messagefoundry

    root = Path(messagefoundry.__file__).parent
    sites: list[tuple[str, str, int, dict[str, ast.expr]]] = []
    for module in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(module.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a broken module fails elsewhere, loudly
            continue
        rel = module.relative_to(root.parent).as_posix()
        # Pass 1: which bare names in THIS module are ldap3's Server/Connection?
        bare: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "ldap3":
                for alias in node.names:
                    if alias.name in _REQUIRED_KWARG:
                        bare[alias.asname or alias.name] = alias.name
        # Pass 2: the constructions themselves, in either form.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            attr: str | None = None
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "ldap3"
                and func.attr in _REQUIRED_KWARG
            ):
                attr = func.attr
            elif isinstance(func, ast.Name) and func.id in bare:
                attr = bare[func.id]
            if attr is None:
                continue
            keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            sites.append((attr, rel, node.lineno, keywords))
    return sites


def test_every_ldap3_construction_site_passes_a_timeout() -> None:
    sites = _ldap3_construction_sites()
    # Sanity: the package walk must still find the three known auth/ldap.py sites, or it has gone
    # vacuously green (a moved file, a renamed package, a broken walker).
    kinds = [attr for attr, _module, _line, _kw in sites]
    assert kinds.count("Server") >= 1 and kinds.count("Connection") >= 2, (
        f"AST walk found an unexpected ldap3 construction set: {sites}"
    )
    assert any(module.endswith("auth/ldap.py") for _a, module, _l, _k in sites), (
        f"the package walk no longer reaches auth/ldap.py; it is not covering anything: {sites}"
    )
    untimed = [
        f"{attr} at {module}:{line}"
        for attr, module, line, kwargs in sites
        if _REQUIRED_KWARG[attr] not in kwargs
    ]
    assert not untimed, (
        "ldap3 construction site(s) with no finite timeout keyword — an unresponsive domain "
        f"controller would block the login thread forever (ASVS 13.1.3): {untimed}"
    )
    # Keyword PRESENCE is not enough: `receive_timeout=None` (or `=0`) satisfies a presence check and
    # restores the unbounded wait. Reject a literal None/0 statically; a non-literal (a settings
    # attribute) is covered by the finiteness assertions in the runtime fakes above.
    unbounded = [
        f"{attr} at {module}:{line} passes {_REQUIRED_KWARG[attr]}={ast.unparse(kwargs[_REQUIRED_KWARG[attr]])}"
        for attr, module, line, kwargs in sites
        if isinstance(value := kwargs.get(_REQUIRED_KWARG[attr]), ast.Constant)
        and (value.value is None or value.value == 0)
    ]
    assert not unbounded, (
        "ldap3 construction site(s) passing an explicitly UNBOUNDED timeout — the keyword is present "
        f"but means 'wait forever' (ASVS 13.1.3): {unbounded}"
    )


def test_static_walker_sees_the_bare_import_call_form() -> None:
    """Proves the coverage the docstring claims, on the form the previous walker could not see.

    ``from ldap3 import Connection`` + ``Connection(server, user=…)`` is the shape that would have
    shipped with ldap3's ``None`` default while the whole suite stayed green.
    """
    source = (
        "from ldap3 import Connection, Server\n"
        "s = Server('ldaps://dc.example.test')\n"
        "c = Connection(s, user='u', password='p')\n"
    )
    tree = ast.parse(source)
    bare: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "ldap3":
            for alias in node.names:
                if alias.name in _REQUIRED_KWARG:
                    bare[alias.asname or alias.name] = alias.name
    assert bare == {"Connection": "Connection", "Server": "Server"}, (
        "the ImportFrom resolution no longer recognises `from ldap3 import ...`; the walker is back "
        "to attribute-call-only coverage while claiming otherwise"
    )
    found = [
        bare[node.func.id]
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in bare
    ]
    assert sorted(found) == ["Connection", "Server"], (
        f"the bare-name call form is not detected: {found}"
    )


# --- settings guard -----------------------------------------------------------------------------


def test_ad_timeout_defaults_are_finite_and_positive() -> None:
    s = AuthSettings()
    assert 0 < s.ad_connect_timeout < float("inf")
    assert 0 < s.ad_receive_timeout < float("inf")


def test_ad_timeouts_are_documented_in_the_operator_configuration_reference() -> None:
    """A MEFOR-owned timeout knob that appears only in a CONNECTIONS.md table cell is undocumented
    for the operator who has to tune it — the artefact ASVS 13.1.3 scores."""
    root = Path(__file__).resolve().parent.parent
    config = (root / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    settings = AuthSettings()
    for field in ("ad_connect_timeout", "ad_receive_timeout"):
        row = [line for line in config.splitlines() if line.strip().startswith(f"| `{field}`")]
        assert row, (
            f"[auth].{field} has no row in docs/CONFIGURATION.md's `[auth]` table; it ships as an "
            "operator knob and must be in the canonical settings reference (ASVS 13.1.3)."
        )
        live = getattr(settings, field)
        assert f"{live:g}" in row[0] or f"{live}" in row[0], (
            f"docs/CONFIGURATION.md's `{field}` row does not state its live default {live!r}"
        )


@pytest.mark.parametrize("bad", [0, -1.0, float("inf"), float("nan")])
def test_ad_timeout_rejects_an_unbounded_value(bad: float) -> None:
    # 0/negative/inf/NaN are four spellings of the same unbounded wait; all are refused at config
    # load, not discovered at bind time against a wedged DC.
    with pytest.raises(ValueError, match="finite number of seconds"):
        _ad_settings(ad_connect_timeout=bad)
    with pytest.raises(ValueError, match="finite number of seconds"):
        _ad_settings(ad_receive_timeout=bad)


# --- resource release: the failed-bind path is the common adversarial case ----------------------


def test_a_rejected_password_still_unbinds_the_user_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ASVS 13.1.3 scores the release procedure, and the doc states one.

    RULE: ``user_conn.unbind()`` must run on BOTH paths. It used to sit after an early
    ``return None``, so a rejected password — by far the most frequent outcome under a password
    spray — left the LDAP connection to be reclaimed by GC, while the doc said "the user bind is
    explicitly unbound".
    """
    # ``bind_ok=False`` fails the USER bind only: the service-account connection is built with
    # auto_bind=True, which these doubles do not honour, so it never takes the explicit-bind path.
    rec = _install_fakes(monkeypatch, bind_ok=False)

    assert LdapAuthenticator(_ad_settings()).authenticate("alice", "wrong-password") is None, (
        "the fake user bind returned False, so authentication must fail"
    )
    assert len(rec.connections) == 2, (
        f"expected a service bind then a user bind; recorded {len(rec.connections)}"
    )
    assert len(rec.unbinds) == 1, (
        "the user connection was NOT unbound on the rejected-password path — the release procedure "
        "documented in docs/CONNECTIONS.md Table B does not run where it matters most (ASVS 13.1.3)"
    )
