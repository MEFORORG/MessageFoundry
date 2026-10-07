# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/seam_discovery.py`` -- the discovered seam surface (BACKLOG #1220).

Two kinds of test, and both are needed:

* **Calibration against the real tree.** The discovery must reproduce the ONE curated list that had
  not drifted (``_APP_STATE_ATTRS``) exactly, and must be a strict SUPERSET of the others. Nothing
  may be lost. Reproducing the un-drifted list is the evidence that the walk measures the contract
  rather than something adjacent to it -- a walk that merely returned "more" would be consistent
  with measuring the wrong thing.
* **Idiom resolution on synthetic input.** Each import idiom resolves as specified, and each idiom
  the walk CANNOT resolve exactly raises :class:`SeamDiscoveryError` rather than being skipped. The
  loud cases all measure zero occurrences in the console today, so they are only reachable here.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
import types
from pathlib import Path
from typing import Any, ClassVar, Literal, cast

import pytest
from pydantic import BaseModel

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path) -> Any:
    """Load a ``scripts/`` module by path.

    ``sys.modules`` registration is REQUIRED before ``exec_module``: ``@dataclass(slots=True)``
    resolves its own module through ``sys.modules`` while the decorator runs, and an unregistered
    module makes that lookup return ``None``.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sd = _load("_seam_discovery", _REPO_ROOT / "scripts" / "seam_discovery.py")


@pytest.fixture(scope="module")
def surface() -> Any:
    return sd.discover(_REPO_ROOT / "messagefoundry_webconsole", _REPO_ROOT / "messagefoundry")


# The RETIRED hand-maintained tuples, frozen at the commit that deleted them (ebf4882a's generator).
# They are literals here on purpose. The calibration below is the evidence that discovery measures
# the contract, and that evidence has to outlive the lists it was measured against -- reading them
# from the generator would make these tests vacuous the moment the generator stopped carrying them.
# Discovery must never DROP one of these names; if it does, the fix swapped one blind spot for
# another and the superset test is what says so.
_RETIRED_APP_STATE = (
    "auth",
    "exposure_protected",
    "loopback",
    "public_origin",
    "ui_connections_render",
    "ui_csp",
    "ui_ws_authorize",
    "webauthn_rp_from_request",
)

_RETIRED_MODELS = (
    "AlertInstanceInfo", "AlertInstanceList", "AlertsConfig", "AttachmentInfo", "ClusterNodeList",
    "ClusterStatus", "ConfigProvenance", "ConnectionEventInfo", "ConnectionFlagRequest",
    "ConnectionRow", "DeadLetterList", "DeadLetterReplayRequest", "DrStatus", "GraphEdge",
    "GraphNode", "GraphResponse", "IntegrityResult", "MessageDetail", "MessageList",
    "MessageSearchResults", "MetricsHistoryResponse", "MetricsHistorySample",
    "PendingApprovalResponse", "ReloadRequest", "ReloadResult", "SecurityPosture",
    "ServiceStatusInfo", "StatsResetRequest", "StatsResetTarget", "SystemStatus",
)  # fmt: skip

_RETIRED_AUTH_MODELS = (
    "AdGroupMap", "AdGroupMapEntry", "AdGroupScopeEntry", "AdGroupScopeMap", "AuditList",
    "ChannelScope", "CurrentUser", "CustomRoleInfo", "CustomRoleRequest", "MfaStatusResponse",
    "PasswordChangeRequest", "RoleInfo", "RolesUpdateRequest", "SecurityEventsList",
    "UserCreateRequest", "UserSummary", "UserUpdateRequest",
)  # fmt: skip

_RETIRED_AUTH_SERVICE = (
    "allow_login_attempt", "allow_phi_read", "audit_kerberos_reject", "audit_oidc_reject",
    "audit_permission_denied", "authenticate_kerberos", "begin_oidc_login",
    "begin_webauthn_assertion", "begin_webauthn_registration", "complete_oidc_login",
    "confirm_mfa_enrollment", "delete_webauthn_credential", "finish_webauthn_assertion",
    "finish_webauthn_registration", "flag_new_client_ip", "has_recent_step_up",
    "identity_for_token", "list_sessions", "login", "logout", "mfa_satisfied", "mfa_status",
    "reauth", "revoke_other_sessions", "revoke_own_session", "verify_mfa", "webauthn_available",
)  # fmt: skip


# --- calibration against the real tree ---------------------------------------------------------


def test_app_state_discovery_reproduces_the_undrifted_curated_list(surface: Any) -> None:
    """The calibration. ``_APP_STATE_ATTRS`` was measured to have ZERO drift in either direction, so
    an exact match is the strongest available evidence that the two-sided rule (console reads
    intersected with engine writes, plus console writes) measures the real contract."""
    assert surface.app_state_attrs == _RETIRED_APP_STATE


def test_nothing_curated_is_lost(surface: Any) -> None:
    """Discovery must be a SUPERSET of every curated list. A fix that merely swapped one blind spot
    for another would show up here as a dropped name."""
    assert {f"messagefoundry.api.models.{n}" for n in _RETIRED_MODELS} <= set(surface.dtos)
    assert {f"messagefoundry.api.auth_models.{n}" for n in _RETIRED_AUTH_MODELS} <= set(
        surface.dtos
    )
    assert set(_RETIRED_AUTH_SERVICE) <= set(surface.auth_service_methods)


def test_the_measured_coverage_hole_is_closed(surface: Any) -> None:
    """The seven DTOs the console imports directly and the curated tuple omits.

    ``UploadedFileList`` is the one that proves the defect was real rather than theoretical: commit
    40a4d5d9 added a REQUIRED ``scope`` field to it, which the console renders unconditionally, and
    changed no seam file at all."""
    for name in (
        "AlertSuspendRequest",
        "EditResendRequest",
        "SearchPresetCreateRequest",
        "SearchPresetCriteria",
        "UploadResendRequest",
        "UploadedFileList",
        "UploadedMessagesResult",
    ):
        assert f"messagefoundry.api.models.{name}" in surface.dtos
        assert name not in _RETIRED_MODELS  # it was absent from the curated tuple: the hole itself


def test_nested_only_models_are_covered(surface: Any) -> None:
    """Models the console never imports, reached only as a field of one it does.

    These matter because the snapshot records field names ONE LEVEL deep with no recursion, so a
    nested model's field set is otherwise absent from the contract entirely."""
    for name in ("DeadLetterRow", "MessageSummary", "ClusterNode", "UploadedFileInfo"):
        assert f"messagefoundry.api.models.{name}" in surface.dtos


def test_security_symbols_are_what_the_console_actually_imports(surface: Any) -> None:
    """Two-sided correction: the curated tuple was missing two symbols AND carrying five stale ones.

    The stale half is why ``messagefoundry/api/_ui_seam.py`` asserted the console imports six symbols
    directly -- false for five of six.

    THIS TUPLE IS A PIN OVER A DISCOVERED SET, so it moves whenever the console adds or drops a
    ``from messagefoundry.api.security import ...`` name -- the same companion edit a seam bump is.
    ``enforce_phi_read_hop`` joined with the ADR 0092 PHI serve-hop refusal on /ui (BACKLOG #1738).
    Update it to what discovery reports; never widen it to a membership check, because the whole
    value here is that an UNNOTICED import shows up as a failure rather than as nothing.
    ``initial_credential_window_hours`` and the two ``pending_credential_deadline`` helpers joined
    with the initial-credential deadline surfaces (BACKLOG #1141, ASVS 6.4.5). ``mark_route_gate`` and
    ``public_route`` joined with the engine's deny-by-default route check (vault BACKLOG #2604).
    ``alert_directory_administrator_granted`` joined with the directory sign-in grant alert (vault
    BACKLOG #2610)."""
    assert surface.security_symbols == (
        "alert_directory_administrator_granted",
        "client_ip",
        "enforce_phi_read_hop",
        "enforce_phi_read_pacing",
        "get_auth",
        "initial_credential_window_hours",
        "mark_route_gate",
        "pending_credential_deadline",
        "pending_credential_deadline_for",
        "public_route",
    )


def test_auth_service_symbols_are_what_the_console_actually_imports(surface: Any) -> None:
    """Every name the console imports from ``messagefoundry.auth.service`` (BACKLOG #2015).

    Before #2015 discovery read only ``AuthService`` out of that module, so a renamed step-up
    constant or exception moved no seam. A PIN OVER A DISCOVERED SET, for the reason the
    ``api.security`` pin above gives: update it to what discovery reports when the console's
    imports change, and never widen it to a membership check.

    Recorded 2026-09-29. The filing named three ``admin.py`` constants; the tree had five names
    there by then, and ``OidcStepUp`` in ``routes/oidc.py`` was new since the filing too.

    Vault BACKLOG #2625 added the five constants of the injection and bulk lanes the console has a
    route for (resend, edit-resend, upload resend, purge, reload)."""
    assert surface.auth_service_symbols == (
        "AuthService",
        "Elevation",
        "FEDERATED_BINDING_CHANGED",
        "MfaStatus",
        "NotifyEmailAlreadySet",
        "OidcStepUp",
        "STEP_UP_ACTION_ADMIN_FEDERATED_IDENTITY",
        "STEP_UP_ACTION_ADMIN_RESET_MFA",
        "STEP_UP_ACTION_ADMIN_RESET_PASSWORD",
        "STEP_UP_ACTION_ADMIN_USER_UPDATE",
        "STEP_UP_ACTION_CONFIG_RELOAD",
        "STEP_UP_ACTION_CONNECTION_PURGE",
        "STEP_UP_ACTION_MESSAGE_EDIT_RESEND",
        "STEP_UP_ACTION_MESSAGE_RESEND",
        "STEP_UP_ACTION_MFA_CONFIRM",
        "STEP_UP_ACTION_MFA_DISABLE",
        "STEP_UP_ACTION_MFA_ENROLL",
        "STEP_UP_ACTION_SESSION_TERMINATE",
        "STEP_UP_ACTION_UPLOAD_RESEND",
        "STEP_UP_ACTION_WEBAUTHN_DELETE",
        "STEP_UP_ACTION_WEBAUTHN_ENROLL",
    )


def test_auth_service_properties_are_discovered_not_only_methods(surface: Any) -> None:
    """``has_action_step_up`` is CALLED by the console and was absent from the curated list, and six
    of the seven additions are PROPERTIES.

    The curated list held methods only because signature rendering could not handle anything else --
    the instrument's limitation had silently defined what counted as the contract."""
    assert "has_action_step_up" in surface.auth_service_methods
    for prop in ("action_step_up_required", "oidc_enabled", "kerberos_available", "store"):
        assert prop in surface.auth_service_methods


def test_discovery_is_order_stable(surface: Any) -> None:
    """Every section is sorted. A digest built on this must not move because a filesystem walk or an
    AST visit changed order."""
    for section in (
        surface.dtos,
        surface.security_symbols,
        surface.auth_service_symbols,
        surface.auth_service_methods,
        surface.app_state_attrs,
    ):
        assert list(section) == sorted(section)


def test_the_engine_package_does_not_import_the_discovery(surface: Any) -> None:
    """Discovery runs in the generator and the test, never behind the seam constant.

    ``messagefoundry/`` must not import the console (the one-way dependency rule) and must not import
    ``scripts/``. Computing the seam at import time would also make every proof condition pass
    vacuously, because a stored value could never disagree with a derived one.

    Checked by parsing IMPORTS, not by substring. A substring scan reports the regenerate-with
    comment in ``_ui_seam.py`` as a violation -- naming a tool is not importing it, and a guard that
    cannot tell those apart would push the next author to delete the instruction rather than the
    dependency.
    """
    banned = {"seam_discovery", "webconsole_seam_snapshot"}
    hits: list[str] = []
    for path in (_REPO_ROOT / "messagefoundry").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            if any(part in banned for name in names for part in name.split(".")):
                hits.append(f"{path.relative_to(_REPO_ROOT).as_posix()}:{node.lineno}")
    assert hits == []


# --- idiom resolution on synthetic input -------------------------------------------------------


class _Nested(BaseModel):
    inner: str


class _Root(BaseModel):
    name: str
    one: _Nested | None = None
    many: list[_Nested] = []
    mode: Literal["a", "b"] = "a"


def _fake_module() -> types.ModuleType:
    module = types.ModuleType("fake.models")
    module._Root = _Root  # type: ignore[attr-defined]
    module._Nested = _Nested  # type: ignore[attr-defined]
    module.NOT_A_MODEL = 42  # type: ignore[attr-defined]
    return module


def _seeds(source: str, module_name: str = "fake.models") -> set[str]:
    tree = ast.parse(source)
    return sd._seeds_from_tree(Path("synthetic.py"), tree, module_name, _fake_module())


def test_plain_from_import_seeds() -> None:
    assert _seeds("from fake.models import _Root") == {"_Root"}


def test_aliased_from_import_seeds_the_original_name() -> None:
    """The alias is a local label; the engine ships the original name."""
    assert _seeds("from fake.models import _Root as Renamed") == {"_Root"}


def test_module_qualified_attribute_access_seeds() -> None:
    src = "import fake.models as m\nx = m._Root\n"
    assert _seeds(src) == {"_Root"}


def test_module_qualified_access_ignores_non_models() -> None:
    src = "import fake.models as m\nx = m.NOT_A_MODEL\n"
    assert _seeds(src) == set()


def test_type_checking_imports_are_included() -> None:
    """A DTO named only in an annotation is still a DTO the console renders against, and ``ast.walk``
    does not care about runtime reachability."""
    src = "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from fake.models import _Root\n"
    assert _seeds(src) == {"_Root"}


def test_star_import_fails_loud() -> None:
    with pytest.raises(sd.SeamDiscoveryError, match="star import"):
        _seeds("from messagefoundry.api.models import *", module_name="messagefoundry.api.models")


def test_module_alias_escaping_attribute_position_fails_loud() -> None:
    """If the alias escapes, names could be reached indirectly and the walk can no longer claim to
    have enumerated them."""
    src = "import fake.models as m\nrender(m)\n"
    with pytest.raises(sd.SeamDiscoveryError, match="outside attribute access"):
        _seeds(src)


def test_dynamic_getattr_on_a_dto_module_fails_loud() -> None:
    src = "import fake.models as m\nx = getattr(m, name)\n"
    with pytest.raises(sd.SeamDiscoveryError, match="dynamic getattr"):
        _seeds(src)


def test_static_getattr_on_a_dto_module_resolves() -> None:
    src = "import fake.models as m\nx = getattr(m, '_Root')\n"
    assert _seeds(src) == {"_Root"}


def test_closure_reaches_nested_models() -> None:
    """Through ``| None`` and ``list[...]`` alike."""
    found = sd._closure({"_Root"}, _fake_module(), "synthetic")
    assert {c.__name__ for c in found} == {"_Root", "_Nested"}


def test_closure_skips_non_dto_imports() -> None:
    """Enums and constants ride in on the same import statement; they carry no field set."""
    assert sd._closure({"NOT_A_MODEL"}, _fake_module(), "synthetic") == set()


def test_closure_fails_loud_on_a_name_the_module_does_not_define() -> None:
    with pytest.raises(sd.SeamDiscoveryError, match="not defined there"):
        sd._closure({"NoSuchModel"}, _fake_module(), "synthetic")


def test_literal_values_are_extracted() -> None:
    """A field's allowed VALUES are contract: the console renders ``UploadedFileList.scope`` as a
    dict lookup, so renaming a literal would KeyError at runtime while a field-NAME snapshot stayed
    byte-identical."""
    lits = sd.literals_in_surface(sd._closure({"_Root"}, _fake_module(), "synthetic"))
    assert lits[f"{_Root.__module__}._Root.mode"] == ("a", "b")


def _auth_service_names(source: str) -> set[str]:
    names: set[str] = sd._auth_service_symbols([(Path("synthetic.py"), ast.parse(source))])
    return names


def test_auth_service_from_import_records_the_original_name() -> None:
    """The alias is a local label; the engine ships the original name."""
    src = "from messagefoundry.auth.service import NotifyEmailAlreadySet as Taken, Elevation\n"
    assert _auth_service_names(src) == {"NotifyEmailAlreadySet", "Elevation"}


def test_a_planted_rename_moves_the_discovered_auth_service_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #2015's closing condition, at the discovery level. The digest-level twin is in
    ``tests/test_webconsole_seam_snapshot.py``. Neither asserts an end-to-end ``UiSeamMismatch``:
    the console's route modules import these names eagerly, so a skewed pair fails at import
    before the handshake runs (BACKLOG #1907).

    The rename is planted on both sides, as the one commit making it would. A console that did NOT
    follow it fails loud instead, which is the last assertion."""
    from messagefoundry.auth import service

    before = _auth_service_names("from messagefoundry.auth.service import NotifyEmailAlreadySet\n")
    monkeypatch.setattr(service, "NotifyEmailTaken", service.NotifyEmailAlreadySet, raising=False)
    monkeypatch.delattr(service, "NotifyEmailAlreadySet")
    after = _auth_service_names("from messagefoundry.auth.service import NotifyEmailTaken\n")
    assert before == {"NotifyEmailAlreadySet"}
    assert after == {"NotifyEmailTaken"}
    with pytest.raises(sd.SeamDiscoveryError, match="does not define it"):
        _auth_service_names("from messagefoundry.auth.service import NotifyEmailAlreadySet\n")


def test_auth_service_star_import_fails_loud() -> None:
    with pytest.raises(sd.SeamDiscoveryError, match="star import from auth.service"):
        _auth_service_names("from messagefoundry.auth.service import *\n")


@pytest.mark.parametrize(
    "src",
    [
        "import messagefoundry.auth.service\n",
        "import messagefoundry.auth.service as svc\n",
        "from messagefoundry.auth import service\n",
        "from messagefoundry.auth import Identity, service as svc\n",
    ],
)
def test_binding_the_auth_service_module_fails_loud(src: str) -> None:
    """Names read through a module binding appear in no import statement, so the walk could not
    claim to have found them all."""
    with pytest.raises(sd.SeamDiscoveryError, match="module import of auth.service"):
        _auth_service_names(src)


@pytest.mark.parametrize(
    "src",
    [
        "from messagefoundry import auth\nx = auth.service.Elevation\n",
        "from messagefoundry import auth as a\nx = a.service\n",
        "import messagefoundry.auth\nx = messagefoundry.auth.service.Elevation\n",
        "import messagefoundry.auth as a\nx = a.service.Elevation\n",
        "import messagefoundry\nx = messagefoundry.auth.service.Elevation\n",
    ],
)
def test_reaching_auth_service_through_a_package_binding_fails_loud(src: str) -> None:
    with pytest.raises(sd.SeamDiscoveryError, match="through a package binding"):
        _auth_service_names(src)


def test_an_unrelated_service_attribute_is_not_refused() -> None:
    """The control for the package-binding refusal: ``.service`` on anything else is not it."""
    src = "from messagefoundry import auth\nimport messagefoundry\nx = app.service\ny = auth.identity\n"
    assert _auth_service_names(src) == set()


def test_a_name_auth_service_does_not_define_fails_loud() -> None:
    """Otherwise the generator dies later with a bare AttributeError that names no console file."""
    with pytest.raises(sd.SeamDiscoveryError, match="synthetic.py.*does not define it"):
        _auth_service_names("from messagefoundry.auth.service import NoSuchName\n")


def test_a_submodule_bound_in_auth_service_fails_loud() -> None:
    """``auth.service`` binds ``oidc`` and other submodules. Importing one records a module, and the
    names read through it are in no import statement."""
    with pytest.raises(sd.SeamDiscoveryError, match="is a module bound in auth.service"):
        _auth_service_names("from messagefoundry.auth.service import oidc\n")


def test_a_star_import_from_any_engine_module_fails_loud() -> None:
    """It could re-export an ``auth.service`` name the walk would never see."""
    with pytest.raises(sd.SeamDiscoveryError, match="star import from an engine module"):
        _auth_service_names("from messagefoundry.api.security import *\n")


def test_the_nested_walk_reads_fields_only_and_sees_callable_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``Callable[[X], R]`` holds ``X`` in a list ``get_args`` does not flatten, and
    ``get_type_hints`` returns ``ClassVar`` annotations, which are not fields."""
    import dataclasses
    from collections.abc import Callable

    # ClassVar is imported at MODULE level on purpose: under string annotations, @dataclass spots a
    # ClassVar only through the defining module's namespace, and would otherwise make it a field.
    fake = types.ModuleType(sd.AUTH_SERVICE_MODULE)

    @dataclasses.dataclass
    class Inner:
        x: int = 0

    @dataclasses.dataclass
    class Unused:
        y: int = 0

    @dataclasses.dataclass
    class Outer:
        callback: Callable[[Inner], None] | None = None
        registry: ClassVar[Unused | None] = None

    for cls in (Inner, Unused, Outer):
        cls.__module__ = sd.AUTH_SERVICE_MODULE
        setattr(fake, cls.__name__, cls)
    # get_type_hints resolves the string annotations in the defining module's namespace.
    fake.Callable = Callable  # type: ignore[attr-defined]
    fake.ClassVar = ClassVar  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, sd.AUTH_SERVICE_MODULE, fake)

    assert sd._with_nested_auth_service_types(fake, {"Outer"}) == {"Outer", "Inner"}


def test_a_class_reached_only_through_a_field_is_recorded() -> None:
    """``OidcStepUp.elevation`` is an ``Elevation``, and the console reads its fields through it.
    Importing ``OidcStepUp`` alone must bring ``Elevation`` into the seam, so its fields do not
    depend on some other route importing it."""
    assert _auth_service_names("from messagefoundry.auth.service import OidcStepUp\n") == {
        "OidcStepUp",
        "Elevation",
    }


def test_a_re_exported_auth_service_class_is_resolved_through_its_source() -> None:
    """``api.security`` imports ``AuthService`` from ``auth.service``, so importing it from there
    still reaches the engine's class and must be recorded."""
    assert _auth_service_names("from messagefoundry.api.security import AuthService\n") == {
        "AuthService"
    }


def test_a_same_named_class_elsewhere_is_not_recorded() -> None:
    """The control for the re-export check. ``api.auth_models.CustomRoleInfo`` is a different class
    from ``auth.service.CustomRoleInfo``. A lookup on ``auth.service`` by the imported name alone
    records it; measured 2026-09-29 on the first draft of this check."""
    from messagefoundry.api import auth_models
    from messagefoundry.auth import service

    # The control's premise, checked at runtime: mypy already knows the two types differ.
    assert cast(object, auth_models.CustomRoleInfo) is not service.CustomRoleInfo
    assert (
        _auth_service_names("from messagefoundry.api.auth_models import CustomRoleInfo\n") == set()
    )


def test_relative_and_unrelated_imports_are_ignored() -> None:
    src = "from ._auth import require_ui\nfrom messagefoundry.auth import Identity\n"
    assert _auth_service_names(src) == set()


def test_an_unresolved_forward_ref_fails_loud() -> None:
    """A ForwardRef pydantic never resolved is a HOLE, not a leaf.

    Found by the #1220 acceptance proof rather than by review: a nested-only DTO reached through a
    string annotation whose target is defined later in the module stayed invisible, so renaming its
    field moved nothing. ``typing.get_args`` returns ``()`` on a ForwardRef, so the closure walked
    past it and reported full coverage -- the silent skip this module exists to prevent, reproduced
    inside the walk that warns about it."""
    unresolved = types.ModuleType("fake.unresolved")

    class _Dangling(BaseModel):
        later: _DefinedLater | None = None  # type: ignore[name-defined]  # noqa: F821 -- deliberately never resolved

    unresolved._Dangling = _Dangling  # type: ignore[attr-defined]

    with pytest.raises(sd.SeamDiscoveryError, match="UNRESOLVED ForwardRef"):
        sd._closure({"_Dangling"}, unresolved, "synthetic")
