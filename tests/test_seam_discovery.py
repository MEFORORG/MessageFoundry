# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from typing import Any, Literal

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
    directly -- false for five of six."""
    assert surface.security_symbols == ("client_ip", "enforce_phi_read_pacing", "get_auth")


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
