# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every ``raise ... from None`` in the engine is classified, because ``from None`` hides nothing
(BACKLOG #1796, the lesson of #1792).

**What ``from None`` does, measured below rather than assumed.** It clears ``__cause__`` and sets
``__suppress_context__``. It leaves ``__context__`` POPULATED. The flag steers the default traceback
printer and removes nothing, so a structured-logging serializer, a crash reporter, a debugger or a
bare ``exc.__context__.object`` still reaches the exception the author meant to hide. #1792 found five
shipped sites that each used it as a redaction tool, each beside a comment naming the exact hazard.
The comment is what defeats review: the code reads as though it already handles the risk.

**The safe shape raises OUTSIDE the handler.** Keep the one content-free fact the refusal needs (an
index, a status code) in a local, let the handler end, then raise. CPython sets ``__context__`` only
for a raise made while an exception is being handled, so both chains stay empty. ruff's B904 cannot
tell these apart: it asks for ``from err`` or ``from None`` on a bare raise in a handler, and a raise
moved out of the handler does not trip it at all.

**Why a source scan and not a traceback scan.** The default printer honours the flag, even with
``compact=False``, so a test that renders the exception and searches the text passes against the
defect. ``test_from_none_leaves_the_context_populated`` pins both halves of that.

**Why every site needs an entry, and not only the dangerous ones.** The discriminator is what the
SUPPRESSED exception carries, including through its own ``__cause__``, and that is semantic: a
``KeyError`` over a registry name carries only the name, while a ``ValueError`` from ``int(value)``
quotes the value. No syntactic rule separates them, so each site carries a one-line reason a reviewer
can check. A new site with no entry fails, and so does an entry whose site is gone, so fixing a site
forces its entry out. A reason starts ``SAFE --`` or ``UNSAFE -- finding, fix pending:``; the second
kind documents a defect without redding ``main``.

**Every ``from None`` counts, not only those written inside a handler.** A helper that raises
``from None`` carries the same hazard once a handler calls it, and moving the raise into a helper is
the obvious way to quiet a handler-only scan. Such a site is keyed ``<no handler>``.

**What this does not cover, on purpose.** An implicit chain (a bare ``raise X(...)`` in a handler) and
an explicit ``from exc`` put the same object on the chain, but neither CLAIMS to withhold it, so
neither reads as handled. Frame locals are also out of scope: the raised exception's own
``__traceback__`` reaches the same frame whether or not the chain is cut, so ``from None`` could never
have hidden them either. The scan covers ``messagefoundry/`` only; ``tee/`` and ``harness/`` are not
the engine package, and the web console had no ``from None`` site on 2026-09-26.

**Key shape.** ``<path>::<enclosing qualname>::<caught type>::<raised callable>``, with a count. No line
numbers, so an unrelated edit to a large module does not move every key.

**Negative control against reverted source.** Run by hand on 2026-09-26 against ``b56c0add0^1``, the
parent of engine PR 1209: this scanner finds all five #1792 sites (``transports/base.py``
``encode_wire_body``, ``transports/soap.py``, ``transports/signing.py`` ``_load_private_key``,
``parsing/fhir/resource.py`` and ``auth/oidc/flow.py`` ``exchange_code``, the last with two), none of
which carries an entry here. The history is not read at test time, because a shallow CI clone does not
have it. ``test_the_five_pre_1209_shapes_are_all_flagged`` carries faithful excerpts instead.
"""

from __future__ import annotations

import ast
import traceback
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_PKG = _ROOT / "messagefoundry"

_SAFE = "SAFE -- "
_UNSAFE = "UNSAFE -- finding, fix pending: "


@dataclass(frozen=True)
class _Allowed:
    key: str
    reason: str
    count: int = 1


_APP = "messagefoundry/api/app.py::create_app"
_HTTP = "::HTTPException"
_NOTHING_WITHHELD = "the detail is str(exc), so nothing is withheld"
_UPLOAD_MISS = (
    "the caught error names a file id or the cipher's own type-only text; below it sits the "
    "Transit exception (may echo ciphertext, never plaintext) or, on malformed Transit output, a "
    "UnicodeDecodeError that cannot hold stored content while both upload writers store ASCII "
    "(base64 body, json.dumps metadata)"
)

#: One entry per (site key, count). Read the module docstring before adding one.
_ALLOWED: tuple[_Allowed, ...] = (
    # ---- SAFE: the suppressed exception carries nothing the raised one does not already say.
    _Allowed(
        "messagefoundry/anon/rules.py::_coerce_kind::ValueError::RuleError",
        _SAFE + "enum miss quoting the rule's own kind name, which the new message also quotes",
    ),
    _Allowed(
        "messagefoundry/api/auth_routes.py::add_auth_routes.login::ValueError" + _HTTP,
        _SAFE + "enum miss over the provider name the client sent; carries no credential",
    ),
    _Allowed(
        "messagefoundry/api/auth_routes.py::add_auth_routes.negotiate::"
        "(binascii.Error, ValueError)" + _HTTP,
        _SAFE + "base64 decode errors name a count or a rule, never the token bytes (measured)",
    ),
    _Allowed(
        "messagefoundry/auth/oidc/claims.py::_require_number::OverflowError::ClaimsError",
        _SAFE + "float() overflow text is fixed ('int too large to convert to float'), no value",
    ),
    _Allowed(
        "messagefoundry/config/code_sets.py::UnmappedPolicy.from_mapping::ValueError::CodeSetError",
        _SAFE + "enum miss quoting the policy kind, which the new message also quotes",
    ),
    _Allowed(
        "messagefoundry/config/code_sets.py::CodeSet.__getitem__::KeyError::KeyError",
        _SAFE + "KeyError carries the lookup key, which the new KeyError also quotes",
    ),
    _Allowed(
        "messagefoundry/config/code_sets.py::load_policy::CodeSetError::CodeSetError",
        _SAFE + "the new message interpolates the caught CodeSetError whole",
    ),
    _Allowed(
        "messagefoundry/config/code_sets.py::code_set::KeyError::CodeSetError",
        _SAFE + "KeyError carries an operator-authored code-set name, also in the new message",
    ),
    _Allowed(
        "messagefoundry/config/reference.py::ReferenceSet.__getitem__::KeyError::KeyError",
        _SAFE + "KeyError carries the lookup key, which the new KeyError also quotes",
    ),
    _Allowed(
        "messagefoundry/config/reference.py::reference::KeyError::ReferenceError",
        _SAFE + "KeyError carries an operator-authored reference-set name, also in the message",
    ),
    _Allowed(
        "messagefoundry/framing.py::codec_for::KeyError::ValueError",
        _SAFE + "KeyError carries the framing preset name, which the new message also quotes",
    ),
    _Allowed(
        "messagefoundry/parsing/compression.py::deflate_decompress::InflateCeilingExceeded"
        "::_over_ceiling",
        _SAFE + "carries only the ceiling integer, which the new error also names",
    ),
    _Allowed(
        "messagefoundry/parsing/compression.py::deflate_decompress::InflateTrailingData"
        "::CompressionError",
        _SAFE + "raised bare, with no arguments and no chain",
    ),
    _Allowed(
        "messagefoundry/parsing/dicom/_inflate.py::bounded_inflate_or_error::"
        "InflateCeilingExceeded::DicomBombError",
        _SAFE + "carries only the ceiling integer, which the new error also names",
    ),
    _Allowed(
        "messagefoundry/pipeline/cluster.py::acquire_leadership_lock::TimeoutError"
        "::StepdownLockTimeout",
        _SAFE + "asyncio.wait_for timeout; its chain is a CancelledError with no content",
    ),
    _Allowed(
        "messagefoundry/pipeline/dryrun.py::select_inbound::KeyError::UnknownInboundError",
        _SAFE + "KeyError carries the inbound name, which the new message also quotes",
    ),
    _Allowed(
        "messagefoundry/pipeline/ingress_guards.py::admit_resubmission::TimeoutError"
        "::IngressGuardError",
        _SAFE + "asyncio.wait_for timeout; its chain is a CancelledError with no content",
    ),
    _Allowed(
        "messagefoundry/pipeline/sandbox.py::SandboxSession._spawn::Empty::SandboxError",
        _SAFE + "queue.Empty carries nothing",
    ),
    _Allowed(
        "messagefoundry/pipeline/sandbox.py::SandboxSession.dispatch::Empty::SandboxError",
        _SAFE + "queue.Empty carries nothing",
    ),
    _Allowed(
        "messagefoundry/store/store.py::parse_audit_anchor::ValueError::AuditAnchorError",
        _SAFE + "int() quotes the anchor's count text, and the new error carries the whole anchor",
    ),
    _Allowed(
        "messagefoundry/transports/base.py::build_source::KeyError::ValueError",
        _SAFE + "registry miss; KeyError carries the connector type, also in the new message",
    ),
    _Allowed(
        "messagefoundry/transports/base.py::build_destination::KeyError::ValueError",
        _SAFE + "registry miss; KeyError carries the connector type, also in the new message",
    ),
    _Allowed(
        "messagefoundry/transports/database.py::DatabaseSource._body::KeyError::ValueError",
        _SAFE + "KeyError carries the body_column name, which the new message also quotes",
    ),
    # api/app.py: HTTP translations of the engine's own errors.
    _Allowed(
        f"{_APP}._dual_role_control::NotDeployedError" + _HTTP,
        _SAFE + _NOTHING_WITHHELD + "; it carries a connection name",
        count=2,
    ),
    _Allowed(
        f"{_APP}._dual_role_control::ShardLaneOwnershipError" + _HTTP,
        _SAFE + _NOTHING_WITHHELD + "; it carries lane and shard names",
    ),
    _Allowed(
        f"{_APP}.resend_message::KeyError" + _HTTP,
        _SAFE + "KeyError carries the outbound name, which the 404 detail also quotes",
    ),
    _Allowed(
        f"{_APP}.resend_message::ResendError" + _HTTP,
        _SAFE + _NOTHING_WITHHELD + "; the store's messages carry ids, never a body",
    ),
    _Allowed(
        f"{_APP}.edit_resend_message::KeyError" + _HTTP,
        _SAFE + "KeyError carries the outbound name, which the 404 detail also quotes",
    ),
    _Allowed(
        f"{_APP}.edit_resend_message::ResendError" + _HTTP,
        _SAFE + _NOTHING_WITHHELD + "; the store's messages carry ids, never a body",
        count=2,
    ),
    _Allowed(
        f"{_APP}.upload_file::<no handler>" + _HTTP,
        _SAFE + "the 415 is raised outside any handler, so this from None does nothing",
    ),
    _Allowed(
        f"{_APP}.upload_file::MultipartTooLargeError" + _HTTP,
        _SAFE + _NOTHING_WITHHELD + "; it carries sizes only",
    ),
    _Allowed(
        f"{_APP}.upload_file::MultipartError" + _HTTP,
        _SAFE + _NOTHING_WITHHELD + "; it names a structural fault, never part content",
    ),
    _Allowed(
        f"{_APP}.upload_file::UploadTooLargeError" + _HTTP,
        _SAFE + _NOTHING_WITHHELD + "; it carries sizes only",
    ),
    _Allowed(
        f"{_APP}.upload_file::UploadContentError" + _HTTP,
        _SAFE + _NOTHING_WITHHELD + "; it quotes the upload's display name, never content",
    ),
    _Allowed(
        f"{_APP}.upload_file::UploadQuotaError" + _HTTP,
        _SAFE + _NOTHING_WITHHELD + "; it carries counts and the uploader name",
    ),
    _Allowed(
        f"{_APP}._authorized_upload_meta::(UploadPathError, UploadNotFoundError)" + _HTTP,
        _SAFE + _UPLOAD_MISS,
    ),
    _Allowed(
        f"{_APP}._authorized_upload_meta::UploadUnreadableError" + _HTTP,
        _SAFE + _UPLOAD_MISS,
        count=2,
    ),
    _Allowed(
        f"{_APP}.browse_uploaded_file::(UploadPathError, UploadNotFoundError)" + _HTTP,
        _SAFE + _UPLOAD_MISS,
    ),
    _Allowed(f"{_APP}.browse_uploaded_file::UploadUnreadableError" + _HTTP, _SAFE + _UPLOAD_MISS),
    _Allowed(
        f"{_APP}.resend_uploaded_message::KeyError" + _HTTP,
        _SAFE + "KeyError carries the inbound name, which the 404 detail also quotes",
    ),
    _Allowed(
        f"{_APP}.resend_uploaded_message::(UploadPathError, UploadNotFoundError)" + _HTTP,
        _SAFE + _UPLOAD_MISS,
    ),
    _Allowed(
        f"{_APP}.resend_uploaded_message::UploadUnreadableError" + _HTTP, _SAFE + _UPLOAD_MISS
    ),
    _Allowed(
        f"{_APP}.delete_uploaded_file::(UploadPathError, UploadNotFoundError)" + _HTTP,
        _SAFE + _UPLOAD_MISS,
    ),
    _Allowed(f"{_APP}.delete_uploaded_file::UploadUnreadableError" + _HTTP, _SAFE + _UPLOAD_MISS),
)


def _last_name(node: ast.expr) -> str:
    """``queue.Empty`` and ``Empty`` name one class, so an import-style change must not move a key."""
    return node.attr if isinstance(node, ast.Attribute) else ast.unparse(node)


class _Scanner(ast.NodeVisitor):
    """Collect EVERY ``raise ... from None``, keyed by where it sits.

    Not only the ones inside a handler: see the module docstring. A raise outside any handler is
    keyed ``<no handler>``. A ``finally:`` body runs while an exception may be propagating, so it is
    keyed ``<finally>``. A ``def``, ``lambda`` or ``class`` resets the context, so a function defined
    inside a handler is keyed ``<no handler>``: where it RUNS is not visible from where it is written.
    """

    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.names: list[str] = []
        self.contexts: list[str] = []
        self.keys: list[str] = []

    def _scope(self, node: ast.AST, name: str) -> None:
        saved = self.contexts
        self.contexts = []
        self.names.append(name)
        self.generic_visit(node)
        self.names.pop()
        self.contexts = saved

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scope(node, node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope(node, node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._scope(node, "<lambda>")

    def _visit_try(self, node: ast.Try | ast.TryStar) -> None:
        for child in (*node.body, *node.handlers, *node.orelse):
            self.visit(child)
        self.contexts.append("<finally>")
        for child in node.finalbody:
            self.visit(child)
        self.contexts.pop()

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._visit_try(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        caught = node.type
        self.contexts.append("<bare>" if caught is None else _last_name(caught))
        self.generic_visit(node)
        self.contexts.pop()

    def visit_Raise(self, node: ast.Raise) -> None:
        cause = node.cause
        if isinstance(cause, ast.Constant) and cause.value is None:
            where = self.contexts[-1] if self.contexts else "<no handler>"
            exc = node.exc
            if isinstance(exc, ast.Call):
                raised = _last_name(exc.func)
            else:
                raised = "" if exc is None else _last_name(exc)
            qualname = ".".join(self.names) or "<module>"
            self.keys.append(f"{self.rel}::{qualname}::{where}::{raised}")
        self.generic_visit(node)


def _scan_source(source: str, rel: str) -> list[str]:
    scanner = _Scanner(rel)
    scanner.visit(ast.parse(source))
    return scanner.keys


def _scan(root: Path, base: Path) -> Counter[str]:
    found: Counter[str] = Counter()
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(base).as_posix()
        found.update(_scan_source(path.read_text(encoding="utf-8"), rel))
    return found


def _assert_classified(found: Counter[str], allowed: tuple[_Allowed, ...]) -> None:
    """The gate, over a named census, so the controls below can drive it into failure."""
    listed: Counter[str] = Counter()
    for entry in allowed:
        listed[entry.key] += entry.count
    unlisted = sorted(k for k in found if found[k] > listed[k])
    stale = sorted(k for k in listed if listed[k] > found[k])
    problems: list[str] = []
    if unlisted:
        problems.append(
            f"`raise ... from None` with no entry in _ALLOWED: {unlisted}\n"
            "`from None` clears __cause__ but LEAVES __context__ populated, so it hides nothing "
            "from code that walks the chain. If the caught exception can carry payload or a "
            "secret, raise OUTSIDE the handler instead: keep only the content-free fact in a "
            "local, let the handler end, then raise (see encode_wire_body in "
            "messagefoundry/transports/base.py). Otherwise add an entry whose reason starts "
            f"{_SAFE!r} and says what the caught exception carries."
        )
    if stale:
        problems.append(
            f"_ALLOWED entries whose site is gone or has fewer raises than listed: {stale}\n"
            "Delete or re-count them, so the list stays a true census. A fixed UNSAFE site "
            "belongs here: removing its entry is part of the fix."
        )
    assert not problems, "\n\n".join(problems)


def test_every_from_none_is_classified() -> None:
    _assert_classified(_scan(_PKG, _ROOT), _ALLOWED)


def test_the_scan_is_armed() -> None:
    """A walker that finds nothing makes the gate pass vacuously.

    The census on 2026-09-26 was 50, and 47 once the three UNSAFE sites were fixed. Those three are
    driven, chain and all, by ``tests/test_refusals_carry_no_chain.py``."""
    found = _scan(_PKG, _ROOT)
    assert sum(found.values()) >= 40, found


def test_every_reason_says_safe_or_unsafe_and_why() -> None:
    bad = [
        e.key
        for e in _ALLOWED
        if not any(
            e.reason.startswith(prefix) and len(e.reason) > len(prefix) + 10
            for prefix in (_SAFE, _UNSAFE)
        )
    ]
    assert not bad, f"each reason must start {_SAFE!r} or {_UNSAFE!r} and give a reason: {bad}"


def test_every_key_is_listed_once() -> None:
    keys = [e.key for e in _ALLOWED]
    dupes = sorted({k for k in keys if keys.count(k) > 1})
    assert not dupes, f"list a repeated site once, with count=N: {dupes}"


_MARKER = "SYNTHETIC-PAYLOAD-7f3a"
#: Ends in a character ASCII cannot encode, so ``.encode("ascii")`` raises over the whole string.
_PAYLOAD = _MARKER + chr(0xE9)


def _refusal(*, suppress: bool) -> ValueError:
    with pytest.raises(ValueError) as caught:
        try:
            _PAYLOAD.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("refused at position N") from None
    exc = caught.value
    exc.__suppress_context__ = suppress
    return exc


def test_from_none_leaves_the_context_populated() -> None:
    """The premise, measured. If a future Python changes it, this is where it shows."""
    exc = _refusal(suppress=True)
    assert exc.__cause__ is None
    context = exc.__context__
    assert isinstance(context, UnicodeEncodeError)
    assert context.object == _PAYLOAD, "the whole payload is reachable by attribute"
    rendered = "".join(traceback.TracebackException.from_exception(exc, compact=False).format())
    assert "UnicodeEncodeError" not in rendered, (
        "the default printer skips the suppressed context, so a traceback scan never sees it"
    )


def test_the_printer_arm_can_fail() -> None:
    """Control for the arm above: with the flag off, the same printer DOES render the context."""
    exc = _refusal(suppress=False)
    rendered = "".join(traceback.TracebackException.from_exception(exc, compact=False).format())
    assert "UnicodeEncodeError" in rendered


def test_the_safe_shape_leaves_both_chains_empty() -> None:
    position: int | None = None
    try:
        _PAYLOAD.encode("ascii")
    except UnicodeEncodeError as err:
        position = err.start
    with pytest.raises(ValueError) as caught:
        if position is not None:
            raise ValueError(f"refused at position {position}")
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


_PLANTED = """
def encode_wire_body(payload, encoding, *, transport):
    try:
        return payload.encode(encoding)
    except UnicodeEncodeError as exc:
        raise NegativeAckError(f"{transport}: position {exc.start}") from None
"""
_PLANTED_KEY = (
    "messagefoundry/planted/mod.py::encode_wire_body::UnicodeEncodeError::NegativeAckError"
)


def test_a_planted_unlisted_site_fails_the_gate(tmp_path: Path) -> None:
    """The positive control: the real gate, with the real list, over one planted module."""
    pkg = tmp_path / "messagefoundry" / "planted"
    pkg.mkdir(parents=True)
    (pkg / "mod.py").write_text(_PLANTED, encoding="utf-8")
    found = _scan(tmp_path / "messagefoundry", tmp_path)
    assert found == Counter({_PLANTED_KEY: 1})
    with pytest.raises(AssertionError) as caught:
        _assert_classified(_scan(_PKG, _ROOT) + found, _ALLOWED)
    assert _PLANTED_KEY in str(caught.value)


def test_a_stale_entry_fails_the_gate() -> None:
    """Fixing a site without deleting its entry must red, or the list stops being a census."""
    ghost = _Allowed("messagefoundry/nowhere.py::gone::KeyError::X", _SAFE + "a site now fixed")
    with pytest.raises(AssertionError) as caught:
        _assert_classified(_scan(_PKG, _ROOT), (*_ALLOWED, ghost))
    assert ghost.key in str(caught.value)


def test_a_second_raise_at_a_listed_key_fails_the_gate() -> None:
    """A count, not a set: a new raise in an already-listed function is still a new site."""
    real = _scan(_PKG, _ROOT)
    key = "messagefoundry/transports/base.py::build_source::KeyError::ValueError"
    assert real[key] == 1
    with pytest.raises(AssertionError) as caught:
        _assert_classified(real + Counter({key: 1}), _ALLOWED)
    assert key in str(caught.value)


#: Faithful excerpts of the five #1792 sites at b56c0add0^1, the parent of engine PR 1209.
_PRE_1209: dict[str, str] = {
    "transports/base.py": """
def encode_wire_body(payload, encoding, *, transport):
    try:
        return payload.encode(encoding)
    except UnicodeEncodeError as exc:
        raise NegativeAckError("...", code="encoding", permanent=True) from None
""",
    "transports/soap.py": """
class SoapDestination:
    def _parse_body_secrets(self, secret, token):
        try:
            secret.encode(self.encoding)
        except UnicodeEncodeError as exc:
            raise ValueError(f"... position {exc.start}") from None
""",
    "transports/signing.py": """
def _load_private_key(private_key, password):
    try:
        key = serialization.load_pem_private_key(material, password=pw)
    except (ValueError, TypeError):
        raise SigningError("could not load the signing private key") from None
""",
    "parsing/fhir/resource.py": """
class FhirResource:
    @classmethod
    def parse(cls, data):
        try:
            model = model_class.model_validate(data)
        except ValidationError as exc:
            raise FhirValidationError(_safe_validation_summary(rt, v, exc)) from None
""",
    "auth/oidc/flow.py": """
def exchange_code(code):
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(1)
    except urllib.error.HTTPError as exc:
        raise FlowError(f"token endpoint returned HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FlowError(f"token endpoint unreachable: {type(exc).__name__}") from None
""",
}


@pytest.mark.parametrize("rel", sorted(_PRE_1209))
def test_the_five_pre_1209_shapes_are_all_flagged(rel: str) -> None:
    """The negative control the row demands: reverted source must fail the gate, BY ITS OWN KEYS.

    Checking only that the gate raised would pass whenever anything else were unlisted or stale.
    """
    keys = Counter(_scan_source(_PRE_1209[rel], f"messagefoundry/{rel}"))
    assert keys, f"the scanner is blind to the pre-1209 shape of {rel}"
    with pytest.raises(AssertionError) as caught:
        _assert_classified(_scan(_PKG, _ROOT) + keys, _ALLOWED)
    missed = sorted(k for k in keys if k not in str(caught.value))
    assert not missed, f"the gate failed, but not over these pre-1209 sites: {missed}"


_FLAGGED_OUTSIDE_A_HANDLER = """
def helper(n):
    raise ValueError(f"position {n}") from None


def in_finally(payload):
    try:
        payload.encode("ascii")
    finally:
        raise ValueError("refused") from None


def defined_in_a_handler(payload):
    try:
        payload.encode("ascii")
    except UnicodeEncodeError:
        def later():
            raise ValueError("may run inside the handler") from None
        later()
"""


def test_from_none_outside_a_handler_is_still_a_site() -> None:
    """A helper or a finally can carry the hazard; moving the raise there must not hide it."""
    assert _scan_source(_FLAGGED_OUTSIDE_A_HANDLER, "x.py") == [
        "x.py::helper::<no handler>::ValueError",
        "x.py::in_finally::<finally>::ValueError",
        "x.py::defined_in_a_handler.later::<no handler>::ValueError",
    ]


_NOT_FLAGGED = """
def outside(payload):
    position = None
    try:
        payload.encode("ascii")
    except UnicodeEncodeError as exc:
        position = exc.start
    if position is not None:
        raise ValueError(f"position {position}")


def explicit_cause(payload):
    try:
        payload.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("refused") from exc


def reraise(payload):
    try:
        payload.encode("ascii")
    except UnicodeEncodeError:
        raise
"""


def test_shapes_that_claim_nothing_are_not_flagged() -> None:
    assert _scan_source(_NOT_FLAGGED, "x.py") == []
