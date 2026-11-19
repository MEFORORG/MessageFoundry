# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The verifier redacts credentials out of the exception text it writes into a check's detail
(BACKLOG #5395).

A verify report is written to JSON and Markdown that an operator pastes into a ticket. Each arm below
used to interpolate the raw exception text, and a store driver or a config module can quote a DSN or
a ``password=`` / ``PWD=`` pair. Every secret here is synthetic, and each carries a hyphen and an
underscore so the unrelated long-base64 sweep cannot be what hides it.
"""

from __future__ import annotations

import importlib
import socket
import ssl
from pathlib import Path

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.config.wiring import Registry, WiringError
from messagefoundry.store import base as store_base
from messagefoundry.verify import checks, runner, smoke
from messagefoundry.verify.model import CheckResult, Status, safe_exc_detail
from messagefoundry.verify.report import render_json, render_markdown

_PLANTED = "pw-V3rify_Det-81"
#: A driver error that quotes its connection in the three shapes a driver uses.
_LEAKY = (
    f"connection to postgresql://svc:{_PLANTED}@db.invalid:5432/mefor failed; "
    f"Server=db.invalid;UID=svc;PWD={_PLANTED}; password={_PLANTED}"
)


def _assert_hidden(result: CheckResult, prefix: str) -> None:
    assert result.detail.startswith(prefix), result.detail
    assert _PLANTED not in result.detail, result.detail
    # The rendered reports are what leave the box; check them too, not only the field.
    assert _PLANTED not in render_json([result])
    assert _PLANTED not in render_markdown([result])


def _raise(exc: BaseException) -> Registry:
    raise exc


@pytest.mark.parametrize("exc", [WiringError(_LEAKY), OSError(_LEAKY), RuntimeError(_LEAKY)])
def test_config_load_failure_detail_hides_the_credential(
    tmp_path: Path, exc: BaseException
) -> None:
    r = smoke.smoke_self(str(tmp_path), graph=lambda: _raise(exc))
    _assert_hidden(r, "config failed to load: ")


def test_a_wiring_error_takes_the_config_load_path(tmp_path: Path) -> None:
    """A WiringError wraps whatever a config module raised, so it takes the config-load arms'
    bound and the square-bracket placeholder, and, being the engine's own diagnostic, no type
    prefix. Control: the same text through the bound-free credential scrub runs past the bound."""
    from messagefoundry.secretscrub import scrub_credentials

    head = f"{_LEAKY}; handler 'h' sends to unknown outbound 'ob_missing'"
    r = smoke.smoke_self(str(tmp_path), graph=lambda: _raise(WiringError(head)))
    assert _PLANTED not in r.detail
    assert "WiringError" not in r.detail
    assert "[redacted]" in r.detail and "<redacted>" not in r.detail, r.detail
    text = "y " * 5000
    huge = smoke.smoke_self(str(tmp_path), graph=lambda: _raise(WiringError(text)))
    assert len(huge.detail) < 400 < len(scrub_credentials(text)), len(huge.detail)


@pytest.mark.parametrize(
    ("exc", "prefix"),
    [
        (ssl.SSLError(_LEAKY), "TLS handshake with the engine inbound at 127.0.0.1:1 failed: "),
        (OSError(_LEAKY), "could not reach the engine inbound at 127.0.0.1:1: "),
    ],
)
def test_live_smoke_connect_failure_detail_hides_the_credential(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException, prefix: str
) -> None:
    def refuse(*_a: object, **_k: object) -> socket.socket:
        raise exc

    monkeypatch.setattr(socket, "create_connection", refuse)
    r = smoke.smoke_live(host="127.0.0.1", port=1, message="MSH|^~\\&|A", timeout=1.0)
    _assert_hidden(r, prefix)


def _store_that_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StoreSettings:
    """A store whose open raises the leaky driver error, past the missing-file gate."""
    db = tmp_path / "verify.db"
    db.write_bytes(b"")

    async def leaky_open(*_a: object, **_k: object) -> object:
        raise RuntimeError(_LEAKY)

    monkeypatch.setattr(store_base, "open_store", leaky_open)
    return StoreSettings(path=str(db))


def test_store_open_failure_detail_hides_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = smoke.check_store_connectivity(_store_that_raises(tmp_path, monkeypatch))
    _assert_hidden(r, "sqlite store failed to open: ")


def test_store_disposition_poll_failure_detail_hides_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _store_that_raises(tmp_path, monkeypatch)
    r = smoke.check_smoke_disposition(settings, control_id="C1", baseline_id=None, timeout=1.0)
    _assert_hidden(r, "could not read the store disposition: ")


def test_the_pre_send_baseline_failure_detail_hides_the_credential_and_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The smoke.disposition row's pre-send baseline read opens the same store the sibling arms do,
    so it takes their PHI and credential passes and the driver bound (BACKLOG #5395). Control: the
    rendering it used before, ``codec_safe_line``, prints the planted value and the whole tail."""
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.redaction import codec_safe_line
    from messagefoundry.verify.model import DRIVER_DETAIL_LIMIT

    exc = RuntimeError(_LEAKY + " tail" * 2000)

    def leaky_baseline(*_a: object, **_k: object) -> str | None:
        raise exc

    monkeypatch.setattr(smoke, "newest_message_id", leaky_baseline)
    monkeypatch.setattr(
        smoke,
        "smoke_live",
        lambda **_kw: CheckResult("smoke.live", "Live smoke (MLLP + ACK)", Status.PASS, "AA"),
    )
    results = runner._run_live_smoke(
        smoke.synthetic_message(),
        host="127.0.0.1",
        port=1,
        settings=ServiceSettings(store=StoreSettings(path=str(tmp_path / "verify.db"))),
        check_disposition=True,
        disposition_timeout=1,
    )
    disp = [r for r in results if r.id == "smoke.disposition"]
    assert disp, results
    _assert_hidden(disp[0], "could not read the pre-send baseline from the store")
    assert "RuntimeError" in disp[0].detail
    assert len(disp[0].detail) < DRIVER_DETAIL_LIMIT + 200, len(disp[0].detail)
    old = codec_safe_line(exc)
    assert _PLANTED in old and len(old) > DRIVER_DETAIL_LIMIT + 200


def test_control_safe_exc_alone_keeps_the_credential() -> None:
    """The positive control for every arm above: ``safe_exc`` by itself is a PHI pass and leaves
    this text's credentials in place, so the arms are hidden by the credential pass, not by it. If
    this goes red, ``safe_exc`` learned credentials and ``model.safe_exc_detail``'s docstring is
    stale."""
    from messagefoundry.redaction import safe_exc

    assert _PLANTED in safe_exc(RuntimeError(_LEAKY))


def test_a_long_detail_is_bounded_and_a_credential_near_the_bound_hidden() -> None:
    """The detail keeps ``safe_text``'s bound, and a credential sitting just inside it is hidden. No
    order control: ``safe_text`` cuts at whole tokens, so neither order was measured to print a
    value at the cut."""
    exc = RuntimeError(" ".join(["word"] * 37) + f" PWD={_PLANTED}" + " tail" * 80)
    detail = safe_exc_detail(exc)
    assert _PLANTED not in detail, detail
    assert "PWD=" in detail, detail
    assert len(detail) < 260, len(detail)


@pytest.mark.parametrize(
    "label", ["Login Password", "Access Token", "Client Secret", "Bind Password"]
)
@pytest.mark.parametrize("sep", ["=", ": ", "='", " = "])
def test_a_capitalized_two_word_label_keeps_its_value_hidden(label: str, sep: str) -> None:
    """The PHI name pass reads ``Login Password`` as a name and takes it. Run before any credential
    pass that needs the label, the value printed; the credentials-first order hides it, and a fragment
    the PHI-first order prints more often than the credentials-first order is hidden. The second
    control is the PHI-first order alone, which prints the value on this text."""
    from messagefoundry.redaction import redact, safe_exc
    from messagefoundry.secretscrub import scrub_credentials

    close = "'" if sep.endswith("'") else ""
    text = f"{label}{sep}{_PLANTED}{close} more"
    exc = RuntimeError(text)
    assert _PLANTED in safe_exc(exc)  # control: the PHI pass alone keeps it
    if sep == "=":
        bare = scrub_credentials(redact(text))
        assert _PLANTED in bare, bare  # control: PHI first alone keeps it
    assert _PLANTED not in safe_exc_detail(exc)


_MRN = "MRN7712345"


@pytest.mark.parametrize(
    "text",
    [
        f"token=tk-1,mrn: {_MRN}",
        f"session=s-1,mrn: {_MRN}",
        f"Access Token=tk-1,mrn: {_MRN}",
        f"password=pw-1,mrn: {_MRN} rest",
        # A PHI label glued on by a character a credential value class does not stop at.
        f"token=tk-1|mrn: {_MRN}",
        f"password=pw-1/mrn: {_MRN}",
        f"token=tk-1:mrn: {_MRN}",
        f"token=tk-1.mrn: {_MRN}",
    ],
)
def test_a_credential_value_does_not_swallow_a_phi_label(text: str) -> None:
    """The review of BACKLOG #5395 measured ``token=tk-1,mrn: MRN7712345`` print its MRN: the shared
    credential vocabulary, run first, read ``tk-1,mrn:`` as the token's value, and the PHI pass then
    found no ``mrn:`` label. The PHI pass runs before that vocabulary now. Controls: the PHI pass
    alone hides the MRN, so the label is what it reads; the credential-first order prints it on at
    least the first text."""
    from messagefoundry.redaction import safe_text
    from messagefoundry.secretscrub import scrub_credentials
    from messagefoundry.verify.model import safe_detail_text

    assert _MRN not in safe_text(text)
    if text.startswith("token="):
        assert _MRN in safe_text(scrub_credentials(text))
    detail = safe_detail_text(text)
    assert _MRN not in detail, detail
    assert "tk-1" not in detail and "s-1" not in detail and "pw-1" not in detail, detail


@pytest.mark.parametrize(
    "text",
    [f"Authorization: Bearer {_PLANTED} q", f"Access Token: Bearer {_PLANTED} q"],
)
def test_a_scheme_word_after_a_token_label_does_not_shield_the_token(text: str) -> None:
    """The pre-mask takes an auth-scheme word with the value. Without that it masked the word
    ``Bearer`` and the token after it printed (simplify pass on BACKLOG #5395)."""
    from messagefoundry.verify.model import safe_detail_text

    assert _PLANTED not in safe_detail_text(text)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        # The PHI pass rewrites part of the DSN or the value; the credential pass must still read it.
        ("connection to postgresql://19800505:Zq7_Secret-Kv9@db.invalid:5432/mefor failed", "Kv9"),
        ("postgresql://svc:Zq7-19800505-Kv9@db.invalid/mefor", "Kv9"),
        ("MEFOR_STORE_KEY=Zq7-19800505-Kv9 x", "Kv9"),
        ("private_key=Zq7-19800505-Kv9 x", "Kv9"),
        ("Bearer Zq7-19800505-Kv9 x", "Kv9"),
    ],
)
def test_a_credential_the_phi_pass_cut_into_is_still_hidden(text: str, secret: str) -> None:
    """The credential pass reads the PHI pass's whole result, not the pieces between its
    placeholders. Control: the pieces, as the bundle's second layer reads them, print the tail."""
    from messagefoundry.redaction import _REDACTED, redact
    from messagefoundry.secretscrub import scrub_credentials
    from messagefoundry.verify.model import safe_detail_text

    pieces = _REDACTED.join(scrub_credentials(x) for x in redact(text).split(_REDACTED))
    assert secret in pieces, pieces
    detail = safe_detail_text(text)
    assert secret not in detail, detail


@pytest.mark.parametrize(
    "text", ["password=Jane Doe failed", "Password: Jane Doe failed", "session: Jane Doe x"]
)
def test_a_name_after_a_credential_label_is_hidden_whole(text: str) -> None:
    """No pass takes only the first word of a value before the PHI pass, so a two-word name after a
    label is still a name run. Control: the PHI pass alone hides the surname."""
    from messagefoundry.redaction import safe_text
    from messagefoundry.verify.model import safe_detail_text

    assert "Doe" not in safe_text(text)
    detail = safe_detail_text(text)
    assert "Doe" not in detail and "Jane" not in detail, detail


@pytest.mark.parametrize(
    ("text", "hidden"),
    [
        # A name before a label: the PHI pass reads it with the label, and it stays hidden.
        (f"Patient Jane Doe Password={_PLANTED} y", ("Jane", "Doe", _PLANTED)),
        ("patient Smithson Token: tk-1 x", ("Smithson", "tk-1")),
        ("login for Doe Password=pw-1", ("Doe", "pw-1")),
        ("user DOE PWD=pw-1", ("DOE", "pw-1")),
        # A label the PHI pass takes in an HL7 field run, its value in the next word.
        ("ERR a|b^password= Zq7x-ghi more", ("Zq7x-ghi",)),
        ("ERR a%7Cb%5Etoken: Zq7x-ghi", ("Zq7x-ghi",)),
        ("DOE^JANE^^password: Zq7x-ghi", ("Zq7x-ghi", "JANE")),
        # A label paired with a name across a newline, a comma or a no-break space.
        ("bad settings:\nServer: db.invalid\nUser: Svc\nPassword: Hq9-Real_Pw", ("Hq9-Real_Pw",)),
        ("User=Svc, Password=x9y8", ("x9y8",)),
        ("UID=SVC, PWD=x9y8", ("x9y8",)),
        ("Login Password=x9y8", ("x9y8",)),
    ],
)
def test_a_word_either_order_hides_stays_hidden(text: str, hidden: tuple[str, ...]) -> None:
    """Code review round 2 measured each of these print under one order of the two passes. A fragment
    the PHI-first order prints more often than the credentials-first order is hidden now. Control:
    one order alone prints at least one of the words, so the other order is what hides it."""
    from messagefoundry.redaction import redact
    from messagefoundry.secretscrub import scrub_credentials
    from messagefoundry.verify.model import safe_detail_text

    phi_first = scrub_credentials(redact(text))
    credentials_first = redact(scrub_credentials(text))
    assert any(w in phi_first or w in credentials_first for w in hidden), (
        phi_first,
        credentials_first,
    )
    detail = safe_detail_text(text)
    for word in hidden:
        assert word not in detail, detail


@pytest.mark.parametrize(
    "text",
    [
        "login failed for svcadmin Login Password: svcadmin",
        "user svcadmin Login Password: svcadmin",
        # The label first: here the FIRST occurrence is the password, so keeping the first of as
        # many as the other order prints would print it (code review of the Counter draft).
        "Login Password: svcadmin for user svcadmin",
    ],
)
def test_a_password_equal_to_another_printed_word_is_hidden_at_every_occurrence(text: str) -> None:
    """Code review round 3 of BACKLOG #5395: against a SET of the other order's words, a password
    equal to a word printed elsewhere on the line survived, so both copies printed. A fragment the
    primary order prints more often than the other order is now hidden everywhere. Control: the
    set the code used before prints the word twice."""
    import re

    from messagefoundry import verify_leaf as model
    from messagefoundry.redaction import redact
    from messagefoundry.secretscrub import scrub_credentials

    def count(out: str) -> int:
        return len(re.findall(r"\bsvcadmin\b", out))

    ph = model._PLACEHOLDER
    phi_first = scrub_credentials(redact(text), placeholder=ph)
    credentials_first = redact(scrub_credentials(text, placeholder=ph))
    printed = {p for w in credentials_first.split() for p in model._fragments(w)}
    as_a_set = re.sub(
        r"\S+",
        lambda m: m[0] if all(p in printed for p in model._fragments(m[0])) else ph,
        phi_first,
    )
    assert count(as_a_set) == 2, as_a_set
    assert count(model.safe_detail_text(text)) == 0, model.safe_detail_text(text)


@pytest.mark.parametrize(
    "text",
    [
        "Login Password: Kv9x7Qz3 retry with Kv9x7Qz3.",
        "Login Password: Kv9x7Qz3 retry with (Kv9x7Qz3),",
        "Login Password: Kv9x7Qz3 retry with 'Kv9x7Qz3'",
    ],
)
def test_a_password_glued_to_punctuation_is_hidden_at_every_occurrence(text: str) -> None:
    """Code review of round 8, BACKLOG #5395: fragments were whole whitespace-split words, so
    ``Kv9x7Qz3.`` was a different fragment from ``Kv9x7Qz3`` and printed. A fragment is a run of
    word characters now. Control: the whole-word fragments the code used before print it."""
    import re
    from collections import Counter

    from messagefoundry import verify_leaf as model
    from messagefoundry.redaction import redact
    from messagefoundry.secretscrub import scrub_credentials

    ph = model._PLACEHOLDER
    detail = model.safe_detail_text(text)
    assert "Kv9x7Qz3" not in detail, detail

    def whole(word: str) -> list[str]:
        return [piece for piece in word.split(ph) if piece]

    phi_first = scrub_credentials(redact(text), placeholder=ph)
    credentials_first = redact(scrub_credentials(text, placeholder=ph))
    printed = Counter(p for w in credentials_first.split() for p in whole(w))
    shown = Counter(p for w in phi_first.split() for p in whole(w))
    before = re.sub(
        r"\S+",
        lambda m: m[0] if all(shown[p] <= printed[p] for p in whole(m[0])) else ph,
        phi_first,
    )
    assert "Kv9x7Qz3" in before, before


@pytest.mark.parametrize(
    "text",
    [
        "Login Password: Kv9x7Qz3 then token=tk-1,mrn: Kv9x7Qz3",
        "Login Password: Kv9x7Qz3 retry token=tk-1,mrn: Kv9x7Qz3 now",
        # Code review round 1: the clauses swapped, so a placeholder that hid several source
        # tokens left a forward-only walk behind and placed the password on the earlier copy.
        "token=tk-1,mrn: Kv9x7Qz3 Login Password: Kv9x7Qz3",
        "token=tk-1,mrn: Kv9x7Qz3 Svc Account Login Password: Kv9x7Qz3",
        # ...and placeholders the source already held, which the walk did not count as slots.
        "[redacted] [redacted] Login Password: Kv9x7Qz3 then token=tk-1,mrn: Kv9x7Qz3",
        # Code review round 2: a trailing name misled the backward walk of the other order too.
        "token=tk-1,mrn: Kv9x7Qz3 Login Password: Kv9x7Qz3 Mary Ann Lee Smith",
    ],
)
def test_a_password_each_order_prints_at_a_different_place_is_hidden(text: str) -> None:
    """BACKLOG #5395 added item 2: the comparison counted fragments and never placed them. Here the
    PHI-first order prints the password and hides the copy after ``mrn:``, the credentials-first
    order does the reverse, so the counts are equal and the password printed. Control: the
    count-only comparison the code used before prints it."""
    import re
    from collections import Counter

    from messagefoundry import verify_leaf as model
    from messagefoundry.redaction import redact
    from messagefoundry.secretscrub import scrub_credentials

    detail = model.safe_detail_text(text)
    assert "Kv9x7Qz3" not in detail, detail

    ph = model._PLACEHOLDER
    phi_first = scrub_credentials(redact(text), placeholder=ph)
    credentials_first = redact(scrub_credentials(text, placeholder=ph))
    printed = Counter(p for w in credentials_first.split() for p in model._fragments(w))
    shown = Counter(p for w in phi_first.split() for p in model._fragments(w))
    counted_only = re.sub(
        r"\S+",
        lambda m: m[0] if all(shown[p] <= printed[p] for p in model._fragments(m[0])) else ph,
        phi_first,
    )
    assert "Kv9x7Qz3" in counted_only, counted_only


def test_a_word_either_order_hid_a_copy_of_is_hidden_everywhere() -> None:
    """Each order hid a different copy of ``X X``, so the counts are equal and both orders print
    one copy. The test is against the source, which holds two."""
    from messagefoundry import verify_leaf as model

    ph = model._PLACEHOLDER
    assert model._printed_by_both(f"{ph} Kv9x7Qz3", f"Kv9x7Qz3 {ph}", "Kv9x7Qz3 Kv9x7Qz3") == (
        f"{ph} {ph}"
    )
    # Control: a word neither order hid any copy of is kept, at every copy.
    assert model._printed_by_both("at Kv9x7Qz3 at", "at Kv9x7Qz3 at", "at Kv9x7Qz3 at") == (
        "at Kv9x7Qz3 at"
    )


def test_the_placeholder_is_not_an_html_tag() -> None:
    """A sink that renders a pasted detail as HTML would drop ``<redacted>`` and show ``PWD=`` as an
    empty password; the detail's placeholder is the square-bracket one."""
    from messagefoundry.verify.model import safe_detail_text

    detail = safe_detail_text(f"Server=db;UID=sa;PWD={_PLANTED};")
    assert "PWD=[redacted]" in detail and "<" not in detail, detail


def test_a_cut_input_keeps_its_unscanned_note() -> None:
    """The window's note says what no pass read; the length bound must not drop it. Control: the
    input is past the window."""
    from messagefoundry.redaction import _REDACT_WINDOW
    from messagefoundry.verify.model import safe_detail_text

    text = "word " * _REDACT_WINDOW
    detail = safe_detail_text(text)
    assert "unscanned" in detail, detail[-200:]
    assert "unscanned" not in safe_detail_text("word " * 10)


def test_placeholders_past_the_window_do_not_call_scanned_text_unscanned() -> None:
    """An input inside the window whose placeholders push the cleaned text past it: every character
    was scanned, so the detail carries no unscanned note, and what the length bound held back is
    counted. Control: ``safe_text`` over that cleaned text at its default window writes the note."""
    from messagefoundry import verify_leaf as model
    from messagefoundry.redaction import _REDACT_WINDOW, safe_text
    from messagefoundry.secretscrub import scrub_credentials

    text = "PWD=x; " * (_REDACT_WINDOW // 8)
    assert len(text) < _REDACT_WINDOW
    detail = model.safe_detail_text(text)
    assert "unscanned" not in detail, detail[-200:]
    assert "chars)" in detail and "PWD=[redacted]" in detail, detail[-200:]
    expanded = scrub_credentials(text, placeholder=model._PLACEHOLDER)
    assert len(expanded) > _REDACT_WINDOW
    assert "unscanned" in safe_text(expanded), "the control no longer crosses the window"


def test_the_credential_pass_reads_only_the_work_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """The input is cut to ``clamp_untrusted``'s window before the credential vocabulary reads it,
    so a peer sizing the text buys no unbounded scan. Control: the input is past the window."""
    import messagefoundry.secretscrub as secretscrub
    from messagefoundry.redaction import _REDACT_WINDOW
    from messagefoundry.verify.model import safe_detail_text

    seen: list[int] = []
    real = secretscrub.scrub_credentials

    def spy(text: str, **kwargs: str) -> str:
        seen.append(len(text))
        return real(text, **kwargs)

    monkeypatch.setattr(secretscrub, "scrub_credentials", spy)
    text = f"PWD={_PLANTED} " + "word " * (_REDACT_WINDOW // 2)
    assert len(text) > _REDACT_WINDOW
    detail = safe_detail_text(text)
    assert seen and max(seen) <= _REDACT_WINDOW, seen
    assert _PLANTED not in detail, detail


def test_a_unicode_error_detail_takes_the_limit() -> None:
    """``limit`` bounds the ``UnicodeError`` branch too. Control: the same error is longer than the
    limit without it."""
    exc = UnicodeDecodeError("utf-8", bytes([0xFF]) * 10, 0, 1, "invalid start byte " * 30)
    assert len(safe_exc_detail(exc)) > 60
    assert len(safe_exc_detail(exc, limit=40)) < 60


@pytest.mark.parametrize(
    "exc",
    [
        ssl.SSLCertVerificationError("certificate verify failed"),
        PermissionError(13, "Permission denied", "/var/lib/messagefoundry/messagefoundry.db"),
    ],
)
def test_the_words_an_operator_needs_survive(exc: BaseException) -> None:
    """The class name and the path stay readable. The bundle's long-base64 sweep, tried first, blanked
    both, since a 24-character run is either."""
    detail = safe_exc_detail(exc)
    assert detail.startswith(type(exc).__name__), detail
    assert str(exc) in detail, detail


def test_a_label_and_its_value_on_different_lines_are_read_together() -> None:
    text = "\n".join(["line one", "password=", f"{_PLANTED} more"])
    detail = safe_exc_detail(RuntimeError(text))
    assert _PLANTED not in detail, detail


def test_a_dry_run_error_detail_hides_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``result.error`` quotes a Router/Handler's own ``raise``, which can quote a DSN."""
    from types import SimpleNamespace

    from messagefoundry.pipeline import dryrun

    reg = Registry()
    monkeypatch.setattr(reg, "validate", lambda: None)
    result = SimpleNamespace(
        inbound="IB_X",
        disposition=SimpleNamespace(value="ERROR"),
        handlers=[],
        deliveries=[],
        error=f"router/handler error: RuntimeError: {_LEAKY}",
    )
    monkeypatch.setattr(dryrun, "dry_run", lambda *_a, **_k: result)
    r = smoke.smoke_self(str(tmp_path), graph=lambda: reg)
    _assert_hidden(r, "inbound=IB_X")


def test_lockable_accounts_store_failure_detail_hides_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same store open as ``store.connect``, so the same driver text, in a sibling row."""
    from messagefoundry.config.settings import AuthSettings

    r = checks.check_lockable_accounts(_store_that_raises(tmp_path, monkeypatch), AuthSettings())
    _assert_hidden(r, "could not read the accounts: ")


def test_the_odbc_census_reason_hides_a_config_load_credential(tmp_path: Path) -> None:
    """The run's shared config load is quoted again in the ODBC hop census, a sibling row."""
    entries, reason = runner._buildable_entries(str(tmp_path), lambda: _raise(OSError(_LEAKY)))
    assert entries == []
    assert reason is not None and "did not load" in reason
    assert _PLANTED not in reason, reason


def test_the_odbc_census_failure_reason_hides_the_credential() -> None:
    def boom() -> checks.OdbcHops:
        raise RuntimeError(_LEAKY)

    hops = checks._census(boom, "host.odbc")
    assert hops.unknown is not None and _PLANTED not in hops.unknown, hops.unknown


def test_the_graph_read_failure_reason_hides_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> object:
        raise RuntimeError(_LEAKY)

    monkeypatch.setattr(runner, "_buildable_entries", boom)
    hops = runner._driver_hops(None, None, str(tmp_path), lambda: Registry())
    assert hops.unknown is not None and "graph read raised" in hops.unknown
    assert _PLANTED not in hops.unknown, hops.unknown


# --- The arms that still quoted an exception raw (BACKLOG #5395 added item 1) ---------------------


def test_a_federation_file_read_failure_hides_the_credential(tmp_path: Path) -> None:
    """The ``fed`` file read quotes the path, and the OSError quotes it again."""
    from messagefoundry.verify import federation

    path = tmp_path / f"jwks password={_PLANTED}.json"
    _, row = federation._read(str(path), "fed.jwks", "JWKS")
    assert row is not None
    _assert_hidden(row, "could not read ")


def test_a_federation_unforeseen_failure_hides_the_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import messagefoundry.auth.oidc as oidc
    from messagefoundry.verify import federation

    def boom(_jwks: bytes) -> object:
        raise RuntimeError(_LEAKY)

    monkeypatch.setattr(oidc, "parse_jwks", boom)
    _, row = federation._jwks_row(b"{}")
    _assert_hidden(row, "RuntimeError: ")


class _UnstatablePath:
    def is_dir(self) -> bool:
        raise OSError(_LEAKY)

    def __str__(self) -> str:
        return "/srv/mefor"


def test_the_writable_dir_stat_failure_hides_the_credential() -> None:
    from typing import cast

    row = checks.check_writable_dir(cast("Path", _UnstatablePath()))
    _assert_hidden(row, "cannot stat /srv/mefor: ")


def test_the_console_window_import_failure_hides_the_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(name: str) -> object:
        raise ImportError(_LEAKY)

    monkeypatch.setattr(importlib, "import_module", boom)
    row = checks.check_console_no_window()
    assert row.status is Status.SKIP
    assert _PLANTED not in row.detail, row.detail
    assert "not importable: " in row.detail
