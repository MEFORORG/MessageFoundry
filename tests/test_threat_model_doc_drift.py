# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Structural + numeric drift guard for ``docs/security/THREAT-MODEL.md``.

Two ASVS cells are scored on this document alone, so **the document IS the control**:

* **15.1.3** — "the application documentation identifies functionality that is resource intensive"
  *and* "documents the strategies used to prevent this from causing denial of service". The
  ``## Resource-demanding functionality (ASVS 15.1.3)`` section is that artifact.
* **15.1.5** — the dangerous/sensitive-functionality inventory. The
  ``## Dangerous functionality (ASVS 15.1.5)`` section is that artifact.

A prose artifact rots silently: a default flips, a route gains a bound, a new shell-execution site
lands — and the doc keeps asserting yesterday's truth while the cell keeps scoring Pass. This module
makes that impossible in the ways a test mechanically can:

1. **Structure** — both headings exist verbatim and each is followed by a markdown table.
2. **Anchor registries** — every surface the sections must enumerate is present in its section's
   slice. The registries live here, so deleting a row from the doc fails the test rather than
   quietly narrowing the inventory. A self-test proves each anchor is load-bearing (delete it from an
   in-memory copy → the checker must report it).
3. **Retired-console ban** — the pre-ADR-0065 PySide6 wording (``OS keyring`` / ``worker thread``)
   must never reappear, and the boundary-4 slice must keep naming the shipped browser-console
   controls.
4. **Setting-name resolution** — every ``[section].key`` the doc cites must resolve to a real field
   on a fresh ``ServiceSettings()`` (same mechanism as ``tests/test_cloud_phi_hipaa_doc_drift.py``).
5. **Numeric parity** — every default and constant the doc quotes is asserted against the **live**
   value by import, so a code-side change fails CI naming the doc row it invalidates.
6. **Shell-site invariant** — the set of modules under ``messagefoundry/`` that execute through a
   shell or an elevation verb must stay exactly the curated pair the 15.1.5 table documents. A new
   one fails with "add a Dangerous functionality row".

What this guard structurally cannot do is discover *tomorrow's* surface: an enumerative table pins
today's rows only (15.1.4 exhibited exactly that failure mode when pydicom/signxml landed later). The
review checklist carries the "does this change introduce a new dangerous-functionality or
resource-demanding surface?" question for that half.

**Where the document is not present** (BACKLOG #1043). ``docs/security/**`` is withheld from public
checkouts (deny-listed and vaulted), so there the doc-CONTENT assertions have nothing to assert.
They used to answer that with a bare ``pytest.skip``, which in a 12,000-test run is indistinguishable
from a pass — a control that cannot report its own inertness (ADR 0158's class 2). Three changes:

* the absence is **announced**, once per run, as a :class:`ThreatModelDocUnenforced` warning that
  names the path it looked for, what stopped enforcing, and what still does. It lands in pytest's
  warnings summary, which prints even under ``-q``;
* ``MEFOR_THREAT_MODEL_DOC`` points the whole module at a copy elsewhere (the vault working tree),
  and ``MEFOR_REQUIRE_THREAT_MODEL_DOC`` makes absence a hard **failure** for any leg that is
  supposed to have it — so the enforcing posture is fail-closed rather than best-effort;
* the **checker mechanism** is verified on every tree, doc or no doc, against an in-module stand-in
  (the ``--- checker self-tests`` section). That is deliberately not a stand-in for the document's
  *content*: a public copy of the registries would be a green proving only that a fixture matches a
  fixture. What it proves is that these checkers can go red — including the one trap this module has
  actually been caught by, a row deleted while the section's prose still carries its anchor.
"""

from __future__ import annotations

import os
import re
import warnings
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_PKG = _ROOT / "messagefoundry"

#: Point this at a copy of the document (e.g. the vault working tree) to enforce the content half
#: from a checkout that does not carry it.
_DOC_ENV = "MEFOR_THREAT_MODEL_DOC"
#: Set truthy where the document is EXPECTED to be present. Absence is then a failure, not a notice.
_REQUIRE_ENV = "MEFOR_REQUIRE_THREAT_MODEL_DOC"


def _doc_path() -> Path:
    """Where the threat model is read from — the env override, else the in-tree (vault) location."""
    override = os.environ.get(_DOC_ENV, "").strip()
    return Path(override) if override else _ROOT / "docs" / "security" / "THREAT-MODEL.md"


_RESOURCE_HEADING = "## Resource-demanding functionality (ASVS 15.1.3)"
_DANGEROUS_HEADING = "## Dangerous functionality (ASVS 15.1.5)"
_BOUNDARY4_HEADING = "### Web console (browser `/ui`) — boundary 4"

# Every [section].key token; the key stops before a glob '*' so `[logging].forward_*` -> forward.
_TOML_TOKEN_RE = re.compile(r"\[([a-z_]+)\]\.([a-z_]+)")


#: Unit suffixes a bound is written with, as their multiplier. Binary units only: every size in
#: this document is a MiB/KiB quantity, and accepting "MB" here would silently equate 10**6 with
#: 2**20 -- a 4.9 percent error no assertion would ever report.
_UNIT_MULTIPLIER: dict[str, float] = {
    "": 1,
    "s": 1,
    "bits": 1,
    "attempts": 1,
    "KiB": 1024,
    "MiB": 1024 * 1024,
    "GiB": 1024 * 1024 * 1024,
}

#: A label's trailing value: a number, an optional unit, then any prose or parenthetical gloss,
#: deliberately ignored -- "2.0 s (POSIX)", "512 (reject-when-full)" and "100 attempts by default"
#: each carry a machine-checkable bound in front of their commentary.
_LABEL_VALUE_RE = re.compile(
    r"=\s*(?P<number>\d[\d,]*(?:\.\d+)?)\s*(?P<unit>KiB|MiB|GiB|bits|attempts|s)?\b"
)


def _bounds_from_label(label: str) -> tuple[float, ...] | None:
    """The bound a row's label states, as its admissible readings, or ``None`` for a posture.

    THE LABEL IS THE BRIDGE, and that is the point of this function. The chain this module needs
    is ``document -> label -> literal -> live constant``. Only the last link was ever asserted
    (BACKLOG #1214), so a literal could be edited to match a code change while the label beside
    it -- the half a reader actually reads -- went on stating the old bound, and nothing failed.

    TWO READINGS, NOT ONE, AND THIS IS A MEASURED CORRECTION RATHER THAN A HEDGE. A first version
    scaled every size to bytes and immediately flagged ``sandbox mem cap = 512 MiB`` against its
    literal ``512``. That was a false positive in the CHECK, not drift in the row: the live value
    is ``s.sandbox.mem_mb``, denominated in MiB, while ``file cap = 16 MiB`` sits beside a literal
    of ``16 * mib`` in BYTES. **A literal's unit is a property of its constant and is not
    recoverable from the label**, so insisting on one convention would red honest rows.

    Both readings are therefore admissible and a row passes if either matches. Weaker on purpose:
    it still catches the class this exists for -- a label and its literal naming genuinely
    different bounds -- while declining to assert a unit it cannot know. What it cannot catch is
    a label and literal that agree numerically under the wrong unit.

    Returns ``None`` for a row like "= unlimited" or "ACK-on-receipt is the default": those state
    a posture with no numeric form, and the caller COUNTS them rather than skipping silently,
    because an unstated exclusion is how a partial check comes to read as a total one.
    """
    match = _LABEL_VALUE_RE.search(label)
    if match is None:
        return None
    number = float(match.group("number").replace(",", ""))
    scaled = number * _UNIT_MULTIPLIER[match.group("unit") or ""]
    return (number,) if scaled == number else (number, scaled)


# --- the curated registries the doc must keep enumerating --------------------------------------

#: ``row-label fragment -> a token that row must carry``, for the surfaces whose bare anchor occurs
#: in MORE THAN ONE row. Keyed on the row's own first cell, so each entry pins exactly one row and
#: deleting it reds CI — a bare-token registry cannot, because the sibling row keeps the token alive.
_RESOURCE_ROW_KEYS: dict[str, str] = {
    "**HL7 parse**": "enforce_size_limits",
    "**Database poll source**": "poll_statement",
    "**`GET /messages/{id}/attachments/{id}`**": "attachments/{id}",
    "**X12 interchange split**": "X12",
    "**Raw TCP / X12 listener**": "X12",
    "**Startup audit-chain verification**": "verify_audit_chain",
    "**`POST /status/integrity-check`**": "verify_audit_chain",
    "**`GET /uploads/{file_id}/messages`**": "/uploads",
    "**`POST /uploads`**": "/uploads",
    "**`GET /logs/tail`**": "/logs/tail",
    "**Per-actor PHI reads**": "/logs/tail",
}

_DANGEROUS_ROW_KEYS: dict[str, str] = {
    # BACKLOG #1278 made `subprocess` the default, so this key names vault text that is now false:
    # in-process is the opt-OUT, not the default. The anchor is deliberately NOT re-picked here. It
    # names a token that must appear in the vault document, and choosing a replacement from a
    # checkout that cannot read that document would trade a stale anchor for an unverifiable one and
    # red the leg for whoever does hold the vault. Same reasoning as the `pickle` anchor below. This
    # is a COUPLED edit: the vault row and this key move together, vault-side.
    "**In-process (default) or subprocess-isolated execution": "sandbox",
    "**`db_lookup`**": "db_lookup",
    "**`fhir_lookup`**": "fhir_lookup",
    # The pipe no longer pickles (ADR 0087 MFW2, BACKLOG #339): a Handler's `__reduce__` executed in
    # the engine parent. Pinning "pickle" here would now REQUIRE the private doc to keep asserting a
    # mechanism the code does not have, so the anchor moved to the module that replaced it. This is a
    # COUPLED edit — `docs/security/THREAT-MODEL.md` lives in the vault (gitignored, absent from every
    # checkout, so these tests skip here and in CI) and its 15.1.5 row must be rewritten to match.
    "**Sandbox IPC deserialization**": "_sandbox_codec",
    "**Other subprocess invocations**": "shell=False",
}

#: Resource-demanding surfaces (ASVS 15.1.3). Each entry must appear in a 15.1.3 TABLE ROW.
#: Removing a row from the doc removes its anchor and reds this test.
_RESOURCE_ANCHORS: tuple[str, ...] = (
    # data plane
    "enforce_size_limits",
    "validation.strict",
    "MAX_ESCAPE_REPEAT",
    "split_batch",
    "X12",
    "C-STORE",
    "huge_tree",
    "MLLP listener",
    "HTTP inbound listener",
    "max_file_bytes",
    "RemoteFile",
    "stream_inflight_budget_bytes",
    "Router / Handler execution",
    # The directory-auth path: bare to_thread, OUTSIDE the argon2 semaphore, on the same default
    # executor as Router/Handler work — so its only bound is the finite ldap3 timeout pair.
    "ad_connect_timeout",
    # The monitoring roll-ups: unbounded COUNT(*) scans on a read permission, polled by the console.
    # Anchored on the store methods, not "/status" — that is a substring of /status/integrity-check.
    "db_status",
    "in_pipeline_depth",
    "poll_statement",
    "attachments/{id}",
    "/replay",
    "db_lookup",
    "fhir_lookup",
    "retry forever",
    "queue_buildup",
    "claim_limit",
    "max_db_mb",
    "verify_audit_chain",
    "forward_",
    # control plane
    "/messages/export",
    "/messages/search",
    "/search/layered",
    "/uploads",
    "/audit/export",
    "/logs/tail",
    "/graph/edges",
    "/status/integrity-check",
    "/ai/chat",
    "/config/reload",
    "argon2",
    "/ws/stats",
    # The message-MULTIPLICATION family: one admitted external message minting N further independent
    # ingress messages. #290 consumes this section as its identification precondition, so designing
    # ingest ceilings blind to the only path that already has a partial cap was the worst gap here.
    "max_correlation_depth",
    "pass-through",
    "capture_response",
    "/ui/uploaded-logs/upload",
)

#: Registered SOURCE connectors that need no 15.1.3 row of their own, each with the written reason.
#: Everything else must be named in a data-plane row, so a twelfth source family cannot land with no
#: resource-demand statement (the completeness axis this cell is scored on).
_RESOURCE_SOURCE_EXEMPTIONS: dict[str, str] = {
    "timer": "clock-driven (ADR 0011): the body and interval are operator-configured, so no "
    "attacker-influenceable input drives the consumption",
    "database": "covered by the **Database poll source** row",
    "remotefile": "covered by the **RemoteFile source** row",
    "file": "covered by the **File source** row",
    "http": "covered by the **HTTP inbound listener** row",
    "tcp": "covered by the **Raw TCP / X12 listener** row",
    "x12": "covered by the **X12 interchange split** and **Raw TCP / X12 listener** rows",
    "mllp": "covered by the **MLLP listener** row",
    "dimse": "covered by the **DICOM C-STORE SCP** row",
    "loopback": "covered by the **Internal re-ingress amplification** row",
    "passthrough": "covered by the **Internal re-ingress amplification** row",
}

#: The availability-strategy vocabulary ASVS 15.1.3 explicitly asks for, plus the honest-gap wording.
_STRATEGY_ANCHORS: tuple[str, ...] = (
    "ACK-on-receipt",
    "queue",
    "Retry-After",
    "per-node",
    "Per-lane isolation",
    "15.2.2",
)

#: Dangerous/sensitive functionality (ASVS 15.1.5). Each must appear in the 15.1.5 section slice.
_DANGEROUS_ANCHORS: tuple[str, ...] = (
    "_exec_module",
    "_assert_safe_config_source",
    "db_lookup",
    "fhir_lookup",
    "JWKS",
    # The two controls that stop the classic attacks on the identity-assertion hop: a closed alg
    # allowlist (alg:none, RS256->HS256 confusion) and exact issuer pinning. The row listed byte
    # caps and key floors while naming neither.
    "oidc_signing_algorithms",
    "pickle",
    "dr_backup",
    "/uploads",
    "takeover_hook",
    "ShellExecute",
    "_is_safe_service_name",
    "shell=False",
    "transports/file.py",
    "edit-resend",
    "connections/{name}/purge",
    "relaunch_branded",
    "ai_broker",
    "DDL",
    "sandbox",
    # The loader-execution-triggers row was the ONE 15.1.5 row carrying no anchor and no
    # _DANGEROUS_ROW_KEYS entry, so deleting it whole was undetectable — a direct violation of the
    # rule this module states about itself ("deleting ANY row must red CI"). ConfigReloadDenied is
    # unique to that row; `config_reload_roots` is not (it also occurs in the loader row).
    "ConfigReloadDenied",
    # Rows added because the inventory omitted two operator-facing dangerous capabilities.
    "logging/level",
    "ad-group-map",
)

#: Browser-console controls the boundary-4 slice must name (the retired-PySide6 regression lock).
_BOUNDARY4_ANCHORS: tuple[str, ...] = (
    "serve_ui",
    "__Host-",
    "mf_session",
    "Content-Security-Policy",
    "SameSite=Strict",
    "Origin",
)

#: Wording that described the RETIRED PySide6 desktop console. It must never reappear.
_RETIRED_CONSOLE_STRINGS: tuple[str, ...] = ("OS keyring", "worker thread")

#: The ONLY modules under messagefoundry/ permitted to reach a shell or an elevation verb. Both are
#: documented rows in the 15.1.5 table; ``checks.py`` is listed because it merely names ``os.system``
#: as a lint trigger STRING (asserted separately below), not because it executes one.
_SHELL_TOKENS: tuple[str, ...] = (
    "create_subprocess_shell",
    "shell=True",
    "os.system",
    "ShellExecute",
)
_ALLOWED_SHELL_SITES: dict[str, str] = {
    "pipeline/dr.py": "[dr].takeover_hook / release_hook run via create_subprocess_shell",
    "service.py": "elevated cmd.exe / powershell.exe via ShellExecuteW|ExW 'runas'",
    "checks.py": "names 'os.system' only as a lint-trigger string literal",
}


# --- helpers ------------------------------------------------------------------------------------


class ThreatModelDocUnenforced(UserWarning):
    """The threat model is absent from this checkout, so the doc-CONTENT assertions are inert.

    A warning rather than a skip reason because a skip is invisible: it prints as one ``s`` among
    thousands, and the run still reads as clean. This lands in pytest's warnings summary, which is
    printed even under ``-q``.
    """


#: Announce once per session, not once per inert test — 80-odd identical entries in the warnings
#: summary would be its own kind of unreadable.
_ANNOUNCED = False


def _announce_absence(path: Path) -> None:
    global _ANNOUNCED
    if _ANNOUNCED:
        return
    _ANNOUNCED = True
    warnings.warn(
        ThreatModelDocUnenforced(
            f"{path} is absent from this checkout (docs/security/** is withheld from public "
            "checkouts — deny-listed and vaulted), so EVERY doc-content assertion in "
            "tests/test_threat_model_doc_drift.py is INERT in this run: the heading/table structure, "
            "the 15.1.3 and 15.1.5 anchor registries, the planted-omission self-tests over the real "
            "document, the setting-name resolution, the doc side of the numeric parity loop, and the "
            "absence-claim tripwire. ASVS 15.1.3 and 15.1.5 are scored on that document, so on this "
            "tree they have no drift enforcement at all. Still enforced here: the checker self-tests, "
            "the subprocess-site inventory, the shell-execution-site invariant, the registered-source "
            "coverage decision, and every live-constant lock. Set "
            f"{_DOC_ENV}=<path to the document> to enforce the content half from this checkout, or "
            f"{_REQUIRE_ENV}=1 to make its absence a hard failure."
        ),
        stacklevel=3,
    )


def _doc_text() -> str:
    """The threat-model text, or an ANNOUNCED per-test skip where the document is not published.

    ``docs/security/**`` is deny-listed from the OSS mirror (and vaulted after the cutover), so this
    document is absent there and every assertion about its CONTENT has nothing to say. Two decisions:

    * **The skip is here, at the single accessor, not at module level.** A module-level skip would
      take the code-only tests down with the doc-anchored ones, including the only inventory of
      process-spawn sites and the only exact-value lock on the shipped security defaults. Those
      assert about CODE and are just as valid on the public repo. It also keeps the code half of a
      MIXED test enforced: ``test_subprocess_sites_are_exactly_the_documented_set`` asserts
      ``live == known`` over the package and only THEN reads the doc, so if that assertion fails you
      never reach the skip. Before that, it failed outright on the mirror and the process-spawn
      inventory guarded nothing there — a list-form ``subprocess.Popen`` could ship unnoticed, which
      is the exact defect its docstring records having already happened once.
    * **The skip announces itself** (#1043). Silence here was a green that meant nothing.
    """
    path = _doc_path()
    if not path.exists():
        if os.environ.get(_REQUIRE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
            pytest.fail(
                f"{_REQUIRE_ENV} is set, so this run is expected to enforce the threat model's "
                f"content — but {path} does not exist. Point {_DOC_ENV} at the document, or unset "
                f"{_REQUIRE_ENV} to run in the announced, non-enforcing posture."
            )
        _announce_absence(path)
        pytest.skip(
            f"{path} is absent — the doc-content half is NOT enforced in this run; see the "
            "ThreatModelDocUnenforced entry in the warnings summary for what that costs"
        )
    return path.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    """The slice from ``heading`` up to the next same-or-higher-level heading (exclusive)."""
    start = text.find(heading)
    assert start != -1, f"THREAT-MODEL.md is missing the required heading: {heading!r}"
    level = heading.split(" ", 1)[0]  # '##' or '###'
    rest = text[start + len(heading) :]
    end = len(rest)
    for candidate in (f"\n{'#' * n} " for n in range(2, len(level) + 1)):
        found = rest.find(candidate)
        if found != -1:
            end = min(end, found)
    return heading + rest[:end]


def _missing(section_text: str, anchors: tuple[str, ...]) -> list[str]:
    """Anchors absent from ``section_text`` — the checker the self-test proves can fail."""
    return [a for a in anchors if a not in section_text]


def _table_rows(section_text: str) -> list[str]:
    """Every markdown TABLE ROW of a section — header and separator rows excluded.

    Scoping to rows is load-bearing, not tidiness. The anchors used to be searched against the whole
    section slice, which includes the closing prose and blockquotes: ``fhir_lookup`` recurs three
    times in the 15.1.5 closing note, and ``db_lookup`` / ``enforce_size_limits`` likewise — so
    deleting the actual TABLE ROW, which is the omission these cells score, left every guard green.
    """
    rows: list[str] = []
    for raw in section_text.splitlines():
        line = raw.strip()
        if not (line.startswith("|") and line.endswith("|") and len(line) > 1):
            continue
        cells = [c.strip() for c in line[1:-1].split("|")]
        if not cells or all(c and set(c) <= set("-: ") for c in cells):
            continue
        if cells[0] in {"Surface", "Functionality"}:  # header row
            continue
        rows.append(line)
    return rows


def _missing_in_rows(section_text: str, anchors: tuple[str, ...]) -> list[str]:
    """Anchors absent from the section's TABLE ROWS (prose does not count)."""
    return _missing("\n".join(_table_rows(section_text)), anchors)


def _drop_lines_containing(text: str, needle: str) -> str:
    """``text`` with every line containing ``needle`` removed (the planted-omission mutation)."""
    return "\n".join(line for line in text.splitlines() if needle not in line)


def _drop_one_row_containing(text: str, needle: str) -> str:
    """``text`` with the FIRST table row containing ``needle`` removed.

    The realistic regression — one row deleted, surrounding prose untouched. It is what
    ``_drop_lines_containing`` could not model: stripping *every* line carrying the anchor also
    removed the prose mentions that were masking the row's absence, so the old self-test "proved" a
    load-bearingness the real check did not have.
    """
    dropped = False
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not dropped and line.startswith("|") and line.endswith("|") and needle in raw:
            dropped = True
            continue
        out.append(raw)
    assert dropped, f"no table row containing {needle!r} to drop — the fixture moved"
    return "\n".join(out)


def _settings_field_names(section: str) -> frozenset[str] | None:
    from messagefoundry.config.settings import ServiceSettings

    model = getattr(ServiceSettings(), section, None)
    if model is None:
        return None
    return frozenset(type(model).model_fields)


def _key_resolves(section: str, key: str) -> bool:
    """``[section].key`` resolves if ``key`` is a field or the stem of a field family."""
    fields = _settings_field_names(section)
    if fields is None:
        return False
    key = key.strip("_")
    return any(f == key or f.startswith(key + "_") for f in fields)


def _package_py_files() -> list[Path]:
    return sorted(p for p in _PKG.rglob("*.py") if p.is_file())


# --- 1. structure -------------------------------------------------------------------------------


@pytest.mark.parametrize("heading", [_RESOURCE_HEADING, _DANGEROUS_HEADING])
def test_required_section_exists_and_carries_a_table(heading: str) -> None:
    """Both ASVS-scored sections exist verbatim and each is followed by a markdown table."""
    section = _section(_doc_text(), heading)
    assert "|---" in section.replace(" ", ""), (
        f"{heading!r} exists but carries no markdown table — the inventory IS the control"
    )


def _delimiters_only(line: str) -> str:
    r"""Drop ``\|`` so a LITERAL pipe inside a cell is not counted as a column delimiter.

    GFM escapes a literal pipe in a table cell as ``\|``; it renders as ``|`` and does NOT split
    the cell. A raw ``line.count("|")`` cannot tell the two apart, so a CORRECT row that quotes a
    pipe reads as malformed -- which is not hypothetical: the 15.1.5 ``fhir_lookup`` row has to
    name ``,`` ``|`` and ``$`` as FHIR *value* separators (BACKLOG #1243 limb B), and this
    function's own docstring has always said "unescaped" while the code counted raw.
    """
    return line.replace(r"\|", "")


def test_every_markdown_table_row_has_a_consistent_column_count() -> None:
    """A stray unescaped ``|`` inside a cell silently splits the row and hides half a control.

    These tables are the ASVS artifact, so a row that renders wrong is a defect, not cosmetics.
    An ESCAPED ``\\|`` is a literal pipe, not a delimiter -- see ``_delimiters_only``.
    """
    broken: list[str] = []
    header_pipes: int | None = None
    for number, raw in enumerate(_doc_text().splitlines(), start=1):
        line = _delimiters_only(raw.strip())
        if not line.startswith("|"):
            header_pipes = None
            continue
        body = line.replace("|", "").replace(" ", "")
        if body and set(body) <= set("-:"):  # the |---|---| separator row
            continue
        pipes = line.count("|")
        if header_pipes is None:
            header_pipes = pipes
        elif pipes != header_pipes:
            broken.append(f"line {number}: {pipes} cells vs header {header_pipes}: {line[:80]}…")
    assert not broken, f"THREAT-MODEL.md has malformed table row(s): {broken}"


# --- 2. anchor registries + planted-omission self-tests -----------------------------------------


def test_resource_demanding_section_enumerates_every_surface() -> None:
    """Every resource-demanding surface in the curated registry appears in the 15.1.3 section."""
    section = _section(_doc_text(), _RESOURCE_HEADING)
    missing = _missing_in_rows(section, _RESOURCE_ANCHORS)
    assert not missing, (
        "THREAT-MODEL.md 15.1.3 no longer identifies these resource-demanding surfaces "
        f"(ASVS 15.1.3 scores the inventory's completeness): {missing}"
    )


def test_resource_demanding_section_documents_the_availability_strategy() -> None:
    """ASVS 15.1.3 demands the DoS-prevention strategy, not only the identification."""
    section = _section(_doc_text(), _RESOURCE_HEADING)
    missing = _missing(section, _STRATEGY_ANCHORS)
    assert not missing, (
        "THREAT-MODEL.md 15.1.3 no longer documents the availability strategy ASVS 15.1.3 "
        f"explicitly requires (async queueing / consumer timeouts / per-user limits): {missing}"
    )


def test_dangerous_functionality_section_enumerates_every_surface() -> None:
    """Every dangerous/sensitive surface in the curated registry appears in the 15.1.5 section."""
    section = _section(_doc_text(), _DANGEROUS_HEADING)
    missing = _missing_in_rows(section, _DANGEROUS_ANCHORS)
    assert not missing, (
        "THREAT-MODEL.md 15.1.5 no longer inventories these dangerous surfaces "
        f"(omission is exactly what kept this cell Partial): {missing}"
    )


@pytest.mark.parametrize("anchor", _RESOURCE_ANCHORS)
def test_planted_omission_in_the_resource_section_is_detected(anchor: str) -> None:
    """Self-test: delete a row from an in-memory copy → the checker MUST report it.

    Proves the guard can fail, not merely pass — every anchor is load-bearing.
    """
    section = _section(_doc_text(), _RESOURCE_HEADING)
    mutated = _drop_one_row_containing(section, anchor)
    if anchor in _RESOURCE_ROW_KEYS.values():
        # A shared anchor cannot be detected by its bare token; its rows are pinned individually by
        # test_every_resource_row_key_pins_exactly_one_row instead.
        pytest.skip(f"{anchor!r} spans several rows; pinned per-row by _RESOURCE_ROW_KEYS")
    assert anchor in _missing_in_rows(mutated, _RESOURCE_ANCHORS), (
        f"the 15.1.3 anchor check does NOT detect the removal of {anchor!r} — the guard is asleep"
    )


@pytest.mark.parametrize("anchor", _DANGEROUS_ANCHORS)
def test_planted_omission_in_the_dangerous_section_is_detected(anchor: str) -> None:
    """Self-test: delete a row from an in-memory copy → the checker MUST report it."""
    section = _section(_doc_text(), _DANGEROUS_HEADING)
    mutated = _drop_one_row_containing(section, anchor)
    if anchor in _DANGEROUS_ROW_KEYS.values():
        pytest.skip(f"{anchor!r} spans several rows; pinned per-row by _DANGEROUS_ROW_KEYS")
    assert anchor in _missing_in_rows(mutated, _DANGEROUS_ANCHORS), (
        f"the 15.1.5 anchor check does NOT detect the removal of {anchor!r} — the guard is asleep"
    )


# --- 3. retired-console regression lock ----------------------------------------------------------


@pytest.mark.parametrize("phrase", _RETIRED_CONSOLE_STRINGS)
def test_retired_pyside6_console_wording_never_reappears(phrase: str) -> None:
    """The boundary-4 inventory described the RETIRED desktop console (BACKLOG #103, ADR 0032).

    ``Auth token stored in the OS keyring; GUI never on a worker thread`` is false of the shipped
    browser console; if it comes back, the interface inventory is wrong again.
    """
    assert phrase not in _doc_text(), (
        f"THREAT-MODEL.md reintroduced retired PySide6-console wording {phrase!r} — the shipped "
        "operator console is the browser web console served at /ui (ADR 0065)"
    )


def test_boundary_four_documents_the_browser_console_controls() -> None:
    """The boundary-4 slice must name the controls that actually bound the shipped console."""
    section = _section(_doc_text(), _BOUNDARY4_HEADING)
    missing = _missing(section, _BOUNDARY4_ANCHORS)
    assert not missing, f"THREAT-MODEL.md boundary 4 no longer names: {missing}"


def test_planted_omission_in_boundary_four_is_detected() -> None:
    """Self-test for the boundary-4 checker."""
    section = _section(_doc_text(), _BOUNDARY4_HEADING)
    mutated = _drop_lines_containing(section, "__Host-")
    assert "__Host-" in _missing(mutated, _BOUNDARY4_ANCHORS)


# --- 4. setting-name resolution ------------------------------------------------------------------


#: Settings the document names to record that they were **REMOVED**, rather than citing as live
#: configuration. A threat model that cannot name a removed control cannot explain why the control
#: is gone, and deleting the mention to satisfy the resolution check below would erase exactly the
#: sentence a reader needs -- reintroducing the "asserts a broader control than ships" defect the
#: removal was written to fix.
#:
#: Each entry names the change that removed it. ``test_removed_setting_allowlist_is_not_stale``
#: refuses an entry whose setting resolves again, so this cannot quietly become a place to park a
#: typo, nor outlive its reason if the setting ever comes back.
_REMOVED_SETTINGS: dict[tuple[str, str], str] = {
    ("egress", "fhir_require_structured_params"): (
        "BACKLOG #1243 limb A removed it together with the verbatim flat '?'-query FHIR search "
        "path it gated; the 15.1.5 fhir_lookup row names it to record that removal"
    ),
}


def test_doc_toml_tokens_resolve_to_settings_fields() -> None:
    """Every ``[section].key`` the threat model cites maps to a real ServiceSettings field.

    Except those it names to record a REMOVAL -- see ``_REMOVED_SETTINGS``.
    """
    tokens = sorted(set(_TOML_TOKEN_RE.findall(_doc_text())))
    assert tokens, "no [section].key tokens found — regex or doc changed unexpectedly"
    unresolved = sorted(
        f"[{sec}].{key}"
        for sec, key in tokens
        if not _key_resolves(sec, key) and (sec, key) not in _REMOVED_SETTINGS
    )
    assert not unresolved, (
        f"THREAT-MODEL.md cites [section].key setting(s) with no matching field: {unresolved}"
    )


def test_removed_setting_allowlist_is_not_stale() -> None:
    """Anti-rot: an entry in ``_REMOVED_SETTINGS`` whose setting RESOLVES again is a hole.

    An exemption that outlives its reason silently excuses a live setting from the resolution
    check above, which is the same shape of defect as a gate that has stopped asserting.
    """
    resurrected = sorted(
        f"[{sec}].{key}" for (sec, key) in _REMOVED_SETTINGS if _key_resolves(sec, key)
    )
    assert not resurrected, (
        f"_REMOVED_SETTINGS exempts setting(s) that resolve again: {resurrected} — the setting is "
        "live, so drop the exemption and let the resolution check cover it"
    )


# --- 5. numeric parity against the live code ------------------------------------------------------


def _checks() -> list[tuple[str, object, object]]:
    """The ``(label, live value, transcribed bound)`` rows that BOTH bound tests read.

    At module scope so the two assertions share one table. Two copies of a 64-row transcription
    would drift apart, which is precisely the defect class this module exists to catch.
    """
    from messagefoundry.api import app as api_app
    from messagefoundry.auth import oidc_http
    from messagefoundry.auth.oidc import flow as oidc_flow
    from messagefoundry.auth.oidc import jwks
    from messagefoundry.auth.service import _ARGON2_MAX_CONCURRENCY
    from messagefoundry.config.models import (
        AckAfter,
        BuildupThreshold,
        RetryPolicy,
        SaturationThreshold,
        StallThreshold,
    )
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.parsing import _builtin_hl7, peek
    from messagefoundry.parsing.x12.delimiters import DEFAULT_MAX_INTERCHANGE_BYTES
    from messagefoundry.pipeline import sandbox, wiring_runner
    from messagefoundry.store import content_search
    from messagefoundry.transports import dicom, http_listener, mllp
    from messagefoundry.transports import file as file_transport

    s = ServiceSettings()
    mib = 1024 * 1024

    return [
        # --- 15.1.3 data plane ---
        ("15.1.3 HL7 parse cap = 16 MiB", peek.DEFAULT_MAX_MESSAGE_BYTES, 16 * mib),
        ("15.1.3 HL7 segment cap = 10,000", peek.DEFAULT_MAX_SEGMENTS, 10_000),
        ("15.1.3 escape repeat clamp = 512", _builtin_hl7.MAX_ESCAPE_REPEAT, 512),
        (
            "15.1.3 strict-validate backstop = 5.0 s",
            wiring_runner._STRICT_VALIDATE_TIMEOUT_SECONDS,
            5.0,
        ),
        ("15.1.3 non-HL7 ingress ceiling = 16 MiB", wiring_runner._INGRESS_MAX_BYTES, 16 * mib),
        ("15.1.3 X12 interchange cap = 16 MiB", DEFAULT_MAX_INTERCHANGE_BYTES, 16 * mib),
        ("15.1.3 DICOM object cap = 128 MiB", dicom.DEFAULT_MAX_OBJECT_BYTES, 128 * mib),
        ("15.1.3 MLLP frame cap = 16 MiB", mllp.DEFAULT_MAX_FRAME_BYTES, 16 * mib),
        ("15.1.3 MLLP connection cap = 256", mllp.DEFAULT_MAX_CONNECTIONS, 256),
        ("15.1.3 MLLP receive timeout = 60.0 s", mllp.DEFAULT_RECEIVE_TIMEOUT, 60.0),
        ("15.1.3 HTTP body cap = 16 MiB", http_listener.DEFAULT_MAX_BODY_BYTES, 16 * mib),
        ("15.1.3 HTTP header cap = 64 KiB", http_listener.DEFAULT_MAX_HEADER_BYTES, 64 * 1024),
        ("15.1.3 file-source cap = 16 MiB", file_transport.DEFAULT_MAX_FILE_BYTES, 16 * mib),
        (
            "15.1.3 streaming-detach budget default 0 = unlimited",
            s.inbound.stream_inflight_budget_bytes,
            0,
        ),
        ("15.1.3 ACK-on-receipt is the default", s.inbound.ack_after, AckAfter.INGEST),
        # BACKLOG #1278 flipped this from "off". The old label read "no Router/Handler wall cap",
        # which is now BACKWARDS: at mode=off `run_sandboxed` is literally `fn(payload)` with no
        # timeout at all, and it is the SUBPROCESS default that arms wall_seconds below. So the
        # shipped posture GAINED a cap it did not have. This is a COUPLED edit -- the 15.1.3 row in
        # `docs/security/THREAT-MODEL.md` (vault-only, absent from every checkout, so the
        # doc-CONTENT half of this module is inert here and in CI) must be rewritten to say the wall
        # cap is enforced on the default rather than off it.
        (
            "15.1.3 sandbox default = subprocess (Router/Handler wall cap ARMED)",
            s.sandbox.mode,
            "subprocess",
        ),
        ("15.1.3 sandbox wall cap = 5.0 s", s.sandbox.wall_seconds, 5.0),
        ("15.1.3 sandbox cpu cap = 2.0 s (POSIX)", s.sandbox.cpu_seconds, 2.0),
        ("15.1.3 sandbox mem cap = 512 MiB (POSIX)", s.sandbox.mem_mb, 512),
        ("15.1.3 live-lookup bridge = 30.0 s", wiring_runner._LOOKUP_RESULT_TIMEOUT_SECONDS, 30.0),
        # BACKLOG #1051 flipped this from None (retry forever) to a finite 100. This is a COUPLED
        # edit — `docs/security/THREAT-MODEL.md` lives in the vault (gitignored, absent from every
        # checkout, so the doc-CONTENT half of this module is inert here and in CI) and its 15.1.3
        # row must be rewritten to state the finite cap. The `retry forever` entry in
        # _RESOURCE_ANCHORS above is deliberately left alone: it names a token that must appear in
        # the vault document, and re-picking it blind from a checkout that cannot read that
        # document would trade a stale row for an unverifiable anchor.
        ("15.1.3 outbound retry cap = 100 attempts by default", RetryPolicy().max_attempts, 100),
        ("15.1.3 retry backoff = 5.0 s", RetryPolicy().backoff_seconds, 5.0),
        ("15.1.3 retry backoff cap = 300.0 s", RetryPolicy().max_backoff_seconds, 300.0),
        ("15.1.3 queue_buildup depth dimension OFF", BuildupThreshold().max_depth, None),
        ("15.1.3 queue_buildup age = 300.0 s", BuildupThreshold().max_oldest_seconds, 300.0),
        ("15.1.3 message_stall OFF by default", StallThreshold().max_oldest_seconds, None),
        ("15.1.3 saturation OFF by default", SaturationThreshold().sustain_samples, None),
        ("15.1.3 fifo_claim_batch = 1 (off)", s.store.fifo_claim_batch, 1),
        ("15.1.3 [retention].max_db_mb = 0 (advisory, off)", s.retention.max_db_mb, 0),
        ("15.1.3 retention purge interval = 3600.0 s", s.retention.purge_interval_seconds, 3600.0),
        ("15.1.3 retention max_pass_seconds = 0.0 (uncapped)", s.retention.max_pass_seconds, 0.0),
        # --- 15.1.3 control plane ---
        ("15.1.3 global request-body cap = 1 MiB", api_app._MAX_REQUEST_BODY_BYTES, mib),
        ("15.1.3 content-search scan default = 2,000", content_search.DEFAULT_SCAN_LIMIT, 2_000),
        ("15.1.3 content-search scan max = 10,000", content_search.MAX_SCAN_LIMIT, 10_000),
        ("15.1.3 upload cap = 25 MiB", s.store.max_upload_bytes, 25 * mib),
        ("15.1.3 preset-layer cap = 8", api_app._MAX_PRESET_LAYERS, 8),
        ("15.1.3 concurrent /ws/stats cap = 64", api_app._MAX_WS_CONNECTIONS, 64),
        ("15.1.3 /ws/stats revalidation = 3.0 s", api_app._WS_REVALIDATE_SECONDS, 3.0),
        ("15.1.3 connection-test probe = 35.0 s", api_app._CONNECTION_TEST_TIMEOUT, 35.0),
        (
            "15.1.3 argon2 concurrency clamp",
            _ARGON2_MAX_CONCURRENCY,
            max(2, min(8, os.cpu_count() or 2)),
        ),
        ("15.1.3 login limiter default ON", s.auth.login_rate_limit_enabled, True),
        ("15.1.3 login per-IP budget = 10", s.auth.login_rate_limit_per_ip, 10),
        ("15.1.3 login global budget = 60", s.auth.login_rate_limit_global, 60),
        ("15.1.3 login window = 60.0 s", s.auth.login_rate_limit_window_seconds, 60.0),
        ("15.1.3 PHI-read limiter default ON", s.auth.phi_read_rate_limit_enabled, True),
        ("15.1.3 PHI-read per-actor budget = 120", s.auth.phi_read_rate_limit_per_actor, 120),
        ("15.1.3 PHI-read window = 60.0 s", s.auth.phi_read_rate_limit_window_seconds, 60.0),
        ("15.1.3 PHI-read global budget = 0 (off)", s.auth.phi_read_rate_limit_global, 0),
        ("15.1.3 admin-write limiter default ON", s.auth.admin_write_rate_limit_enabled, True),
        ("15.1.3 admin-write per-actor budget = 12", s.auth.admin_write_rate_limit_per_actor, 12),
        ("15.1.3 admin-write window = 1.0 s", s.auth.admin_write_rate_limit_window_seconds, 1.0),
        (
            "15.1.3 admin-write limiter is per-actor ONLY (no global arm)",
            "admin_write_rate_limit_global" in type(s.auth).model_fields,
            False,
        ),
        # --- 15.1.5 ---
        ("15.1.5 sandbox pickle frame ceiling = 64 MiB", sandbox._MAX_FRAME, 64 * mib),
        ("15.1.5 OIDC round trip = 10.0 s", oidc_http.DEFAULT_IDP_TIMEOUT_SECONDS, 10.0),
        (
            "15.1.5 OIDC token response bound = 256 KiB",
            oidc_flow._MAX_TOKEN_RESPONSE_BYTES,
            256 * 1024,
        ),
        ("15.1.5 JWKS body bound = 512 KiB", jwks._MAX_JWKS_BYTES, 512 * 1024),
        ("15.1.5 JWKS TTL = 3600.0 s", jwks.DEFAULT_JWKS_TTL_SECONDS, 3600.0),
        ("15.1.5 JWKS min-refetch floor = 300.0 s", jwks.DEFAULT_JWKS_MIN_REFETCH_SECONDS, 300.0),
        ("15.1.5 JWKS RSA floor = 2048 bits", jwks._MIN_RSA_BITS, 2048),
        ("15.1.5 OIDC pending-flow TTL = 300 s", s.auth.oidc_flow_ttl_seconds, 300),
        ("15.1.5 OIDC pending-flow cap = 512 (reject-when-full)", s.auth.oidc_flow_cache_max, 512),
        ("15.1.5 DR hook timeout = 30.0 s", s.dr.takeover_timeout_seconds, 30.0),
        ("15.1.5 web console served by default", s.api.serve_ui, True),
        (
            "15.1.5 [egress].deny_by_default is OFF in the shipped default",
            s.egress.deny_by_default,
            False,
        ),
        # BACKLOG #1243 removed `[egress].fhir_require_structured_params` along with the flat
        # '?'-query it gated, so its row is gone from here. This is a COUPLED edit —
        # `docs/security/THREAT-MODEL.md` lives in the vault (gitignored, absent from every checkout,
        # so these tests cannot enforce it here or in CI) and its 15.1.5 sentence at :256 must be
        # rewritten to match: the structured `params=` form is now the ONLY search form, and the
        # rewrite must also say what percent-encoding does NOT cover — it defeats structure injection,
        # not FHIR value-layer injection (',' '|' '$' survive percent-decoding as separators, #1243
        # limb B). Without that clause the threat model asserts a broader control than ships.
    ]


def test_transcribed_bounds_match_the_live_constants() -> None:
    """Every bound TRANSCRIBED IN THIS FILE is asserted against the live value by import.

    RENAMED FROM ``test_documented_bounds_match_the_live_constants`` (BACKLOG #1214). "documented"
    promised the DOCUMENT, and this assertion never opens it. The failure text was corrected first;
    the NAME outlived it, and a name is what a reader sees in a CI failure list before any message.
    A check named for its subject rather than its assertion is SDS-3.8 in one identifier.

    REWORDED IN SUBSTANCE, NOT COSMETICALLY (BACKLOG #1214). This reported a mismatch as
    ``doc says {expected}``, which was false of all 64 of its rows: ``expected`` is a literal in
    this file and nothing binds it to the document. The comparison is real and worth keeping --
    it catches the CODE drifting from the transcription -- but it is structurally incapable of
    catching the TRANSCRIPTION drifting from the document, so it must not say otherwise. A gate
    whose failure text names an artefact it never opened sends every reader to the wrong file.
    """
    drifted = [
        f"{label}: this file transcribes {expected!r}, code says {actual!r}"
        for label, actual, expected in _checks()
        if actual != expected
    ]
    assert not drifted, (
        "A live constant no longer matches the bound transcribed here. This assertion does NOT "
        "open THREAT-MODEL.md, so fix the row AND re-check the document by hand in the SAME "
        f"change: {drifted}"
    )


def test_each_label_states_the_bound_its_row_transcribes() -> None:
    """A row's label and its literal must agree -- the link BACKLOG #1214 found missing.

    The chain this module needs is ``document -> label -> literal -> live constant``. Only the
    last link was ever asserted, so a literal could be updated to match a code change while the
    label beside it -- the half a reader actually reads -- went on stating the old bound, with
    nothing failing. This runs everywhere and needs no document, because both sides are here.
    """
    disagreed: list[str] = []
    for label, _actual, expected in _checks():
        stated = _bounds_from_label(label)
        if stated is None or isinstance(expected, bool) or not isinstance(expected, (int, float)):
            continue
        if float(expected) not in stated:
            disagreed.append(f"{label}: label states {stated!r}, row transcribes {expected!r}")
    assert not disagreed, (
        "A row's label and its transcribed literal state DIFFERENT bounds, so the two halves of "
        f"one row disagree about what the document says: {disagreed}"
    )


def test_the_label_check_states_the_rows_it_cannot_see() -> None:
    """A partial check that does not state its own scope reads as a total one.

    Rows stating a posture in words -- "= unlimited", "ACK-on-receipt is the default" -- have no
    numeric form, so the label check cannot see them. The floors below are the guard on that: if
    a future edit made most labels unparseable, the check above would go quietly vacuous and
    still pass, which is this module's own defect class one level up.
    """
    rows = _checks()
    covered = [label for label, _a, _e in rows if _bounds_from_label(label) is not None]
    assert len(rows) >= 60, f"the transcription table shrank unexpectedly: {len(rows)} rows"
    assert len(covered) >= 45, (
        f"only {len(covered)} of {len(rows)} labels carry a machine-checkable bound, so the "
        "label check has gone largely vacuous"
    )


def test_hl7_batch_split_is_still_unbounded_in_message_count() -> None:
    """The 15.1.3 row states ``split_batch`` has NO cap on the message count.

    A behavioural assertion, so the honest "unbounded" wording cannot silently become false: if a
    count bound is later added (the data-plane-bounds work), this fails and the row must be rewritten
    to state the new bound.
    """
    from messagefoundry.parsing.split import split_batch

    count = 2_000
    batch = "\r".join(f"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|{i}|P|2.5" for i in range(count))
    assert len(split_batch(batch)) == count, (
        "split_batch no longer returns every MSH-led message — THREAT-MODEL.md 15.1.3 states the "
        "batch-split message count is UNBOUNDED; update the row if a cap landed"
    )


# --- 6. shell-execution-site invariant -----------------------------------------------------------


def test_shell_execution_sites_are_exactly_the_documented_set() -> None:
    """Locks the corrected 15.1.5 claim: shell/elevation execution lives ONLY where documented.

    The table previously asserted "list-form argv, **never** ``shell=True``" as a universal, which was
    false — ``[dr]``'s hooks run through ``create_subprocess_shell`` and Windows service control
    launches an elevated ``cmd.exe``/``powershell.exe``. The doc now names both as deliberate
    exceptions with their own guards; a NEW shell site anywhere else must add a row.
    """
    found: set[str] = set()
    for path in _package_py_files():
        text = path.read_text(encoding="utf-8")
        if any(token in text for token in _SHELL_TOKENS):
            found.add(path.relative_to(_PKG).as_posix())
    expected = set(_ALLOWED_SHELL_SITES)
    unexpected = sorted(found - expected)
    assert not unexpected, (
        "a new shell-execution / elevation site landed in messagefoundry/ — add a "
        f"'Dangerous functionality' row to THREAT-MODEL.md (ASVS 15.1.5) for: {unexpected}"
    )
    vanished = sorted(expected - found)
    assert not vanished, (
        "a documented shell-execution site disappeared — remove/rewrite its THREAT-MODEL.md "
        f"15.1.5 row in the same change: {vanished}"
    )


def test_checks_py_only_names_os_system_as_a_lint_string() -> None:
    """``checks.py`` matches the shell scan only because it lists ``os.system`` as a lint trigger."""
    text = (_PKG / "checks.py").read_text(encoding="utf-8")
    assert '"os.system"' in text, "checks.py's os.system lint trigger changed shape"
    for token in ("create_subprocess_shell", "shell=True", "ShellExecute"):
        assert token not in text, f"checks.py gained a real shell-execution site: {token}"


# --- per-row pinning: the half a bare-token registry structurally cannot do ----------------------


def _row_first_cells(section_text: str) -> list[str]:
    return [row[1:-1].split("|")[0].strip() for row in _table_rows(section_text)]


@pytest.mark.parametrize(
    ("heading", "keys"),
    [
        (_RESOURCE_HEADING, _RESOURCE_ROW_KEYS),
        (_DANGEROUS_HEADING, _DANGEROUS_ROW_KEYS),
    ],
)
def test_every_shared_anchor_row_is_pinned_individually(heading: str, keys: dict[str, str]) -> None:
    """Rows whose bare anchor is shared with a sibling are pinned by their OWN first cell.

    RULE: deleting ANY row must red CI. ``X12`` appears in both the interchange-split row and the
    raw-TCP listener row; ``sandbox`` appears in five 15.1.5 rows; ``/uploads`` in two. A
    bare-token check cannot see one of them go, so each is keyed on its own label here.
    """
    section = _section(_doc_text(), heading)
    rows = _table_rows(section)
    cells = _row_first_cells(section)
    for label, token in sorted(keys.items()):
        owning = [i for i, cell in enumerate(cells) if label in cell]
        assert len(owning) == 1, (
            f"expected exactly one row whose first cell contains {label!r}; found {len(owning)}. "
            "Each shared-anchor row must be individually identifiable, or its deletion is invisible."
        )
        assert token in rows[owning[0]], f"the {label!r} row no longer carries {token!r}"


@pytest.mark.parametrize(
    ("heading", "keys"),
    [
        (_RESOURCE_HEADING, _RESOURCE_ROW_KEYS),
        (_DANGEROUS_HEADING, _DANGEROUS_ROW_KEYS),
    ],
)
def test_shared_anchor_row_pinning_detects_a_planted_deletion(
    heading: str, keys: dict[str, str]
) -> None:
    """Proves the per-row pinning can fail: delete one shared-anchor row and it must be reported."""
    section = _section(_doc_text(), heading)
    rows = _table_rows(section)
    shared = [lab for lab, tok in sorted(keys.items()) if sum(1 for row in rows if tok in row) > 1]
    assert shared, f"no shared-anchor row left in {heading!r}; the registry is now redundant"
    label = shared[0]
    mutated = _drop_one_row_containing(section, label)
    assert not [c for c in _row_first_cells(mutated) if label in c], (
        f"deleting the {label!r} row was not detected — the per-row pinning is not load-bearing"
    )
    # And the bare-token checker demonstrably does NOT catch it, which is why this exists.
    assert keys[label] not in _missing_in_rows(mutated, tuple(keys.values())), (
        "fixture drifted: this anchor is no longer shared with a sibling row"
    )


# --- 15.1.5: the "complete subprocess inventory" claim, made falsifiable ------------------------

#: Every module under ``messagefoundry/`` that spawns a process, and why the 15.1.5 table admits it.
#: The doc claims this set is COMPLETE; ``tray/branding.py`` shipped undocumented under that claim
#: because the only guard scanned for SHELL tokens, and a list-form ``Popen`` carries none.
_ALLOWED_SUBPROCESS_SITES: dict[str, str] = {
    "checks.py": "advisory ruff/mypy gate, list-form argv, 120 s bound, skipped when absent",
    "pipeline/dr.py": "[dr].takeover_hook / release_hook — the deliberate SHELL exception",
    "pipeline/sandbox.py": "ADR 0087 sandbox worker, fixed argv, close_fds=True",
    "pipeline/supervisor.py": "engine-shard supervisor, fixed argv",
    "service.py": "elevated cmd.exe / powershell.exe — the deliberate ELEVATION exception",
    "service_status.py": "`sc query`, list-form argv, 5 s bound",
    "store/store.py": "`icacls` store-file ACL lockdown, one argv token per grant",
    "auth/trust_anchors.py": "`icacls` trust-anchor ACL VERIFY (read-only DACL check, list-form argv)",
    "tray/actions.py": "tray's VS Code open, list-form argv",
    "tray/branding.py": "tray's branded-launcher relaunch, fixed argv, close_fds=True",
}

#: Every spawn form, not just the two the narrow version matched. The 15.1.5 row above asserts the
#: subprocess inventory is COMPLETE and that "a CI guard asserts that set cannot grow silently" — a
#: claim that was false while ``subprocess.call`` / ``check_call`` / ``check_output``, ``os.popen`` /
#: ``posix_spawn`` / ``exec*``, ``multiprocessing.Process``, ``ProcessPoolExecutor`` and ``pty.spawn``
#: were all invisible to it. (``pipeline/sandbox.py`` lists a bare ``"multiprocessing"`` in its
#: FORBIDDEN-import set, which the ``multiprocessing\.Process`` alternative deliberately does not
#: match; ``checks.py`` carries ``"os.popen"`` as a lint-trigger STRING and is already allow-listed.)
_SUBPROCESS_RE = re.compile(
    r"subprocess\.(?:run|Popen|call|check_call|check_output)"
    r"|create_subprocess_(?:exec|shell)"
    r"|os\.(?:popen|posix_spawn|exec[lv][pe]*|spawn[lv][pe]*)"
    r"|multiprocessing\.Process"
    r"|ProcessPoolExecutor"
    r"|pty\.spawn"
)


def _subprocess_sites() -> set[str]:
    return {
        path.relative_to(_PKG).as_posix()
        for path in sorted(_PKG.rglob("*.py"))
        if _SUBPROCESS_RE.search(path.read_text(encoding="utf-8"))
    }


def test_subprocess_sites_are_exactly_the_documented_set() -> None:
    """The row's completeness claim, made falsifiable.

    RULE: a module that spawns a process is dangerous functionality and needs a 15.1.5 row. The
    pre-existing ``_SHELL_TOKENS`` scan only looked for ``shell=True`` / ``os.system`` /
    ``ShellExecute``, so a **list-form** ``subprocess.Popen`` — which is what
    ``tray/branding.py::relaunch_branded`` is — shipped with the suite green next to a doc sentence
    claiming the inventory was complete.
    """
    live = _subprocess_sites()
    known = set(_ALLOWED_SUBPROCESS_SITES)
    assert live == known, (
        f"the subprocess-site set changed: {sorted(live ^ known)}. Add a Dangerous functionality row "
        "to docs/security/THREAT-MODEL.md (ASVS 15.1.5) and register it here in the same change — "
        "the table states this inventory is COMPLETE."
    )
    section = _section(_doc_text(), _DANGEROUS_HEADING)
    undocumented = sorted(module for module in known if module.split("/")[-1] not in section)
    assert not undocumented, (
        f"subprocess site(s) not named anywhere in the 15.1.5 section: {undocumented}"
    )


# --- 15.1.3: the relative links the sections cite must resolve ---------------------------------

_MD_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)#\s]+\.md)(?:#[^)]*)?\)")


@pytest.mark.parametrize("heading", [_RESOURCE_HEADING, _DANGEROUS_HEADING])
def test_relative_links_in_the_scored_sections_resolve(heading: str) -> None:
    """A tracker cite that points at a closed-out plan is a false statement.

    The honest-gap note claimed the remaining work "is tracked as the **data-plane-bounds** work in
    ASVS-L3-REMEDIATION-PLAN.md" — a string that appears in no file under ``docs/``, in a plan whose
    own header declares "0 open Fails or Partials".
    """
    section = _section(_doc_text(), heading)
    missing = [
        target
        for target in _MD_LINK_RE.findall(section)
        if not (_doc_path().parent / target).resolve().exists()
        and not (_ROOT / "docs" / target).resolve().exists()
    ]
    assert not missing, (
        f"{heading}: relative markdown link(s) whose target does not exist: {missing}"
    )


def test_the_open_gap_is_tracked_against_an_artifact_that_exists() -> None:
    """And the tracker the note names must actually carry the requirement it claims to track."""
    section = _section(_doc_text(), _RESOURCE_HEADING)
    note = section[section.index("**ASVS 15.2.2**") :] if "**ASVS 15.2.2**" in section else ""
    assert note, "the 15.1.3 honest-gap note no longer names ASVS 15.2.2"
    targets = _MD_LINK_RE.findall(note)
    assert targets, "the honest-gap note cites no tracking artifact"
    for target in targets:
        path = (_doc_path().parent / target).resolve()
        assert path.exists(), f"the cited tracker {target} does not exist"
        assert "15.2.2" in path.read_text(encoding="utf-8"), (
            f"{target} does not mention 15.2.2, so it does not track the gap this note assigns to it"
        )


# --- 15.1.3: the DOC side of the numeric loop --------------------------------------------------


#: ``(row-label fragment, live value, the rendered form the row must carry)``.
#:
#: ``test_transcribed_bounds_match_the_live_constants`` compares a live constant to a literal
#: hardcoded in THIS FILE — it never reads the document, so editing THREAT-MODEL.md to say "32 MiB"
#: left the suite green. That is the rot mode that matters for a cell scored on documentation, so
#: this closes the other half: the rendered value must appear in that row's own line.
def _doc_side_bounds() -> list[tuple[str, object, str]]:
    from messagefoundry.auth.service import _ARGON2_MAX_CONCURRENCY
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.parsing import _builtin_hl7, peek
    from messagefoundry.transports import dicom, http_listener, mllp
    from messagefoundry.transports import file as file_transport

    s = ServiceSettings()
    mib = 1024 * 1024
    return [
        ("**HL7 parse**", peek.DEFAULT_MAX_MESSAGE_BYTES // mib, "16 MiB"),
        ("**HL7 parse**", peek.DEFAULT_MAX_SEGMENTS, "10,000"),
        ("**HL7 escape expansion**", _builtin_hl7.MAX_ESCAPE_REPEAT, "512"),
        ("**HL7 escape expansion**", _builtin_hl7.MAX_COUNTED_ESCAPE_OPENERS, "100,000"),
        ("**MLLP listener**", mllp.DEFAULT_MAX_CONNECTIONS, "256"),
        ("**MLLP listener**", int(mllp.DEFAULT_RECEIVE_TIMEOUT), "60"),
        ("**HTTP inbound listener**", http_listener.DEFAULT_MAX_BODY_BYTES // mib, "16 MiB"),
        ("**HTTP inbound listener**", http_listener.DEFAULT_MAX_HEADER_BYTES // 1024, "64 KiB"),
        ("**DICOM C-STORE SCP**", dicom.DEFAULT_MAX_OBJECT_BYTES // mib, "128 MiB"),
        ("**File source**", file_transport.DEFAULT_MAX_FILE_BYTES // mib, "16 MiB"),
        ("**Database poll source**", 5, "5.0"),
        ("**Router / Handler execution**", s.sandbox.wall_seconds, "5.0"),
        ("**Router / Handler execution**", s.sandbox.mem_mb, "512"),
        ("**argon2 verification**", _ARGON2_MAX_CONCURRENCY, "cpu_count"),
        ("**Per-actor PHI reads**", s.auth.phi_read_rate_limit_per_actor, "120"),
        ("**Per-actor admin writes**", s.auth.admin_write_rate_limit_per_actor, "12"),
        ("**`GET /logs/tail`**", 2_000, "2,000"),
        ("**`GET /messages/export`**", 100_000, "100,000"),
        ("**`POST /uploads`**", s.store.max_upload_bytes // mib, "25 MiB"),
        ("**Outbound retry**", 5.0, "5.0"),
        ("**Outbound retry**", 300.0, "300"),
        ("**Queue claim sizing**", 20, "20"),
        ("**Backlog alerting**", 300.0, "300"),
    ]


def _dangerous_doc_side_bounds() -> list[tuple[str, object, str]]:
    """The same closure for the **15.1.5** table, which had none at all.

    Every bound the 15.1.5 rows quote was a doc-side literal nothing read: planting eight lies (RSA
    floor 2048 -> 1024, JWKS 512 KiB -> 512 MiB, the pickle frame 64 MiB -> 6 GiB, the min-refetch
    floor 300 s -> 3 s, the token bound 256 KiB -> 256 MiB, the DR hook 30 s -> 3000 s, the OIDC
    round trip 10 s -> 1000 s, `oidc_flow_cache_max` 512 -> 99999) left the whole suite green. For a
    cell where the document IS the control, that is the rot mode that matters.
    """
    from messagefoundry.auth import oidc_http
    from messagefoundry.auth.oidc import flow as oidc_flow
    from messagefoundry.auth.oidc import jwks
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.pipeline import sandbox

    s = ServiceSettings()
    mib = 1024 * 1024
    return [
        ("**Sandbox IPC deserialization**", sandbox._MAX_FRAME // mib, "64 MiB"),
        (
            "**OIDC token-endpoint POST + JWKS GET**",
            int(oidc_http.DEFAULT_IDP_TIMEOUT_SECONDS),
            "**10 s** per round trip",
        ),
        (
            "**OIDC token-endpoint POST + JWKS GET**",
            oidc_flow._MAX_TOKEN_RESPONSE_BYTES // 1024,
            "256 KiB",
        ),
        ("**OIDC token-endpoint POST + JWKS GET**", jwks._MAX_JWKS_BYTES // 1024, "512 KiB"),
        ("**OIDC token-endpoint POST + JWKS GET**", jwks._MIN_RSA_BITS, "2048"),
        ("**OIDC token-endpoint POST + JWKS GET**", int(jwks.DEFAULT_JWKS_TTL_SECONDS), "3600"),
        # Rendered as the FULL phrase, not the bare number: the row carries two independent 300 s
        # constants and three "512"s, so a bare token let a planted lie be satisfied by its sibling.
        (
            "**OIDC token-endpoint POST + JWKS GET**",
            int(jwks.DEFAULT_JWKS_MIN_REFETCH_SECONDS),
            "min-refetch floor of 300 s",
        ),
        (
            "**OIDC token-endpoint POST + JWKS GET**",
            s.auth.oidc_flow_cache_max,
            "`oidc_flow_cache_max` **512**",
        ),
        (
            "**OIDC token-endpoint POST + JWKS GET**",
            int(s.auth.oidc_flow_ttl_seconds),
            "`[auth].oidc_flow_ttl_seconds` **300 s**",
        ),
        ("**Operator-configured SHELL execution**", s.dr.takeover_timeout_seconds, "30.0 s"),
        ("**HTTP uploads**", s.store.max_upload_bytes // mib, "25 MiB"),
    ]


@pytest.mark.parametrize(
    ("heading", "which"),
    [
        (_RESOURCE_HEADING, "15.1.3"),
        (_DANGEROUS_HEADING, "15.1.5"),
    ],
)
def test_every_quoted_bound_appears_in_its_own_doc_row(heading: str, which: str) -> None:
    """Closes the doc side of the numeric loop, for BOTH scored sections.

    RULE: the value must be stated **in the row that names the surface** — a stray "16 MiB"
    elsewhere in the section cannot satisfy it, and editing the row to a different number reds CI.
    """
    bounds = _doc_side_bounds() if which == "15.1.3" else _dangerous_doc_side_bounds()
    section = _section(_doc_text(), heading)
    rows = _table_rows(section)
    problems: list[str] = []
    for label, _live, rendered in bounds:
        owning = [row for row in rows if label in row.split("|")[1]]
        if len(owning) != 1:
            problems.append(f"{label!r}: {len(owning)} rows carry this label, expected exactly 1")
            continue
        if rendered not in owning[0]:
            problems.append(f"{label!r} row does not state {rendered!r}")
    assert not problems, (
        f"docs/security/THREAT-MODEL.md's {which} rows disagree with the values this guard pins: "
        f"{problems}. A doc-side edit is the rot mode that matters for a cell scored on the "
        "documentation, and the code-side check alone cannot see it."
    )


#: Each entry: (import path, dotted symbol, what it implements, phrases the doc must NOT contain).
#: Every guard above pins a value that IS rendered, so all of them are structurally blind to a
#: sentence asserting a bound's ABSENCE. That is not hypothetical: the HL7 escape-expansion row
#: asserted "There is no aggregate per-message budget" for the entire life of
#: ``peek.enforce_expansion_budget``, and re-inserting that exact sentence left all 81 tests green
#: (verified 2026-07-28). Because ASVS 15.1.3 scores the DOCUMENT, the stale sentence was itself the
#: control defect — a false claim about the most attacker-exposed bound in the product.
_ABSENCE_CLAIMS: list[tuple[str, str, str, tuple[str, ...]]] = [
    (
        "messagefoundry.parsing.peek",
        "enforce_expansion_budget",
        "aggregate HL7 escape-expansion budget (ASVS 1.3.3)",
        (
            "no aggregate per-message budget",
            "there is no aggregate",
            "has no aggregate",
        ),
    ),
]


def test_the_document_does_not_deny_a_bound_the_code_implements() -> None:
    """A shipped bound must not be described as absent.

    The symbol's existence is ASSERTED, not merely probed, and that is deliberate. If the guard
    skipped when the symbol went missing, deleting the control would silently disable the only test
    that notices — the guard would pass hardest exactly when the bound disappeared. Asserting instead
    means removing the budget reds this test and forces the author to say so in the document, which is
    the outcome the requirement wants either way.

    Scope honesty: this catches a fixed phrase list, not paraphrase. It is a tripwire for the specific
    claims we have already seen rot, not a proof that the document contains no false negative claim.
    """
    import importlib

    text = _doc_text().lower()
    scanned: list[str] = []
    problems: list[str] = []
    for module_path, symbol, description in ((c[0], c[1], c[2]) for c in _ABSENCE_CLAIMS):
        module = importlib.import_module(module_path)
        assert hasattr(module, symbol), (
            f"{module_path}.{symbol} is gone — it implements {description}. If the bound was removed "
            "on purpose, update docs/security/THREAT-MODEL.md to say so and retire this entry; do not "
            "delete the assertion and leave the document claiming a control that no longer exists."
        )
        scanned.append(f"{module_path}.{symbol}")
    for _module_path, symbol, description, phrases in _ABSENCE_CLAIMS:
        for phrase in phrases:
            if phrase.lower() in text:
                problems.append(f"{phrase!r} contradicts the shipped {description} ({symbol})")
    # Liveness receipt: name what was examined, so a future reader can tell an empty scan from a
    # clean one. A guard that reports "nothing found" without saying what it looked at is the
    # failure mode this file exists to prevent.
    assert scanned, "the absence-claim table is empty — this guard examined nothing"
    assert not problems, (
        f"docs/security/THREAT-MODEL.md denies a bound the code implements: {problems}. Examined "
        f"{len(scanned)} shipped control(s): {scanned}. ASVS 15.1.3 scores this document, so a stale "
        "claim that a control is missing is a control defect, not a typo."
    )


def test_every_registered_source_connector_is_covered_or_explicitly_exempt() -> None:
    """Code-derived completeness for the data plane, the half the anchor list cannot supply.

    ``_RESOURCE_ANCHORS`` is a curated string list: it can only pin rows that already exist. A NEW
    inbound connector family — the shape that adds a fresh attacker-influenceable input — would ship
    with no row and green CI. Importing ``messagefoundry.transports`` runs every ``register_source``,
    so the registry is the live truth.
    """
    import messagefoundry.transports  # noqa: F401  (import = registration)
    from messagefoundry.transports.base import _SOURCES

    registered = {kind.value for kind in _SOURCES}
    assert registered, "the source registry is empty — import-time registration broke"
    undecided = sorted(registered - set(_RESOURCE_SOURCE_EXEMPTIONS))
    assert not undecided, (
        f"registered inbound connector(s) with no 15.1.3 coverage decision: {undecided}. Add a "
        "data-plane row to docs/security/THREAT-MODEL.md naming the attacker-influenceable input and "
        "the bound in force, then register it in _RESOURCE_SOURCE_EXEMPTIONS with the reason."
    )
    stale = sorted(set(_RESOURCE_SOURCE_EXEMPTIONS) - registered)
    assert not stale, (
        f"_RESOURCE_SOURCE_EXEMPTIONS names connectors that are no longer registered: {stale}"
    )


def test_every_dangerous_row_is_pinned_by_an_anchor_or_a_row_key() -> None:
    """Closes the class permanently: no 15.1.5 row may ship unpinned.

    The loader-execution-triggers row carried neither an anchor nor a ``_DANGEROUS_ROW_KEYS`` entry,
    so deleting it whole produced zero failures — while this module's own docstring states the rule
    "deleting ANY row must red CI".
    """
    rows = _table_rows(_section(_doc_text(), _DANGEROUS_HEADING))
    unpinned = [
        row.split("|")[1].strip()[:70]
        for row in rows
        if not any(anchor in row for anchor in _DANGEROUS_ANCHORS)
        and not any(key in row for key in _DANGEROUS_ROW_KEYS)
    ]
    assert not unpinned, (
        "15.1.5 row(s) with no _DANGEROUS_ANCHORS token and no _DANGEROUS_ROW_KEYS entry — deleting "
        f"them would not red CI: {unpinned}"
    )


# --- checker self-tests: the half that must run on EVERY tree (BACKLOG #1043) --------------------
#
# Everything above this line asserts about a document that is absent from a public checkout. These
# assert about the CHECKERS, against a stand-in written here, and therefore never go inert. They are
# not a stand-in for the document's content — a public copy of the registries would be a green
# proving only that a fixture matches a fixture. They prove the checkers can go RED, which is the
# property a skipped run silently stops evidencing.

#: A miniature of the two scored sections. The prose after each table repeats a row's anchor on
#: purpose: that is the exact shape that once left `_missing` green next to a deleted row, and it is
#: why `_missing_in_rows` exists.
_STAND_IN = """\
# Stand-in threat model

## Resource-demanding functionality (ASVS 15.1.3)

| Surface | Attacker-influenceable input | Bound in force |
|---|---|---|
| **Widget parse** | the widget body | capped by `widget_limit` at 4 MiB |
| **Gadget poll** | the polled row set | capped by `gadget_limit` |

Closing note: `widget_limit` is also named here, in prose, after the table. See
[CONFIGURATION.md](CONFIGURATION.md) and the `[api].serve_ui` setting.

## Dangerous functionality (ASVS 15.1.5)

| Functionality | Guard |
|---|---|
| **Shell hook** | runs via `create_subprocess_shell` behind an operator-only setting |

### First subsection

subprocess.Popen appears here, in prose inside the 15.1.5 section.

### Second subsection

nothing of interest.
"""


def _stand_in_resource_section() -> str:
    return _section(_STAND_IN, _RESOURCE_HEADING)


def test_section_slicing_stops_at_the_next_same_or_higher_heading() -> None:
    """The contract is *same-or-higher* level, so a `###` subsection stays inside its `##` parent.

    Worth pinning rather than assuming: that inclusion is precisely why the anchor checks are scoped
    to TABLE ROWS. A `##` slice carries its subsections' prose, so a section-scoped token search can
    be satisfied by text that is not a row. (This assertion was written the other way round first,
    and the stand-in caught it — which is the point of having one.)
    """
    resource = _stand_in_resource_section()
    assert "**Widget parse**" in resource
    assert "**Shell hook**" not in resource, "the 15.1.3 slice swallowed the next `##` section"
    dangerous = _section(_STAND_IN, _DANGEROUS_HEADING)
    assert "**Shell hook**" in dangerous
    assert "First subsection" in dangerous, "a `###` subsection is part of its `##` section"
    sub = _section(_STAND_IN, "### First subsection")
    assert "subprocess.Popen" in sub
    assert "Second subsection" not in sub, "a `###` slice swallowed the next `###`"


def test_table_row_extraction_drops_the_header_and_separator() -> None:
    rows = _table_rows(_stand_in_resource_section())
    assert len(rows) == 2, f"expected the two body rows, got {rows}"
    assert _row_first_cells(_stand_in_resource_section()) == ["**Widget parse**", "**Gadget poll**"]


def test_a_deleted_row_is_detected_even_though_the_prose_still_carries_its_anchor() -> None:
    """THE trap this module has already been caught by, proven detectable on every tree.

    RULE: a gate that has never been red is a claim. Here the red is produced on purpose: drop the
    `widget_limit` ROW while the closing prose keeps naming `widget_limit`, and the row-scoped
    checker must still report it — while the section-scoped one demonstrably does not.
    """
    section = _stand_in_resource_section()
    assert _missing_in_rows(section, ("widget_limit", "gadget_limit")) == []

    mutated = _drop_one_row_containing(section, "widget_limit")
    assert _missing_in_rows(mutated, ("widget_limit",)) == ["widget_limit"], (
        "the row-scoped checker did not notice a deleted row — it is asleep"
    )
    # Only ONE row goes: the sibling must still be found, or the mutation is too blunt to model a
    # realistic single-row regression.
    assert _missing_in_rows(mutated, ("gadget_limit",)) == []
    # And the section-scoped checker is blind to it, because the prose still says `widget_limit`.
    # That is not a defect here; it is the measured reason the row-scoped one exists.
    assert _missing(mutated, ("widget_limit",)) == []


def test_the_row_mutation_helper_refuses_to_silently_do_nothing() -> None:
    """If the needle is gone, `_drop_one_row_containing` must fail rather than return the text
    unchanged — otherwise every planted-omission self-test above would pass vacuously."""
    with pytest.raises(AssertionError, match="no table row containing"):
        _drop_one_row_containing(_stand_in_resource_section(), "a-token-in-no-row")


def test_the_token_and_link_scanners_find_what_they_claim_to() -> None:
    assert ("api", "serve_ui") in _TOML_TOKEN_RE.findall(_STAND_IN)
    assert _MD_LINK_RE.findall(_STAND_IN) == ["CONFIGURATION.md"]
    assert _SUBPROCESS_RE.search("create_subprocess_shell(...)") is not None
    assert _SUBPROCESS_RE.search("subprocess.Popen([...])") is not None
    assert _SUBPROCESS_RE.search("a line that spawns nothing") is None


# --- the enforcement posture is itself asserted --------------------------------------------------


def test_the_doc_content_half_reports_whether_it_is_enforcing() -> None:
    """Neither posture may be silent (#1043).

    Present: the accessor returns the document, so the assertions above are live. Absent: the
    accessor emits a ThreatModelDocUnenforced warning naming what stopped enforcing, and only THEN
    skips. A run that quietly skipped 80-odd assertions and reported green is the defect being fixed,
    so the announcement is asserted rather than assumed.
    """
    global _ANNOUNCED
    path = _doc_path()
    if path.exists():
        assert _doc_text().strip(), f"{path} exists but is empty — the content half asserts nothing"
        return
    was_announced, _ANNOUNCED = _ANNOUNCED, False
    try:
        with (
            pytest.warns(ThreatModelDocUnenforced, match=str(_DOC_ENV)),
            pytest.raises(pytest.skip.Exception),
        ):
            _doc_text()
    finally:
        _ANNOUNCED = was_announced


def test_requiring_the_document_turns_its_absence_into_a_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The fail-closed arm, for a leg that IS supposed to carry the document.

    Both directions are exercised, so neither the env name nor the truthiness test can rot: pointed
    at a real file the accessor reads it, pointed at a missing one under the require flag it fails.
    """
    monkeypatch.setenv(_REQUIRE_ENV, "1")
    monkeypatch.setenv(_DOC_ENV, str(tmp_path / "absent" / "THREAT-MODEL.md"))
    with pytest.raises(pytest.fail.Exception, match=_REQUIRE_ENV):
        _doc_text()

    stand_in = tmp_path / "THREAT-MODEL.md"
    stand_in.write_text(_STAND_IN, encoding="utf-8")
    monkeypatch.setenv(_DOC_ENV, str(stand_in))
    assert _doc_text() == _STAND_IN, "the override is not what the accessor actually reads"
