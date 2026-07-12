# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Rename / delete PRE-FLIGHT (#152) — :mod:`messagefoundry.config.impact`.

Loads real config modules (so the referrer edges come from genuinely-compiled ``co_consts``) then
exercises the tokenize-safe referent rewriter: a rename rewrites the object's own definition + every
referent (a handler's ``Send()``, an inbound's ``router=`` binding, a ``connections.toml`` value) while
a lookalike identifier / comment / substring / f-string / bytes / adjacent-string-concat / unrelated
data literal is left alone. Dry-run writes nothing; ``--apply`` rewrites and is idempotent; CRLF and LF
byte layouts survive verbatim outside the replaced spans."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config import codeset_edit
from messagefoundry.config.code_sets import load_code_set
from messagefoundry.config.impact import (
    apply_rename,
    delete_impact,
    plan_rename,
)
from messagefoundry.config.reachability import Reference, build_reference_index
from messagefoundry.config.wiring import WiringError, load_config

# --- fixtures ----------------------------------------------------------------

# One outbound (OB_OLD) referenced by a handler's Send(); the router body carries an *unrelated* data
# literal that happens to equal "OB_OLD" (a router makes no outbound edge, so it is NOT a referrer and
# must be left alone), and the referrer handler carries an identifier / substring lookalike in-span.
_OUTBOUND_CFG = (
    "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_MAIN", MLLP(port=2701), router="r_main")\n'
    'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6100))\n'
    'outbound("OB_KEEP", MLLP(host="127.0.0.1", port=6101))\n'
    "\n"
    "\n"
    '@router("r_main")\n'
    "def route(msg):\n"
    '    unrelated = "OB_OLD"  # router body: no outbound edge, leave this literal alone\n'
    '    return ["h_send"]\n'
    "\n"
    "\n"
    '@handler("h_send")\n'
    "def h_send(msg):\n"
    '    sentinel = "kept"  # a plain value, untouched\n'
    '    near = "OB_OLD_2"  # substring lookalike, value != "OB_OLD"\n'
    "    # comment mentioning OB_OLD must be ignored\n"
    '    return Send("OB_OLD", msg)\n'
)

# A router (r_shared) bound by BOTH a code-first inbound and a connections.toml inbound, so a rename
# must rewrite the @router definition, the code-first router= binding, and the TOML router value.
_ROUTER_MOD = (
    "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_CODE", MLLP(port=2711), router="r_shared")\n'
    'outbound("OB_X", MLLP(host="127.0.0.1", port=6200))\n'
    "\n"
    "\n"
    '@router("r_shared")\n'
    "def r_shared(msg):\n"
    '    return ["h_x"]\n'
    "\n"
    "\n"
    '@handler("h_x")\n'
    "def h_x(msg):\n"
    '    return Send("OB_X", msg)\n'
)

_ROUTER_TOML = (
    "[[inbound]]\n"
    'name = "IB_DATA"\n'
    'transport = "mllp"\n'
    'router = "r_shared"\n'
    "  [inbound.settings]\n"
    "  port = 2712\n"
)

# A handler that references OB_OLD as a plain Send() literal but also mentions it as an f-string, a
# bytes literal, and an implicit adjacent-string concatenation — none of which may be rewritten.
_UNSAFE_LITERALS_CFG = (
    "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_U", MLLP(port=2721), router="r_u")\n'
    'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6300))\n'
    "\n"
    "\n"
    '@router("r_u")\n'
    "def r_u(msg):\n"
    '    return ["h_u"]\n'
    "\n"
    "\n"
    '@handler("h_u")\n'
    "def h_u(msg):\n"
    '    fs = f"OB_OLD"\n'
    '    by = b"OB_OLD"\n'
    '    cc = "OB_" "OLD"\n'
    '    return Send("OB_OLD", msg)\n'
)


# A handler that references a code_set("diets") table by name (call-time) so a code-set rename/delete
# has a live referent to rewrite / warn about.
_CODESET_MOD = (
    "from messagefoundry import MLLP, Send, code_set, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_CS", MLLP(port=2731), router="r_cs")\n'
    'outbound("OB_CS", MLLP(host="127.0.0.1", port=6400))\n'
    "\n"
    "\n"
    '@router("r_cs")\n'
    "def r_cs(msg):\n"
    '    return ["h_cs"]\n'
    "\n"
    "\n"
    '@handler("h_cs")\n'
    "def h_cs(msg):\n"
    '    label = code_set("diets").get("A")\n'
    '    return Send("OB_CS", msg)\n'
)


# A handler that references OB_OLD as a plain Send() literal AND concatenates the same fragment onto an
# f-string. On 3.12+ `"OB_OLD" f"{msg}"` is a STRING token adjacent to an FSTRING_START — a real implicit
# concat whose fragment must NOT be rewritten (doing so silently changes the runtime value).
_FSTRING_CONCAT_CFG = (
    "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_FC", MLLP(port=2771), router="r_fc")\n'
    'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6800))\n'
    "\n"
    "\n"
    '@router("r_fc")\n'
    "def r_fc(msg):\n"
    '    return ["h_fc"]\n'
    "\n"
    "\n"
    '@handler("h_fc")\n'
    "def h_fc(msg):\n"
    '    label = "OB_OLD" f"{msg}"  # str fragment concatenated with an f-string — leave verbatim\n'
    '    return Send("OB_OLD", msg)\n'
)

# A handler whose ONLY reference to OB_OLD is an implicit adjacent-string concat that folds to the name
# ("OB_" "OLD" -> const "OB_OLD"). It is a genuine referrer in the reverse index, but the tokenizer must
# refuse to split it — so the rename reports it as UNRESOLVED rather than dropping it silently.
_FOLDED_CONCAT_CFG = (
    "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_F", MLLP(port=2741), router="r_f")\n'
    'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6500))\n'
    "\n"
    "\n"
    '@router("r_f")\n'
    "def r_f(msg):\n"
    '    return ["h_f"]\n'
    "\n"
    "\n"
    '@handler("h_f")\n'
    "def h_f(msg):\n"
    '    return Send("OB_" "OLD", msg)\n'
)

# A live DatabaseLookup("clarity") declaration + a handler that queries it via db_lookup("clarity").
_LOOKUP_MOD = (
    "from messagefoundry import DatabaseLookup, MLLP, Send, db_lookup, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_L", MLLP(port=2751), router="r_l")\n'
    'outbound("OB_L", MLLP(host="127.0.0.1", port=6600))\n'
    'DatabaseLookup("clarity", server="db", database="Clarity", username="u", password="p")\n'
    "\n"
    "\n"
    '@router("r_l")\n'
    "def r_l(msg):\n"
    '    return ["h_l"]\n'
    "\n"
    "\n"
    '@handler("h_l")\n'
    "def h_l(msg):\n"
    '    row = db_lookup("clarity", "SELECT 1", ())\n'
    '    return Send("OB_L", msg)\n'
)

# A Reference("providers") declaration + a handler that reads it via reference("providers").
_REFERENCE_MOD = (
    "from messagefoundry import FileRef, MLLP, Reference, Send, handler, inbound, outbound, reference, "
    "router\n"
    "\n"
    'inbound("IB_R", MLLP(port=2761), router="r_r")\n'
    'outbound("OB_R", MLLP(host="127.0.0.1", port=6700))\n'
    'Reference("providers", source=FileRef(path="providers.csv"))\n'
    "\n"
    "\n"
    '@router("r_r")\n'
    "def r_r(msg):\n"
    '    return ["h_r"]\n'
    "\n"
    "\n"
    '@handler("h_r")\n'
    "def h_r(msg):\n"
    '    npi = reference("providers").get("x")\n'
    '    return Send("OB_R", msg)\n'
)


def _write_config(tmp_path: Path, files: dict[str, str]) -> Path:
    """Write ``files`` verbatim (``newline=""`` = no line-ending translation, so an LF fixture stays LF
    and a CRLF fixture stays CRLF on every host) into a fresh config dir and return it."""
    d = tmp_path / "config"
    d.mkdir()
    for name, body in files.items():
        (d / name).write_text(body, encoding="utf-8", newline="")
    return d


def _validate_code_set(path: Path) -> None:
    """The real post-write check codeset_edit injects: prove the written file loads."""
    load_code_set(path)


def _write_codeset_config(tmp_path: Path) -> Path:
    """A config dir with a ``codesets/diets.csv`` table and a handler that names it."""
    config_dir = _write_config(tmp_path, {"mod.py": _CODESET_MOD})
    codesets = config_dir / "codesets"
    codesets.mkdir()
    (codesets / "diets.csv").write_text("code,value\nA,Apple\n", encoding="utf-8", newline="")
    return config_dir


# --- rename: referent rewrite + span scoping ---------------------------------


def test_rename_outbound_rewrites_referrer_and_definition_and_spares_lookalikes(
    tmp_path: Path,
) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    registry = load_config(config_dir)

    plan = plan_rename(registry, config_dir, "outbound", "OB_OLD", "OB_NEW")

    # Exactly two edits: the outbound(...) definition and the Send("OB_OLD", ...) referent. The router
    # body's unrelated = "OB_OLD", the identifier, the substring, and the comment are NOT edits.
    assert len(plan.edits) == 2
    assert {e.old_literal for e in plan.edits} == {'"OB_OLD"'}
    assert {e.new_literal for e in plan.edits} == {'"OB_NEW"'}

    applied = apply_rename(plan)
    assert len(applied) == 2

    text = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert 'outbound("OB_NEW", MLLP(host="127.0.0.1", port=6100))' in text
    assert 'return Send("OB_NEW", msg)' in text
    # Left alone: the router's unrelated literal, the substring lookalike, the comment.
    assert 'unrelated = "OB_OLD"' in text
    assert 'near = "OB_OLD_2"' in text
    assert "# comment mentioning OB_OLD must be ignored" in text
    # The renamed graph still loads (OB_NEW now defined + referenced consistently).
    load_config(config_dir)


def test_rename_router_rewrites_binding_and_definition_and_connections_toml(
    tmp_path: Path,
) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _ROUTER_MOD, "connections.toml": _ROUTER_TOML})
    registry = load_config(config_dir)

    plan = plan_rename(registry, config_dir, "router", "r_shared", "r_flow")

    # Three edits: the @router("r_shared") definition, the code-first inbound router= binding, and the
    # connections.toml router value.
    files = {Path(e.file).name for e in plan.edits}
    assert files == {"mod.py", "connections.toml"}
    assert len(plan.edits) == 3

    apply_rename(plan)
    mod = (config_dir / "mod.py").read_text(encoding="utf-8")
    toml = (config_dir / "connections.toml").read_text(encoding="utf-8")
    assert '@router("r_flow")' in mod
    assert 'router="r_flow"' in mod
    assert 'router = "r_flow"' in toml
    # The TOML connection name (a differently-keyed value) is untouched.
    assert 'name = "IB_DATA"' in toml
    # The def statement's NAME token (def r_shared) is not a string literal — never rewritten.
    assert "def r_shared(msg):" in mod
    load_config(config_dir)


def test_fstring_bytes_and_adjacent_concat_are_never_rewritten(tmp_path: Path) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _UNSAFE_LITERALS_CFG})
    registry = load_config(config_dir)

    plan = plan_rename(registry, config_dir, "outbound", "OB_OLD", "OB_NEW")
    apply_rename(plan)

    text = (config_dir / "mod.py").read_text(encoding="utf-8")
    # Only the plain Send() literal + the outbound definition are rewritten.
    assert 'outbound("OB_NEW"' in text
    assert 'return Send("OB_NEW", msg)' in text
    # The f-string, bytes, and adjacent-concat forms survive verbatim (rewriting a fragment would
    # corrupt the value, so the tokenizer refuses even though the heuristic index counts the edge).
    assert 'fs = f"OB_OLD"' in text
    assert 'by = b"OB_OLD"' in text
    assert 'cc = "OB_" "OLD"' in text


def test_string_fragment_adjacent_to_fstring_is_never_rewritten(tmp_path: Path) -> None:
    # `"OB_OLD" f"{msg}"` is an implicit concat (STRING next to FSTRING_START on 3.12+). Rewriting the
    # STRING fragment would flip the expression's runtime value from "OB_OLD"+str(msg) to
    # "OB_NEW"+str(msg) — so it must be left verbatim, exactly like a STRING-STRING concat.
    config_dir = _write_config(tmp_path, {"mod.py": _FSTRING_CONCAT_CFG})
    registry = load_config(config_dir)

    plan = plan_rename(registry, config_dir, "outbound", "OB_OLD", "OB_NEW")
    apply_rename(plan)

    text = (config_dir / "mod.py").read_text(encoding="utf-8")
    # The definition and the plain Send() referent are rewritten...
    assert 'outbound("OB_NEW"' in text
    assert 'return Send("OB_NEW", msg)' in text
    # ...but the fragment concatenated onto the f-string survives byte-for-byte.
    assert 'label = "OB_OLD" f"{msg}"' in text


def test_folded_adjacent_concat_referent_is_reported_unresolved(tmp_path: Path) -> None:
    # A handler whose only reference is `Send("OB_" "OLD", …)` folds to the const "OB_OLD" (a real
    # referrer) but the tokenizer refuses to split the concat — so it can't be rewritten. The rename must
    # surface it as unresolved rather than renaming the definition and silently leaving it dangling.
    config_dir = _write_config(tmp_path, {"mod.py": _FOLDED_CONCAT_CFG})
    registry = load_config(config_dir)
    index = build_reference_index(registry)
    assert delete_impact(index, "outbound", "OB_OLD") == [
        Reference("handler", "h_f", "outbound", "OB_OLD")
    ]

    plan = plan_rename(registry, config_dir, "outbound", "OB_OLD", "OB_NEW")
    # Only the outbound() definition is a concrete edit; the folded-concat referent is unresolved.
    assert [e.old_literal for e in plan.edits] == ['"OB_OLD"']
    assert plan.unresolved == (Reference("handler", "h_f", "outbound", "OB_OLD"),)

    apply_rename(plan)
    text = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert 'outbound("OB_NEW"' in text
    assert 'Send("OB_" "OLD", msg)' in text  # left verbatim (unrewritable)


# --- definition rewrite for code-first lookup / reference declarations --------


def test_rename_lookup_rewrites_definition_and_referent(tmp_path: Path) -> None:
    # A DatabaseLookup("clarity") declaration has no source_line on its spec, but its `.py` definition
    # literal must still be rewritten alongside the db_lookup("clarity") referent — else --apply renames
    # only the referent and the registry keeps the OLD lookup name, breaking the feed at runtime.
    config_dir = _write_config(tmp_path, {"mod.py": _LOOKUP_MOD})
    registry = load_config(config_dir)

    plan = plan_rename(registry, config_dir, "lookup", "clarity", "clarity2")
    assert (
        len(plan.edits) == 2
    )  # the DatabaseLookup(...) definition AND the db_lookup(...) referent
    assert {e.old_literal for e in plan.edits} == {'"clarity"'}
    assert plan.unresolved == ()

    apply_rename(plan)
    text = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert 'DatabaseLookup("clarity2", server="db"' in text
    assert 'db_lookup("clarity2", "SELECT 1", ())' in text
    load_config(config_dir)


def test_rename_reference_rewrites_definition_and_referent(tmp_path: Path) -> None:
    # A `reference` is a code-first Reference("providers") declaration (NOT a file-backed table), so its
    # definition literal is rewritten like any other code-first declaration.
    config_dir = _write_config(tmp_path, {"mod.py": _REFERENCE_MOD})
    registry = load_config(config_dir)

    plan = plan_rename(registry, config_dir, "reference", "providers", "prov2")
    assert len(plan.edits) == 2  # the Reference(...) definition AND the reference(...) referent
    assert {e.old_literal for e in plan.edits} == {'"providers"'}

    apply_rename(plan)
    text = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert 'Reference("prov2", source=FileRef(path="providers.csv"))' in text
    assert 'reference("prov2").get("x")' in text
    load_config(config_dir)


def test_rename_onto_existing_name_is_rejected(tmp_path: Path) -> None:
    # OB_KEEP already exists; renaming OB_OLD onto it would write a duplicate outbound() definition and
    # load_config would fail with "duplicate outbound connection name". Reject it up front.
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    registry = load_config(config_dir)
    with pytest.raises(WiringError):
        plan_rename(registry, config_dir, "outbound", "OB_OLD", "OB_KEEP")


# --- dry-run vs apply, idempotency -------------------------------------------


def test_dry_run_writes_nothing_then_apply_is_idempotent(tmp_path: Path) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    registry = load_config(config_dir)
    before = (config_dir / "mod.py").read_bytes()

    # plan_rename (the dry-run) reads but never writes.
    plan = plan_rename(registry, config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert (config_dir / "mod.py").read_bytes() == before

    # A second plan on the still-unchanged tree yields identical edits.
    plan2 = plan_rename(registry, config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert [e.as_dict() for e in plan.edits] == [e.as_dict() for e in plan2.edits]

    apply_rename(plan)
    after = (config_dir / "mod.py").read_bytes()
    assert after != before

    # Re-applying the same plan is a no-op: the spans already carry the new literal.
    assert apply_rename(plan) == []
    assert (config_dir / "mod.py").read_bytes() == after


def test_rewrite_preserves_crlf_bytes(tmp_path: Path) -> None:
    crlf = _OUTBOUND_CFG.replace("\n", "\r\n")
    config_dir = _write_config(tmp_path, {"mod.py": crlf})
    # The fixture is genuinely CRLF on disk.
    assert b"\r\n" in (config_dir / "mod.py").read_bytes()
    assert b"\n" in (config_dir / "mod.py").read_bytes()

    registry = load_config(config_dir)
    plan = plan_rename(registry, config_dir, "outbound", "OB_OLD", "OB_NEW")
    apply_rename(plan)

    raw = (config_dir / "mod.py").read_bytes()
    # The rewrite happened, CRLF terminators survived, and no lone LF was introduced (every \n is
    # part of a \r\n, so stripping them leaves no stray \n).
    assert b'Send("OB_NEW", msg)' in raw
    assert b"\r\n" in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")


# --- delete pre-flight -------------------------------------------------------


def test_delete_impact_lists_live_referrers(tmp_path: Path) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    registry = load_config(config_dir)
    index = build_reference_index(registry)

    dangling = delete_impact(index, "outbound", "OB_OLD")
    assert dangling == [Reference("handler", "h_send", "outbound", "OB_OLD")]
    # An object nobody references has no dangling referrers.
    assert delete_impact(index, "outbound", "OB_KEEP") == []


# --- name safety on `new` ----------------------------------------------------


def test_name_safety_rejects_traversal_on_new_for_file_backed_kind(tmp_path: Path) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    registry = load_config(config_dir)
    # `new` is validated (file-stem safety for a code_set) BEFORE the `old` existence check, so a
    # traversal in `new` is rejected regardless of whether `old` resolves.
    with pytest.raises(WiringError):
        plan_rename(registry, config_dir, "code_set", "cs_old", "../evil")


def test_name_safety_rejects_quote_in_new_for_any_kind(tmp_path: Path) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    registry = load_config(config_dir)
    # A quote/backslash would break out of the source string literal the rewrite embeds it into.
    with pytest.raises(WiringError):
        plan_rename(registry, config_dir, "outbound", "OB_OLD", 'OB_"NEW')


def test_unknown_kind_is_rejected(tmp_path: Path) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    registry = load_config(config_dir)
    with pytest.raises(WiringError):
        plan_rename(registry, config_dir, "channel", "anything", "other")


# --- CLI surface (messagefoundry impact) -------------------------------------


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, object]]:
    rc = main(args)
    out = capsys.readouterr().out
    return rc, json.loads(out)


def test_cli_reports_referrers(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    rc, data = _run(["impact", "--config", str(config_dir), "outbound", "OB_OLD", "--json"], capsys)
    assert rc == 0
    assert data["count"] == 1
    assert data["referrers"][0]["referrer"] == "h_send"


def test_cli_rename_dry_run_writes_nothing_then_apply(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    before = (config_dir / "mod.py").read_bytes()

    rc, data = _run(
        [
            "impact",
            "--config",
            str(config_dir),
            "outbound",
            "OB_OLD",
            "--rename-to",
            "OB_NEW",
            "--json",
        ],
        capsys,
    )
    assert rc == 0 and data["dry_run"] is True
    assert len(data["edits"]) == 2
    assert (config_dir / "mod.py").read_bytes() == before  # dry-run wrote nothing

    rc, data = _run(
        [
            "impact",
            "--config",
            str(config_dir),
            "outbound",
            "OB_OLD",
            "--rename-to",
            "OB_NEW",
            "--apply",
            "--json",
        ],
        capsys,
    )
    assert rc == 0 and data["dry_run"] is False and data["applied"] == 2
    assert b'Send("OB_NEW", msg)' in (config_dir / "mod.py").read_bytes()


def test_cli_delete_preflight(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    rc, data = _run(
        ["impact", "--config", str(config_dir), "outbound", "OB_OLD", "--delete", "--json"], capsys
    )
    assert rc == 0
    assert data["op"] == "delete" and data["would_dangle"] == 1
    assert data["referrers"][0]["referrer"] == "h_send"


def test_cli_rename_and_delete_are_mutually_exclusive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    rc = main(
        [
            "impact",
            "--config",
            str(config_dir),
            "outbound",
            "OB_OLD",
            "--rename-to",
            "OB_NEW",
            "--delete",
            "--json",
        ]
    )
    assert rc != 0


def test_cli_apply_requires_rename_to(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config_dir = _write_config(tmp_path, {"mod.py": _OUTBOUND_CFG})
    rc = main(["impact", "--config", str(config_dir), "outbound", "OB_OLD", "--apply", "--json"])
    assert rc != 0


# --- codeset_edit composition (#152 item 3) ----------------------------------


def test_codeset_rename_rewrites_referent_and_moves_file(tmp_path: Path) -> None:
    config_dir = _write_codeset_config(tmp_path)
    result = codeset_edit.rename_code_set(config_dir, "diets", "meals", validate=_validate_code_set)
    # The referent pre-flight rewrote the handler's code_set("diets") call.
    assert result["referents_rewritten"] == 1
    assert (config_dir / "codesets" / "meals.csv").exists()
    assert not (config_dir / "codesets" / "diets.csv").exists()
    mod = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert 'code_set("meals")' in mod
    assert 'code_set("diets")' not in mod
    # The renamed graph still loads (the table + its referent now agree).
    load_config(config_dir)


def test_codeset_remove_surfaces_dangling_referrers_before_unlink(tmp_path: Path) -> None:
    config_dir = _write_codeset_config(tmp_path)
    # The delete pre-flight must be computed while the table still resolves — after the unlink the
    # reverse index would build no code_set edge, so the referrers would come back empty.
    result = codeset_edit.remove_code_set(config_dir, "diets", validate=_validate_code_set)
    assert not (config_dir / "codesets" / "diets.csv").exists()
    assert result["referrers"] == [{"referrer_kind": "handler", "referrer": "h_cs"}]
