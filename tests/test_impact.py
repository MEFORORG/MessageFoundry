# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
from typing import Any

import pytest

from messagefoundry.config import codeset_edit
from messagefoundry.config.code_sets import load_code_set
from messagefoundry.config.impact import (
    LiteralEdit,
    RenamePlan,
    apply_rename,
    delete_impact,
    plan_rename,
)
from messagefoundry.config.reachability import Reference, build_reference_index
from messagefoundry.config.wiring import WiringError, load_config
from messagefoundry_toolkit.__main__ import main
from tests._share_fault import unlistable_dir

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


@pytest.mark.parametrize("separator", ["\u2028", "\u0085"])
def test_rename_router_toml_binding_survives_a_unicode_line_separator_in_an_earlier_value(
    tmp_path: Path, separator: str
) -> None:
    # str.splitlines breaks a line on U+2028 / U+0085, but apply_rename splits as tokenize does (\n,
    # \r\n, \r only). A connections.toml edit numbered by str.splitlines lands one line too low, so the
    # router binding below the value is skipped and dangles after the rename.
    original = (
        "[[outbound]]\n"
        'name = "OB_FILE"\n'
        'transport = "file"\n'
        "  [outbound.settings]\n"
        f'  directory = "out{separator}dir"\n'
        "\n" + _ROUTER_TOML
    )
    config_dir = _write_config(tmp_path, {"mod.py": _ROUTER_MOD, "connections.toml": original})
    registry = load_config(config_dir)

    plan = plan_rename(registry, config_dir, "router", "r_shared", "r_flow")
    applied = apply_rename(plan)

    assert len(applied) == len(plan.edits) == 3
    raw = (config_dir / "connections.toml").read_bytes().decode("utf-8")
    # The binding is rewritten and nothing else in the file moved.
    assert raw == original.replace('router = "r_shared"', 'router = "r_flow"')
    assert load_config(config_dir).inbound["IB_DATA"].router == "r_flow"


def test_apply_rename_multi_line_edit_keeps_an_earlier_edit_on_its_line_after_u2028(
    tmp_path: Path,
) -> None:
    # A multi-line (backslash-continued) literal is re-split after it is rewritten. Re-split with
    # str.splitlines, a U+2028 earlier on its first line breaks that line in two, so an earlier edit on
    # the same line no longer finds its literal at its column and is silently skipped.
    path = tmp_path / "m.py"
    first = 's = "\u2028"; t = "AA"; u = "BB\\\n'
    path.write_text(first + 'BB"\n', encoding="utf-8", newline="")
    aa = first.index('"AA"')
    bb = first.index('"BB')
    edits = (
        LiteralEdit(str(path), 1, aa, 1, aa + 4, '"AA"', '"CC"'),
        LiteralEdit(str(path), 1, bb, 2, 3, '"BB\\\nBB"', '"DD"'),
    )
    applied = apply_rename(RenamePlan("outbound", "x", "y", edits=edits))

    assert len(applied) == 2
    assert path.read_bytes().decode("utf-8") == 's = "\u2028"; t = "CC"; u = "DD"\n'


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


def test_rename_refuses_a_config_dir_it_cannot_list(tmp_path: Path) -> None:
    """The declaration is found by listing the directory's modules. A listing that failed read as
    an empty directory, so the plan left the definition out with nothing said, and an apply would
    rename only the referents (vault BACKLOG #5117)."""
    registry = load_config(_write_config(tmp_path, {"mod.py": _LOOKUP_MOD}))
    with (
        unlistable_dir(tmp_path) as folder,
        pytest.raises(WiringError, match="could not list the config dir"),
    ):
        plan_rename(registry, folder, "lookup", "clarity", "clarity2")


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


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
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


def test_cli_code_set_apply_is_refused_and_points_at_codeset_rename(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5820: apply_rename rewrites only the code_set("...") literals, so an applied
    code_set rename left codesets/diets.csv behind and a config that no longer loads, with exit 0."""
    config_dir = _write_codeset_config(tmp_path)
    before = (config_dir / "mod.py").read_bytes()
    argv = ["impact", "--config", str(config_dir), "code_set", "diets", "--rename-to", "meals"]

    rc, data = _run([*argv, "--apply", "--json"], capsys)

    assert rc != 0
    assert "codeset rename" in data["error"]
    assert (config_dir / "mod.py").read_bytes() == before
    assert (config_dir / "codesets" / "diets.csv").exists()
    load_config(config_dir)

    # The dry-run plan is still offered.
    rc, data = _run([*argv, "--json"], capsys)
    assert rc == 0 and data["dry_run"] is True and data["edits"]


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


# The same module with its two connection declarations removed: a handler that still names the code
# set, in a dir that declares no connection at all. The A/B partner of _CODESET_MOD.
_CODESET_MOD_NO_CONNECTIONS = (
    "from messagefoundry import Send, code_set, handler, router\n"
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


def test_codeset_rename_still_rewrites_referents_with_no_connection_declared(
    tmp_path: Path,
) -> None:
    """The #1648 empty-graph refusal must not reach this pre-flight, which SWALLOWS load failures.

    ``_load_referent_registry`` catches ``WiringError`` and returns ``None``, so a refusal here is
    silent: the table moves and every ``code_set("diets")`` call is left pointing at a file that no
    longer exists, with no ``referents_rewritten`` key and no error. Measured A/B against
    ``test_codeset_rename_rewrites_referent_and_moves_file`` above -- the only difference between the
    two fixtures is whether a connection is declared.

    Falsified by dropping ``allow_empty=True`` from ``_load_referent_registry``."""
    config_dir = _write_config(tmp_path, {"mod.py": _CODESET_MOD_NO_CONNECTIONS})
    codesets = config_dir / "codesets"
    codesets.mkdir()
    (codesets / "diets.csv").write_text("code,value\nA,Apple\n", encoding="utf-8", newline="")

    result = codeset_edit.rename_code_set(config_dir, "diets", "meals", validate=_validate_code_set)

    assert result["referents_rewritten"] == 1
    mod = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert 'code_set("meals")' in mod and 'code_set("diets")' not in mod


def test_codeset_remove_still_surfaces_referrers_with_no_connection_declared(
    tmp_path: Path,
) -> None:
    """The delete pre-flight degrades the same silent way — zero referrers when there is one."""
    config_dir = _write_config(tmp_path, {"mod.py": _CODESET_MOD_NO_CONNECTIONS})
    codesets = config_dir / "codesets"
    codesets.mkdir()
    (codesets / "diets.csv").write_text("code,value\nA,Apple\n", encoding="utf-8", newline="")

    result = codeset_edit.remove_code_set(config_dir, "diets", validate=_validate_code_set)

    assert result["referrers"] == [{"referrer_kind": "handler", "referrer": "h_cs"}]


# --- BACKLOG #5620 / #5621: referent sites outside the referrer's own body ------

# One handler reaching three tables three ways: a module-top capture (DIETS), a helper it calls
# (_label), and a module-level accepts predicate (_only_known). None of the three names appears in
# the handler's own body.
_HELPERS_CODESET_MOD = (
    "from messagefoundry import MLLP, Send, code_set, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_HS", MLLP(port=2791), router="r_hs")\n'
    'outbound("OB_HS", MLLP(host="127.0.0.1", port=6900))\n'
    "\n"
    'DIETS = code_set("diets")\n'
    "\n"
    "\n"
    "def _label(code):\n"
    '    return code_set("meals_table").get(code)\n'
    "\n"
    "\n"
    "def _only_known(msg):\n"
    '    return "A" in code_set("allow_list")\n'
    "\n"
    "\n"
    '@router("r_hs")\n'
    "def r_hs(msg):\n"
    '    return ["h_hs"]\n'
    "\n"
    "\n"
    '@handler("h_hs", accepts=_only_known)\n'
    "def h_hs(msg):\n"
    '    first = DIETS.get("A")\n'
    '    second = _label("A")\n'
    '    return Send("OB_HS", msg)\n'
)


def _write_helpers_codeset_config(tmp_path: Path) -> Path:
    config_dir = _write_config(tmp_path, {"mod.py": _HELPERS_CODESET_MOD})
    codesets = config_dir / "codesets"
    codesets.mkdir()
    for name in ("diets", "meals_table", "allow_list"):
        (codesets / f"{name}.csv").write_text("code,value\nA,Apple\n", encoding="utf-8", newline="")
    return config_dir


@pytest.mark.parametrize("table", ["diets", "meals_table", "allow_list"])
def test_table_read_at_module_top_in_a_helper_or_a_predicate_is_a_live_referrer(
    tmp_path: Path, table: str
) -> None:
    """A table captured at module top level, read in a helper the handler calls, or read in a
    module-level accepts predicate is load-bearing; the removal pre-flight must name the handler and
    dead-config must not list the table (BACKLOG #5621)."""
    config_dir = _write_helpers_codeset_config(tmp_path)
    registry = load_config(config_dir)
    index = build_reference_index(registry)
    assert delete_impact(index, "code_set", table) == [
        Reference("handler", "h_hs", "code_set", table)
    ]
    assert ("code_set", table) not in index.unreferenced(registry)


@pytest.mark.parametrize("table", ["diets", "meals_table", "allow_list"])
def test_rename_rewrites_module_top_helper_and_predicate_table_reads(
    tmp_path: Path, table: str
) -> None:
    """BACKLOG #5620: the rename planner rewrites the referent where it is written, not only inside
    the handler's own body, and the renamed graph still loads."""
    config_dir = _write_helpers_codeset_config(tmp_path)
    result = codeset_edit.rename_code_set(config_dir, table, "renamed", validate=_validate_code_set)
    assert result["referents_rewritten"] == 1
    assert "referents_unresolved" not in result
    mod = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert f'code_set("{table}")' not in mod
    assert 'code_set("renamed")' in mod
    load_config(config_dir)


_MODULE_CONSTANT_TARGET_MOD = (
    "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_MC", MLLP(port=2793), router="r_mc")\n'
    'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6910))\n'
    "\n"
    'TARGET = "OB_OLD"\n'
    "\n"
    "\n"
    '@router("r_mc")\n'
    "def r_mc(msg):\n"
    '    return ["h_mc"]\n'
    "\n"
    "\n"
    '@handler("h_mc")\n'
    "def h_mc(msg):\n"
    "    return Send(TARGET, msg)\n"
)


_SIBLING_HELPERS_MOD = (
    "import _shared\n"
    "from _shared import label\n"
    "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_SH", MLLP(port=2799), router="r_sh")\n'
    'outbound("OB_SH", MLLP(host="127.0.0.1", port=6940))\n'
    "\n"
    "\n"
    '@router("r_sh")\n'
    "def r_sh(msg):\n"
    '    return ["h_sh"]\n'
    "\n"
    "\n"
    '@handler("h_sh")\n'
    "def h_sh(msg):\n"
    '    value = label("A")\n'
    '    other = _shared.kinds("A")\n'
    '    return Send("OB_SH", msg)\n'
)

_SIBLING_HELPERS = (
    "from messagefoundry import code_set\n"
    "\n"
    'KINDS = code_set("kinds")\n'
    "\n"
    "\n"
    "def label(code):\n"
    '    return code_set("diets").get(code)\n'
    "\n"
    "\n"
    "def kinds(code):\n"
    "    return KINDS.get(code)\n"
)


@pytest.mark.parametrize("table", ["diets", "kinds"])
def test_table_reads_in_a_sibling_helper_module_are_referent_sites(
    tmp_path: Path, table: str
) -> None:
    """BACKLOG #5620/#5621: a table read in a ``_``-prefixed helper module, reached by a ``from``
    import or through the module (``_shared.kinds``), is a referent of the handler and rewrites."""
    config_dir = _write_config(
        tmp_path, {"mod.py": _SIBLING_HELPERS_MOD, "_shared.py": _SIBLING_HELPERS}
    )
    codesets = config_dir / "codesets"
    codesets.mkdir()
    for name in ("diets", "kinds"):
        (codesets / f"{name}.csv").write_text("code,value\nA,Apple\n", encoding="utf-8", newline="")
    registry = load_config(config_dir)
    index = build_reference_index(registry)
    assert delete_impact(index, "code_set", table) == [
        Reference("handler", "h_sh", "code_set", table)
    ]

    result = codeset_edit.rename_code_set(config_dir, table, "renamed", validate=_validate_code_set)
    assert result["referents_rewritten"] == 1
    assert "referents_unresolved" not in result
    assert 'code_set("renamed")' in (config_dir / "_shared.py").read_text(encoding="utf-8")
    load_config(config_dir)


def test_rename_rewrites_a_module_level_target_constant(tmp_path: Path) -> None:
    """BACKLOG #5620: ``Send(TARGET)`` with ``TARGET = "OB_OLD"`` at module scope is a referent; the
    planner rewrites the constant, so the applied rename leaves a config that loads."""
    config_dir = _write_config(tmp_path, {"mod.py": _MODULE_CONSTANT_TARGET_MOD})
    registry = load_config(config_dir)
    plan = plan_rename(registry, config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    text = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert 'TARGET = "OB_NEW"' in text
    assert '"OB_OLD"' not in text
    load_config(config_dir)


# The body carries one rewritable referent and one the tokenizer refuses to split.
_PARTIAL_EDIT_MOD = (
    "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
    "\n"
    'inbound("IB_PE", MLLP(port=2795), router="r_pe")\n'
    'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6920))\n'
    "\n"
    "\n"
    '@router("r_pe")\n'
    "def r_pe(msg):\n"
    '    return ["h_pe"]\n'
    "\n"
    "\n"
    '@handler("h_pe")\n'
    "def h_pe(msg):\n"
    "    if msg is None:\n"
    '        return Send("OB_" "OLD", msg)\n'
    '    return Send("OB_OLD", msg)\n'
)


def test_unresolved_report_is_per_site_not_any_edit_in_the_body(tmp_path: Path) -> None:
    """BACKLOG #5620: one rewritten literal in the body must not mark a second, unrewritable referent
    in the same body as covered."""
    config_dir = _write_config(tmp_path, {"mod.py": _PARTIAL_EDIT_MOD})
    registry = load_config(config_dir)
    plan = plan_rename(registry, config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == (Reference("handler", "h_pe", "outbound", "OB_OLD"),)


# A code set and a Reference declaration that share one name, each read by its own handler.
_SAME_NAME_TABLES_MOD = (
    "from messagefoundry import FileRef, MLLP, Reference, Send, code_set, handler, inbound, "
    "outbound, reference, router\n"
    "\n"
    'inbound("IB_SN", MLLP(port=2797), router="r_sn")\n'
    'outbound("OB_SN", MLLP(host="127.0.0.1", port=6930))\n'
    'Reference("shared", source=FileRef(path="shared.csv"))\n'
    "\n"
    "\n"
    '@router("r_sn")\n'
    "def r_sn(msg):\n"
    '    return ["h_code", "h_ref"]\n'
    "\n"
    "\n"
    '@handler("h_code")\n'
    "def h_code(msg):\n"
    '    label = code_set("shared").get("A")\n'
    '    return Send("OB_SN", msg)\n'
    "\n"
    "\n"
    '@handler("h_ref")\n'
    "def h_ref(msg):\n"
    '    npi = reference("shared").get("x")\n'
    '    return Send("OB_SN", msg)\n'
)


def _write_same_name_config(tmp_path: Path) -> Path:
    config_dir = _write_config(tmp_path, {"mod.py": _SAME_NAME_TABLES_MOD})
    codesets = config_dir / "codesets"
    codesets.mkdir()
    (codesets / "shared.csv").write_text("code,value\nA,Apple\n", encoding="utf-8", newline="")
    return config_dir


def test_same_named_code_set_and_reference_keep_their_own_kinds(tmp_path: Path) -> None:
    """BACKLOG #5621: a code set and a reference that share a name are two objects; each keeps its
    own referrer, and neither reads as dead."""
    config_dir = _write_same_name_config(tmp_path)
    registry = load_config(config_dir)
    index = build_reference_index(registry)
    assert delete_impact(index, "code_set", "shared") == [
        Reference("handler", "h_code", "code_set", "shared")
    ]
    assert delete_impact(index, "reference", "shared") == [
        Reference("handler", "h_ref", "reference", "shared")
    ]
    assert index.unreferenced(registry) == []


def test_renaming_one_of_two_same_named_tables_leaves_the_other_alone(tmp_path: Path) -> None:
    """BACKLOG #5621: renaming the code set rewrites its own read and leaves the reference's."""
    config_dir = _write_same_name_config(tmp_path)
    result = codeset_edit.rename_code_set(
        config_dir, "shared", "renamed", validate=_validate_code_set
    )
    assert result["referents_rewritten"] == 1
    assert "referents_unresolved" not in result
    mod = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert 'code_set("renamed")' in mod
    assert 'reference("shared")' in mod
    assert 'Reference("shared"' in mod


def _codeset_dir(tmp_path: Path, files: dict[str, str], *tables: str) -> Path:
    config_dir = _write_config(tmp_path, files)
    codesets = config_dir / "codesets"
    codesets.mkdir()
    for name in tables:
        (codesets / f"{name}.csv").write_text("code,value\nA,Apple\n", encoding="utf-8", newline="")
    return config_dir


_PREAMBLE = (
    "from messagefoundry import FileRef, MLLP, Reference, Send, code_set, handler, "
    "inbound, outbound, reference, router\n"
    "\n"
    'inbound("IB_Q", MLLP(port=2801), router="r_q")\n'
    'outbound("OB_Q", MLLP(host="127.0.0.1", port=6950))\n'
    "\n"
    "\n"
    '@router("r_q")\n'
    "def r_q(msg):\n"
    '    return ["h_q"]\n'
    "\n"
    "\n"
)


def test_an_accessor_inside_an_fstring_replacement_field_is_a_referent(tmp_path: Path) -> None:
    """A code set and a reference share a name; the code set is read once plainly and once inside
    an f-string's replacement field. The rename rewrites both reads, and the reference read inside an
    f-string elsewhere keeps the reference live."""
    body = _PREAMBLE + (
        'Reference("shared", source=FileRef(path="shared.csv"))\n'
        "\n"
        "\n"
        '@handler("h_q")\n'
        "def h_q(msg):\n"
        '    a = code_set("shared").get("A")\n'
        "    b = f\"{code_set('shared').get('A')}\"\n"
        "    c = f\"{reference('shared').get('x')}\"\n"
        '    return Send("OB_Q", msg)\n'
    )
    config_dir = _codeset_dir(tmp_path, {"mod.py": body}, "shared")
    registry = load_config(config_dir)
    index = build_reference_index(registry)
    assert delete_impact(index, "reference", "shared") == [
        Reference("handler", "h_q", "reference", "shared")
    ]
    plan = plan_rename(registry, config_dir, "code_set", "shared", "renamed")
    assert plan.unresolved == ()
    assert len(plan.edits) == 2


def test_a_bound_method_predicate_still_counts_its_table(tmp_path: Path) -> None:
    body = _PREAMBLE + (
        "class _Gate:\n"
        "    def ok(self, msg):\n"
        '        return "A" in code_set("allow_list")\n'
        "\n"
        "\n"
        "_GATE = _Gate()\n"
        "\n"
        "\n"
        '@handler("h_q", accepts=_GATE.ok)\n'
        "def h_q(msg):\n"
        '    return Send("OB_Q", msg)\n'
    )
    config_dir = _codeset_dir(tmp_path, {"mod.py": body}, "allow_list")
    registry = load_config(config_dir)
    index = build_reference_index(registry)
    assert delete_impact(index, "code_set", "allow_list") == [
        Reference("handler", "h_q", "code_set", "allow_list")
    ]


def test_a_capture_inside_a_module_level_try_is_rewritten(tmp_path: Path) -> None:
    body = _PREAMBLE + (
        "try:\n"
        '    DIETS = code_set("diets")\n'
        "except ValueError:\n"
        "    DIETS = {}\n"
        "\n"
        "\n"
        '@handler("h_q")\n'
        "def h_q(msg):\n"
        '    a = DIETS.get("A")\n'
        '    b = code_set("diets").get("A")\n'
        '    return Send("OB_Q", msg)\n'
    )
    config_dir = _codeset_dir(tmp_path, {"mod.py": body}, "diets")
    result = codeset_edit.rename_code_set(
        config_dir, "diets", "renamed", validate=_validate_code_set
    )
    assert result["referents_rewritten"] == 2
    assert "referents_unresolved" not in result
    assert 'code_set("diets")' not in (config_dir / "mod.py").read_text(encoding="utf-8")


def test_a_capture_imported_by_name_from_a_helper_is_reported_unresolved(tmp_path: Path) -> None:
    """``from _shared import KINDS`` hides where the code set is captured, so the planner cannot
    rewrite it. One plain read beside it must not make the referrer read as covered."""
    body = (
        "from _shared import KINDS\n"
        + _PREAMBLE
        + (
            '@handler("h_q")\n'
            "def h_q(msg):\n"
            '    a = KINDS.get("A")\n'
            '    b = code_set("kinds").get("A")\n'
            '    return Send("OB_Q", msg)\n'
        )
    )
    helper = 'from messagefoundry import code_set\n\nKINDS = code_set("kinds")\n'
    config_dir = _codeset_dir(tmp_path, {"mod.py": body, "_shared.py": helper}, "kinds")
    registry = load_config(config_dir)
    plan = plan_rename(registry, config_dir, "code_set", "kinds", "renamed")
    assert plan.unresolved == (Reference("handler", "h_q", "code_set", "kinds"),)


def test_a_helper_literal_that_is_not_a_table_read_is_left_alone(tmp_path: Path) -> None:
    body = _PREAMBLE + (
        'LABELS = {"diets": "Diet orders"}\n'
        "\n"
        "\n"
        "def _label(k):\n"
        '    if k == "diets":\n'
        '        return LABELS["diets"]\n'
        '    return code_set("diets").get(k)\n'
        "\n"
        "\n"
        '@handler("h_q")\n'
        "def h_q(msg):\n"
        '    a = _label("A")\n'
        '    return Send("OB_Q", msg)\n'
    )
    config_dir = _codeset_dir(tmp_path, {"mod.py": body}, "diets")
    result = codeset_edit.rename_code_set(
        config_dir, "diets", "renamed", validate=_validate_code_set
    )
    assert result["referents_rewritten"] == 1
    text = (config_dir / "mod.py").read_text(encoding="utf-8")
    assert 'LABELS = {"diets": "Diet orders"}' in text
    assert 'if k == "diets":' in text
    assert 'code_set("renamed").get(k)' in text


def test_a_method_call_is_not_read_as_a_module_function(tmp_path: Path) -> None:
    """``code_set("units").get(...)`` calls the CodeSet's ``get``; a module function named ``get``
    that reads another table is not a helper of the handler."""
    body = _PREAMBLE + (
        "def get(code):\n"
        '    return code_set("diets").get(code)\n'
        "\n"
        "\n"
        '@handler("h_q")\n'
        "def h_q(msg):\n"
        '    a = code_set("units").get("A")\n'
        '    return Send("OB_Q", msg)\n'
    )
    config_dir = _codeset_dir(tmp_path, {"mod.py": body}, "diets", "units")
    index = build_reference_index(load_config(config_dir))
    assert delete_impact(index, "code_set", "diets") == []


@pytest.mark.parametrize(
    "capture",
    [
        ('DIET_TABLE = "diets"\n', "def h_q(msg):\n    a = code_set(DIET_TABLE)\n"),
        ("", 'def h_q(msg, cs=code_set("diets")):\n    a = cs.get("A")\n'),
    ],
)
def test_a_name_constant_or_a_default_argument_is_a_live_table_read(
    tmp_path: Path, capture: tuple[str, str]
) -> None:
    module_top, handler_def = capture
    body = (
        _PREAMBLE
        + module_top
        + '\n\n@handler("h_q")\n'
        + handler_def
        + '    return Send("OB_Q", msg)\n'
    )
    config_dir = _codeset_dir(tmp_path, {"mod.py": body}, "diets")
    registry = load_config(config_dir)
    assert delete_impact(build_reference_index(registry), "code_set", "diets") == [
        Reference("handler", "h_q", "code_set", "diets")
    ]
    result = codeset_edit.rename_code_set(
        config_dir, "diets", "renamed", validate=_validate_code_set
    )
    assert result["referents_rewritten"] == 1
    assert "referents_unresolved" not in result
    load_config(config_dir)


def test_a_binding_the_plan_cannot_rewrite_leaves_the_referrer_unresolved(tmp_path: Path) -> None:
    body = _PREAMBLE + (
        'A, B = "diets", "x"\n'
        "\n"
        "\n"
        '@handler("h_q")\n'
        "def h_q(msg):\n"
        "    a = code_set(A)\n"
        '    b = code_set("diets").get("A")\n'
        '    return Send("OB_Q", msg)\n'
    )
    config_dir = _codeset_dir(tmp_path, {"mod.py": body}, "diets")
    plan = plan_rename(load_config(config_dir), config_dir, "code_set", "diets", "renamed")
    assert plan.unresolved == (Reference("handler", "h_q", "code_set", "diets"),)


def test_a_helper_default_naming_the_table_is_rewritten(tmp_path: Path) -> None:
    body = _PREAMBLE + (
        'def _lookup(code, table="diets"):\n'
        "    return code_set(table).get(code)\n"
        "\n"
        "\n"
        '@handler("h_q")\n'
        'def h_q(msg, *, cs=code_set("diets")):\n'
        '    a = _lookup("A")\n'
        '    return Send("OB_Q", msg)\n'
    )
    config_dir = _codeset_dir(tmp_path, {"mod.py": body}, "diets")
    result = codeset_edit.rename_code_set(
        config_dir, "diets", "renamed", validate=_validate_code_set
    )
    assert result["referents_rewritten"] == 2
    assert "referents_unresolved" not in result
    load_config(config_dir)


def test_a_send_in_a_helper_is_rewritten_with_the_handlers_own(tmp_path: Path) -> None:
    body = (
        "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
        "\n"
        'inbound("IB_HF", MLLP(port=2803), router="r_hf")\n'
        'outbound("OB_OLD", MLLP(host="127.0.0.1", port=6960))\n'
        "\n"
        "\n"
        "def _fallback(msg):\n"
        '    return Send("OB_OLD", msg)\n'
        "\n"
        "\n"
        '@router("r_hf")\n'
        "def r_hf(msg):\n"
        '    return ["h_hf"]\n'
        "\n"
        "\n"
        '@handler("h_hf")\n'
        "def h_hf(msg):\n"
        "    if msg is None:\n"
        "        return [_fallback(msg)]\n"
        '    return Send("OB_OLD", msg)\n'
    )
    config_dir = _write_config(tmp_path, {"mod.py": body})
    plan = plan_rename(load_config(config_dir), config_dir, "outbound", "OB_OLD", "OB_NEW")
    assert plan.unresolved == ()
    apply_rename(plan)
    assert '"OB_OLD"' not in (config_dir / "mod.py").read_text(encoding="utf-8")


def test_a_callable_with_a_raising_getattr_does_not_break_the_index(tmp_path: Path) -> None:
    body = _PREAMBLE + (
        "import functools\n"
        "\n"
        "\n"
        "class _Lazy:\n"
        "    def __call__(self, x):\n"
        "        return x\n"
        "\n"
        "    def __getattr__(self, name):\n"
        '        raise RuntimeError("not initialised")\n'
        "\n"
        "\n"
        "LAZY = _Lazy()\n"
        "\n"
        "\n"
        "def _gate(flag, msg):\n"
        "    return flag\n"
        "\n"
        "\n"
        '@handler("h_q", accepts=functools.partial(_gate, True))\n'
        "def h_q(msg):\n"
        "    LAZY(1)\n"
        '    return Send("OB_Q", msg)\n'
    )
    config_dir = _write_config(tmp_path, {"mod.py": body})
    registry = load_config(config_dir)
    build_reference_index(registry)
    plan = plan_rename(registry, config_dir, "outbound", "OB_Q", "OB_R")
    assert plan.unresolved == ()


@pytest.mark.parametrize("decorator", ["@_Trace", "@functools.cache"])
def test_a_handler_behind_a_non_function_wrapper_keeps_its_table(
    tmp_path: Path, decorator: str
) -> None:
    """A class-based decorator that calls functools.update_wrapper, or functools.cache, wraps the
    handler in an object that is not a function. Its __wrapped__ is followed, as inspect.unwrap did,
    so the table it reads is not reported dead, and the rename still rewrites the read."""
    body = (
        "import functools\n"
        + _PREAMBLE
        + (
            "class _Trace:\n"
            "    def __init__(self, fn):\n"
            "        functools.update_wrapper(self, fn)\n"
            "        self._fn = fn\n"
            "\n"
            "    def __call__(self, msg):\n"
            "        return self._fn(msg)\n"
            "\n"
            "\n"
            '@handler("h_q")\n'
            f"{decorator}\n"
            "def h_q(msg):\n"
            '    a = code_set("diets").get("A")\n'
            '    return Send("OB_Q", msg)\n'
        )
    )
    config_dir = _codeset_dir(tmp_path, {"mod.py": body}, "diets")
    registry = load_config(config_dir)
    index = build_reference_index(registry)
    assert delete_impact(index, "code_set", "diets") == [
        Reference("handler", "h_q", "code_set", "diets")
    ]
    assert ("code_set", "diets") not in index.unreferenced(registry)
    plan = plan_rename(registry, config_dir, "code_set", "diets", "renamed")
    assert plan.unresolved == ()
    assert len(plan.edits) == 1


def test_a_form_feed_line_does_not_shift_the_rename(tmp_path: Path) -> None:
    body = _PREAMBLE + (
        "\x0c\n"
        '@handler("h_q")\n'
        "def h_q(msg):\n"
        '    a = 1; b = code_set("diets").get("A")\n'
        '    return Send("OB_Q", msg)\n'
    )
    config_dir = _codeset_dir(tmp_path, {"mod.py": body}, "diets")
    registry = load_config(config_dir)
    plan = plan_rename(registry, config_dir, "code_set", "diets", "renamed")
    assert plan.unresolved == ()
    assert len(plan.edits) == 1
