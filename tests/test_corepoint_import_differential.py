# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Differential no-fail-open guard for the Corepoint importer's handle flow (BACKLOG #313 step 2).

Step 1 (on main at the time of writing) raises at a role-parsed ``MsgSend`` that does not provably
deliver ``msg``. Step 2 binds each message handle to a Python local and may turn such a raise into a
send, but only into a CORRECT one. Every review round of step 2 found a new shape in which the
generated handler sent a message Corepoint never sent, and most were introduced by the previous
round's repair. This guard exists so the next repair is checked against every shape at once rather
than against the one it was written for.

**How it works.** A small grammar generates action-list SHAPES: statements (clone, ``MsgCreate``,
field write, log, send, statements the import does not read, exits) inside constructs (If, ElseIf,
Else in five export spellings and with a disabled branch line, ChooseFrom, ForEach in several
spellings of what it binds, Loop, Try and Catch in three spellings, Block with a prose or a
statement label, an inlined or bare ``ActionListCall``, an unmodelled tag, a ``<Line>`` carrying a
nested list, ``@Disabled`` with a sure and an unsure value on a whole construct or on one branch
marker, and a branch marker with no construct), with role markup present, absent or mixed and with
hostile handle spellings. Each shape is rendered to XML and imported twice: by the head importer and
by the step 1 importer, vendored byte-for-byte from main at ``bca583f2a`` (blob ``b88e7152``) as
``tests/fixtures/corepoint/step1_corepoint_import.py.txt``. A vendored copy, not ``git show
origin/main``, because once step 2 merges ``origin/main`` IS the head, and the comparison would become
the head against itself; and because a CI checkout need not hold that ref. The vendored file is never
edited. The baseline the guard runs is that file plus the amendments in ``_STEP1_AMENDMENTS``, made
as it loads: the changes the step 1 code path has gained on purpose since that tree. There is one,
BACKLOG #2632, and ``test_the_amendment_changes_only_a_list_holding_a_statement_off_a_line`` bounds
what it may change against the file exactly as vendored. The bound is one rule: the amended
baseline, and the head wherever the gate is closed, are never QUIETER than that file. No refusal
goes, no marked ending goes, and nothing main counted unmapped goes uncounted (:func:`_quieter`).
``test_no_raw_list_is_quieter_than_main`` asks the same of lists drawn with no grammar.

**The invariant (the whole-list gate, ADR 0086).** For every shape, EITHER the head's generated
module and summary counts are step 1's byte for byte (the gate is closed), OR the guard's own
allow-list walker (:func:`_fully_understood`, written apart from the importer and never calling its
gate) finds every element of the list allow-listed AND every oracle check below passes (the gate is
open). The constructs above close the gate, so most of the battery is a byte-identity check; the
shapes drawn from the allow-list alone (:func:`_open_shapes`) open it, and one in four carries one
spoiler just off the allow-list to test its edge.

Each shape also carries its own ORACLE: an abstract interpreter over the shape (not over the XML)
that says, for every ``MsgSend``, which trees the export may send there, over every path, and in
both a case-sensitive and a case-insensitive reading of handle names (Corepoint's is unverified),
and which literals each tree held AT the send. Anything the oracle does not model makes every handle
unknown. Where the gate is open, the generated handlers are EXECUTED against one synthetic input,
and their source is read, and the guard asserts:

1. (i) the head never delivers where step 1 raises or filters unless the oracle proves the tree,
   and the delivered message carries no literal its tree did not hold at the send (a write after a
   send must not reach the message already sent);
2. (ii) the head never lifts a send out of a branch: no send line sits at a shallower indent than in
   step 1, and no send the oracle places in a branch runs on the all-placeholders-false path;
3. (iii) the head never delivers ``msg`` for a send of another handle, or of a tree the oracle
   proves is not the input;
4. every LIVE send line in the head is provable on every path: the oracle's tree set at that send is
   exactly one known tree, of the same kind as the local (``msg`` only for the input itself). This
   reaches the branches the executed path skips;
5. a local other than ``msg`` is bound, and sent, only at the handler's own level (the gate admits
   no construct, ADR 0086). Together with an execution that runs past every refusal (each ``raise
   NotImplementedError`` is read as a human deleting it), that puts every such send on the executed
   path, so (i) compares the tree it actually delivers, not only its kind.

All fixtures are synthetic. The shapes come from a fixed seed, so a failure is reproducible.
"""

from __future__ import annotations

import hashlib
import html
import random
import re
import sys
import types
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import corepoint_import as head
from messagefoundry.config.wiring import Registry, _loading
from messagefoundry.parsing.message import Message

# --- the step 1 importer --------------------------------------------------------------------------

_STEP1_PATH = Path(__file__).parent / "fixtures" / "corepoint" / "step1_corepoint_import.py.txt"
# The git blob id of messagefoundry/corepoint_import.py at main bca583f2a, the last step 1 tree.
_STEP1_BLOB = "b88e7152853c36b0611422541ec922dafda55d97"


def _step1_bytes() -> bytes:
    # A Windows checkout may hold the fixture with CRLF; git stores it with LF.
    return _STEP1_PATH.read_bytes().replace(b"\r\n", b"\n")


# What the step 1 code path has gained since that tree, as ``(text the vendored file holds exactly
# once, what replaces it)``. The vendored file itself is never edited: its blob id stays pinned, and
# the baseline the guard runs is that file with these replacements made when it loads.
#
# BACKLOG #2632, the one amendment so far. A statement in the ``@Data`` of an element that is not a
# ``<Line>`` used to render as a label, as the text of a dead condition, as a live send, or not at
# all, while the handle scan counted its clone. The step 1 path now marks that statement as a counted
# TODO, never emits it as a write or a delivery, refuses it where it is a send, and holds no handle
# for the list. A list the gate declines takes that path, so "renders as step 1" has to mean this
# path, or the guard would fail on the repair itself. The rule is copied here as text, apart from
# the head, so a later change to the head's rule turns the guard red until someone amends this copy
# on purpose.
_LABEL_RULE = """\
_STATEMENT_VERBS = frozenset(
    {"itemappend", "itemclear", "itemcopy", "msgcreate", "msglog", "msgsend", "msgtreecopy"}
)
_LABEL_STATEMENT_WHY = (
    "not on a Line, so it may never have run; nothing is mapped and no role-marked handle here "
    "is taken to be msg"
)
_LABEL_SEND_REFUSAL = (
    "MsgSend is not on a Line, so it may never have run; nothing is mapped and no role-marked "
    "handle here is taken to be msg; the import refuses to send msg in its place"
)


@dataclass(frozen=True)
class LabelMarker(UnmappedAction):
    pass


@dataclass(frozen=True)
class _Demoted(Control):
    was: str = ""


def _label_statement(elem: Element) -> str:
    tag = _local(elem.tag).lower()
    if tag == "line":
        return ""
    data = _attr(elem, "Data")
    roles = parse_roles(data)
    verb = _statement_verb(roles, _split_verb(strip_markup(data))[0])
    lowered = verb.lower()
    kind = _CONTAINER_KIND_BY_TAG.get(tag)
    if kind is not None:
        rendered = _statement_kind(tag, verb)
        if rendered != "send" and rendered == _KIND_BY_VERB.get(lowered):
            return ""
    leads = next((token for token in roles if token.role not in _PROSE_ROLES), None)
    bare = kind == "block" or tag in _LIST_TAGS
    styled = bare and leads is not None and leads.role == "keyword" and _role_verb(roles)
    return verb if lowered in _STATEMENT_VERBS or styled else ""


def _label_marker(elem: Element) -> list[LabelMarker]:
    carried = _label_statement(elem)
    if not carried:
        return []
    statement = strip_markup(_attr(elem, "Data"))
    return [LabelMarker(carried, f"{_LABEL_STATEMENT_WHY}: {statement}")]


"""
_SOURCE_LABEL_DEF = "def _source_label(tag: str, verb: str) -> str:\n"
_SCAN_SKIP = (
    "        if not tokens:\n            continue  # markup-free: no handle roles to learn from\n"
)
_WRAPPER_FLATTEN = (
    "            steps.extend(_parse_list(child, subject, held, in_control, depth + 1))\n"
)
_SIBLING_PARSE = (
    "        produced = _parse_statement(child, subject, held, in_control, depth + 1)\n"
)
_SIBLING_KEPT = "            continue\n        steps.extend(produced)\n"
_BARE_MARKER = "and step.kind in _BRANCH_PARENT and not step.body:\n"
_BRANCH_BODY = "branches.append(replace(marker, body=tuple(steps[start:i])))\n"
_LAST_BRANCH_BODY = "branches.append(replace(marker, body=tuple(steps[start:])))\n"
_BRANCH_GROUP = "any(isinstance(s, Control) and s.kind == kind for s in body):\n"
_SEND_REFUSAL = '        refusal = _send_refusal(role_operands, held) if roles else ""\n'
_UNKNOWN_ARM = "    if tag.lower() not in _STATEMENT_TAGS:\n"
_UNKNOWN_RETURN = '        return [Control("unknown", tag, statement or note, body=tuple(body))]\n'
_BLOCK_RETURN = "return [Control(kind, source, statement or note or tag, body=tuple(body))]\n"
_CONSTRUCT_RETURN = "    return [Control(kind, source, detail, body=inner, branches=branches)]\n"
_STEP1_AMENDMENTS: tuple[tuple[str, str], ...] = (
    # The rule and its marker, just after ``_statement_kind``, which the rule calls.
    (_SOURCE_LABEL_DEF, _LABEL_RULE + _SOURCE_LABEL_DEF),
    # The scan: a list holding such a statement holds no handle at all.
    (
        _SCAN_SKIP,
        "        if _label_statement(elem):\n            return frozenset(), frozenset()\n"
        + _SCAN_SKIP,
    ),
    # The render, a ``<List>`` wrapper: the marker where the wrapper sits, ahead of its
    # flattened body.
    (_WRAPPER_FLATTEN, "            steps.extend(_label_marker(child))\n" + _WRAPPER_FLATTEN),
    # The adoption of a sibling branch never sees a marker, at any depth. Written apart from the
    # head, which holds the markers back from the list until a statement position follows them.
    # Here the markers are lifted off the end of the list, main's own adoption runs untouched on
    # what is left, and they go back after whatever it did.
    (
        _SIBLING_PARSE,
        _SIBLING_PARSE + "        lifted: list[Step] = []\n"
        "        while steps and isinstance(steps[-1], LabelMarker):\n"
        "            lifted.insert(0, steps.pop())\n",
    ),
    (
        _SIBLING_KEPT,
        "            steps.extend(lifted)\n"
        "            continue\n"
        "        steps.extend(lifted)\n"
        "        steps.extend(produced)\n",
    ),
    # The render, an unmodelled tag: the statement is named in the marker that tag already has.
    (_UNKNOWN_ARM, "    marker = _label_marker(elem)\n" + _UNKNOWN_ARM),
    (
        _UNKNOWN_RETURN,
        "        detail = marker[0].detail if marker else statement or note\n"
        '        return [Control("unknown", tag, detail, body=tuple(body))]\n'
        # A Call carrying a statement is a plain label, and no call: the label, its marker and
        # its body beneath. It remembers the kind it had.
        '    if marker and kind == "call":\n'
        '        return [_Demoted("block", tag, statement, body=(*marker, *body), was=kind)]\n',
    ),
    # A send in a Block's or a Call's ``@Data`` is never a delivery, and never a comment either.
    # It stays the send main made of it, in main's own send arm, and is always refused. So it
    # raises where main raised or delivered, its destination stays declared, and the handler
    # keeps the closing ``return`` main gave it. Written apart from the head, which chooses the
    # refusal in an ``if`` and an ``else``.
    (
        _SEND_REFUSAL,
        _SEND_REFUSAL + "        if marker:\n            refusal = _LABEL_SEND_REFUSAL\n",
    ),
    # The shape of the tree is main's. The branch-group test reads the kind a demoted label had.
    # And a branch marker holding nothing but label markers still opens its branch, and keeps
    # them. Written apart from the head, which asks one function for the kind and tests the
    # marker's body with ``all``.
    (_BRANCH_GROUP, _BRANCH_GROUP.replace("s.kind", 'getattr(s, "was", s.kind)')),
    (
        _BARE_MARKER,
        _BARE_MARKER.replace(
            "not step.body", "not [s for s in step.body if not isinstance(s, LabelMarker)]"
        ),
    ),
    (
        _BRANCH_BODY,
        _BRANCH_BODY.replace("tuple(steps[start:i])", "(*marker.body, *steps[start:i])"),
    ),
    (
        _LAST_BRANCH_BODY,
        _LAST_BRANCH_BODY.replace("tuple(steps[start:])", "(*marker.body, *steps[start:])"),
    ),
    # The render, a container: the marker ahead of its body, or ahead of the construct.
    (_BLOCK_RETURN, _BLOCK_RETURN.replace("body=tuple(body)", "body=(*marker, *body)")),
    (_CONSTRUCT_RETURN, _CONSTRUCT_RETURN.replace("[Control(", "[*marker, Control(")),
)


def _load_step1(name: str, amendments: tuple[tuple[str, str], ...]) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    source = _step1_bytes().decode("utf-8")
    for found, replacement in amendments:
        # Exactly once, so an amendment can neither miss nor land somewhere it was not meant to.
        assert source.count(found) == 1, f"the vendored step 1 file holds {found!r} other than once"
        source = source.replace(found, replacement)
    module = types.ModuleType(name)
    # dataclasses resolve string annotations through sys.modules, so register before running it.
    sys.modules[name] = module
    # An amended source is compiled under its own name: a traceback must not quote the vendored
    # file's lines for code that sits at other lines once amended.
    filename = f"<{_STEP1_PATH.name} amended>" if amendments else str(_STEP1_PATH)
    exec(compile(source, filename, "exec"), module.__dict__)
    return module


#: The baseline: the step 1 code path as it stands, which a gate-declined list must match.
step1: Any = _load_step1("_mefor_corepoint_import_step1", _STEP1_AMENDMENTS)
#: The vendored tree exactly as main held it, with no amendment. Only the amendment's own test reads it.
step1_as_vendored: Any = _load_step1("_mefor_corepoint_import_step1_as_vendored", ())


def test_the_step1_fixture_is_mains_step1_importer_byte_for_byte() -> None:
    """The baseline is only a baseline if nobody edited it. Its git blob id is pinned."""
    data = _step1_bytes()
    blob = hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()
    assert blob == _STEP1_BLOB


# --- the shape grammar ----------------------------------------------------------------------------


@dataclass(frozen=True)
class H:
    """A handle reference: its spelling, and the span class (``""``: input-handle for the input's
    exact spelling, other-handle for anything else)."""

    name: str
    cls: str = ""


@dataclass(frozen=True)
class Clone:
    src: H
    dst: H
    uid: int
    markup: bool = True


@dataclass(frozen=True)
class Create:
    h: H
    k: int
    good: bool = True
    markup: bool = True


@dataclass(frozen=True)
class Write:
    h: H
    lit: str
    path: str = "/PID-8"
    markup: bool = True
    verb: str = "ItemCopy"  # ItemCopy | ItemAppend | ItemClear (which ignores ``lit``)


@dataclass(frozen=True)
class Log:
    h: H
    markup: bool = True


@dataclass(frozen=True)
class SendS:
    h: H
    dest: str
    markup: bool = True


@dataclass(frozen=True)
class Unread:
    """A statement the oracle does not model: every handle is unknown after it."""

    kind: str  # "merge" | "var" | "worded"
    a: H
    b: H
    markup: bool = True


@dataclass(frozen=True)
class Exit:
    verb: str = "ActionListExit"


@dataclass(frozen=True)
class LoopExit:
    pass


@dataclass(frozen=True)
class Raw:
    """A verbatim element, for the fixed seeds. ``havoc``: every handle is unknown after it."""

    xml: str
    havoc: bool = True


Arm = tuple[str, "H | None", "tuple[Node, ...]"]


@dataclass(frozen=True)
class If:
    arms: tuple[Arm, ...]
    form: str = "inbody"  # inbody | wrapper | wrapper-bare | lines | sibling
    # The index of an arm whose own line carries @Disabled="1" (-1: none). Not for "inbody", where
    # the first arm's line is the construct itself.
    off_arm: int = -1


@dataclass(frozen=True)
class Case:
    pre: tuple[Node, ...]
    arms: tuple[tuple[Node, ...], ...]


@dataclass(frozen=True)
class Each:
    body: tuple[Node, ...]
    over: H | None = None
    form: str = "elem"  # elem | line


@dataclass(frozen=True)
class Loop:
    body: tuple[Node, ...]


@dataclass(frozen=True)
class Try:
    body: tuple[Node, ...]
    catches: tuple[tuple[Node, ...], ...]
    into: H | None = None
    form: str = "inbody"  # inbody | wrapper | sibling


@dataclass(frozen=True)
class Block:
    body: tuple[Node, ...]
    # A label that is itself a writing statement (the pre-existing label defect): havoc first.
    label: str = "Section"
    havoc: bool = False


@dataclass(frozen=True)
class Call:
    body: tuple[Node, ...]
    passing: str = ""
    inlined: bool = True


@dataclass(frozen=True)
class Unknown:
    body: tuple[Node, ...]


@dataclass(frozen=True)
class Off:
    node: Node
    value: str = "1"


@dataclass(frozen=True)
class Orphan:
    """A branch marker with no construct to continue (or one carrying ``@Disabled``, which no
    construct can continue either); what follows it may or may not run."""

    kind: str
    body: tuple[Node, ...]
    disabled: str = ""


@dataclass(frozen=True)
class FlatOpen:
    """A construct line that owns nothing, then its would-be body as siblings, then ``EndIf``: the
    flat form some exporter may write. Whether the siblings are conditional is not known."""

    body: tuple[Node, ...]


@dataclass(frozen=True)
class OffList:
    """A ``<List>`` wrapper carrying ``@Disabled``: whether its statements run is not known."""

    body: tuple[Node, ...]


@dataclass(frozen=True)
class Nested:
    """A ``<Line>`` whose verb is no construct, carrying a nested list: an unmodelled construct."""

    body: tuple[Node, ...]
    verb: str = "Otherwise"


Node = (
    Clone
    | Create
    | Write
    | Log
    | SendS
    | Unread
    | Exit
    | LoopExit
    | Raw
    | If
    | Case
    | Each
    | Loop
    | Try
    | Block
    | Call
    | Unknown
    | Off
    | Orphan
    | Nested
    | FlatOpen
    | OffList
)


@dataclass(frozen=True)
class Shape:
    name: str
    inp: str
    nodes: tuple[Node, ...]


# --- rendering a shape to XML ---------------------------------------------------------------------


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\n", "&#10;")
    )


def _span(cls: str, text: str) -> str:
    return f"<span class='{cls}'>{text}</span>"


def _kw(text: str) -> str:
    return _span("keyword", text)


def _hs(h: H, inp: str) -> str:
    return _span(h.cls or ("input-handle" if h.name == inp else "other-handle"), h.name)


def _lit(text: str) -> str:
    return _span("literal", f'"{text}"')


def _line(data: str, children: str | None = None, disabled: str = "") -> str:
    dis = f' Disabled="{_esc(disabled)}"' if disabled else ""
    if children is None:
        return f'<Line Data="{_esc(data)}"{dis}/>'
    return f'<Line Data="{_esc(data)}"{dis}><List>{children}</List></Line>'


def _leaf_data(node: Node, inp: str) -> str | None:
    """The @Data of a leaf statement, or None for a construct."""
    match node:
        case Clone(src, dst, _, markup):
            if markup:
                return (
                    f"{_kw('MsgTreeCopy')} {_hs(src, inp)}{_span('path', '/')} to "
                    f"{_hs(dst, inp)}{_span('path', '/')}"
                )
            return f"MsgTreeCopy {src.name}/ to {dst.name}/"
        case Create(h, k, good, markup):
            kind = f"ADT^A{k:02d}"
            if markup:
                tail = f" version {_lit('2.5.1')}" if good else ""
                return f"{_kw('MsgCreate')} {_hs(h, inp)} as {_lit(kind)}{tail}"
            return f'MsgCreate {h.name} as "{kind}"' + (' version "2.5.1"' if good else "")
        case Write(h, lit, path, markup, verb):
            if verb == "ItemClear":
                if markup:
                    return f"{_kw(verb)} {_hs(h, inp)}{_span('path', path)}"
                return f"{verb} {h.name}{path}"
            if markup:
                return f"{_kw(verb)} {_lit(lit)} to {_hs(h, inp)}{_span('path', path)}"
            return f'{verb} "{lit}" to {h.name}{path}'
        case Log(h, markup):
            return f"{_kw('MsgLog')} {_hs(h, inp)}" if markup else f"MsgLog {h.name}"
        case SendS(h, dest, markup):
            if markup:
                return f"{_kw('MsgSend')} {_hs(h, inp)} to connection {_lit(dest)}"
            return f'MsgSend {h.name} to connection "{dest}"'
        case Unread(kind, a, b, markup):
            if kind == "var":
                if markup:
                    return f"{_span('variable', '$X')} = {_hs(a, inp)}{_span('path', '/PID-8')}"
                return f"$X = {a.name}/PID-8"
            verb = "MsgTreeMerge" if kind == "merge" else "MsgTreeCopy"
            extra = " append" if kind == "worded" else ""
            if markup:
                return (
                    f"{_kw(verb)} {_hs(a, inp)}{_span('path', '/')} to {_hs(b, inp)}"
                    f"{_span('path', '/')}{_kw(extra.strip()) if extra else ''}"
                )
            return f"{verb} {a.name}/ to {b.name}/{extra}"
        case Exit(verb):
            return verb
        case LoopExit():
            return "LoopExit"
        case _:
            return None


def _cond(kind: str, h: H | None, inp: str) -> str:
    if kind == "Else":
        return "Else"
    if h is None:
        return f'{kind} (x = "1")'
    if h.cls == "plain":  # a markup-free condition naming a whole handle
        return f"{kind} {h.name} exists"
    return f"{_kw(kind)} {_hs(h, inp)} exists"


def _render(nodes: Sequence[Node], inp: str) -> str:
    return "".join(_render_one(n, inp) for n in nodes)


def _render_one(node: Node, inp: str, disabled: str = "") -> str:
    data = _leaf_data(node, inp)
    if data is not None:
        return _line(data, disabled=disabled)
    dis = f' Disabled="{_esc(disabled)}"' if disabled else ""
    match node:
        case Raw(xml, _):
            return xml
        case Off(inner, value):
            if _leaf_data(inner, inp) is not None or isinstance(
                inner, (Each, Loop, Block, Call, Unknown, Case)
            ):
                return _render_one(inner, inp, value)
            return f'<Block Data="Off" Disabled="{_esc(value)}"><List>{_render((inner,), inp)}</List></Block>'
        case If(arms, form) as n:
            (k0, c0, b0), rest = arms[0], arms[1:]
            if form == "inbody":
                content = _render(b0, inp) + "".join(
                    _line(_cond(k, c, inp)) + _render(b, inp) for k, c, b in rest
                )
                return f'<If Data="{_esc(_cond(k0, c0, inp))}"{dis}><List>{content}</List></If>'
            chain = "".join(
                _line(_cond(k, c, inp), _render(b, inp), "1" if i == n.off_arm else "")
                for i, (k, c, b) in enumerate(arms)
            )
            if form == "wrapper":
                return f"<If{dis}><List>{chain}</List></If>"
            if form == "wrapper-bare":  # the branch lines sit directly in the <If>, no <List>
                return f"<If{dis}>{chain}</If>"
            if form == "sibling":
                off = ' Disabled="1"' if n.off_arm == 0 else ""
                chain = (
                    f'<If Data="{_esc(_cond(k0, c0, inp))}"{off}>'
                    f"<List>{_render(b0, inp)}</List></If>"
                )
                chain += "".join(
                    _line(_cond(k, c, inp), _render(b, inp), "1" if i + 1 == n.off_arm else "")
                    for i, (k, c, b) in enumerate(rest)
                )
            return chain if not dis else f'<Block Data="Off"{dis}><List>{chain}</List></Block>'
        case Case(pre, arms):
            content = _render(pre, inp) + "".join(
                _line(f'Matching "M{i}"') + _render(a, inp) for i, a in enumerate(arms)
            )
            return f'<Case Data="ChooseFrom (x)"{dis}><List>{content}</List></Case>'
        case Each(body, over, form):
            if over is None:
                data = "ForEach %SRC/OBX $obx"  # a path into a handle and a variable: binds nothing
            elif over.cls == "plain":
                data = f"ForEach {over.name} in %SRC/OBX"
            elif over.cls == "verbless":  # a <Foreach> whose @Data does not start with its verb
                data = f"{over.name} in %SRC/OBX"
            elif over.cls == "rootish":  # a path span that may still mean the whole tree
                data = f"{_kw('ForEach')} {_hs(H(over.name), inp)}{_span('path', '/.')}"
            else:
                data = f"{_kw('ForEach')} {_hs(over, inp)}"
            if form == "line":
                return _line(data, _render(body, inp), disabled)
            return f'<Foreach Data="{_esc(data)}"{dis}><List>{_render(body, inp)}</List></Foreach>'
        case Loop(body):
            return f'<Loop Data="Loop"{dis}><List>{_render(body, inp)}</List></Loop>'
        case Try(body, catches, into, form):
            cdata = f"{_kw('Catch')} into {_hs(into, inp)}" if into else "Catch"
            if form == "inbody":
                content = _render(body, inp) + "".join(
                    _line(cdata) + _render(c, inp) for c in catches
                )
                return f"<Try{dis}><List>{content}</List></Try>"
            caught = "".join(_line(cdata, _render(c, inp)) for c in catches)
            if form == "wrapper":
                return f"<Try{dis}><List>{_line('Try', _render(body, inp))}{caught}</List></Try>"
            chain = f"<Try><List>{_render(body, inp)}</List></Try>{caught}"
            return chain if not dis else f'<Block Data="Off"{dis}><List>{chain}</List></Block>'
        case Block(body, label, _):
            return f'<Block Data="{_esc(label)}"{dis}><List>{_render(body, inp)}</List></Block>'
        case Call(body, passing, inlined):
            line = f'ActionListCall "Sub"{passing}'
            if not inlined:
                return _line(line, disabled=disabled)
            return f'<Call Data="{_esc(line)}"{dis}><Actions>{_render(body, inp)}</Actions></Call>'
        case Unknown(body):
            return f'<Switch Data="Mystery"{dis}><List>{_render(body, inp)}</List></Switch>'
        case Orphan(kind, body, off):
            return _line(kind, disabled=off) + _render(body, inp)
        case Nested(body, verb):
            return _line(_kw(verb), _render(body, inp), disabled)
        case FlatOpen(body):
            return _line('If (x = "1")') + _render(body, inp) + _line("EndIf")
        case OffList(body):
            return f'<List Disabled="1">{_render(body, inp)}</List>'
    raise AssertionError(f"unrendered node {node!r}")


def _package(body: str) -> str:
    return f'<Package Name="ACME X"><ActionList Name="T"><List>{body}</List></ActionList></Package>'


# --- the guard's own allow-list walker ------------------------------------------------------------
#
# The whole-list gate's specification, written a second time and on purpose apart from the importer:
# nothing here imports or calls the importer's gate. Where the head's output differs from step 1, the
# list must be fully understood by THIS walker, or the importer's gate is wider than the allow-list.


# Each allowed statement as ONE whole-string template, matched against the entire ``@Data`` at once:
# the exact spelling, spacing and span quoting, not a token walk. H names a handle span, R the root
# path span, F a single-occurrence field path span (never MSH-1 or MSH-2), and L a quoted literal span.
def _h(n: int) -> str:
    return (
        rf"<span class='(?P<c{n}>input-handle|other-handle)'>"
        rf"(?P<h{n}>%[A-Za-z][A-Za-z0-9_]{{0,39}})</span>"
    )


_R = r"<span class='path'>/</span>"
_F = (
    r"<span class='path'>/(?:MSH-(?![12](?![0-9]))|(?:EVN|PID|PD1|PV1|PV2|MRG|ACC|UB1|UB2)-)"
    r"[1-9][0-9]*(?:-[1-9][0-9]*){0,2}</span>"
)
# A written value: printable ASCII less the quote, the markup characters and the HL7 delimiters.
_VAL = r"<span class='literal'>\"(?P<v>(?:(?![\"&<>\\^|~])[ -~])*)\"</span>"


def _kwd(verb: str) -> str:
    return f"<span class='keyword'>{verb}</span>"


_TEMPLATES = {
    "MsgTreeCopy": re.compile(_kwd("MsgTreeCopy") + " " + _h(1) + _R + " to " + _h(2) + _R),
    "MsgCreate": re.compile(
        _kwd("MsgCreate")
        + " "
        + _h(1)
        + r" as <span class='literal'>\"[A-Z0-9]{3}\^[A-Z0-9]{3}(?:\^[A-Z0-9_]{3,7})?\"</span>"
        + r" version <span class='literal'>\"2\.[1-9](?:\.[1-9])?\"</span>"
    ),
    "ItemCopy": re.compile(_kwd("ItemCopy") + " " + _VAL + " to " + _h(1) + _F),
    "ItemClear": re.compile(_kwd("ItemClear") + " " + _h(1) + _F),
    "ItemAppend": re.compile(_kwd("ItemAppend") + " " + _VAL + " to " + _h(1) + _F),
    "MsgLog": re.compile(_kwd("MsgLog") + " " + _h(1)),
    "MsgSend": re.compile(_kwd("MsgSend") + " " + _h(1) + " to connection " + _VAL),
}
_G_CONTROL_WORDS = frozenset(
    [
        "if",
        "elseif",
        "else",
        "foreach",
        "loop",
        "loopexit",
        "try",
        "catch",
        "choosefrom",
        "case",
        "matching",
        "msgsend",
        "actionlistcall",
        "returns",
        "actionlistexit",
        "actionliststop",
    ]
)


def _g_statement(data: str, handles: list[tuple[str, str]], writes: list[str]) -> bool:
    """Whether ``data`` is one allowed statement; record its handles and what it overwrites."""
    for verb, template in _TEMPLATES.items():
        found = template.fullmatch(data)
        if found is None:
            continue
        named = found.groupdict()
        pairs = [(named[f"h{n}"], named[f"c{n}"]) for n in (1, 2) if named.get(f"h{n}")]
        if verb == "MsgSend" and not named["v"].strip():
            return False
        handles.extend(pairs)
        if verb in ("MsgTreeCopy", "MsgCreate"):
            writes.append(pairs[-1][0])
        return True
    return False


def _fully_understood(xml: str) -> bool:
    """Whether every element of the list, at every depth, is on the allow-list (ADR 0086)."""
    from messagefoundry._vendor.defusedxml.ElementTree import fromstring

    try:
        (action_list,) = list(fromstring(_package(xml)))
    except Exception:  # noqa: BLE001 - malformed is not understood
        return False
    handles: list[tuple[str, str]] = []
    writes: list[str] = []

    def walk(elem: Any) -> bool:
        for child in elem:
            if (child.text or "").strip() or (child.tail or "").strip():
                return False
            attrs = dict(child.attrib)
            if child.tag == "List":
                if attrs or not walk(child):
                    return False
                continue
            off = attrs.pop("Disabled", None)
            if off is not None and off.lower() not in ("1", "true", "yes"):
                return False
            data = attrs.pop("Data", "")
            if attrs:
                return False
            if child.tag == "Line":
                if len(child) or not _g_statement(data, handles, writes):
                    return False
            elif child.tag != "Block" or data or not walk(child):
                return False
        return True

    if set(action_list.attrib) - {"Name", "Desc"} or (action_list.text or "").strip():
        return False
    if not walk(action_list):
        return False
    classes: dict[str, set[str]] = {}
    for text, cls in handles:
        classes.setdefault(text, set()).add(cls)
    inputs = {t for t, c in classes.items() if "input-handle" in c}
    return (
        all(len(c) == 1 for c in classes.values())
        and len({t.lower() for t in classes}) == len(classes)
        and len(inputs) <= 1
        and not inputs & set(writes)
    )


# --- the oracle -----------------------------------------------------------------------------------

Val = tuple[Any, ...]
IN: Val = ("in",)
UNK: Val = ("unknown",)
EMPTY: Val = ("empty",)
_DISABLED_SURE = frozenset({"1", "true", "yes"})
_PLAIN_PASS = re.compile(r"(?: pass \S+)?")


class _Env:
    def __init__(self, default: frozenset[Val] = frozenset({EMPTY})) -> None:
        self.vals: dict[str, frozenset[Val]] = {}
        self.default = default
        # No path reaches this point: an exit ended every one that got here.
        self.ended = False
        # Some path that would have reached this point may have stopped before it: an exit on one
        # arm, or something whose completion nothing here can tell (an unmodelled element, a call
        # whose list is not inlined, a LoopExit with no loop, an orphan marker).
        self.may_end = False

    def get(self, key: str) -> frozenset[Val]:
        return frozenset() if self.ended else self.vals.get(key, self.default)

    def copy(self) -> _Env:
        env = _Env(self.default)
        env.vals = dict(self.vals)
        env.ended = self.ended
        env.may_end = self.may_end
        return env

    def havoc(self) -> None:
        self.vals = {}
        self.default = frozenset({UNK})  # an ended env stays ended: get() answers nothing

    def same(self, other: _Env) -> bool:
        keys = self.vals.keys() | other.vals.keys()
        return (
            self.ended == other.ended
            and self.may_end == other.may_end
            and self.default == other.default
            and all(self.get(k) == other.get(k) for k in keys)
        )


def _join(envs: Sequence[_Env]) -> _Env:
    live = [e for e in envs if not e.ended]
    if not live:
        out = _Env()
        out.ended = True
        return out
    out = _Env(frozenset().union(*(e.default for e in live)))
    for key in set().union(*(e.vals.keys() for e in live)):
        out.vals[key] = frozenset().union(*(e.get(key) for e in live))
    out.may_end = len(live) < len(envs) or any(e.may_end for e in live)
    return out


@dataclass
class _Ctx:
    # Whether this point runs on the path where every placeholder condition is false.
    dead: bool = True
    loops: list[list[_Env]] = field(default_factory=list)
    trys: list[list[_Env]] = field(default_factory=list)
    # Whether this point sits where the import lost the export's scope (an unmodelled element's
    # body, or what follows a branch marker with no construct): it may run, or not, or repeat.
    doubt: bool = False

    def cond(self) -> _Ctx:
        return _Ctx(False, self.loops, self.trys, self.doubt)

    def lost(self) -> _Ctx:
        return _Ctx(False, self.loops, self.trys, True)


class _Oracle:
    """What the export may send at each ``MsgSend``, over every path, in one reading of names."""

    def __init__(self, shape: Shape, fold: bool) -> None:
        self.fold = fold
        self.inp_key = self.key(shape.inp)
        self.sends: dict[str, set[Val]] = {}
        self.send_keys: dict[str, set[str]] = {}
        self.dead: set[str] = set()
        self.doubt: set[str] = set()
        self.may_skip: set[str] = set()
        # Each tree's field writes, path to literal: a later write to a field replaces the earlier.
        self.lits: dict[Val, dict[str, str]] = {}
        # The literals each send's tree held AT the send: a later write changes the tree in
        # Corepoint, not the message already sent.
        self.sent_lits: dict[str, set[str]] = {}
        env = _Env()
        env.vals[self.inp_key] = frozenset({IN})
        self.run(shape.nodes, env, _Ctx())

    def key(self, name: str) -> str:
        bare = name.strip().lstrip("%").rstrip("/")
        if self.fold:
            bare = unicodedata.normalize(
                "NFKC", unicodedata.normalize("NFKC", bare).upper().casefold()
            )
        return bare

    def run(self, nodes: Sequence[Node], env: _Env, ctx: _Ctx) -> _Env:
        for node in nodes:
            env = self.step(node, env, ctx)
            for states in ctx.trys:
                states.append(env.copy())
        return env

    def step(self, node: Node, env: _Env, ctx: _Ctx) -> _Env:  # noqa: C901 - one arm per node kind
        match node:
            case Clone(src, dst, uid, _):
                new: set[Val] = set()
                for v in env.get(self.key(src.name)):
                    if v in (UNK, EMPTY):
                        new.add(UNK)
                        continue
                    root = v[2] if v[0] == "clone" else v
                    made: Val = ("clone", uid, root)
                    # A copy holds what its source held at the copy, and nothing written later.
                    self.lits.setdefault(made, {}).update(self.lits.get(v, {}))
                    new.add(made)
                env.vals[self.key(dst.name)] = frozenset(new)
            case Create(h, k, good, _):
                env.vals[self.key(h.name)] = frozenset({("create", k) if good else UNK})
            case Write(h, lit, path, _, verb):
                key = self.key(h.name)
                vals = env.get(key)
                for v in vals - {UNK, EMPTY}:
                    fields = self.lits.setdefault(v, {})
                    if verb == "ItemClear":
                        fields[path] = ""
                    elif verb == "ItemAppend":
                        fields[path] = fields.get(path, "") + lit
                    else:
                        fields[path] = lit
                if EMPTY in vals:  # a write into nothing may build a tree
                    env.vals[key] = (vals - {EMPTY}) | {UNK}
            case Log():
                pass
            case SendS(h, dest, _):
                self.sends.setdefault(dest, set()).update(env.get(self.key(h.name)))
                for v in env.get(self.key(h.name)):
                    text = "".join(self.lits.get(v, {}).values())
                    self.sent_lits.setdefault(dest, set()).update(_LITERAL.findall(text))
                self.send_keys.setdefault(dest, set()).add(self.key(h.name))
                if ctx.dead and not env.ended:
                    self.dead.add(dest)
                if ctx.doubt:
                    self.doubt.add(dest)
                if env.may_end:
                    self.may_skip.add(dest)
            case Unread():
                env.havoc()
            case Exit():
                # An exit ends the list: nothing after it runs on this path. Neither importer
                # models it (both render a TODO), so a send after it that the head makes live is
                # a send Corepoint never makes.
                env = env.copy()
                env.ended = True
            case LoopExit():
                if ctx.loops:
                    ctx.loops[-1].append(env.copy())
                else:  # with no loop here, it may leave a caller's loop, ending this list
                    stopped = env.copy()
                    stopped.ended = True
                    env = _join([env, stopped])
            case Raw(_, havoc):
                if havoc:
                    env.havoc()
            case If(arms, _, off_arm):
                # A condition reads the handle it names; it never binds one (ADR 0086). A ForEach
                # or a Catch line may bind the handle it names, and those two do (below).
                outs = [env.copy()]  # every condition is a placeholder, so no arm may run
                for i, (_, _, body) in enumerate(arms):
                    if i == off_arm:
                        continue  # a disabled branch line never runs
                    # What follows a disabled branch line has nothing certain to continue.
                    arm_ctx = ctx.lost() if 0 <= off_arm < i else ctx.cond()
                    outs.append(self.run(body, env.copy(), arm_ctx))
                env = _join(outs)
            case Case(pre, arms):
                env = self.run(pre, env, ctx)
                outs = [env.copy()] + [self.run(a, env.copy(), ctx.cond()) for a in arms]
                env = _join(outs)
            case Each(body, over, _):
                if over is not None:
                    env.vals[self.key(over.name)] = frozenset({UNK})
                env = self.loop(body, env, ctx)
            case Loop(body):
                env = self.loop(body, env, ctx)
            case Try(body, catches, into, _):
                if not catches:
                    return self.run(body, env, ctx)
                states = [env.copy()]
                inner = _Ctx(ctx.dead, ctx.loops, [*ctx.trys, states], ctx.doubt)
                out = self.run(body, env.copy(), inner)
                start = _join(states)
                if into is not None:
                    start.vals[self.key(into.name)] = frozenset({UNK})
                outs = [out] + [self.run(c, start.copy(), ctx.cond()) for c in catches]
                env = _join(outs)
            case Block(body, _, havoc):
                if havoc:
                    env.havoc()
                env = self.run(body, env, ctx)
            case Call(body, passing, inlined):
                plain = _PLAIN_PASS.fullmatch(passing) is not None
                if inlined and plain and body and all(isinstance(n, Log) for n in body):
                    return env  # a list that only logs writes nothing, whatever its scope
                # Nothing ties the called list's names to the caller's: what it sends is unknown,
                # and afterwards so is every caller handle. A list nothing here can see, or one
                # that may stop, may stop the caller too.
                called = self.run(body, _Env(frozenset({UNK})), ctx)
                env.havoc()
                if not inlined or called.ended or called.may_end:
                    env.may_end = True
            case Unknown(body) | Nested(body):
                env.havoc()
                env = _join([env.copy(), self.run(body, env.copy(), ctx.lost())])
                env.havoc()
                env.may_end = True  # an unmodelled construct may itself stop the list
            case FlatOpen(body) | OffList(body):
                env = _join([env.copy(), self.run(body, env.copy(), ctx.lost())])
            case Off(inner, value):
                if value.strip().lower() in _DISABLED_SURE:
                    return env
                env = _join([env.copy(), self.run((inner,), env.copy(), ctx.cond())])
            case Orphan(_, body, _):
                env = _join([env.copy(), self.run(body, env.copy(), ctx.lost())])
                env.may_end = True  # what a marker with no construct means is not known
        return env

    def loop(self, body: tuple[Node, ...], env: _Env, ctx: _Ctx) -> _Env:
        cur = env
        for _ in range(16):
            breaks: list[_Env] = []
            inner = _Ctx(False, [*ctx.loops, breaks], ctx.trys, ctx.doubt)
            out = self.run(body, cur.copy(), inner)
            nxt = _join([cur, out, *breaks])
            if nxt.same(cur):
                return cur
            cur = nxt
        cur.havoc()
        return cur


@dataclass
class _Verdict:
    """Both readings of handle names, joined."""

    inp_keys: tuple[str, ...]
    sends: dict[str, set[Val]]
    keys: dict[str, list[tuple[str, str]]]  # dest -> [(input key, sent key)] per reading
    dead: set[str]
    doubt: set[str]
    may_skip: set[str]
    sent_lits: dict[str, set[str]]


def _oracle(shape: Shape) -> _Verdict:
    worlds = [_Oracle(shape, fold) for fold in (False, True)]
    verdict = _Verdict(tuple(w.inp_key for w in worlds), {}, {}, set(), set(), set(), {})
    for w in worlds:
        for dest, vals in w.sends.items():
            verdict.sends.setdefault(dest, set()).update(vals)
        for dest, keys in w.send_keys.items():
            verdict.keys.setdefault(dest, []).extend((w.inp_key, k) for k in keys)
        verdict.dead |= w.dead
        verdict.doubt |= w.doubt
        verdict.may_skip |= w.may_skip
        for dest, lits in w.sent_lits.items():
            verdict.sent_lits.setdefault(dest, set()).update(lits)
    return verdict


def _kind(value: Val) -> str:
    """What an observed message can show of a tree: the input object, a copy of the input, or the
    message one ``MsgCreate`` built (or a copy of it)."""
    if value == IN:
        return "IN"
    if value[0] == "create":
        return f"C{value[1]}"
    root = value[2]
    return "COPY-IN" if root == IN else f"C{root[1]}"


# --- running both importers -----------------------------------------------------------------------

_INPUT = (
    "MSH|^~\\&|A|B|C|D|20260930||ADT^A01|CTRL|P|2.5.1\rEVN|A01\rPID|1||123\rPV1|1|I\rOBX|1|ST|X||Y"
)
_LITERAL = re.compile(r"W\d+Z")


@dataclass
class _Run:
    src: str
    # Every Send the handler made, including those made before a later refusal raised: a refusal
    # dead-letters the message, but it is a TODO, and once a human finishes it those Sends deliver.
    # Reading only a completed run let one late refusal hide every wrong send ahead of it.
    sends: list[tuple[str, object]]
    inp: Message | None


def _execute(src: str, where: Path) -> _Run:
    if not src:
        return _Run("", [], None)
    registry = Registry()
    namespace: dict[str, Any] = {"__name__": "mefor_differential_generated"}
    # Every refusal is read as a human deleting it: the handler runs on past it, so a send after a
    # refusal is executed and checked too, in both importers alike.
    runnable = _REFUSAL.sub(r"\1pass  # refusal removed by the guard", src)
    with _loading(where, registry):
        exec(compile(runnable, _GENERATED, "exec"), namespace)
    inp = Message.parse(_INPUT)
    try:
        result = registry.handlers["t"](inp)
    except Exception as exc:  # noqa: BLE001 - a refusal or a write that cannot land
        items: list[Any] = []
        tb = exc.__traceback__
        while tb is not None:
            if tb.tb_frame.f_code.co_filename == _GENERATED:
                items = list(tb.tb_frame.f_locals.get("sends", []))
            tb = tb.tb_next
    else:
        items = [] if result is None else result if isinstance(result, list) else [result]
    return _Run(src, [(item.to, item.message) for item in items], inp)


_GENERATED = "generated-by-the-corepoint-import.py"
_REFUSAL = re.compile(r"^(\s*)raise NotImplementedError\(.*\)$", re.MULTILINE)


def _observed(message: object, inp: Message | None) -> str:
    if message is inp:
        return "IN"
    if not isinstance(message, Message):
        return "OTHER"
    trigger = message.field("MSH-9.2") or ""
    if trigger == "A01":
        return "COPY-IN"
    match = re.fullmatch(r"A(\d\d)", trigger)
    return f"C{int(match.group(1))}" if match else "OTHER"


_LIVE_SEND = re.compile(r'^(\s*)sends\.append\(Send\("([^"]+)", (\w+)\)\)')
# A line that binds a local other than msg, or sends one.
_LOCAL_LINE = re.compile(
    r"^(\s*)(?:\w+_msg(?:_\d+)? = |sends\.append\(Send\(\"[^\"]+\", (?!msg\))\w+\)\))"
)


def _live_sends(src: str) -> list[tuple[int, str, str]]:
    return [
        (len(m.group(1)), m.group(2), m.group(3))
        for m in map(_LIVE_SEND.match, src.splitlines())
        if m is not None
    ]


_RETURNED_SEND = re.compile(r'Send\("([^"]+)", msg\)')


def _trailing_sends(src: str) -> list[str]:
    """Every destination a handler's closing ``return`` delivers to. :func:`_live_sends` reads the
    ``sends.append`` lines alone, and a handler with no send the render reaches ends on a
    ``return Send(...)`` for every destination in its tree."""
    return [
        dest
        for line in src.splitlines()
        if line.startswith("    return ")
        for dest in _RETURNED_SEND.findall(line)
    ]


def _send_indent(src: str, dest: str, *, live_only: bool = False) -> int | None:
    """The shallowest code line (not a comment) that sends, or refuses to send, to ``dest``. With
    ``live_only``, a live send only: a refusal at any depth fails closed."""
    token = re.compile(
        rf'Send\("{re.escape(dest)}"'
        if live_only
        else rf'"{re.escape(dest)}"|to {re.escape(dest)}:'
    )
    found = [
        len(line) - len(line.lstrip())
        # The handler only: the module's outbound() declarations name every destination at indent 0.
        for line in src.split("@handler")[-1].splitlines()
        if token.search(line) and not line.lstrip().startswith("#")
    ]
    return min(found) if found else None


#: What :func:`_generate` returns: the module, and ``(mapped, unmapped names, disabled)`` for
#: each handler.
_Out = tuple[str, tuple[tuple[int, list[str], int], ...]]


def _generate(module: Any, xml: str) -> _Out:
    """The generated module and the summary counts, or ``("", ())`` when the import refuses."""
    try:
        channel = module.parse_package(_package(xml))[0]
        src = module.generate_module(channel)
    except module.CorepointImportError:
        return "", ()
    return src, tuple(module._count_steps(h.steps, in_loop=False) for h in channel.handlers)


def _violations(shape: Shape) -> list[str]:
    """Every way the head breaks the whole-list gate's invariant for ``shape``.

    The gate is closed, and then the head's module and summary counts are step 1's byte for byte;
    or it is open, and then the guard's OWN walker (:func:`_fully_understood`, never the importer's
    gate) must find every element allow-listed, and every oracle check must pass."""
    xml = _render(shape.nodes, shape.inp)
    head_out, step1_out = _generate(head, xml), _generate(step1, xml)
    if head_out == step1_out:
        return []
    found: list[str] = []
    if not step1_out[0]:
        found.append("(refusal) step 1 refuses the list, and the head renders it")
    if not head_out[0]:
        found.append("(refusal) the head refuses a list step 1 renders")
    if not _fully_understood(xml):
        found.append("(gate) the head differs from step 1 on a list that is not fully understood")
    return found + _oracle_violations(shape, head_out[0], step1_out[0])


def _oracle_violations(shape: Shape, head_src: str, step1_src: str) -> list[str]:
    """Every way the head's handler for ``shape`` fails open against step 1 and the oracle.

    Run only where the head differs from step 1, so nothing step 1 also renders is exempt: every
    live send of the head must be provable, and every message it delivers must carry exactly the
    literals its tree held at the send."""
    verdict = _oracle(shape)
    out_head = _execute(head_src, _WHERE)
    out_step1 = _execute(step1_src, _WHERE)
    found: list[str] = []

    def provable(dest: str, local_is_msg: bool) -> str:
        values = verdict.sends.get(dest, set())
        if len(values) != 1:
            return f"the export may send {len(values)} different trees there"
        (value,) = values
        if value in (UNK, EMPTY):
            return "the export sends a tree nobody can identify there"
        if local_is_msg != (value == IN):
            return (
                f"the local is {'msg' if local_is_msg else 'a copy'} but the tree is {_kind(value)}"
            )
        return ""

    # (ii), static: no send line is shallower in the head than in step 1.
    for dest in verdict.sends:
        h_at = _send_indent(out_head.src, dest, live_only=True)
        s_at = _send_indent(out_step1.src, dest)
        if h_at is not None and s_at is not None and h_at < s_at:
            found.append(f"(ii) {dest} sits at indent {h_at} in the head, {s_at} in step 1")

    # The gate admits no construct: a local other than msg is bound and sent only at the handler's
    # own level.
    for line in out_head.src.split("@handler")[-1].splitlines():
        found_local = _LOCAL_LINE.match(line)
        if found_local and len(found_local.group(1)) != 4:
            found.append(f"(level) a local is bound or sent below the handler level: {line}")

    # Every live send line of the head, on every path.
    for _, dest, local in _live_sends(out_head.src):
        is_msg = local == "msg"
        if is_msg:
            # (iii): msg only for the input handle, in every reading of names, and only when the
            # export does not provably send another tree.
            if any(sent != inp for inp, sent in verdict.keys.get(dest, [])):
                found.append(f"(iii) {dest} sends msg for a handle that is not the input")
            values = verdict.sends.get(dest, set())
            if values and not values & {IN, UNK, EMPTY}:
                found.append(f"(iii) {dest} sends msg where the export sends another tree")
        if dest in verdict.doubt:
            found.append(f"(ii) {dest} sends {local} live where the import lost the scope")
            continue
        if dest in verdict.may_skip:
            found.append(f"(reach) {dest} sends {local} live, but Corepoint may stop before it")
            continue
        why = provable(dest, is_msg)
        if why:
            found.append(f"(render) {dest} sends {local} live: {why}")

    # (i) and (ii), executed on the path where every placeholder condition is false.
    if out_head.sends:
        for dest, message in out_head.sends:
            seen = _observed(message, out_head.inp)
            if dest not in verdict.dead:
                found.append(f"(ii) {dest} is delivered, but the export sends it only in a branch")
                continue
            why = provable(dest, seen == "IN")
            if why:
                found.append(f"(i) {dest} is delivered as {seen}: {why}")
                continue
            (value,) = verdict.sends[dest]
            if _kind(value) != seen:
                found.append(f"(i) {dest} delivers {seen}; the export sends {_kind(value)}")
            assert isinstance(message, Message)
            held = set(_LITERAL.findall(message.encode()))
            stray = held - verdict.sent_lits.get(dest, set())
            if stray:
                found.append(
                    f"(i) {dest} carries {sorted(stray)}, written to another tree or after the send"
                )
            missing = verdict.sent_lits.get(dest, set()) - held
            if missing:
                found.append(f"(i) {dest} lacks {sorted(missing)}, which its tree held at the send")
    return found


_WHERE = Path(__file__).parent / "fixtures" / "corepoint"


# --- generating shapes ----------------------------------------------------------------------------

_INPUTS = ("%ADT", "ADT", "%ADT-1", "%Eingang")
_OTHERS = ("%OUT", "%OUT-A", "%OUT.A", "%AUSGANGÄ", "OUT", "%Ω", "%OUT$1", "%ADT2")


class _Build:
    """Fresh destinations, literals, uids and message types for one shape."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.n = 0
        self.inp = H(rng.choice(_INPUTS))
        out = rng.choice(_OTHERS)
        self.out = H(out)
        self.new = H(rng.choice([o for o in _OTHERS if o != out] + ["%NEW"]))
        # Sometimes a statement spells a handle in another case; sometimes markup is mixed.
        self.variant = rng.random() < 0.25
        self.mode = rng.choices(("role", "mixed", "plain"), (6, 3, 1))[0]

    def _next(self) -> int:
        self.n += 1
        return self.n

    def m(self) -> bool:
        return self.mode == "role" or (self.mode == "mixed" and self.rng.random() < 0.6)

    def spell(self, h: H) -> H:
        # A case variant is never tagged input-handle: the exporter's markup names the list's real
        # input, and a tag on another spelling would make the markup and the oracle disagree.
        if self.variant and self.rng.random() < 0.3:
            return H(h.name.swapcase())
        return h

    def clone(self, src: H, dst: H) -> Clone:
        return Clone(self.spell(src), self.spell(dst), self._next(), self.m())

    def create(self, h: H, good: bool = True) -> Create:
        # Never ADT^A01: that is the synthetic input's type, which _observed reads as a copy of it.
        return Create(self.spell(h), 2 + self._next() % 97, good, self.m())

    def write(self, h: H) -> Write:
        return Write(
            self.spell(h), f"W{self._next()}Z", self.rng.choice(("/PID-8", "/MSH-10")), self.m()
        )

    def send(self, h: H) -> SendS:
        return SendS(self.spell(h), f"OB_{self._next()}", self.m())

    def log(self, h: H) -> Log:
        return Log(self.spell(h), self.m())

    def unread(self) -> Unread:
        kind = self.rng.choice(("merge", "var", "worded"))
        return Unread(kind, self.spell(self.new), self.spell(self.out), self.m())


def _payloads(b: _Build) -> dict[str, tuple[Node, ...]]:
    i, o, n = b.inp, b.out, b.new
    return {
        "rebuild-send": (b.create(o), b.send(o)),
        "send": (b.send(o), b.send(i)),
        "clone-write": (b.clone(i, o), b.write(o), b.write(i)),
        "havoc": (b.unread(),),
        "create-new-send": (b.create(n), b.send(n)),
        "reclone-from-new": (b.clone(n, o), b.send(o)),
    }


_IF_FORMS = ("inbody", "wrapper", "wrapper-bare", "lines", "sibling")
_TRY_FORMS = ("inbody", "wrapper", "sibling")


def _wrap(kind: str, body: tuple[Node, ...], b: _Build) -> Node:
    """Wrap ``body`` in one construct of ``kind``; the spelling is drawn from ``b``'s seed."""
    rng = b.rng
    named = b.spell(rng.choice((b.inp, b.out))) if rng.random() < 0.5 else None
    if named is not None and rng.random() < 0.3:
        named = H(named.name, "plain")
    # How a ForEach names what it binds: role markup, markup-free, without its verb first, or in
    # a span whose class the reader must not trust (a variable or literal holding a handle name).
    over = None
    if rng.random() < 0.6:
        over_cls = rng.choice(
            ("", "plain", "verbless", "variable", "literal", "handle", "description", "rootish")
        )
        over = H(b.spell(rng.choice((b.inp, b.out))).name, over_cls)
    form = rng.choice(_IF_FORMS)
    if kind == "if":
        return If((("If", named, body),), form)
    if kind == "else":
        return If((("If", named, (b.log(b.inp),)), ("Else", None, body)), form)
    if kind == "elseif":
        return If((("If", None, ()), ("ElseIf", named, body), ("Else", None, ())), form)
    if kind == "elseif-else":
        return If(
            (("If", None, ()), ("ElseIf", named, (b.log(b.inp),)), ("Else", None, body)), form
        )
    if kind == "case":
        return Case((), (body, ())) if rng.random() < 0.5 else Case(body, ((b.log(b.inp),),))
    if kind == "each":
        form = (
            "elem" if over is not None and over.cls == "verbless" else rng.choice(("elem", "line"))
        )
        return Each(body, over, form)
    if kind == "loop":
        return Loop((*body, LoopExit())) if rng.random() < 0.5 else Loop(body)
    if kind == "try":
        return Try(body, ((b.log(b.inp),),), named, rng.choice(_TRY_FORMS))
    if kind == "catch":
        return Try((b.log(b.inp),), (body,), named, rng.choice(_TRY_FORMS))
    if kind == "try-no-catch":
        return Try(body, (), None, "inbody")
    if kind == "block":
        return Block(body)
    if kind == "call":
        passing = rng.choice(("", f" pass {b.out.name}", f" pass {b.inp.name}"))
        return Call(body, passing)
    if kind == "call-logs":
        return Block((Call((b.log(H("%P")),), rng.choice(("", f" pass {b.inp.name}"))), *body))
    if kind == "call-bare":
        return Block((Call((), f" pass {b.out.name}", inlined=False), *body))
    if kind == "unknown":
        return Unknown(body)
    if kind == "off":
        return Off(Block(body), "1")
    if kind == "off-unsure":
        return Off(Block(body), "on")
    if kind == "orphan":
        return Block((Orphan(rng.choice(("Else", "Catch", "Matching")), body),))
    if kind == "disabled-marker":
        # One branch marker carries @Disabled, so it continues nothing and what follows it folds
        # into the arm before it.
        value = rng.choice(("1", "on"))
        return rng.choice(
            (
                Try((b.log(b.inp), Orphan("Catch", body, value)), ((b.log(b.inp),),)),
                Case((Orphan("Matching", body, value),), ((b.log(b.inp),),)),
                If((("If", None, (b.log(b.inp), Orphan("Else", body, value))),)),
                Each((Orphan("Else", body, value),)),
            )
        )
    if kind == "disabled-branch-line":
        arms: tuple[Arm, ...] = (("If", None, (b.log(b.inp),)), ("Else", None, body))
        return If(arms, rng.choice(_IF_FORMS[1:]), off_arm=0)
    if kind == "nested-line":
        return Nested(body)
    if kind == "block-label":
        # A Block whose label is itself a writing statement, marked up, plain, or plain inside a
        # span of the label's own class.
        label = _leaf_data(b.clone(b.new, b.out), b.inp.name)
        assert label is not None
        if rng.random() < 0.3:
            plain = _leaf_data(Clone(b.new, b.out, 0, False), b.inp.name)
            assert plain is not None
            label = _span("block", plain)
        return Block(body, label, havoc=True)
    if kind == "may-stop-first":
        # Something that may stop the list, then the body.
        first: Node = rng.choice(
            (
                Off(Exit(), "on"),
                If((("If", None, (Exit(),)),)),
                If((("If", None, (LoopExit(),)),)),
                Try((LoopExit(),), ((b.log(b.inp),),)),
                Call((), "", inlined=False),
                Unknown(()),
                If(
                    (
                        ("If", None, (b.log(b.inp),)),
                        ("Else", None, (b.log(b.inp), Orphan("ElseIf", (Exit(),)))),
                    ),
                    "wrapper",
                ),
            )
        )
        return Block((first, *body))
    if kind == "flat-open":
        return FlatOpen(body)
    if kind == "disabled-list":
        return OffList(body)
    if kind == "stray":
        # A bodyless branch marker inside a construct that cannot continue it: the importer adopts
        # it and renders it after the construct, with its scope lost.
        stray = Orphan(rng.choice(("Else", "Catch", "Matching")), body)
        return rng.choice(
            (
                Each((stray,)),
                Loop((stray,)),
                Try((Orphan("Else", body),), ((b.log(b.inp),),)),
            )
        )
    raise AssertionError(kind)


_KINDS = (
    "if",
    "else",
    "elseif",
    "elseif-else",
    "case",
    "each",
    "loop",
    "try",
    "catch",
    "try-no-catch",
    "block",
    "call",
    "call-logs",
    "call-bare",
    "unknown",
    "off",
    "off-unsure",
    "orphan",
    "stray",
    "disabled-marker",
    "disabled-branch-line",
    "nested-line",
    "block-label",
    "may-stop-first",
    "flat-open",
    "disabled-list",
)


def _framed(b: _Build, middle: Node, name: str) -> Shape:
    """Clone the input and write the clone, run ``middle``, then send every handle."""
    i, o, n = b.inp, b.out, b.new
    nodes: tuple[Node, ...] = (
        b.clone(i, o),
        b.write(o),
        middle,
        b.send(o),
        b.send(i),
        b.send(n),
    )
    return Shape(name, i.name, nodes)


def _paired_shapes(seed: int) -> Iterator[Shape]:
    """Every ordered pair of constructs, nested two deep, with every payload."""
    rng = random.Random(seed)
    for outer in _KINDS:
        for inner in _KINDS:
            for payload in _payloads(_Build(random.Random(0))):
                b = _Build(random.Random(rng.random()))
                body = _payloads(b)[payload]
                middle = _wrap(outer, (b.log(b.inp), _wrap(inner, body, b)), b)
                yield _framed(b, middle, f"{outer}/{inner}/{payload}")


def _random_node(b: _Build, depth: int) -> Node:
    rng = b.rng
    if depth <= 0 or rng.random() < 0.45:
        return rng.choice(
            (
                lambda: b.clone(rng.choice((b.inp, b.new, b.out)), rng.choice((b.out, b.new))),
                lambda: b.create(rng.choice((b.out, b.new)), rng.random() < 0.9),
                lambda: b.write(rng.choice((b.inp, b.out, b.new))),
                lambda: b.send(rng.choice((b.inp, b.out, b.new))),
                lambda: b.log(rng.choice((b.inp, b.out))),
                lambda: b.unread(),
                lambda: Exit(),
            )
        )()
    body = tuple(_random_node(b, depth - 1) for _ in range(rng.randint(1, 3)))
    return _wrap(rng.choice(_KINDS), body, b)


def _random_shapes(seed: int, count: int) -> Iterator[Shape]:
    rng = random.Random(seed)
    for k in range(count):
        b = _Build(random.Random(rng.random()))
        middle = Block(tuple(_random_node(b, 3) for _ in range(rng.randint(1, 4))))
        yield _framed(b, middle, f"random-{k}")


# --- shapes the gate is meant to open -------------------------------------------------------------
#
# The constructs above all close the gate, so on their own they test only byte-identity. These draw
# from the allow-list alone (straight-line statements, unlabelled Blocks, surely disabled steps) with
# handles the gate reads, so the gate opens and the oracle's checks do the work. One in four also
# carries ONE spoiler, an element just outside the allow-list, so the gate's edge is tested too.

_SAFE_OTHERS = ("%OUT", "%NEW", "%OUT_A", "%X1", "%Tmp")


# Fields and components of segments the synthetic input carries, none inside another.
# /PID-8 twice, so a later write to a field it already wrote is common.
_OPEN_PATHS = ("/PID-8", "/PID-8", "/MSH-10", "/PID-5-1", "/PV1-2", "/EVN-1")


class _OpenBuild(_Build):
    def __init__(self, rng: random.Random) -> None:
        super().__init__(rng)
        self.inp = H("%ADT")
        self.out, self.new = (H(n) for n in rng.sample(_SAFE_OTHERS, 2))
        self.variant = False
        self.mode = "role"

    def write(self, h: H) -> Write:
        verb = self.rng.choice(("ItemCopy", "ItemCopy", "ItemAppend", "ItemClear"))
        return Write(h, f"W{self._next()}Z", self.rng.choice(_OPEN_PATHS), True, verb)


def _spoiler(b: _OpenBuild) -> Node:
    """One element just outside the allow-list."""
    o = b.out
    w = _leaf_data(Write(o, f"W{b._next()}Z"), b.inp.name)
    s = _leaf_data(b.send(o), b.inp.name)
    assert w is not None and s is not None
    return b.rng.choice(
        (
            Raw(_line(w.replace("ItemCopy", "itemcopy")), havoc=False),
            Raw(_line(s + _span("description", "note")), havoc=False),
            Raw(_line(s + _span("comment", "note")), havoc=False),
            Raw(_line(w).replace("<Line ", '<Line Enabled="false" ', 1), havoc=False),
            Raw(_line(w).replace("<Line ", '<Line Comment="note" ', 1), havoc=False),
            Raw(_line(w).replace("/PID-8", "//PID-8").replace("/MSH-10", "//MSH-10"), havoc=False),
            b.write(H(o.name.swapcase())),
            Write(o, f"W{b._next()}Z", "/PID-8", markup=False),
            Off(b.write(o), "on"),
            Block((b.write(o),), "itemclear OUT", havoc=True),
            Block((b.write(o),), "Patient MSH", havoc=False),
            If((("If", None, (b.write(o),)),)),
            Unread("merge", b.out, b.new),
            Clone(b.out, b.inp, b._next()),
            b.create(o, good=False),
            OffList((b.write(o),)),
        )
    )


def _open_node(b: _OpenBuild, depth: int) -> Node:
    rng = b.rng
    handles = (b.inp, b.out, b.new)
    roll = rng.random()
    if depth > 0 and roll < 0.12:
        body = tuple(_open_node(b, depth - 1) for _ in range(rng.randint(1, 3)))
        return Block(body, "")
    if roll < 0.18:
        return Off(_open_node(b, 0), rng.choice(("1", "true", "yes")))
    return rng.choice(
        (
            lambda: b.clone(rng.choice(handles), rng.choice((b.out, b.new))),
            lambda: b.create(rng.choice((b.out, b.new))),
            lambda: b.write(rng.choice(handles)),
            lambda: b.write(rng.choice(handles)),
            lambda: b.send(rng.choice(handles)),
            lambda: b.send(rng.choice(handles)),
            lambda: b.log(rng.choice(handles)),
        )
    )()


def _open_shapes(seed: int, count: int) -> Iterator[Shape]:
    rng = random.Random(seed)
    for k in range(count):
        b = _OpenBuild(random.Random(rng.random()))
        nodes = [_open_node(b, 2) for _ in range(rng.randint(2, 9))]
        if rng.random() < 0.25:
            nodes.insert(rng.randint(0, len(nodes)), _spoiler(b))
        yield Shape(f"open-{k}", b.inp.name, tuple(nodes))


# --- the fixed seeds: every repro from every review of PR 1900 ------------------------------------

_ADT, _OUT, _NEW, _P, _ERR = H("%ADT"), H("%OUT"), H("%NEW"), H("%P"), H("%ERR")


def _seed_shapes() -> Iterator[Shape]:
    """Each review's repros, in the review's own words where the comment gives them."""
    clone = Clone(_ADT, _OUT, 1)
    for markup in (True, False):
        # 9b8f13481 MEDIUM: an inlined call stopped unbinding a handle it passes.
        c = Clone(_ADT, _OUT, 1, markup)
        for body in (
            (Create(_P, 4, markup=markup),),
            (Log(_P, markup),),
            (Off(Create(_P, 4, markup=markup)),),
        ):
            yield Shape(
                f"9b8f13481-medium-{markup}-{len(body)}",
                "%ADT",
                (c, Call(body, " pass %OUT"), SendS(_OUT, "OB_OUT", markup)),
            )
    # 9b8f13481 LOW 2: a clone over a built handle, then a write and a send.
    yield Shape(
        "9b8f13481-low2",
        "%ADT",
        (Create(_NEW, 4), Clone(_ADT, _NEW, 2), Write(_NEW, "W1Z"), SendS(_NEW, "OB_NEW")),
    )
    # 9b8f13481 LOW 4: an unstyled-connective append that maps on the input.
    append = (
        "<Line Data=\"&lt;span class='keyword'&gt;ItemAppend&lt;/span&gt; "
        "&lt;span class='literal'&gt;&quot;x&quot;&lt;/span&gt; "
        "&lt;span class='keyword'&gt;before&lt;/span&gt; "
        "&lt;span class='input-handle'&gt;%ADT&lt;/span&gt;&lt;span class='path'&gt;/PID-8"
        '&lt;/span&gt;"/>'
    )
    yield Shape("9b8f13481-low4", "%ADT", (Raw(append, havoc=False), SendS(_ADT, "OB_IN")))
    # d401cdb5b MEDIUM: name matching missed hyphen, dot, non-ASCII and %-free handles.
    for name in ("%OUT-A", "%OUT.A", "%AUSGANGÄ"):
        h = H(name)
        for passing, body in ((f" pass {name}", (Create(_P, 4),)), ("", (Create(h, 4),))):
            yield Shape(
                f"d401cdb5b-medium-{name}-{bool(passing)}",
                "%ADT",
                (Clone(_ADT, h, 1), Call(body, passing), SendS(h, "OB_OUT")),
            )
    bare_in, bare_out = H("ADT"), H("OUT")
    yield Shape(
        "d401cdb5b-medium-no-percent",
        "ADT",
        (Clone(bare_in, bare_out, 1), Call((Create(bare_out, 4),)), SendS(bare_out, "OB_OUT")),
    )
    yield Shape(
        "d401cdb5b-medium-hyphen-in-a-foreach",
        "%ADT",
        (
            Clone(_ADT, H("%OUT-A"), 1),
            Each((SendS(H("%OUT-A"), "OB_OUT"), Call((Create(_P, 4),), " pass %OUT-A"))),
        ),
    )
    # d401cdb5b LOW 2: a called list's input handle may receive the caller's input.
    yield Shape(
        "d401cdb5b-low2",
        "%ADT",
        (
            Write(_ADT, "W1Z", "/MSH-6"),
            Call((Log(H("%P", "input-handle")), Create(_P, 4))),
            SendS(_ADT, "OB_IN"),
        ),
    )
    # d26545d6f HIGH: a bracketed branch came loose and its body ran unconditionally.
    new_body: tuple[Node, ...] = (Create(_NEW, 4), SendS(_NEW, "OB_NEW"))
    for form in _IF_FORMS:
        yield Shape(
            f"d26545d6f-high-1-{form}",
            "%ADT",
            (If((("If", _ADT, (Log(_P),)), ("Else", None, new_body)), form),),
        )
        yield Shape(
            f"d26545d6f-high-2-{form}",
            "%ADT",
            (If((("If", None, ()), ("ElseIf", _ADT, new_body)), form),),
        )
    for form in _TRY_FORMS:
        yield Shape(f"d26545d6f-high-3-{form}", "%ADT", (Try((Log(_P),), (new_body,), _ERR, form),))
    # The d26545d6f re-cut's own open item (1), pre-existing on main: a Block whose label is a
    # writing statement. Recorded so a change to it is seen; the oracle reads the label as a write.
    yield Shape(
        "d26545d6f-open-1-block-label",
        "%ADT",
        (clone, Block((SendS(_ADT, "OB_IN"),), "MsgTreeCopy %NEW/ to %ADT/", havoc=True)),
    )
    yield Shape(
        "d26545d6f-high-4-plain-sibling",
        "%ADT",
        (If((("If", H("%ADT", "plain"), (Log(_P),)), ("Else", None, new_body)), "sibling"),),
    )
    # The d26545d6f review's call battery (its scratchpad repro2.py): eight spellings, seven call
    # shapes, a send of the clone and a send of the input after each.
    for name in ("%OUT", "%OUT-A", "%OUT.A", "%ÖUT", "OUT", "%out", "％OUT", "%OUT/"):
        h = H(name)
        calls: dict[str, tuple[Node, ...]] = {
            "pass": (Call((Log(_P),), f" pass {name}"),),
            "nopass": (Call((Log(_P),)),),
            "nopass-empty": (Call(()),),
            "rebuild": (Call((Clone(H("%IN", "input-handle"), H("%X"), 9),), f" pass {name}"),),
            "foreach": (Each((Log(_P),), h),),
            "foreach-plain": (Each((Clone(H("%Z"), h, 8),)),),
            "none": (),
        }
        for cname, call in calls.items():
            for tail in (SendS(h, "OB_OUT"), SendS(_ADT, "OB_IN")):
                yield Shape(
                    f"d26545d6f-battery-{name}-{cname}-{tail.dest}",
                    "%ADT",
                    (Write(_ADT, "W1Z", "/MSH-6"), Clone(_ADT, h, 1), *call, tail),
                )
    # A ForEach or a Catch that binds the handle it names, in spellings neither reading sees: no
    # ``%``, markup-free, and an unlisted span class ("handle").
    for over in (H("OUT", "plain"), H("%OUT", "plain"), H("OUT"), H("%OUT", "handle")):
        h = H(over.name)
        tag = f"{over.name}-{over.cls or 'span'}"
        yield Shape(
            f"foreach-binds-{tag}",
            "%ADT",
            (Clone(_ADT, h, 1), Each((SendS(h, "OB_LOOP"),), over), SendS(h, "OB_AFTER")),
        )
        yield Shape(
            f"catch-binds-{tag}",
            "%ADT",
            (
                Clone(_ADT, h, 1),
                Try((Log(_P),), ((SendS(h, "OB_CATCH"),),), over),
                SendS(h, "OB_AFTER"),
            ),
        )
    # The wider sweep on seed 4: a <Try> with no @Data holding a nested <Try> element dissolved as
    # if it were the export's branch-group wrapper, so its Catch came loose and the clone in its
    # body read as made on every path.
    yield Shape(
        "nested-try-is-not-a-wrapper",
        "%ADT",
        (
            Block((Try((Try((Log(_P),), ((Log(_P),),)), Clone(_ADT, _OUT, 1)), ((Log(_P),),)),)),
            SendS(_OUT, "OB_OUT"),
        ),
    )
    # From the narrowing rounds, kept as seeds: what a ForEach or Catch line may bind mattered most
    # for the INPUT before the first bind, since a loop that rebinds it, then a clone of it, would
    # copy the message that arrived. Under the whole-list gate any ForEach or Catch closes the gate.
    for name in ("ADT", "%ADT", "%adt"):
        for cls in ("", "plain", "verbless", "variable", "literal", "handle"):
            over = H(name, cls)
            form = "elem" if cls == "verbless" else "line"
            after: tuple[Node, ...] = (
                Clone(_ADT, _OUT, 1),
                SendS(_OUT, "OB_OUT"),
                SendS(_ADT, "OB_IN"),
            )
            yield Shape(
                f"input-rebound-by-foreach-{name}-{cls or 'span'}",
                "%ADT",
                (Each((Log(_P),), over, form), *after),
            )
            if cls not in ("verbless",):
                yield Shape(
                    f"input-rebound-by-catch-{name}-{cls or 'span'}",
                    "%ADT",
                    (Try((Log(_P),), ((Log(_P),),), over, "wrapper"), *after),
                )
    # The HIGH with msg in the loose branch: step 1 kept that send under its placeholder.
    in_sent: tuple[Node, ...] = (SendS(_ADT, "OB_IN"),)
    for form in _IF_FORMS:
        yield Shape(
            f"d26545d6f-high-msg-1-{form}",
            "%ADT",
            (If((("If", _ADT, (Log(_P),)), ("Else", None, in_sent)), form),),
        )
        yield Shape(
            f"d26545d6f-high-msg-2-{form}",
            "%ADT",
            (If((("If", None, ()), ("ElseIf", _ADT, in_sent)), form),),
        )
    for form in _TRY_FORMS:
        yield Shape(
            f"d26545d6f-high-msg-3-{form}", "%ADT", (Try((Log(_P),), (in_sent,), _ERR, form),)
        )
    # The code review of this branch (round 2): shapes that passed the guard as it then was.
    new_sent: tuple[Node, ...] = (Create(_NEW, 4), SendS(_NEW, "OB_NEW"))
    for value in ("1", "on"):
        yield Shape(
            f"review-disabled-catch-{value}",
            "%ADT",
            (Try((Log(_P), Orphan("Catch", new_sent, value)), ()),),
        )
        yield Shape(
            f"review-disabled-matching-{value}",
            "%ADT",
            (Case((Orphan("Matching", new_sent, value),), ((Log(_P),),)),),
        )
        yield Shape(
            f"review-disabled-else-{value}",
            "%ADT",
            (If((("If", None, (Log(_P), Orphan("Else", new_sent, value))),)),),
        )
    yield Shape(
        "review-exit-then-build-and-send",
        "%ADT",
        (Log(_ADT), Exit(), Create(_OUT, 4), SendS(_OUT, "OB_OUT")),
    )
    yield Shape("review-nested-line", "%ADT", (Nested(new_sent),))
    for form in _IF_FORMS[1:]:
        yield Shape(
            f"review-disabled-if-line-{form}",
            "%ADT",
            (If((("If", None, (Log(_P),)), ("Else", None, (SendS(_ADT, "OB_IN"),))), form, 0),),
        )
    yield Shape(
        "review-verbless-foreach",
        "%ADT",
        (
            Create(_OUT, 4),
            Each((SendS(_OUT, "OB_LOOP"),), H("OUT", "verbless")),
            SendS(_OUT, "OB_AFTER"),
        ),
    )
    label = _leaf_data(Clone(_NEW, _OUT, 9), "%ADT")
    assert label is not None
    yield Shape(
        "review-block-label-writes",
        "%ADT",
        (Create(_OUT, 4), Block((SendS(_OUT, "OB_OUT"),), label, havoc=True)),
    )
    for cls in ("variable", "literal"):
        yield Shape(
            f"review-foreach-span-class-{cls}",
            "%ADT",
            (
                Clone(_ADT, _OUT, 1),
                Each((SendS(_OUT, "OB_LOOP"),), H("OUT", cls), "line"),
                SendS(_OUT, "OB_AFTER"),
            ),
        )
    # The Lander's QA of db8873d19e (PR 1900): a ForEach or Catch naming the clone in a span whose
    # class says it is not a handle, or with a path that may still mean the whole tree.
    for cls in ("variable", "literal", "numeral", "description", "comment", "detail", "rootish"):
        over = H("%OUT", cls)
        yield Shape(
            f"lander-db8873d19e-foreach-{cls}",
            "%ADT",
            (Clone(_ADT, _OUT, 1), Each((Log(_P),), over, "line"), SendS(_OUT, "OB_OUT")),
        )
        if cls != "rootish":
            yield Shape(
                f"lander-db8873d19e-catch-{cls}",
                "%ADT",
                (
                    Clone(_ADT, _OUT, 1),
                    Try((Log(_P),), ((Log(_P),),), over, "wrapper"),
                    SendS(_OUT, "OB_OUT"),
                ),
            )
        # And the same span ahead of the first bind, naming the input.
        yield Shape(
            f"lander-db8873d19e-input-{cls}",
            "%ADT",
            (Each((Log(_P),), H("%ADT", cls), "line"), Clone(_ADT, _OUT, 1), SendS(_OUT, "OB_OUT")),
        )
    # The code review of this branch, round 3: what may stop the list before a top-level build.
    stops: dict[str, Node] = {
        "unsure-exit": Off(Exit(), "on"),
        "exit-in-if": If((("If", None, (Exit(),)),)),
        "unsure-if-with-exit": Off(If((("If", None, (Exit(),)),)), "on"),
        "loopexit-in-if": If((("If", None, (LoopExit(),)),)),
        "loopexit-in-try": Try((LoopExit(),), ((Log(_ADT),),)),
        "bare-call": Call((), "", inlined=False),
        "bodyless-unknown": Unknown(()),
        "exit-in-a-branch-of-a-branch": If(
            (("If", None, (Log(_ADT),)), ("Else", None, (Orphan("ElseIf", (Exit(),)),))),
            "wrapper",
        ),
        "flat-open": FlatOpen(()),
        "stray-branch": Each((Orphan("Matching", (Log(_ADT),)),)),
    }
    for name, stop in stops.items():
        yield Shape(f"review-r3-{name}", "%ADT", (Log(_ADT), stop, *new_sent))
        yield Shape(
            f"review-r3-{name}-after-a-bind", "%ADT", (Clone(_ADT, _OUT, 1), stop, *new_sent)
        )
    yield Shape("review-r3-disabled-list", "%ADT", (Log(_ADT), OffList(new_sent)))
    yield Shape("review-r3-flat-open-body", "%ADT", (Log(_ADT), FlatOpen(new_sent)))
    yield Shape(
        "review-r3-block-span-label",
        "%ADT",
        (
            Block((), _span("block", "MsgTreeCopy %NEW/ to %ADT/"), havoc=True),
            Clone(_ADT, _OUT, 1),
            SendS(_OUT, "OB_OUT"),
        ),
    )
    # The existing hostile spellings, each cloned, called over and sent.
    for name in ("%OUT-", "%ÄÖ-ß.x", "%OUT(1)", "%OUT;A", "%_", "%1OUT"):
        h = H(name)
        yield Shape(
            f"hostile-{name}",
            "%ADT",
            (Clone(_ADT, h, 1), SendS(h, "OB_BEFORE"), Call((Log(_P),)), SendS(h, "OB_AFTER")),
        )
    yield from _round3_shapes()
    yield from _gate_review_shapes()
    yield from _label_statement_shapes()
    # The Lander's QA of db8873d19e, pre-existing on main: a line between an If and its Else.
    for between in (
        "<Line/>",
        '<Line Comment="note"/>',
        _line(_leaf_data(Log(_ADT), "%ADT") or ""),
    ):
        yield Shape(
            f"lander-db8873d19e-line-between-if-and-else-{len(between)}",
            "%ADT",
            (
                Raw(
                    '<If><List><Line Data="If (x)"><List>'
                    + _line(_leaf_data(Log(_ADT), "%ADT") or "")
                    + "</List></Line>"
                    + between
                    + '<Line Data="Else"><List>'
                    + _line(_leaf_data(SendS(_ADT, "OB_IN"), "%ADT") or "")
                    + "</List></Line></List></If>"
                ),
            ),
        )


def _round3_shapes() -> Iterator[Shape]:
    """The report-only review of 6fa49a9d5 (round 3 of the differential-guard pass): seven fail-open
    shapes that passed the guard as it then was, in the review's own spellings. Each spoils the
    allow-list except the write after a send, which the gate admits and :class:`_Binder` declines."""
    log_adt = _line(f"{_kw('MsgLog')} {_hs(_ADT, '%ADT')}")
    send_in = _line(f"{_kw('MsgSend')} {_hs(_ADT, '%ADT')} to connection {_lit('OB_IN')}")
    new_sent: tuple[Node, ...] = (Create(_NEW, 4), SendS(_NEW, "OB_NEW"))
    out = H("%OUT")

    def raw_line(data: str) -> Raw:
        return Raw(_line(data), havoc=False)

    try_el = Raw("<Try><List>" + log_adt + "</List></Try>", havoc=False)
    if_el = Raw('<If Data="If (x = &quot;1&quot;)"><List>' + log_adt + "</List></If>", havoc=False)
    shapes: dict[str, tuple[Node, ...]] = {
        # (1) a loose Catch or Matching line after its construct
        "C-flat-catch": (try_el, raw_line("Catch"), *new_sent),
        "C-flat-else": (if_el, raw_line("Else"), *new_sent, raw_line("EndIf")),
        "C-flat-if-else": (raw_line('If (x = "1")'), raw_line("Else"), *new_sent),
        "flat-choosefrom": (raw_line("ChooseFrom (x)"), raw_line('Matching "A"'), *new_sent),
        "flat-while": (raw_line(_kw("While") + ' (x = "1")'), *new_sent, raw_line("EndWhile")),
        "own-tag-catch": (
            Raw(
                "<Try>"
                + _line("Try", log_adt)
                + '<Try Data="Catch"><List>'
                + send_in
                + "</List></Try></Try>",
                havoc=False,
            ),
        ),
        "own-tag-matching": (
            Raw(
                "<Case>"
                + _line("ChooseFrom (x)", log_adt)
                + '<Case Data="Matching &quot;A&quot;"><List>'
                + send_in
                + "</List></Case></Case>",
                havoc=False,
            ),
        ),
        "split-list-wrapper": (
            Raw(
                "<If><List>"
                + _line('If (x = "1")', log_adt)
                + "</List><List>"
                + _line("Else", send_in)
                + "</List></If>",
                havoc=False,
            ),
        ),
        # (2) a statement the import cannot read, which never stopped binding
        "B-split-exit": (Log(_ADT), raw_line(_kw("ActionList") + _kw("Exit")), *new_sent),
        "B-unread-verb": (
            Log(_ADT),
            Raw(_line(_kw("MsgDiscard") + " " + _hs(_ADT, "%ADT")), havoc=True),
            *new_sent,
        ),
        "B-after-bind": (
            Create(out, 4),
            raw_line(_kw("ActionList") + _kw("Exit")),
            Create(_NEW, 5),
            SendS(_NEW, "OB_NEW"),
        ),
        # (3) a lowercase verb label
        "label-itemclear-lower": (
            Create(out, 4),
            Block((SendS(out, "OB_OUT"),), "itemclear OUT", True),
        ),
        "label-itemclear-lower-nohavoc": (
            Create(out, 4),
            Block((SendS(out, "OB_OUT"),), "itemclear OUT", False),
        ),
        # (4) a write after a send reaching the sent message (copy-on-Send off, as here)
        "A-write-after-send": (Clone(_ADT, out, 1), SendS(out, "OB_OUT"), Write(out, "W9Z")),
        "A-created-write-after-send": (
            Create(out, 4),
            SendS(out, "OB_OUT"),
            Write(out, "W9Z", "/MSH-10"),
        ),
        "A-write-after-send-then-resend": (
            Clone(_ADT, out, 1),
            SendS(out, "OB_OUT"),
            Write(out, "W9Z"),
            SendS(out, "OB_AGAIN"),
        ),
        # (5) description or comment spans on MsgTreeCopy and MsgCreate
        "clone-description-qualifier": (
            raw_line(
                f"{_kw('MsgTreeCopy')} {_hs(_ADT, '%ADT')}{_span('path', '/')} to "
                f"{_hs(out, '%ADT')}{_span('path', '/')} {_span('description', 'append')}"
            ),
            SendS(out, "OB_OUT"),
        ),
        "create-description-template": (
            raw_line(
                f"{_kw('MsgCreate')} {_hs(out, '%ADT')} as {_lit('ADT^A04')} version "
                f"{_lit('2.5.1')} {_span('description', 'from template T')}"
            ),
            SendS(out, "OB_OUT"),
        ),
        "create-comment-template": (
            raw_line(
                f"{_kw('MsgCreate')} {_hs(out, '%ADT')} as {_lit('ADT^A04')} version "
                f"{_lit('2.5.1')} {_span('comment', 'from template T')}"
            ),
            SendS(out, "OB_OUT"),
        ),
        # (6) an unread attribute on a statement line
        "enabled-false": (
            Log(_ADT),
            Raw(
                _line(_leaf_data(Create(_NEW, 4), "%ADT") or "").replace(
                    "<Line ", '<Line Enabled="false" ', 1
                ),
                havoc=False,
            ),
            Raw(
                _line(_leaf_data(SendS(_NEW, "OB_NEW"), "%ADT") or "").replace(
                    "<Line ", '<Line Enabled="false" ', 1
                ),
                havoc=False,
            ),
        ),
        # (7) a //ADT path
        "foreach-double-slash": (
            raw_line(f"{_kw('ForEach')} {_hs(_ADT, '%ADT')}{_span('path', '//ADT')}"),
            Clone(_ADT, out, 1),
            SendS(out, "OB_OUT"),
        ),
        "clone-double-slash": (
            raw_line(
                f"{_kw('MsgTreeCopy')} {_hs(_ADT, '%ADT')}{_span('path', '//ADT')} to "
                f"{_hs(out, '%ADT')}{_span('path', '/')}"
            ),
            SendS(out, "OB_OUT"),
        ),
        # The same review's refusal-text shape after the narrowing.
        "narrow-refusal-text": (
            Clone(_ADT, out, 1),
            If((("If", None, (Log(_P),)),)),
            SendS(out, "OB_OUT"),
            SendS(_ADT, "OB_IN"),
        ),
    }
    for name, nodes in shapes.items():
        yield Shape(f"review-6fa49a9d5-{name}", "%ADT", nodes)


def _gate_review_shapes() -> Iterator[Shape]:
    """The code review of the whole-list gate itself (round 1): a skeleton written outside its MSH
    then sent, statements spelled with other spacing or quoting, literals carrying HL7 delimiters,
    and lists nested deeper than step 1 accepts."""
    out = H("%OUT")
    clone = Clone(_ADT, out, 1)
    send = f"{_kw('MsgSend')} {_hs(out, '%ADT')} to connection {_lit('OB_OUT')}"
    spelled = {
        "no-spaces": f"{_kw('MsgSend')}{_hs(out, '%ADT')}to connection{_lit('OB_OUT')}",
        "double-space": send.replace(" to ", "  to ", 1),
        "nbsp": send.replace("to connection", "to connection"),
        "line-separator": send.replace("to connection", "to connection"),
        "double-quoted-class": send.replace("class='keyword'", 'class="keyword"'),
        "leading-space": " " + send,
    }
    for name, data in spelled.items():
        yield Shape(f"gate-review-send-{name}", "%ADT", (clone, Raw(_line(data), havoc=False)))
    spaced_clone = (
        f"{_kw('MsgTreeCopy')} {_hs(_ADT, '%ADT')} {_span('path', '/')} to "
        f"{_hs(out, '%ADT')} {_span('path', '/')}"
    )
    yield Shape(
        "gate-review-clone-space-before-path",
        "%ADT",
        (Raw(_line(spaced_clone), havoc=False), SendS(out, "OB_OUT")),
    )
    yield Shape(
        "gate-review-skeleton-write-then-send",
        "%ADT",
        (Create(out, 4), Write(out, "W7Z", "/PID-8"), SendS(out, "OB_OUT")),
    )
    for value in ("A|B", "a\\F\\b", "x^y", "q~r", "t&u"):
        yield Shape(
            f"gate-review-delimiter-{value!r}",
            "%ADT",
            (clone, Write(out, value), SendS(out, "OB_OUT")),
        )
    # Round 2 of the same review: a label read as prose, and a path annotation or spelling.
    for label in ("Section", "While x", "raisesalert", "Raisesalert", "endif", "exit"):
        yield Shape(
            f"gate-review-label-{label}",
            "%ADT",
            (clone, Block((SendS(out, "OB_OUT"),), label, havoc=True)),
        )
    for path in ("/PID-8 (replace all)", "/PID-3 (2)", "/PID-5.1", "/MSH-6 (Receiving Facility)"):
        for verb in ("ItemCopy", "ItemAppend", "ItemClear"):
            yield Shape(
                f"gate-review-path-{verb}-{path}",
                "%ADT",
                (clone, Write(out, "W8Z", path, True, verb), SendS(out, "OB_OUT")),
            )
    # Each write verb over a field already written, on a clone and on msg.
    for target, sent in ((out, "OB_OUT"), (_ADT, "OB_IN")):
        for verb in ("ItemAppend", "ItemClear", "ItemCopy"):
            yield Shape(
                f"gate-review-{verb}-over-a-write-{sent}",
                "%ADT",
                (
                    clone,
                    Write(target, "W1Z"),
                    Write(target, "W2Z", "/PID-8", True, verb),
                    SendS(target, sent),
                ),
            )
    for depth in (12, 34, 40, 49):
        nested: Node = Block((clone, SendS(out, "OB_OUT")))
        for _ in range(depth - 1):
            nested = Block((nested,))
        yield Shape(f"gate-review-nested-{depth}", "%ADT", (nested,))


#: A construct, and a branch marker a ``<Line>`` after it carries as its sibling.
_SIBLING_PAIRS = (
    ("if-else", '<If Data="If (x)"><List/></If>', "Else"),
    ("if-elseif", '<If Data="If (x)"><List/></If>', "ElseIf (y)"),
    ("try-catch", "<Try><List/></Try>", "Catch"),
    ("case-matching", '<Case Data="ChooseFrom (x)"><List/></Case>', 'Matching "M0"'),
)
_FILLED = '<Line Data="ItemClear %ADT/PID-20"/>'
#: Wrappers between such a pair, nested. ``{S}`` is where one carries a statement. A ``filled``
#: wrapper holds a statement of its own, which orphans the branch on main already.
_NESTED_WRAPPERS = {
    "side-by-side": "<List{S}/><Actions{S}/>",
    "inner-of-2": "<List><List{S}/></List>",
    "both-of-2": "<List{S}><List{S}/></List>",
    "all-of-3": "<List{S}><Actions{S}><List{S}/></Actions></List>",
    "innermost-of-3": "<List><List><List{S}/></List></List>",
    "middle-of-3": "<List><List{S}><List/></List></List>",
    "outermost-of-3": "<Actions{S}><List><List/></List></Actions>",
    "filled-one": f"<List{{S}}>{_FILLED}</List>",
    "filled-inner-of-2": f"<List><List{{S}}>{_FILLED}</List></List>",
    "filled-outer-of-2": f"<List{{S}}><List>{_FILLED}</List></List>",
    "filled-beside-the-inner-of-2": f"<List>{_FILLED}<List{{S}}/></List>",
}
_CONTAINER_TAGS = ("Block", "Call", "Case", "Foreach", "If", "Loop", "Try")
#: Every tag the #2632 seeds put a statement on: each container, an unmodelled tag, a list wrapper.
_CARRIER_TAGS = (*_CONTAINER_TAGS, "Switch", "Actions")
_STATEMENT_VERBS = (
    "ItemAppend",
    "ItemClear",
    "ItemCopy",
    "MsgCreate",
    "MsgLog",
    "MsgSend",
    "MsgTreeCopy",
)


def _label_statement_shapes() -> Iterator[Shape]:
    """BACKLOG #2632: a statement in the ``@Data`` of an element that is not a ``<Line>``. Each of
    the seven container tags, an unmodelled tag and a list wrapper carries one. The random shapes
    put one on a ``<Block>`` only, and only ever a ``MsgTreeCopy``, so without these seeds a change
    to the rule for another tag, another verb, or a verb the exporter styled as a keyword, would
    pass the guard untested."""
    out = H("%OUT")
    clone = _leaf_data(Clone(_ADT, out, 1), "%ADT")
    write = _leaf_data(Write(_ADT, "W3Z"), "%ADT")
    send = _leaf_data(SendS(_ADT, "OB_LABEL"), "%ADT")
    # A verb outside the importer's table, styled as a keyword: a statement on a Block alone.
    merge = _leaf_data(Unread("merge", _NEW, _ADT), "%ADT")
    assert clone is not None and write is not None and send is not None and merge is not None

    def carrying(tag: str, data: str, body: tuple[Node, ...] = ()) -> Raw:
        return Raw(f'<{tag} Data="{_esc(data)}"><List>{_render(body, "%ADT")}</List></{tag}>')

    for tag in _CARRIER_TAGS:
        yield Shape(f"2632-{tag}-clone", "%ADT", (carrying(tag, clone), SendS(out, "OB_OUT")))
        yield Shape(f"2632-{tag}-write", "%ADT", (carrying(tag, write), SendS(_ADT, "OB_IN")))
        yield Shape(f"2632-{tag}-send", "%ADT", (carrying(tag, send), SendS(_ADT, "OB_IN")))
        yield Shape(f"2632-{tag}-keyword", "%ADT", (carrying(tag, merge), SendS(_ADT, "OB_IN")))
        yield Shape(
            f"2632-{tag}-clone-over-a-body",
            "%ADT",
            (
                carrying(tag, clone, (Write(out, "W4Z"), SendS(out, "OB_BODY"))),
                SendS(_ADT, "OB_IN"),
            ),
        )
        for verb in _STATEMENT_VERBS:
            for spelling in (verb, verb.lower()):
                yield Shape(
                    f"2632-{tag}-flat-{spelling}",
                    "%ADT",
                    (carrying(tag, f"{spelling} %NEW/ to %ADT/"), SendS(_ADT, "OB_IN")),
                )
    # A wrapper holding a statement, between a construct and the branch marker written after it
    # as a sibling. The adoption must not see the marker: an orphaned branch renders live.
    arm = _render((Write(_ADT, "W5Z", markup=False), SendS(_ADT, "OB_ARM", markup=False)), "%ADT")
    for name, construct, branch in _SIBLING_PAIRS:
        for label, data in (("log", "MsgLog %ADT"), ("clone", clone)):
            between = Raw(construct + carrying("List", data).xml + _line(branch, arm))
            yield Shape(f"2632-List-{label}-before-a-sibling-{name}", "%ADT", (between,))
            # The Lander's hold on PR 1938: the same, with the wrapper nested in others, to a
            # depth of two and three, and the statement on the inner one, the outer, or each.
            for nesting, template in _NESTED_WRAPPERS.items():
                wrappers = template.replace("{S}", f' Data="{_esc(data)}"')
                nested = Raw(construct + wrappers + _line(branch, arm))
                yield Shape(
                    f"2632-List-{label}-{nesting}-before-a-sibling-{name}", "%ADT", (nested,)
                )
    # The other routes by which a marker comes last in a list a branch is adopted in: a body
    # flattened to that level. And a send label over a construct, whose body main left there.
    if_x, else_arm = _SIBLING_PAIRS[0][1], _line("Else", arm)
    for nesting, template in (("one", "<List{S}/>"), ("two", _NESTED_WRAPPERS["inner-of-2"])):
        wrappers = template.replace("{S}", ' Data="MsgLog %ADT"')
        for route, xml in (
            ("a-branch-group", f"<If>{_line('If (x)', '')}{wrappers}</If>"),
            ("a-line-body", _line("ItemClear %ADT/PID-18", if_x + wrappers)),
            ("a-wrapper-around-the-construct", f"<List>{if_x}{wrappers}</List>"),
        ):
            yield Shape(
                f"2632-List-log-{nesting}-deep-at-the-end-of-{route}",
                "%ADT",
                (Raw(xml + else_arm),),
            )
    for tag in ("Block", "Call"):
        over = carrying(tag, "MsgSend %ADT [OB_LABEL]", (Raw(if_x),))
        yield Shape(f"2632-{tag}-send-over-a-construct", "%ADT", (Raw(over.xml + else_arm),))
    # A construct carrying a statement still adopts its own sibling branch.
    carrier = carrying("If", "MsgLog %ADT")
    yield Shape("2632-If-log-before-its-own-sibling-else", "%ADT", (Raw(carrier.xml + else_arm),))
    # Code review of the repair: the shape of the tree is decided in two more places.
    log_wrapper = '<List Data="MsgLog %ADT"/>'
    for name, construct, branch in _SIBLING_PAIRS:
        # A branch marker written in the construct's own list, holding nothing but such a wrapper.
        # It must still open its branch: what follows it is dead until the condition is written.
        inside = construct.replace(
            "<List/>", f"<List>{_FILLED}{_line(branch, log_wrapper)}{arm}</List>"
        )
        yield Shape(f"2632-List-log-in-a-bare-{name}-marker", "%ADT", (Raw(inside),))
        # A label demoted from a call, or a send off a Line, inside an element with no
        # ``@Data``. Whether that element is a branch-group is read from the kind it had on
        # main.
        after = _line(branch, arm)
        for outer, tag, data in (
            ("Call", "Call", "MsgLog %ADT"),
            ("Block", "Call", "MsgLog %ADT"),
            ("Block", "Block", "MsgSend %ADT [OB_LABEL]"),
        ):
            group = f'<{outer}><{tag} Data="{_esc(data)}"/>{construct}</{outer}>'
            yield Shape(
                f"2632-{tag}-{data[:6]}-in-a-bare-{outer}-before-a-{name}",
                "%ADT",
                (Raw(group + after),),
            )
    # Code review of the repair, round 2. A send label beside a send the render never reaches:
    # main does not render a branch held by another branch. Demoting the label takes away the
    # handler's only visible send, and the handler must not fall back to the closing
    # ``return Send``, which would deliver the unrendered one for every message.
    opener = _esc('Matching "M0"')
    held = _line('Matching "M0"') + _line("MsgSend %ADT [OB_HIDDEN]")
    hidden = f'<Case><Block Data="{opener}">{held}</Block>'
    for tag in ("Block", "Call"):
        label = f'<{tag} Data="MsgSend %ADT [OB_LABEL]"/>'
        yield Shape(
            f"2632-{tag}-send-beside-a-send-main-never-renders",
            "%ADT",
            (Raw(hidden + label + "</Case>"),),
        )
    # The Lander's second hold on PR 1938: a send off a Line that main REFUSES, or ends on the
    # ``return None`` that says no destination was named. The head must be no quieter. Every
    # seed above puts the input's own send there, which main delivers, so none of them could
    # show a refusal that went. ``%OUT`` is never copied into here, so main refuses its send.
    refused = _leaf_data(SendS(out, "OB_R"), "%ADT")
    assert refused is not None
    unnamed = f"{_kw('MsgSend')} {_hs(out, '%ADT')}"
    catch = _line("Catch") + _render((Write(_ADT, "W6Z", markup=False),), "%ADT")
    for tag in ("Block", "Call"):
        alone = carrying(tag, refused)
        yield Shape(f"2632-{tag}-send-main-refuses", "%ADT", (alone,))
        yield Shape(
            f"2632-{tag}-send-main-refuses-beside-a-send", "%ADT", (alone, SendS(_ADT, "OB_IN"))
        )
        # A Catch must not swallow the refusal: main re-raises it ahead of every Catch.
        tried = Raw(f"<Try><List>{alone.xml}{catch}</List></Try>")
        yield Shape(f"2632-{tag}-send-main-refuses-in-a-try", "%ADT", (tried,))
        yield Shape(f"2632-{tag}-send-naming-no-destination", "%ADT", (carrying(tag, unnamed),))
        yield Shape(
            f"2632-{tag}-flat-send-naming-no-destination",
            "%ADT",
            (carrying(tag, "MsgSend %OUT"),),
        )
    # A keyword span that does not lead a Block's label, and a table verb that does not lead it:
    # both still read as a label.
    connective = f"Copy patient {_kw('to')} output"
    yield Shape(
        "2632-not-leading-keyword", "%ADT", (carrying("Block", connective), SendS(_ADT, "OB_IN"))
    )
    late = "Step 1: MsgTreeCopy %NEW/ to %ADT/"
    yield Shape("2632-not-leading-verb", "%ADT", (carrying("Block", late), SendS(_ADT, "OB_IN")))


# --- the guard ------------------------------------------------------------------------------------

_SEED = 313
_RANDOM = 1000
_OPEN = 2400
_CHUNKS = 24


def _all_shapes() -> list[Shape]:
    return [
        *_seed_shapes(),
        *_paired_shapes(_SEED),
        *_random_shapes(_SEED, _RANDOM),
        *_open_shapes(_SEED, _OPEN),
    ]


_SHAPES = _all_shapes()


def test_the_battery_is_as_wide_as_it_claims() -> None:
    """Every ordered construct pair at depth 2, every payload, plus the seeds, the random shapes and
    the shapes drawn from the allow-list."""
    pairs = {s.name.rsplit("/", 1)[0] for s in _SHAPES if s.name.count("/") == 2}
    assert len(pairs) == len(_KINDS) ** 2
    assert len(_SHAPES) == len(list(_seed_shapes())) + len(_KINDS) ** 2 * 6 + _RANDOM + _OPEN


def test_open_gate_shapes_are_well_represented() -> None:
    """The guard's own walker finds a large share of the battery fully understood, and on most of
    those the head binds a local, so the oracle checks have real work to do. Measured at the time of
    writing: see ADR 0086."""
    understood = [s for s in _SHAPES if _fully_understood(_render(s.nodes, s.inp))]
    bound = [s for s in understood if "_msg = " in _generate(head, _render(s.nodes, s.inp))[0]]
    assert len(understood) >= 1500
    assert len(bound) >= 1000


def _generate_text(module: Any, text: str) -> _Out:
    try:
        channel = module.parse_package(text)[0]
    except module.CorepointImportError:
        return "", ()
    counts = tuple(module._count_steps(h.steps, in_loop=False) for h in channel.handlers)
    return module.generate_module(channel), counts


_SUB = _render((Create(_OUT, 4), SendS(_OUT, "OB_OUT")), "%ADT")
_CALL = _line(f"{_kw('ActionListCall')} {_lit('Sub')}")
# The three spellings of Lander QA on f0a62ef70a: the attribute, as the XML parser returns it, does
# not spell the verb, and step 1 reads it all the same.
_QA_CALLS = {
    "a-decimal-reference": 'ActionList&#67;all "Sub"',
    "a-hex-reference": 'ActionList&#x43;all "Sub"',
    "an-empty-tag": 'ActionList<b></b>Call "Sub"',
}
# A ``<Call>`` element as step 1 reads the tag: on its local name, in any case.
_CALL_TAGS = {
    "anywhere": "Call",
    "in-lower-case": "call",
    "in-upper-case": "CALL",
    "in-a-namespace": "q:Call",
}


def _calling(
    call: str, condition: str = "If (x)", sub: str = _SUB, *, sub_first: bool = False
) -> str:
    """A package whose list ``Main`` holds the element ``call`` under an ``If``, and whose list
    ``Sub`` is fully understood when it stands alone. ``sub_first`` puts ``Sub`` ahead of ``Main``."""
    main = (
        f'<ActionList Name="Main"><List><If Data="{_esc(condition)}"><List>{call}</List></If>'
        "</List></ActionList>"
    )
    called = f'<ActionList Name="Sub"><List>{sub}</List></ActionList>'
    return f'<Package Name="A">{called + main if sub_first else main + called}</Package>'


def _renders_as_step1(package: str) -> bool:
    return _generate_text(head, package) == _generate_text(step1, package)


@pytest.mark.parametrize(
    "package",
    [
        pytest.param(_calling(_CALL), id="a-list-another-list-calls"),
        pytest.param(_calling(_CALL, sub_first=True), id="a-list-a-later-list-calls"),
        *(
            pytest.param(_calling(_line(data)), id=f"a-call-spelled-with-{name}")
            for name, data in _QA_CALLS.items()
        ),
        *(
            pytest.param(
                f'<Package Name="A" xmlns:q="urn:q"><ActionList Name="Main"><List><{tag} Data="Sub">'
                f'<Actions/></{tag}></List></ActionList><ActionList Name="Sub"><List>{_SUB}</List>'
                "</ActionList></Package>",
                id=f"a-call-tag-{name}",
            )
            for name, tag in _CALL_TAGS.items()
        ),
        pytest.param(
            '<Package Name="A"><ActionList Name="Outer"><List><Loop><List><ActionList Name="Sub">'
            "<List>" + _SUB + "</List></ActionList></List></Loop></List></ActionList></Package>",
            id="a-list-nested-in-a-loop",
        ),
        pytest.param(
            '<Package Name="A"><ActionList Name="Outer"><List><Line><List><ActionList Name="Sub">'
            "<List>" + _SUB + "</List></ActionList></List></Line></List></ActionList></Package>",
            id="a-list-nested-in-a-line",
        ),
        pytest.param(
            '<Foreach><ActionList Name="Sub"><List>' + _SUB + "</List></ActionList></Foreach>",
            id="a-root-that-is-no-package",
        ),
        pytest.param(
            '<Package Name="A" Enabled="false"><ActionList Name="Sub"><List>'
            + _SUB
            + "</List></ActionList></Package>",
            id="an-unread-attribute-on-the-package",
        ),
        pytest.param(
            f'<Package Name="A"><actionlist Name="Sub"><List>{_SUB}</List></actionlist></Package>',
            id="a-list-tag-in-another-case",
        ),
        pytest.param(
            '<Package Name="A" xmlns:q="urn:q"><q:ActionList Name="Sub"><List>'
            + _SUB
            + "</List></q:ActionList></Package>",
            id="a-namespaced-list-tag",
        ),
        pytest.param(
            '<Package Name="A"><Connection Note="ActionListCall Sub"/><ActionList Name="Sub"><List>'
            + _SUB
            + "</List></ActionList></Package>",
            id="a-call-named-outside-every-list",
        ),
        pytest.param(
            '<Package Name="A"><Rules><Call Data="Sub"/></Rules><ActionList Name="Sub"><List>'
            + _SUB
            + "</List></ActionList></Package>",
            id="a-call-tag-outside-every-list",
        ),
    ],
)
def test_the_package_around_a_list_can_close_its_gate(package: str) -> None:
    """The shapes above all sit in one fixed package frame. These do not. A list another list may
    call, before it or after it: by the plain verb, by a verb the attribute does not spell, or by a
    ``<Call>`` tag in any case or namespace. A list nested in another list's construct. A root that
    is no package. An unread attribute on the package. A list whose own tag is in another case or a
    namespace. A call named, or a ``<Call>`` tag, outside every list. Each renders exactly as step 1
    renders it (code review of the gate, round 2, and Lander QA on f0a62ef70a). The control: the
    same list alone in a plain package opens the gate."""
    assert _renders_as_step1(package)
    plain = f'<Package Name="A"><ActionList Name="Sub"><List>{_SUB}</List></ActionList></Package>'
    assert not _renders_as_step1(plain)


# --- a call the attribute does not spell ----------------------------------------------------------
#
# Step 1 reads a verb with the markup stripped, so the attribute need not spell ``ActionListCall``
# for step 1 to read a call (Lander QA on f0a62ef70a; ADR 0086 has the readings). The seeds below
# write ONE character of the verb another way, at every position, in every frame a verb can sit in,
# and a second arm writes several at once. Which of them hide a call is decided by step 1's OWN
# parse of the package: never by the head's gate, and never by a list of spellings.

_CALL_VERBS = (
    "ActionListCall",
    "actionlistcall",
    "ACTIONLISTCALL",
    "Actionlistcall",
    "actionListCall",
)
#: One character of a verb, written so that the attribute no longer spells the verb.
_HIDES: dict[str, Callable[[str], str]] = {
    "decimal": lambda ch: f"&#{ord(ch)};",
    "decimal-padded": lambda ch: f"&#{ord(ch):05d};",
    "decimal-open": lambda ch: f"&#{ord(ch)}",
    "hex": lambda ch: f"&#x{ord(ch):x};",
    "hex-upper": lambda ch: f"&#X{ord(ch):X};",
    "hex-open": lambda ch: f"&#x{ord(ch):x}",
    "empty-tag": lambda ch: f"<b></b>{ch}",
    "void-tag": lambda ch: f"<br/>{ch}",
    "wrapping-tag": lambda ch: f"<i>{ch}</i>",
    "tag-with-attributes": lambda ch: f"<font color='red'>{ch}</font>",
}
#: Where a verb can sit in ``@Data``.
_FRAMES: dict[str, Callable[[str], str]] = {
    "flat": lambda verb: f'{verb} "Sub"',
    "keyword": lambda verb: f"{_kw(verb)} {_lit('Sub')}",
    "keyword-double-quoted": lambda verb: f'<span class="keyword">{verb}</span> {_lit("Sub")}',
    "keyword-after-prose": lambda verb: f"{_span('comment', 'note')} {_kw(verb)} {_lit('Sub')}",
    "keyword-in-a-span": lambda verb: f"{_span('block', _kw(verb))} {_lit('Sub')}",
    # Read whole, ``&#xAc`` is one reference and the verb is gone. Read span by span, it is there.
    "keyword-after-an-open-reference": lambda verb: f"&#x{_kw(verb)} {_lit('Sub')}",
}
#: The element and the attribute key step 1 reads a statement from: ``@Data`` in any case or
#: namespace, on a ``<Line>`` or as a ``<Block>`` label.
_CARRIERS: dict[str, Callable[[str], str]] = {
    "a-line": _line,
    "a-lower-case-key": lambda data: f'<Line data="{_esc(data)}"/>',
    "an-upper-case-key": lambda data: f'<Line DATA="{_esc(data)}"/>',
    "a-namespaced-key": lambda data: f'<Line xmlns:q="urn:q" q:Data="{_esc(data)}"/>',
    "a-block-label": lambda data: f'<Block Data="{_esc(data)}"><List/></Block>',
    "a-line-with-a-body": lambda data: _line(data, ""),
}
#: Calls no cell of the table above reaches: step 1 reads each from the whole value only, because no
#: ``keyword`` span holds a verb. A span cuts the verb, or cuts one reference in two.
_WHOLE_VALUE_CALLS = {
    "a-span-inside-a-flat-verb": "ActionList<span class='x'>C</span>all \"Sub\"",
    "a-reference-a-span-cuts-in-two": "ActionList&#6<span class='x'>7;</span>all \"Sub\"",
}
#: Elements step 1 reads no call from, which name one all the same: in the raw attribute only, in a
#: string step 1 never reads, or in another spelling. The gate is more eager than step 1 on each.
_MENTIONS = {
    "after-an-open-reference": _line('&#xActionListCall "Sub"'),
    "inside-a-tag": _line("<b title='ActionListCall'>note</b>"),
    "as-an-element-tag": '<ActionListCall Data="Sub"/>',
    "as-an-attribute-name": '<Line ActionListCall="Sub"/>',
    "as-the-text-in-an-element": '<Line>ActionListCall "Sub"</Line>',
    "as-the-text-after-an-element": _line("MsgLog %ADT") + 'ActionListCall "Sub"',
    "as-a-span-class": _line(
        f"{_kw('Call')} {_lit('Sub')} {_span('action-list-call-pass', 'pass %ADT')}"
    ),
    "in-another-attribute": '<Line Data="MsgLog %ADT" Comment="ActionListCall Sub"/>',
    "with-underscores": _line('Action_List_Call "Sub"'),
    "with-dots": _line('Action.List.Call "Sub"'),
    "with-a-digit": _line('ActionList2Call "Sub"'),
    "with-a-space": _line('ActionList Call "Sub"'),
}


def _step1_reads_a_call(element: str) -> bool:
    """Whether step 1's own parse of a package holding ``element`` finds a call: the baseline's
    reading."""
    try:
        channel = step1.parse_package(_calling(element))[0]
    except step1.CorepointImportError:
        return False
    stack = [step for handler in channel.handlers for step in handler.steps]
    while stack:
        step = stack.pop()
        if isinstance(step, step1.Control):
            if step.kind == "call":
                return True
            stack.extend((*step.body, *step.branches))
    return False


def _hides_a_call(data: str, carrier: Callable[[str], str] = _line) -> bool:
    """Whether ``data`` does not spell the verb, and step 1 reads a call from it all the same."""
    return "actionlistcall" not in data.lower() and _step1_reads_a_call(carrier(data))


def _closes(element: str) -> bool:
    """Whether a package holding ``element`` renders as step 1, with ``Sub`` after ``Main`` and with
    ``Sub`` before it."""
    return all(_renders_as_step1(_calling(element, sub_first=first)) for first in (False, True))


def _left_open(hidden: list[str], carrier: Callable[[str], str] = _line) -> str:
    """The hidden calls the gate stays open on, as a failure message, or ``""``."""
    failures = [data for data in hidden if not _closes(carrier(data))]
    return "\n".join(failures[:10]) + f"\n... {len(failures)} of {len(hidden)}" if failures else ""


def _one_hidden(frame: str, hide: str) -> list[str]:
    """Each ``@Data`` in ``frame`` with one character of the verb written as ``hide`` writes it."""
    return [
        _FRAMES[frame](verb[:at] + _HIDES[hide](verb[at]) + verb[at + 1 :])
        for verb in _CALL_VERBS
        for at in range(len(verb))
    ]


def _several_hidden(seed: int, count: int) -> list[str]:
    """``count`` values with two to five characters of the verb each written another way."""
    rng = random.Random(seed)
    hides, frames = list(_HIDES.values()), list(_FRAMES.values())
    found: list[str] = []
    for _ in range(count):
        verb = rng.choice(_CALL_VERBS)
        at = set(rng.sample(range(len(verb)), rng.randint(2, 5)))
        hidden = "".join(rng.choice(hides)(ch) if i in at else ch for i, ch in enumerate(verb))
        found.append(rng.choice(frames)(hidden))
    return found


@pytest.mark.parametrize("hide", _HIDES)
@pytest.mark.parametrize("frame", _FRAMES)
def test_a_call_the_attribute_does_not_spell_closes_the_gate(frame: str, hide: str) -> None:
    """Wherever step 1 reads a call the attribute does not spell, the head renders the package as
    step 1 does. Every frame and every way of writing a character hides at least one call, so no
    cell of this table passes by testing nothing."""
    hidden = [data for data in _one_hidden(frame, hide) if _hides_a_call(data)]
    assert hidden, "nothing here hides a call from the attribute, so this cell tests nothing"
    assert not _left_open(hidden)


@pytest.mark.parametrize("carrier", _CARRIERS)
def test_a_hidden_call_closes_the_gate_wherever_step1_reads_data(carrier: str) -> None:
    """Step 1 reads ``@Data`` under a key in any case or namespace, and on a ``<Block>`` as on a
    ``<Line>``. The gate reads every attribute of every element, so it closes on each."""
    carry = _CARRIERS[carrier]
    values = [*_one_hidden("flat", "decimal"), *_one_hidden("keyword", "empty-tag")]
    hidden = [data for data in values if _hides_a_call(data, carry)]
    assert hidden, "step 1 reads no hidden call here, so this carrier tests nothing"
    assert not _left_open(hidden, carry)


@pytest.mark.parametrize("data", _WHOLE_VALUE_CALLS.values(), ids=list(_WHOLE_VALUE_CALLS))
def test_a_call_only_the_whole_value_spells_closes_the_gate(data: str) -> None:
    assert _hides_a_call(data)
    assert _closes(_line(data))


@pytest.mark.parametrize("element", _MENTIONS.values(), ids=list(_MENTIONS))
def test_a_call_step1_does_not_read_still_closes_the_gate(element: str) -> None:
    """The gate reads what step 1 reads AND more: the raw value it always read, every string of
    every element, and the letters alone."""
    assert _generate_text(step1, _calling(element))[0], "step 1 must import the package"
    assert not _step1_reads_a_call(element)
    assert _closes(element)


def test_a_call_hidden_at_several_characters_closes_the_gate() -> None:
    hidden = [data for data in _several_hidden(_SEED, 600) if _hides_a_call(data)]
    assert len(hidden) >= 200
    assert not _left_open(hidden)


def test_a_reference_outside_a_call_leaves_the_gate_open() -> None:
    """The control for the tests above: the same package holding a reference or a tag in a verb
    that is no call still opens the gate for ``Sub``, wherever ``Sub`` sits. So those tests pass
    because the head saw the call, and not because any reference or tag closes every gate."""
    for data in (
        "MsgLo&#103; %ADT",
        "MsgLo<b></b>g %ADT",
        f"&#x{_kw('MsgLog')} {_hs(_ADT, '%ADT')}",
    ):
        assert not _step1_reads_a_call(_line(data))
        for first in (False, True):
            assert not _renders_as_step1(_calling(_line(data), sub_first=first)), data


@pytest.mark.parametrize("spelling", _QA_CALLS.values(), ids=list(_QA_CALLS))
def test_the_f0a62ef70a_markup_call_repro_does_not_fail_open(spelling: str) -> None:
    """Lander QA on f0a62ef70a, as filed: one list calls another under an ``If``, with the verb
    spelled so the attribute does not hold it. The called list builds a message and sends it. Step 1
    refuses that send, and the head must not turn it into a send made for every message."""
    built = _render((Create(_NEW, 4), SendS(_NEW, "OB_NEW")), "%ADT")
    package = _calling(_line(spelling), 'If $FLAG = "1"', built)
    head_src, step1_src = _generate_text(head, package)[0], _generate_text(step1, package)[0]
    assert "raise NotImplementedError" in step1_src
    assert 'Send("OB_NEW", new_msg)' not in head_src
    assert head_src == step1_src


def test_the_walker_tells_the_gate_apart_on_its_own_seeds() -> None:
    """The control for the walker: it accepts a plain clone-write-send and refuses one spoiler of
    each kind, so a walker that accepts everything (or nothing) cannot pass the guard."""
    plain = (Clone(_ADT, _OUT, 1), Write(_OUT, "W1Z"), SendS(_OUT, "OB_OUT"))
    assert _fully_understood(_render(plain, "%ADT"))
    spoiled = [s for s in _round3_shapes() if "write-after-send" not in s.name]
    assert len(spoiled) == 20
    assert not any(_fully_understood(_render(s.nodes, s.inp)) for s in spoiled)


# --- the baseline's one amendment (BACKLOG #2632) -------------------------------------------------

_STATEMENT_WORD = re.compile("|".join(_STATEMENT_VERBS), re.IGNORECASE)
_ANY_TAG = re.compile(r"<[^<>]*>")
_VOCABULARY_CALL = re.compile(r"^\s*(?:set_field|append_to_field|copy_field)\(.*$", re.MULTILINE)


def _may_carry_a_label_statement(xml: str) -> bool:
    """Whether some element's ``@Data`` could be a statement off a ``<Line>``. Written apart from
    the importer and WIDER than its rule on purpose: any element but a ``<Line>``, live or not,
    whose ``@Data`` names one of the seven statement verbs anywhere, or holds a ``keyword`` span."""
    from messagefoundry._vendor.defusedxml.ElementTree import fromstring

    for elem in fromstring(_package(xml)).iter():
        if elem.tag.rsplit("}", 1)[-1].lower() == "line":
            continue
        for key, data in elem.attrib.items():
            if key.rsplit("}", 1)[-1].lower() == "data" and (
                "keyword" in data or _STATEMENT_WORD.search(html.unescape(_ANY_TAG.sub("", data)))
            ):
                return True
    return False


def _unmapped_names(out: _Out) -> list[str]:
    """Every name the summary counts unmapped."""
    return [name for counts in out[1] for name in counts[1]]


def _unmapped(out: _Out) -> int:
    """How many steps the summary counts unmapped."""
    return len(_unmapped_names(out))


def _handler_lines(src: str) -> list[str]:
    """The lines of the generated handler, blank ones left out, its closing ``return`` last. The
    guard wraps every list in one action-list, so a module holds one handler."""
    return [line for line in src.split("@handler")[-1].splitlines() if line]


# A LOUD line: a live send, a refusal, or the guard that re-raises a refusal ahead of a Catch.
_LOUD = re.compile(
    r"^(\s*)(?:sends\.append\(Send\(|raise NotImplementedError\(|except NotImplementedError:)"
)


def _loud(lines: Sequence[str]) -> Counter[int]:
    """The loud lines among ``lines``, counted by indent. One at the handler's own level acts on
    every message. The same line one level in is dead until someone writes the condition."""
    return Counter(len(m.group(1)) for m in map(_LOUD.match, lines) if m is not None)


def _quieter(was: _Out, now: _Out) -> list[str]:
    """Every way ``now`` is QUIETER than ``was``, which is main's tree as vendored. It must be
    none. The rule (ADR 0086 §2(b.4)):

    (b) where main sends or refuses, ``now`` sends or refuses. No loud line goes, at any indent
        (:func:`_loud`), and the handler's closing ``return`` is main's line. A refusal sends the
        message to ERROR. With a comment in its place the handler returns an empty list or
        ``None``, and the message is FILTERED with nothing said.
    (c) what main counted unmapped is still counted, name for name, and the handler holds at
        least as many ``# TODO`` lines.

    LOUDER is allowed, and is the whole of what the amendment does: a delivery that becomes a
    refusal, a mapped step that becomes a counted TODO. Live code it must not add is clause (a),
    which :func:`_breaches` reads."""
    if bool(was[0]) != bool(now[0]):
        return ["(refusal) one of the two refuses the whole list, and the other renders it"]
    if not was[0]:
        return []
    old, new = _handler_lines(was[0]), _handler_lines(now[0])
    found: list[str] = []
    lost = _loud(old) - _loud(new)
    if lost:
        found.append(f"(b) a send or a refusal of main's is gone, at indent {sorted(lost)}")
    if new[-1] != old[-1]:
        found.append(f"(b) the handler ends on {new[-1]!r} where main ends on {old[-1]!r}")
    uncounted = Counter(_unmapped_names(was)) - Counter(_unmapped_names(now))
    if uncounted:
        found.append(f"(c) main counts {sorted(uncounted)} unmapped, and this does not")
    if sum("# TODO" in line for line in new) < sum("# TODO" in line for line in old):
        found.append("(c) a TODO line main writes is gone")
    return found


def _breaches(xml: str, was: _Out, now: _Out) -> list[str]:
    """Every way ``now`` breaks the bound on what BACKLOG #2632 may change, against ``was``, the
    tree exactly as vendored.

    It changes a list only when an element in it may carry a statement off a ``<Line>``, by a
    reading written apart from the rule and wider than it. And where it changes a list:

    (a) it adds no live send, inline or in the closing ``return``, and no vocabulary call;
    (b), (c) it is never quieter than main: see :func:`_quieter`.

    It then counts at least one more step unmapped, with the marker's reason in the module. The
    exception is a list whose counts stay as they were: a statement under a ``@Disabled``
    ancestor, one on an unmodelled tag beside no send the scan reads, or a send off a ``<Line>``
    that main already counted unmapped. There only comment lines and refusals change."""
    if now == was:
        return []
    found: list[str] = []
    if not _may_carry_a_label_statement(xml):
        found.append("(rule) no element here may carry a statement off a Line")
    if Counter(_live_sends(now[0])) - Counter(_live_sends(was[0])):
        found.append("(a) a live send main does not make")
    if Counter(_trailing_sends(now[0])) - Counter(_trailing_sends(was[0])):
        found.append("(a) a closing return that delivers where main's does not")
    if Counter(_VOCABULARY_CALL.findall(now[0])) - Counter(_VOCABULARY_CALL.findall(was[0])):
        found.append("(a) a vocabulary call main does not make")
    found.extend(_quieter(was, now))
    if _unmapped(now) > _unmapped(was):
        if step1._LABEL_STATEMENT_WHY not in now[0]:
            found.append("(reason) one more step is unmapped, and no marker says why")
        return found
    was_lines, now_lines = Counter(was[0].splitlines()), Counter(now[0].splitlines())
    changed = (was_lines - now_lines) + (now_lines - was_lines)
    if now[1] != was[1]:
        found.append("(counts) the counts change, and no more is unmapped")
    if not all(line.lstrip().startswith("#") or _REFUSAL.match(line) for line in changed):
        found.append("(code) more than comment lines and refusals change")
    return found


def _bound(name: str, xml: str) -> tuple[bool, list[str]]:
    """Whether the amended baseline renders the list ``xml`` otherwise than the vendored tree
    does, and every way it breaks the bound of :func:`_breaches`.

    The head is held to the same bound, against the same vendored tree, wherever the gate is
    closed. On the battery that is what the head-equals-baseline check already implies. On a list
    drawn with no grammar nothing else compares the head with main. A fully understood list takes
    the step 2 path, where a refusal may become a delivery the oracle proves."""
    was, now = _generate(step1_as_vendored, xml), _generate(step1, xml)
    broken = [f"{name}: the amended baseline: {b}" for b in _breaches(xml, was, now)]
    # The head's own output is judged only where it is not the baseline's, which was just judged.
    if not _fully_understood(xml) and (ahead := _generate(head, xml)) != now:
        broken += [f"{name}: the head: {b}" for b in _breaches(xml, was, ahead)]
    return now != was, broken


def _amendment_changes(shape: Shape) -> bool:
    """Whether the amended baseline renders ``shape`` otherwise than the vendored tree does, having
    checked that the change is one the amendment may make: see :func:`_bound`."""
    changes, broken = _bound(shape.name, _render(shape.nodes, shape.inp))
    assert not broken, "\n".join(broken)
    return changes


def _assert_within_the_bound(shapes: Sequence[tuple[str, str]]) -> None:
    broken: list[str] = []
    for name, xml in shapes:
        broken.extend(_bound(name, xml)[1])
    assert not broken, "\n".join(broken[:20]) + f"\n... {len(broken)} in all"


@pytest.mark.parametrize("chunk", range(_CHUNKS))
def test_the_amendment_changes_only_a_list_holding_a_statement_off_a_line(chunk: int) -> None:
    """The baseline is main's step 1 tree plus one amendment, so this test bounds what the amendment
    may change, against the tree exactly as vendored: see :func:`_bound`. Over the battery here,
    and over the lists drawn with no grammar in ``test_no_raw_list_is_quieter_than_main``."""
    _assert_within_the_bound(
        [(shape.name, _render(shape.nodes, shape.inp)) for shape in _SHAPES[chunk::_CHUNKS]]
    )


def test_the_amendment_reaches_every_seed_written_for_it() -> None:
    """The bound above is not vacuous: the seed that recorded the defect changes, and so does every
    statement on every carrier tag. Three kinds of seed must NOT change, or the rule is wider than
    it says: a keyword-styled verb outside the table anywhere but on a ``<Block>`` or a list
    wrapper, a keyword span that does not lead a Block's label, and a table verb that does not
    lead it."""
    assert {tag.lower() for tag in _CONTAINER_TAGS} == set(head._CONTAINER_KIND_BY_TAG)
    assert {verb.lower() for verb in _STATEMENT_VERBS} == head._STATEMENT_VERBS
    recorded = next(s for s in _SHAPES if s.name == "d26545d6f-open-1-block-label")
    assert _amendment_changes(recorded)
    for shape in _label_statement_shapes():
        _, tag, kind = shape.name.split("-", 2)
        expected = tag in ("Block", "Actions") if kind == "keyword" else tag != "not"
        assert _amendment_changes(shape) is expected, shape.name


def _skeleton(module: Any, xml: str) -> tuple[Any, ...] | None:
    """The SHAPE of the parsed list, or ``None`` where the import refuses: every construct as
    ``(kind, body, branches)``, every other step as ``"."``. Label markers are left out, and a
    label demoted from a call counts as the kind it had. So this is the tree as main
    sees it. Which construct holds which branch, and which branch marker stands alone as an
    orphan, are both in it."""
    try:
        channel = module.parse_package(_package(xml))[0]
    except module.CorepointImportError:
        return None
    marker = getattr(module, "LabelMarker", ())

    def shape(steps: Sequence[Any]) -> tuple[Any, ...]:
        return tuple(
            (
                getattr(step, "demoted_from", "") or getattr(step, "was", "") or step.kind,
                shape(step.body),
                shape(step.branches),
            )
            if isinstance(step, module.Control)
            else "."
            for step in steps
            if not isinstance(step, marker)
        )

    return tuple(shape(handler.steps) for handler in channel.handlers)


def _adopted(steps: Sequence[Any]) -> int:
    """How many branches the constructs of a skeleton hold."""
    return sum(
        len(step[2]) + _adopted(step[1]) + _adopted(step[2]) for step in steps if step != "."
    )


def _structure_moved(name: str, xml: str) -> tuple[int, list[str]]:
    """What the amendment, or the head, changes about the shape of the tree, against the file
    exactly as vendored. It must change nothing. A statement off a ``<Line>`` is marked, and a
    marker is no statement position. So no branch main adopts is orphaned, at any depth, none it
    orphans is adopted, and no construct appears or goes. The head is held to that wherever the
    gate is closed. A fully understood list takes the step 2 path, which builds its own tree.

    Also says how many branches main adopts in the list: where it adopts none, or refuses the
    list, there is no branch for the amendment to orphan."""
    was = _skeleton(step1_as_vendored, xml)
    modules = [("the amended baseline", step1)]
    if not _fully_understood(xml):
        modules.append(("the head", head))
    moved = [
        f"{name}: {who} parses {now} where main parses {was}"
        for who, module in modules
        if (now := _skeleton(module, xml)) != was
    ]
    return sum(_adopted(handler) for handler in was or ()), moved


_RAW_TAGS = (
    *("List", "Actions", "Line", "Line", "Line", "Block", "Call"),
    *("If", "Try", "Case", "Foreach", "Loop", "Switch"),
)
_RAW_DATA = (
    *(None, None, None, "Section", "MsgLog %ADT", "MsgSend %ADT [OB_X]", "ItemClear %ADT/PID-19"),
    *("MsgTreeCopy %ADT/ to %OUT/", "If (x)", "Else", "ElseIf (y)", "Catch", 'Matching "M"'),
    *(
        "ChooseFrom (x)",
        'ActionListCall "Sub"',
        "LoopExit",
        "Try",
        "Returns",
        "ForEach %ADT/OBX $o",
    ),
)
#: Role-marked statements, so the keyword half of the rule and the handle scan are in play.
_RAW_MARKED = tuple(
    data
    for data in (
        _leaf_data(Clone(_ADT, _OUT, 1), "%ADT"),
        _leaf_data(SendS(_OUT, "OB_R"), "%ADT"),
        _leaf_data(Unread("merge", _NEW, _ADT), "%ADT"),
    )
    if data is not None
)
#: One element in ten is switched off, and one in ten carries an operator's comment.
_RAW_EXTRA = (*[""] * 8, ' Disabled="1"', ' Comment="note"')
_RAW = 4000


def _raw_element(rng: random.Random, depth: int) -> str:
    """One element of any tag, with any ``@Data``, around up to three more. No grammar: a branch
    verb on a container, a statement on a wrapper, a wrapper in a branch line. Not every spelling:
    one casing per tag, and three role-marked statements."""
    tag, data = rng.choice(_RAW_TAGS), rng.choice((*_RAW_DATA, *_RAW_MARKED))
    attr = f' Data="{_esc(data)}"' if data is not None else ""
    attr += rng.choice(_RAW_EXTRA)
    if depth == 0 or rng.random() < 0.3:
        return f"<{tag}{attr}/>"
    children = "".join(_raw_element(rng, depth - 1) for _ in range(rng.randint(0, 3)))
    if tag not in ("List", "Actions") and rng.random() < 0.6:
        children = f"<List>{children}</List>"
    return f"<{tag}{attr}>{children}</{tag}>"


def _structure_shapes() -> list[tuple[str, str]]:
    """Every shape of the battery, and ``_RAW`` lists drawn with no grammar at all. The battery's
    grammar writes well-formed constructs, so a route nobody thought to seed is not in it. The
    raw lists are for this test alone: the oracle does not model them."""
    rng = random.Random(_SEED)
    raw = ("".join(_raw_element(rng, 3) for _ in range(rng.randint(1, 4))) for _ in range(_RAW))
    return [
        *((shape.name, _render(shape.nodes, shape.inp)) for shape in _SHAPES),
        *((f"raw-{i}", xml) for i, xml in enumerate(raw)),
    ]


_STRUCTURE_SHAPES = _structure_shapes()
#: The lists drawn with no grammar, which follow the battery in ``_STRUCTURE_SHAPES``.
_RAW_LISTS = _STRUCTURE_SHAPES[len(_SHAPES) :]
#: The fewest branches main must adopt over the lists of one chunk of the shape test.
_ADOPTED_A_CHUNK = 200


@pytest.mark.parametrize("chunk", range(_CHUNKS))
def test_no_branch_main_adopts_is_orphaned(chunk: int) -> None:
    """The acceptance rule of the repair to PR 1938, and more than it: the amendment changes the
    shape of no tree. See :func:`_structure_moved`."""
    moved: list[str] = []
    adopted = 0
    for name, xml in _STRUCTURE_SHAPES[chunk::_CHUNKS]:
        branches, found = _structure_moved(name, xml)
        adopted += branches
        moved.extend(found)
    assert not moved, "\n".join(moved[:20]) + f"\n... {len(moved)} in all"
    # Equal trees prove nothing where main adopts no branch, or where the import refused.
    assert adopted >= _ADOPTED_A_CHUNK


@pytest.mark.parametrize("chunk", range(_CHUNKS))
def test_no_raw_list_is_quieter_than_main(chunk: int) -> None:
    """The bound of :func:`_bound`, over the lists drawn with no grammar. The battery's seeds all
    put a send main DELIVERS where a label belongs, so a refusal that went was in no shape the
    bound read (the Lander's second hold on PR 1938). The raw lists draw a role-marked send of
    ``%OUT`` onto any element, with a copy into it or without."""
    _assert_within_the_bound(_RAW_LISTS[chunk::_CHUNKS])


# The control for the bound's rule (b). The amended baseline, but with a send off a ``<Line>``
# rendered as a label and its marker, and no refusal: the rule as the Lander held it on PR 1938.
_SEND_ARM = '    if kind == "send":\n'
_QUIET_SEND = (
    '    if marker and kind == "send":\n'
    '        return [Control("block", tag, statement, body=tuple(marker)), *body]\n'
)
#: The fewest raw lists on which that control must turn the bound red.
_QUIET_RAW_FLOOR = 300


def _quiet_baseline() -> Any:
    amendments = (
        *(pair for pair in _STEP1_AMENDMENTS if pair[0] != _SEND_REFUSAL),
        (_SEND_ARM, _QUIET_SEND + _SEND_ARM),
    )
    return _load_step1("_mefor_corepoint_import_step1_quiet_send", amendments)


def test_the_bound_sees_a_refusal_turned_into_a_quiet_filter() -> None:
    """The bound's rules (b) and (c) can fail. With a send off a Line rendered as a comment, the
    bound is red on every seed where main refuses that send or delivers it, and on raw lists in
    number. With the amendment as it stands, the tests above hold it green on the same lists."""
    quiet = _quiet_baseline()

    def breaches(xml: str) -> list[str]:
        return _breaches(xml, _generate(step1_as_vendored, xml), _generate(quiet, xml))

    gone = "(b) a send or a refusal of main's is gone"
    seeds = [
        s
        for s in _label_statement_shapes()
        if "-send-main-refuses" in s.name or s.name in ("2632-Block-send", "2632-Call-send")
    ]
    assert len(seeds) == 8
    for shape in seeds:
        found = breaches(_render(shape.nodes, shape.inp))
        assert any(b.startswith(gone) for b in found), shape.name
    quieter = [name for name, xml in _RAW_LISTS if any(b[:3] == "(b)" for b in breaches(xml))]
    assert len(quieter) >= _QUIET_RAW_FLOOR
    # Each clause of the rule, on one handler. main refuses this send and names no destination.
    lone = next(s for s in _label_statement_shapes() if s.name.endswith("-naming-no-destination"))
    was = _generate(step1_as_vendored, _render(lone.nodes, lone.inp))
    assert not _quieter(was, was)
    lines = was[0].splitlines()
    assert _REFUSAL.match(lines[-2]) and lines[-1].startswith("    return None  # TODO")

    def said(src: list[str], counts: tuple[tuple[int, list[str], int], ...] = was[1]) -> str:
        return " ".join(_quieter(was, ("\n".join(src) + "\n", counts)))

    assert gone in said([*lines[:-2], lines[-1]])
    assert gone in said([*lines[:-2], "    " + lines[-2], lines[-1]])
    assert "(b) the handler ends on" in said([*lines[:-1], "    return sends"])
    assert "(c) a TODO line main writes is gone" in said([*lines[:-3], *lines[-2:]])
    assert "(c) main counts ['MsgSend'] unmapped" in said(lines, ((0, [], 0),))


def test_the_structure_check_sees_an_orphan_and_an_adoption() -> None:
    """The control for the test above: the reading tells an adopted branch from an orphaned one, on
    the vendored tree itself. A ``<List>`` holding a statement between an If and its Else orphans
    the Else on main; an empty one does not."""
    if_x, arm = _SIBLING_PAIRS[0][1], _line("Else", _line("MsgLog %ADT"))
    adopted = _skeleton(step1_as_vendored, if_x + "<List/>" + arm)
    orphaned = _skeleton(step1_as_vendored, if_x + "<List>" + _FILLED + "</List>" + arm)
    assert adopted == ((("if", (), (("else", (".",), ()),)),),)
    assert orphaned == ((("if", (), ()), ".", ("else", (".",), ())),)
    # The raw lists reach what the seeds are written for: branches main adopts, in number, in
    # lists where the amendment marks a statement.
    raw = [xml for _, xml in _RAW_LISTS]
    marked = [xml for xml in raw if step1._LABEL_STATEMENT_WHY in _generate(step1, xml)[0]]
    assert len(raw) == _RAW and len(marked) >= _RAW // 2
    assert (
        sum(_adopted(h) for xml in marked for h in _skeleton(step1_as_vendored, xml) or ()) >= 500
    )
    # And every seed with a wrapper between a construct and a sibling branch main adopts is one
    # the bound sees change.
    nested = [s for s in _label_statement_shapes() if "-before-a-sibling-" in s.name]
    held = [
        s
        for s in nested
        if any(_adopted(h) for h in _skeleton(step1_as_vendored, _render(s.nodes, s.inp)) or ())
    ]
    filled = sum(name.startswith("filled") for name in _NESTED_WRAPPERS)
    assert len(nested) == len(_SIBLING_PAIRS) * 2 * (1 + len(_NESTED_WRAPPERS))
    assert len(held) == len(nested) - len(_SIBLING_PAIRS) * 2 * filled > 0
    assert all(_amendment_changes(s) for s in held)


@pytest.mark.parametrize("chunk", range(_CHUNKS))
def test_the_head_never_fails_open_where_step1_did_not(chunk: int) -> None:
    failures: list[str] = []
    for shape in _SHAPES[chunk::_CHUNKS]:
        found = _violations(shape)
        if found:
            failures.append(f"{shape.name}: {found[0]}  ({len(found)} total)")
    assert not failures, "\n".join(failures[:40]) + f"\n... {len(failures)} shapes fail open"


@pytest.mark.parametrize(
    "shape",
    [s for s in _seed_shapes() if s.name.startswith("d26545d6f-high")],
    ids=lambda s: s.name,
)
def test_the_d26545d6f_high_repros_do_not_fail_open(shape: Shape) -> None:
    """Named separately so the Lander's HIGH on PR 1900 stays visible in a test id."""
    assert _violations(shape) == []
