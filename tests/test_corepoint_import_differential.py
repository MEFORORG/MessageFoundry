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
the head against itself; and because a CI checkout need not hold that ref.

Each shape also carries its own ORACLE: an abstract interpreter over the shape (not over the XML)
that says, for every ``MsgSend``, which trees the export may send there, over every path, and in
both a case-sensitive and a case-insensitive reading of handle names (Corepoint's is unverified).
Anything the oracle does not model makes every handle unknown. The generated handlers are then
EXECUTED against one synthetic input, and their source is read, and the guard asserts:

1. (i) the head never delivers where step 1 raises or filters unless the oracle proves the tree;
2. (ii) the head never lifts a send out of a branch: no send line sits at a shallower indent than in
   step 1, and no send the oracle places in a branch runs on the all-placeholders-false path;
3. (iii) the head never delivers ``msg`` for a send of another handle, or of a tree the oracle
   proves is not the input;
4. every LIVE send line in the head is provable on every path: the oracle's tree set at that send is
   exactly one known tree, of the same kind as the local (``msg`` only for the input itself). This
   reaches the branches the executed path skips;
5. a local other than ``msg`` is bound, and sent, only at the handler's own level (the narrowing,
   ADR 0086). Together with an execution that runs past every refusal (each ``raise
   NotImplementedError`` is read as a human deleting it), that puts every such send on the executed
   path, so (i) compares the tree it actually delivers, not only its kind.

All fixtures are synthetic. The shapes come from a fixed seed, so a failure is reproducible.
"""

from __future__ import annotations

import hashlib
import random
import re
import sys
import types
import unicodedata
from collections.abc import Iterator, Sequence
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


def _load_step1() -> Any:
    name = "_mefor_corepoint_import_step1"
    if name in sys.modules:
        return sys.modules[name]
    module = types.ModuleType(name)
    # dataclasses resolve string annotations through sys.modules, so register before running it.
    sys.modules[name] = module
    exec(compile(_step1_bytes().decode("utf-8"), str(_STEP1_PATH), "exec"), module.__dict__)
    return module


step1: Any = _load_step1()


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
        case Write(h, lit, path, markup):
            if markup:
                return f"{_kw('ItemCopy')} {_lit(lit)} to {_hs(h, inp)}{_span('path', path)}"
            return f'ItemCopy "{lit}" to {h.name}{path}'
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
    raise AssertionError(f"unrendered node {node!r}")


def _package(body: str) -> str:
    return f'<Package Name="ACME X"><ActionList Name="T"><List>{body}</List></ActionList></Package>'


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

    def get(self, key: str) -> frozenset[Val]:
        return frozenset() if self.ended else self.vals.get(key, self.default)

    def copy(self) -> _Env:
        env = _Env(self.default)
        env.vals = dict(self.vals)
        env.ended = self.ended
        return env

    def havoc(self) -> None:
        self.vals = {}
        self.default = frozenset({UNK})  # an ended env stays ended: get() answers nothing

    def same(self, other: _Env) -> bool:
        keys = self.vals.keys() | other.vals.keys()
        return (
            self.ended == other.ended
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
        self.lits: dict[Val, set[str]] = {}
        self.sources: dict[Val, set[Val]] = {}
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
                    self.sources.setdefault(made, set()).add(v)
                    new.add(made)
                env.vals[self.key(dst.name)] = frozenset(new)
            case Create(h, k, good, _):
                env.vals[self.key(h.name)] = frozenset({("create", k) if good else UNK})
            case Write(h, lit, _, _):
                key = self.key(h.name)
                vals = env.get(key)
                for v in vals - {UNK, EMPTY}:
                    self.lits.setdefault(v, set()).add(lit)
                if EMPTY in vals:  # a write into nothing may build a tree
                    env.vals[key] = (vals - {EMPTY}) | {UNK}
            case Log():
                pass
            case SendS(h, dest, _):
                self.sends.setdefault(dest, set()).update(env.get(self.key(h.name)))
                self.send_keys.setdefault(dest, set()).add(self.key(h.name))
                if ctx.dead and not env.ended:
                    self.dead.add(dest)
                if ctx.doubt:
                    self.doubt.add(dest)
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
                # and afterwards so is every caller handle.
                self.run(body, _Env(frozenset({UNK})), ctx)
                env.havoc()
            case Unknown(body) | Nested(body):
                env.havoc()
                env = _join([env.copy(), self.run(body, env.copy(), ctx.lost())])
                env.havoc()
            case Off(inner, value):
                if value.strip().lower() in _DISABLED_SURE:
                    return env
                env = _join([env.copy(), self.run((inner,), env.copy(), ctx.cond())])
            case Orphan(_, body, _):
                env = _join([env.copy(), self.run(body, env.copy(), ctx.lost())])
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
    lits: dict[Val, set[str]]
    sources: dict[Val, set[Val]]

    def allowed(self, value: Val) -> set[str]:
        seen: set[Val] = set()
        out: set[str] = set()
        todo = [value]
        while todo:
            v = todo.pop()
            if v in seen:
                continue
            seen.add(v)
            out |= self.lits.get(v, set())
            todo.extend(self.sources.get(v, ()))
        return out


def _oracle(shape: Shape) -> _Verdict:
    worlds = [_Oracle(shape, fold) for fold in (False, True)]
    verdict = _Verdict(tuple(w.inp_key for w in worlds), {}, {}, set(), set(), {}, {})
    for w in worlds:
        for dest, vals in w.sends.items():
            verdict.sends.setdefault(dest, set()).update(vals)
        for dest, keys in w.send_keys.items():
            verdict.keys.setdefault(dest, []).extend((w.inp_key, k) for k in keys)
        verdict.dead |= w.dead
        verdict.doubt |= w.doubt
        for v, lits in w.lits.items():
            verdict.lits.setdefault(v, set()).update(lits)
        for v, srcs in w.sources.items():
            verdict.sources.setdefault(v, set()).update(srcs)
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

_INPUT = "MSH|^~\\&|A|B|C|D|20260930||ADT^A01|CTRL|P|2.5.1\rPID|1||123\rOBX|1|ST|X||Y"
_LITERAL = re.compile(r"W\d+Z")


@dataclass
class _Run:
    src: str
    # Every Send the handler made, including those made before a later refusal raised: a refusal
    # dead-letters the message, but it is a TODO, and once a human finishes it those Sends deliver.
    # Reading only a completed run let one late refusal hide every wrong send ahead of it.
    sends: list[tuple[str, object]]
    inp: Message | None


def _execute(module: Any, xml: str, where: Path) -> _Run:
    try:
        src = module.generate_module(module.parse_package(_package(xml))[0])
    except module.CorepointImportError:
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


def _violations(shape: Shape) -> list[str]:
    """Every way the head's handler for ``shape`` fails open against step 1 and the oracle."""
    xml = _render(shape.nodes, shape.inp)
    verdict = _oracle(shape)
    out_head = _execute(head, xml, _WHERE)
    out_step1 = _execute(step1, xml, _WHERE)
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

    # The narrowing: a local other than msg is bound and sent only at the handler's own level.
    for line in out_head.src.split("@handler")[-1].splitlines():
        found_local = _LOCAL_LINE.match(line)
        if found_local and len(found_local.group(1)) != 4:
            found.append(f"(narrowing) a local is bound or sent below the handler level: {line}")

    # Every live send line of the head, on every path.
    step1_live = {(d, local) for _, d, local in _live_sends(out_step1.src)}
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
        if (dest, local) in step1_live:
            continue  # step 1 renders the same live send: not a change step 2 made
        if dest in verdict.doubt:
            found.append(f"(ii) {dest} sends {local} live where the import lost the scope")
            continue
        why = provable(dest, is_msg)
        if why:
            found.append(f"(render) {dest} sends {local} live: {why}")

    # (i) and (ii), executed on the path where every placeholder condition is false.
    if out_head.sends:
        delivered = {(d, _observed(m, out_step1.inp)) for d, m in out_step1.sends}
        for dest, message in out_head.sends:
            seen = _observed(message, out_head.inp)
            if (dest, seen) in delivered:
                continue
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
            stray = set(_LITERAL.findall(message.encode())) - verdict.allowed(value)
            if stray:
                found.append(f"(i) {dest} carries {sorted(stray)}, written to another tree")
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
        return Create(self.spell(h), 1 + self._next() % 98, good, self.m())

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
        over_cls = rng.choice(("", "plain", "verbless", "variable", "literal", "handle"))
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
        # A Block whose label is itself a writing statement.
        label = _leaf_data(b.clone(b.new, b.out), b.inp.name)
        assert label is not None
        return Block(body, label, havoc=True)
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
    # Under the narrowing nothing binds inside a construct, so what a ForEach or Catch line may
    # bind matters most for the INPUT before the first bind: a loop that rebinds it, then a clone of
    # it, would copy the message that arrived instead of what the loop left there.
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
    # The existing hostile spellings, each cloned, called over and sent.
    for name in ("%OUT-", "%ÄÖ-ß.x", "%OUT(1)", "%OUT;A", "%_", "%1OUT"):
        h = H(name)
        yield Shape(
            f"hostile-{name}",
            "%ADT",
            (Clone(_ADT, h, 1), SendS(h, "OB_BEFORE"), Call((Log(_P),)), SendS(h, "OB_AFTER")),
        )


# --- the guard ------------------------------------------------------------------------------------

_SEED = 313
_RANDOM = 1000
_CHUNKS = 24


def _all_shapes() -> list[Shape]:
    return [*_seed_shapes(), *_paired_shapes(_SEED), *_random_shapes(_SEED, _RANDOM)]


_SHAPES = _all_shapes()


def test_the_battery_is_as_wide_as_it_claims() -> None:
    """Every ordered construct pair at depth 2, every payload, plus the seeds and random shapes."""
    pairs = {s.name.rsplit("/", 1)[0] for s in _SHAPES if s.name.count("/") == 2}
    assert len(pairs) == len(_KINDS) ** 2
    assert len(_SHAPES) == len(list(_seed_shapes())) + len(_KINDS) ** 2 * 6 + _RANDOM


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
