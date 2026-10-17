# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Texts that name the insecure-TLS escape also name the posture it needs (vault BACKLOG #2637,
#3099).

``MEFOR_ALLOW_INSECURE_TLS`` is honoured only on an instance at ``[security].enforcement = warn``
(:func:`~messagefoundry.config.settings.weakened_tls_escape_permitted`). Under ``enforce``, the
default, and with no posture it changes nothing. A refusal that told an operator to set it without
saying so sent them to set a variable that does nothing on a default instance. An authoring
docstring that says the same sends them there before anything is refused.

**What the call scanner sees.** One call at a time -- a ``raise X(...)``, a ``logger.warning(...)``,
an ``out.append((...))``. A call names the escape when anything in its arguments or keyword
arguments spells the variable in a string, or refers to ``INSECURE_TLS_ESCAPE_ENV`` by name or as
an attribute; that covers f-strings, ``%`` and ``+`` formatting, ``.format``, and a ``%s`` logging
argument. A nested call keeps its strings to itself, so it cannot lend the posture to the call
around it. Two nested calls are this call's own text instead: ``"...".format(...)``, and a call
whose result ``%`` or ``.format`` fills, such as ``_("set %s") % NAME``. That second rule has a
cost: any call on the left of ``%`` lends its strings, whatever it is for. A literal, an f-string
and a ``+`` chain
of them are read as the one string Python builds, in source order, with ``{}`` where a value goes.
The text is every such string that holds a space or spells the variable, so a bare key such as the
``""`` default of ``os.environ.get`` is not a message. That text must name the posture, and a
phrase that wraps or is split across ``+`` still counts.

**What the prose scans see** (vault BACKLOG #3099). Docstrings in ``_DOCSTRING_FILES``, one
paragraph at a time: a paragraph that spells the variable must name the posture, so a mention
cannot ride on the posture in another paragraph. Two mentions inside one paragraph are judged
together. Comments in ``_COMMENT_FILES``: own-line comments on consecutive
lines are one comment, and a comment after code is read alone. A comment names the escape when it
spells the variable. A comment in a ``def`` signature also names it when it says "the escape",
because a factory's parameter comments are the help text the connection editor shows
(:mod:`messagefoundry.config.connection_schema`). A signature comment about another escape must
name that one some other way. The editor joins a parameter's comments by its own rules, and this
scan does not copy them: it reads each trailing comment alone, which is stricter.

**The docstring files are a pinned list, not the tree.** At least ``_reject_unknown_env_keys`` and
``weakened_tls_escape_permitted`` in ``config/settings.py`` name the variable to list it or to
define the rule, so a scan of every docstring flags some text that misleads nobody. The list is
the files brought into line so far, and it is not every file that needs it. Where a file cannot be
held whole, ``_DOCSTRING_FUNCTIONS`` holds single functions to the rule, at least
``insecure_tls_allowed`` in ``config/settings.py``. Every other docstring in that file goes unread.

**What none of them sees**, at least: a message built in a variable before the call; the variable
imported under another name; a message with no space that only interpolates the variable, such
as ``f"{INSECURE_TLS_ESCAPE_ENV}=1:refused"``; a call lent through ``+``, as in
``(_("set %s") + "...") % NAME``; a method called on the template, as in
``"set %s".strip() % NAME``; the variable handed through a nested call, as in
``"set %s" % str(NAME)``; a docstring or comment outside the pinned files; and prose that
says "the dev escape" without the variable. A lent call that spells the variable itself is counted
twice, once on its own and once in the call around it. A ``.format`` call is also judged on its
own, by its arguments and without its template, so a spaced argument beside the variable is
flagged even where the template names the posture. A green run is a statement about the shapes
above, not about every text in the packages.

**The positive controls are planted and pinned.** Each scanner is proved on planted sources, some
that must be flagged and some that must pass. The tree walks are proved by pinning the files they
must find, so a scanner that silently matches nothing cannot pass by finding nothing to judge."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Iterator
from pathlib import Path

from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
from tests._ast_sites import named_func, parse_source

_REPO = Path(__file__).resolve().parent.parent
#: Every shipped Python package ci.yml type-checks. The engine is ``messagefoundry``; the others
#: name no escape today, and are walked so a text added there is judged too.
_PACKAGES = ("messagefoundry", "messagefoundry_webconsole", "messagefoundry_toolkit")
_NAME = "INSECURE_TLS_ESCAPE_ENV"
_POSTURE = "[security].enforcement = warn"
#: What a value reads as inside the one string a ``+`` chain or an f-string builds.
_HOLE = "{}"
#: A signature comment that says this names the escape without spelling the variable.
_UNNAMED_ESCAPE = "the escape"
_BOM = "\ufeff"

#: Files that must each hold at least one checked text. Pinned so a scanner that matches nothing
#: fails here instead of passing vacuously. ``auth/ldap.py`` left the list with vault BACKLOG #3230:
#: its LDAPS refusal no longer names the escape, because no escape releases that bind.
_MUST_FIND = frozenset(
    {
        "messagefoundry/config/settings.py",
        "messagefoundry/pipeline/alert_sinks.py",
        "messagefoundry/store/postgres.py",
        "messagefoundry/store/sqlserver.py",
        "messagefoundry/transports/ai_broker.py",
        "messagefoundry/transports/database.py",
        "messagefoundry/transports/direct.py",
        "messagefoundry/transports/email.py",
        "messagefoundry/transports/mllp.py",
        "messagefoundry/transports/remotefile.py",
    }
)

#: Files whose docstrings are held to the rule. Each must hold at least one docstring that names
#: the escape, for the same reason ``_MUST_FIND`` is pinned.
_DOCSTRING_FILES = (
    "messagefoundry/config/wiring.py",
    "messagefoundry/store/postgres.py",
    "messagefoundry/transports/database.py",
    "messagefoundry/transports/direct.py",
    "messagefoundry/transports/email.py",
    "messagefoundry/transports/remotefile.py",
    "messagefoundry/transports/rest.py",
)
#: Single functions held to the rule, in a file that cannot be held whole. Each docstring must name
#: the escape, so a rewrite that drops it fails instead of passing with nothing to judge.
_DOCSTRING_FUNCTIONS = (("messagefoundry/config/settings.py", "insecure_tls_allowed"),)
#: Files whose comments are held to it. The authoring factories live here, and their parameter
#: comments reach an operator as help text.
_COMMENT_FILES = ("messagefoundry/config/wiring.py",)

_DEF = ast.FunctionDef | ast.AsyncFunctionDef
_DOCUMENTED = ast.Module | ast.ClassDef | _DEF
_PARAGRAPH_BREAK = re.compile(r"(\n\s*\n)")


def _squash(text: str) -> str:
    """``text`` with each run of whitespace as one space, so a phrase that wraps still matches."""
    return " ".join(text.split())


def _spell(node: ast.AST, holes: list[ast.AST]) -> str:
    """The text a string expression builds: a literal, an f-string, or a ``+`` chain of them,
    joined with nothing between the parts, as Python joins them. Any other part is written as
    ``{}`` and put on ``holes``, to be read on its own."""
    spelled: list[str] = []
    # A stack, not recursion: a long ``+`` chain nests one level per term.
    todo = [node]
    while todo:
        part = todo.pop()
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            spelled.append(part.value)
        elif isinstance(part, ast.JoinedStr):
            todo.extend(reversed(part.values))
        elif isinstance(part, ast.BinOp) and isinstance(part.op, ast.Add):
            todo.extend((part.right, part.left))
        else:
            holes.append(part)
            spelled.append(_HOLE)
    return "".join(spelled)


def _is_text(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    return isinstance(node, ast.JoinedStr) or (
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
    )


def _read(node: ast.AST, texts: list[str], *, lent: bool = False) -> bool:
    """Put the strings ``node`` holds on ``texts``, in source order, and say whether ``node`` names
    the escape.

    A nested call keeps its strings to itself. Two calls are read as this text instead: a
    ``.format(...)`` call, and a call whose result is the template that ``%`` or ``.format``
    fills (``lent``), because its arguments are that template."""
    named = False
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            named = _read(func.value, texts, lent=True)
        elif not lent:
            return False
        parts: list[ast.AST] = [*node.args, *(kw.value for kw in node.keywords)]
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        named = _read(node.left, texts, lent=True)
        parts = [node.right]
    elif _is_text(node):
        parts = []
        text = _spell(node, parts)
        texts.append(text)
        named = INSECURE_TLS_ESCAPE_ENV in text
    else:
        named = (isinstance(node, ast.Name) and node.id == _NAME) or (
            isinstance(node, ast.Attribute) and node.attr == _NAME
        )
        parts = list(ast.iter_child_nodes(node))
    # Read every part before asking: each one's strings are wanted, whichever names the escape.
    part_names = [_read(part, texts) for part in parts]
    return named or any(part_names)


def escape_texts_without_posture(source: str) -> tuple[list[int], int]:
    """Line numbers of calls whose text names the escape but not the posture, and how many calls
    named the escape at all."""
    unposted: list[int] = []
    seen = 0
    # parse_source tolerates a leading byte-order mark. Its tree is cached and shared: read only.
    for call in ast.walk(parse_source(source)):
        if not isinstance(call, ast.Call):
            continue
        found: list[str] = []
        operands = [*call.args, *(kw.value for kw in call.keywords)]
        names = [_read(operand, found) for operand in operands]
        if not any(names):
            continue
        # A spaced string is a message. So is any string that spells the variable, spaced or not.
        texts = [s for s in found if " " in s or INSECURE_TLS_ESCAPE_ENV in s]
        if not texts:
            continue
        seen += 1
        if _POSTURE not in _squash(" ".join(texts)):
            unposted.append(call.lineno)
    return unposted, seen


def _docstring_without_posture(node: _DOCUMENTED) -> tuple[list[int], int]:
    """:func:`docstrings_without_posture` for ``node``'s own docstring alone."""
    unposted: list[int] = []
    seen = 0
    text = ast.get_docstring(node, clean=False)
    if text is None:
        return unposted, seen
    line = node.body[0].lineno
    for chunk in _PARAGRAPH_BREAK.split(text):
        at = chunk.find(INSECURE_TLS_ESCAPE_ENV)
        if at >= 0:
            seen += 1
            if _POSTURE not in _squash(chunk):
                unposted.append(line + chunk.count("\n", 0, at))
        line += chunk.count("\n")
    return unposted, seen


def docstrings_without_posture(source: str) -> tuple[list[int], int]:
    """Lines of docstring paragraphs that name the escape but not the posture, and how many
    paragraphs named the escape at all. The line is where the paragraph first spells the variable."""
    unposted: list[int] = []
    seen = 0
    for node in ast.walk(parse_source(source)):
        if isinstance(node, _DOCUMENTED):
            lines, count = _docstring_without_posture(node)
            unposted.extend(lines)
            seen += count
    return sorted(unposted), seen


def _comments(source: str) -> Iterator[tuple[int, str]]:
    """Each comment as its first line and its text. Own-line comments on consecutive lines are one
    comment; a comment after code stands alone."""
    parts: list[str] = []
    start = 0
    takes_more = False
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.COMMENT:
            continue
        line = token.start[0]
        own_line = not token.line[: token.start[1]].strip()
        text = token.string.lstrip("#").strip()
        if takes_more and own_line and line == start + len(parts):
            parts.append(text)
            continue
        if parts:
            yield start, " ".join(parts)
        parts, start, takes_more = [text], line, own_line
    if parts:
        yield start, " ".join(parts)


def comments_without_posture(source: str) -> tuple[list[int], int]:
    """First lines of comments that name the escape but not the posture, and how many comments
    named the escape at all."""
    source = source.removeprefix(_BOM)
    signature: set[int] = set()
    for node in ast.walk(parse_source(source)):
        if isinstance(node, _DEF):
            # To the last line of the parameters or the return type, not to the body: a comment
            # between the colon and the first statement is about the body.
            parts = [*ast.walk(node.args), *([node.returns] if node.returns else [])]
            last = max((getattr(part, "end_lineno", None) or 0 for part in parts), default=0)
            signature.update(range(node.lineno, last + 1))
    unposted: list[int] = []
    seen = 0
    for line, text in _comments(source):
        named = INSECURE_TLS_ESCAPE_ENV in text or (
            line in signature and _UNNAMED_ESCAPE in text.lower()
        )
        if not named:
            continue
        seen += 1
        if _POSTURE not in _squash(text):
            unposted.append(line)
    return unposted, seen


def test_the_scanner_flags_a_text_that_omits_the_posture() -> None:
    planted = (
        "def f():\n"
        "    raise ValueError(\n"
        '        f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set (dev only)"\n'
        "    )\n"
        "    log.warning('allowed because %s is set', INSECURE_TLS_ESCAPE_ENV)\n"
        "    raise ValueError('set MEFOR_ALLOW_INSECURE_TLS=1 to allow it')\n"
        "    raise ValueError('set %s=1 to allow it' % settings.INSECURE_TLS_ESCAPE_ENV)\n"
        "    raise HTTPException(detail='set {}=1 to allow it'.format(INSECURE_TLS_ESCAPE_ENV))\n"
        "    out.append(('escape', 'MEFOR_ALLOW_INSECURE_TLS is honoured'))\n"
        "    log.warning('set by %s', INSECURE_TLS_ESCAPE_ENV, d('[security].enforcement = warn'))\n"
        "    raise ValueError('MEFOR_ALLOW_INSECURE_TLS=1:refused')\n"
    )
    unposted, seen = escape_texts_without_posture(planted)
    assert seen == 8
    assert unposted == [2, 5, 6, 7, 8, 9, 10, 11]


def test_the_scanner_passes_a_text_that_names_the_posture() -> None:
    planted = (
        "def f():\n"
        "    raise ValueError(\n"
        '        f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set on an instance at "\n'
        '        "[security].enforcement = warn"\n'
        "    )\n"
        "    log.warning(\n"
        "        'allowed because %s is set at [security].enforcement = warn',\n"
        "        INSECURE_TLS_ESCAPE_ENV,\n"
        "    )\n"
        "    os.environ.get(INSECURE_TLS_ESCAPE_ENV, '')\n"
    )
    unposted, seen = escape_texts_without_posture(planted)
    assert seen == 2
    assert unposted == []


def test_the_scanner_reads_a_call_that_percent_formats_from_outside() -> None:
    """Vault BACKLOG #3099, gap A. The string sits in a nested call and the variable outside it.

    Line 6 is the control the fix must not lose: a nested call that is only another argument
    still cannot lend the posture. Line 7 is the same shape with ``.format`` doing the filling."""
    planted = (
        "def f():\n"
        "    raise ValueError(_('set %s=1 to allow it') % INSECURE_TLS_ESCAPE_ENV)\n"
        "    raise ValueError(\n"
        "        _('set %s=1 at [security].enforcement = warn') % INSECURE_TLS_ESCAPE_ENV\n"
        "    )\n"
        "    log.warning('set by %s', INSECURE_TLS_ESCAPE_ENV, d('[security].enforcement = warn'))\n"
        "    raise ValueError(_('set {}=1 to allow it').format(INSECURE_TLS_ESCAPE_ENV))\n"
    )
    unposted, seen = escape_texts_without_posture(planted)
    assert seen == 4
    assert unposted == [2, 6, 7]


def test_the_scanner_reads_a_plus_chain_as_one_string_in_order() -> None:
    """Vault BACKLOG #3099, gap B. The parts of a ``+`` chain are joined as Python joins them.

    Line 2 splits the posture across ``+`` and must pass. Line 5 holds the same words in the wrong
    order and must be flagged; read back to front and joined with a space, it spelt the posture."""
    planted = (
        "def f():\n"
        "    raise ValueError(\n"
        "        'set MEFOR_ALLOW_INSECURE_TLS=1 at [security].enforcement' + ' = warn'\n"
        "    )\n"
        "    raise ValueError('= warn' + ' set MEFOR_ALLOW_INSECURE_TLS=1, [security].enforcement')\n"
        "    raise ValueError('set ' + INSECURE_TLS_ESCAPE_ENV + '=1 at [security].enforce' + 'ment = warn')\n"
        "    raise ValueError('set ' + INSECURE_TLS_ESCAPE_ENV + '=1 to allow' + ' it')\n"
    )
    unposted, seen = escape_texts_without_posture(planted)
    assert seen == 4
    assert unposted == [5, 7]


def test_the_scanner_reads_a_source_that_starts_with_a_byte_order_mark() -> None:
    """Vault BACKLOG #3099, gap C. ``Path.read_text(encoding="utf-8")`` keeps the mark, and raw
    ``ast.parse`` refuses it."""
    planted = _BOM + "raise ValueError('set MEFOR_ALLOW_INSECURE_TLS=1 to allow it')\n"
    assert escape_texts_without_posture(planted) == ([1], 1)
    prose = _BOM + '"""Set ``MEFOR_ALLOW_INSECURE_TLS``."""\nX = 1  # MEFOR_ALLOW_INSECURE_TLS\n'
    assert docstrings_without_posture(prose) == ([1], 1)
    assert comments_without_posture(prose) == ([2], 1)


_PROSE_THAT_OMITS_THE_POSTURE = '''"""Module text. Weakening TLS needs ``MEFOR_ALLOW_INSECURE_TLS``."""


def factory(
    *,
    verify_tls: bool = True,  # False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
    tls_verify: bool = True,  # False (dev only) needs the escape
) -> None:
    """A factory.

    The posture is ``[security].enforcement = warn``, in a paragraph that names no variable.

    Refused unless
    ``MEFOR_ALLOW_INSECURE_TLS`` is set.
    """
    # MEFOR_ALLOW_INSECURE_TLS lets this through
    # on any instance.
    x = 1  # the escape, outside a signature, is some other escape
'''

_PROSE_THAT_NAMES_THE_POSTURE = '''"""Module text. ``MEFOR_ALLOW_INSECURE_TLS`` works only at ``[security].enforcement =
warn``."""


def factory(
    *,
    verify_tls: bool = True,  # False needs MEFOR_ALLOW_INSECURE_TLS at [security].enforcement = warn
    tls_verify: bool = True,  # False needs the escape at [security].enforcement = warn
    quote: str = "",  # an escape character, which this rule does not read
) -> None:
    # the escape meant here is some other one: this comment is past the signature
    """Refused unless ``MEFOR_ALLOW_INSECURE_TLS`` is set on an instance at
    ``[security].enforcement = warn``."""
    # MEFOR_ALLOW_INSECURE_TLS lets this through only at [security].enforcement =
    # warn.
'''


def test_the_prose_scans_flag_a_text_that_omits_the_posture() -> None:
    # The posture two paragraphs up does not cover the last paragraph, and line 14 is where that
    # paragraph spells the variable, not where it starts.
    assert docstrings_without_posture(_PROSE_THAT_OMITS_THE_POSTURE) == ([1, 14], 2)
    # One function alone, as _DOCSTRING_FUNCTIONS reads it: the module docstring is not its text.
    factory = named_func(parse_source(_PROSE_THAT_OMITS_THE_POSTURE), "factory")
    assert _docstring_without_posture(factory) == ([14], 1)
    assert comments_without_posture(_PROSE_THAT_OMITS_THE_POSTURE) == ([6, 7, 16], 3)


def test_the_prose_scans_pass_a_text_that_names_the_posture() -> None:
    # The posture wraps in the module docstring and in the last comment, so both scans must
    # squash whitespace, and the comment scan must join the two lines.
    assert docstrings_without_posture(_PROSE_THAT_NAMES_THE_POSTURE) == ([], 2)
    assert comments_without_posture(_PROSE_THAT_NAMES_THE_POSTURE) == ([], 3)


def test_every_runtime_text_naming_the_escape_names_the_posture() -> None:
    failures: list[str] = []
    found: set[str] = set()
    roots = [_REPO / name for name in _PACKAGES]
    assert all(root.is_dir() for root in roots), roots
    for path in sorted(p for root in roots for p in root.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if _NAME not in source and INSECURE_TLS_ESCAPE_ENV not in source:
            continue
        rel = path.relative_to(_REPO).as_posix()
        unposted, seen = escape_texts_without_posture(source)
        if seen:
            found.add(rel)
        failures.extend(f"{rel}:{line}" for line in unposted)
    missing = _MUST_FIND - found
    assert not missing, f"the scan found no escape text in {sorted(missing)}"
    assert not failures, (
        f"these texts name {INSECURE_TLS_ESCAPE_ENV} without saying it works only at "
        f"{_POSTURE!r}: {failures}"
    )


def _text(rel: str) -> str:
    return (_REPO / rel).read_text(encoding="utf-8")


def test_every_authoring_text_naming_the_escape_names_the_posture() -> None:
    failures: list[str] = []
    silent: list[str] = []
    results = (
        [("docstring", rel, docstrings_without_posture(_text(rel))) for rel in _DOCSTRING_FILES]
        + [
            (
                f"{name} docstring",
                rel,
                _docstring_without_posture(named_func(parse_source(_text(rel)), name)),
            )
            for rel, name in _DOCSTRING_FUNCTIONS
        ]
        + [("comment", rel, comments_without_posture(_text(rel))) for rel in _COMMENT_FILES]
    )
    for kind, rel, (unposted, seen) in results:
        if not seen:
            silent.append(f"{rel} ({kind}s)")
        failures.extend(f"{rel}:{line} ({kind})" for line in unposted)
    assert not silent, f"the scan found no text naming the escape in {silent}"
    assert not failures, (
        f"these docstrings and comments name {INSECURE_TLS_ESCAPE_ENV}, or say "
        f"{_UNNAMED_ESCAPE!r} in a signature comment, without saying it works only at "
        f"{_POSTURE!r}. A signature comment that means some other escape must name that one "
        f"another way: {failures}"
    )
