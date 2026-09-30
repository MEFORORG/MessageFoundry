# defusedxml 0.7.1 (vendored)

This directory carries two modules of `defusedxml` 0.7.1, `common.py` and `ElementTree.py`, so the
engine no longer installs the package.

## Why it is vendored

The engine parses untrusted XML through this copy in at least three places: `RawMessage.xml()` in
`parsing/message.py`, the SVG attachment sanitizer in `api/svg_sanitize.py`, and the Corepoint export
import in `corepoint_import.py`. Each relies on defusedxml's refusal flags (`forbid_dtd`,
`forbid_entities`, `forbid_external`), not only on expat's amplification limits. CPython's own
`ElementTree` still expands a declared internal entity, so dropping to the standard library would
loosen that posture. The lxml path in `parsing/xml/` and the SOAP gate's `xml.sax` parser are
hardened separately and do not use this copy.

Upstream has gone quiet. 0.7.1 was released on 2021-03-08. The last commit to `tiran/defusedxml` is
from 2023-10-25, and the 0.8.0 release candidates tagged in 2023-09 were never finalised. No advisory
names this release in OSV or GHSA. These readings were taken on 2026-09-30 and will age.

Copying the two modules in means the code the engine trusts is reviewed in this tree, and it cannot
change under us through a resolver. The owner chose to do this on 2026-09-30.

## Source

| | |
|---|---|
| Upstream version | `defusedxml` 0.7.1 |
| Source | https://files.pythonhosted.org/packages/0f/d5/c66da9b79e5bdb124974bfe172b4daf3c984ebd9c2a06e2b8a4dc7331c72/defusedxml-0.7.1.tar.gz |
| sdist SHA-256 | `1bb3032db185915b62d7c6209c5a8792be6a32ab2fedacc84e01b52c51aa3e69` |
| Project | https://github.com/tiran/defusedxml |
| Licence | PSF License version 2 (SPDX `PSF-2.0`), text in `LICENSE` here |

The sdist hash is the one `uv.lock` records for 0.7.1. That entry stays in the lock because the `x12`
extra's `pyx12` still installs upstream defusedxml; the engine itself no longer does.

## What changed from upstream

| File | Change | SHA-256 of the upstream file |
|---|---|---|
| `common.py` | Two header lines added at the top | `ddddba8cd5b87cd5f38235a1bd47ecf3701f8b3e44571143ba941bba09123197` |
| `ElementTree.py` | Two header lines added at the top | `18b4aaa42cf9f285c63c6cb37ff1f296c3d2f7f75c1953f948de1d2bbcafc8fc` |
| `LICENSE` | None | `b80ce9da8c42a1f91079627fbbe2bf27210ae108a0ffe5f077d5b08e076c24c8` |
| `__init__.py` | Replaced with our own | not upstream's |

The header lines give each file its SPDX identifier and point here. Everything after them is upstream's
bytes. Upstream's `__init__.py` is left out because its `defuse_stdlib()` imports seven modules that
are not copied here. Our `__init__.py` holds only a docstring.

`tests/test_vendored_defusedxml.py` checks the table: it strips the two header lines and compares each
file's SHA-256 with the value above.

## Rules for this directory

1. Do not edit `common.py` or `ElementTree.py` below their header. A fix goes in as a new upstream
   version with this README and its test updated, or as a change recorded in the table above.
2. Ruff and mypy skip this directory. It is upstream's code in upstream's style, and making it pass
   strict typing would mean rewriting it. The engine code that calls it is checked as before.
3. `tests/test_xml_refusal_guard.py` pins the refusal each call site relies on. It names no XML
   library, so it passed unchanged before and after the switch to this copy.
