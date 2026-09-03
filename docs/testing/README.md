# Most of this directory is not in this repository

Only [`VERIFY.md`](VERIFY.md) is tracked here. Everything else under `docs/testing/` is
maintainer QA planning, and it is kept in a separate maintainer repository.

**So a path under `docs/testing/` that you cannot open says nothing about whether the work
exists.** Unreadable and unstarted look identical from an engine checkout, and that is the
mistake this page exists to stop.

## Why you are probably reading this

You followed a citation. `docs/BACKLOG.md`, an ADR, a test docstring or a source comment names a
path under `docs/testing/`, you went looking for it, and it is not on disk. That citation is real.
It names a document that exists, and it is written for provenance: it records where a decision or
a test row came from, not a file you can open here.

`git ls-files docs/testing` returns one file. That is the rule working, not a gap.

## What this means when you are grading work

Do not treat an unreadable document as an absent one.

If an item asks you to satisfy a criterion, discharge a row, or check a claim in a document under
`docs/testing/`, you cannot verify that half from an engine checkout. Say so in those words. Record
the limb as unverified, not as satisfied and not as missing. Claiming you met a criterion you could
not read is the failure mode; it happened, and it is why this file is here.

The same caution applies to the reverse move. A limb that looks undone may simply be graded in a
document you do not have.

## Why the split

[ADR 0160](../adr/0160-public-repo-content-policy-operator-and-security-review-material-only.md)
sets the test: a tracked file must be something an operator running MessageFoundry needs, or
something a security reviewer assessing it needs. QA planning for a maintainer build box is
neither, so it moved. `VERIFY.md` stayed because it documents `messagefoundry verify`, the on-box
acceptance check a real deployment runs.

None of this is a confidentiality control and it must never be described as one. This material was
never secret. It is process noise, and moving it was subject-matter tidying.

The `.gitignore` block that implements the split carries the full reasoning. Search it for
`/docs/testing/*`.

## The neighbouring case, which is a different rule

`docs/security/` and `docs/reviews/` are also absent, and they are held back for their own reasons.
[`SECURITY-DOCS-POLICY.md`](../SECURITY-DOCS-POLICY.md) states that rule, says what is public, and
tells adopters, evaluators and security reviewers how to request the withheld material. Read it
there. Do not assume the reasoning on this page carries over.

## What this page will not do

It will not list what is in the other repository. A path-to-document map over a closed set hands out
what is not covered by subtraction, so this is a pointer and never an index. If you need something
named here, ask a maintainer through the route `SECURITY-DOCS-POLICY.md` documents.

## If you are writing a citation

Name the unreadability in the same breath as the path. One clause is enough, for example that the
path is vault-only, gitignored, or unreachable from an engine checkout. A reader who meets your
citation months later gets the same warning you would have wanted, without having to find this page
first.
