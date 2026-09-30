# Changelog fragments

Add your changelog entry here as a new file. Do not edit `CHANGELOG.md` in a pull request.

Every pull request used to edit the same `## [Unreleased]` section of `CHANGELOG.md`, so nearly
every pair of open pull requests conflicted there. Two pull requests that add different files do
not conflict. Two that pick the same file name still do, so pick a name nobody else will.

This folder is for the engine's changelog only. A web console change still goes straight into
`packaging/messagefoundry-webconsole/CHANGELOG.md`, which has its own version and release.

## Write a fragment

1. Name the file `<name>.<category>.md`.
2. For `<name>`, use the backlog item number, such as `2080`. With no item, use a short slug in
   lower case, such as `fix-install-typo`. Letters, digits and hyphens only.
3. For `<category>`, use one of `added`, `changed`, `deprecated`, `removed`, `fixed` or `security`.
4. Write the entry as one or more Markdown bullets, the same text you would have put in
   `CHANGELOG.md`. Indent continuation lines. Do not add a heading.
5. Start each relative link with `../`, such as `[PHI.md](../docs/PHI.md)`. That form works from
   this folder, and the release step drops the `../` so it works from `CHANGELOG.md` too.

If the name is already taken, for example by an earlier pull request for the same item, add a
suffix: `2080-docs.fixed.md`.

Example, `changelog.d/2080.changed.md`:

```markdown
- **Changelog entries are now fragment files.** A pull request adds one file under
  `changelog.d/` instead of editing `CHANGELOG.md`. (`BACKLOG #2080`)
```

Check your fragment before you push:

```
python scripts/release/changelog_fragments.py check
```

CI runs the same check on every pull request, docs-only ones included. CI also warns, without
failing, when a pull request edits `CHANGELOG.md` directly.

## At release

Every engine tag needs this step first, a pre-release tag such as `v0.5.0-rc1` included.

1. In the release pull request, run
   `python scripts/release/changelog_fragments.py assemble`. It adds each fragment to
   `CHANGELOG.md` and deletes it.
2. Then rename `[Unreleased]` to the version, and add a fresh, empty `[Unreleased]` above it.

Run them in that order. If you rename first, the entries land under the new `[Unreleased]` and miss
the release notes.

Each entry goes at the end of the first `###` heading of its category under `[Unreleased]`. A
category with no heading gets a new one, in Keep a Changelog order.

CI fails a release pull request that still has fragments. It also fails one whose new
`[Unreleased]` is not empty. The release workflow refuses to publish a tag while any fragment
remains, because it reads the release notes from `CHANGELOG.md` alone.

Files whose names start with a dot are ignored. Any other file here that is not named like a
fragment fails the check, so it cannot be skipped and lost at release.
