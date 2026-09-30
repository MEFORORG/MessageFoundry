# Changelog fragments

Add your changelog entry here as a new file. Do not edit `CHANGELOG.md` in a pull request.

Every pull request used to edit the same `## [Unreleased]` section of `CHANGELOG.md`, so nearly
every pair of open pull requests conflicted there. Two new files never conflict.

## Write a fragment

1. Name the file `<name>.<category>.md`.
2. For `<name>`, use the backlog item number, such as `2080`. With no item, use a short slug in
   lower case, such as `fix-install-typo`. Letters, digits and hyphens only.
3. For `<category>`, use one of `added`, `changed`, `deprecated`, `removed`, `fixed` or `security`.
4. Write the entry as one or more Markdown bullets, the same text you would have put in
   `CHANGELOG.md`. Indent continuation lines. Do not add a heading.

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

CI runs the same check on every pull request.

## At release

The release pull request folds the fragments into `CHANGELOG.md` and deletes them:

```
python scripts/release/changelog_fragments.py assemble
```

Each entry goes at the end of the matching `###` heading under `## [Unreleased]`, after every
entry already there. Then the release pull request renames `[Unreleased]` to the version, as
before. The release workflow refuses to publish a tag while any fragment is left in this folder,
because the release notes are read from `CHANGELOG.md` and would miss it.

This file is the only file here that is not a fragment. Any other misnamed file fails the check,
rather than being skipped and lost at release.
