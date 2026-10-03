- **A release now refuses a tag whose commit is not on `main`, or whose required checks did not
  pass.** A new `tag-provenance` job in `release.yml` runs before any job that builds a release
  artifact. It asks the server whether the tagged commit is on `main`, and whether every required
  check passed on it, reading the required set from branch protection and from
  `.github/required-contexts.txt`. The rule is in `scripts/release/tag_provenance.py`.
  (`vault BACKLOG #2631`)
- **No asset is added to a GitHub release after it is published.** The engine release is created
  as a draft, the harness wheel is attached to the draft, and a new `publish-github-release` job
  publishes it last. A re-run never uploads to a published release. This lets immutable releases
  be turned on without breaking the release workflow. (`vault BACKLOG #2631`)
- **Every remote pre-commit hook repository is pinned by commit, not by tag.** Each `rev:` in
  `.pre-commit-config.yaml` is the commit its tag named, with the tag beside it as
  `# frozen: <tag>`. A test fails on a hook repository pinned any other way. (`vault BACKLOG #2631`)
