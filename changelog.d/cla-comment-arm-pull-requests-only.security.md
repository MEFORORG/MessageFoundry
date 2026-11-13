- **The CLA workflow acts on a `recheck` or sign comment only when it is posted on a pull request.**
  A comment on a plain issue no longer runs the CLA action. A new, not yet wired pre-check,
  `scripts/security/cla_precheck.py`, reads every commit of a pull request and refuses one that is
  linked to no GitHub account but carries an allowlisted name as its git author name.
