- **Every release ships the engine, web console, toolkit and harness at one version.** A release
  now tags the web console at the engine's version even when the console did not change, and a
  console-only fix ships as a patch release of all four rather than as a `.postN` release of the
  console. A test fails while the console's version differs from the engine's, and the console
  release job now refuses a tag that is not `webconsole-` followed by an engine tag spelling, such
  as `webconsole-v0.5.3-post1`.
  [`docs/WEBCONSOLE-PACKAGE.md`](../docs/WEBCONSOLE-PACKAGE.md) states the rule, and
  [`CONTRIBUTING.md`](../CONTRIBUTING.md) lists what a version bump moves.
