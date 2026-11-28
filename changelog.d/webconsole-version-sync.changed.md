- **The web console carries the engine's version, and every release includes it.** The web
  console now carries the engine's version, as the toolkit and the harness already did, and every
  release includes all four at that number, the console included when it did not change. A
  console-only fix ships as a patch release of all four, never as a `.postN` release. The console
  keeps its own `webconsole-v*` tag, pushed by hand once the engine is on PyPI, and its own
  changelog. A test fails while the console's version differs from the engine's, and the console
  release job refuses a tag that is not `webconsole-` followed by an engine tag spelling, such as
  `webconsole-v0.5.3-post1`. The engine still checks the pair by its UI seam, not by the number.
  [`docs/WEBCONSOLE-PACKAGE.md`](../docs/WEBCONSOLE-PACKAGE.md) states the rule.
