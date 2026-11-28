- **The web console carries the engine's version.** The web console now carries the engine's
  version, as the toolkit and the harness already did, so each console release takes the number
  of the engine release it pairs with. The console keeps its own `webconsole-v*` tag and
  changelog, and the engine still checks the pair by its UI seam, not by the number.
  [`docs/WEBCONSOLE-PACKAGE.md`](../docs/WEBCONSOLE-PACKAGE.md) states the rule.
