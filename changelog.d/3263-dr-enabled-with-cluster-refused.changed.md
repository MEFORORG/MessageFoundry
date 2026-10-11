- **Breaking: `[dr].enabled` with `[cluster].enabled` is refused at config load**, as
  `[dr].activate` with it already was. A DR box that is not activated is passive, so as a
  cluster leader it would serve nothing. Run a warm DR-site engine as a non-promotable cluster
  member (`[cluster].promotable = false`), not as a `[dr]` box. (`vault BACKLOG #3263`)
