- **A start applies the `environments/` value-file bytes its `config_loaded` digest names.** A
  start resolved its `env()` values from disk when the engine was built, and its digest read the
  config directory's `environments/` folder later, in the load's snapshot, so an edit in between
  was named and not applied. `serve` now parses the value file there from that snapshot, as a
  reload does. A value file malformed, created or removed between the build and the load refuses
  the start; one the load could not read leaves the build's values in place and is left out of
  the digest. A value file outside the config directory stays out of every published digest.
  (vault `BACKLOG #2596`)
