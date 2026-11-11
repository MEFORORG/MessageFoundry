- **A start applies the `environments/` value-file bytes its `config_loaded` digest names.** A
  start resolved its `env()` values from disk when the engine was built, and its digest read the
  config directory's `environments/` folder later, in the load's snapshot, so an edit in between
  was named and not applied. `serve` now parses the value file there from that snapshot, and vets
  it and its folder, as a reload does, so the start refuses at least what a reload of the same
  bytes refuses: a malformed value file, and a file or folder that vet refuses, even where the
  value file is absent.
  A value file the load could not read leaves the build's values in place and is left out of the
  digest. A value file outside the config directory stays out of every published digest.
  (vault `BACKLOG #2596`)
