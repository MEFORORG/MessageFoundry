- **A start applies the `environments/` value-file bytes its `config_loaded` digest names.** A
  start resolved its `env()` values from disk when the engine was built, and its digest read the
  config directory's `environments/` folder later, in the load's snapshot, so an edit in between
  was named and not applied. `serve` now parses the value file there from that snapshot. It vets
  the file and its folder first, as a reload does, and applies the snapshot's bytes only where the
  file, read again after that vet, still holds them. The start refuses at least a malformed value
  file, one created, removed or edited since the load read it, and a file or folder the vet
  refuses, the folder even where the value file is absent. A value file the load could not read,
  as under an antivirus lock, does not refuse the start: the start then runs no vet beyond the
  build's, keeps the values read when the engine was built, and the digest leaves the file out. A value file anywhere but `environments/` stays
  out of every published digest, one inside the config directory under another
  `[environments].dir` included. (vault `BACKLOG #2596`)
