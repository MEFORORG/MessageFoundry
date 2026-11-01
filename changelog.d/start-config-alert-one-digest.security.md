- **A start's config fingerprint now names the bytes its load read.** A start read the config directory
  for a fingerprint twice around its load and recorded the later read, so an edit after the load
  was recorded as loaded, and the next start saw no change. A file locked after the load left a
  partial loaded fingerprint. The fingerprint now comes from the load's own read, as a reload's
  does, and one read of the directory after the load is compared beside it. `config_changed` fires
  when either differs from the baseline, and on a change after the load the next start raises it
  again. `GET /config/provenance` and a DR activation's `disk_config` verdict now treat two
  fingerprints as equal only over the same files, and name what was left out: `left_out_files`
  counts it and `disk_config_left_out` lists it. With a graph loaded, `drift` is now `null`, and the
  console and the IDE say so, when the engine took no on-disk fingerprint, where it read as clean. A backup
  compares nothing; its manifest and audit row now record what its `config_fingerprint` left out,
  as `config_unreadable_files`. The alert's reason now leads with its marker, such as
  `changed_during_load`, and the logging sink carries the baseline node whole. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md).
