- **A DR backup records what its config walk did not archive.** The manifest, the `dr_backup`
  audit row and the `messagefoundry backup` summary carry `config_skipped_files`, naming at least
  each config file the walk did not add as a regular file, such as a symlinked `connections.toml`
  the config digest read through, each directory link it did not follow, and each folder it could
  not list, with `config_skipped_count` the total. The walk logs them in WARNINGs; a directory
  link it lists as a folder keeps the WARNING it had. Before this, `config_bundled: true`
  and a digest covering a file did not mean the archive held it. (vault `BACKLOG #5233`)
