- **A DR backup records what its config walk did not archive.** The manifest, the `dr_backup`
  audit row and the `messagefoundry backup` summary carry `config_skipped_files`, naming at least
  each config file the walk did not add as a regular file, such as a symlinked `connections.toml`
  the config digest read through, each directory link it did not follow, and each folder it could
  not list, with `config_skipped_count` the total. The entries other than directory links are
  logged in one WARNING; a directory link keeps its own WARNING. Before this, `config_bundled: true`
  and a digest covering a file did not mean the archive held it. (vault `BACKLOG #5233`)
