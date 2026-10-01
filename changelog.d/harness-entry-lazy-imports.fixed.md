- **The `messagefoundry-harness` wheel passes its release smoke again.** The release job installs
  the harness wheel without its dependencies and imports `harness.__main__` to prove the wheel
  carries its code. Two engine imports at the top of that module made the import fail, so the
  v0.5.0 release published the engine and toolkit but not the harness. The imports now run inside
  `main()`, and `tests/test_harness_entry_imports_no_engine.py` imports the entry module with only
  the standard library available, so the next one fails in CI instead of at tag time.
