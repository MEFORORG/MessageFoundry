- **The de-identification package leaves the engine wheel.** ADR 0201 slice 6 moves
  `messagefoundry/anon/` to `messagefoundry_toolkit/anon/`, so it ships in the
  `messagefoundry-toolkit` distribution and an engine-only install no longer carries it. Import it
  as `messagefoundry_toolkit.anon`. What it does is unchanged: the rules, the keying, the
  fail-closed leak-check and its limits are the same, and the tee keeps its vendored copy in
  `tee/anon/`, so `python -m tee anonymize-captures` is unaffected. The release member gate now
  refuses an engine wheel or sdist that carries a member under `messagefoundry/anon/`. (BACKLOG #1192)
