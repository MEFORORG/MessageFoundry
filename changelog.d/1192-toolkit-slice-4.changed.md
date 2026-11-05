- **The engine's `messagefoundry` command carries only production commands.** ADR 0201 slice 4
  moves `init`, `import corepoint`, `impact`, `generate`, `lens` (`parse`, `rewrite`, `schema`),
  `hl7schema` and `hl7structures` to the separate `messagefoundry-toolkit` command, beside
  `adr-analyze`, and moves `scaffold.py`, `lens.py`, `lens_schema.py` and `corepoint_import.py` out
  of the engine wheel into `messagefoundry_toolkit/`. Install the toolkit at the engine's own version
  on an authoring machine (`pip install "messagefoundry-toolkit==<version>"`); a production host
  needs the engine alone. The engine refuses a moved command with exit 2 and a line naming
  `messagefoundry-toolkit <command>` and its install command; a refused `lens rewrite` still carries
  the `"code"` the IDE branches on. `messagefoundry-toolkit init` also writes a
  `requirements-dev.txt` pinning the toolkit, so a deploy that installs `requirements.txt` carries no
  toolkit. The VS Code extension runs the Steps view and Generate Samples through
  `python -m messagefoundry_toolkit`, and says so by name when the interpreter has no toolkit. The
  release smoke now asserts that the built engine registers exactly the production rows of
  `CLI_TIERS`. `generators/`, `hl7schema.py` and `hl7structures.py` stay in the engine until a later
  slice. (BACKLOG #1192)
