# messagefoundry-toolkit

The authoring and development commands for
[**MessageFoundry**](https://github.com/MEFORORG/MessageFoundry), the open-source healthcare
integration engine (HL7 v2.x and more), kept out of the engine wheel.

A production host runs the engine alone. The engine's `messagefoundry` command carries only what a
deployed engine needs to run, operate and check itself. The commands that help you write and test a
configuration live here instead, behind their own command, `messagefoundry-toolkit`. The design and
the reasons are in
[ADR 0201](https://github.com/MEFORORG/MessageFoundry/blob/main/docs/adr/0201-a-messagefoundry-toolkit-distribution-carries-the-authoring-and-development-tooling-out-of-the-engine-wheel.md).

> Released **in lockstep with the engine**: the toolkit and the engine carry the same version, and
> the toolkit requires the engine at exactly that version. If the two installed versions ever differ,
> the toolkit refuses to run and names both.

Install it on an authoring machine, beside the engine and at the engine's version. A deploy does not
need it, and a production host is better without it.

## Use

```text
messagefoundry-toolkit init ./my-config-repo                     # scaffold a config repo
messagefoundry-toolkit generate --type ADT --count 5 --out ./adt # synthetic HL7, no real PHI
messagefoundry-toolkit lens parse ./config/IB_DEMO.py --json     # the VS Code Steps view's rows
messagefoundry-toolkit import corepoint ./export.xml --out ./cfg # a Corepoint action-list import
messagefoundry-toolkit impact --config ./config router my_router # who references an object
messagefoundry-toolkit hl7schema --json                          # the HL7 v2.5.1 field schema
messagefoundry-toolkit adr-analyze --adr-dir docs/adr --json     # ADR acceptance-criteria coverage
messagefoundry-toolkit --help                                    # every toolkit command
```

From a source checkout, run `python -m messagefoundry_toolkit` instead. The VS Code extension runs
the Steps view and Generate Samples that way, with the interpreter it is set to use, so that
interpreter needs the toolkit too.

The engine's `messagefoundry` command refuses each of these commands with a line naming
`messagefoundry-toolkit <command>`.
