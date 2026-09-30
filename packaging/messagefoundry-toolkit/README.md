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
messagefoundry-toolkit adr-analyze --adr-dir docs/adr --json   # ADR acceptance-criteria coverage
messagefoundry-toolkit --help                                  # every toolkit command
```

From a source checkout, run `python -m messagefoundry_toolkit` instead.

The toolkit's commands move out of the engine one at a time. A command that has moved is refused by
the engine's `messagefoundry` command, with a line naming `messagefoundry-toolkit <command>`.
