Your interfaces live as **code-first Python** under the config dir (`messagefoundry.configDir`,
default `samples/config`): one module per Connection / Router / Handler, plus an optional
`connections.toml` for data-authored transport config.

```
samples/config/
  IB_ACME_ADT.py     # inbound Connection + @router + @handler
  connections.toml   # data-authored connections (opens in a form by default)
  codesets/          # translation tables (CSV grids)
```

Opening `connections.toml` or a `codesets/*.csv` lands you in a **form** — use **Reopen With → Text
Editor** any time you want the raw file. Everything else is ordinary Python: Pylance, the debugger,
and MessageFoundry's completion all work as usual.
