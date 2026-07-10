**Insert Element** is a quick-pick of the most-used Handler/Router idioms — read a field, copy a
field, loop over repetitions, look up a code set, convert a timestamp, send — dropped into the
active editor as real, editable Python:

```python
value = msg["PID-3.1"]
msg["PID-3.1"] = "value"
```

It reads the same snippet catalog the editor's prefix tab-completion uses, so there is one source
of truth. Open a Python config file, place your cursor, then run the command.
