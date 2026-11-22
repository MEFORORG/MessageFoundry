- **`engine.stop()` now holds its CRL, watch and alert waits to the shutdown's budget, to keep a
  stop inside NSSM's stop window.** Before, each kept a fixed bound of up to 10 s whatever the
  stop had left. The graph supervisor's wait and the other stop steps are not held to the budget,
  so a slow one can still carry the stop past the window. On a tight stop these waits are cut short, and a cut
  can lose a remote-debug audit row, an alert-instance write, or a CRL reload pass in flight.
  [SERVICE.md](../docs/SERVICE.md#start--stop--status) says how short and what is lost.
  (vault `BACKLOG #3191`)
