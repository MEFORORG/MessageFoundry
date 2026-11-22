- **`engine.stop()` now holds its supervisor, CRL, watch and alert waits to the shutdown's
  budget, so a stop fits NSSM's stop window.** Before, each kept a fixed bound of up to 10 s
  whatever the stop had left. On a tight stop, at least the remote-debug watch's last audit pass
  and the alert-instance drain can be cut to about 0.1 s, and a CRL reload pass to about 1.5 s or
  less. A cut audit pass can leave a refusal with no audit row or alert, and an alert raise or
  clear not yet written is lost when the store closes. A cut CRL pass is abandoned, and the next
  start reloads from the file. [SERVICE.md](../docs/SERVICE.md#start--stop--status) says more.
  (vault `BACKLOG #3191`)
