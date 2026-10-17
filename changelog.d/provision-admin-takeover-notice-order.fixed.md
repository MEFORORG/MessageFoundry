- **`provision-admin` tells the earlier holder before it writes the new `--email` address.** On a
  repair, the takeover notice now goes out before the address write. A run that stopped between
  that write and the role used to leave the operator's address on the row, so the re-run told the
  operator instead of the earlier holder. A run that stops just after the notice sends it again
  on the re-run. (vault BACKLOG #2915)
