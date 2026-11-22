- **`support-bundle` reads at most the last 4 MiB of the app log.** It used to read the whole
  file, so a large enough log could exhaust memory and leave no zip. The tail can now hold fewer
  lines than `--log-tail-lines`. When the bytes kept, less the line the bound cuts into, hold
  nothing but line breaks, as when a line longer than the bound is followed only by blank lines
  or by nothing, `app-log.txt` reports `MF-BUNDLE-LOG-003 _LogLineTooLong`. A log truncated in place on both
  reads reports `MF-BUNDLE-LOG-002 _LogFileShrank`. (`BACKLOG #5385`)
