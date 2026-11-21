- **`support-bundle` reads at most the last 4 MiB of the app log.** It used to read the whole
  file, so a large enough log could exhaust memory and leave no zip. The tail can now hold fewer
  lines than `--log-tail-lines`, and a last line longer than the bound reports
  `MF-BUNDLE-LOG-002 _LogLineTooLong` in `app-log.txt`. (`BACKLOG #5385`)
