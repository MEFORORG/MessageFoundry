- **The all-platforms lock auditor reads a line of backslashes as pip does, and refuses `-r` after
  the lock.** A line holding only a backslash was counted as a requirement, and an include such as
  `-r other.txt` after one escaped the pip-option-line refusal. pip joins such a line into nothing,
  so the auditor now does too, and refuses that include with exit 2. `-r` or `--requirement` after
  the lock, short, abbreviated or in the `=` form, is refused with exit 2, since pip-audit would
  read that file with its markers in place. The printed count no longer counts one pin twice where
  the lock pins one version under two markers, and a lock character the console cannot encode is
  printed as `?` instead of ending the run with a traceback.
