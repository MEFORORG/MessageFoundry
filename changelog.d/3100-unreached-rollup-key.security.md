- **One rollup of unreachable accounts cannot silence a later one.** The notifier keys its
  re-alert cooldown and an operator's suspend by type and source. Under one shared rollup source,
  inside the cooldown of the last rollup sent, or while any rollup was suspended, a later rollup
  would page nobody: at least one account entering after five or more were paged, and a later
  rollup of other accounts. A rollup now counts only the accounts entering on its own pass, so
  one account entering after a rollup pages under its own name. Each rollup pages under
  `directory-reconciler-unreached-rollup:<key>`, keyed by the accounts entering, so it is its
  own instance, and an INFO line logs the key. A cooldown or suspend reaches only a later
  rollup of the same accounts; a set that differs, even one of accounts paged before, pages.
  These instances have no inverse, so the notifier keeps a rollup's in-memory cooldown and
  occurrence count for the 1024 rollups emitted most recently only; an older one pages on its next
  emit at the base escalation tier, as after a restart. At startup the notifier seeds suspends from
  the live instances suspended past now, so unsuspended instances no longer crowd one out of its
  read; that read still holds at most 1000, and one that fails seeds none. To match every
  unreachable-account alert, an `[alerts]` rule names `directory-reconciler-unreached*` (vault
  BACKLOG #3100 item 14).
