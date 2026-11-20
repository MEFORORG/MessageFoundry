- **An alert rule's `control_action` restart runs on its own throttle.** Its window, per event
  type and connection, is now kept apart from the notification's, and only a restart the sink
  actually schedules starts it. So a restart can fire on an alert whose page is throttled, when no
  earlier alert in the window ran a restart. The 2026-11-19 amendment to ADR 0128 section 4 states the bound and at least its
  limits, a zero cooldown and a `schedule` switch (owner ruling 2026-11-19, on PR 3069).
  (`BACKLOG #5910`)
