// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors

// One section of the pane. A failed read keeps the last good data and sets `error`, so the pane can
// say both "this read failed" and "this is what we last saw, and when". `data: null` with no error
// is only possible before the first read, which the pane shows as "not read yet".
export type FleetSection<T> = {
  okAt: number | null
  // When the latest read failed, or null once a read succeeds.
  failedAt: number | null
  error: string | null
  data: T | null
}

export type FleetSeat = {
  state: string
  detail: string
  surface: string
  login: string
  short: string
  worktree: string
  branch: string
  isSelf: boolean
}

export type FleetPr = {
  number: number
  title: string
  isDraft: boolean
  required: string
  requiredReason: string | null
  failing: number
  pending: number
  missing: number
  unknown: number
  mergeable: string
  queuePosition: number | null
}

export type FleetQueueEntry = { state: string; number: number | null }

export type FleetPrs = {
  dataFetchedAt: string | null
  pollFetchedAt: string | null
  pollError: string | null
  consecutiveFailures: number
  nextPollNotBefore: string | null
  requiredContextsNote: string | null
  // null: the poller has no good data yet, which is unknown, never "no PRs".
  pullRequests: FleetPr[] | null
  openCount: number | null
  truncated: boolean
  mergeQueue: FleetQueueEntry[] | null
  mergeQueueTruncated: boolean
}

export type FleetUsageWindow = {
  label: string
  usedPercentage: number | null
  state: string
  reason: string | null
}

export type FleetUsage = {
  state: string
  reason: string | null
  capturedAt: string | null
  windows: FleetUsageWindow[]
}

export type FleetLane = {
  capacity: number | null
  statedFree: number | null
  statedInFlight: number | null
  statedUtc: string | null
  statedNote: string
  absent: string | null
}

declare module 'claude-code' {
  interface PluginState {
    'fleet-pane': {
      seats: FleetSection<FleetSeat[]>
      prs: FleetSection<FleetPrs>
      usage: FleetSection<FleetUsage>
      lane: FleetSection<FleetLane>
      now: number
    }
  }
}
