// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors

// Pure parsers, one per source. Each returns the section's data or throws an Error whose message is
// what the pane prints. None of them may turn a failed read into an empty list: an empty result is
// returned only when the source itself said "nothing".

import type { FleetLane, FleetPr, FleetPrs, FleetQueueEntry, FleetSeat, FleetUsage, FleetUsageWindow } from '../types'

export type Ran = { exitCode: number; stdout: string; stderr: string }

type Json = Record<string, unknown>

export const firstLine = (text: string): string => text.trim().split(/\r?\n/)[0] ?? ''
export const words = (err: unknown): string => (err instanceof Error ? err.message : String(err))
const exited = (script: string, ran: Ran): string =>
  `${script} exited ${ran.exitCode}: ${firstLine(ran.stderr) || 'no stderr'}`

const str = (v: unknown, fallback = ''): string => (typeof v === 'string' ? v : fallback)
const strOrNull = (v: unknown): string | null => (typeof v === 'string' ? v : null)
const numOrNull = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v)
const len = (v: unknown): number => (Array.isArray(v) ? v.length : 0)

function parseJson(text: string, what: string): unknown {
  try {
    return JSON.parse(text)
  } catch (err) {
    throw new Error(`${what} printed no JSON: ${words(err)}`)
  }
}

// presence.ps1 -Json prints `[]` on stdout and the reason on stderr when the roster is unavailable,
// so an empty list beside stderr is a failure, not "nobody is live".
export function parsePresence(ran: Ran): FleetSeat[] {
  if (ran.exitCode !== 0) {
    throw new Error(exited('presence.ps1', ran))
  }
  const rows = parseJson(ran.stdout, 'presence.ps1')
  if (!Array.isArray(rows)) throw new Error('presence.ps1 printed JSON that is not a list')
  if (rows.length === 0 && ran.stderr.trim() !== '') {
    throw new Error(`roster unavailable: ${firstLine(ran.stderr)}`)
  }
  return rows.filter(isObject).map(row => ({
    state: str(row.State, '?'),
    detail: str(row.Detail),
    surface: str(row.Surface),
    login: str(row.Login),
    short: str(row.Short),
    worktree: str(row.Worktree),
    branch: str(row.Branch),
    isSelf: row.IsSelf === true,
  }))
}

// GitHub's null and UNKNOWN both mean it has not computed the answer yet.
function mergeableWord(pr: Json): string {
  return pr.mergeStateKnown === false || pr.mergeable === 'UNKNOWN' ? 'computing' : str(pr.mergeable, 'computing')
}

function parsePr(pr: Json): FleetPr {
  const required = isObject(pr.required) ? pr.required : {}
  const entry = isObject(pr.mergeQueueEntry) ? pr.mergeQueueEntry : null
  return {
    number: numOrNull(pr.number) ?? 0,
    title: str(pr.title),
    isDraft: pr.isDraft === true,
    // required.state, never the sticky `ci-red` label (docs/WORKTREES.md reading rule 4).
    required: str(required.state, 'UNKNOWN'),
    requiredReason: strOrNull(required.reason),
    failing: len(required.failing),
    pending: len(required.pending),
    missing: len(required.missing),
    // Contexts the verdict could not settle, including ones GitHub requires but the list lacks.
    unknown: len(required.unknown) + len(required.requiredByGithubNotInList),
    mergeable: mergeableWord(pr),
    queuePosition: entry ? numOrNull(entry.position) : null,
  }
}

// Reader rules: docs/WORKTREES.md, "A PR-state cache for read-only panes".
export function parsePrState(text: string): FleetPrs {
  const doc = parseJson(text, 'pr-state.json')
  if (!isObject(doc)) throw new Error('pr-state.json is not a JSON object')
  if (doc.schemaVersion !== 1) {
    throw new Error(`pr-state.json has schemaVersion ${String(doc.schemaVersion)}; this pane reads 1 only`)
  }
  const pollError = strOrNull(doc.error)
  const part = strOrNull(doc.errorPart)
  const contexts = doc.requiredContexts
  const contextsError = strOrNull(doc.requiredContextsError)
  let requiredContextsNote: string | null = null
  if (!Array.isArray(contexts) || contexts.length === 0) {
    requiredContextsNote = `required list ${contexts === null || contexts === undefined ? 'missing' : 'empty'}: ${contextsError ?? 'no error recorded'}`
  } else if (contextsError) {
    requiredContextsNote = `last required-list refresh failed (older list kept): ${contextsError}`
  }
  // `data: null` means no good poll yet: every field below then reads as unknown, never as none.
  const data: Json = isObject(doc.data) ? doc.data : {}
  const prs = Array.isArray(data.pullRequests) ? data.pullRequests.filter(isObject).map(parsePr) : null
  const queue: FleetQueueEntry[] | null =
    Array.isArray(data.mergeQueue)
      ? data.mergeQueue.filter(isObject).map(q => ({
          state: str(q.state, '?'),
          number: numOrNull(q.number),
        }))
      : null
  return {
    dataFetchedAt: strOrNull(data.fetchedAt),
    pollFetchedAt: strOrNull(doc.fetchedAt),
    pollError: pollError ? (part ? `${pollError} (${part})` : pollError) : null,
    consecutiveFailures: numOrNull(doc.consecutiveFailures) ?? 0,
    requiredContextsNote,
    pullRequests: prs,
    openCount: numOrNull(data.openPullRequestCount),
    truncated: data.truncated === true,
    mergeQueue: queue,
    mergeQueueTruncated: data.mergeQueueTruncated === true,
  }
}

function usageWindow(v: unknown): FleetUsageWindow | null {
  if (!isObject(v)) return null
  return {
    label: str(v.label, '?'),
    usedPercentage: numOrNull(v.used_percentage),
    state: str(v.state, 'UNKNOWN'),
    reason: strOrNull(v.reason),
  }
}

// usage.ps1 exits non-zero for UNKNOWN and other states and still prints its JSON, so the JSON
// decides, and the exit code matters only when there is none.
export function parseUsage(ran: Ran): FleetUsage {
  let doc: unknown
  try {
    doc = JSON.parse(ran.stdout)
  } catch {
    throw new Error(`${exited('usage.ps1', ran)} (and printed no JSON)`)
  }
  if (!isObject(doc) || typeof doc.state !== 'string') throw new Error('usage.ps1 printed JSON with no state')
  const windows = [usageWindow(doc.five_hour), usageWindow(doc.seven_day)].filter(
    (w): w is FleetUsageWindow => w !== null,
  )
  return { state: doc.state, reason: strOrNull(doc.reason), capturedAt: strOrNull(doc.captured_at), windows }
}

// lane.ps1 -Show prints a blank record with `absent` set when it found none. "No lane record" is an
// honest "not stated"; any other `absent` is a read that failed, so it is an error.
export function parseLane(ran: Ran): FleetLane {
  if (ran.exitCode !== 0) {
    throw new Error(exited('lane.ps1', ran))
  }
  const doc = parseJson(ran.stdout, 'lane.ps1')
  if (!isObject(doc)) throw new Error('lane.ps1 printed JSON that is not an object')
  const absent = strOrNull(doc.absent)
  if (absent && !/^no lane record at |^no lanes directory found at /.test(absent)) throw new Error(absent)
  return {
    capacity: numOrNull(doc.capacity),
    statedFree: numOrNull(doc.statedFree),
    statedInFlight: numOrNull(doc.statedInFlight),
    statedUtc: strOrNull(doc.statedUtc),
    statedNote: str(doc.statedNote),
    absent,
  }
}

export function ageWords(ms: number): string {
  if (ms < 0) return 'just now'
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  if (m < 120) return `${m}m ago`
  return `${Math.round(m / 60)}h ago`
}

// How old an ISO time is, in ms; an absent or unreadable one counts as infinitely old.
export function pollAge(iso: string | null, now: number): number {
  const t = iso ? Date.parse(iso) : NaN
  return Number.isNaN(t) ? Infinity : now - t
}

export function sinceIso(iso: string | null, now: number): string {
  if (!iso) return 'never'
  const t = Date.parse(iso)
  return Number.isNaN(t) ? `unreadable time ${iso}` : ageWords(now - t)
}
