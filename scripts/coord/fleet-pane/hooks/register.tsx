// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors

// The /fleet pane: live seats, open PRs and the merge queue, usage headroom, and this worktree's
// lane, read from the coordination scripts beside this folder. Read-only, and it makes no model
// call: it reaches the host through $.process.run, $.fs.read and $.env.get alone. Every path literal uses
// forward slashes, because a backslash in a JS string is an escape and the path silently breaks.

import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { FleetLane, FleetPrs, FleetSeat, FleetSection, FleetUsage } from '../types'
import { ageWords, firstLine, parseLane, parsePresence, parsePrState, parseUsage, pollAge, sinceIso, words } from './sources'
import type { Ran } from './sources'

const PANE = 'fleet'
const TITLE = 'Fleet'

// How often each source is read while the pane is placed. One timer ticks every TICK and reads the
// sources that are due, so a closed pane costs one engine call per tick and nothing else.
const EVERY = { seats: 60000, prs: 30000, usage: 120000, lane: 120000 } as const
const TICK = 15000
// The poller writes every 2 minutes; data older than this means it has stopped.
const PR_STALE_MS = 10 * 60000
// Only this repository's scripts run, so a user-wide install never runs another repo's scripts/coord.
const OUR_REMOTE = /[/:]MEFORORG\/MessageFoundry(\.git)?$/i
type SourceName = keyof typeof EVERY
const SOURCES = Object.keys(EVERY) as SourceName[]

const blank = { okAt: null, failedAt: null, error: null, data: null }
const seats = atom({ plugin: 'fleet-pane', key: 'seats' } as const, blank as FleetSection<FleetSeat[]>)
const prs = atom({ plugin: 'fleet-pane', key: 'prs' } as const, blank as FleetSection<FleetPrs>)
const usage = atom({ plugin: 'fleet-pane', key: 'usage' } as const, blank as FleetSection<FleetUsage>)
const lane = atom({ plugin: 'fleet-pane', key: 'lane' } as const, blank as FleetSection<FleetLane>)
// Moves on every tick while the pane is placed, so each section's age stays true between reads.
const now = atom({ plugin: 'fleet-pane', key: 'now' } as const, 0)

type Where = { cwd: string; root: string; commonDir: string; configRoot: string }

const slashes = (p: string): string => p.trim().replace(/\\/g, '/')

// Module variables start over on a reload, which is what these want: the reload drops the old
// timer, session.start sets the cwd again, and the rest is re-derived on the next read. The
// validator asks that `$` be passed only to functions declared at the top of the file, so every
// helper lives here.
let sessionCwd: string | null = null
let where: Promise<Where> | null = null
let isTicking = false
const busy = new Set<SourceName>()
const lastRun: Partial<Record<SourceName, number>> = {}

async function resolveWhere($: EngineInterface): Promise<Where> {
  if (!sessionCwd) throw new Error('the session has not started yet')
  const cwd = sessionCwd
  const [git, remote, configDir, profile] = await Promise.all([
    $.process.run(['git', 'rev-parse', '--path-format=absolute', '--show-toplevel', '--git-common-dir'], {
      cwd,
      timeoutMs: 10000,
    }),
    $.process.run(['git', 'config', '--get', 'remote.origin.url'], { cwd, timeoutMs: 10000 }),
    $.env.get('CLAUDE_CONFIG_DIR'),
    $.env.get('USERPROFILE'),
  ])
  const [root, commonDir] = git.stdout.trim().split(/\r?\n/)
  if (git.exitCode !== 0 || !root || !commonDir) {
    throw new Error(`not in a git checkout (${firstLine(git.stderr) || `git exited ${git.exitCode}`})`)
  }
  const origin = remote.stdout.trim()
  if (!OUR_REMOTE.test(origin)) {
    throw new Error(`this checkout's origin is ${origin || 'unset'}, not MEFORORG/MessageFoundry; nothing was run`)
  }
  // CLAUDE_CONFIG_DIR is unset in desktop sessions; the default root is the profile's .claude.
  const configRoot = configDir ? slashes(configDir) : profile ? `${slashes(profile)}/.claude` : ''
  if (!configRoot) throw new Error('neither CLAUDE_CONFIG_DIR nor USERPROFILE is set')
  return { cwd, root: slashes(root), commonDir: slashes(commonDir), configRoot }
}

function locate($: EngineInterface): Promise<Where> {
  if (!where) {
    const found = resolveWhere($)
    where = found
    // A failed lookup is retried on the next read rather than cached.
    found.catch(() => {
      if (where === found) where = null
    })
  }
  return where
}

function pwsh($: EngineInterface, w: Where, script: string, args: string[]): Promise<Ran> {
  return $.process.run(
    ['pwsh', '-NoProfile', '-NonInteractive', '-File', `${w.root}/scripts/coord/${script}`, ...args],
    { cwd: w.cwd, timeoutMs: 20000 },
  )
}

async function readPrState($: EngineInterface, w: Where): Promise<FleetPrs> {
  const path = `${w.commonDir}/mefor-coord/pr-state.json`
  let text: string
  try {
    text = await $.fs.read(path)
  } catch (err) {
    throw new Error(`cannot read ${path} (is the MEFOR-PR-State task registered?): ${words(err)}`)
  }
  return parsePrState(text)
}

type Outcome<T> = { ok: true; data: T } | { ok: false; error: string }

// One read of one source, its failure kept as words rather than thrown.
async function attempt<T>(read: Promise<T>): Promise<Outcome<T>> {
  try {
    return { ok: true, data: await read }
  } catch (err) {
    return { ok: false, error: words(err) }
  }
}

// A failure keeps the last good data beside the error, so the pane can show both.
function applied<T>(old: FleetSection<T>, t: number, o: Outcome<T>): FleetSection<T> {
  return o.ok ? { okAt: t, failedAt: null, error: null, data: o.data } : { ...old, failedAt: t, error: o.error }
}

async function readSource($: EngineInterface, name: SourceName): Promise<void> {
  if (busy.has(name)) return
  busy.add(name)
  try {
    const t = await $.clock.now()
    lastRun[name] = t
    // A lookup failure lands in the section that asked, so a broken checkout shows on every one.
    const w = locate($)
    if (name === 'seats') {
      const o = await attempt(w.then(async v => parsePresence(await pwsh($, v, 'presence.ps1', ['-Json']))))
      await update($, seats, old => applied(old, t, o))
    } else if (name === 'prs') {
      const o = await attempt(w.then(v => readPrState($, v)))
      await update($, prs, old => applied(old, t, o))
    } else if (name === 'usage') {
      const o = await attempt(
        w.then(async v =>
          parseUsage(await pwsh($, v, 'usage.ps1', ['-Json', '-StateDir', `${v.configRoot}/mefor-usage`])),
        ),
      )
      await update($, usage, old => applied(old, t, o))
    } else {
      const o = await attempt(w.then(async v => parseLane(await pwsh($, v, 'lane.ps1', ['-Show']))))
      await update($, lane, old => applied(old, t, o))
    }
  } finally {
    busy.delete(name)
  }
}

async function isPlaced($: EngineInterface): Promise<boolean> {
  return (await $.ui.panes()).some(pane => pane.id === PANE && pane.isPlaced)
}

// Reads the sources named, then moves the clock the ages are drawn from.
async function readAndTick($: EngineInterface, names: SourceName[]): Promise<void> {
  await Promise.all(names.map(name => readSource($, name)))
  const t = await $.clock.now()
  await update($, now, () => t)
}

// Fire-and-forget work still reports a failure, in the debug log and the transcript's dim line.
function background($: EngineInterface, work: Promise<void>): void {
  work.catch(err => $.ui.log(`fleet-pane: ${words(err)}`))
}

// One tick: nothing while the pane is not placed, else every source whose interval has passed.
async function onTick($: EngineInterface): Promise<void> {
  if (!(await isPlaced($))) return
  const t = await $.clock.now()
  // Half a tick of slack: lastRun is stamped a few ms after the tick that started the read, so an
  // exact comparison would push every source one whole tick late.
  await readAndTick($, SOURCES.filter(name => t - (lastRun[name] ?? -Infinity) >= EVERY[name] - TICK / 2))
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    if (e.cwd !== sessionCwd) where = null
    sessionCwd = e.cwd
    await $.command.register({
      name: 'fleet',
      description: 'Show fleet status beside the chat: live seats, open PRs, usage, this lane',
    })
    if (!isTicking) {
      isTicking = true
      $.clock.every(TICK, () => background($, onTick($)))
    }
    // A reload keeps the pane open but starts the module over; refill it at once if it is up.
    background($, onTick($))
    return next(e)
  })

  on('command.run', { command: 'fleet' }, async $ => {
    const opened = await $.ui.open({ id: PANE, title: TITLE })
    background($, readAndTick($, SOURCES))
    return { text: opened.isPlaced ? 'Fleet pane opened.' : `Fleet pane is open but not drawn: ${opened.reason}` }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const t = (await read($, now)) || (await $.clock.now())
    const width = Math.max(20, e.props.bodyColumns)
    const cut = (s: string) => (s.length > width ? `${s.slice(0, width - 1)}~` : s)

    function head<T>(title: string, s: FleetSection<T>, name: SourceName) {
      const age =
        s.okAt !== null ? `read ${ageWords(t - s.okAt)}` : s.failedAt !== null ? 'no good read yet' : 'not read yet'
      return (
        <Box flexDirection="column">
          <Text bold>{cut(`${title}  (${age}; every ${EVERY[name] / 1000}s)`)}</Text>
          {s.error !== null && (
            <Text color="red">{cut(`READ FAILED ${s.failedAt === null ? '' : ageWords(t - s.failedAt)}: ${s.error}`)}</Text>
          )}
          {s.error !== null && s.data !== null && <Text dimColor>showing the last good read</Text>}
        </Box>
      )
    }

    const [s, p, u, l] = await Promise.all([read($, seats), read($, prs), read($, usage), read($, lane)])

    const seatRows = (s.data ?? []).map(row => (
      <Text dimColor={row.state !== 'LIVE'}>
        {cut(
          `${row.state} ${row.short} ${row.worktree || '(primary)'} [${row.branch}] ${row.surface}/${row.login}` +
            `${row.isSelf ? ' (this session)' : ''}${row.detail ? ` - ${row.detail}` : ''}`,
        )}
      </Text>
    ))

    const pd = p.data
    const prRows = (pd?.pullRequests ?? []).map(pr => (
      <Text color={pr.required === 'FAILURE' ? 'red' : undefined} dimColor={pr.isDraft}>
        {cut(
          `#${pr.number} ${pr.required}` +
            `${pr.failing ? ` ${pr.failing} failing` : ''}${pr.pending ? ` ${pr.pending} pending` : ''}` +
            `${pr.missing ? ` ${pr.missing} missing` : ''}${pr.unknown ? ` ${pr.unknown} unknown` : ''}${pr.requiredReason ? ` (${pr.requiredReason})` : ''}` +
            ` merge:${pr.mergeable}${pr.queuePosition !== null ? ` queue#${pr.queuePosition}` : ''}` +
            `${pr.isDraft ? ' draft' : ''} ${pr.title}`,
        )}
      </Text>
    ))

    const ud = u.data
    const ld = l.data

    return (
      <Box flexDirection="column">
        {head('Live seats', s, 'seats')}
        {s.data !== null && s.data.length === 0 && <Text dimColor>roster read: no live seats</Text>}
        {seatRows}
        <Text> </Text>

        {head('Open PRs and merge queue', p, 'prs')}
        {pd !== null && (
          <Box flexDirection="column">
            <Text dimColor>
              {cut(`poller data ${sinceIso(pd.dataFetchedAt, t)}; last poll ${sinceIso(pd.pollFetchedAt, t)}`)}
            </Text>
            {pd.pollError === null && pollAge(pd.pollFetchedAt, t) > PR_STALE_MS && (
              <Text color="red">
                {cut(`POLLER STOPPED? last poll ${sinceIso(pd.pollFetchedAt, t)}; is the MEFOR-PR-State task running?`)}
              </Text>
            )}
            {pd.pollError !== null && (
              <Text color="red">
                {cut(`POLL FAILED (${pd.consecutiveFailures} in a row, data is stale): ${pd.pollError}`)}
              </Text>
            )}
            {pd.requiredContextsNote !== null && <Text color="yellow">{cut(pd.requiredContextsNote)}</Text>}
            {pd.pullRequests === null && <Text color="yellow">no good poll yet: open PRs unknown</Text>}
            {pd.pullRequests !== null && pd.pullRequests.length === 0 && !pd.truncated && (
              <Text dimColor>GitHub reports no open PRs</Text>
            )}
            {pd.truncated && (
              <Text color="yellow">{cut(`list truncated: ${pd.openCount ?? '?'} open, ${pd.pullRequests?.length ?? 0} shown`)}</Text>
            )}
            {prRows}
            <Text>
              {cut(
                pd.mergeQueue === null
                  ? 'merge queue: GitHub returned none'
                  : pd.mergeQueue.length === 0
                    ? 'merge queue: empty'
                    : `merge queue: ${pd.mergeQueue.map(q => `#${q.number ?? '?'} ${q.state}`).join(', ')}` +
                      `${pd.mergeQueueTruncated ? ' (truncated)' : ''}`,
              )}
            </Text>
          </Box>
        )}
        <Text> </Text>

        {head('Usage', u, 'usage')}
        {ud !== null && (
          <Box flexDirection="column">
            <Text color={ud.state === 'UNKNOWN' ? 'yellow' : undefined}>
              {cut(`${ud.state}${ud.capturedAt ? `, reading taken ${sinceIso(ud.capturedAt, t)}` : ''}${ud.reason ? `: ${ud.reason}` : ''}`)}
            </Text>
            {ud.windows.map(w => (
              <Text>
                {cut(
                  `${w.label}: ${w.usedPercentage === null ? '?' : `${w.usedPercentage}%`} ${w.state}` +
                    `${w.reason ? ` (${w.reason})` : ''}`,
                )}
              </Text>
            ))}
          </Box>
        )}
        <Text> </Text>

        {head('This lane', l, 'lane')}
        {ld !== null && (
          <Text>
            {cut(
              ld.absent !== null
                ? `not stated: ${ld.absent}`
                : `free ${ld.statedFree ?? '?'} / in flight ${ld.statedInFlight ?? '?'} of ${ld.capacity ?? '?'}` +
                    `, stated ${sinceIso(ld.statedUtc, t)}${ld.statedNote ? ` - ${ld.statedNote}` : ''}`,
            )}
          </Text>
        )}
      </Box>
    )
  })
}
