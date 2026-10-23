// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors

import { expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'

import { isOurOrigin, looksStopped, parsePrState } from '../hooks/sources'

const PANE = {
  plugin: 'fleet-pane',
  component: 'Pane',
  requestId: 'fleet',
  props: {
    title: 'Fleet',
    isFocused: false,
    bodyColumns: 200,
    placement: 'dock',
    scroll: { offset: 0, bodyRows: 60 },
    view: {},
  },
} as const

const SEAT = {
  State: 'LIVE', Detail: '', Surface: 'desktop', Login: 'default', Short: 'abcd1234',
  Worktree: 'brave-knuth', Branch: 'claude/brave-knuth', IsSelf: true, IsPrimary: false,
}

const PR_STATE = {
  schemaVersion: 1,
  fetchedAt: '2026-10-23T15:25:01Z',
  error: null,
  errorPart: null,
  stale: false,
  consecutiveFailures: 0,
  requiredContexts: ['CI gate'],
  requiredContextsError: null,
  data: {
    fetchedAt: '2026-10-23T15:25:01Z',
    openPullRequestCount: 1,
    truncated: false,
    pullRequests: [
      {
        number: 2504,
        title: 'vault hop',
        isDraft: false,
        mergeable: 'UNKNOWN',
        mergeStateStatus: null,
        mergeStateKnown: false,
        labels: ['ci-red', 'qa'],
        mergeQueueEntry: null,
        required: { state: 'PENDING', failing: [], pending: ['a', 'b'], missing: ['CI gate'], reason: null },
      },
    ],
    mergeQueue: [],
    mergeQueueTruncated: false,
  },
}

const USAGE = {
  state: 'UNKNOWN',
  captured_at: '2026-10-22T21:06:05Z',
  five_hour: { label: 'session (5h)', used_percentage: 11, state: 'UNKNOWN', reason: 'reading is old' },
  seven_day: { label: 'weekly (7d)', used_percentage: 29, state: 'UNKNOWN', reason: 'reading is old' },
}

const LANE = { capacity: 4, statedFree: null, statedInFlight: null, statedNote: '', absent: 'no lane record at D:/x.json' }

// The person typed /fleet in the composer of a fullscreen terminal.
const FLEET = {
  command: 'fleet',
  args: '',
  origin: { kind: 'composer' },
  presentation: { isFullscreen: true, columns: 200 },
} as const

type World = {
  presence?: { stdout: string; stderr: string }
  origin?: string
  prState?: unknown
  panesDeny?: string
}

// Answers every host call the pane makes, and records any call it must never make.
function host(on: On, world: World = {}) {
  const forbidden: string[] = []
  const ran: string[] = []
  // The host refuses some of these before any hook here sees them (a prompt.submit from a
  // command.run hook), so this is a run-time check only; tests/test_fleet_pane_guard.py scans the source.
  for (const name of ['model.complete', 'model.fork', 'agent.spawn', 'agent.register', 'prompt.submit', 'tool.register', 'tool.call', 'command.run'] as const) {
    on(name, () => {
      forbidden.push(name)
      throw new Error(`fleet-pane must not call ${name}`)
    })
  }
  mock.env(on, { USERPROFILE: 'D:/profile' })
  on('command.register', () => ({ value: { command: 'fleet' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  const logs: string[] = []
  on('ui.log', (_, e) => {
    logs.push(e.text)
    return { value: undefined }
  })
  on('ui.panes', () =>
    world.panesDeny
      ? { deny: world.panesDeny }
      : { value: [{ id: 'fleet', title: 'Fleet', isShown: true, isFocused: false, isPlaced: true }] },
  )
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('fs.read', (_, e) => {
    ran.push(`read ${e.path}`)
    return { value: JSON.stringify(world.prState ?? PR_STATE) }
  })
  on('process.run', (_, e) => {
    const argv = e.argv.join(' ')
    ran.push(argv)
    const ok = (stdout: string, stderr = '') => ({
      value: { exitCode: 0, stdout, stderr, isStdoutTruncated: false, isStderrTruncated: false },
    })
    if (argv.startsWith('git config')) return ok(world.origin ?? 'https://github.com/MEFORORG/MessageFoundry.git\n')
    if (argv.startsWith('git ')) return ok('D:/repo\nD:/repo/.git\n')
    if (argv.includes('presence.ps1')) {
      const p = world.presence ?? { stdout: JSON.stringify([SEAT]), stderr: '' }
      return ok(p.stdout, p.stderr)
    }
    if (argv.includes('usage.ps1')) return { value: { ...ok(JSON.stringify(USAGE)).value, exitCode: 20 } }
    if (argv.includes('lane.ps1')) return ok(JSON.stringify(LANE))
    throw new Error(`unexpected command: ${argv}`)
  })
  return { forbidden, ran, logs }
}

test('the pane reads every source and no hook beneath sees a model, agent, prompt or tool call', async ($, on) => {
  const clock = mock.clock(on, { now: Date.parse('2026-10-23T15:26:00Z') })
  const { forbidden, ran } = host(on)

  await $.session.start({ cwd: 'D:/repo', surface: 'desktop', isInteractive: true })
  await $.command.run(FLEET)
  await clock.advance(130000)

  expect(forbidden).toEqual([])
  // The positive control: the run did reach the host, so the empty list above means something.
  expect(ran.some(r => r.includes('presence.ps1 -Json'))).toBe(true)
  expect(ran.some(r => r.includes('usage.ps1 -Json -StateDir D:/profile/.claude/mefor-usage'))).toBe(true)
  expect(ran.some(r => r.includes('lane.ps1 -Show'))).toBe(true)
  // The host spells the path the platform's way, so compare with forward slashes.
  expect(ran.map(r => r.split('\\').join('/'))).toContain('read D:/repo/.git/mefor-coord/pr-state.json')
})

test('the pane draws each section, with merge state from required and UNKNOWN as computing', async ($, on) => {
  const clock = mock.clock(on, { now: Date.parse('2026-10-23T15:26:00Z') })
  host(on)
  await $.session.start({ cwd: 'D:/repo', surface: 'desktop', isInteractive: true })
  await $.command.run(FLEET)
  await clock.settle()

  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ ...PANE, surface })
    expect((await ui.find({ type: 'Text', text: /abcd1234/ }))?.text).toContain('(this session)')
    const pr = (await ui.find({ type: 'Text', text: /#2504/ }))?.text ?? ''
    expect(pr).toContain('PENDING')
    expect(pr).toContain('merge:computing')
    expect(pr).not.toContain('ci-red')
    expect(await ui.find({ type: 'Text', text: /merge queue: empty/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /session \(5h\): 11% UNKNOWN/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /not stated: no lane record/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /READ FAILED/ })).toBeUndefined()
    await ui.unmount()
  }
})

test('an unavailable roster reads as a failure, never as an empty list', async ($, on) => {
  const clock = mock.clock(on, { now: Date.parse('2026-10-23T15:26:00Z') })
  host(on, { presence: { stdout: '[]', stderr: 'coordination root unreachable\n' } })
  await $.session.start({ cwd: 'D:/repo', surface: 'desktop', isInteractive: true })
  await $.command.run(FLEET)
  await clock.settle()

  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect((await ui.find({ type: 'Text', text: /READ FAILED/ }))?.text).toContain(
    'roster unavailable: coordination root unreachable',
  )
  expect(await ui.find({ type: 'Text', text: /no live seats/ })).toBeUndefined()
  await ui.unmount()
})

test('another repository runs nothing, and every section says why', async ($, on) => {
  const clock = mock.clock(on, { now: Date.parse('2026-10-23T15:26:00Z') })
  const { ran } = host(on, { origin: 'https://github.com/someone/other.git\n' })
  await $.session.start({ cwd: 'D:/repo', surface: 'desktop', isInteractive: true })
  await $.command.run(FLEET)
  await clock.settle()

  expect(ran.filter(r => r.startsWith('pwsh') || r.startsWith('read'))).toEqual([])
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  const failed = (await ui.find({ type: 'Text', text: /READ FAILED/ }))?.text ?? ''
  expect(failed).toContain('not github.com/MEFORORG/MessageFoundry')
  expect(failed).not.toContain('someone')
  await ui.unmount()
})

test('a stopped poller is flagged, and unknown counts only unsettled contexts', async ($, on) => {
  const clock = mock.clock(on, { now: Date.parse('2026-10-23T15:26:00Z') })
  const old = '2026-10-23T14:00:00Z'
  const pr = {
    ...PR_STATE.data.pullRequests[0],
    required: {
      state: 'UNKNOWN',
      failing: [],
      pending: ['a'],
      missing: [],
      unknown: ['b'],
      requiredByGithubNotInList: ['a'],
      reason: null,
    },
  }
  const prState = { ...PR_STATE, fetchedAt: old, data: { ...PR_STATE.data, fetchedAt: old, pullRequests: [pr] } }
  host(on, { prState })
  await $.session.start({ cwd: 'D:/repo', surface: 'desktop', isInteractive: true })
  await $.command.run(FLEET)
  await clock.settle()

  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect(await ui.find({ type: 'Text', text: /POLLER STOPPED\?/ })).toBeDefined()
  const row = (await ui.find({ type: 'Text', text: /#2504/ }))?.text ?? ''
  expect(row).toContain('1 pending 1 unknown')
  await ui.unmount()
})

test('a fresh poll raises no stopped-poller flag', async ($, on) => {
  const clock = mock.clock(on, { now: Date.parse('2026-10-23T15:26:00Z') })
  host(on)
  await $.session.start({ cwd: 'D:/repo', surface: 'desktop', isInteractive: true })
  await $.command.run(FLEET)
  await clock.settle()

  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect(await ui.find({ type: 'Text', text: /POLLER STOPPED/ })).toBeUndefined()
  await ui.unmount()
})

test('a source is read again at its interval, not a tick late', async ($, on) => {
  const clock = mock.clock(on, { now: Date.parse('2026-10-23T15:26:00Z') })
  const { ran } = host(on)
  await $.session.start({ cwd: 'D:/repo', surface: 'desktop', isInteractive: true })
  // Open the pane off the tick grid: the PR read lands 1 s after a tick, so the tick 29 s later must
  // still count it as due. An exact comparison would wait for the tick after that, 44 s later.
  await clock.advance(1000)
  await $.command.run(FLEET)
  await clock.settle()
  const reads = () => ran.filter(r => r.startsWith('read')).length
  const first = reads()
  await clock.advance(29000)
  expect(reads()).toBe(first + 1)
})

test('the origin check takes github.com spellings of this repository and nothing else', () => {
  for (const url of [
    'https://github.com/MEFORORG/MessageFoundry.git',
    'https://github.com/MEFORORG/MessageFoundry',
    'https://github.com/MEFORORG/MessageFoundry/',
    'git@github.com:MEFORORG/MessageFoundry.git',
    'ssh://git@github.com/MEFORORG/MessageFoundry.git',
  ]) {
    expect(isOurOrigin(url)).toBe(true)
  }
  for (const url of [
    'https://evil.example/MEFORORG/MessageFoundry.git',
    'https://github.com.evil.example/MEFORORG/MessageFoundry.git',
    'https://x-access-token:secret@github.com/MEFORORG/MessageFoundry.git',
    'git@evil.example:MEFORORG/MessageFoundry.git',
    'ssh://git@github.com.evil.example/MEFORORG/MessageFoundry.git',
    'https://github.com/MEFORORG/MessageFoundry-fork.git',
    'https://github.com/someone/MessageFoundry.git',
    '',
  ]) {
    expect(isOurOrigin(url)).toBe(false)
  }
})

test('the origin token never reaches the pane', async ($, on) => {
  const clock = mock.clock(on, { now: Date.parse('2026-10-23T15:26:00Z') })
  host(on, { origin: 'https://x-access-token:secret@evil.example/MEFORORG/MessageFoundry.git\n' })
  await $.session.start({ cwd: 'D:/repo', surface: 'desktop', isInteractive: true })
  await $.command.run(FLEET)
  await clock.settle()

  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect(await ui.find({ type: 'Text', text: /secret/ })).toBeUndefined()
  expect(await ui.find({ type: 'Text', text: /READ FAILED/ })).toBeDefined()
  await ui.unmount()
})

test('an old poll inside the poller back-off is not flagged as stopped', async ($, on) => {
  const clock = mock.clock(on, { now: Date.parse('2026-10-23T15:26:00Z') })
  const old = '2026-10-23T14:00:00Z'
  const prState = {
    ...PR_STATE,
    fetchedAt: old,
    nextPollNotBefore: '2026-10-23T15:40:00Z',
    data: { ...PR_STATE.data, fetchedAt: old },
  }
  host(on, { prState })
  await $.session.start({ cwd: 'D:/repo', surface: 'desktop', isInteractive: true })
  await $.command.run(FLEET)
  await clock.settle()

  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect(await ui.find({ type: 'Text', text: /POLLER STOPPED/ })).toBeUndefined()
  expect((await ui.find({ type: 'Text', text: /backing off/ }))?.text).toBe('poller backing off for 14 more min')
  await ui.unmount()
})

test('a fault is logged once, and again if it returns after a recovery', async ($, on) => {
  const clock = mock.clock(on, { now: Date.parse('2026-10-23T15:26:00Z') })
  const world: World = {}
  const { logs } = host(on, world)
  await $.session.start({ cwd: 'D:/repo', surface: 'desktop', isInteractive: true })
  await clock.settle()

  world.panesDeny = 'panes unavailable'
  await clock.advance(15000)
  await clock.advance(15000)
  expect(logs.length).toBe(1)

  world.panesDeny = undefined
  await clock.advance(15000)
  world.panesDeny = 'panes unavailable'
  await clock.advance(15000)
  expect(logs.length).toBe(2)
})

test('the stopped-poller rule follows the poller: back-off, its 2 h cap, then one interval of grace', () => {
  const at = (iso: string) => Date.parse(iso)
  const cache = (nextPollNotBefore: string | null) =>
    parsePrState(JSON.stringify({ ...PR_STATE, fetchedAt: '2026-10-23T14:00:00Z', nextPollNotBefore }))

  // No back-off: an 86-minute-old poll is a stopped poller.
  expect(looksStopped(cache(null), at('2026-10-23T15:26:00Z'))).toBe(true)
  // Inside a back-off, and in the scheduled interval right after it ends, it is not.
  expect(looksStopped(cache('2026-10-23T15:40:00Z'), at('2026-10-23T15:26:00Z'))).toBe(false)
  expect(looksStopped(cache('2026-10-23T15:40:00Z'), at('2026-10-23T15:43:00Z'))).toBe(false)
  // Once that interval and the pane's own read lag have passed with no new poll, it is.
  expect(looksStopped(cache('2026-10-23T15:40:00Z'), at('2026-10-23T15:44:00Z'))).toBe(true)
  // A stamp the poller would ignore (over 2 h past the poll that wrote it) holds nothing back.
  expect(looksStopped(cache('2026-10-24T14:00:00Z'), at('2026-10-23T15:26:00Z'))).toBe(true)
})
