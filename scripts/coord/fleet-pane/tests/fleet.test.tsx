// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors

import { expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'

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

type World = { presence?: { stdout: string; stderr: string } }

// Answers every host call the pane makes, and records any call it must never make.
function host(on: On, world: World = {}) {
  const forbidden: string[] = []
  const ran: string[] = []
  for (const name of ['model.complete', 'model.fork', 'agent.spawn', 'agent.register', 'prompt.submit', 'tool.register'] as const) {
    on(name, () => {
      forbidden.push(name)
      throw new Error(`fleet-pane must not call ${name}`)
    })
  }
  mock.env(on, { USERPROFILE: 'D:/profile' })
  on('command.register', () => ({ value: { command: 'fleet' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.panes', () => ({ value: [{ id: 'fleet', title: 'Fleet', isShown: true, isFocused: false, isPlaced: true }] }))
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('fs.read', (_, e) => {
    ran.push(`read ${e.path}`)
    return { value: JSON.stringify(PR_STATE) }
  })
  on('process.run', (_, e) => {
    const argv = e.argv.join(' ')
    ran.push(argv)
    const ok = (stdout: string, stderr = '') => ({
      value: { exitCode: 0, stdout, stderr, isStdoutTruncated: false, isStderrTruncated: false },
    })
    if (argv.startsWith('git ')) return ok('D:/repo\nD:/repo/.git\n')
    if (argv.includes('presence.ps1')) {
      const p = world.presence ?? { stdout: JSON.stringify([SEAT]), stderr: '' }
      return ok(p.stdout, p.stderr)
    }
    if (argv.includes('usage.ps1')) return { value: { ...ok(JSON.stringify(USAGE)).value, exitCode: 20 } }
    if (argv.includes('lane.ps1')) return ok(JSON.stringify(LANE))
    throw new Error(`unexpected command: ${argv}`)
  })
  return { forbidden, ran }
}

test('the pane reads every source and never reaches a model, agent, prompt or tool', async ($, on) => {
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
