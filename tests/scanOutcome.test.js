import test from 'node:test'
import assert from 'node:assert/strict'
import { describeOutcome, waitForResult } from '../src/scanOutcome.js'

const complete = {
  status: 'completed', findings: [], issues: [],
  scannerRuns: [{ scannerId: 'native', status: 'completed' }],
  coverage: { nativeProcessedFiles: 2 },
}

test('zero findings is scoped to checks that ran', () => {
  assert.equal(describeOutcome(complete), 'No findings from the checks that ran.')
  assert.match(describeOutcome({ ...complete, coverage: { nativeProcessedFiles: 0 } }), /No eligible files/)
  assert.match(describeOutcome({ ...complete, findings: [{}] }), /with findings/)
})

test('incomplete and unknown outcomes cannot produce the clean copy', () => {
  for (const change of [{ status: 'partial' }, { status: 'cancelled' }, { status: 'failed' },
    { status: 'completed_with_issues' }, { status: 'unexpected' }, { issues: [{}] },
    { scannerRuns: [] }, { scannerRuns: [{ status: 'failed' }] }]) {
    assert.notEqual(describeOutcome({ ...complete, ...change }), describeOutcome(complete))
  }
})

test('a fast completion and a still-running scan both resolve by ID', async () => {
  let reads = 0
  let waits = 0
  const get = async id => {
    assert.equal(id, 7)
    if (++reads === 1) throw { code: 'scan_running' }
    return { scanId: 7, status: 'cancelled' }
  }
  const fetch = () => waitForResult(7, get, () => { waits++ }, () => true)
  assert.equal((await fetch()).status, 'cancelled')
  assert.equal((await fetch()).status, 'cancelled')
  assert.equal(waits, 1)
})

test('transport errors and other scans cannot be mistaken for empty reports', async () => {
  const unused = () => assert.fail('unexpected retry')
  await assert.rejects(waitForResult(7, () => ({ scanId: 8 }), unused, () => true))
  await assert.rejects(waitForResult(7, () => { throw new Error('offline') }, unused, () => true))
  assert.equal(await waitForResult(7, unused, unused, () => false), null)
})
