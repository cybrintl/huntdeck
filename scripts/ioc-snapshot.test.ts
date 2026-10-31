import assert from 'node:assert/strict'
import test from 'node:test'
import { selectIocSample } from './ioc-snapshot'

test('limits each IOC source sample to the first 100 unique feed entries', () => {
  const values = Array.from({ length: 150 }, (_, index) => `indicator-${index}`)
  assert.deepEqual(selectIocSample(values), values.slice(0, 100))
})

test('deduplicates indicators before applying the per-source sample limit', () => {
  assert.deepEqual(selectIocSample(['first', 'second', 'first', 'third'], 3), [
    'first',
    'second',
    'third',
  ])
})

test('rejects invalid IOC sample limits', () => {
  assert.throws(() => selectIocSample(['indicator'], 0), /positive integer/)
})
