import assert from 'node:assert/strict'
import test from 'node:test'
import type { HuntHypothesis } from '../types'
import { findRelatedHunts } from './hunt-links'

const hypotheses: HuntHypothesis[] = [
  {
    id: 'hyp-one',
    title: 'First hunt',
    attack_techniques: ['T1059.001', 'T1059.003'],
    queries: {},
  },
  {
    id: 'hyp-two',
    title: 'Second hunt',
    attack_techniques: ['T1003.001'],
    queries: {},
  },
  {
    id: 'hyp-no-technique',
    title: 'Unmapped hunt',
    queries: {},
  },
]

test('links reports to exact ATT&CK matches and returns each hypothesis once', () => {
  const related = findRelatedHunts(['T1059.001', 'T1059.003', 'T1003.001'], hypotheses)
  assert.deepEqual(
    related.map(({ hypothesis, technique }) => [hypothesis.id, technique]),
    [
      ['hyp-one', 'T1059.001'],
      ['hyp-two', 'T1003.001'],
    ],
  )
})

test('does not infer matches from partial or absent technique references', () => {
  assert.deepEqual(findRelatedHunts(['T1059'], hypotheses), [])
  assert.deepEqual(findRelatedHunts([], hypotheses), [])
})
