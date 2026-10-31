import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

interface SnapshotHypothesis {
  id: string
  attack_techniques: string[]
  log_sources: string[]
  investigation_steps: string[]
  validation_notes: string
  false_positive_notes: string
  queries: Record<string, { query: string }>
}

const hypotheses: SnapshotHypothesis[] = JSON.parse(
  readFileSync(new URL('../public/data/hunt-hypotheses.json', import.meta.url), 'utf8')
)

test('includes platform-diverse hypotheses with investigation guidance and four query formats', () => {
  assert.ok(hypotheses.length >= 13)

  for (const id of ['hyp-t1110-001', 'hyp-t1098-004', 'hyp-t1078-004']) {
    const hypothesis = hypotheses.find(item => item.id === id)
    assert.ok(hypothesis, `Expected authored hypothesis ${id}`)
    assert.ok(hypothesis.attack_techniques.length > 0)
    assert.ok(hypothesis.log_sources.length > 0)
    assert.ok(hypothesis.investigation_steps.length >= 3)
    assert.ok(hypothesis.validation_notes.length > 0)
    assert.ok(hypothesis.false_positive_notes.length > 0)
    for (const language of ['kql', 'spl', 'elastic', 'sigma']) {
      assert.ok(hypothesis.queries[language]?.query.trim(), `${id} must include ${language}`)
    }
  }
})
