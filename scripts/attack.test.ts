import assert from 'node:assert/strict'
import test from 'node:test'
import { buildAttackTechniques } from './attack'

test('joins MITRE detection strategies and analytics to their ATT&CK technique', () => {
  const techniques = buildAttackTechniques([
    {
      type: 'attack-pattern',
      id: 'attack-pattern-technique',
      name: 'Scheduled Task',
      description: 'Technique overview.',
      external_references: [{ source_name: 'mitre-attack', external_id: 'T1053.005' }],
      kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }],
    },
    {
      type: 'x-mitre-detection-strategy',
      id: 'x-mitre-detection-strategy-example',
      name: 'Suspicious task creation',
      external_references: [{
        source_name: 'mitre-attack',
        external_id: 'DET0441',
        url: 'https://attack.mitre.org/detectionstrategies/DET0441',
      }],
      x_mitre_analytic_refs: ['x-mitre-analytic-example'],
    },
    {
      type: 'x-mitre-analytic',
      id: 'x-mitre-analytic-example',
      name: 'Analytic 1',
      description: 'Review task creation followed by execution.',
      x_mitre_platforms: ['Windows'],
      x_mitre_log_source_references: [{
        name: 'WinEventLog:Security',
        channel: 'EventCode=4698',
      }],
    },
    {
      type: 'relationship',
      relationship_type: 'detects',
      source_ref: 'x-mitre-detection-strategy-example',
      target_ref: 'attack-pattern-technique',
    },
  ])

  assert.equal(techniques.length, 1)
  assert.equal(techniques[0].description, 'Technique overview.')
  assert.equal(techniques[0].detection_strategies?.[0].id, 'DET0441')
  assert.equal(
    techniques[0].detection_strategies?.[0].analytics[0].log_sources[0],
    'WinEventLog:Security (EventCode=4698)'
  )
  assert.equal(techniques[0].detection_strategies?.[0].analytics[0].platforms[0], 'Windows')
})
