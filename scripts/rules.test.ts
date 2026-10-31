import assert from 'node:assert/strict'
import test from 'node:test'
import { parseDetectionRule, ruleSources } from './rules'

const sigma = ruleSources.find(source => source.id === 'sigma')
const sentinel = ruleSources.find(source => source.id === 'microsoft-sentinel')
const splunk = ruleSources.find(source => source.id === 'splunk-security-content')

test('parses Sigma technique tags and log sources without copying rule content', () => {
  assert.ok(sigma)
  const rule = parseDetectionRule(sigma, 'rules/windows/process_creation/test.yml', `
title: Suspicious Process
id: 1234
status: test
level: high
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
`)

  assert.equal(rule?.language, 'Sigma')
  assert.equal(rule?.source_id, 'sigma')
  assert.deepEqual(rule?.attack_techniques, ['T1059.001'])
  assert.equal(rule?.log_source, 'windows / process_creation')
  assert.equal(rule?.query_text, undefined)
})

test('parses Microsoft Sentinel KQL and relevant ATT&CK metadata', () => {
  assert.ok(sentinel)
  const rule = parseDetectionRule(sentinel, 'Hunting Queries/Process/test.yaml', `
id: 1234
name: Certutil network download
description: Hunt for certutil downloading files
tactics:
  - CommandAndControl
relevantTechniques:
  - T1105
query: |
  DeviceProcessEvents
  | where ProcessCommandLine has "certutil"
`)

  assert.equal(rule?.language, 'KQL')
  assert.equal(rule?.license, 'MIT')
  assert.deepEqual(rule?.attack_techniques, ['T1105'])
  assert.match(rule?.query_text ?? '', /DeviceProcessEvents/)
})

test('parses Splunk SPL, data sources, techniques, and false-positive context', () => {
  assert.ok(splunk)
  const rule = parseDetectionRule(splunk, 'detections/endpoint/test.yml', `
name: LSASS memory access
id: 1234
description: Detect suspicious access to LSASS
modification_date: '2026-10-01'
data_source:
  - Sysmon EventID 10
search: |-
  \`sysmon\` EventCode=10 TargetImage=*lsass.exe
tags:
  mitre_attack_id:
    - T1003.001
known_false_positives: Approved endpoint security tools
`)

  assert.equal(rule?.language, 'SPL')
  assert.equal(rule?.license, 'Apache-2.0')
  assert.deepEqual(rule?.attack_techniques, ['T1003.001'])
  assert.equal(rule?.data_sources[0], 'Sysmon EventID 10')
  assert.equal(rule?.known_false_positives, 'Approved endpoint security tools')
  assert.equal(rule?.updated_at, '2026-10-01')
})
