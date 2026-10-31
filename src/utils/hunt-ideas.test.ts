import assert from 'node:assert/strict'
import test from 'node:test'
import {
  classifyMentionedContext,
  extractReportIndicators,
  suggestionForReport,
} from './hunt-ideas'

test('only returns industry and geography labels explicitly mentioned in the report text', () => {
  assert.deepEqual(classifyMentionedContext(
    'A healthcare provider in the United States reported an incident.'
  ), {
    industries: ['Healthcare'],
    geographies: ['United States'],
  })
  assert.deepEqual(classifyMentionedContext('A generic vulnerability affects many users.'), {
    industries: [],
    geographies: [],
  })
})

test('extracts only observables literally present in the report title and summary', () => {
  assert.deepEqual(extractReportIndicators(
    'CVE-2026-12345 used by 203.0.113.15',
    'Callback to https://malicious.example/path and hash 44d88612fea8a8f36de82e1278abb02f'
  ), [
    { value: 'https://malicious.example/path', type: 'url' },
    { value: '44d88612fea8a8f36de82e1278abb02f', type: 'md5' },
    { value: '203.0.113.15', type: 'ip' },
    { value: 'malicious.example', type: 'domain' },
  ])
})

test('builds a report-grounded suggestion without inventing CVEs or ATT&CK mappings', () => {
  assert.match(suggestionForReport({
    title: 'Reported attack',
    cves: ['CVE-2026-12345'],
    techniques: [],
  }), /CVE-2026-12345/)
  assert.match(suggestionForReport({
    title: 'Reported attack',
    cves: [],
    techniques: [{ id: 'T1059.001', name: 'PowerShell' }],
  }), /T1059\.001 \(PowerShell\)/)
  assert.match(suggestionForReport({
    title: 'Reported attack',
    cves: [],
    techniques: [],
  }), /linked report/)
})
