import assert from 'node:assert/strict'
import { performance } from 'node:perf_hooks'
import test from 'node:test'
import type { KevSnapshot } from '../types'
import { classifyIndicators, extractIndicators, toCsv, toStixBundle } from './indicators'

test('extracts unique public indicators and excludes private IPv4 addresses', () => {
  const found = extractIndicators([
    'source=8.8.8.8 src=10.1.2.3 dst=192.168.1.10',
    'https://evil.example/path?x=1 CVE-2026-12345 T1110.003',
    'sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'repeat=8.8.8.8',
  ].join('\n'))

  assert.deepEqual(found.map(item => item.type), ['url', 'sha256', 'cve', 'attack', 'ip', 'domain'])
  assert.equal(found.filter(item => item.value === '8.8.8.8').length, 1)
  assert.equal(found.some(item => item.value === '10.1.2.3'), false)
  assert.equal(found.some(item => item.value === '192.168.1.10'), false)
})

test('labels known KEV and local IOC matches without treating unknown as clean', () => {
  const kev: KevSnapshot = { vulnerabilities: [{ cveID: 'CVE-2026-12345' }] }
  const results = classifyIndicators(
    [
      { type: 'cve', value: 'CVE-2026-12345' },
      { type: 'ip', value: '8.8.8.8' },
      { type: 'domain', value: 'unknown.example' },
    ],
    [{
      value: '8.8.8.8',
      type: 'ip',
      category: 'C2',
      sources: ['Test feed'],
      malware_family: 'Test family',
    }],
    kev,
  )

  assert.equal(results[0]?.verdict, 'Known-exploited CVE')
  assert.equal(results[1]?.verdict, 'C2')
  assert.equal(results[1]?.malware_family, 'Test family')
  assert.equal(results[2]?.verdict, 'Not in snapshot')
})

test('extracts indicators from five thousand log lines within the target budget', () => {
  const line = 'src=8.8.8.8 host=bad.example url=https://bad.example/x CVE-2026-12345 T1110.003 hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  const input = Array.from({ length: 5000 }, (_, index) => `${index} ${line}`).join('\n')
  const started = performance.now()
  const indicators = extractIndicators(input)
  const elapsed = performance.now() - started

  assert.equal(indicators.length, 6)
  assert.ok(elapsed < 2000, `5k log lines took ${elapsed.toFixed(1)} ms`)
})

test('exports CSV-escaped values and a STIX 2.1 bundle', () => {
  const indicators = classifyIndicators(
    [{ type: 'url', value: "https://example.test/a'b" }, { type: 'cve', value: 'CVE-2026-12345' }],
    [{
      value: "https://example.test/a'b",
      type: 'url',
      category: 'Phishing',
      sources: ['Feed "test"'],
    }],
    undefined,
  )
  const csv = toCsv(indicators)
  const stix = toStixBundle(indicators)

  assert.match(csv, /""/)
  assert.equal(stix.type, 'bundle')
  assert.ok(stix.objects.some(object => object.type === 'indicator'))
  assert.ok(stix.objects.some(object => object.type === 'note'))
  assert.ok(stix.objects.every(object => object.spec_version === '2.1'))
})
