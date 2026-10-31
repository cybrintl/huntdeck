import { mkdir, writeFile } from 'node:fs/promises'
import { recordSourceStatus } from './source-status'

const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
const res = await fetch(url)
if (!res.ok) {
  throw new Error(`Failed to fetch KEV data: ${res.status} ${res.statusText}`)
}
const data: unknown = await res.json()
if (
  typeof data !== 'object' ||
  data === null ||
  !('vulnerabilities' in data) ||
  !Array.isArray(data.vulnerabilities) ||
  data.vulnerabilities.length === 0
) {
  throw new Error('KEV feed did not contain any vulnerabilities')
}
await mkdir('public/data', { recursive: true })
await writeFile('public/data/kev.json', JSON.stringify(data, null, 2))
await recordSourceStatus('kev', {
  kind: 'vulnerability',
  source: 'CISA Known Exploited Vulnerabilities',
  url,
  fetched_at: new Date().toISOString(),
  status: 'ok',
  count: data.vulnerabilities.length,
})
console.log(`✅ KEV saved (${data.vulnerabilities.length} vulnerabilities)`)
