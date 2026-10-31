import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { gunzipSync } from 'node:zlib'
import { recordSourceStatus } from './source-status'

const url = 'https://epss.cyentia.com/epss_scores-current.csv.gz'
const res = await fetch(url)
if (!res.ok) {
  throw new Error(`Failed to fetch EPSS data: ${res.status} ${res.statusText}`)
}

const compressed = Buffer.from(await res.arrayBuffer())
const csv = gunzipSync(compressed).toString('utf8')
const lines = csv.split(/\r?\n/)
const headerIndex = lines.findIndex(line => line.startsWith('cve,'))
if (headerIndex === -1) {
  throw new Error('EPSS feed did not contain a CSV header')
}

const headers = lines[headerIndex].split(',')
const cveIndex = headers.indexOf('cve')
const epssIndex = headers.indexOf('epss')
const percentileIndex = headers.indexOf('percentile')
if (cveIndex === -1 || epssIndex === -1) {
  throw new Error('EPSS feed is missing required CVE or score columns')
}

const allScores = lines.slice(headerIndex + 1).flatMap(line => {
  if (!line) return []
  const columns = line.split(',')
  const cve = columns[cveIndex]
  const epss = Number(columns[epssIndex])
  const percentile = percentileIndex === -1 ? undefined : Number(columns[percentileIndex])
  if (!cve || !Number.isFinite(epss)) return []
  return [{
    cve,
    epss,
    ...(Number.isFinite(percentile) ? { percentile } : {})
  }]
})
if (allScores.length === 0) {
  throw new Error('EPSS feed did not contain any valid records')
}

const kev: unknown = JSON.parse(await readFile('public/data/kev.json', 'utf8'))
if (
  typeof kev !== 'object' ||
  kev === null ||
  !('vulnerabilities' in kev) ||
  !Array.isArray(kev.vulnerabilities)
) {
  throw new Error('Cannot filter EPSS data: KEV snapshot has an invalid format')
}
const kevCves = new Set(
  kev.vulnerabilities.flatMap(vulnerability =>
    typeof vulnerability === 'object' &&
    vulnerability !== null &&
    'cveID' in vulnerability &&
    typeof vulnerability.cveID === 'string'
      ? [vulnerability.cveID]
      : []
  )
)
const topScores = [...allScores]
  .sort((a, b) => b.epss - a.epss)
  .slice(0, 5000)
const selectedCves = new Set([...kevCves, ...topScores.map(score => score.cve)])
const data = allScores.filter(score => selectedCves.has(score.cve))

await mkdir('public/data', { recursive: true })
await writeFile('public/data/epss.json', JSON.stringify(data))
await recordSourceStatus('epss', {
  kind: 'vulnerability',
  source: 'FIRST EPSS',
  url,
  fetched_at: new Date().toISOString(),
  status: 'ok',
  count: data.length,
})
console.log(`EPSS saved (${data.length} scores: ${kevCves.size} KEV + top 5,000 EPSS)`)
