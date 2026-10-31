import { mkdir, writeFile } from 'node:fs/promises'
import { gunzipSync } from 'node:zlib'

const res = await fetch('https://epss.cyentia.com/epss_scores-current.csv.gz')
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

const data = lines.slice(headerIndex + 1).flatMap(line => {
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
if (data.length === 0) {
  throw new Error('EPSS feed did not contain any valid records')
}

await mkdir('public/data', { recursive: true })
await writeFile('public/data/epss.json', JSON.stringify(data))
console.log(`EPSS saved (${data.length} scores)`)
