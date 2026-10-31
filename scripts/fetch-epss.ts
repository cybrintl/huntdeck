import { mkdir, writeFile } from 'node:fs/promises'
const res = await fetch('https://api.first.epss.debian.org/epss')
if (!res.ok) {
  throw new Error(`Failed to fetch EPSS data: ${res.status} ${res.statusText}`)
}
const csv = await res.text()
const lines = csv.split(/\r?\n/).slice(1)
const data = lines.map(l => {
  const [cve, epss] = l.split(',')
  return { cve, epss: parseFloat(epss) }
}).filter(d => d.cve && Number.isFinite(d.epss))
if (data.length === 0) {
  throw new Error('EPSS feed did not contain any valid records')
}
await mkdir('public/data', { recursive: true })
await writeFile('public/data/epss.json', JSON.stringify(data, null, 2))
console.log('✅ EPSS saved')
