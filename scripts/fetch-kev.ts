import { mkdir, writeFile } from 'node:fs/promises'
const URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
const res = await fetch(URL)
if (!res.ok) {
  throw new Error(`Failed to fetch KEV data: ${res.status} ${res.statusText}`)
}
const data: unknown = await res.json()
await mkdir('public/data', { recursive: true })
await writeFile('public/data/kev.json', JSON.stringify(data, null, 2))
console.log('✅ KEV saved')
