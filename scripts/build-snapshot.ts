import { mkdir, readFile, writeFile } from 'node:fs/promises'

const kev: unknown = JSON.parse(await readFile('public/data/kev.json', 'utf8'))
const epss: unknown = JSON.parse(await readFile('public/data/epss.json', 'utf8'))
if (
  typeof kev !== 'object' ||
  kev === null ||
  !('vulnerabilities' in kev) ||
  !Array.isArray(kev.vulnerabilities) ||
  !Array.isArray(epss)
) {
  throw new Error('Cannot build manifest: KEV or EPSS data has an invalid format')
}

const manifest = {
  schema_version: 1,
  built_at: new Date().toISOString(),
  counts: {
    kev: kev.vulnerabilities.length,
    epss: epss.length
  },
  sources: {
    kev: new Date().toISOString(),
    epss: new Date().toISOString()
  }
}
await mkdir('public/data', { recursive: true })
await writeFile('public/data/manifest.json', JSON.stringify(manifest, null, 2))
console.log('✅ Manifest saved')
