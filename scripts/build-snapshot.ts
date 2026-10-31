import { mkdir, writeFile } from 'node:fs/promises'
const manifest = {
  schema_version: 1,
  built_at: new Date().toISOString(),
  sources: {
    kev: new Date().toISOString(),
    epss: new Date().toISOString()
  }
}
await mkdir('public/data', { recursive: true })
await writeFile('public/data/manifest.json', JSON.stringify(manifest, null, 2))
console.log('✅ Manifest saved')
