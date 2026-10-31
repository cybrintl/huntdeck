import { mkdir, writeFile } from 'node:fs/promises'
import { buildAttackTechniques } from './attack'
import { recordSourceStatus } from './source-status'

const url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
const response = await fetch(url)
if (!response.ok) {
  throw new Error(`Failed to fetch MITRE ATT&CK STIX: ${response.status} ${response.statusText}`)
}

const bundle: unknown = await response.json()
if (
  typeof bundle !== 'object' ||
  bundle === null ||
  !('objects' in bundle) ||
  !Array.isArray(bundle.objects)
) {
  throw new Error('MITRE ATT&CK response is not a valid STIX bundle')
}

const techniques = buildAttackTechniques(bundle.objects)

if (techniques.length < 500) {
  throw new Error(`ATT&CK dataset appears incomplete: received ${techniques.length} techniques`)
}

await mkdir('public/data', { recursive: true })
await writeFile('public/data/techniques.json', JSON.stringify(techniques))
await recordSourceStatus('attack', {
  kind: 'attack',
  source: 'MITRE ATT&CK Enterprise',
  url: 'https://github.com/mitre/cti/tree/master/enterprise-attack',
  fetched_at: new Date().toISOString(),
  status: 'ok',
  count: techniques.length,
})
console.log(`ATT&CK saved (${techniques.length} techniques)`)
