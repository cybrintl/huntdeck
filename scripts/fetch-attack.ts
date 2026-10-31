import { mkdir, writeFile } from 'node:fs/promises'

interface StixObject {
  type?: string
  revoked?: boolean
  x_mitre_deprecated?: boolean
  name?: string
  description?: string
  x_mitre_data_sources?: string[]
  kill_chain_phases?: Array<{ kill_chain_name?: string; phase_name?: string }>
  external_references?: Array<{ source_name?: string; external_id?: string }>
}

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

const techniques = bundle.objects.flatMap((object: StixObject) => {
  if (
    object.type !== 'attack-pattern' ||
    object.revoked ||
    object.x_mitre_deprecated ||
    !object.name
  ) {
    return []
  }
  const id = object.external_references?.find(reference => reference.source_name === 'mitre-attack')?.external_id
  if (!id || !/^T\d{4}(?:\.\d{3})?$/.test(id)) return []
  const tactics = [...new Set(
    (object.kill_chain_phases ?? [])
      .filter(phase => phase.kill_chain_name === 'mitre-attack')
      .flatMap(phase => phase.phase_name ? [phase.phase_name] : [])
  )]
  return [{
    id,
    name: object.name,
    tactics,
    data_sources: object.x_mitre_data_sources ?? [],
    detection: object.description ?? '',
  }]
})

if (techniques.length < 500) {
  throw new Error(`ATT&CK dataset appears incomplete: received ${techniques.length} techniques`)
}

await mkdir('public/data', { recursive: true })
await writeFile('public/data/techniques.json', JSON.stringify(techniques))
console.log(`ATT&CK saved (${techniques.length} techniques)`)
