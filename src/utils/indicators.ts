import type { IOCRecord, IOCType, KevSnapshot } from '../types'

export interface ExtractedIndicator {
  value: string
  type: IOCType
  verdict: string
  sources: string[]
  malware_family?: string
  source_weight?: number
}

export function maskIndicator(value: string, type: IOCType): string {
  if (type === 'ip' || type === 'domain') {
    return value.replace(/\./g, '[.]')
  }
  if (type === 'url') {
    return value
      .replace(/^https?/i, protocol => protocol.toLowerCase() === 'https' ? 'hxxps' : 'hxxp')
      .replace(/\./g, '[.]')
  }
  if (type === 'md5' || type === 'sha1' || type === 'sha256') {
    if (value.length <= 16) return '[masked hash]'
    return `${value.slice(0, 8)}...${value.slice(-4)}`
  }
  return value
}

const patterns: { type: IOCType; regex: RegExp }[] = [
  { type: 'url', regex: /\bhttps?:\/\/[^\s"'<>()[\]{}]+/gi },
  { type: 'sha256', regex: /\b[a-f\d]{64}\b/gi },
  { type: 'sha1', regex: /\b[a-f\d]{40}\b/gi },
  { type: 'md5', regex: /\b[a-f\d]{32}\b/gi },
  { type: 'cve', regex: /\bCVE-\d{4}-\d{4,}\b/gi },
  { type: 'attack', regex: /\bT\d{4}(?:\.\d{3})?\b/gi },
  { type: 'ip', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
  { type: 'domain', regex: /\b(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,63}\b/gi },
]

function isPublicIpv4(value: string): boolean {
  const octets = value.split('.').map(Number)
  if (octets.length !== 4 || octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return false
  }
  const [first, second] = octets
  return first !== undefined && second !== undefined &&
    first !== 0 &&
    first !== 10 &&
    first !== 127 &&
    !(first === 169 && second === 254) &&
    !(first === 172 && second >= 16 && second <= 31) &&
    !(first === 192 && second === 168) &&
    !(first >= 224)
}

function normalize(value: string, type: IOCType): string {
  if (type === 'url') {
    return value.replace(/[.,;:!?]+$/, '')
  }
  return value.toLowerCase()
}

export function extractIndicators(text: string): Array<{ value: string; type: IOCType }> {
  const found = new Map<string, { value: string; type: IOCType }>()
  for (const { type, regex } of patterns) {
    for (const match of text.matchAll(regex)) {
      const rawValue = match[0]
      if (!rawValue) continue
      if (type === 'ip' && !isPublicIpv4(rawValue)) continue
      const value = normalize(rawValue, type)
      const key = `${type}:${value}`
      found.set(key, { value, type })
    }
  }
  return [...found.values()]
}

export function classifyIndicators(
  indicators: Array<{ value: string; type: IOCType }>,
  corpus: IOCRecord[],
  kev: KevSnapshot | undefined,
): ExtractedIndicator[] {
  const knownIocs = new Map(corpus.map(ioc => [`${ioc.type}:${ioc.value.toLowerCase()}`, ioc]))
  const knownCves = new Set((kev?.vulnerabilities ?? []).map(entry => entry.cveID.toLowerCase()))

  return indicators.map(indicator => {
    if (indicator.type === 'cve' && knownCves.has(indicator.value.toLowerCase())) {
      return { ...indicator, verdict: 'Known-exploited CVE', sources: ['CISA KEV'] }
    }
    const record = knownIocs.get(`${indicator.type}:${indicator.value.toLowerCase()}`)
    if (record) {
      return {
        ...indicator,
        verdict: record.category,
        sources: record.sources,
        malware_family: record.malware_family,
        source_weight: record.source_weight,
      }
    }
    if (indicator.type === 'attack') {
      return { ...indicator, verdict: 'ATT&CK technique reference', sources: [] }
    }
    return { ...indicator, verdict: 'Not in snapshot', sources: [] }
  })
}

export function toCsv(indicators: ExtractedIndicator[]): string {
  const escape = (value: string) => `"${value.replace(/"/g, '""')}"`
  return [
    'value,type,verdict,sources,malware_family,source_weight',
    ...indicators.map(indicator => [
      maskIndicator(indicator.value, indicator.type),
      indicator.type,
      indicator.verdict,
      indicator.sources.join('; '),
      indicator.malware_family ?? '',
      indicator.source_weight?.toString() ?? '',
    ].map(escape).join(',')),
  ].join('\r\n')
}

export function toStixBundle(indicators: ExtractedIndicator[]) {
  const now = new Date().toISOString()
  const identityId = `identity--${crypto.randomUUID()}`
  const objects: Record<string, unknown>[] = [{
    type: 'identity',
    spec_version: '2.1',
    id: identityId,
    created: now,
    modified: now,
    name: 'HuntDeck local triage',
    identity_class: 'organization',
  }]
  for (const indicator of indicators) {
    const literal = indicator.value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")
    let pattern: string | undefined
    if (indicator.type === 'ip') pattern = `[ipv4-addr:value = '${literal}']`
    if (indicator.type === 'domain') pattern = `[domain-name:value = '${literal}']`
    if (indicator.type === 'url') pattern = `[url:value = '${literal}']`
    if (indicator.type === 'md5') pattern = `[file:hashes.'MD5' = '${literal}']`
    if (indicator.type === 'sha1') pattern = `[file:hashes.'SHA-1' = '${literal}']`
    if (indicator.type === 'sha256') pattern = `[file:hashes.'SHA-256' = '${literal}']`
    if (pattern && indicator.verdict !== 'Not in snapshot') {
      objects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${crypto.randomUUID()}`,
        created: now,
        modified: now,
        created_by_ref: identityId,
        name: `${indicator.verdict}: ${indicator.value}`,
        pattern_type: 'stix',
        pattern,
        valid_from: now,
        labels: [indicator.verdict.toLowerCase().replace(/ /g, '-')],
      })
    } else {
      objects.push({
        type: 'note',
        spec_version: '2.1',
        id: `note--${crypto.randomUUID()}`,
        created: now,
        modified: now,
        created_by_ref: identityId,
        abstract: `${indicator.type.toUpperCase()} reference`,
        content: `${indicator.value} — ${indicator.verdict}${indicator.sources.length ? ` (${indicator.sources.join(', ')})` : ''}`,
        object_refs: [identityId],
        note_types: ['other'],
      })
    }
  }
  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID()}`,
    objects,
  }
}
