import { mkdir, readFile, writeFile } from 'node:fs/promises'

interface Source {
  id: string
  name: string
  url: string
  type: 'ip' | 'url'
  category: string
  sourceWeight: number
  parse: (text: string) => string[]
}

interface IOCRecord {
  value: string
  type: 'ip' | 'url'
  category: string
  sources: string[]
  source_weight?: number
  last_seen?: string
}

interface SourceResult {
  kind: 'ioc'
  id: string
  url: string
  source: string
  fetched_at: string
  status: 'ok' | 'stale'
  count: number
}

interface SourceStatusDocument {
  sources: Record<string, SourceResult | { kind?: 'ioc' | 'detection'; [key: string]: unknown } | string>
  warnings: string[]
}

const ipv4Pattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/
const sources: Source[] = [
  {
    id: 'openphish',
    name: 'OpenPhish Community Feed',
    url: 'https://openphish.com/feed.txt',
    type: 'url',
    category: 'phishing',
    sourceWeight: 0.8,
    parse: text => text.split(/\r?\n/).map(line => line.trim()).filter(line => /^https?:\/\//i.test(line)),
  },
  {
    id: 'dshield',
    name: 'DShield Recommended Block List',
    url: 'https://feeds.dshield.org/block.txt',
    type: 'ip',
    category: 'abuse',
    sourceWeight: 0.7,
    parse: text => text.split(/\r?\n/).flatMap(line => {
      const match = line.match(ipv4Pattern)?.[0]
      return match ? [match] : []
    }),
  },
  {
    id: 'cins',
    name: 'CINS Army',
    url: 'https://cinsscore.com/list/ci-badguys.txt',
    type: 'ip',
    category: 'abuse',
    sourceWeight: 0.7,
    parse: text => text.split(/\r?\n/).map(line => line.trim()).filter(line => ipv4Pattern.test(line)),
  },
  {
    id: 'blocklist-de',
    name: 'blocklist.de',
    url: 'https://lists.blocklist.de/lists/all.txt',
    type: 'ip',
    category: 'abuse',
    sourceWeight: 0.7,
    parse: text => text.split(/\r?\n/).map(line => line.trim()).filter(line => ipv4Pattern.test(line)),
  },
]

function isPublicIpv4(value: string): boolean {
  const octets = value.split('.').map(Number)
  if (octets.length !== 4 || octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return false
  }
  const first = octets[0] ?? 0
  const second = octets[1] ?? 0
  return first !== 0 &&
    first !== 10 &&
    first !== 127 &&
    !(first === 169 && second === 254) &&
    !(first === 172 && second >= 16 && second <= 31) &&
    !(first === 192 && second === 168) &&
    first < 224
}

async function fetchText(source: Source): Promise<string> {
  let lastError: Error | undefined
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const response = await fetch(source.url, { signal: AbortSignal.timeout(30_000) })
      if (response.ok) return response.text()
      const retryable = response.status === 429 || response.status >= 500
      if (!retryable || attempt === 2) {
        throw new Error(`${source.name} returned ${response.status} ${response.statusText}`)
      }
      const retryAfter = Number(response.headers.get('retry-after'))
      const delay = Number.isFinite(retryAfter) && retryAfter > 0
        ? Math.min(retryAfter * 1000, 30_000)
        : 1000 * (attempt + 1)
      await new Promise(resolve => setTimeout(resolve, delay))
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))
      if (attempt === 2) break
      await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)))
    }
  }
  throw lastError ?? new Error(`${source.name} fetch failed`)
}

async function readPrevious(): Promise<IOCRecord[]> {
  try {
    const value: unknown = JSON.parse(await readFile('public/data/iocs.json', 'utf8'))
    if (Array.isArray(value)) return value as IOCRecord[]
    throw new Error('Existing IOC snapshot is not an array')
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return []
    throw error
  }
}

function sourceIdForName(name: string): string {
  const source = sources.find(item => item.name === name)
  return source?.id ?? name.toLocaleLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
}

async function readSourceStatus(): Promise<SourceStatusDocument> {
  try {
    const value: unknown = JSON.parse(await readFile('public/data/source-status.json', 'utf8'))
    if (
      typeof value !== 'object' ||
      value === null ||
      !('sources' in value) ||
      !('warnings' in value) ||
      !Array.isArray(value.warnings) ||
      typeof value.sources !== 'object' ||
      value.sources === null
    ) {
      throw new Error('Existing source status snapshot has an invalid format')
    }

    const normalizedSources: Record<string, SourceResult | string> = {}
    if (Array.isArray(value.sources)) {
      for (const entry of value.sources) {
        if (typeof entry !== 'object' || entry === null || !('source' in entry) ||
          typeof entry.source !== 'string' || !('fetched_at' in entry) ||
          typeof entry.fetched_at !== 'string' || !('status' in entry) ||
          (entry.status !== 'ok' && entry.status !== 'stale') || !('count' in entry) ||
          typeof entry.count !== 'number') {
          throw new Error('Existing source status snapshot contains an invalid entry')
        }
        normalizedSources[sourceIdForName(entry.source)] = {
          kind: 'ioc',
          id: sourceIdForName(entry.source),
          url: '',
          source: entry.source,
          fetched_at: entry.fetched_at,
          status: entry.status,
          count: entry.count,
        }
      }
    } else {
      Object.assign(normalizedSources, value.sources)
    }
    return {
      sources: normalizedSources,
      warnings: value.warnings.filter(item => typeof item === 'string'),
    }
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      return { sources: {}, warnings: [] }
    }
    throw error
  }
}

const previous = await readPrevious()
const records = new Map<string, IOCRecord>()
const statuses: SourceResult[] = []
const warnings: string[] = []

for (const source of sources) {
  try {
    const text = await fetchText(source)
    const values = source.parse(text)
    const accepted = values.filter(value => source.type !== 'ip' || isPublicIpv4(value))
    if (accepted.length === 0) throw new Error(`${source.name} contained no valid indicators`)
    for (const rawValue of accepted) {
      const value = source.type === 'url' ? rawValue.replace(/[.,;:!?]+$/, '') : rawValue
      const key = `${source.type}:${value.toLowerCase()}`
      const record = records.get(key) ?? {
        value,
        type: source.type,
        category: source.category,
        sources: [],
        source_weight: source.sourceWeight,
      }
      if (!record.sources.includes(source.name)) record.sources.push(source.name)
      record.source_weight = Math.max(record.source_weight ?? 0, source.sourceWeight)
      records.set(key, record)
    }
    statuses.push({
      kind: 'ioc',
      id: source.id,
      url: source.url,
      source: source.name,
      fetched_at: new Date().toISOString(),
      status: 'ok',
      count: accepted.length,
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.warn(`Optional IOC source unavailable; retaining last-good records: ${message}`)
    warnings.push(message)
    const priorRecords = previous.filter(record => record.sources.includes(source.name))
    for (const record of priorRecords) {
      const key = `${record.type}:${record.value.toLowerCase()}`
      const { last_seen: _lastSeen, ...retained } = record
      const merged = records.get(key) ?? { ...retained, sources: [...record.sources] }
      if (!merged.sources.includes(source.name)) merged.sources.push(source.name)
      records.set(key, merged)
    }
    statuses.push({
      kind: 'ioc',
      id: source.id,
      url: source.url,
      source: source.name,
      fetched_at: new Date().toISOString(),
      status: 'stale',
      count: priorRecords.length,
    })
  }
}

const categoryOrder: Record<string, number> = { c2: 0, phishing: 1, abuse: 2 }
const snapshot = [...records.values()]
  .sort((a, b) =>
    (b.sources.length - a.sources.length) ||
    ((categoryOrder[a.category] ?? 9) - (categoryOrder[b.category] ?? 9)) ||
    (b.source_weight ?? 0) - (a.source_weight ?? 0) ||
    a.value.localeCompare(b.value)
  )
  .slice(0, 30_000)
await mkdir('public/data', { recursive: true })
await writeFile('public/data/iocs.json', JSON.stringify(snapshot))
const sourceStatus = await readSourceStatus()
for (const status of statuses) sourceStatus.sources[status.id] = status
sourceStatus.warnings = [
  ...sourceStatus.warnings.filter(warning => !warning.startsWith('ioc:')),
  ...warnings.map(warning => `ioc: ${warning}`),
]
await writeFile('public/data/source-status.json', JSON.stringify(sourceStatus, null, 2))
console.log(`IOC snapshot saved (${snapshot.length} unique indicators)`)
