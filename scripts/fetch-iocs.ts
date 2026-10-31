import { mkdir, readFile, writeFile } from 'node:fs/promises'

interface Source {
  id: string
  name: string
  url: string
  type: 'ip' | 'url'
  category: string
  confidence: number
  parse: (text: string) => string[]
}

interface IOCRecord {
  value: string
  type: 'ip' | 'url'
  category: string
  sources: string[]
  confidence?: number
  last_seen?: string
}

interface SourceResult {
  source: string
  fetched_at: string
  status: 'ok' | 'stale'
  count: number
}

const ipv4Pattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/
const sources: Source[] = [
  {
    id: 'openphish',
    name: 'OpenPhish Community Feed',
    url: 'https://openphish.com/feed.txt',
    type: 'url',
    category: 'phishing',
    confidence: 0.8,
    parse: text => text.split(/\r?\n/).map(line => line.trim()).filter(line => /^https?:\/\//i.test(line)),
  },
  {
    id: 'dshield',
    name: 'DShield Recommended Block List',
    url: 'https://feeds.dshield.org/block.txt',
    type: 'ip',
    category: 'abuse',
    confidence: 0.7,
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
    confidence: 0.7,
    parse: text => text.split(/\r?\n/).map(line => line.trim()).filter(line => ipv4Pattern.test(line)),
  },
  {
    id: 'blocklist-de',
    name: 'blocklist.de',
    url: 'https://lists.blocklist.de/lists/all.txt',
    type: 'ip',
    category: 'abuse',
    confidence: 0.7,
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
        confidence: source.confidence,
        last_seen: new Date().toISOString().slice(0, 10),
      }
      if (!record.sources.includes(source.name)) record.sources.push(source.name)
      record.confidence = Math.max(record.confidence ?? 0, source.confidence)
      records.set(key, record)
    }
    statuses.push({
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
      const merged = records.get(key) ?? { ...record, sources: [...record.sources] }
      if (!merged.sources.includes(source.name)) merged.sources.push(source.name)
      records.set(key, merged)
    }
    statuses.push({
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
    (b.confidence ?? 0) - (a.confidence ?? 0) ||
    a.value.localeCompare(b.value)
  )
  .slice(0, 30_000)
await mkdir('public/data', { recursive: true })
await writeFile('public/data/iocs.json', JSON.stringify(snapshot))
await writeFile('public/data/source-status.json', JSON.stringify({ sources: statuses, warnings }, null, 2))
console.log(`IOC snapshot saved (${snapshot.length} unique indicators)`)
