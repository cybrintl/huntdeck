import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { parseNewsFeed, type NewsArticle, type NewsSource } from './news'

interface NewsSourceStatus {
  id: string
  name: string
  url: string
  fetched_at: string
  status: 'ok' | 'stale'
  count: number
}

interface NewsSnapshot {
  built_at: string
  items: NewsArticle[]
  sources: NewsSourceStatus[]
  warnings: string[]
}

const sources: NewsSource[] = [
  {
    id: 'offsec-radar',
    name: 'OffSec Radar',
    url: 'https://radar.offseq.com/rss.xml',
  },
  {
    id: 'sans-isc',
    name: 'SANS Internet Storm Center',
    url: 'https://isc.sans.edu/rssfeed.xml',
  },
  {
    id: 'cisco-talos',
    name: 'Cisco Talos',
    url: 'https://blog.talosintelligence.com/rss/',
  },
  {
    id: 'microsoft-security',
    name: 'Microsoft Security Blog',
    url: 'https://www.microsoft.com/en-us/security/blog/feed/',
  },
  {
    id: 'unit42',
    name: 'Palo Alto Networks Unit 42',
    url: 'https://unit42.paloaltonetworks.com/feed/',
  },
  {
    id: 'securelist',
    name: 'Kaspersky Securelist',
    url: 'https://securelist.com/feed/',
  },
]

const snapshotPath = 'public/data/news.json'
const maximumFeedBytes = 2_000_000
const maximumAge = 30 * 24 * 60 * 60 * 1000
const maximumItems = 500

function articleSignature(article: NewsArticle): string {
  return `${article.title.toLocaleLowerCase().replace(/\s+/g, ' ').trim()}|${article.cves.join(',')}`
}

async function readPrevious(): Promise<NewsSnapshot> {
  try {
    const parsed: unknown = JSON.parse(await readFile(snapshotPath, 'utf8'))
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !('items' in parsed) ||
      !Array.isArray(parsed.items) ||
      !('sources' in parsed) ||
      !Array.isArray(parsed.sources)
    ) {
      throw new Error('Existing news snapshot has an invalid format')
    }
    return parsed as NewsSnapshot
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      return { built_at: '', items: [], sources: [], warnings: [] }
    }
    throw error
  }
}

async function fetchFeed(source: NewsSource): Promise<string> {
  const response = await fetch(source.url, {
    headers: { accept: 'application/atom+xml, application/rss+xml, application/xml, text/xml' },
    signal: AbortSignal.timeout(20_000),
  })
  if (!response.ok) {
    throw new Error(`${source.name} returned ${response.status} ${response.statusText}`)
  }
  const xml = await response.text()
  if (Buffer.byteLength(xml, 'utf8') > maximumFeedBytes) {
    throw new Error(`${source.name} feed exceeded the 2 MB size limit`)
  }
  return xml
}

const previous = await readPrevious()
const items = new Map<string, NewsArticle>()
const sourceStatuses: NewsSourceStatus[] = []
const warnings: string[] = []
const seenSignatures = new Set<string>()
const now = Date.now()
const cutoff = now - maximumAge

for (const source of sources) {
  try {
    const articles = parseNewsFeed(await fetchFeed(source), source)
      .filter(article => !article.published_at || Date.parse(article.published_at) >= cutoff)
      .sort((a, b) => (b.published_at ?? '').localeCompare(a.published_at ?? ''))
    let count = 0
    for (const article of articles) {
      const signature = articleSignature(article)
      if (seenSignatures.has(signature)) continue
      seenSignatures.add(signature)
      items.set(article.url, article)
      count += 1
      if (count >= maximumItems) break
    }
    sourceStatuses.push({
      ...source,
      fetched_at: new Date().toISOString(),
      status: 'ok',
      count,
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.warn(`News source unavailable; retaining last-good headlines: ${message}`)
    warnings.push(message)
    const priorItems = previous.items.filter(item => item.source === source.id)
    for (const article of priorItems) {
      const signature = articleSignature(article)
      if (seenSignatures.has(signature)) continue
      seenSignatures.add(signature)
      items.set(article.url, article)
    }
    sourceStatuses.push({
      ...source,
      fetched_at: new Date().toISOString(),
      status: 'stale',
      count: priorItems.length,
    })
  }
}

const snapshot: NewsSnapshot = {
  built_at: new Date().toISOString(),
  items: [...items.values()]
    .filter(article => !article.published_at || Date.parse(article.published_at) >= cutoff)
    .sort((a, b) => (b.published_at ?? '').localeCompare(a.published_at ?? ''))
    .slice(0, maximumItems),
  sources: sourceStatuses,
  warnings,
}

await mkdir('public/data', { recursive: true })
await writeFile(snapshotPath, JSON.stringify(snapshot))
console.log(`News snapshot saved (${snapshot.items.length} headlines; ${warnings.length} source warning(s))`)
