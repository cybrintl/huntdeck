import { XMLParser, XMLValidator } from 'fast-xml-parser'

export interface NewsSource {
  id: string
  name: string
  url: string
}

export interface NewsArticle {
  url: string
  title: string
  source: string
  source_name: string
  published_at?: string
  cves: string[]
  techniques: string[]
  topics: string[]
}

const parser = new XMLParser({
  ignoreAttributes: false,
  removeNSPrefix: true,
  cdataPropName: '__cdata',
  textNodeName: '#text',
  parseTagValue: false,
  trimValues: true,
  processEntities: false,
})

const topicRules: [string, RegExp][] = [
  ['Exploitation', /\b(?:actively exploited|exploit(?:ation|ed|ing)?|zero.day|in the wild)\b/i],
  ['Vulnerability', /\b(?:CVE-\d{4}-\d{4,}|vulnerabilit(?:y|ies)|security flaw)\b/i],
  ['Malware', /\b(?:malware|ransomware|backdoor|trojan|infostealer|botnet|rootkit|stealer)\b/i],
  ['Threat activity', /\b(?:threat actor|APT\d*|espionage|intrusion|campaign|attack|phishing|credential|breach)\b/i],
  ['Detection and response', /\b(?:detection|threat hunting|incident response|defen[cs]e)\b/i],
  ['Cloud and identity', /\b(?:cloud|identity|Azure|AWS|GCP)\b/i],
]

type XmlRecord = Record<string, unknown>

function record(value: unknown): XmlRecord | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as XmlRecord
    : undefined
}

function values(value: unknown): unknown[] {
  if (value === undefined || value === null) return []
  return Array.isArray(value) ? value : [value]
}

function text(value: unknown): string {
  if (typeof value === 'string' || typeof value === 'number') return String(value)
  const item = record(value)
  if (!item) return ''
  return text(item.__cdata ?? item['#text'] ?? item['@_term'] ?? '')
}

function decodeXmlText(value: string): string {
  return value
    .replace(/&#(\d+);/g, (_match, code: string) => decodeCodePoint(code, 10))
    .replace(/&#x([0-9a-f]+);/gi, (_match, code: string) => decodeCodePoint(code, 16))
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
}

function decodeCodePoint(value: string, radix: number): string {
  const codePoint = Number.parseInt(value, radix)
  return codePoint <= 0x10ffff && !(codePoint >= 0xd800 && codePoint <= 0xdfff)
    ? String.fromCodePoint(codePoint)
    : ''
}

function cleanTitle(value: unknown): string {
  return decodeXmlText(text(value))
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 240)
}

function getLink(value: unknown): string {
  for (const candidate of values(value)) {
    const item = record(candidate)
    if (!item) {
      const link = text(candidate).trim()
      if (link) return link
      continue
    }
    const rel = text(item['@_rel'])
    if (rel && rel !== 'alternate') continue
    const link = text(item['@_href'] ?? item['#text'])
    if (link) return link.trim()
  }
  return ''
}

function getCategories(value: unknown): string[] {
  return values(value)
    .map(item => decodeXmlText(text(item)).trim())
    .filter(Boolean)
}

function parseDate(value: unknown): string | undefined {
  const raw = text(value).trim()
  if (!raw) return undefined
  const timestamp = Date.parse(raw)
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : undefined
}

function secureArticleUrl(rawUrl: string): string | undefined {
  try {
    const url = new URL(rawUrl)
    if (url.protocol !== 'https:' || url.username || url.password) return undefined
    return url.href
  } catch {
    return undefined
  }
}

function parseEntry(entry: unknown, source: NewsSource): NewsArticle | undefined {
  const item = record(entry)
  if (!item) return undefined
  const title = cleanTitle(item.title)
  const url = secureArticleUrl(getLink(item.link))
  if (!title || !url) return undefined

  const categories = getCategories(item.category)
  const evidence = `${title} ${categories.join(' ')}`
  const cves = [...new Set(evidence.match(/\bCVE-\d{4}-\d{4,}\b/gi) ?? [])]
    .map(cve => cve.toUpperCase())
  const techniques = [...new Set(evidence.match(/\bT\d{4}(?:\.\d{3})?\b/gi) ?? [])]
    .map(technique => technique.toUpperCase())
  const topics = topicRules
    .filter(([, pattern]) => pattern.test(evidence))
    .map(([topic]) => topic)
  if (cves.length === 0 && techniques.length === 0 && topics.length === 0) return undefined

  return {
    url,
    title,
    source: source.id,
    source_name: source.name,
    published_at: parseDate(item.pubDate ?? item.published ?? item.updated ?? item.date),
    cves,
    techniques,
    topics,
  }
}

export function parseNewsFeed(xml: string, source: NewsSource): NewsArticle[] {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) {
    throw new Error(`${source.name} feed contains a forbidden XML declaration`)
  }
  const validation = XMLValidator.validate(xml)
  if (validation !== true) {
    throw new Error(`${source.name} feed is invalid XML: ${validation.err.msg}`)
  }

  const parsed = record(parser.parse(xml))
  if (!parsed) throw new Error(`${source.name} feed has no XML root`)
  const rss = record(parsed.rss)
  const channel = record(rss?.channel ?? parsed.channel)
  const atom = record(parsed.feed)
  const rdf = record(parsed.RDF)
  const entries = channel?.item ?? atom?.entry ?? rdf?.item
  const articles = values(entries)
    .map(entry => parseEntry(entry, source))
    .filter((article): article is NewsArticle => article !== undefined)

  if (articles.length === 0) {
    throw new Error(`${source.name} feed contains no usable article links`)
  }
  return articles
}
