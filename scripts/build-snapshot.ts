import { mkdir, readFile, writeFile } from 'node:fs/promises'

const kev: unknown = JSON.parse(await readFile('public/data/kev.json', 'utf8'))
const epss: unknown = JSON.parse(await readFile('public/data/epss.json', 'utf8'))
const techniques: unknown = JSON.parse(await readFile('public/data/techniques.json', 'utf8'))
const hypotheses: unknown = JSON.parse(await readFile('public/data/hunt-hypotheses.json', 'utf8'))
const iocs: unknown = JSON.parse(await readFile('public/data/iocs.json', 'utf8'))
const rules: unknown = JSON.parse(await readFile('public/data/rules.json', 'utf8'))
const news: unknown = JSON.parse(await readFile('public/data/news.json', 'utf8'))
const sourceStatus: unknown = JSON.parse(await readFile('public/data/source-status.json', 'utf8'))
if (
  typeof kev !== 'object' ||
  kev === null ||
  !('vulnerabilities' in kev) ||
  !Array.isArray(kev.vulnerabilities) ||
  !Array.isArray(epss) ||
  !Array.isArray(techniques) ||
  !Array.isArray(hypotheses) ||
  !Array.isArray(iocs) ||
  !Array.isArray(rules) ||
  typeof news !== 'object' ||
  news === null ||
  !('items' in news) ||
  !Array.isArray(news.items) ||
  !('built_at' in news) ||
  typeof news.built_at !== 'string' ||
  !('sources' in news) ||
  !Array.isArray(news.sources) ||
  !('warnings' in news) ||
  !Array.isArray(news.warnings) ||
  typeof sourceStatus !== 'object' ||
  sourceStatus === null ||
  !('sources' in sourceStatus) ||
  !('warnings' in sourceStatus) ||
  typeof sourceStatus.sources !== 'object' ||
  sourceStatus.sources === null ||
  Array.isArray(sourceStatus.sources) ||
  !Array.isArray(sourceStatus.warnings)
) {
  throw new Error('Cannot build manifest: one or more snapshots have an invalid format')
}

const builtAt = new Date().toISOString()
const manifest = {
  schema_version: 1,
  built_at: builtAt,
  counts: {
    kev: kev.vulnerabilities.length,
    epss: epss.length,
    techniques: techniques.length,
    hypotheses: hypotheses.length,
    iocs: iocs.length,
    rules: rules.length,
    news: news.items.length,
  },
  sources: {
    ...sourceStatus.sources,
    news: {
      kind: 'news',
      source: 'Threat intelligence and security news RSS feeds',
      fetched_at: news.built_at,
      status: news.sources.length > 0 && news.sources.every(source =>
        typeof source === 'object' &&
        source !== null &&
        'status' in source &&
        source.status === 'ok'
      ) ? 'ok' : 'stale',
      count: news.items.length,
    },
  },
  warnings: [...sourceStatus.warnings, ...news.warnings],
}
await mkdir('public/data', { recursive: true })
await writeFile('public/data/manifest.json', JSON.stringify(manifest, null, 2))
console.log('✅ Manifest saved')
