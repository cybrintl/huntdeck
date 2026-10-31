import { readdir, readFile, stat } from 'node:fs/promises'
import path from 'node:path'

const directory = path.resolve('public/data')
const required = [
  'kev.json',
  'epss.json',
  'techniques.json',
  'hunt-hypotheses.json',
  'iocs.json',
  'rules.json',
  'news.json',
  'source-status.json',
  'manifest.json',
]
const available = await readdir(directory)
for (const file of required) {
  if (!available.includes(file)) {
    throw new Error(`Required snapshot is missing: ${file}`)
  }
}

const parsed = new Map<string, unknown>()
for (const file of required) {
  const contents = await readFile(path.join(directory, file))
  const fileStat = await stat(path.join(directory, file))
  if (fileStat.size > 5_000_000) {
    throw new Error(`${file} is larger than the 5 MB per-file budget`)
  }
  try {
    parsed.set(file, JSON.parse(contents.toString('utf8')))
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(`${file} is not valid JSON: ${detail}`)
  }
}

const totalBytes = await Promise.all(available
  .filter(file => file.endsWith('.json'))
  .map(async file => (await stat(path.join(directory, file))).size))
  .then(sizes => sizes.reduce((sum, size) => sum + size, 0))
if (totalBytes > 40_000_000) {
  throw new Error(`Snapshot directory is larger than the 40 MB budget (${totalBytes} bytes)`)
}

const kev = parsed.get('kev.json')
if (typeof kev !== 'object' || kev === null || !('vulnerabilities' in kev) || !Array.isArray(kev.vulnerabilities)) {
  throw new Error('kev.json must contain a vulnerabilities array')
}
for (const file of required.filter(name => !['kev.json', 'manifest.json', 'source-status.json'].includes(name))) {
  if (file !== 'news.json' && !Array.isArray(parsed.get(file))) {
    throw new Error(`${file} must contain a JSON array`)
  }
}

const news = parsed.get('news.json')
if (
  typeof news !== 'object' ||
  news === null ||
  !('items' in news) ||
  !Array.isArray(news.items) ||
  !('sources' in news) ||
  !Array.isArray(news.sources) ||
  !('warnings' in news) ||
  !Array.isArray(news.warnings)
) {
  throw new Error('news.json must contain items, sources, and warnings arrays')
}
for (const [index, item] of news.items.entries()) {
  if (
    typeof item !== 'object' ||
    item === null ||
    !('title' in item) ||
    typeof item.title !== 'string' ||
    !('url' in item) ||
    typeof item.url !== 'string' ||
    !item.url.startsWith('https://') ||
    !('source' in item) ||
    typeof item.source !== 'string' ||
    !('cves' in item) ||
    !Array.isArray(item.cves) ||
    !('techniques' in item) ||
    !Array.isArray(item.techniques) ||
    !('topics' in item) ||
    !Array.isArray(item.topics)
  ) {
    throw new Error(`news.json item ${index} has an invalid shape`)
  }
}

const hypotheses = parsed.get('hunt-hypotheses.json')
if (Array.isArray(hypotheses)) {
  for (const [index, item] of hypotheses.entries()) {
    if (typeof item !== 'object' || item === null || !('id' in item) || !('title' in item) || !('queries' in item)) {
      throw new Error(`hunt-hypotheses.json[${index}] is missing required fields`)
    }
    const queries = item.queries
    if (typeof queries !== 'object' || queries === null || !('kql' in queries) || !('sigma' in queries)) {
      throw new Error(`hunt-hypotheses.json[${index}] must provide KQL and Sigma`)
    }
    for (const language of ['kql', 'spl', 'elastic', 'sigma']) {
      const query = queries[language]
      if (
        typeof query !== 'object' ||
        query === null ||
        !('language' in query) ||
        typeof query.language !== 'string' ||
        !('query' in query) ||
        typeof query.query !== 'string' ||
        query.query.trim().length === 0
      ) {
        throw new Error(`hunt-hypotheses.json[${index}] has an invalid ${language} query`)
      }
    }
  }
}

const manifest = parsed.get('manifest.json')
if (typeof manifest !== 'object' || manifest === null || !('schema_version' in manifest) || !('built_at' in manifest)) {
  throw new Error('manifest.json must include schema_version and built_at')
}

console.log(`Validated ${required.length} snapshots (${(totalBytes / 1024 / 1024).toFixed(2)} MB total)`)
