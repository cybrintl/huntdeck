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
const hypothesisRecords = parsed.get('hunt-hypotheses.json')
if (!Array.isArray(hypothesisRecords) || hypothesisRecords.length < 10) {
  throw new Error('hunt-hypotheses.json must contain at least 10 authored hypotheses')
}
for (const [index, hypothesis] of hypothesisRecords.entries()) {
  if (
    typeof hypothesis !== 'object' ||
    hypothesis === null ||
    !('id' in hypothesis) ||
    typeof hypothesis.id !== 'string' ||
    !('title' in hypothesis) ||
    typeof hypothesis.title !== 'string' ||
    !('investigation_steps' in hypothesis) ||
    !Array.isArray(hypothesis.investigation_steps) ||
    hypothesis.investigation_steps.length === 0 ||
    !('validation_notes' in hypothesis) ||
    typeof hypothesis.validation_notes !== 'string' ||
    !('false_positive_notes' in hypothesis) ||
    typeof hypothesis.false_positive_notes !== 'string' ||
    !('queries' in hypothesis) ||
    typeof hypothesis.queries !== 'object' ||
    hypothesis.queries === null
  ) {
    throw new Error(`hunt-hypotheses.json[${index}] has incomplete hunt guidance`)
  }
  for (const language of ['kql', 'spl', 'elastic', 'sigma']) {
    const query: unknown = Reflect.get(hypothesis.queries, language)
    if (
      typeof query !== 'object' ||
      query === null ||
      !('query' in query) ||
      typeof query.query !== 'string' ||
      query.query.trim() === ''
    ) {
      throw new Error(`hunt-hypotheses.json[${index}] is missing its ${language} query`)
    }
  }
}
const techniques = parsed.get('techniques.json')
if (!Array.isArray(techniques) || techniques.length < 500) {
  throw new Error('techniques.json must contain at least 500 ATT&CK techniques')
}
let detectionStrategyCount = 0
let analyticCount = 0
for (const [index, technique] of techniques.entries()) {
  if (
    typeof technique !== 'object' ||
    technique === null ||
    !('id' in technique) ||
    typeof technique.id !== 'string' ||
    !('name' in technique) ||
    typeof technique.name !== 'string' ||
    !('description' in technique) ||
    typeof technique.description !== 'string' ||
    !('detection_strategies' in technique) ||
    !Array.isArray(technique.detection_strategies)
  ) {
    throw new Error(`techniques.json[${index}] has an invalid ATT&CK technique record`)
  }
  for (const strategy of technique.detection_strategies) {
    if (
      typeof strategy !== 'object' ||
      strategy === null ||
      !('id' in strategy) ||
      typeof strategy.id !== 'string' ||
      !('name' in strategy) ||
      typeof strategy.name !== 'string' ||
      !('url' in strategy) ||
      typeof strategy.url !== 'string' ||
      !strategy.url.startsWith('https://') ||
      !('analytics' in strategy) ||
      !Array.isArray(strategy.analytics)
    ) {
      throw new Error(`techniques.json[${index}] has an invalid detection strategy`)
    }
    detectionStrategyCount += 1
    analyticCount += strategy.analytics.length
    for (const analytic of strategy.analytics) {
      if (
        typeof analytic !== 'object' ||
        analytic === null ||
        !('name' in analytic) ||
        typeof analytic.name !== 'string' ||
        !('description' in analytic) ||
        typeof analytic.description !== 'string' ||
        !('platforms' in analytic) ||
        !Array.isArray(analytic.platforms) ||
        !('log_sources' in analytic) ||
        !Array.isArray(analytic.log_sources)
      ) {
        throw new Error(`techniques.json[${index}] has an invalid detection analytic`)
      }
    }
  }
}
if (detectionStrategyCount === 0 || analyticCount === 0) {
  throw new Error('techniques.json must include linked ATT&CK detection strategies and analytics')
}

for (const file of required.filter(name => !['kev.json', 'manifest.json', 'source-status.json'].includes(name))) {
  if (file !== 'news.json' && !Array.isArray(parsed.get(file))) {
    throw new Error(`${file} must contain a JSON array`)
  }
}

const iocs = parsed.get('iocs.json')
if (!Array.isArray(iocs) || iocs.length === 0) {
  throw new Error('iocs.json must contain at least one indicator')
}
for (const [index, item] of iocs.entries()) {
  if (
    typeof item !== 'object' ||
    item === null ||
    !('value' in item) ||
    typeof item.value !== 'string' ||
    !('type' in item) ||
    !['ip', 'domain', 'url', 'md5', 'sha1', 'sha256'].includes(String(item.type)) ||
    !('category' in item) ||
    typeof item.category !== 'string' ||
    !('sources' in item) ||
    !Array.isArray(item.sources) ||
    item.sources.length === 0 ||
    item.sources.some((source: unknown) => typeof source !== 'string') ||
    ('source_weight' in item &&
      (typeof item.source_weight !== 'number' || item.source_weight < 0 || item.source_weight > 1))
  ) {
    throw new Error(`iocs.json[${index}] has an invalid indicator record`)
  }
}

const rules = parsed.get('rules.json')
if (!Array.isArray(rules) || rules.length === 0) {
  throw new Error('rules.json must contain indexed detection content')
}
const ruleLanguages = new Set<string>()
for (const [index, item] of rules.entries()) {
  if (
    typeof item !== 'object' ||
    item === null ||
    !('id' in item) ||
    typeof item.id !== 'string' ||
    !('title' in item) ||
    typeof item.title !== 'string' ||
    !('language' in item) ||
    typeof item.language !== 'string' ||
    !('url' in item) ||
    typeof item.url !== 'string' ||
    !item.url.startsWith('https://') ||
    !('attack_techniques' in item) ||
    !Array.isArray(item.attack_techniques)
  ) {
    throw new Error(`rules.json[${index}] has an invalid rule record`)
  }
  ruleLanguages.add(item.language)
  if (
    ['KQL', 'SPL'].includes(item.language) &&
    (!('query_text' in item) || typeof item.query_text !== 'string' || item.query_text.trim() === '')
  ) {
    throw new Error(`rules.json[${index}] is missing its ${item.language} query`)
  }
}
for (const language of ['KQL', 'SPL', 'Sigma']) {
  if (!ruleLanguages.has(language)) {
    throw new Error(`rules.json must include ${language} detection content`)
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
    !('summary' in item) ||
    typeof item.summary !== 'string' ||
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
    !Array.isArray(item.topics) ||
    !('tags' in item) ||
    !Array.isArray(item.tags) ||
    !('severity' in item) ||
    !['critical', 'high', 'medium', 'low', 'unknown'].includes(String(item.severity))
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
