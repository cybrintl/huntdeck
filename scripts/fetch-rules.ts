import { execFile } from 'node:child_process'
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { parseDetectionRule, ruleDateValue, ruleSources, type DetectionRule } from './rules'

const execFileAsync = promisify(execFile)
const maximumQueryCharacters = 30_000
const maximumSnapshotBytes = 4_800_000
const minimumRulesPerQueryLanguage = 100

interface SourceStatus {
  kind?: 'ioc' | 'detection'
  source: string
  url?: string
  fetched_at: string
  status: 'ok' | 'stale'
  count: number
}

interface SourceStatusDocument {
  sources: Record<string, SourceStatus | string>
  warnings: string[]
}

interface SourceFetchResult {
  rules: DetectionRule[]
  parseErrors: string[]
}

async function walk(directory: string): Promise<string[]> {
  const files: string[] = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await walk(fullPath))
    else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) files.push(fullPath)
  }
  return files
}

async function readPrevious(): Promise<DetectionRule[]> {
  try {
    const value: unknown = JSON.parse(await readFile('public/data/rules.json', 'utf8'))
    if (Array.isArray(value)) return value as DetectionRule[]
    throw new Error('Existing rules snapshot is not an array')
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return []
    throw error
  }
}

function sourceIdForName(name: string): string {
  return ruleSources.find(source => source.name === name)?.id ??
    name.toLocaleLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
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

    const sources: Record<string, SourceStatus | string> = {}
    if (Array.isArray(value.sources)) {
      for (const entry of value.sources) {
        if (typeof entry !== 'object' || entry === null || !('source' in entry) ||
          typeof entry.source !== 'string' || !('fetched_at' in entry) ||
          typeof entry.fetched_at !== 'string' || !('status' in entry) ||
          (entry.status !== 'ok' && entry.status !== 'stale') || !('count' in entry) ||
          typeof entry.count !== 'number') {
          throw new Error('Existing source status snapshot contains an invalid entry')
        }
        sources[sourceIdForName(entry.source)] = {
          source: entry.source,
          fetched_at: entry.fetched_at,
          status: entry.status,
          count: entry.count,
        }
      }
    } else {
      Object.assign(sources, value.sources)
    }
    return { sources, warnings: value.warnings.filter(item => typeof item === 'string') }
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      return { sources: {}, warnings: [] }
    }
    throw error
  }
}

function previousForSource(previous: DetectionRule[], sourceId: string): DetectionRule[] {
  return previous.filter(rule =>
    rule.source_id === sourceId ||
    (sourceId === 'sigma' && !rule.source_id && rule.language === 'Sigma')
  )
}

async function fetchSource(
  sourceId: string,
  temporaryDirectory: string,
): Promise<SourceFetchResult> {
  const source = ruleSources.find(item => item.id === sourceId)
  if (!source) throw new Error(`Unknown detection source: ${sourceId}`)

  const repositoryDirectory = path.join(temporaryDirectory, source.id)
  await execFileAsync('git', [
    'clone', '--depth=1', '--filter=blob:none', '--sparse', '--branch', source.branch,
    source.repository, repositoryDirectory,
  ], { maxBuffer: 10 * 1024 * 1024 })
  await execFileAsync('git', ['-C', repositoryDirectory, 'sparse-checkout', 'set', source.path], {
    maxBuffer: 10 * 1024 * 1024,
  })

  const sourceDirectory = path.join(repositoryDirectory, source.path)
  const files = await walk(sourceDirectory)
  const indexed: DetectionRule[] = []
  const parseErrors: string[] = []
  for (const file of files) {
    const relativePath = path.relative(repositoryDirectory, file).split(path.sep).join('/')
    try {
      const rule = parseDetectionRule(source, relativePath, await readFile(file, 'utf8'))
      if (!rule || (rule.query_text && rule.query_text.length > maximumQueryCharacters)) continue
      indexed.push(rule)
    } catch (error) {
      parseErrors.push(`${relativePath}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  if (indexed.length < source.minimum_rules) {
    throw new Error(`Only ${indexed.length} usable rules were found (minimum ${source.minimum_rules})`)
  }

  indexed.sort((left, right) =>
    ruleDateValue(right) - ruleDateValue(left) || left.title.localeCompare(right.title)
  )
  const limited = indexed.slice(0, source.maximum_rules)
  if (parseErrors.length > 0) {
    console.warn(`${source.name}: skipped ${parseErrors.length} unsupported or invalid YAML files`)
  }
  console.log(`${source.name} index built (${limited.length} rules)`)
  return { rules: limited, parseErrors }
}

const previous = await readPrevious()
const sourceStatus = await readSourceStatus()
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'huntdeck-rules-'))
const rulesById = new Map<string, DetectionRule>()
const warnings: string[] = []

try {
  for (const source of ruleSources) {
    try {
      const result = await fetchSource(source.id, temporaryDirectory)
      for (const rule of result.rules) rulesById.set(rule.id, rule)
      sourceStatus.sources[source.id] = {
        kind: 'detection',
        source: source.name,
        url: `https://github.com/${source.repository.split('/').slice(-2).join('/').replace(/\.git$/, '')}`,
        fetched_at: new Date().toISOString(),
        status: 'ok',
        count: result.rules.length,
      }
      if (result.parseErrors.length > 0) {
        warnings.push(
          `${source.id}: skipped ${result.parseErrors.length} invalid YAML files; examples: ${result.parseErrors.slice(0, 3).join('; ')}`
        )
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn(`${source.name} unavailable; retaining last-good rules: ${message}`)
      warnings.push(`${source.id}: ${message}`)
      const priorRules = previousForSource(previous, source.id)
      for (const rule of priorRules) rulesById.set(rule.id, rule)
      sourceStatus.sources[source.id] = {
        kind: 'detection',
        source: source.name,
        url: `https://github.com/${source.repository.split('/').slice(-2).join('/').replace(/\.git$/, '')}`,
        fetched_at: new Date().toISOString(),
        status: 'stale',
        count: priorRules.length,
      }
    }
  }
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true })
}

let rules = [...rulesById.values()].sort((left, right) =>
  left.source_name.localeCompare(right.source_name) || left.title.localeCompare(right.title)
)
const trimmedBySource = new Map<string, number>()
while (Buffer.byteLength(JSON.stringify(rules)) > maximumSnapshotBytes) {
  const sourceCounts = new Map<string, number>()
  for (const rule of rules) {
    if (rule.query_text) sourceCounts.set(rule.source_id, (sourceCounts.get(rule.source_id) ?? 0) + 1)
  }
  const candidate = rules
    .filter(rule =>
      rule.query_text &&
      (sourceCounts.get(rule.source_id) ?? 0) > minimumRulesPerQueryLanguage
    )
    .sort((left, right) =>
      (right.query_text?.length ?? 0) - (left.query_text?.length ?? 0) ||
      left.id.localeCompare(right.id)
    )[0]
  if (!candidate) {
    throw new Error(`Detection index cannot fit within the ${maximumSnapshotBytes}-byte file budget`)
  }
  rulesById.delete(candidate.id)
  trimmedBySource.set(candidate.source_id, (trimmedBySource.get(candidate.source_id) ?? 0) + 1)
  rules = rules.filter(rule => rule.id !== candidate.id)
}
for (const source of ruleSources) {
  const status = sourceStatus.sources[source.id]
  if (typeof status === 'object' && status !== null) {
    status.count = rules.filter(rule => rule.source_id === source.id).length
  }
}
for (const [sourceId, count] of trimmedBySource) {
  warnings.push(`rule-index: trimmed ${count} long queries from ${sourceId} to fit the snapshot file budget`)
}
await mkdir('public/data', { recursive: true })
await writeFile('public/data/rules.json', JSON.stringify(rules))
sourceStatus.warnings = [
  ...sourceStatus.warnings.filter(warning =>
    !ruleSources.some(source => warning.startsWith(`${source.id}:`)) &&
    !warning.startsWith('rule-index:')
  ),
  ...warnings,
]
await writeFile('public/data/source-status.json', JSON.stringify(sourceStatus, null, 2))
console.log(`Detection index saved (${rules.length} rules; ${warnings.length} source warning(s))`)
