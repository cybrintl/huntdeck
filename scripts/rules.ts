import { parse } from 'yaml'

export interface DetectionRule {
  id: string
  source_id: string
  source_name: string
  title: string
  description?: string
  attack_techniques: string[]
  tactics: string[]
  log_source?: string
  data_sources: string[]
  language: string
  license: string
  url: string
  query_text?: string
  severity?: string
  known_false_positives?: string
  updated_at?: string
}

interface RuleSource {
  id: string
  name: string
  language: string
  license: string
  repository: string
  branch: string
  path: string
  minimum_rules: number
  maximum_rules: number
}

type YamlObject = Record<string, unknown>

export const ruleSources: RuleSource[] = [
  {
    id: 'sigma',
    name: 'SigmaHQ',
    language: 'Sigma',
    license: 'LGPL-2.1',
    repository: 'https://github.com/SigmaHQ/sigma.git',
    branch: 'master',
    path: 'rules',
    minimum_rules: 100,
    maximum_rules: 10_000,
  },
  {
    id: 'microsoft-sentinel',
    name: 'Microsoft Sentinel Hunting Queries',
    language: 'KQL',
    license: 'MIT',
    repository: 'https://github.com/Azure/Azure-Sentinel.git',
    branch: 'master',
    path: 'Hunting Queries',
    minimum_rules: 20,
    maximum_rules: 500,
  },
  {
    id: 'splunk-security-content',
    name: 'Splunk Security Content',
    language: 'SPL',
    license: 'Apache-2.0',
    repository: 'https://github.com/splunk/security_content.git',
    branch: 'develop',
    path: 'detections',
    minimum_rules: 20,
    maximum_rules: 500,
  },
]

function object(value: unknown): YamlObject | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as YamlObject
    : undefined
}

function string(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined
}

function stringList(value: unknown): string[] {
  return (Array.isArray(value) ? value : value === undefined ? [] : [value])
    .map(item => string(item))
    .filter((item): item is string => item !== undefined)
}

function normalizeTechnique(value: string): string | undefined {
  const match = value.match(/\bT\d{4}(?:\.\d{3})?\b/i)
  return match?.[0]?.toUpperCase()
}

function techniqueIds(values: string[]): string[] {
  return [...new Set(values.map(normalizeTechnique).filter((value): value is string => Boolean(value)))]
}

function githubFileUrl(source: RuleSource, relativePath: string): string {
  const encodedPath = relativePath.split('/').map(segment => encodeURIComponent(segment)).join('/')
  return `https://github.com/${source.repository.split('/').slice(-2).join('/').replace(/\.git$/, '')}/blob/${source.branch}/${encodedPath}`
}

function parseYaml(content: string, filePath: string): YamlObject {
  const value: unknown = parse(content)
  const parsed = object(value)
  if (!parsed) throw new Error(`${filePath} does not contain a YAML object`)
  return parsed
}

function parseSigmaRule(
  source: RuleSource,
  relativePath: string,
  content: string,
): DetectionRule | undefined {
  const document = parseYaml(content, relativePath)
  const title = string(document.title)
  if (!title) return undefined

  const logSource = object(document.logsource)
  const logSourceLabel = ['product', 'service', 'category']
    .map(key => string(logSource?.[key]))
    .filter((value): value is string => Boolean(value))
    .join(' / ')
  const tags = stringList(document.tags)

  return {
    id: `${source.id}:${string(document.id) ?? relativePath.replace(/\.ya?ml$/i, '')}`,
    source_id: source.id,
    source_name: source.name,
    title,
    description: string(document.description),
    attack_techniques: techniqueIds(tags),
    tactics: [...new Set(tags.filter(tag => !normalizeTechnique(tag)))],
    log_source: logSourceLabel || undefined,
    data_sources: logSourceLabel ? [logSourceLabel] : [],
    language: source.language,
    license: source.license,
    url: githubFileUrl(source, relativePath),
    severity: string(document.level),
  }
}

function parseSentinelRule(
  source: RuleSource,
  relativePath: string,
  content: string,
): DetectionRule | undefined {
  const document = parseYaml(content, relativePath)
  const title = string(document.name)
  const query = string(document.query)
  if (!title || !query) return undefined

  const connectors = Array.isArray(document.requiredDataConnectors)
    ? document.requiredDataConnectors.flatMap(connector => {
      const item = object(connector)
      return item ? stringList(item.connectorId) : []
    })
    : []

  return {
    id: `${source.id}:${string(document.id) ?? relativePath.replace(/\.ya?ml$/i, '')}`,
    source_id: source.id,
    source_name: source.name,
    title,
    description: string(document.description),
    attack_techniques: techniqueIds(stringList(document.relevantTechniques)),
    tactics: stringList(document.tactics),
    data_sources: connectors,
    language: source.language,
    license: source.license,
    url: githubFileUrl(source, relativePath),
    query_text: query,
    updated_at: string(document.lastUpdated ?? document.createdDateTime),
  }
}

function parseSplunkRule(
  source: RuleSource,
  relativePath: string,
  content: string,
): DetectionRule | undefined {
  const document = parseYaml(content, relativePath)
  const title = string(document.name)
  const query = string(document.search)
  if (!title || !query) return undefined

  const tags = object(document.tags)
  const dataSources = stringList(document.data_source)
  const rawTechniques = stringList(tags?.mitre_attack_id ?? tags?.mitre_attack)
  const falsePositives = string(document.known_false_positives)

  return {
    id: `${source.id}:${string(document.id) ?? relativePath.replace(/\.ya?ml$/i, '')}`,
    source_id: source.id,
    source_name: source.name,
    title,
    description: string(document.description),
    attack_techniques: techniqueIds(rawTechniques),
    tactics: stringList(tags?.mitre_attack_tactic),
    log_source: dataSources.join(', ') || undefined,
    data_sources: dataSources,
    language: source.language,
    license: source.license,
    url: githubFileUrl(source, relativePath),
    query_text: query,
    severity: string(tags?.impact),
    known_false_positives: falsePositives,
    updated_at: string(document.modification_date),
  }
}

export function parseDetectionRule(
  source: RuleSource,
  relativePath: string,
  content: string,
): DetectionRule | undefined {
  if (source.id === 'sigma') return parseSigmaRule(source, relativePath, content)
  if (source.id === 'microsoft-sentinel') return parseSentinelRule(source, relativePath, content)
  if (source.id === 'splunk-security-content') return parseSplunkRule(source, relativePath, content)
  throw new Error(`Unsupported detection source: ${source.id}`)
}

export function ruleDateValue(rule: DetectionRule): number {
  const timestamp = rule.updated_at ? Date.parse(rule.updated_at) : Number.NaN
  return Number.isFinite(timestamp) ? timestamp : 0
}

export type { RuleSource }
