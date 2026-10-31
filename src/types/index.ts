export type QueryLanguage = 'kql' | 'spl' | 'elastic' | 'sigma'

export interface HuntQuery {
  language: string
  query: string
  sigma_link?: string
}

export interface HuntHypothesis {
  id: string
  title: string
  origin?: string
  generated?: boolean
  needs_review?: boolean
  attack_techniques?: string[]
  tactics?: string[]
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  date?: string
  why?: string
  why_sources?: string[]
  log_sources?: string[]
  hypothesis?: string
  investigation_steps?: string[]
  validation_notes?: string
  false_positive_notes?: string
  queries: Partial<Record<QueryLanguage, HuntQuery>>
  tags?: string[]
  ai?: { relevance_score?: number; summary?: string; cluster_id?: string }
}

export interface KevEntry {
  cveID: string
  vendorProject?: string
  product?: string
  vulnerabilityName?: string
  dateAdded?: string
  dueDate?: string
  knownRansomwareCampaignUse?: string
  shortDescription?: string
  requiredAction?: string
}

export interface KevSnapshot {
  title?: string
  catalogVersion?: string
  dateReleased?: string
  vulnerabilities: KevEntry[]
}

export interface EpssEntry {
  cve: string
  epss: number
  percentile?: number
}

export interface DataManifest {
  schema_version?: number
  built_at?: string
  counts?: {
    kev: number
    epss: number
    techniques?: number
    hypotheses?: number
    iocs?: number
    rules?: number
    news?: number
  }
  sources?: Record<string, string | DataSourceStatus>
  warnings?: string[]
  ai?: { model?: string; golden_set_accuracy?: number | null; skipped?: boolean }
}

export interface DataSourceStatus {
  kind?: 'ioc' | 'detection' | 'news' | 'vulnerability' | 'attack'
  source?: string
  url?: string
  fetched_at: string
  status: 'ok' | 'stale' | 'unknown'
  count: number
  published_count?: number
}

export type IOCType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'cve' | 'attack'

export interface IOCRecord {
  value: string
  type: IOCType
  category: string
  sources: string[]
  malware_family?: string
  source_weight?: number
  first_seen?: string
  last_seen?: string
}

export interface DetectionRule {
  id: string
  source_id?: string
  source_name?: string
  title: string
  description?: string
  attack_techniques: string[]
  tactics?: string[]
  log_source?: string
  data_sources?: string[]
  language: string
  license: string
  url: string
  query_text?: string
  severity?: string
  known_false_positives?: string
  updated_at?: string
  internal_path?: string
}

export interface NewsArticle {
  url: string
  title: string
  summary: string
  source: string
  source_name: string
  published_at?: string
  cves: string[]
  techniques: string[]
  topics: string[]
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'unknown'
  cvss?: number
  tags: string[]
}

export interface NewsSourceStatus {
  id: string
  name: string
  url: string
  fetched_at: string
  status: 'ok' | 'stale' | 'unknown'
  count: number
}

export interface NewsSnapshot {
  built_at: string
  items: NewsArticle[]
  sources: NewsSourceStatus[]
  warnings: string[]
}

export interface AttackTechnique {
  id: string
  name: string
  tactics: string[]
  data_sources?: string[]
  description?: string
  detection?: string
  detection_strategies?: AttackDetectionStrategy[]
  trending_score?: number
  cves?: string[]
  atomic_tests?: string[]
}

export interface AttackDetectionStrategy {
  id: string
  name: string
  url: string
  analytics: AttackAnalytic[]
}

export interface AttackAnalytic {
  name: string
  description: string
  platforms: string[]
  log_sources: string[]
}
