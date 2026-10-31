export type QueryLanguage = 'kql' | 'spl' | 'elastic' | 'sigma'
export type HuntStatus = 'backlog' | 'hunting' | 'covered' | 'not_relevant'

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
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  date?: string
  why?: string
  why_sources?: string[]
  log_sources?: string[]
  hypothesis?: string
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
  sources?: Record<string, string | { source?: string; fetched_at: string; status: string; count: number }>
  warnings?: string[]
  ai?: { model?: string; golden_set_accuracy?: number | null; skipped?: boolean }
}

export interface HuntState {
  id: string
  status: HuntStatus
  note: string
  updated_at: string
  reviewed?: boolean
}

export type HuntResult = 'true_positive' | 'false_positive' | 'nothing_found' | 'detection_gap'

export interface JournalEntry {
  id: string
  hypothesis_id?: string
  title: string
  date: string
  analyst: string
  result: HuntResult
  notes: string
  evidence: string
}

export type IOCType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'cve' | 'attack'

export interface IOCRecord {
  value: string
  type: IOCType
  category: string
  sources: string[]
  malware_family?: string
  confidence?: number
  first_seen?: string
  last_seen?: string
}

export interface DetectionRule {
  id: string
  title: string
  attack_techniques: string[]
  log_source?: string
  language: string
  license: string
  url: string
  query_text?: string
  severity?: string
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

export interface NewsSourceStatus {
  id: string
  name: string
  url: string
  fetched_at: string
  status: 'ok' | 'stale'
  count: number
}

export interface NewsSnapshot {
  built_at: string
  items: NewsArticle[]
  sources: NewsSourceStatus[]
  warnings: string[]
}

export interface RuleDeploymentState {
  id: string
  status: 'deployed' | 'not_deployed' | 'na'
  updated_at: string
}

export interface AttackTechnique {
  id: string
  name: string
  tactics: string[]
  data_sources?: string[]
  detection?: string
  trending_score?: number
  cves?: string[]
  atomic_tests?: string[]
}

export interface CoverageOverride {
  id: string
  score: number
  comment: string
  updated_at: string
}

export interface JournalDraft {
  id: string
  title: string
  source_entry_id: string
  created_at: string
  notes: string
}