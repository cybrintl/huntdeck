import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  useEpss,
  useHypotheses,
  useKev,
  useNews,
  useRules,
  useTechniques,
} from '../../data/snapshots'
import type { AttackTechnique, DetectionRule, HuntHypothesis, NewsArticle } from '../../types'
import {
  classifyMentionedContext,
  extractReportIndicators,
  suggestionForReport,
} from '../../utils/hunt-ideas'

const timeRanges = [
  { value: '7', label: 'Past 7 days' },
  { value: '30', label: 'Past 30 days' },
  { value: '90', label: 'Past 90 days' },
  { value: 'all', label: 'All available dates' },
]

function formatDate(value?: string): string {
  if (!value) return 'Date unavailable'
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? 'Date unavailable'
    : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function articleContext(article: NewsArticle) {
  return `${article.title} ${article.summary} ${article.tags.join(' ')}`
}

function namedTechniques(
  article: NewsArticle,
  techniquesById: Map<string, AttackTechnique>
): Array<{ id: string; name: string; tactics: string[] }> {
  return article.techniques.map(id => {
    const technique = techniquesById.get(id)
    return {
      id,
      name: technique?.name ?? 'ATT&CK technique',
      tactics: technique?.tactics ?? [],
    }
  })
}

function rulesForArticle(
  article: NewsArticle,
  rulesByTechnique: Map<string, DetectionRule[]>
): DetectionRule[] {
  const unique = new Map<string, DetectionRule>()
  for (const technique of article.techniques) {
    for (const rule of rulesByTechnique.get(technique) ?? []) unique.set(rule.id, rule)
  }
  return [...unique.values()]
}

function hypothesesForArticle(
  article: NewsArticle,
  hypothesesByTechnique: Map<string, HuntHypothesis[]>
): Array<{ hypothesis: HuntHypothesis; technique: string }> {
  const unique = new Map<string, { hypothesis: HuntHypothesis; technique: string }>()
  for (const technique of article.techniques) {
    for (const hypothesis of hypothesesByTechnique.get(technique) ?? []) {
      if (!unique.has(hypothesis.id)) unique.set(hypothesis.id, { hypothesis, technique })
    }
  }
  return [...unique.values()]
}

export default function Ideas() {
  const news = useNews()
  const kev = useKev()
  const epss = useEpss()
  const rules = useRules()
  const hypotheses = useHypotheses()
  const techniques = useTechniques()
  const [search, setSearch] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [topicFilter, setTopicFilter] = useState('')
  const [industryFilter, setIndustryFilter] = useState('')
  const [geographyFilter, setGeographyFilter] = useState('')
  const [tacticFilter, setTacticFilter] = useState('')
  const [techniqueFilter, setTechniqueFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [timeRange, setTimeRange] = useState('30')
  const [kevOnly, setKevOnly] = useState(false)
  const [indicatorsOnly, setIndicatorsOnly] = useState(false)
  const [displayLimit, setDisplayLimit] = useState(30)
  const [copyMessage, setCopyMessage] = useState('')

  const articles = news.data?.items ?? []
  const kevCves = useMemo(
    () => new Set((kev.data?.vulnerabilities ?? []).map(item => item.cveID)),
    [kev.data]
  )
  const epssByCve = useMemo(
    () => new Map((epss.data ?? []).map(item => [item.cve, item.epss])),
    [epss.data]
  )
  const techniquesById = useMemo(
    () => new Map((techniques.data ?? []).map(technique => [technique.id, technique])),
    [techniques.data]
  )
  const hypothesesByTechnique = useMemo(() => {
    const result = new Map<string, HuntHypothesis[]>()
    for (const hypothesis of hypotheses.data ?? []) {
      for (const technique of hypothesis.attack_techniques ?? []) {
        result.set(technique, [...(result.get(technique) ?? []), hypothesis])
      }
    }
    return result
  }, [hypotheses.data])
  const rulesByTechnique = useMemo(() => {
    const result = new Map<string, DetectionRule[]>()
    for (const rule of rules.data ?? []) {
      for (const technique of rule.attack_techniques) {
        result.set(technique, [...(result.get(technique) ?? []), rule])
      }
    }
    return result
  }, [rules.data])
  const sources = news.data?.sources ?? []
  const topics = useMemo(
    () => [...new Set(articles.flatMap(article => article.topics))].sort(),
    [articles]
  )
  const industries = useMemo(
    () => [...new Set(articles.flatMap(article =>
      classifyMentionedContext(articleContext(article)).industries
    ))].sort(),
    [articles]
  )
  const geographies = useMemo(
    () => [...new Set(articles.flatMap(article =>
      classifyMentionedContext(articleContext(article)).geographies
    ))].sort(),
    [articles]
  )
  const tactics = useMemo(
    () => [...new Set(articles.flatMap(article =>
      namedTechniques(article, techniquesById).flatMap(technique => technique.tactics)
    ))].sort(),
    [articles, techniquesById]
  )
  const techniqueIds = useMemo(
    () => [...new Set(articles.flatMap(article => article.techniques))].sort(),
    [articles]
  )

  const filtered = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase()
    const cutoff = timeRange === 'all'
      ? undefined
      : Date.now() - Number(timeRange) * 24 * 60 * 60 * 1000
    return articles.filter(article => {
      const context = articleContext(article)
      const mentioned = classifyMentionedContext(context)
      const indicators = extractReportIndicators(article.title, article.summary)
      const articleTechniques = namedTechniques(article, techniquesById)
      const articleTactics = articleTechniques.flatMap(technique => technique.tactics)
      const hasKev = article.cves.some(cve => kevCves.has(cve))
      const published = article.published_at ? Date.parse(article.published_at) : Number.NaN
      const withinTimeRange = cutoff === undefined ||
        (Number.isFinite(published) && published >= cutoff)
      return (!needle || context.toLocaleLowerCase().includes(needle) ||
        article.cves.some(cve => cve.toLocaleLowerCase().includes(needle)) ||
        indicators.some(indicator => indicator.value.toLocaleLowerCase().includes(needle))) &&
        (!sourceFilter || article.source === sourceFilter) &&
        (!topicFilter || article.topics.includes(topicFilter)) &&
        (!industryFilter || (industryFilter === '__none__'
          ? mentioned.industries.length === 0
          : mentioned.industries.includes(industryFilter))) &&
        (!geographyFilter || (geographyFilter === '__none__'
          ? mentioned.geographies.length === 0
          : mentioned.geographies.includes(geographyFilter))) &&
        (!tacticFilter || articleTactics.includes(tacticFilter)) &&
        (!techniqueFilter || article.techniques.includes(techniqueFilter)) &&
        (!severityFilter || article.severity === severityFilter) &&
        (!kevOnly || hasKev) &&
        (!indicatorsOnly || indicators.length > 0) &&
        withinTimeRange
    }).sort((a, b) => (b.published_at ?? '').localeCompare(a.published_at ?? ''))
  }, [
    articles, search, sourceFilter, topicFilter, industryFilter, geographyFilter,
    tacticFilter, techniqueFilter, severityFilter, timeRange, kevOnly,
    indicatorsOnly, techniquesById, kevCves,
  ])

  function clearFilters() {
    setSearch('')
    setSourceFilter('')
    setTopicFilter('')
    setIndustryFilter('')
    setGeographyFilter('')
    setTacticFilter('')
    setTechniqueFilter('')
    setSeverityFilter('')
    setTimeRange('30')
    setKevOnly(false)
    setIndicatorsOnly(false)
    setDisplayLimit(30)
  }

  async function copyIndicators(article: NewsArticle) {
    const indicators = extractReportIndicators(article.title, article.summary)
    if (indicators.length === 0) return
    try {
      await navigator.clipboard.writeText(indicators.map(indicator => indicator.value).join('\n'))
      setCopyMessage(`${indicators.length} report-mentioned indicator(s) copied`)
    } catch (error) {
      setCopyMessage(error instanceof Error ? `Copy failed: ${error.message}` : 'Copy failed')
    }
  }

  const loading = news.isLoading
  const errorMessages = [news, kev, epss, rules, hypotheses, techniques]
    .filter(query => query.isError)
    .map(query => query.error.message)

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Threat-informed hunting</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Hunt idea radar</h1>
          <p className="mt-2 max-w-3xl text-slate-600">
            Turn recent reporting into evidence-linked starting points for your next hunt. Each suggestion
            connects report claims with named CVEs, ATT&amp;CK techniques, published indicators, and indexed queries.
          </p>
        </div>
        <div className="flex gap-2">
          <Link className="button-secondary" to="/hypotheses">Browse hunt library</Link>
          <Link className="button-secondary" to="/">Daily brief</Link>
        </div>
      </header>

      <aside className="rounded-xl border border-sky-200 bg-sky-50 p-4 text-sm leading-relaxed text-sky-950">
        <strong>How suggestions work:</strong> They are deterministic prompts built from the published headline and
        short feed summary—not AI analysis or verified incident findings. Indicator chips appear only when a literal
        is present in that feed text. Industry and geography filters match terms explicitly mentioned in the report;
        they do not establish victim location, target, attribution, or actor origin. Open the source and verify context.
      </aside>

      <section aria-label="Hunt idea snapshot summary" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <SummaryCard label="Reports in snapshot" value={articles.length} loading={news.isLoading} />
        <SummaryCard
          label="Reports mentioning ATT&CK techniques"
          value={articles.filter(article => article.techniques.length > 0).length}
          loading={news.isLoading}
        />
        <SummaryCard
          label="Reports mentioning CISA KEV entries"
          value={articles.filter(article => article.cves.some(cve => kevCves.has(cve))).length}
          loading={news.isLoading || kev.isLoading}
        />
        <SummaryCard
          label="Reports with explicit observables"
          value={articles.filter(article =>
            extractReportIndicators(article.title, article.summary).length > 0
          ).length}
          loading={news.isLoading}
        />
      </section>

      {sources.length > 0 && (
        <section aria-label="Research source status" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {sources.map(source => (
            <article className="rounded-xl border border-slate-200 bg-white p-3" key={source.id}>
              <div className="flex items-center justify-between gap-2">
                <a className="text-sm font-semibold text-slate-900 hover:text-sky-800 hover:underline"
                  href={source.url} target="_blank" rel="noreferrer">{source.name}</a>
                <span className={source.status === 'ok' ? 'badge-success' : 'badge-warning'}>
                  {source.status === 'ok' ? 'Current' : 'Last snapshot'}
                </span>
              </div>
              <p className="mt-1 text-xs text-slate-500">
                {source.count} reports · refreshed {formatDate(source.fetched_at)}
              </p>
            </article>
          ))}
        </section>
      )}

      {news.data?.warnings.length ? (
        <p className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900" role="status">
          One or more feeds could not be refreshed. The displayed items may include last-good source snapshots.
        </p>
      ) : null}
      {errorMessages.length > 0 && (
        <p className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-900" role="alert">
          Some hunting context could not be loaded: {errorMessages.join(' ')}
        </p>
      )}

      <section aria-label="Filter hunt ideas"
        className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 sm:grid-cols-2 lg:grid-cols-4">
        <label className="sm:col-span-2">
          <span className="field-label">Search reports, CVEs, techniques, and observables</span>
          <input className="field-input" type="search" value={search}
            onChange={event => {
              setSearch(event.target.value)
              setDisplayLimit(30)
            }} placeholder="e.g. ransomware, T1059.001, CVE, IP, domain, or hash" />
        </label>
        <label>
          <span className="field-label">Report age</span>
          <select className="field-input" value={timeRange} onChange={event => {
            setTimeRange(event.target.value)
            setDisplayLimit(30)
          }}>
            {timeRanges.map(range => <option key={range.value} value={range.value}>{range.label}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Research source</span>
          <select className="field-input" value={sourceFilter} onChange={event => setSourceFilter(event.target.value)}>
            <option value="">All sources</option>
            {sources.map(source => <option key={source.id} value={source.id}>{source.name}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Report topic</span>
          <select className="field-input" value={topicFilter} onChange={event => setTopicFilter(event.target.value)}>
            <option value="">All topics</option>
            {topics.map(topic => <option key={topic}>{topic}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Industry mentioned</span>
          <select className="field-input" value={industryFilter} onChange={event => setIndustryFilter(event.target.value)}>
            <option value="">All / not specified</option>
            <option value="__none__">No industry mentioned</option>
            {industries.map(industry => <option key={industry}>{industry}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Country / region mentioned</span>
          <select className="field-input" value={geographyFilter}
            onChange={event => setGeographyFilter(event.target.value)}>
            <option value="">All / not specified</option>
            <option value="__none__">No geography mentioned</option>
            {geographies.map(geography => <option key={geography}>{geography}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">ATT&amp;CK tactic</span>
          <select className="field-input" value={tacticFilter} onChange={event => setTacticFilter(event.target.value)}>
            <option value="">All tactics</option>
            {tactics.map(tactic => <option key={tactic}>{tactic}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">ATT&amp;CK technique</span>
          <select className="field-input" value={techniqueFilter}
            onChange={event => setTechniqueFilter(event.target.value)}>
            <option value="">All techniques</option>
            {techniqueIds.map(technique => (
              <option key={technique} value={technique}>
                {technique} · {techniquesById.get(technique)?.name ?? 'ATT&CK technique'}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="field-label">Feed severity</span>
          <select className="field-input" value={severityFilter}
            onChange={event => setSeverityFilter(event.target.value)}>
            <option value="">All severities</option>
            {['critical', 'high', 'medium', 'low', 'unknown'].map(severity => (
              <option key={severity} value={severity}>{severity === 'unknown' ? 'Unrated' : severity}</option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-700">
          <input type="checkbox" checked={kevOnly} onChange={event => setKevOnly(event.target.checked)} />
          Report references a CISA KEV
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-700">
          <input type="checkbox" checked={indicatorsOnly}
            onChange={event => setIndicatorsOnly(event.target.checked)} />
          Report text contains an observable
        </label>
        <div className="flex items-end">
          <button className="button-secondary" onClick={clearFilters}>Clear filters</button>
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-bold text-slate-950">Suggested hunt starting points</h2>
        <span className="text-sm text-slate-500">
          {loading ? 'Loading reports…' : `${filtered.length.toLocaleString()} of ${articles.length.toLocaleString()} reports`}
        </span>
      </div>

      {loading ? (
        <p className="rounded-xl border border-slate-200 bg-white p-6 text-slate-600">Loading report signals…</p>
      ) : filtered.length > 0 ? (
        <section aria-label="Suggested hunt ideas" className="grid gap-4 xl:grid-cols-2">
          {filtered.slice(0, displayLimit).map(article => (
            <IdeaCard
              article={article}
              key={article.url}
              techniquesById={techniquesById}
              kevCves={kevCves}
              epssByCve={epssByCve}
              hypothesesByTechnique={hypothesesByTechnique}
              rulesByTechnique={rulesByTechnique}
              onCopyIndicators={() => void copyIndicators(article)}
            />
          ))}
        </section>
      ) : (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white p-6">
          <p className="font-medium text-slate-800">
            {articles.length === 0 ? 'No reports are available in the current snapshot.' : 'No reports match those filters.'}
          </p>
          <p className="mt-1 text-sm text-slate-600">
            Broaden the report age or remove filters. Industry and geography filters only match explicit report mentions.
          </p>
        </div>
      )}

      {displayLimit < filtered.length && (
        <div className="text-center">
          <button className="button-secondary" onClick={() => setDisplayLimit(limit => limit + 30)}>
            Show 30 more reports ({(filtered.length - displayLimit).toLocaleString()} remaining)
          </button>
        </div>
      )}
      {copyMessage && <p className="text-sm text-slate-600" role="status">{copyMessage}</p>}
      <p className="text-xs text-slate-500">
        Report snapshots are refreshed by GitHub Actions. A headline, CVE, IOC, KEV match, or ATT&amp;CK mapping is
        a research lead—not confirmation of exploitation, compromise, or relevance to your environment.
      </p>
    </div>
  )
}

function SummaryCard({ label, value, loading }: { label: string; value: number; loading: boolean }) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <p className="text-sm text-slate-600">{label}</p>
      <p className="mt-2 text-2xl font-bold text-slate-950">{loading ? 'Loading…' : value.toLocaleString()}</p>
    </article>
  )
}

function IdeaCard({
  article,
  techniquesById,
  kevCves,
  epssByCve,
  hypothesesByTechnique,
  rulesByTechnique,
  onCopyIndicators,
}: {
  article: NewsArticle
  techniquesById: Map<string, AttackTechnique>
  kevCves: Set<string>
  epssByCve: Map<string, number>
  hypothesesByTechnique: Map<string, HuntHypothesis[]>
  rulesByTechnique: Map<string, DetectionRule[]>
  onCopyIndicators: () => void
}) {
  const text = articleContext(article)
  const mentioned = classifyMentionedContext(text)
  const observables = extractReportIndicators(article.title, article.summary)
  const resolvedTechniques = namedTechniques(article, techniquesById)
  const relatedRules = rulesForArticle(article, rulesByTechnique)
  const relatedHypotheses = hypothesesForArticle(article, hypothesesByTechnique)
  const kevMatches = article.cves.filter(cve => kevCves.has(cve))
  const highestEpss = Math.max(0, ...article.cves.map(cve => epssByCve.get(cve) ?? 0))
  const suggestion = suggestionForReport({
    title: article.title,
    cves: article.cves,
    techniques: resolvedTechniques,
  })

  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-800">
            {article.source_name} · {formatDate(article.published_at)}
          </p>
          <h3 className="mt-2 text-lg font-semibold leading-snug text-slate-950">
            <a className="hover:text-sky-800 hover:underline" href={article.url} target="_blank" rel="noreferrer">
              {article.title}
              <span className="sr-only"> (opens source in a new tab)</span>
            </a>
          </h3>
        </div>
        <div className="flex flex-wrap gap-2">
          {article.severity && article.severity !== 'unknown' && (
            <span className={article.severity === 'critical' ? 'badge-warning' : 'badge'}>
              Feed: {article.severity}
            </span>
          )}
          {kevMatches.length > 0 && <span className="badge-warning">CISA KEV reference</span>}
        </div>
      </div>

      {article.summary && <p className="mt-3 text-sm leading-relaxed text-slate-600">{article.summary}</p>}

      <section className="mt-4 rounded-lg border border-sky-100 bg-sky-50 p-4">
        <h4 className="text-sm font-semibold text-sky-950">Suggested hunt focus</h4>
        <p className="mt-2 text-sm leading-relaxed text-slate-700">{suggestion}</p>
        <ol className="mt-3 list-decimal space-y-1 pl-5 text-xs leading-relaxed text-slate-600">
          {article.cves.length > 0 && (
            <li>Check asset and vulnerability inventory for the named CVE(s); confirm affected versions and exposure before assuming impact.</li>
          )}
          {article.techniques.length > 0 ? (
            <li>Use the mapped ATT&amp;CK behavior and the linked query/rule references below to scope available telemetry.</li>
          ) : (
            <li>Open the report and identify concrete behavior, affected products, and time bounds before translating it into searches.</li>
          )}
          <li>Correlate relevant network, endpoint, identity, and application events; validate expected activity and benign explanations.</li>
        </ol>
      </section>

      <div className="mt-3 flex flex-wrap gap-2">
        {article.topics.map(topic => <span className="badge-muted" key={topic}>{topic}</span>)}
        {mentioned.industries.map(industry => (
          <span className="badge-muted" key={`industry:${industry}`}>Industry mentioned: {industry}</span>
        ))}
        {mentioned.geographies.map(geography => (
          <span className="badge-muted" key={`geo:${geography}`}>Geography mentioned: {geography}</span>
        ))}
      </div>

      {(article.cves.length > 0 || article.techniques.length > 0 || observables.length > 0) && (
        <section className="mt-4 border-t border-slate-100 pt-3" aria-label="Report evidence">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Report evidence</h4>
          {article.cves.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-2">
              {article.cves.map(cve => {
                const score = epssByCve.get(cve)
                return (
                  <a className="badge" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`}
                    key={cve} target="_blank" rel="noreferrer">
                    {cve}{kevCves.has(cve) ? ' · KEV' : ''}
                    {score !== undefined ? ` · EPSS ${(score * 100).toFixed(1)}%` : ''}
                  </a>
                )
              })}
            </div>
          )}
          {resolvedTechniques.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-2">
              {resolvedTechniques.map(technique => (
                <Link className="badge" key={technique.id}
                  to={`/coverage?technique=${encodeURIComponent(technique.id)}`}>
                  {technique.id} · {technique.name}
                </Link>
              ))}
            </div>
          )}
          {observables.length > 0 && (
            <div className="mt-2">
              <p className="text-xs text-slate-500">
                Literal observables from the feed text; not independently verified or matched against the IOC snapshot.
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                {observables.map(indicator => (
                  <code className="max-w-full break-all rounded bg-slate-100 px-2 py-1 text-xs text-slate-800"
                    key={`${indicator.type}:${indicator.value}`}>{indicator.value}</code>
                ))}
              </div>
              <button className="mt-2 text-xs font-semibold text-sky-800 hover:underline"
                onClick={onCopyIndicators}>Copy report-mentioned observables</button>
            </div>
          )}
        </section>
      )}

      {article.cves.length > 0 && (
        <p className="mt-2 text-xs text-slate-500">
          {kevMatches.length > 0 && `CISA KEV: ${kevMatches.join(', ')}. `}
          {highestEpss > 0 && `Highest matched EPSS: ${(highestEpss * 100).toFixed(1)}%. `}
          KEV and EPSS are vulnerability-prioritization context, not evidence that an asset was exploited.
        </p>
      )}

      {(article.techniques.length > 0 || article.cves.length > 0) && (
        <section className="mt-4 border-t border-slate-100 pt-3" aria-label="Related hunting content">
          <h4 className="text-sm font-semibold text-slate-900">Related hunting content</h4>
          {relatedHypotheses.length > 0 && (
            <ul className="mt-2 space-y-1">
              {relatedHypotheses.slice(0, 3).map(({ hypothesis, technique }) => (
                <li key={hypothesis.id}>
                  <Link className="text-sm text-sky-800 hover:underline"
                    to={`/hypotheses?technique=${encodeURIComponent(technique)}`}>
                    {hypothesis.title}
                  </Link>
                </li>
              ))}
            </ul>
          )}
          {relatedRules.length > 0 ? (
            <p className="mt-2 text-xs text-slate-600">
              {relatedRules.length.toLocaleString()} indexed query/rule references map to the reported techniques
              ({[...new Set(relatedRules.map(rule => rule.language))].join(', ')}).
            </p>
          ) : article.techniques.length > 0 ? (
            <p className="mt-2 text-xs text-slate-600">
              No indexed rule currently maps to these report techniques.
            </p>
          ) : null}
          {article.techniques.length > 0 && (
            <Link className="mt-2 inline-block text-sm font-semibold text-sky-800 hover:underline"
              to={`/rules?technique=${encodeURIComponent(article.techniques[0])}`}>
              Browse rules and queries for reported techniques
            </Link>
          )}
          {article.cves.length > 0 && relatedRules.length === 0 && article.techniques.length === 0 && (
            <p className="mt-2 text-xs text-slate-600">
              No ATT&amp;CK technique was extracted from this feed summary. Review the source report for behavioral details.
            </p>
          )}
        </section>
      )}
    </article>
  )
}
