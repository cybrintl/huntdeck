import MiniSearch from 'minisearch'
import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useHypotheses, useRules } from '../../data/snapshots'
import type { DetectionRule, HuntHypothesis, QueryLanguage } from '../../types'

type HuntLibraryItem =
  | { kind: 'hypothesis'; id: string; title: string; hypothesis: HuntHypothesis }
  | { kind: 'query'; id: string; title: string; rule: DetectionRule }

const queryLanguageLabels: Record<QueryLanguage, string> = {
  kql: 'KQL',
  spl: 'SPL',
  elastic: 'Elastic KQL',
  sigma: 'Sigma',
}

function isQueryLanguage(value: string): value is QueryLanguage {
  return value === 'kql' || value === 'spl' || value === 'elastic' || value === 'sigma'
}

function ruleLanguageKey(language: string): QueryLanguage | undefined {
  if (/^kql\b/i.test(language)) return 'kql'
  if (/^spl\b/i.test(language)) return 'spl'
  if (/elastic/i.test(language)) return 'elastic'
  if (/sigma/i.test(language)) return 'sigma'
  return undefined
}

function itemLanguages(item: HuntLibraryItem): QueryLanguage[] {
  return item.kind === 'hypothesis'
    ? Object.keys(item.hypothesis.queries) as QueryLanguage[]
    : [ruleLanguageKey(item.rule.language)].filter((value): value is QueryLanguage => Boolean(value))
}

function itemTechniques(item: HuntLibraryItem): string[] {
  return item.kind === 'hypothesis'
    ? item.hypothesis.attack_techniques ?? []
    : item.rule.attack_techniques
}

function itemTactics(item: HuntLibraryItem): string[] {
  return item.kind === 'hypothesis'
    ? item.hypothesis.tactics ?? []
    : item.rule.tactics ?? []
}

function ruleDataSources(rule: DetectionRule): string[] {
  return rule.data_sources?.length ? rule.data_sources : rule.log_source ? [rule.log_source] : []
}

function itemDataSources(item: HuntLibraryItem): string[] {
  if (item.kind === 'hypothesis') return item.hypothesis.log_sources ?? []
  return ruleDataSources(item.rule)
}

function itemSeverity(item: HuntLibraryItem): string | undefined {
  return item.kind === 'hypothesis'
    ? item.hypothesis.severity
    : item.rule.severity?.toLocaleLowerCase()
}

export default function Library() {
  const query = useHypotheses()
  const rulesQuery = useRules()
  const [searchParams, setSearchParams] = useSearchParams()
  const [search, setSearch] = useState('')
  const techniqueFilter = searchParams.get('technique') ?? ''
  const [languageFilter, setLanguageFilter] = useState<QueryLanguage | ''>('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [tacticFilter, setTacticFilter] = useState('')
  const [dataSourceFilter, setDataSourceFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [contentTypeFilter, setContentTypeFilter] = useState('')
  const [reviewOnly, setReviewOnly] = useState(false)
  const [displayLimit, setDisplayLimit] = useState(50)
  const hypotheses = query.data ?? []
  const sourcedRules = useMemo(
    () => (rulesQuery.data ?? []).filter(rule =>
      rule.source_id !== 'huntdeck-hunts' && ruleLanguageKey(rule.language)
    ),
    [rulesQuery.data]
  )

  const items = useMemo<HuntLibraryItem[]>(() => [
    ...hypotheses.map(hypothesis => ({
      kind: 'hypothesis' as const,
      id: `hypothesis:${hypothesis.id}`,
      title: hypothesis.title,
      hypothesis,
    })),
    ...sourcedRules.map(rule => ({
      kind: 'query' as const,
      id: `query:${rule.id}`,
      title: rule.title,
      rule,
    })),
  ], [hypotheses, sourcedRules])

  const searchIndex = useMemo(() => {
    const index = new MiniSearch({
      fields: [
        'title', 'description', 'why', 'hypothesis', 'tags', 'attack_techniques',
        'tactics', 'data_sources', 'query_text', 'source_name',
      ],
      storeFields: ['id'],
      searchOptions: { prefix: true, fuzzy: 0.2 },
    })
    index.addAll(items.map(item => item.kind === 'hypothesis'
      ? {
        id: item.id,
        title: item.title,
        why: item.hypothesis.why,
        hypothesis: item.hypothesis.hypothesis,
        tags: item.hypothesis.tags?.join(' '),
        attack_techniques: itemTechniques(item).join(' '),
        tactics: itemTactics(item).join(' '),
        data_sources: itemDataSources(item).join(' '),
        query_text: Object.values(item.hypothesis.queries).map(entry => entry?.query ?? '').join(' '),
      }
      : {
        id: item.id,
        title: item.title,
        description: item.rule.description,
        attack_techniques: itemTechniques(item).join(' '),
        tactics: itemTactics(item).join(' '),
        data_sources: itemDataSources(item).join(' '),
        query_text: item.rule.query_text,
        source_name: item.rule.source_name,
      }))
    return index
  }, [items])

  const techniques = useMemo(
    () => [...new Set(items.flatMap(itemTechniques))].sort(),
    [items]
  )
  const languages = useMemo(
    () => [...new Set(items.flatMap(itemLanguages))].sort(),
    [items]
  )
  const sources = useMemo(
    () => [...new Set(items.filter(item => item.kind === 'query')
      .map(item => item.rule.source_name ?? item.rule.source_id ?? 'Other'))].sort(),
    [items]
  )
  const tactics = useMemo(
    () => [...new Set(items.flatMap(itemTactics))].sort(),
    [items]
  )
  const dataSources = useMemo(
    () => [...new Set(items.flatMap(itemDataSources))].sort(),
    [items]
  )
  const severities = useMemo(
    () => [...new Set(items.map(itemSeverity).filter((value): value is string => Boolean(value)))].sort(),
    [items]
  )

  const filtered = useMemo(() => {
    const searchResults = search.trim() ? searchIndex.search(search) : undefined
    const searchIds = searchResults ? new Set(searchResults.map(result => String(result.id))) : undefined
    const searchOrder = searchResults
      ? new Map(searchResults.map((result, index) => [String(result.id), index]))
      : undefined
    return items.filter(item => {
      return (!searchIds || searchIds.has(item.id)) &&
        (!techniqueFilter || itemTechniques(item).includes(techniqueFilter)) &&
        (!languageFilter || itemLanguages(item).includes(languageFilter)) &&
        (!sourceFilter || (item.kind === 'query' && (item.rule.source_name ?? item.rule.source_id) === sourceFilter)) &&
        (!tacticFilter || itemTactics(item).includes(tacticFilter)) &&
        (!dataSourceFilter || itemDataSources(item).includes(dataSourceFilter)) &&
        (!severityFilter || itemSeverity(item) === severityFilter) &&
        (!contentTypeFilter || item.kind === contentTypeFilter) &&
        (!reviewOnly || (item.kind === 'hypothesis' && item.hypothesis.needs_review))
    }).sort((a, b) => {
      if (searchOrder) return (searchOrder.get(a.id) ?? Number.MAX_SAFE_INTEGER) -
        (searchOrder.get(b.id) ?? Number.MAX_SAFE_INTEGER)
      return Number(a.kind !== 'hypothesis') - Number(b.kind !== 'hypothesis') ||
        a.title.localeCompare(b.title)
    })
  }, [
    items, searchIndex, search, techniqueFilter, languageFilter, sourceFilter,
    tacticFilter, dataSourceFilter, severityFilter, contentTypeFilter, reviewOnly,
  ])
  const authoredCount = items.filter(item => item.kind === 'hypothesis').length
  const sourcedContentCount = items.filter(item => item.kind === 'query').length
  const sourcedQueryCount = items.filter(item =>
    item.kind === 'query' && Boolean(item.rule.query_text)
  ).length
  const metadataOnlyCount = sourcedContentCount - sourcedQueryCount

  function setTechniqueFilter(value: string) {
    const nextParams = new URLSearchParams(searchParams)
    if (value) nextParams.set('technique', value)
    else nextParams.delete('technique')
    setSearchParams(nextParams, { replace: true })
  }

  function clearFilters() {
    setSearch('')
    setTechniqueFilter('')
    setLanguageFilter('')
    setSourceFilter('')
    setTacticFilter('')
    setDataSourceFilter('')
    setSeverityFilter('')
    setContentTypeFilter('')
    setReviewOnly(false)
    setDisplayLimit(50)
  }

  function exportFilteredHunts() {
    const content = [
      '# HuntDeck Hunt Pack',
      '',
      `Exported ${new Date().toISOString()}`,
      '',
      ...filtered.flatMap(item => item.kind === 'hypothesis'
        ? [
          `## ${item.hypothesis.title}`,
          '',
          item.hypothesis.hypothesis ?? '',
          '',
          ...(item.hypothesis.attack_techniques?.length
            ? [`ATT&CK: ${item.hypothesis.attack_techniques.join(', ')}`, '']
            : []),
          ...(item.hypothesis.log_sources?.length
            ? [`Telemetry: ${item.hypothesis.log_sources.join(', ')}`, '']
            : []),
          ...(item.hypothesis.investigation_steps?.length
            ? ['### Investigation steps', ...item.hypothesis.investigation_steps.map(step => `- ${step}`), '']
            : []),
          ...(item.hypothesis.validation_notes ? [`**Validation:** ${item.hypothesis.validation_notes}`, ''] : []),
          ...(item.hypothesis.false_positive_notes
            ? [`**Potential false positives:** ${item.hypothesis.false_positive_notes}`, '']
            : []),
          ...Object.values(item.hypothesis.queries).flatMap(query =>
            query ? [`### ${query.language}`, '', '```', query.query, '```', ''] : []
          ),
        ]
        : [
          `## ${item.rule.title}`,
          '',
          `Source: ${item.rule.source_name} · ${item.rule.language} · ${item.rule.license}`,
          '',
          item.rule.description ?? '',
          '',
          ...(item.rule.attack_techniques.length
            ? [`ATT&CK: ${item.rule.attack_techniques.join(', ')}`, '']
            : []),
          ...(itemDataSources(item).length ? [`Telemetry: ${itemDataSources(item).join(', ')}`, ''] : []),
          `Upstream: ${item.rule.url}`,
          '',
          ...(item.rule.query_text
            ? [`### ${item.rule.language}`, '', '```', item.rule.query_text, '```', '']
            : ['Query logic is available at the upstream source link above.', '']),
          ...(item.rule.known_false_positives
            ? [`**Known false positives:** ${item.rule.known_false_positives}`, '']
            : []),
        ]),
      '> Validate query fields and thresholds against your telemetry before use.',
    ].join('\n')
    const url = URL.createObjectURL(new Blob([content], { type: 'text/markdown' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `huntdeck-hunt-pack-${new Date().toISOString().slice(0, 10)}.md`
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Hunt library</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Hunt hypotheses &amp; query library</h1>
          <p className="mt-2 max-w-3xl text-slate-600">
            Explore HuntDeck-authored hypotheses and source-attributed KQL, SPL, and Sigma hunting content.
            Use the filters to find telemetry and platform-specific starting points.
          </p>
        </div>
        <div className="flex gap-2">
          <button className="button-secondary" disabled={filtered.length === 0} onClick={exportFilteredHunts}>
            Export filtered results
          </button>
          <Link className="button-secondary" to="/">Back to daily brief</Link>
        </div>
      </header>

      <section aria-label="Hunt library filters"
        className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 sm:grid-cols-2 xl:grid-cols-4">
        <label className="sm:col-span-2">
          <span className="field-label">Search hypotheses, titles, queries, techniques, and telemetry</span>
          <input className="field-input" type="search" value={search}
            onChange={event => {
              setSearch(event.target.value)
              setDisplayLimit(50)
            }} placeholder="e.g. PowerShell, T1003.001, DeviceProcessEvents, or AWS" />
        </label>
        <label>
          <span className="field-label">Content type</span>
          <select className="field-input" value={contentTypeFilter}
            onChange={event => setContentTypeFilter(event.target.value)}>
            <option value="">All hunting content</option>
            <option value="hypothesis">HuntDeck hypotheses</option>
            <option value="query">Sourced queries and detections</option>
          </select>
        </label>
        <label>
          <span className="field-label">Query language</span>
          <select className="field-input" value={languageFilter}
            onChange={event => setLanguageFilter(
              isQueryLanguage(event.target.value) ? event.target.value : ''
            )}>
            <option value="">All languages</option>
            {languages.map(language => (
              <option key={language} value={language}>{queryLanguageLabels[language]}</option>
            ))}
          </select>
        </label>
        <label>
          <span className="field-label">ATT&amp;CK technique</span>
          <select className="field-input" value={techniqueFilter} onChange={event => setTechniqueFilter(event.target.value)}>
            <option value="">All techniques</option>
            {techniques.map(technique => <option key={technique}>{technique}</option>)}
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
          <span className="field-label">Telemetry / data source</span>
          <select className="field-input" value={dataSourceFilter}
            onChange={event => setDataSourceFilter(event.target.value)}>
            <option value="">All telemetry</option>
            {dataSources.map(dataSource => <option key={dataSource}>{dataSource}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Severity</span>
          <select className="field-input" value={severityFilter} onChange={event => setSeverityFilter(event.target.value)}>
            <option value="">All severities</option>
            {severities.map(severity => (
              <option key={severity} value={severity}>{severity}</option>
            ))}
          </select>
        </label>
        <label>
          <span className="field-label">Query source</span>
          <select className="field-input" value={sourceFilter} onChange={event => setSourceFilter(event.target.value)}>
            <option value="">All sources</option>
            {sources.map(source => <option key={source}>{source}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 self-end pb-2 text-sm text-slate-700">
          <input type="checkbox" checked={reviewOnly} onChange={event => setReviewOnly(event.target.checked)} />
          Show only hypotheses needing review
        </label>
        <div className="flex items-end">
          <button className="button-secondary" onClick={clearFilters}>Clear filters</button>
        </div>
      </section>

      {(query.isError || rulesQuery.isError) && (
        <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">
          Could not load all hunting content: {[query, rulesQuery]
            .filter(result => result.isError).map(result => result.error.message).join(' ')}
        </p>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-slate-500">
          {query.isLoading || rulesQuery.isLoading
            ? 'Loading hunt and query indexes…'
            : `${filtered.length.toLocaleString()} of ${items.length.toLocaleString()} results · ${authoredCount} authored hypotheses · ${sourcedQueryCount.toLocaleString()} sourced queries · ${metadataOnlyCount.toLocaleString()} metadata-only Sigma entries`}
        </p>
        <p className="text-xs text-slate-500">
          External queries remain attributed to and linked to their original source.
        </p>
      </div>
      <section className="grid gap-4 xl:grid-cols-2" aria-label="Hunt library results">
        {filtered.slice(0, displayLimit).map(item => item.kind === 'hypothesis' ? (
          <HypothesisCard key={item.id} hypothesis={item.hypothesis} preferredQueryLanguage={languageFilter} />
        ) : (
          <SourcedQueryCard key={item.id} rule={item.rule} />
        ))}
        {!query.isLoading && !rulesQuery.isLoading && filtered.length === 0 && (
          <div className="rounded-xl border border-dashed border-slate-300 p-6 text-slate-600 xl:col-span-2">
            No hunting content matches those filters. Try broadening the platform, tactic, telemetry, or source filters.
          </div>
        )}
      </section>
      {displayLimit < filtered.length && (
        <div className="text-center">
          <button className="button-secondary" onClick={() => setDisplayLimit(limit => limit + 50)}>
            Show 50 more ({(filtered.length - displayLimit).toLocaleString()} remaining)
          </button>
        </div>
      )}
    </div>
  )
}

function SourcedQueryCard({ rule }: { rule: DetectionRule }) {
  const [copyError, setCopyError] = useState('')

  async function copyQuery() {
    if (!rule.query_text) return
    try {
      await navigator.clipboard.writeText(rule.query_text)
      setCopyError('')
    } catch (error) {
      setCopyError(error instanceof Error ? error.message : 'Clipboard access failed')
    }
  }

  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <span className="badge-muted">Sourced hunting content</span>
          <h2 className="mt-2 text-lg font-semibold text-slate-950">{rule.title}</h2>
          <p className="mt-1 text-xs text-slate-500">{rule.source_name} · {rule.id}</p>
        </div>
        <span className="badge">{rule.language}</span>
        <span className="badge-muted">{rule.license}</span>
      </div>
      {rule.description && <p className="mt-3 text-sm leading-relaxed text-slate-600">{rule.description}</p>}
      <div className="mt-3 flex flex-wrap gap-2">
        {rule.attack_techniques.map(technique => <span className="badge" key={technique}>{technique}</span>)}
        {(rule.tactics ?? []).slice(0, 4).map(tactic => <span className="badge-muted" key={tactic}>{tactic}</span>)}
      </div>
      {ruleDataSources(rule).length > 0 && (
        <p className="mt-3 text-xs text-slate-600">
          <strong>Telemetry:</strong> {ruleDataSources(rule).join(', ')}
        </p>
      )}
      {rule.known_false_positives && (
        <p className="mt-2 text-xs leading-relaxed text-slate-600">
          <strong>False-positive context:</strong> {rule.known_false_positives}
        </p>
      )}
      {rule.query_text ? (
      <div className="mt-4">
        <div className="mb-1 flex justify-end">
          <button className="text-xs font-semibold text-sky-800 hover:underline" onClick={() => void copyQuery()}>
            Copy {rule.language} query
          </button>
        </div>
        <pre className="max-h-96 overflow-auto rounded-lg bg-slate-950 p-3 text-sm text-slate-100">
          <code>{rule.query_text}</code>
        </pre>
      </div>
      ) : (
        <p className="mt-4 rounded-lg bg-slate-50 p-3 text-sm text-slate-600">
          This Sigma entry is indexed as metadata only. Open the source rule to review its detection logic.
        </p>
      )}
      {copyError && <p className="mt-2 text-xs text-red-700" role="alert">{copyError}</p>}
      <a className="mt-4 inline-block border-t border-slate-100 pt-4 text-sm font-semibold text-sky-800 underline"
        href={rule.url} target="_blank" rel="noreferrer">Review upstream content and license</a>
    </article>
  )
}

function HypothesisCard({
  hypothesis,
  preferredQueryLanguage,
}: {
  hypothesis: HuntHypothesis
  preferredQueryLanguage: QueryLanguage | ''
}) {
  const [activeQuery, setActiveQuery] = useState('')
  const [copyError, setCopyError] = useState('')
  const activeQueryKey = activeQuery ||
    (preferredQueryLanguage && hypothesis.queries[preferredQueryLanguage] ? preferredQueryLanguage : '') ||
    Object.keys(hypothesis.queries)[0] ||
    ''
  const query = Object.entries(hypothesis.queries).find(([key]) => key === activeQueryKey)?.[1]

  async function copyQuery() {
    if (!query) return
    try {
      await navigator.clipboard.writeText(query.query)
      setCopyError('')
    } catch (error) {
      setCopyError(error instanceof Error ? error.message : 'Clipboard access failed')
    }
  }

  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-950">{hypothesis.title}</h2>
          <p className="mt-1 text-xs text-slate-500">{hypothesis.id}{hypothesis.origin ? ` · ${hypothesis.origin}` : ''}</p>
        </div>
        {hypothesis.needs_review && <span className="badge-warning">Review recommended</span>}
      </div>

      {hypothesis.hypothesis && <p className="mt-4 text-sm text-slate-700">{hypothesis.hypothesis}</p>}
      {hypothesis.why && <p className="mt-2 text-sm text-slate-600">{hypothesis.why}</p>}
      <div className="mt-3 flex flex-wrap gap-2">
        {(hypothesis.attack_techniques ?? []).map(technique => <span className="badge" key={technique}>{technique}</span>)}
        {(hypothesis.tags ?? []).map(tag => <span className="badge-muted" key={tag}>{tag}</span>)}
        <span className="badge">{hypothesis.severity ?? 'Unrated'}</span>
      </div>
      {hypothesis.log_sources && hypothesis.log_sources.length > 0 && (
        <p className="mt-3 text-xs text-slate-600"><strong>Log sources:</strong> {hypothesis.log_sources.join(', ')}</p>
      )}
      {hypothesis.investigation_steps && hypothesis.investigation_steps.length > 0 && (
        <section className="mt-4 rounded-lg bg-slate-50 p-3">
          <h3 className="text-sm font-semibold text-slate-900">Investigation pivots</h3>
          <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-slate-700">
            {hypothesis.investigation_steps.map(step => <li key={step}>{step}</li>)}
          </ol>
        </section>
      )}
      {(hypothesis.validation_notes || hypothesis.false_positive_notes) && (
        <div className="mt-3 space-y-2 text-xs leading-relaxed text-slate-600">
          {hypothesis.validation_notes && <p><strong>Validation:</strong> {hypothesis.validation_notes}</p>}
          {hypothesis.false_positive_notes && <p><strong>Potential false positives:</strong> {hypothesis.false_positive_notes}</p>}
        </div>
      )}

      <div className="mt-4">
        <div className="flex flex-wrap gap-2" role="tablist" aria-label="Query language">
          {Object.entries(hypothesis.queries).map(([key, item]) => item && (
            <button key={key} role="tab" aria-selected={activeQuery === key}
              className={activeQuery === key ? 'query-tab query-tab-active' : 'query-tab'}
              onClick={() => setActiveQuery(key)}>
              {item.language}
            </button>
          ))}
        </div>
        {query && (
          <div className="mt-2">
            <div className="mb-1 flex justify-end">
              <button className="text-xs font-semibold text-sky-800 hover:underline" onClick={() => void copyQuery()}>
                Copy query
              </button>
            </div>
            <pre className="overflow-x-auto rounded-lg bg-slate-950 p-3 text-sm text-slate-100">
              <code>{query.query}</code>
            </pre>
            {'sigma_link' in query && query.sigma_link && (
              <a className="mt-2 inline-block text-xs text-sky-800 underline" href={query.sigma_link}
                target="_blank" rel="noreferrer">View Sigma source</a>
            )}
          </div>
        )}
        {copyError && <p className="mt-2 text-xs text-red-700" role="alert">{copyError}</p>}
      </div>

    </article>
  )
}
