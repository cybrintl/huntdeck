import MiniSearch from 'minisearch'
import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useHypotheses } from '../../data/snapshots'
import type { HuntHypothesis } from '../../types'

export default function Library() {
  const query = useHypotheses()
  const [searchParams, setSearchParams] = useSearchParams()
  const [search, setSearch] = useState('')
  const techniqueFilter = searchParams.get('technique') ?? ''
  const [severityFilter, setSeverityFilter] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateThrough, setDateThrough] = useState('')
  const [reviewOnly, setReviewOnly] = useState(false)
  const hypotheses = query.data ?? []

  const searchIndex = useMemo(() => {
    const index = new MiniSearch({
      fields: ['title', 'why', 'hypothesis', 'tags', 'attack_techniques', 'origin'],
      storeFields: ['id'],
      searchOptions: { prefix: true, fuzzy: 0.2 },
    })
    index.addAll(hypotheses.map(hypothesis => ({
      ...hypothesis,
      attack_techniques: hypothesis.attack_techniques?.join(' '),
      tags: hypothesis.tags?.join(' '),
    })))
    return index
  }, [hypotheses])

  const techniques = useMemo(
    () => [...new Set(hypotheses.flatMap(hypothesis => hypothesis.attack_techniques ?? []))].sort(),
    [hypotheses]
  )

  const filtered = useMemo(() => {
    const searchResults = search.trim() ? searchIndex.search(search) : undefined
    const searchIds = searchResults ? new Set(searchResults.map(result => String(result.id))) : undefined
    const searchOrder = searchResults
      ? new Map(searchResults.map((result, index) => [String(result.id), index]))
      : undefined
    return hypotheses.filter(hypothesis => {
      const date = hypothesis.date?.slice(0, 10)
      return (!searchIds || searchIds.has(hypothesis.id)) &&
        (!techniqueFilter || hypothesis.attack_techniques?.includes(techniqueFilter)) &&
        (!severityFilter || hypothesis.severity === severityFilter) &&
        (!dateFrom || Boolean(date && date >= dateFrom)) &&
        (!dateThrough || Boolean(date && date <= dateThrough)) &&
        (!reviewOnly || hypothesis.needs_review)
    }).sort((a, b) => {
      if (searchOrder) return (searchOrder.get(a.id) ?? Number.MAX_SAFE_INTEGER) -
        (searchOrder.get(b.id) ?? Number.MAX_SAFE_INTEGER)
      return (b.date ?? '').localeCompare(a.date ?? '')
    })
  }, [hypotheses, searchIndex, search, techniqueFilter, severityFilter, dateFrom, dateThrough, reviewOnly])

  function setTechniqueFilter(value: string) {
    const nextParams = new URLSearchParams(searchParams)
    if (value) nextParams.set('technique', value)
    else nextParams.delete('technique')
    setSearchParams(nextParams, { replace: true })
  }

  function exportFilteredHunts() {
    const content = [
      '# HuntDeck Hunt Pack',
      '',
      `Exported ${new Date().toISOString()}`,
      '',
      ...filtered.flatMap(hypothesis => [
        `## ${hypothesis.title}`,
        '',
        hypothesis.hypothesis ?? '',
        '',
        ...(hypothesis.attack_techniques?.length
          ? [`ATT&CK: ${hypothesis.attack_techniques.join(', ')}`, '']
          : []),
        ...(hypothesis.log_sources?.length
          ? [`Telemetry: ${hypothesis.log_sources.join(', ')}`, '']
          : []),
        ...(hypothesis.investigation_steps?.length
          ? ['### Investigation steps', ...hypothesis.investigation_steps.map(step => `- ${step}`), '']
          : []),
        ...(hypothesis.validation_notes ? [`**Validation:** ${hypothesis.validation_notes}`, ''] : []),
        ...(hypothesis.false_positive_notes ? [`**Potential false positives:** ${hypothesis.false_positive_notes}`, ''] : []),
        ...Object.values(hypothesis.queries).flatMap(query =>
          query ? [`### ${query.language}`, '', '```', query.query, '```', ''] : []
        ),
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
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Hypotheses</h1>
          <p className="mt-2 text-slate-600">Search and adapt deterministic, copyable hunt ideas for your telemetry.</p>
        </div>
        <div className="flex gap-2">
          <button className="button-secondary" disabled={filtered.length === 0} onClick={exportFilteredHunts}>
            Export filtered hunt pack
          </button>
          <Link className="button-secondary" to="/">Back to daily brief</Link>
        </div>
      </header>

      <section aria-label="Hypothesis filters" className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 md:grid-cols-2 xl:grid-cols-6">
        <label className="xl:col-span-2">
          <span className="field-label">Search</span>
          <input className="field-input" type="search" value={search}
            onChange={event => setSearch(event.target.value)} placeholder="Title, technique, tag, or text" />
        </label>
        <label>
          <span className="field-label">ATT&CK technique</span>
          <select className="field-input" value={techniqueFilter} onChange={event => setTechniqueFilter(event.target.value)}>
            <option value="">All techniques</option>
            {techniques.map(technique => <option key={technique}>{technique}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Severity</span>
          <select className="field-input" value={severityFilter} onChange={event => setSeverityFilter(event.target.value)}>
            <option value="">All severities</option>
            {['critical', 'high', 'medium', 'low', 'informational'].map(severity => (
              <option key={severity} value={severity}>{severity}</option>
            ))}
          </select>
        </label>
        <label>
          <span className="field-label">Date from</span>
          <input className="field-input" type="date" value={dateFrom} onChange={event => setDateFrom(event.target.value)} />
        </label>
        <label>
          <span className="field-label">Date through</span>
          <input className="field-input" type="date" value={dateThrough} onChange={event => setDateThrough(event.target.value)} />
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-700 md:col-span-2 xl:col-span-6">
          <input type="checkbox" checked={reviewOnly} onChange={event => setReviewOnly(event.target.checked)} />
          Show only hypotheses needing review
        </label>
      </section>

      {query.isError && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">{query.error.message}</p>}

      <p className="text-sm text-slate-500">
        {query.isLoading ? 'Loading snapshot…' : `${filtered.length} of ${hypotheses.length} hypotheses`}
      </p>
      <section className="grid gap-4 xl:grid-cols-2" aria-label="Search results">
        {filtered.map(hypothesis => (
          <HypothesisCard
            key={hypothesis.id}
            hypothesis={hypothesis}
          />
        ))}
        {!query.isLoading && filtered.length === 0 && (
          <div className="rounded-xl border border-dashed border-slate-300 p-6 text-slate-600 xl:col-span-2">
            No hypotheses match those filters.
          </div>
        )}
      </section>
    </div>
  )
}

function HypothesisCard({
  hypothesis,
}: {
  hypothesis: HuntHypothesis
}) {
  const [activeQuery, setActiveQuery] = useState(Object.keys(hypothesis.queries)[0] ?? '')
  const [copyError, setCopyError] = useState('')
  const query = hypothesis.queries[activeQuery as keyof typeof hypothesis.queries]

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
