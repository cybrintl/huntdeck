import MiniSearch from 'minisearch'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useHypotheses } from '../../data/snapshots'
import type { HuntHypothesis, HuntState, HuntStatus, JournalEntry } from '../../types'
import { getHuntStates, saveHuntState, saveJournalEntry } from '../../storage/user-store'

const statuses: { value: HuntStatus; label: string }[] = [
  { value: 'backlog', label: 'Backlog' },
  { value: 'hunting', label: 'Hunting' },
  { value: 'covered', label: 'Covered' },
  { value: 'not_relevant', label: 'Not relevant' },
]

export default function Library() {
  const query = useHypotheses()
  const [search, setSearch] = useState('')
  const [techniqueFilter, setTechniqueFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateThrough, setDateThrough] = useState('')
  const [reviewOnly, setReviewOnly] = useState(false)
  const [states, setStates] = useState<Record<string, HuntState>>({})
  const [storeError, setStoreError] = useState('')
  const [notice, setNotice] = useState('')
  const hypotheses = query.data ?? []

  useEffect(() => {
    let active = true
    getHuntStates().then(items => {
      if (active) setStates(Object.fromEntries(items.map(item => [item.id, item])))
    }).catch(error => {
      if (active) setStoreError(error instanceof Error ? error.message : 'Could not load local hunt state')
    })
    return () => { active = false }
  }, [])

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
      const state = states[hypothesis.id]?.status ?? 'backlog'
      const date = hypothesis.date?.slice(0, 10)
      return (!searchIds || searchIds.has(hypothesis.id)) &&
        (!techniqueFilter || hypothesis.attack_techniques?.includes(techniqueFilter)) &&
        (!severityFilter || hypothesis.severity === severityFilter) &&
        (!dateFrom || Boolean(date && date >= dateFrom)) &&
        (!dateThrough || Boolean(date && date <= dateThrough)) &&
        (!statusFilter || state === statusFilter) &&
        (!reviewOnly || (hypothesis.needs_review && !states[hypothesis.id]?.reviewed))
    }).sort((a, b) => {
      if (searchOrder) return (searchOrder.get(a.id) ?? Number.MAX_SAFE_INTEGER) -
        (searchOrder.get(b.id) ?? Number.MAX_SAFE_INTEGER)
      return (b.date ?? '').localeCompare(a.date ?? '')
    })
  }, [hypotheses, searchIndex, search, techniqueFilter, severityFilter, dateFrom, dateThrough, statusFilter, reviewOnly, states])

  async function updateState(hypothesis: HuntHypothesis, status: HuntStatus, note: string, reviewed?: boolean) {
    const state: HuntState = {
      id: hypothesis.id,
      status,
      note,
      updated_at: new Date().toISOString(),
      reviewed: reviewed ?? states[hypothesis.id]?.reviewed,
    }
    try {
      await saveHuntState(state)
      setStates(previous => ({ ...previous, [state.id]: state }))
      setStoreError('')
      setNotice(`Saved status for “${hypothesis.title}” on this device.`)
    } catch (error) {
      setStoreError(error instanceof Error ? error.message : 'Could not save local hunt state')
    }
  }

  async function logHunt(hypothesis: HuntHypothesis) {
    const entry: JournalEntry = {
      id: crypto.randomUUID(),
      hypothesis_id: hypothesis.id,
      title: hypothesis.title,
      date: new Date().toISOString(),
      analyst: '',
      result: 'nothing_found',
      notes: '',
      evidence: '',
    }
    try {
      await saveJournalEntry(entry)
      setNotice(`Logged “${hypothesis.title}” locally. Journal entries stay in this browser.`)
      setStoreError('')
    } catch (error) {
      setStoreError(error instanceof Error ? error.message : 'Could not save this hunt locally')
    }
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Hunt library</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Hypotheses</h1>
          <p className="mt-2 text-slate-600">Search deterministic, copyable hunts and track your local progress.</p>
        </div>
        <Link className="button-secondary" to="/">Back to daily brief</Link>
      </header>

      <section aria-label="Hypothesis filters" className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 md:grid-cols-2 xl:grid-cols-7">
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
          <span className="field-label">Hunt status</span>
          <select className="field-input" value={statusFilter} onChange={event => setStatusFilter(event.target.value)}>
            <option value="">All statuses</option>
            {statuses.map(status => <option key={status.value} value={status.value}>{status.label}</option>)}
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
        <label className="flex items-center gap-2 text-sm text-slate-700 md:col-span-2 xl:col-span-7">
          <input type="checkbox" checked={reviewOnly} onChange={event => setReviewOnly(event.target.checked)} />
          Show only hypotheses needing review
        </label>
      </section>

      {notice && <p className="rounded-lg bg-emerald-50 p-3 text-sm text-emerald-900" role="status">{notice}</p>}
      {storeError && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">{storeError}</p>}
      {query.isError && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">{query.error.message}</p>}

      <p className="text-sm text-slate-500">
        {query.isLoading ? 'Loading snapshot…' : `${filtered.length} of ${hypotheses.length} hypotheses`}
      </p>
      <section className="grid gap-4 xl:grid-cols-2" aria-label="Search results">
        {filtered.map(hypothesis => (
          <HypothesisCard
            key={hypothesis.id}
            hypothesis={hypothesis}
            state={states[hypothesis.id]}
            onSave={updateState}
            onLog={logHunt}
            onPromote={async item => {
              await updateState(item, states[item.id]?.status ?? 'backlog', states[item.id]?.note ?? '', true)
              setNotice(`“${item.title}” marked reviewed on this device.`)
            }}
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
  state,
  onSave,
  onLog,
  onPromote,
}: {
  hypothesis: HuntHypothesis
  state?: HuntState
  onSave: (hypothesis: HuntHypothesis, status: HuntStatus, note: string, reviewed?: boolean) => Promise<void>
  onLog: (hypothesis: HuntHypothesis) => Promise<void>
  onPromote: (hypothesis: HuntHypothesis) => Promise<void>
}) {
  const [status, setStatus] = useState<HuntStatus>(state?.status ?? 'backlog')
  const [note, setNote] = useState(state?.note ?? '')
  const [activeQuery, setActiveQuery] = useState(Object.keys(hypothesis.queries)[0] ?? '')
  const [copyError, setCopyError] = useState('')
  const query = hypothesis.queries[activeQuery as keyof typeof hypothesis.queries]

  useEffect(() => {
    setStatus(state?.status ?? 'backlog')
    setNote(state?.note ?? '')
  }, [state])

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
        {hypothesis.needs_review && !state?.reviewed && <span className="badge-warning">AI draft · needs review</span>}
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

      <div className="mt-5 grid gap-3 border-t border-slate-100 pt-4 sm:grid-cols-2">
        <label>
          <span className="field-label">My hunt status</span>
          <select className="field-input" value={status} onChange={event => setStatus(event.target.value as HuntStatus)}>
            {statuses.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Private note (stored on this device)</span>
          <input className="field-input" value={note} onChange={event => setNote(event.target.value)} maxLength={500}
            placeholder="Optional analyst note" />
        </label>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <button className="button-primary" onClick={() => void onSave(hypothesis, status, note)}>Save local status</button>
        <button className="button-secondary" onClick={() => void onLog(hypothesis)}>Log this hunt</button>
        {hypothesis.needs_review && !state?.reviewed && (
          <button className="button-secondary" onClick={() => void onPromote(hypothesis)}>Mark reviewed locally</button>
        )}
        {hypothesis.needs_review && state?.reviewed && <span className="badge-success">Reviewed on this device</span>}
      </div>
    </article>
  )
}
