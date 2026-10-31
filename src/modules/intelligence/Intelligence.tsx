import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useEpss, useKev, useNews } from '../../data/snapshots'
import type { NewsArticle } from '../../types'

const timeWindows = [
  { value: '1', label: 'Past 24 hours' },
  { value: '7', label: 'Past 7 days' },
  { value: '30', label: 'Past 30 days' },
]

function formatDate(value?: string): string {
  if (!value) return 'Date unavailable'
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? 'Date unavailable'
    : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export default function Intelligence() {
  const news = useNews()
  const kev = useKev()
  const epss = useEpss()
  const [search, setSearch] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [topicFilter, setTopicFilter] = useState('')
  const [timeWindow, setTimeWindow] = useState('7')
  const items = news.data?.items ?? []
  const kevCves = useMemo(
    () => new Set((kev.data?.vulnerabilities ?? []).map(item => item.cveID)),
    [kev.data]
  )
  const epssByCve = useMemo(
    () => new Map((epss.data ?? []).map(item => [item.cve, item.epss])),
    [epss.data]
  )
  const sources = news.data?.sources ?? []
  const topics = useMemo(
    () => [...new Set(items.flatMap(item => item.topics))].sort(),
    [items]
  )
  const filtered = useMemo(() => {
    const query = search.trim().toLocaleLowerCase()
    const cutoff = Date.now() - Number(timeWindow) * 24 * 60 * 60 * 1000
    return items.filter(item => {
      const searchable = `${item.title} ${item.cves.join(' ')} ${item.topics.join(' ')}`.toLocaleLowerCase()
      const withinWindow = Boolean(item.published_at && Date.parse(item.published_at) >= cutoff)
      return (!query || searchable.includes(query)) &&
        (!sourceFilter || item.source === sourceFilter) &&
        (!topicFilter || item.topics.includes(topicFilter)) &&
        withinWindow
    }).sort((a, b) => (b.published_at ?? '').localeCompare(a.published_at ?? ''))
  }, [items, search, sourceFilter, topicFilter, timeWindow])

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Research signals</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Intel leads</h1>
          <p className="mt-2 max-w-3xl text-slate-600">
            Recent security research with CVEs matched against local KEV/EPSS data and ATT&amp;CK references
            linked to coverage. Headlines only; open the source for full reporting.
          </p>
        </div>
        <Link className="button-secondary" to="/">Back to daily brief</Link>
      </header>

      <section aria-label="Feed status" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {sources.map(source => (
          <article className="rounded-xl border border-slate-200 bg-white p-4" key={source.id}>
            <div className="flex items-center justify-between gap-2">
              <h2 className="font-semibold text-slate-900">{source.name}</h2>
              <span className={source.status === 'ok' ? 'badge-success' : 'badge-warning'}>
                {source.status === 'ok' ? 'Current' : 'Using last snapshot'}
              </span>
            </div>
            <p className="mt-1 text-xs text-slate-600">
              {source.count} headlines · refreshed {formatDate(source.fetched_at)}
            </p>
          </article>
        ))}
        {sources.length === 0 && !news.isLoading && (
          <p className="rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-600">
            No feed status is available in this snapshot.
          </p>
        )}
      </section>

      {news.data?.warnings.length ? (
        <p className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900" role="status">
          One or more feeds could not be refreshed. Existing headlines are retained where available.
        </p>
      ) : null}
      {news.isError && (
        <p className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-900" role="alert">
          Could not load the news snapshot: {news.error.message}
        </p>
      )}

      <section aria-label="Filter research headlines" className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 sm:grid-cols-2 lg:grid-cols-4">
        <label className="lg:col-span-2">
          <span className="field-label">Search headlines, CVEs, and topics</span>
          <input className="field-input" type="search" value={search}
            onChange={event => setSearch(event.target.value)} placeholder="e.g. ransomware or CVE-2026-12345" />
        </label>
        <label>
          <span className="field-label">Source</span>
          <select className="field-input" value={sourceFilter} onChange={event => setSourceFilter(event.target.value)}>
            <option value="">All sources</option>
            {sources.map(source => <option key={source.id} value={source.id}>{source.name}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Time range</span>
          <select className="field-input" value={timeWindow} onChange={event => setTimeWindow(event.target.value)}>
            {timeWindows.map(window => <option key={window.value} value={window.value}>{window.label}</option>)}
          </select>
        </label>
        {topics.length > 0 && (
          <label className="sm:col-span-2 lg:col-span-4">
            <span className="field-label">Topic</span>
            <select className="field-input" value={topicFilter} onChange={event => setTopicFilter(event.target.value)}>
              <option value="">All topics</option>
              {topics.map(topic => <option key={topic}>{topic}</option>)}
            </select>
          </label>
        )}
      </section>

      <div className="flex items-center justify-between gap-3">
        <h2 className="text-xl font-bold text-slate-950">Recent research</h2>
        <span className="text-sm text-slate-500">{filtered.length} of {items.length} headlines</span>
      </div>

      {news.isLoading ? (
        <p className="rounded-xl border border-slate-200 bg-white p-6 text-slate-600">Loading research headlines…</p>
      ) : filtered.length > 0 ? (
        <section aria-label="Research headlines" className="grid gap-4 lg:grid-cols-2">
          {filtered.map(article => (
            <NewsCard
              article={article}
              key={article.url}
              isKev={cve => kevCves.has(cve)}
              getEpss={cve => epssByCve.get(cve)}
            />
          ))}
        </section>
      ) : (
        <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-6">
          <p className="font-medium text-slate-800">
            {items.length === 0 ? 'No headlines are available in this snapshot.' : 'No headlines match those filters.'}
          </p>
          <p className="mt-1 text-sm text-slate-600">
            Check feed status above or broaden the time range and filters.
          </p>
        </div>
      )}

      <p className="text-xs text-slate-500">
        Feed headlines are refreshed by GitHub Actions. CVE and technique matches are automatic and should be
        verified in the linked source. Snapshot built {formatDate(news.data?.built_at)}.
      </p>
    </div>
  )
}

function NewsCard({
  article,
  isKev,
  getEpss,
}: {
  article: NewsArticle
  isKev: (cve: string) => boolean
  getEpss: (cve: string) => number | undefined
}) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-xs font-semibold uppercase tracking-wide text-sky-800">
        {article.source_name} · {formatDate(article.published_at)}
      </p>
      <h3 className="mt-2 text-lg font-semibold leading-snug text-slate-950">
        <a href={article.url} target="_blank" rel="noreferrer" className="hover:text-sky-800 hover:underline">
          {article.title}
          <span className="sr-only"> (opens source in a new tab)</span>
        </a>
      </h3>
      {(article.topics.length > 0 || article.cves.length > 0 || article.techniques.length > 0) && (
        <div className="mt-3 flex flex-wrap gap-2">
          {article.topics.map(topic => <span className="badge-muted" key={topic}>{topic}</span>)}
          {article.cves.map(cve => {
            const score = getEpss(cve)
            return (
              <a className="badge" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`}
                key={cve} target="_blank" rel="noreferrer">
                {cve}{isKev(cve) ? ' · KEV' : ''}
                {score !== undefined ? ` · EPSS ${(score * 100).toFixed(1)}%` : ''}
              </a>
            )
          })}
          {article.techniques.map(technique => (
            <Link className="badge" key={technique} to="/coverage">{technique}</Link>
          ))}
        </div>
      )}
    </article>
  )
}
