import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useIocs, useKev, useManifest } from '../../data/snapshots'
import type { DataSourceStatus, IOCRecord } from '../../types'
import { classifyIndicators, extractIndicators, maskIndicator, toCsv, toStixBundle } from '../../utils/indicators'

const sample = `2026-10-31T12:00:00Z denied connection from 198.51.100.23 to suspicious.example
Alert: CVE-2026-12345 observed on host 10.1.2.3
File hash: 44d88612fea8a8f36de82e1278abb02f`

function csvEscape(value: string): string {
  return `"${value.replace(/"/g, '""')}"`
}

function snapshotCsv(records: IOCRecord[], sourceUrls: Map<string, string>): string {
  return [
    'value,type,category,sources,source_urls,source_weight,malware_family',
    ...records.map(record => [
      maskIndicator(record.value, record.type),
      record.type,
      record.category,
      record.sources.join('; '),
      record.sources.map(source => sourceUrls.get(source) ?? '').filter(Boolean).join('; '),
      record.source_weight?.toString() ?? '',
      record.malware_family ?? '',
    ].map(csvEscape).join(',')),
  ].join('\r\n')
}

export default function Triage() {
  const [input, setInput] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [displayLimit, setDisplayLimit] = useState(100)
  const iocs = useIocs()
  const kev = useKev()
  const manifest = useManifest()
  const corpus = iocs.data ?? []
  const extracted = useMemo(
    () => submitted ? extractIndicators(input) : [],
    [input, submitted]
  )
  const results = useMemo(
    () => classifyIndicators(extracted, corpus, kev.data),
    [extracted, corpus, kev.data]
  )
  const loading = iocs.isLoading || kev.isLoading
  const types = useMemo(() => [...new Set(corpus.map(record => record.type))].sort(), [corpus])
  const categories = useMemo(() => [...new Set(corpus.map(record => record.category))].sort(), [corpus])
  const sources = useMemo(
    () => [...new Set(corpus.flatMap(record => record.sources))].sort(),
    [corpus]
  )
  const iocSourceStatuses = useMemo<Array<[string, DataSourceStatus]>>(() => {
    const statuses: Array<[string, DataSourceStatus]> = []
    for (const [id, status] of Object.entries(manifest.data?.sources ?? {})) {
      if (typeof status === 'object' && status !== null && status.kind === 'ioc') {
        statuses.push([id, status])
      }
    }
    return statuses.sort((a, b) => (a[1].source ?? '').localeCompare(b[1].source ?? ''))
  }, [manifest.data])
  const sourceUrls = useMemo(
    () => new Map(iocSourceStatuses.flatMap(([, status]) =>
      status.source && status.url ? [[status.source, status.url] as const] : []
    )),
    [iocSourceStatuses]
  )
  const filteredIocs = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase()
    return corpus.filter(record => {
      const searchable = [
        record.value,
        record.category,
        record.malware_family ?? '',
        record.sources.join(' '),
      ].join(' ').toLocaleLowerCase()
      return (!needle || searchable.includes(needle)) &&
        (!typeFilter || record.type === typeFilter) &&
        (!categoryFilter || record.category === categoryFilter) &&
        (!sourceFilter || record.sources.includes(sourceFilter))
    })
  }, [corpus, search, typeFilter, categoryFilter, sourceFilter])

  function download(name: string, content: string, type: string) {
    const url = URL.createObjectURL(new Blob([content], { type }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = name
    anchor.click()
    URL.revokeObjectURL(url)
  }

  function exportStix() {
    download(
      'huntdeck-triage.stix.json',
      JSON.stringify(toStixBundle(results), null, 2),
      'application/json',
    )
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Browser-only analysis</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">IOC intelligence &amp; triage</h1>
          <p className="mt-2 text-slate-600">
            Browse the published indicator snapshot or compare indicators extracted from your own text.
          </p>
        </div>
        <Link className="button-secondary" to="/">Back to daily brief</Link>
      </header>

      <aside className="rounded-xl border border-sky-200 bg-sky-50 p-4 text-sm text-sky-950">
        Pasted text is processed in this browser and is never uploaded. Indicator matches are leads, not verdicts:
        verify context and source before acting. “Not in snapshot” does not mean safe. Indicators are masked in
        results and CSV exports; STIX export contains the original values and requires confirmation.
      </aside>

      <section aria-labelledby="ioc-snapshot-heading" className="space-y-4">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 id="ioc-snapshot-heading" className="text-xl font-bold text-slate-950">Published IOC snapshot</h2>
            <p className="mt-1 text-sm text-slate-600">
              {iocs.isLoading ? 'Loading indicator intelligence…' :
                `${corpus.length.toLocaleString()} indicators from ${iocSourceStatuses.length || sources.length} published feeds`}
            </p>
          </div>
          <button className="button-secondary" disabled={filteredIocs.length === 0}
            onClick={() => download(
              'huntdeck-ioc-snapshot.csv',
              snapshotCsv(filteredIocs, sourceUrls),
              'text/csv;charset=utf-8',
            )}>
            Export filtered snapshot CSV
          </button>
        </div>

        <p className="text-xs text-slate-500">
          The snapshot includes up to 100 unique indicators per feed, in feed order; a feed may not provide per-indicator
          timestamps. Fetch time is when HuntDeck collected a feed, not when an indicator was last observed.
          Source weight is a HuntDeck sorting heuristic, not source-provided confidence.
        </p>
        {iocSourceStatuses.length > 0 && (
          <ul aria-label="Published IOC feeds" className="grid gap-x-5 gap-y-2 rounded-xl border border-slate-200 bg-white px-4 py-3 sm:grid-cols-2">
            {iocSourceStatuses.map(([id, status]) => (
              <li className="flex min-w-0 items-center gap-2 text-xs" key={id}>
                <span className={status.status === 'ok' ? 'size-2 shrink-0 rounded-full bg-emerald-500' : 'size-2 shrink-0 rounded-full bg-amber-500'} aria-hidden="true" />
                {status.url ? (
                  <a className="truncate font-semibold text-sky-800 underline"
                    href={status.url} target="_blank" rel="noreferrer">
                    {status.source ?? id}
                  </a>
                ) : <span className="truncate font-semibold text-slate-800">{status.source ?? id}</span>}
                <span className="shrink-0 text-slate-500">
                  {status.published_count ?? Math.min(status.count, 100)} indexed
                  {status.count > (status.published_count ?? 100) &&
                    ` · ${status.count.toLocaleString()} in feed`}
                </span>
              </li>
            ))}
          </ul>
        )}
        <p className="text-right text-xs text-slate-500">
          <Link className="font-semibold text-sky-800 underline" to="/health">View all data source health</Link>
        </p>
        {manifest.data?.warnings && manifest.data.warnings.length > 0 && (
          <p className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900" role="status">
            Some data sources reported refresh warnings. Check each source status and verify indicator age before use.
          </p>
        )}

        <section aria-label="Filter published indicators"
          className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 sm:grid-cols-2 lg:grid-cols-4">
          <label className="lg:col-span-2">
            <span className="field-label">Search indicator, family, source, or category</span>
            <input className="field-input" type="search" value={search}
              onChange={event => {
                setSearch(event.target.value)
                setDisplayLimit(100)
              }} placeholder="e.g. address, domain, or malware family" />
          </label>
          <label>
            <span className="field-label">Indicator type</span>
            <select className="field-input" value={typeFilter} onChange={event => setTypeFilter(event.target.value)}>
              <option value="">All types</option>
              {types.map(type => <option key={type} value={type}>{type.toUpperCase()}</option>)}
            </select>
          </label>
          <label>
            <span className="field-label">Category</span>
            <select className="field-input" value={categoryFilter}
              onChange={event => setCategoryFilter(event.target.value)}>
              <option value="">All categories</option>
              {categories.map(category => <option key={category}>{category}</option>)}
            </select>
          </label>
          <label className="sm:col-span-2 lg:col-span-4">
            <span className="field-label">Source</span>
            <select className="field-input" value={sourceFilter}
              onChange={event => setSourceFilter(event.target.value)}>
              <option value="">All sources</option>
              {sources.map(source => <option key={source}>{source}</option>)}
            </select>
          </label>
        </section>

        {iocs.isError && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">
          Could not load the IOC snapshot: {iocs.error.message}
        </p>}
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
          <table className="w-full min-w-[850px] text-left text-sm">
            <thead className="bg-slate-100 text-xs uppercase text-slate-600">
              <tr>
                <th className="px-4 py-3">Indicator</th>
                <th className="px-4 py-3">Type / category</th>
                <th className="px-4 py-3">Threat context</th>
                <th className="px-4 py-3">Sources &amp; references</th>
                <th className="px-4 py-3">Source weight (heuristic)</th>
              </tr>
            </thead>
            <tbody>
              {filteredIocs.slice(0, displayLimit).map(record => (
                <tr className="border-t border-slate-100" key={`${record.type}:${record.value}`}>
                  <td className="break-all px-4 py-3 font-mono text-xs">
                    {maskIndicator(record.value, record.type)}
                  </td>
                  <td className="px-4 py-3">
                    <span className="badge">{record.type.toUpperCase()}</span>
                    <span className="ml-1 badge-muted">{record.category}</span>
                  </td>
                  <td className="px-4 py-3 text-slate-700">{record.malware_family ?? 'No family metadata'}</td>
                  <td className="px-4 py-3 text-xs text-slate-600">
                    <ul className="space-y-1">
                      {record.sources.map(source => (
                        <li key={source}>
                          {sourceUrls.has(source) ? (
                            <a className="font-medium text-sky-800 underline" href={sourceUrls.get(source)}
                              target="_blank" rel="noreferrer">{source}</a>
                          ) : source}
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td className="px-4 py-3">
                    {record.source_weight === undefined ? '—' : `${Math.round(record.source_weight * 100)}%`}
                  </td>
                </tr>
              ))}
              {!iocs.isLoading && filteredIocs.length === 0 && (
                <tr><td className="px-4 py-6 text-slate-600" colSpan={5}>No indicators match these filters.</td></tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-slate-600">
          <span>
            Showing {Math.min(displayLimit, filteredIocs.length).toLocaleString()} of {filteredIocs.length.toLocaleString()} matching indicators.
          </span>
          {displayLimit < filteredIocs.length && (
            <button className="button-secondary" onClick={() => setDisplayLimit(limit => limit + 100)}>
              Show 100 more
            </button>
          )}
        </div>
      </section>

      <section aria-labelledby="paste-triage-heading" className="space-y-4">
        <div>
          <h2 id="paste-triage-heading" className="text-xl font-bold text-slate-950">Check your own logs or text</h2>
          <p className="mt-1 text-sm text-slate-600">
            Extract indicators locally and match them against the published IOC and KEV snapshots.
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <label htmlFor="triage-input" className="field-label">Paste firewall logs, CSV, or JSON</label>
          <textarea
            id="triage-input"
            className="field-input min-h-48 resize-y font-mono"
            value={input}
            onChange={event => {
              setInput(event.target.value)
              setSubmitted(false)
            }}
            placeholder="Paste text to extract IPs, domains, URLs, hashes, CVEs, and ATT&CK technique IDs…"
            spellCheck={false}
          />
          <div className="mt-3 flex flex-wrap gap-2">
            <button className="button-primary" disabled={loading || input.trim().length === 0}
              onClick={() => setSubmitted(true)}>
              {loading ? 'Loading snapshots…' : 'Extract and check in browser'}
            </button>
            <button className="button-secondary" onClick={() => {
              setInput(sample)
              setSubmitted(false)
            }}>
              Load sample
            </button>
            <button className="button-secondary" onClick={() => {
              setInput('')
              setSubmitted(false)
            }}>
              Clear
            </button>
          </div>
          {(iocs.isError || kev.isError) && (
            <p className="mt-3 text-sm text-red-800" role="alert">
              Could not load local intelligence: {[iocs, kev].filter(q => q.isError).map(q => q.error.message).join(' ')}
            </p>
          )}
        </div>
      </section>

      {submitted && (
        <section aria-labelledby="results-heading">
          <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 id="results-heading" className="text-xl font-bold text-slate-950">Triage results</h2>
              <p className="mt-1 text-sm text-slate-600">{results.length} unique indicators extracted</p>
            </div>
            {results.length > 0 && (
              <div className="flex gap-2">
                <button className="button-secondary" onClick={() =>
                  download('huntdeck-triage.csv', toCsv(results), 'text/csv;charset=utf-8')}>
                  Export CSV
                </button>
                <button className="button-primary" onClick={() => {
                  if (window.confirm(
                    'STIX export contains the original, unmasked indicator values. Only continue if you intend to export these clear IOCs.'
                  )) exportStix()
                }}>Export raw STIX 2.1…</button>
              </div>
            )}
          </div>
          {results.length > 0 ? (
            <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
              <table className="w-full min-w-[700px] text-left text-sm">
                <thead className="bg-slate-100 text-xs uppercase text-slate-600">
                  <tr>
                    <th className="px-4 py-3">Indicator</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Verdict</th>
                    <th className="px-4 py-3">Evidence source</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map(result => (
                    <tr className="border-t border-slate-100" key={`${result.type}:${result.value}`}>
                      <td className="break-all px-4 py-3 font-mono text-xs">
                        {maskIndicator(result.value, result.type)}
                      </td>
                      <td className="px-4 py-3 uppercase">{result.type}</td>
                      <td className="px-4 py-3">
                        <span className={result.verdict === 'Not in snapshot' ? 'badge-muted' : 'badge-warning'}>
                          {result.verdict}
                        </span>
                        {result.malware_family && <span className="ml-2 text-xs text-slate-600">{result.malware_family}</span>}
                      </td>
                      <td className="px-4 py-3 text-slate-600">{result.sources.join(', ') || 'Local extraction'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="rounded-xl border border-dashed border-slate-300 p-5 text-slate-600">
              No supported indicators found in the pasted text.
            </div>
          )}
        </section>
      )}
      {manifest.isError && <p className="text-xs text-red-800" role="alert">
        Could not load source freshness metadata: {manifest.error.message}
      </p>}
    </div>
  )
}
