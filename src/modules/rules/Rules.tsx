import MiniSearch from 'minisearch'
import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useHypotheses, useManifest, useRules } from '../../data/snapshots'
import type { DataSourceStatus, DetectionRule } from '../../types'

function platformLabel(language: string): string {
  if (/^kql\b/i.test(language)) return 'KQL'
  if (/^spl\b/i.test(language)) return 'SPL'
  if (/elastic/i.test(language)) return 'Elastic KQL'
  if (/sigma/i.test(language)) return 'Sigma'
  return language
}

export default function Rules() {
  const query = useRules()
  const hypothesesQuery = useHypotheses()
  const manifest = useManifest()
  const [searchParams, setSearchParams] = useSearchParams()
  const [search, setSearch] = useState('')
  const [language, setLanguage] = useState('')
  const [source, setSource] = useState('')
  const [technique, setTechnique] = useState(() => searchParams.get('technique') ?? '')
  const [tactic, setTactic] = useState('')
  const [severity, setSeverity] = useState('')
  const [telemetry, setTelemetry] = useState('')
  const [error, setError] = useState('')
  const [displayLimit, setDisplayLimit] = useState(50)
  const rules = useMemo(() => {
    const indexed = query.data ?? []
    const authored: DetectionRule[] = (hypothesesQuery.data ?? []).flatMap(hypothesis =>
      Object.entries(hypothesis.queries).flatMap(([key, item]) => {
        if (!item) return []
        const platform = key === 'kql' ? 'KQL' :
          key === 'spl' ? 'SPL' :
            key === 'elastic' ? 'Elastic KQL' : 'Sigma'
        return [{
          id: `huntdeck:${hypothesis.id}:${key}`,
          source_id: 'huntdeck-hunts',
          source_name: 'HuntDeck Hunt Library',
          title: `${hypothesis.title} · ${platform}`,
          description: hypothesis.hypothesis ?? hypothesis.why,
          attack_techniques: hypothesis.attack_techniques ?? [],
          tactics: hypothesis.tactics ?? [],
          log_source: hypothesis.log_sources?.join(', '),
          data_sources: hypothesis.log_sources ?? [],
          language: platform,
          license: 'Apache-2.0',
          url: '',
          query_text: item.query,
          severity: hypothesis.severity,
          internal_path: hypothesis.attack_techniques?.[0]
            ? `/hypotheses?technique=${encodeURIComponent(hypothesis.attack_techniques[0])}`
            : '/hypotheses',
        } satisfies DetectionRule]
      })
    )
    return [...indexed, ...authored]
  }, [query.data, hypothesesQuery.data])

  const index = useMemo(() => {
    const miniSearch = new MiniSearch({
      fields: [
        'id',
        'title',
        'description',
        'attack_techniques',
        'tactics',
        'log_source',
        'data_sources',
        'language',
        'severity',
        'source_name',
        'query_text',
      ],
      storeFields: ['id'],
      searchOptions: { prefix: true, fuzzy: 0.2 },
    })
    miniSearch.addAll(rules.map(rule => ({
      ...rule,
      attack_techniques: rule.attack_techniques.join(' '),
      tactics: rule.tactics?.join(' '),
      data_sources: rule.data_sources?.join(' '),
    })))
    return miniSearch
  }, [rules])

  const languages = useMemo(
    () => [...new Set(rules.map(rule => platformLabel(rule.language)))].sort(),
    [rules]
  )
  const sources = useMemo(
    () => [...new Set(rules.map(rule => rule.source_name ?? rule.source_id ?? 'Other'))].sort(),
    [rules]
  )
  const techniques = useMemo(
    () => [...new Set(rules.flatMap(rule => rule.attack_techniques))].sort(),
    [rules]
  )
  const severities = useMemo(
    () => [...new Set(rules.map(rule => rule.severity).filter((value): value is string => Boolean(value)))].sort(),
    [rules]
  )
  const tactics = useMemo(
    () => [...new Set(rules.flatMap(rule => rule.tactics ?? []))].sort(),
    [rules]
  )
  const dataSources = useMemo(
    () => [...new Set(rules.flatMap(rule => rule.data_sources ?? (rule.log_source ? [rule.log_source] : [])))].sort(),
    [rules]
  )
  const indexStatuses = useMemo<Array<[string, DataSourceStatus]>>(() => {
    const statuses: Array<[string, DataSourceStatus]> = []
    for (const [id, status] of Object.entries(manifest.data?.sources ?? {})) {
      if (typeof status === 'object' && status !== null && status.kind === 'detection') {
        statuses.push([id, status])
      }
    }
    return statuses.sort((a, b) => (a[1].source ?? '').localeCompare(b[1].source ?? ''))
  }, [manifest.data])
  const sourceWarnings = (manifest.data?.warnings ?? []).filter(warning =>
    ['sigma', 'microsoft-sentinel', 'splunk-security-content', 'rule-index']
      .some(sourceId => warning.startsWith(`${sourceId}:`))
  )
  const filtered = useMemo(() => {
    const ids = search.trim() ? new Set(index.search(search).map(result => String(result.id))) : undefined
    return rules.filter(rule =>
      (!ids || ids.has(rule.id)) &&
      (!language || platformLabel(rule.language) === language) &&
      (!source || (rule.source_name ?? rule.source_id ?? 'Other') === source) &&
      (!technique || rule.attack_techniques.includes(technique)) &&
      (!tactic || rule.tactics?.includes(tactic)) &&
      (!severity || rule.severity === severity) &&
      (!telemetry || (rule.data_sources ?? []).includes(telemetry) || rule.log_source === telemetry)
    )
  }, [rules, index, search, language, source, technique, tactic, severity, telemetry])

  function updateTechnique(value: string) {
    const nextParams = new URLSearchParams(searchParams)
    if (value) nextParams.set('technique', value)
    else nextParams.delete('technique')
    setSearchParams(nextParams, { replace: true })
    setTechnique(value)
    setDisplayLimit(50)
  }

  function clearFilters() {
    setSearch('')
    setLanguage('')
    setSource('')
    updateTechnique('')
    setTactic('')
    setSeverity('')
    setTelemetry('')
    setDisplayLimit(50)
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Detection engineering</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Hunt queries &amp; rules</h1>
          <p className="mt-2 max-w-3xl text-slate-600">
            Search native KQL, Splunk SPL, Elastic KQL, and Sigma content from public sources and HuntDeck’s
            authored hunt templates. Verify platform fields, macros, and data availability before use.
          </p>
        </div>
        <Link className="button-secondary" to="/">Back to daily brief</Link>
      </header>

      <section aria-label="Filter rules"
        className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 sm:grid-cols-2 lg:grid-cols-3">
        <label className="sm:col-span-2 lg:col-span-3">
          <span className="field-label">Search titles, descriptions, queries, techniques, or telemetry</span>
          <input className="field-input" type="search" value={search}
            onChange={event => {
              setSearch(event.target.value)
              setDisplayLimit(50)
            }}
            placeholder="e.g. LSASS, T1003.001, DeviceProcessEvents, or command line" />
        </label>
        <label>
          <span className="field-label">Query language</span>
          <select className="field-input" value={language} onChange={event => {
            setLanguage(event.target.value)
            setDisplayLimit(50)
          }}>
            <option value="">All languages</option>
            {languages.map(item => <option key={item}>{item}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Source</span>
          <select className="field-input" value={source} onChange={event => {
            setSource(event.target.value)
            setDisplayLimit(50)
          }}>
            <option value="">All sources</option>
            {sources.map(item => <option key={item}>{item}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">ATT&amp;CK technique</span>
          <select className="field-input" value={technique} onChange={event => updateTechnique(event.target.value)}>
            <option value="">All techniques</option>
            {techniques.map(item => <option key={item}>{item}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">ATT&amp;CK tactic</span>
          <select className="field-input" value={tactic} onChange={event => {
            setTactic(event.target.value)
            setDisplayLimit(50)
          }}>
            <option value="">All tactics</option>
            {tactics.map(item => <option key={item}>{item}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Severity</span>
          <select className="field-input" value={severity} onChange={event => {
            setSeverity(event.target.value)
            setDisplayLimit(50)
          }}>
            <option value="">All severities</option>
            {severities.map(item => <option key={item}>{item}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Telemetry / data source</span>
          <select className="field-input" value={telemetry} onChange={event => {
            setTelemetry(event.target.value)
            setDisplayLimit(50)
          }}>
            <option value="">All telemetry</option>
            {dataSources.map(item => <option key={item}>{item}</option>)}
          </select>
        </label>
        <div className="flex items-end">
          <button className="button-secondary" onClick={clearFilters}>Clear filters</button>
        </div>
      </section>

      {indexStatuses.length > 0 && (
        <section aria-label="Detection source status" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {indexStatuses.map(([id, status]) => (
            <article className="rounded-xl border border-slate-200 bg-white p-4" key={id}>
              <div className="flex items-center justify-between gap-2">
                <h2 className="font-semibold text-slate-900">{status.source ?? id}</h2>
                <span className={status.status === 'ok' ? 'badge-success' : 'badge-warning'}>
                  {status.status === 'ok' ? 'Current' : 'Using last-good index'}
                </span>
              </div>
              <p className="mt-1 text-xs text-slate-600">
                {status.count.toLocaleString()} indexed · fetched {new Date(status.fetched_at).toLocaleString()}
              </p>
            </article>
          ))}
        </section>
      )}
      {(query.isError || hypothesesQuery.isError) && (
        <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">
          Could not load all rule content: {[query, hypothesesQuery]
            .filter(result => result.isError).map(result => result.error.message).join(' ')}
        </p>
      )}
      {error && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">{error}</p>}
      {manifest.isError && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">
        Could not load detection-source status: {manifest.error.message}
      </p>}
      {sourceWarnings.length > 0 && <p className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900" role="status">
        Detection index warnings: {sourceWarnings.join(' ')}
      </p>}
      <p className="text-sm text-slate-500">
        {query.isLoading || hypothesesQuery.isLoading
          ? 'Loading detection content…'
          : `${filtered.length.toLocaleString()} matching · showing ${Math.min(displayLimit, filtered.length).toLocaleString()} of ${rules.length.toLocaleString()} rules and queries`}
      </p>

      {filtered.length > 0 ? (
        <section className="grid gap-4 xl:grid-cols-2" aria-label="Detection rule results">
          {filtered.slice(0, displayLimit).map(rule => (
            <article key={rule.id} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h2 className="font-semibold text-slate-950">{rule.title}</h2>
                  <p className="mt-1 text-xs text-slate-500">{rule.source_name ?? rule.source_id} · {rule.id}</p>
                </div>
                <span className="badge-muted">{rule.license}</span>
              </div>
              {rule.description && <p className="mt-3 text-sm leading-relaxed text-slate-600">{rule.description}</p>}
              <div className="mt-3 flex flex-wrap gap-2">
                <span className="badge">{platformLabel(rule.language)}</span>
                {rule.severity && <span className="badge">{rule.severity}</span>}
                {rule.attack_techniques.map(item => <span className="badge" key={item}>{item}</span>)}
                {(rule.tactics ?? []).slice(0, 4).map(item => <span className="badge-muted" key={item}>{item}</span>)}
              </div>
              {rule.log_source && <p className="mt-3 text-sm text-slate-600">
                <strong>Telemetry:</strong> {rule.log_source}
              </p>}
              {rule.known_false_positives && <p className="mt-2 text-sm text-slate-600">
                <strong>False-positive context:</strong> {rule.known_false_positives}
              </p>}
              {rule.query_text ? (
                <div className="mt-3">
                  <div className="mb-1 flex justify-end">
                    <button className="text-xs font-semibold text-sky-800 hover:underline"
                      onClick={() => navigator.clipboard.writeText(rule.query_text ?? '')
                        .then(() => setError(''))
                        .catch(reason => setError(reason instanceof Error ? reason.message : 'Clipboard access failed'))}>
                      Copy query
                    </button>
                  </div>
                  <pre className="overflow-x-auto rounded-lg bg-slate-950 p-3 text-sm text-slate-100">
                    <code>{rule.query_text}</code>
                  </pre>
                </div>
              ) : (
                <p className="mt-3 rounded-lg bg-slate-50 p-3 text-sm text-slate-600">
                  This Sigma entry is indexed as metadata. Open the source rule to review its detection logic.
                </p>
              )}
              {rule.internal_path ? (
                <Link className="mt-4 inline-block border-t border-slate-100 pt-4 text-sm font-semibold text-sky-800 underline"
                  to={rule.internal_path}>Open related HuntDeck hypothesis</Link>
              ) : (
                <a className="mt-4 inline-block border-t border-slate-100 pt-4 text-sm font-semibold text-sky-800 underline"
                  href={rule.url} target="_blank" rel="noreferrer">Open source content</a>
              )}
            </article>
          ))}
        </section>
      ) : (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white p-6">
          <h2 className="font-semibold text-slate-900">
            {query.isLoading || hypothesesQuery.isLoading
              ? 'Loading detection content…'
              : rules.length === 0 ? 'No detection content is available' : 'No matching rules or queries'}
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            {rules.length === 0
              ? 'Run the Build Data workflow to refresh the KQL, SPL, and Sigma indexes.'
              : 'Try a different query, platform, source, ATT&CK technique, severity, or telemetry filter.'}
          </p>
        </div>
      )}
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
