import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useManifest, useNews } from '../../data/snapshots'
import type { DataSourceStatus } from '../../types'

interface HealthSource extends DataSourceStatus {
  id: string
  area: string
}

const primarySources: Array<{
  id: string
  kind: NonNullable<DataSourceStatus['kind']>
  source: string
  url: string
  area: string
  countKey: 'kev' | 'epss' | 'techniques'
}> = [
  {
    id: 'kev',
    kind: 'vulnerability',
    source: 'CISA Known Exploited Vulnerabilities',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    area: 'Vulnerability intelligence',
    countKey: 'kev',
  },
  {
    id: 'epss',
    kind: 'vulnerability',
    source: 'FIRST EPSS',
    url: 'https://www.first.org/epss/',
    area: 'Vulnerability intelligence',
    countKey: 'epss',
  },
  {
    id: 'attack',
    kind: 'attack',
    source: 'MITRE ATT&CK Enterprise',
    url: 'https://attack.mitre.org/',
    area: 'ATT&CK coverage',
    countKey: 'techniques',
  },
]

const areaLabels: Record<string, string> = {
  ioc: 'IOC intelligence',
  detection: 'Detection content',
  news: 'Threat intelligence & news',
  vulnerability: 'Vulnerability intelligence',
  attack: 'ATT&CK coverage',
}

const freshnessWindowMs = 48 * 60 * 60 * 1000

function sourceState(source: DataSourceStatus): 'current' | 'stale' | 'unknown' {
  if (source.status === 'unknown') return 'unknown'
  const timestamp = Date.parse(source.fetched_at)
  if (
    source.status === 'stale' ||
    !Number.isFinite(timestamp) ||
    Date.now() - timestamp > freshnessWindowMs
  ) {
    return 'stale'
  }
  return 'current'
}

function stateLabel(state: ReturnType<typeof sourceState>): string {
  if (state === 'current') return 'Current'
  if (state === 'stale') return 'Stale / last good'
  return 'Status unavailable'
}

function formattedDate(value: string | undefined): string {
  if (!value) return 'Not recorded'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Not recorded' : date.toLocaleString()
}

export default function Health() {
  const manifest = useManifest()
  const news = useNews()
  const sources = useMemo(() => {
    const storedSources = manifest.data?.sources ?? {}
    const rows: HealthSource[] = primarySources.map(source => {
      const stored = storedSources[source.id]
      const status = typeof stored === 'object' && stored !== null
        ? stored
        : {
            kind: source.kind,
            source: source.source,
            url: source.url,
            fetched_at: typeof stored === 'string' ? stored : manifest.data?.built_at ?? '',
            status: typeof stored === 'string' ? 'ok' as const : 'unknown' as const,
            count: manifest.data?.counts?.[source.countKey] ?? 0,
          }
      return {
        id: source.id,
        area: source.area,
        ...status,
        source: status.source ?? source.source,
        url: status.url || source.url,
      }
    })

    for (const [id, status] of Object.entries(storedSources)) {
      if (id === 'news' || primarySources.some(source => source.id === id)) continue
      if (typeof status !== 'object' || status === null) continue
      rows.push({
        id,
        area: areaLabels[status.kind ?? ''] ?? 'Other published data',
        ...status,
      })
    }

    for (const source of news.data?.sources ?? []) {
      rows.push({
        id: `news-${source.id}`,
        kind: 'news',
        area: areaLabels.news ?? 'Threat intelligence & news',
        source: source.name,
        url: source.url,
        fetched_at: source.fetched_at,
        status: source.status,
        count: source.count,
      })
    }

    return rows.sort((a, b) =>
      a.area.localeCompare(b.area) || (a.source ?? a.id).localeCompare(b.source ?? b.id)
    )
  }, [manifest.data, news.data])

  const currentCount = sources.filter(source => sourceState(source) === 'current').length
  const staleCount = sources.filter(source => sourceState(source) === 'stale').length
  const unknownCount = sources.length - currentCount - staleCount
  const warnings = manifest.data?.warnings ?? []

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Published data operations</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Data source health</h1>
          <p className="mt-2 max-w-3xl text-slate-600">
            Feed status and synchronization times for the public snapshots used across HuntDeck.
          </p>
        </div>
        <Link className="button-secondary" to="/triage">Back to IOC triage</Link>
      </header>

      <aside className="rounded-xl border border-sky-200 bg-sky-50 p-4 text-sm text-sky-950">
        This is a read-only view of the last published data build, not a live check of upstream services.
        A source is marked stale when its fetch failed or its last recorded sync is over 48 hours old.
        Latest published build: <strong>{formattedDate(manifest.data?.built_at)}</strong>.
      </aside>

      {(manifest.isError || news.isError) && (
        <p className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-900" role="alert">
          Could not load complete source health data. {[
            manifest.isError ? manifest.error.message : '',
            news.isError ? news.error.message : '',
          ].filter(Boolean).join(' ')}
        </p>
      )}

      <section aria-label="Source status summary" className="grid gap-3 sm:grid-cols-3">
        {[
          { label: 'Current', count: currentCount, style: 'badge-success' },
          { label: 'Stale / last good', count: staleCount, style: 'badge-warning' },
          { label: 'Status unavailable', count: unknownCount, style: 'badge-muted' },
        ].map(item => (
          <article className="rounded-xl border border-slate-200 bg-white p-4" key={item.label}>
            <p className="text-sm text-slate-600">{item.label}</p>
            <p className="mt-1 text-2xl font-bold text-slate-950">{item.count}</p>
          </article>
        ))}
      </section>

      <section aria-labelledby="sources-heading" className="space-y-3">
        <div>
          <h2 className="text-xl font-bold text-slate-950" id="sources-heading">Sources by product area</h2>
          <p className="mt-1 text-sm text-slate-600">
            Feed counts reflect the indexed snapshot and are not an upstream completeness guarantee.
          </p>
        </div>
        {manifest.isLoading || news.isLoading ? (
          <p className="rounded-xl border border-slate-200 bg-white p-5 text-sm text-slate-600">
            Loading source health…
          </p>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="bg-slate-100 text-xs uppercase text-slate-600">
                <tr>
                  <th className="px-4 py-3">Product area</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Indexed</th>
                  <th className="px-4 py-3">Last sync</th>
                </tr>
              </thead>
              <tbody>
                {sources.map(source => {
                  const state = sourceState(source)
                  return (
                    <tr className="border-t border-slate-100" key={source.id}>
                      <td className="px-4 py-3 text-slate-600">{source.area}</td>
                      <td className="px-4 py-3 font-medium">
                        {source.url ? (
                          <a className="text-sky-800 underline" href={source.url} target="_blank" rel="noreferrer">
                            {source.source ?? source.id}
                          </a>
                        ) : source.source ?? source.id}
                      </td>
                      <td className="px-4 py-3">
                        <span className={state === 'current' ? 'badge-success' : state === 'stale' ? 'badge-warning' : 'badge-muted'}>
                          {stateLabel(state)}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-600">
                        {source.published_count !== undefined
                          ? `${source.published_count.toLocaleString()} sampled of ${source.count.toLocaleString()}`
                          : source.count.toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-slate-600">{formattedDate(source.fetched_at)}</td>
                    </tr>
                  )
                })}
                {sources.length === 0 && (
                  <tr><td className="px-4 py-6 text-slate-600" colSpan={5}>No source metadata was published.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {warnings.length > 0 && (
        <section aria-labelledby="warnings-heading" className="space-y-2">
          <h2 className="text-lg font-bold text-slate-950" id="warnings-heading">Build warnings</h2>
          <ul className="list-inside list-disc rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
            {warnings.map((warning, index) => <li key={`${index}:${warning}`}>{warning}</li>)}
          </ul>
        </section>
      )}
    </div>
  )
}
