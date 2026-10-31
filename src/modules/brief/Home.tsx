import { useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  useEpss,
  useHypotheses,
  useKev,
  useManifest,
  useNews,
} from '../../data/snapshots'
import type { EpssEntry, HuntHypothesis, KevEntry, NewsArticle } from '../../types'

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }

function rankedHypotheses(hypotheses: HuntHypothesis[]) {
  return [...hypotheses].sort((a, b) => {
    const severity = (severityOrder[a.severity ?? 'informational'] ?? 5) -
      (severityOrder[b.severity ?? 'informational'] ?? 5)
    if (severity !== 0) return severity
    return (b.ai?.relevance_score ?? 0) - (a.ai?.relevance_score ?? 0)
  })
}

function relativeAge(timestamp?: string): string {
  if (!timestamp) return 'Snapshot date unavailable'
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return 'Snapshot date unavailable'
  const hours = Math.max(0, Math.floor((Date.now() - date.getTime()) / 3_600_000))
  if (hours < 1) return 'Updated less than an hour ago'
  if (hours < 24) return `Updated ${hours}h ago`
  const days = Math.floor(hours / 24)
  return `Updated ${days}d ago`
}

function saveMarkdown(hypotheses: HuntHypothesis[]) {
  const content = [
    '# HuntDeck Daily Hunt Brief',
    '',
    ...hypotheses.flatMap(hypothesis => [
      `## ${hypothesis.title}`,
      '',
      hypothesis.hypothesis ?? hypothesis.why ?? '',
      '',
      ...(hypothesis.attack_techniques?.length
        ? [`ATT&CK: ${hypothesis.attack_techniques.join(', ')}`, '']
        : []),
      ...Object.values(hypothesis.queries).flatMap(query =>
        query ? [`### ${query.language}`, '', '```', query.query, '```', ''] : []
      ),
    ]),
  ].join('\n')
  const url = URL.createObjectURL(new Blob([content], { type: 'text/markdown' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `huntdeck-brief-${new Date().toISOString().slice(0, 10)}.md`
  anchor.click()
  URL.revokeObjectURL(url)
}

export default function Home() {
  const manifest = useManifest()
  const kev = useKev()
  const epss = useEpss()
  const hypothesesQuery = useHypotheses()
  const news = useNews()
  const [copyMessage, setCopyMessage] = useState('')
  const hypotheses = useMemo(
    () => rankedHypotheses(hypothesesQuery.data ?? []),
    [hypothesesQuery.data]
  )
  const epssByCve = useMemo(
    () => new Map((epss.data ?? []).map((entry: EpssEntry) => [entry.cve, entry])),
    [epss.data]
  )
  const recentKev = useMemo(() => {
    const entries = kev.data?.vulnerabilities ?? []
    const cutoff = Date.now() - 24 * 60 * 60 * 1000
    const addedRecently = entries.filter(entry => {
      const date = entry.dateAdded ? Date.parse(entry.dateAdded) : Number.NaN
      return Number.isFinite(date) && date >= cutoff
    })
    return (addedRecently.length > 0 ? addedRecently : entries)
      .slice()
      .sort((a, b) => (b.dateAdded ?? '').localeCompare(a.dateAdded ?? ''))
      .slice(0, 6)
  }, [kev.data])
  const recentNews = useMemo(
    () => [...(news.data?.items ?? [])]
      .sort((a, b) => (b.published_at ?? '').localeCompare(a.published_at ?? ''))
      .slice(0, 4),
    [news.data]
  )

  async function copyQuery(query: string) {
    try {
      await navigator.clipboard.writeText(query)
      setCopyMessage('Query copied')
      window.setTimeout(() => setCopyMessage(''), 1800)
    } catch (error) {
      setCopyMessage(error instanceof Error ? `Copy failed: ${error.message}` : 'Copy failed')
    }
  }

  return (
    <div className="mx-auto max-w-7xl space-y-8">
      <section className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Threat intelligence</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Daily hunt brief</h1>
          <p className="mt-2 max-w-2xl text-slate-600">
            Prioritized hunts and fresh vulnerability intelligence from the latest static snapshot.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 print:hidden">
          <button className="button-secondary" onClick={() => window.print()}>Print brief</button>
          <button
            className="button-primary"
            disabled={hypotheses.length === 0}
            onClick={() => saveMarkdown(hypotheses)}
          >
            Export Markdown
          </button>
        </div>
      </section>

      <section aria-label="Snapshot summary" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <SummaryCard
          label="Known exploited vulnerabilities"
          value={manifest.data?.counts?.kev ?? kev.data?.vulnerabilities.length}
          loading={manifest.isLoading && kev.isLoading}
        />
        <SummaryCard
          label="EPSS-scored CVEs in snapshot"
          value={manifest.data?.counts?.epss ?? epss.data?.length}
          loading={manifest.isLoading && epss.isLoading}
        />
        <SummaryCard label="Hunt hypotheses" value={hypotheses.length} loading={hypothesesQuery.isLoading} />
        <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <p className="text-sm text-slate-600">Data freshness</p>
          <p className="mt-2 text-lg font-bold text-slate-950">
            {manifest.isLoading ? 'Loading…' : relativeAge(manifest.data?.built_at)}
          </p>
          {manifest.data?.warnings && manifest.data.warnings.length > 0 && (
            <p className="mt-1 text-xs text-amber-800">{manifest.data.warnings.length} source warning(s)</p>
          )}
        </article>
      </section>

      {(manifest.isError || kev.isError || epss.isError || hypothesesQuery.isError ||
        news.isError) && (
        <section className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-900" role="alert">
          Some snapshot data could not be loaded:{' '}
          {[manifest, kev, epss, hypothesesQuery, news]
            .filter(query => query.isError)
            .map(query => query.error.message)
            .join(' ')}
        </section>
      )}

      <section aria-labelledby="hunt-now-heading">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 id="hunt-now-heading" className="text-xl font-bold text-slate-950">Hunt now</h2>
            <p className="mt-1 text-sm text-slate-600">Start with the highest-priority hypotheses in the snapshot.</p>
          </div>
          <Link className="text-sm font-semibold text-sky-800 hover:underline print:hidden" to="/hypotheses">
            Browse all hypotheses
          </Link>
          <Link className="text-sm font-semibold text-sky-800 hover:underline print:hidden" to="/ideas">
            Get ideas from recent reporting
          </Link>
        </div>
        {hypotheses.length > 0 ? (
          <div className="grid gap-4 lg:grid-cols-2">
            {hypotheses.slice(0, 4).map(hypothesis => (
              <article key={hypothesis.id} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 className="font-semibold text-slate-950">{hypothesis.title}</h3>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {(hypothesis.attack_techniques ?? []).map(technique => (
                        <span className="badge" key={technique}>{technique}</span>
                      ))}
                      {hypothesis.needs_review && <span className="badge-warning">Needs review</span>}
                    </div>
                  </div>
                  <span className="badge">{hypothesis.severity ?? 'Unrated'}</span>
                </div>
                <p className="mt-3 text-sm text-slate-600">
                  {hypothesis.hypothesis ?? hypothesis.why ?? 'A deterministic hunt template is available below.'}
                </p>
                <div className="mt-4 space-y-3">
                  {Object.entries(hypothesis.queries).map(([key, query]) => query && (
                    <div key={key}>
                      <div className="mb-1 flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                          {query.language}
                        </span>
                        <button className="text-xs font-semibold text-sky-800 hover:underline print:hidden"
                          onClick={() => void copyQuery(query.query)}>
                          Copy
                        </button>
                      </div>
                      <pre className="overflow-x-auto rounded-lg bg-slate-950 p-3 text-sm text-slate-100">
                        <code>{query.query}</code>
                      </pre>
                    </div>
                  ))}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState
            title={hypothesesQuery.isLoading ? 'Loading hunt hypotheses…' : 'No hunt hypotheses in this snapshot'}
            detail="Refresh the data workflow or add a curated hypothesis to the snapshot."
          />
        )}
      </section>

      <section aria-labelledby="research-heading">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 id="research-heading" className="text-xl font-bold text-slate-950">Research leads</h2>
            <p className="mt-1 text-sm text-slate-600">Recent reporting to help prioritize your next hunt.</p>
          </div>
          <Link className="text-sm font-semibold text-sky-800 hover:underline print:hidden" to="/intelligence">
            Browse intel leads
          </Link>
        </div>
        {recentNews.length > 0 ? (
          <div className="grid gap-3 lg:grid-cols-2">
            {recentNews.map(article => <BriefNewsRow article={article} key={article.url} />)}
          </div>
        ) : (
          <EmptyState
            title={news.isLoading ? 'Loading research headlines…' : 'No research headlines are available'}
            detail={news.data?.warnings.length
              ? 'One or more sources could not be refreshed; check the Intel leads page for source status.'
              : 'Curated feed headlines will appear here after the data workflow runs.'}
          />
        )}
      </section>

      <section aria-labelledby="kev-heading">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 id="kev-heading" className="text-xl font-bold text-slate-950">Known exploited vulnerabilities</h2>
            <p className="mt-1 text-sm text-slate-600">Recent additions when available; otherwise the newest catalog entries.</p>
          </div>
          {kev.data && <span className="text-sm text-slate-500">{kev.data.vulnerabilities.length.toLocaleString()} total</span>}
        </div>
        {kev.isLoading ? <EmptyState title="Loading KEV catalog…" /> : (
          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
            {recentKev.map(entry => (
              <KevRow key={entry.cveID} entry={entry} epss={epssByCve.get(entry.cveID)} />
            ))}
            {recentKev.length === 0 && <EmptyState title="No KEV entries are available in this snapshot" />}
          </div>
        )}
      </section>

      <section aria-label="Other intelligence feeds" className="grid gap-4 lg:grid-cols-2">
        <FeedStatusCard
          title="ATT&CK techniques indexed"
          count={manifest.data?.counts?.techniques}
          detail={`${manifest.data?.counts?.hypotheses ?? hypotheses.length} deterministic hunt hypotheses are linked to the ATT&CK technique catalog.`}
          to="/coverage"
          linkLabel="Open coverage workspace"
        />
        <FeedStatusCard
          title="Indicators indexed"
          count={manifest.data?.counts?.iocs}
          detail={(manifest.data?.counts?.iocs ?? 0) > 0
            ? 'A public indicator corpus is available to browse or compare against pasted telemetry in browser-only IOC triage.'
            : 'No indicators are available in the current snapshot.'}
          to="/triage"
          linkLabel="Browse IOC sources and triage"
        />
        <FeedStatusCard
          title="Detection rules indexed"
          count={manifest.data?.counts?.rules}
          detail={(manifest.data?.counts?.rules ?? 0) > 0
            ? 'KQL, SPL, and Sigma content from public sources and HuntDeck-authored hypotheses is available.'
            : 'The rule index has not been generated yet.'}
          to="/rules"
          linkLabel="Search rules"
        />
        <FeedStatusCard
          title="Ransomware activity"
          detail="Ransomware group profiles and victim activity are not in the current data pipeline yet."
        />
      </section>
      {copyMessage && <div className="sr-only" role="status">{copyMessage}</div>}
    </div>
  )
}

function SummaryCard({ label, value, loading = false }: { label: string; value?: number; loading?: boolean }) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm text-slate-600">{label}</p>
      <p className="mt-2 text-3xl font-bold text-slate-950">
        {loading ? 'Loading…' : value?.toLocaleString() ?? 'Unavailable'}
      </p>
    </article>
  )
}

function KevRow({ entry, epss }: { entry: KevEntry; epss?: EpssEntry }) {
  return (
    <article className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 p-4 last:border-b-0">
      <div className="min-w-0">
        <h3 className="font-semibold text-slate-950">{entry.cveID}</h3>
        <p className="mt-1 text-sm text-slate-600">
          {[entry.vendorProject, entry.product, entry.vulnerabilityName].filter(Boolean).join(' · ') || entry.shortDescription}
        </p>
      </div>
      <div className="flex flex-wrap gap-2 text-xs">
        {entry.dateAdded && <span className="badge">Added {entry.dateAdded}</span>}
        {epss && <span className="badge">EPSS {(epss.epss * 100).toFixed(1)}%</span>}
        {entry.knownRansomwareCampaignUse === 'Known' && <span className="badge-warning">Ransomware use</span>}
      </div>
    </article>
  )
}

function BriefNewsRow({ article }: { article: NewsArticle }) {
  const date = article.published_at ? new Date(article.published_at) : undefined
  const formattedDate = date && !Number.isNaN(date.getTime())
    ? date.toLocaleDateString(undefined, { dateStyle: 'medium' })
    : 'Date unavailable'
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <p className="text-xs font-semibold uppercase tracking-wide text-sky-800">
        {article.source_name} · {formattedDate}
      </p>
      <h3 className="mt-2 font-semibold leading-snug text-slate-950">
        <a href={article.url} target="_blank" rel="noreferrer" className="hover:text-sky-800 hover:underline">
          {article.title}
        </a>
      </h3>
      {article.cves.length > 0 && (
        <p className="mt-2 text-xs text-slate-600">
          CVE references: {article.cves.slice(0, 3).join(', ')}
        </p>
      )}
      {article.summary && <p className="mt-2 line-clamp-2 text-sm text-slate-600">{article.summary}</p>}
    </article>
  )
}

function FeedStatusCard({
  title,
  detail,
  count,
  to,
  linkLabel,
  children,
}: {
  title: string
  detail: string
  count?: number
  to?: string
  linkLabel?: string
  children?: ReactNode
}) {
  return (
    <article className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-5">
      <div className="flex items-center justify-between gap-2">
        <h2 className="font-semibold text-slate-900">{title}</h2>
        <span className={count !== undefined && count > 0 ? 'badge-success' : 'badge-muted'}>
          {count === undefined ? 'Loading' : count.toLocaleString()}
        </span>
      </div>
      <p className="mt-2 text-sm text-slate-600">{detail}</p>
      {children}
      {to && linkLabel && <Link className="mt-3 inline-block text-sm font-semibold text-sky-800 hover:underline print:hidden" to={to}>{linkLabel}</Link>}
    </article>
  )
}

function EmptyState({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-5">
      <p className="font-medium text-slate-800">{title}</p>
      {detail && <p className="mt-1 text-sm text-slate-600">{detail}</p>}
    </div>
  )
}
