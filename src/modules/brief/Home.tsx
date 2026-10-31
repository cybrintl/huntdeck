import hypothesesData from '../../../public/data/hunt-hypotheses.json'
import { useQuery } from '@tanstack/react-query'
import type { HuntHypothesis } from '../../types'

const hypotheses: HuntHypothesis[] = hypothesesData

interface DataManifest {
  counts?: {
    kev: number
    epss: number
  }
}

async function fetchManifest(): Promise<DataManifest> {
  const url = new URL('data/manifest.json', document.baseURI).toString()
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Failed to load data manifest: ${response.status} ${response.statusText}`)
  }
  const data: unknown = await response.json()
  if (typeof data !== 'object' || data === null) {
    throw new Error('Data manifest has an invalid format')
  }
  if (!('counts' in data)) {
    return {}
  }
  const { counts } = data
  if (
    typeof counts !== 'object' ||
    counts === null ||
    !('kev' in counts) ||
    !('epss' in counts) ||
    typeof counts.kev !== 'number' ||
    typeof counts.epss !== 'number'
  ) {
    throw new Error('Data manifest has invalid feed counts')
  }
  return { counts: { kev: counts.kev, epss: counts.epss } }
}

export default function Home() {
  const manifest = useQuery({ queryKey: ['data-manifest'], queryFn: fetchManifest })
  const counts = manifest.data?.counts
  const feedsEmpty = manifest.isSuccess && (!counts || counts.kev === 0 || counts.epss === 0)

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <section>
        <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Threat intelligence</p>
        <h1 className="mt-2 text-3xl font-bold text-slate-950">Daily hunt brief</h1>
        <p className="mt-2 max-w-2xl text-slate-600">
          A quick view of the available vulnerability intelligence and hunt playbooks.
        </p>
      </section>

      <section aria-label="Threat data summary" className="grid gap-4 sm:grid-cols-3">
        <SummaryCard label="Known exploited vulnerabilities" value={counts?.kev} loading={manifest.isLoading} />
        <SummaryCard label="EPSS-scored CVEs" value={counts?.epss} loading={manifest.isLoading} />
        <SummaryCard label="Hunt playbooks" value={hypotheses.length} />
      </section>

      <section aria-labelledby="playbooks-heading">
        <div className="mb-4">
          <h2 id="playbooks-heading" className="text-xl font-bold text-slate-950">Hunt playbooks</h2>
          <p className="mt-1 text-sm text-slate-600">Detection ideas with example queries for your SIEM.</p>
        </div>
        {hypotheses.length > 0 ? (
          <div className="grid gap-4 lg:grid-cols-2">
            {hypotheses.map(hypothesis => (
              <article key={hypothesis.id} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="flex items-start justify-between gap-4">
                  <h3 className="text-lg font-semibold text-slate-950">{hypothesis.title}</h3>
                  <span className="shrink-0 rounded-full bg-sky-50 px-3 py-1 text-xs font-medium text-sky-800">
                    {hypothesis.id}
                  </span>
                </div>
                <div className="mt-4 space-y-3">
                  {Object.values(hypothesis.queries).map(({ language, query }) => (
                    <div key={language}>
                      <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{language}</h4>
                      <pre className="overflow-x-auto rounded-lg bg-slate-950 p-3 text-sm text-slate-100">
                        <code>{query}</code>
                      </pre>
                    </div>
                  ))}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <p className="rounded-xl border border-dashed border-slate-300 bg-white p-5 text-slate-600">
            No hunt playbooks are available yet.
          </p>
        )}
      </section>

      {manifest.isError && (
        <section aria-label="Feed loading error" className="rounded-xl border border-red-200 bg-red-50 p-5">
          <h2 className="font-semibold text-red-950">Unable to load vulnerability feeds</h2>
          <p className="mt-1 text-sm text-red-900">{manifest.error.message}</p>
        </section>
      )}

      {feedsEmpty && (
        <section aria-label="Feed status" className="rounded-xl border border-amber-200 bg-amber-50 p-5">
          <h2 className="font-semibold text-amber-950">
            {counts ? 'Vulnerability feeds have no data yet' : 'Vulnerability data has not been built yet'}
          </h2>
          <p className="mt-1 text-sm text-amber-900">
            Run the Build Data workflow to fetch current vulnerability feeds and publish them to the site.
          </p>
        </section>
      )}
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