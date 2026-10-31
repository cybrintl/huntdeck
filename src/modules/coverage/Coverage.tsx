import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useHypotheses, useRules, useTechniques } from '../../data/snapshots'
import type { AttackTechnique, HuntHypothesis } from '../../types'

function formatAttackText(text: string) {
  const tokenPattern = /(<code>[\s\S]*?<\/code>|\[[^\]]+\]\(https?:\/\/[^)\s]+\))/gi
  return text.split(tokenPattern).map((segment, index) => {
    const code = segment.match(/^<code>([\s\S]+)<\/code>$/i)
    if (code) {
      return <code className="rounded bg-slate-100 px-1 font-mono text-xs" key={index}>{code[1]}</code>
    }
    const link = segment.match(/^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/i)
    if (link) {
      return <a className="text-sky-800 underline" href={link[2]} key={index}
        target="_blank" rel="noreferrer">{link[1]}</a>
    }
    return segment
  })
}

function techniquesForHypothesis(hypothesis: HuntHypothesis): string[] {
  const declared = hypothesis.attack_techniques ?? []
  const originId = hypothesis.origin?.match(/\bT\d{4}(?:\.\d{3})?\b/)?.[0]
  return [...new Set(originId ? [...declared, originId] : declared)]
}

function makeLayer(techniques: AttackTechnique[], hypothesisCount: Map<string, number>, ruleCount: Map<string, number>) {
  return {
    name: 'HuntDeck reference coverage',
    versions: { attack: '17', navigator: '4.9.1', layer: '4.5' },
    domain: 'enterprise-attack',
    description: 'Indexed HuntDeck hunt hypotheses and detection rules. This is not deployment or organizational coverage.',
    filters: { platforms: [], stages: [], actors: [], malware: [], teams: [], tactics: [], data_sources: [], query: '' },
    sorting: 0,
    layout: { layout: 'side', aggregateFunction: 'average', showID: true, showName: true, showAggregateScores: false, countUnscored: false },
    hideDisabled: false,
    techniques: techniques.map(technique => {
      const hunts = hypothesisCount.get(technique.id) ?? 0
      const rules = ruleCount.get(technique.id) ?? 0
      const score = Math.min(100, hunts * 35 + rules * 25)
      return {
        techniqueID: technique.id,
        score,
        comment: `${hunts} indexed hunt hypothesis/hypotheses; ${rules} indexed detection rule(s).`,
      }
    }),
    gradient: { colors: ['#ffffff', '#7bc8a4', '#d9534f'], minValue: 0, maxValue: 100 },
    legendItems: [
      { label: 'No indexed reference', color: '#ffffff' },
      { label: 'Indexed hunt or detection content', color: '#7bc8a4' },
      { label: 'Multiple indexed references', color: '#d9534f' },
    ],
    metadata: [],
  }
}

export default function Coverage() {
  const techniqueQuery = useTechniques()
  const hypothesisQuery = useHypotheses()
  const rulesQuery = useRules()
  const [searchParams] = useSearchParams()
  const [selectedTactic, setSelectedTactic] = useState('')
  const [search, setSearch] = useState(() => searchParams.get('technique') ?? '')
  const [referencesOnly, setReferencesOnly] = useState(false)
  const [displayLimit, setDisplayLimit] = useState(30)
  const hypotheses = hypothesisQuery.data ?? []
  const rules = rulesQuery.data ?? []

  const techniques = useMemo(() => {
    const snapshotTechniques = techniqueQuery.data ?? []
    if (snapshotTechniques.length > 0) return snapshotTechniques
    const derived = new Map<string, AttackTechnique>()
    for (const hypothesis of hypotheses) {
      for (const id of techniquesForHypothesis(hypothesis)) {
        const existing = derived.get(id)
        const title = hypothesis.title.replace(/^Hunt:\s*/i, '')
        derived.set(id, {
          id,
          name: existing ? `${existing.name}; ${title}` : title,
          tactics: existing?.tactics ?? ['Not categorized'],
        })
      }
    }
    return [...derived.values()]
  }, [techniqueQuery.data, hypotheses])

  const hypothesesByTechnique = useMemo(() => {
    const result = new Map<string, HuntHypothesis[]>()
    for (const hypothesis of hypotheses) {
      for (const id of techniquesForHypothesis(hypothesis)) {
        result.set(id, [...(result.get(id) ?? []), hypothesis])
      }
    }
    return result
  }, [hypotheses])
  const rulesByTechnique = useMemo(() => {
    const result = new Map<string, typeof rules>()
    for (const rule of rules) {
      for (const id of rule.attack_techniques) {
        result.set(id, [...(result.get(id) ?? []), rule])
      }
    }
    return result
  }, [rules])

  const tactics = useMemo(
    () => [...new Set(techniques.flatMap(technique => technique.tactics))].sort(),
    [techniques]
  )
  const visible = useMemo(() => {
    const normalizedSearch = search.trim().toLocaleLowerCase()
    return techniques.filter(technique =>
      (!selectedTactic || technique.tactics.includes(selectedTactic)) &&
      (!referencesOnly ||
        (hypothesesByTechnique.get(technique.id)?.length ?? 0) > 0 ||
        (rulesByTechnique.get(technique.id)?.length ?? 0) > 0) &&
      (!normalizedSearch || [
        technique.id,
        technique.name,
        technique.tactics.join(' '),
        technique.description ?? '',
        technique.detection ?? '',
        (technique.detection_strategies ?? []).map(strategy =>
          `${strategy.name} ${strategy.analytics.map(analytic =>
            `${analytic.name} ${analytic.description} ${analytic.log_sources.join(' ')}`
          ).join(' ')}`
        ).join(' '),
        technique.data_sources?.join(' ') ?? '',
      ].join(' ').toLocaleLowerCase().includes(normalizedSearch))
    )
  }, [techniques, selectedTactic, search, referencesOnly, hypothesesByTechnique, rulesByTechnique])
  const withReferences = techniques.filter(technique =>
    (hypothesesByTechnique.get(technique.id)?.length ?? 0) > 0 ||
    (rulesByTechnique.get(technique.id)?.length ?? 0) > 0
  ).length
  const detectionStrategyCount = techniques.reduce(
    (count, technique) => count + (technique.detection_strategies?.length ?? 0),
    0
  )

  function exportLayer() {
    const hypothesisCounts = new Map([...hypothesesByTechnique].map(([id, items]) => [id, items.length]))
    const ruleCounts = new Map([...rulesByTechnique].map(([id, items]) => [id, items.length]))
    const layer = makeLayer(techniques, hypothesisCounts, ruleCounts)
    const url = URL.createObjectURL(new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'huntdeck-reference-coverage.json'
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">MITRE ATT&amp;CK</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Technique map</h1>
          <p className="mt-2 max-w-3xl text-slate-600">
            Explore ATT&amp;CK techniques linked to HuntDeck hypotheses and detection rules. These public references
            do not indicate what any organization has deployed or covered.
          </p>
        </div>
        <Link className="button-secondary" to="/">Back to daily brief</Link>
      </header>

      <section aria-label="Reference coverage summary" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <SummaryCard label="ATT&CK techniques" value={techniques.length} loading={techniqueQuery.isLoading} />
        <SummaryCard
          label="With indexed hunt or rule references"
          value={withReferences}
          loading={techniqueQuery.isLoading || hypothesisQuery.isLoading || rulesQuery.isLoading}
        />
        <SummaryCard label="Hunt hypotheses" value={hypotheses.length} loading={hypothesisQuery.isLoading} />
        <SummaryCard label="Linked detection strategies" value={detectionStrategyCount} loading={techniqueQuery.isLoading} />
      </section>

      <section className="flex flex-wrap items-end gap-3 rounded-xl border border-slate-200 bg-white p-4">
        <label className="min-w-60 flex-1">
          <span className="field-label">Search technique, behavior, guidance, or telemetry</span>
          <input className="field-input" type="search" value={search}
            onChange={event => {
              setSearch(event.target.value)
              setDisplayLimit(30)
            }} placeholder="Technique ID, behavior, tactic, or data source" />
        </label>
        <label className="min-w-52">
          <span className="field-label">Tactic</span>
          <select className="field-input" value={selectedTactic}
            onChange={event => {
              setSelectedTactic(event.target.value)
              setDisplayLimit(30)
            }}>
            <option value="">All tactics</option>
            {tactics.map(tactic => <option key={tactic}>{tactic}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 self-end pb-2 text-sm text-slate-700">
          <input type="checkbox" checked={referencesOnly}
            onChange={event => {
              setReferencesOnly(event.target.checked)
              setDisplayLimit(30)
            }} />
          Only techniques with indexed content
        </label>
        <button className="button-primary" onClick={exportLayer}
          disabled={techniques.length === 0 || hypothesisQuery.isLoading || rulesQuery.isLoading}>
          Export Navigator layer
        </button>
      </section>

      {(techniqueQuery.isError || hypothesisQuery.isError || rulesQuery.isError) && (
        <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">
          Could not load one or more ATT&amp;CK reference snapshots.
        </p>
      )}

      <div className="flex items-center justify-between gap-3">
        <h2 className="text-xl font-bold text-slate-950">Technique references</h2>
        <span className="text-sm text-slate-500">
          {visible.length.toLocaleString()} matching · showing {Math.min(displayLimit, visible.length).toLocaleString()}
        </span>
      </div>
      {visible.length > 0 ? (
        <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-3" aria-label="ATT&CK technique references">
          {visible.slice(0, displayLimit).map(technique => {
            const linkedHypotheses = hypothesesByTechnique.get(technique.id) ?? []
            const linkedRules = rulesByTechnique.get(technique.id) ?? []
            const linkedTelemetry = [...new Set([
              ...linkedHypotheses.flatMap(hypothesis => hypothesis.log_sources ?? []),
              ...linkedRules.flatMap(rule => rule.data_sources ?? (rule.log_source ? [rule.log_source] : [])),
            ])]
            const descriptionParagraphs = (technique.description ?? '')
              .split(/\n\s*\n/)
              .map(paragraph => paragraph.trim())
              .filter(Boolean) ?? []
            const legacyDetectionParagraphs = (technique.detection ?? '')
              .split(/\n\s*\n/)
              .map(paragraph => paragraph.trim())
              .filter(Boolean) ?? []
            const detectionStrategies = technique.detection_strategies ?? []
            return (
              <article key={technique.id} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                <h3 className="font-semibold text-slate-950">
                  <a className="hover:text-sky-800 hover:underline"
                    href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
                    target="_blank" rel="noreferrer">{technique.name}</a>
                </h3>
                <p className="mt-1 text-xs text-slate-500">{technique.id} · {technique.tactics.join(', ')}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <span className="badge">{linkedHypotheses.length} hunt references</span>
                  <span className="badge-muted">{linkedRules.length} rule references</span>
                </div>
                {technique.data_sources?.length ? (
                  <p className="mt-3 text-xs text-slate-600">
                    <strong>ATT&amp;CK data sources:</strong> {technique.data_sources.join(', ')}
                  </p>
                ) : null}
                {linkedTelemetry.length > 0 && (
                  <p className="mt-2 text-xs text-slate-600">
                    <strong>Telemetry in linked content:</strong> {linkedTelemetry.join(', ')}
                  </p>
                )}
                {descriptionParagraphs.length > 0 && (
                  <details className="mt-3 rounded-lg bg-slate-50 p-3">
                    <summary className="cursor-pointer text-sm font-semibold text-slate-800">
                      Technique overview
                    </summary>
                    <div className="mt-2 space-y-2 text-sm leading-relaxed text-slate-600">
                      {descriptionParagraphs.map((paragraph, index) => (
                        <p key={index}>{formatAttackText(paragraph)}</p>
                      ))}
                    </div>
                  </details>
                )}
                {(detectionStrategies.length > 0 || legacyDetectionParagraphs.length > 0) && (
                  <details className="mt-3 rounded-lg border border-sky-100 bg-sky-50 p-3">
                    <summary className="cursor-pointer text-sm font-semibold text-sky-900">
                      ATT&amp;CK detection guidance
                      {detectionStrategies.length > 0 && ` · ${detectionStrategies.length} strategies`}
                    </summary>
                    <p className="mt-1 text-xs text-slate-500">
                      Published by MITRE ATT&amp;CK; validate applicability against your environment and available telemetry.
                    </p>
                    <div className="mt-3 space-y-3">
                      {detectionStrategies.map(strategy => (
                        <article key={strategy.id} className="rounded-lg border border-sky-100 bg-white p-3">
                          <a className="text-sm font-semibold text-sky-900 hover:underline"
                            href={strategy.url} target="_blank" rel="noreferrer">
                            {strategy.name}
                          </a>
                          <p className="mt-1 text-xs text-slate-500">{strategy.id}</p>
                          <div className="mt-3 space-y-3">
                            {strategy.analytics.map(analytic => (
                              <section className="border-t border-slate-100 pt-3" key={analytic.name}>
                                <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-600">
                                  {analytic.name}
                                </h4>
                                {analytic.description && (
                                  <p className="mt-1 text-sm leading-relaxed text-slate-700">
                                    {formatAttackText(analytic.description)}
                                  </p>
                                )}
                                {analytic.platforms.length > 0 && (
                                  <p className="mt-2 text-xs text-slate-600">
                                    <strong>Platforms:</strong> {analytic.platforms.join(', ')}
                                  </p>
                                )}
                                {analytic.log_sources.length > 0 && (
                                  <p className="mt-1 text-xs text-slate-600">
                                    <strong>Relevant telemetry:</strong> {analytic.log_sources.join(', ')}
                                  </p>
                                )}
                              </section>
                            ))}
                          </div>
                        </article>
                      ))}
                      {legacyDetectionParagraphs.map((paragraph, index) => (
                        <p className="text-sm leading-relaxed text-slate-700" key={`legacy-${index}`}>
                          {formatAttackText(paragraph)}
                        </p>
                      ))}
                    </div>
                  </details>
                )}
                {linkedHypotheses.length > 0 && (
                  <div className="mt-3 border-t border-slate-100 pt-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Hunt hypotheses</h4>
                    <ul className="mt-2 space-y-1">
                    {linkedHypotheses.map(hypothesis => (
                      <li key={hypothesis.id}>
                        <Link className="text-sm text-sky-800 hover:underline"
                          to={`/hypotheses?technique=${encodeURIComponent(technique.id)}`}>
                          {hypothesis.title}
                        </Link>
                      </li>
                    ))}
                    </ul>
                  </div>
                )}
                {linkedRules.length > 0 && (
                  <div className="mt-3 border-t border-slate-100 pt-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Indexed rules and queries
                    </h4>
                    <ul className="mt-2 space-y-1">
                      {linkedRules.slice(0, 4).map(rule => (
                        <li className="truncate text-sm text-slate-700" key={rule.id}>{rule.title}</li>
                      ))}
                    </ul>
                    {linkedRules.length > 4 && (
                      <p className="mt-1 text-xs text-slate-500">and {linkedRules.length - 4} more</p>
                    )}
                    <Link className="mt-2 inline-block text-sm font-semibold text-sky-800 hover:underline"
                      to={`/rules?technique=${encodeURIComponent(technique.id)}`}>
                      Browse {linkedRules.length} indexed rules and queries
                    </Link>
                  </div>
                )}
              </article>
            )
          })}
        </section>
      ) : (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white p-6 text-slate-600">
          {techniqueQuery.isLoading
            ? 'Loading the ATT&CK technique snapshot…'
            : 'No techniques match. Try a different tactic or search term.'}
        </div>
      )}
      {displayLimit < visible.length && (
        <div className="text-center">
          <button className="button-secondary" onClick={() => setDisplayLimit(limit => limit + 30)}>
            Show 30 more techniques
          </button>
        </div>
      )}
    </div>
  )
}

function SummaryCard({ label, value, loading }: { label: string; value: number; loading: boolean }) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm text-slate-600">{label}</p>
      <p className="mt-2 text-3xl font-bold text-slate-950">{loading ? 'Loading…' : value.toLocaleString()}</p>
    </article>
  )
}
