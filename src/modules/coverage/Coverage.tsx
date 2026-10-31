import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useHypotheses, useRules, useTechniques } from '../../data/snapshots'
import type { AttackTechnique, HuntHypothesis } from '../../types'

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
  const [selectedTactic, setSelectedTactic] = useState('')
  const [search, setSearch] = useState('')
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
      (!normalizedSearch || `${technique.id} ${technique.name} ${technique.tactics.join(' ')}`
        .toLocaleLowerCase().includes(normalizedSearch))
    )
  }, [techniques, selectedTactic, search])
  const withReferences = techniques.filter(technique =>
    (hypothesesByTechnique.get(technique.id)?.length ?? 0) > 0 ||
    (rulesByTechnique.get(technique.id)?.length ?? 0) > 0
  ).length

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

      <section aria-label="Reference coverage summary" className="grid gap-3 sm:grid-cols-3">
        <SummaryCard label="ATT&CK techniques" value={techniques.length} loading={techniqueQuery.isLoading} />
        <SummaryCard label="With indexed hunt or rule references" value={withReferences} loading={techniqueQuery.isLoading} />
        <SummaryCard label="Hunt hypotheses" value={hypotheses.length} loading={hypothesisQuery.isLoading} />
      </section>

      <section className="flex flex-wrap items-end gap-3 rounded-xl border border-slate-200 bg-white p-4">
        <label className="min-w-60 flex-1">
          <span className="field-label">Search technique or tactic</span>
          <input className="field-input" type="search" value={search}
            onChange={event => setSearch(event.target.value)} placeholder="Technique ID, name, or tactic" />
        </label>
        <label className="min-w-52">
          <span className="field-label">Tactic</span>
          <select className="field-input" value={selectedTactic}
            onChange={event => setSelectedTactic(event.target.value)}>
            <option value="">All tactics</option>
            {tactics.map(tactic => <option key={tactic}>{tactic}</option>)}
          </select>
        </label>
        <button className="button-primary" onClick={exportLayer} disabled={techniques.length === 0}>
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
        <span className="text-sm text-slate-500">{visible.length} techniques</span>
      </div>
      {visible.length > 0 ? (
        <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-3" aria-label="ATT&CK technique references">
          {visible.map(technique => {
            const linkedHypotheses = hypothesesByTechnique.get(technique.id) ?? []
            const linkedRules = rulesByTechnique.get(technique.id) ?? []
            return (
              <article key={technique.id} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                <h3 className="font-semibold text-slate-950">{technique.name}</h3>
                <p className="mt-1 text-xs text-slate-500">{technique.id} · {technique.tactics.join(', ')}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <span className="badge">{linkedHypotheses.length} hunt references</span>
                  <span className="badge-muted">{linkedRules.length} rule references</span>
                </div>
                {technique.data_sources?.length ? (
                  <p className="mt-3 text-xs text-slate-600"><strong>Data sources:</strong> {technique.data_sources.join(', ')}</p>
                ) : null}
                {technique.detection && (
                  <details className="mt-3">
                    <summary className="cursor-pointer text-sm font-medium text-sky-800">Detection guidance</summary>
                    <p className="mt-2 text-sm text-slate-600">{technique.detection}</p>
                  </details>
                )}
                {linkedHypotheses.length > 0 && (
                  <ul className="mt-3 space-y-1 border-t border-slate-100 pt-3">
                    {linkedHypotheses.map(hypothesis => (
                      <li key={hypothesis.id}>
                        <Link className="text-sm text-sky-800 hover:underline" to="/hypotheses">{hypothesis.title}</Link>
                      </li>
                    ))}
                  </ul>
                )}
                {linkedRules.length > 0 && (
                  <ul className="mt-3 space-y-1 border-t border-slate-100 pt-3">
                    {linkedRules.slice(0, 4).map(rule => (
                      <li className="truncate text-sm text-slate-700" key={rule.id}>{rule.title}</li>
                    ))}
                  </ul>
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
