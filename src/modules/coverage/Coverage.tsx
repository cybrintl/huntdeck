import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { Link } from 'react-router-dom'
import { useHypotheses, useRules, useTechniques } from '../../data/snapshots'
import type {
  AttackTechnique,
  CoverageOverride,
  HuntHypothesis,
  HuntState,
  RuleDeploymentState,
} from '../../types'
import {
  getCoverageOverrides,
  getHuntStates,
  getRuleStates,
  saveCoverageOverride,
} from '../../storage/user-store'

interface NavigatorTechnique {
  techniqueID: string
  score?: number
  comment?: string
}

interface NavigatorLayer {
  domain?: string
  techniques?: NavigatorTechnique[]
}

function techniquesForHypothesis(hypothesis: HuntHypothesis): string[] {
  const declared = hypothesis.attack_techniques ?? []
  const originId = hypothesis.origin?.match(/\bT\d{4}(?:\.\d{3})?\b/)?.[0]
  return [...new Set(originId ? [...declared, originId] : declared)]
}

function makeLayer(techniques: AttackTechnique[], scores: Record<string, CoverageOverride>, covered: Set<string>) {
  return {
    name: 'HuntDeck Coverage',
    versions: { attack: '17', navigator: '4.9.1', layer: '4.5' },
    domain: 'enterprise-attack',
    description: 'Coverage exported from HuntDeck. Scores reflect local hunt coverage and trend context.',
    filters: { platforms: [], stages: [], actors: [], malware: [], teams: [], tactics: [], data_sources: [], query: '' },
    sorting: 0,
    layout: { layout: 'side', aggregateFunction: 'average', showID: true, showName: true, showAggregateScores: false, countUnscored: false },
    hideDisabled: false,
    techniques: techniques.map(technique => ({
      techniqueID: technique.id,
      score: scores[technique.id]?.score ?? (covered.has(technique.id) ? 100 : Math.max(0, Math.min(100, technique.trending_score ?? 0))),
      comment: scores[technique.id]?.comment ?? (covered.has(technique.id) ? 'HuntDeck local status: covered' : 'HuntDeck local status: not marked covered'),
    })),
    gradient: { colors: ['#ffffff', '#7bc8a4', '#d9534f'], minValue: 0, maxValue: 100 },
    legendItems: [
      { label: 'No trend / uncovered', color: '#ffffff' },
      { label: 'Trending or covered', color: '#7bc8a4' },
      { label: 'Highest score', color: '#d9534f' },
    ],
    metadata: [],
  }
}

export default function Coverage() {
  const techniqueQuery = useTechniques()
  const hypothesisQuery = useHypotheses()
  const rulesQuery = useRules()
  const fileInput = useRef<HTMLInputElement>(null)
  const [huntStates, setHuntStates] = useState<Record<string, HuntState>>({})
  const [ruleStates, setRuleStates] = useState<Record<string, RuleDeploymentState>>({})
  const [overrides, setOverrides] = useState<Record<string, CoverageOverride>>({})
  const [selectedTactic, setSelectedTactic] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    let active = true
    Promise.all([getHuntStates(), getRuleStates(), getCoverageOverrides()]).then(([hunts, rules, savedOverrides]) => {
      if (!active) return
      setHuntStates(Object.fromEntries(hunts.map(item => [item.id, item])))
      setRuleStates(Object.fromEntries(rules.map(item => [item.id, item])))
      setOverrides(Object.fromEntries(savedOverrides.map(item => [item.id, item])))
    }).catch(reason => {
      if (active) setError(reason instanceof Error ? reason.message : 'Could not load local coverage state')
    })
    return () => { active = false }
  }, [])

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

  const associatedHypotheses = useMemo(() => {
    const byTechnique = new Map<string, HuntHypothesis[]>()
    for (const hypothesis of hypotheses) {
      for (const id of techniquesForHypothesis(hypothesis)) {
        byTechnique.set(id, [...(byTechnique.get(id) ?? []), hypothesis])
      }
    }
    return byTechnique
  }, [hypotheses])

  const covered = useMemo(() => {
    const techniqueIds = new Set<string>()
    for (const [techniqueId, linked] of associatedHypotheses) {
      if (linked.some(item => huntStates[item.id]?.status === 'covered')) techniqueIds.add(techniqueId)
    }
    for (const rule of rules) {
      if (ruleStates[rule.id]?.status === 'deployed') {
        rule.attack_techniques.forEach(id => techniqueIds.add(id))
      }
    }
    return techniqueIds
  }, [associatedHypotheses, huntStates, rules, ruleStates])

  const tactics = useMemo(
    () => [...new Set(techniques.flatMap(technique => technique.tactics))].sort(),
    [techniques]
  )
  const visible = selectedTactic
    ? techniques.filter(technique => technique.tactics.includes(selectedTactic))
    : techniques
  const gaps = [...techniques]
    .filter(technique => !covered.has(technique.id) && (technique.trending_score ?? 0) > 0)
    .sort((a, b) => (b.trending_score ?? 0) - (a.trending_score ?? 0))

  async function importLayer(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) return
    try {
      const parsed: unknown = JSON.parse(await file.text())
      if (
        typeof parsed !== 'object' ||
        parsed === null ||
        !('domain' in parsed) ||
        parsed.domain !== 'enterprise-attack' ||
        !('techniques' in parsed) ||
        !Array.isArray(parsed.techniques)
      ) {
        throw new Error('Choose a valid ATT&CK Navigator enterprise-attack layer JSON file')
      }
      const layer = parsed as NavigatorLayer
      const importedTechniques = layer.techniques ?? []
      const next = new Map(Object.entries(overrides))
      for (const item of importedTechniques) {
        if (
          typeof item.techniqueID !== 'string' ||
          !/^T\d{4}(?:\.\d{3})?$/.test(item.techniqueID) ||
          (item.score !== undefined && (typeof item.score !== 'number' || item.score < 0 || item.score > 100))
        ) {
          throw new Error('Navigator layer contains an invalid technique ID or score')
        }
        const override: CoverageOverride = {
          id: item.techniqueID,
          score: item.score ?? 0,
          comment: item.comment ?? 'Imported from ATT&CK Navigator',
          updated_at: new Date().toISOString(),
        }
        await saveCoverageOverride(override)
        next.set(override.id, override)
      }
      setOverrides(Object.fromEntries(next))
      setError('')
      setNotice(`Imported ${importedTechniques.length} ATT&CK Navigator technique scores locally.`)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not import Navigator layer')
    } finally {
      event.target.value = ''
    }
  }

  function exportLayer() {
    const layer = makeLayer(techniques, overrides, covered)
    const url = URL.createObjectURL(new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'huntdeck-attack-navigator-layer.json'
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">MITRE ATT&CK</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Coverage workspace</h1>
          <p className="mt-2 text-slate-600">Combine hunt status, deployed rules, and Navigator layer scores stored in this browser.</p>
        </div>
        <Link className="button-secondary" to="/">Back to daily brief</Link>
      </header>

      <section className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-200 bg-white p-4">
        <button className="button-primary" onClick={exportLayer} disabled={techniques.length === 0}>Export Navigator layer</button>
        <button className="button-secondary" onClick={() => fileInput.current?.click()}>Import Navigator layer</button>
        <input ref={fileInput} className="sr-only" type="file" accept="application/json,.json" onChange={event => void importLayer(event)} />
        <span className="text-sm text-slate-500">{techniques.length} techniques in current snapshot</span>
      </section>
      {notice && <p className="rounded-lg bg-emerald-50 p-3 text-sm text-emerald-900" role="status">{notice}</p>}
      {error && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">{error}</p>}
      {(techniqueQuery.isError || hypothesisQuery.isError || rulesQuery.isError) && (
        <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">
          Could not load one or more coverage snapshots.
        </p>
      )}

      {gaps.length > 0 && (
        <section className="rounded-xl border border-amber-200 bg-amber-50 p-5">
          <h2 className="font-semibold text-amber-950">Trending but uncovered</h2>
          <ul className="mt-3 flex flex-wrap gap-2">
            {gaps.map(technique => (
              <li className="badge-warning" key={technique.id}>{technique.id} · score {technique.trending_score}</li>
            ))}
          </ul>
        </section>
      )}

      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-xl font-bold text-slate-950">Technique coverage</h2>
          <select className="field-input w-auto" value={selectedTactic} onChange={event => setSelectedTactic(event.target.value)}>
            <option value="">All tactics</option>
            {tactics.map(tactic => <option key={tactic}>{tactic}</option>)}
          </select>
        </div>
        {visible.length > 0 ? (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {visible.map(technique => {
              const isCovered = covered.has(technique.id)
              const score = overrides[technique.id]?.score ?? technique.trending_score ?? (isCovered ? 100 : 0)
              return (
                <article key={technique.id} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h3 className="font-semibold text-slate-950">{technique.name}</h3>
                      <p className="mt-1 text-xs text-slate-500">{technique.id} · {technique.tactics.join(', ')}</p>
                    </div>
                    <span className={isCovered ? 'badge-success' : 'badge-muted'}>{isCovered ? 'Covered' : 'Gap'}</span>
                  </div>
                  <div className="mt-4">
                    <div className="flex justify-between text-xs text-slate-600"><span>Navigator score</span><span>{score}/100</span></div>
                    <div className="mt-1 h-2 overflow-hidden rounded-full bg-slate-100">
                      <div className={isCovered ? 'h-full bg-emerald-500' : 'h-full bg-amber-400'} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
                    </div>
                  </div>
                  {technique.data_sources && <p className="mt-3 text-xs text-slate-600">Data sources: {technique.data_sources.join(', ')}</p>}
                  {technique.detection && <p className="mt-2 line-clamp-3 text-xs text-slate-600">{technique.detection}</p>}
                  {associatedHypotheses.get(technique.id)?.length ? (
                    <p className="mt-3 text-xs text-sky-800">
                      {associatedHypotheses.get(technique.id)?.length} linked hunt hypothesis/hypotheses
                    </p>
                  ) : <p className="mt-3 text-xs text-slate-500">No linked hunt hypothesis</p>}
                </article>
              )
            })}
          </div>
        ) : (
          <div className="rounded-xl border border-dashed border-slate-300 bg-white p-6 text-slate-600">
            {techniqueQuery.isLoading
              ? 'Loading the ATT&CK technique snapshot…'
              : 'No ATT&CK techniques are indexed yet. Navigator import/export is available when a technique set is loaded.'}
          </div>
        )}
      </section>
    </div>
  )
}
