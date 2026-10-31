import MiniSearch from 'minisearch'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useRules } from '../../data/snapshots'
import type { DetectionRule, RuleDeploymentState } from '../../types'
import { getRuleStates, saveRuleState } from '../../storage/user-store'

const deploymentStatuses: RuleDeploymentState['status'][] = ['not_deployed', 'deployed', 'na']

export default function Rules() {
  const query = useRules()
  const rules = query.data ?? []
  const [search, setSearch] = useState('')
  const [language, setLanguage] = useState('')
  const [states, setStates] = useState<Record<string, RuleDeploymentState>>({})
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    let active = true
    getRuleStates().then(items => {
      if (active) setStates(Object.fromEntries(items.map(item => [item.id, item])))
    }).catch(reason => {
      if (active) setError(reason instanceof Error ? reason.message : 'Could not load local rule state')
    })
    return () => { active = false }
  }, [])

  const index = useMemo(() => {
    const miniSearch = new MiniSearch({
      fields: ['id', 'title', 'attack_techniques', 'log_source', 'language', 'severity'],
      storeFields: ['id'],
      searchOptions: { prefix: true, fuzzy: 0.2 },
    })
    miniSearch.addAll(rules.map(rule => ({ ...rule, attack_techniques: rule.attack_techniques.join(' ') })))
    return miniSearch
  }, [rules])

  const languages = useMemo(() => [...new Set(rules.map(rule => rule.language))].sort(), [rules])
  const filtered = useMemo(() => {
    const ids = search.trim() ? new Set(index.search(search).map(result => String(result.id))) : undefined
    return rules.filter(rule => (!ids || ids.has(rule.id)) && (!language || rule.language === language))
  }, [rules, index, search, language])

  async function setDeployment(rule: DetectionRule, status: RuleDeploymentState['status']) {
    const next = { id: rule.id, status, updated_at: new Date().toISOString() }
    try {
      await saveRuleState(next)
      setStates(previous => ({ ...previous, [rule.id]: next }))
      setError('')
      setNotice(`Saved deployment status for “${rule.title}” on this device.`)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not save local rule state')
    }
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Detection engineering</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Rule search</h1>
          <p className="mt-2 text-slate-600">Search indexed detections by title, technique, source, or query language.</p>
        </div>
        <Link className="button-secondary" to="/">Back to daily brief</Link>
      </header>

      <section className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 md:grid-cols-3">
        <label className="md:col-span-2">
          <span className="field-label">Search rules</span>
          <input className="field-input" type="search" value={search} onChange={event => setSearch(event.target.value)}
            placeholder="Title, ATT&CK ID, log source, or language" />
        </label>
        <label>
          <span className="field-label">Language</span>
          <select className="field-input" value={language} onChange={event => setLanguage(event.target.value)}>
            <option value="">All languages</option>
            {languages.map(item => <option key={item}>{item}</option>)}
          </select>
        </label>
      </section>

      {notice && <p className="rounded-lg bg-emerald-50 p-3 text-sm text-emerald-900" role="status">{notice}</p>}
      {error && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">{error}</p>}
      {query.isError && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">{query.error.message}</p>}
      <p className="text-sm text-slate-500">{query.isLoading ? 'Loading detection index…' : `${filtered.length} rules`}</p>

      {filtered.length > 0 ? (
        <section className="grid gap-4 xl:grid-cols-2" aria-label="Detection rule results">
          {filtered.map(rule => (
            <article key={rule.id} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h2 className="font-semibold text-slate-950">{rule.title}</h2>
                  <p className="mt-1 text-xs text-slate-500">{rule.id}</p>
                </div>
                <span className="badge-muted">{rule.license}</span>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <span className="badge">{rule.language}</span>
                {rule.severity && <span className="badge">{rule.severity}</span>}
                {rule.attack_techniques.map(technique => <span className="badge" key={technique}>{technique}</span>)}
              </div>
              {rule.log_source && <p className="mt-3 text-sm text-slate-600">Log source: {rule.log_source}</p>}
              {rule.query_text && (
                <div className="mt-3">
                  <div className="mb-1 flex justify-end">
                    <button className="text-xs font-semibold text-sky-800 hover:underline" onClick={() =>
                      navigator.clipboard.writeText(rule.query_text!).catch(reason =>
                        setError(reason instanceof Error ? reason.message : 'Clipboard access failed'))}>
                      Copy query
                    </button>
                  </div>
                  <pre className="overflow-x-auto rounded-lg bg-slate-950 p-3 text-sm text-slate-100">
                    <code>{rule.query_text}</code>
                  </pre>
                </div>
              )}
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4">
                <a className="text-sm font-semibold text-sky-800 underline" href={rule.url}
                  target="_blank" rel="noreferrer">Open source rule</a>
                <label className="flex items-center gap-2 text-xs text-slate-600">
                  Deployment status
                  <select className="field-input min-h-9 w-auto" value={states[rule.id]?.status ?? 'not_deployed'}
                    onChange={event => void setDeployment(rule, event.target.value as RuleDeploymentState['status'])}>
                    {deploymentStatuses.map(status => (
                      <option key={status} value={status}>{status.replace('_', ' ')}</option>
                    ))}
                  </select>
                </label>
              </div>
            </article>
          ))}
        </section>
      ) : (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white p-6">
          <h2 className="font-semibold text-slate-900">
            {query.isLoading ? 'Loading rule index…' : rules.length === 0 ? 'No rules have been indexed yet' : 'No matching rules'}
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            {rules.length === 0
              ? 'The search interface is ready; the rules snapshot will populate it when the data pipeline adds Sigma and detection-rule metadata.'
              : 'Try a different title, technique ID, log source, or language.'}
          </p>
        </div>
      )}
    </div>
  )
}
