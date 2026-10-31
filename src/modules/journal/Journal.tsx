import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useHypotheses } from '../../data/snapshots'
import type { HuntResult, JournalDraft, JournalEntry } from '../../types'
import {
  deleteJournalEntry,
  getJournalDrafts,
  getJournalEntries,
  saveJournalDraft,
  saveJournalEntry,
} from '../../storage/user-store'

const results: { value: HuntResult; label: string }[] = [
  { value: 'true_positive', label: 'True positive' },
  { value: 'false_positive', label: 'False positive' },
  { value: 'nothing_found', label: 'Nothing found' },
  { value: 'detection_gap', label: 'Detection gap found' },
]

const today = new Date().toISOString().slice(0, 10)

export default function Journal() {
  const hypotheses = useHypotheses()
  const [entries, setEntries] = useState<JournalEntry[]>([])
  const [drafts, setDrafts] = useState<JournalDraft[]>([])
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('')
  const [title, setTitle] = useState('')
  const [hypothesisId, setHypothesisId] = useState('')
  const [analyst, setAnalyst] = useState('')
  const [date, setDate] = useState(today)
  const [result, setResult] = useState<HuntResult>('nothing_found')
  const [notes, setNotes] = useState('')
  const [evidence, setEvidence] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  async function refresh() {
    const [savedEntries, savedDrafts] = await Promise.all([getJournalEntries(), getJournalDrafts()])
    setEntries(savedEntries)
    setDrafts(savedDrafts)
  }

  useEffect(() => {
    let active = true
    Promise.all([getJournalEntries(), getJournalDrafts()]).then(([savedEntries, savedDrafts]) => {
      if (active) {
        setEntries(savedEntries)
        setDrafts(savedDrafts)
      }
    }).catch(reason => {
      if (active) setError(reason instanceof Error ? reason.message : 'Could not load local journal')
    })
    return () => { active = false }
  }, [])

  const filtered = useMemo(() => entries.filter(entry => {
    const text = `${entry.title} ${entry.analyst} ${entry.notes} ${entry.evidence}`.toLowerCase()
    return (!filter || entry.result === filter) && (!search || text.includes(search.toLowerCase()))
  }), [entries, filter, search])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const linked = hypotheses.data?.find(item => item.id === hypothesisId)
    const entry: JournalEntry = {
      id: crypto.randomUUID(),
      hypothesis_id: hypothesisId || undefined,
      title: title.trim() || linked?.title || '',
      date: new Date(`${date}T12:00:00`).toISOString(),
      analyst: analyst.trim(),
      result,
      notes: notes.trim(),
      evidence: evidence.trim(),
    }
    try {
      await saveJournalEntry(entry)
      await refresh()
      setTitle('')
      setHypothesisId('')
      setNotes('')
      setEvidence('')
      setError('')
      setNotice('Hunt log saved locally on this device.')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not save this journal entry')
    }
  }

  async function removeEntry(entry: JournalEntry) {
    try {
      await deleteJournalEntry(entry.id)
      await refresh()
      setNotice('Journal entry deleted from this device.')
      setError('')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not delete this journal entry')
    }
  }

  async function saveDraft() {
    if (!title.trim() && !notes.trim()) {
      setError('Add a title or hunt notes before saving a hypothesis draft.')
      return
    }
    const draft: JournalDraft = {
      id: crypto.randomUUID(),
      title: title.trim() || 'Untitled hypothesis draft',
      source_entry_id: '',
      created_at: new Date().toISOString(),
      notes: notes.trim(),
    }
    try {
      await saveJournalDraft(draft)
      await refresh()
      setNotice('Hypothesis draft saved locally.')
      setError('')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not save the hypothesis draft')
    }
  }

  function exportMarkdown() {
    const body = [
      '# HuntDeck Hunt Journal',
      '',
      ...filtered.flatMap(entry => [
        `## ${entry.title}`,
        '',
        `- Date: ${entry.date.slice(0, 10)}`,
        `- Analyst: ${entry.analyst || 'Not specified'}`,
        `- Result: ${results.find(item => item.value === entry.result)?.label ?? entry.result}`,
        ...(entry.hypothesis_id ? [`- Hypothesis: ${entry.hypothesis_id}`] : []),
        '',
        entry.notes,
        ...(entry.evidence ? ['', '### Evidence', '', '```text', entry.evidence, '```'] : []),
        '',
      ]),
    ].join('\n')
    const url = URL.createObjectURL(new Blob([body], { type: 'text/markdown' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `huntdeck-journal-${today}.md`
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Analyst workspace</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">Hunt journal</h1>
          <p className="mt-2 text-slate-600">Logs, notes, and evidence stay in this browser’s IndexedDB.</p>
        </div>
        <div className="flex gap-2">
          <button className="button-secondary" disabled={filtered.length === 0} onClick={exportMarkdown}>Export Markdown</button>
          <Link className="button-secondary" to="/">Back to daily brief</Link>
        </div>
      </header>

      <section className="rounded-xl border border-sky-200 bg-sky-50 p-4 text-sm text-sky-950">
        Journal data is local to this browser profile. Clearing site storage removes it; use Markdown export for a backup.
      </section>

      <form className="grid gap-4 rounded-xl border border-slate-200 bg-white p-5 md:grid-cols-2" onSubmit={event => void submit(event)}>
        <h2 className="text-lg font-bold md:col-span-2">Log a hunt</h2>
        <label>
          <span className="field-label">Hypothesis</span>
          <select className="field-input" value={hypothesisId} onChange={event => {
            const id = event.target.value
            setHypothesisId(id)
            const linked = hypotheses.data?.find(item => item.id === id)
            if (linked && !title) setTitle(linked.title)
          }}>
            <option value="">No linked hypothesis</option>
            {(hypotheses.data ?? []).map(item => <option value={item.id} key={item.id}>{item.title}</option>)}
          </select>
        </label>
        <label>
          <span className="field-label">Hunt title</span>
          <input className="field-input" value={title} onChange={event => setTitle(event.target.value)} maxLength={160}
            placeholder="What did you hunt?" required={!hypothesisId} />
        </label>
        <label>
          <span className="field-label">Date</span>
          <input className="field-input" type="date" value={date} onChange={event => setDate(event.target.value)} required />
        </label>
        <label>
          <span className="field-label">Analyst name (optional)</span>
          <input className="field-input" value={analyst} onChange={event => setAnalyst(event.target.value)} maxLength={100} />
        </label>
        <label>
          <span className="field-label">Result</span>
          <select className="field-input" value={result} onChange={event => setResult(event.target.value as HuntResult)}>
            {results.map(item => <option value={item.value} key={item.value}>{item.label}</option>)}
          </select>
        </label>
        <label className="md:col-span-2">
          <span className="field-label">Notes</span>
          <textarea className="field-input min-h-24 resize-y" value={notes} onChange={event => setNotes(event.target.value)}
            maxLength={10000} placeholder="What did you observe?" />
        </label>
        <label className="md:col-span-2">
          <span className="field-label">Evidence (optional; kept locally)</span>
          <textarea className="field-input min-h-28 resize-y font-mono" value={evidence}
            onChange={event => setEvidence(event.target.value)} maxLength={50000}
            placeholder="Paste relevant evidence or a redacted excerpt…" />
        </label>
        <div className="flex flex-wrap gap-2 md:col-span-2">
          <button className="button-primary" type="submit">Save hunt log</button>
          <button className="button-secondary" type="button" onClick={() => void saveDraft()}>Save as hypothesis draft</button>
        </div>
      </form>

      {notice && <p className="rounded-lg bg-emerald-50 p-3 text-sm text-emerald-900" role="status">{notice}</p>}
      {error && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-900" role="alert">{error}</p>}

      {drafts.length > 0 && (
        <section>
          <h2 className="mb-3 text-lg font-bold">Local hypothesis drafts</h2>
          <div className="grid gap-3 md:grid-cols-2">
            {drafts.map(draft => (
              <article key={draft.id} className="rounded-xl border border-amber-200 bg-amber-50 p-4">
                <h3 className="font-semibold">{draft.title}</h3>
                <p className="mt-1 whitespace-pre-wrap text-sm text-slate-700">{draft.notes || 'No notes yet.'}</p>
                <p className="mt-2 text-xs text-slate-500">Saved {new Date(draft.created_at).toLocaleString()} · this device only</p>
              </article>
            ))}
          </div>
        </section>
      )}

      <section className="space-y-4">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-xl font-bold">Hunt history</h2>
            <p className="mt-1 text-sm text-slate-600">{filtered.length} local entries</p>
          </div>
          <div className="flex gap-2">
            <input className="field-input" type="search" value={search} onChange={event => setSearch(event.target.value)}
              placeholder="Search journal" aria-label="Search journal" />
            <select className="field-input" value={filter} onChange={event => setFilter(event.target.value)} aria-label="Filter by result">
              <option value="">All results</option>
              {results.map(item => <option value={item.value} key={item.value}>{item.label}</option>)}
            </select>
          </div>
        </div>
        {filtered.length > 0 ? filtered.map(entry => (
          <article key={entry.id} className="rounded-xl border border-slate-200 bg-white p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="font-semibold text-slate-950">{entry.title}</h3>
                <p className="mt-1 text-xs text-slate-500">
                  {entry.date.slice(0, 10)} · {entry.analyst || 'Analyst not specified'} · {results.find(item => item.value === entry.result)?.label}
                </p>
              </div>
              <button className="text-sm text-red-700 hover:underline" onClick={() => void removeEntry(entry)}>Delete</button>
            </div>
            {entry.hypothesis_id && <p className="mt-2 text-xs text-slate-500">Hypothesis: {entry.hypothesis_id}</p>}
            {entry.notes && <p className="mt-3 whitespace-pre-wrap text-sm text-slate-700">{entry.notes}</p>}
            {entry.evidence && (
              <details className="mt-3">
                <summary className="cursor-pointer text-sm font-medium text-sky-800">View local evidence</summary>
                <pre className="mt-2 max-h-80 overflow-auto rounded-lg bg-slate-950 p-3 text-xs text-slate-100">{entry.evidence}</pre>
              </details>
            )}
          </article>
        )) : (
          <div className="rounded-xl border border-dashed border-slate-300 p-6 text-slate-600">
            No journal entries match. New entries are saved only in your browser.
          </div>
        )}
      </section>
    </div>
  )
}
