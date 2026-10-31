import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useIocs, useKev } from '../../data/snapshots'
import { classifyIndicators, extractIndicators, toCsv, toStixBundle } from '../../utils/indicators'

const sample = `2026-10-31T12:00:00Z denied connection from 198.51.100.23 to suspicious.example
Alert: CVE-2026-12345 observed on host 10.1.2.3
File hash: 44d88612fea8a8f36de82e1278abb02f`

export default function Triage() {
  const [input, setInput] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const iocs = useIocs()
  const kev = useKev()
  const extracted = useMemo(
    () => submitted ? extractIndicators(input) : [],
    [input, submitted]
  )
  const results = useMemo(
    () => classifyIndicators(extracted, iocs.data ?? [], kev.data),
    [extracted, iocs.data, kev.data]
  )
  const loading = iocs.isLoading || kev.isLoading

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
          <p className="text-sm font-semibold uppercase tracking-widest text-sky-700">Offline workbench</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-950">IOC triage</h1>
          <p className="mt-2 text-slate-600">Extract and check indicators against the locally published snapshots.</p>
        </div>
        <Link className="button-secondary" to="/">Back to daily brief</Link>
      </header>

      <aside className="rounded-xl border border-sky-200 bg-sky-50 p-4 text-sm text-sky-950">
        Pasted text is processed in this browser and is never uploaded. Verdicts are limited to the local snapshot:
        “Not in snapshot” does not mean safe.
      </aside>

      <section className="rounded-xl border border-slate-200 bg-white p-4">
        <label htmlFor="triage-input" className="field-label">Paste firewall logs, CSV, or JSON</label>
        <textarea
          id="triage-input"
          className="field-input min-h-56 resize-y font-mono"
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
            {loading ? 'Loading local snapshot…' : 'Extract and check locally'}
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
            Could not load the local indicator snapshot: {[iocs, kev].filter(q => q.isError).map(q => q.error.message).join(' ')}
          </p>
        )}
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
                <button className="button-primary" onClick={exportStix}>Export STIX 2.1</button>
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
                      <td className="break-all px-4 py-3 font-mono text-xs">{result.value}</td>
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
    </div>
  )
}
