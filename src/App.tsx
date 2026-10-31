import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Route, Routes } from 'react-router-dom'
import Layout from './Layout'
import Home from './modules/brief/Home'
import Library from './modules/hypotheses/Library'
import Coverage from './modules/coverage/Coverage'
import Triage from './modules/triage/Triage'
import Rules from './modules/rules/Rules'
import Journal from './modules/journal/Journal'
import Intelligence from './modules/intelligence/Intelligence'
const qc = new QueryClient()
export default function App() {
  return <QueryClientProvider client={qc}>
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="intelligence" element={<Intelligence />} />
        <Route path="hypotheses" element={<Library />} />
        <Route path="coverage" element={<Coverage />} />
        <Route path="triage" element={<Triage />} />
        <Route path="rules" element={<Rules />} />
        <Route path="journal" element={<Journal />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  </QueryClientProvider>
}

function NotFound() {
  return (
    <section className="mx-auto max-w-3xl rounded-xl border border-slate-200 bg-white p-8 text-center">
      <h1 className="text-2xl font-bold text-slate-950">Page not found</h1>
      <p className="mt-2 text-slate-600">That HuntDeck page is not available.</p>
    </section>
  )
}
