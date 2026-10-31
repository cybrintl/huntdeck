import { Link, NavLink, Outlet } from 'react-router-dom'

const navigation = [
  { to: '/', label: 'Daily brief', end: true },
  { to: '/intelligence', label: 'Intel leads', end: false },
  { to: '/hypotheses', label: 'Hypotheses', end: false },
  { to: '/coverage', label: 'Coverage', end: false },
  { to: '/triage', label: 'IOC triage', end: false },
  { to: '/rules', label: 'Rules', end: false },
  { to: '/journal', label: 'Journal', end: false },
]

export default function Layout() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-800 bg-slate-900 text-white print:hidden">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <Link to="/" className="flex items-center gap-3 font-semibold tracking-wide">
            <span className="grid size-9 place-items-center rounded-lg bg-sky-500 text-sm font-black text-slate-950">HD</span>
            <span>HuntDeck</span>
          </Link>
          <nav aria-label="Primary navigation" className="flex flex-wrap gap-1">
            {navigation.map(item => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => isActive ? 'nav-link nav-link-active' : 'nav-link'}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          <span className="hidden text-xs text-slate-400 md:block">Static intel · private local workspace</span>
        </div>
      </header>
      <main className="px-4 py-8 sm:px-6 lg:py-10">
        <Outlet />
      </main>
      <footer className="mx-auto max-w-7xl px-4 pb-8 text-xs text-slate-500 sm:px-6 print:hidden">
        HuntDeck runs in your browser. Analyst notes and hunt status stay on this device.
      </footer>
    </div>
  )
}
