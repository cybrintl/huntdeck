import { useLayoutEffect, useState } from 'react'
import { Link, NavLink, Outlet } from 'react-router-dom'

const themes = [
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
  { value: 'ocean', label: 'Ocean' },
  { value: 'forest', label: 'Forest' },
] as const

type Theme = typeof themes[number]['value']

function isTheme(value: string | null): value is Theme {
  return themes.some(theme => theme.value === value)
}

const navigation = [
  { to: '/', label: 'Daily brief', end: true },
  { to: '/hypotheses', label: 'Hypotheses', end: false },
  { to: '/ideas', label: 'Hunt ideas', end: false },
  { to: '/coverage', label: 'Coverage', end: false },
  { to: '/rules', label: 'Rules', end: false },
  { to: '/triage', label: 'IOC triage', end: false },
  { to: '/health', label: 'Data health', end: false },
  { to: '/intelligence', label: 'Intel leads', end: false },
]

export default function Layout() {
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = window.localStorage.getItem('huntdeck-theme')
    return isTheme(saved) ? saved : 'light'
  })
  const [themeError, setThemeError] = useState('')

  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.style.colorScheme = theme === 'light' ? 'light' : 'dark'
  }, [theme])

  function changeTheme(value: string) {
    if (!isTheme(value)) return
    setTheme(value)
    try {
      window.localStorage.setItem('huntdeck-theme', value)
      setThemeError('')
    } catch (error) {
      setThemeError(error instanceof Error ? error.message : 'Theme preference could not be saved')
    }
  }

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
          <label className="flex items-center gap-2 text-xs text-slate-300">
            <span>Theme</span>
            <select className="theme-select" value={theme} onChange={event => changeTheme(event.target.value)}
              aria-label="Color theme">
              {themes.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
            </select>
          </label>
        </div>
        {themeError && <p className="px-4 pb-2 text-right text-xs text-amber-200" role="status">{themeError}</p>}
      </header>
      <main className="px-4 py-8 sm:px-6 lg:py-10">
        <Outlet />
      </main>
      <footer className="mx-auto max-w-7xl px-4 pb-8 text-xs text-slate-500 sm:px-6 print:hidden">
        Open threat-hunting references for everyone. No account, server-side profiles, or submitted hunt data.
      </footer>
    </div>
  )
}
