import { Link, Outlet } from 'react-router-dom'
export default function Layout() {
  return <div className="min-h-screen">
    <header className="bg-gray-800 p-4"><Link to="/" className="text-white">HuntDeck</Link></header>
    <main className="p-4"><Outlet /></main>
  </div>
}
