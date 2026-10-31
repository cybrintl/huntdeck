import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Route, Routes } from 'react-router-dom'
import Layout from './Layout'
import Home from './modules/brief/Home'
const qc = new QueryClient()
export default function App() {
  return <QueryClientProvider client={qc}>
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
      </Route>
    </Routes>
  </QueryClientProvider>
}
