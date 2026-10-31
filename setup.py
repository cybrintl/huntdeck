import os

# Get current directory (your Codespace repo)
BASE = os.getcwd()
print(f"📁 Installing HuntDeck in: {BASE}")

# Create all directories
dirs = [
    ".github/workflows",
    "scripts/ai/fixtures", "scripts/ai/prompts",
    "src/modules/brief", "src/modules/hypotheses", "src/modules/coverage",
    "src/modules/triage", "src/modules/rules",
    "src/hooks", "src/types", "src/utils",
    "public/data", "docs"
]
for d in dirs:
    os.makedirs(d, exist_ok=True)
    print(f"📁 Created: {d}")

# ========== ROOT FILES ==========
files = {
    "package.json": '''{
  "name": "huntdeck",
  "private": true,
  "version": "0.1.0",
  "license": "Apache-2.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^19.3.1",
    "react-dom": "^19.3.1",
    "react-router-dom": "^7.6.1",
    "@tanstack/react-query": "^5.80.7",
    "lucide-react": "^0.513.0",
    "minisearch": "^7.1.1"
  },
  "devDependencies": {
    "@types/react": "^19.0.8",
    "@types/react-dom": "^19.0.3",
    "@vitejs/plugin-react": "^4.3.3",
    "autoprefixer": "^10.4.21",
    "oxlint": "^0.9.10",
    "postcss": "^8.5.6",
    "tailwindcss": "^4.3.3",
    "typescript": "^5.6.3",
    "vite": "^5.4.10"
  }
}''',
    "vite.config.ts": '''import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  base: '/huntdeck/',
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
})
''',
    "tsconfig.json": '''{
  "compilerOptions": {
    "target": "ES2020", "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext", "skipLibCheck": true,
    "moduleResolution": "bundler", "allowImportingTsExtensions": true,
    "resolveJsonModule": true, "isolatedModules": true, "noEmit": true,
    "jsx": "react-jsx", "strict": true, "baseUrl": ".",
    "paths": { "@/*": ["src/*"] }
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}''',
    "tsconfig.node.json": '''{
  "compilerOptions": {
    "composite": true, "skipLibCheck": true,
    "module": "ESNext", "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true, "strict": true
  },
  "include": ["scripts", "vite.config.ts"]
}''',
    "index.html": '''<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/huntdeck/favicon.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>HuntDeck</title>
    <link rel="manifest" href="/huntdeck/manifest.json" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/huntdeck/src/main.tsx"></script>
  </body>
</html>''',
    ".gitignore": '''node_modules/
dist/
.tsbuildinfo
.vite/
.DS_Store
''',
    "tailwind.config.js": '''export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: 'class',
  theme: { extend: {} },
  plugins: [],
}''',
    "postcss.config.js": '''export default {
  plugins: { tailwindcss: {}, autoprefixer: {} },
}''',
    "README.md": '''# HuntDeck
Client-side threat hunting platform
`npm install && npm run dev`
'''
}

for name, content in files.items():
    with open(name, 'w') as f:
        f.write(content)
    print(f"📄 Created: {name}")

# ========== GITHUB WORKFLOWS ==========
with open(".github/workflows/ci.yml", 'w') as f:
    f.write('''name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm ci
''')
print("📄 Created: .github/workflows/ci.yml")

with open(".github/workflows/build-data.yml", 'w') as f:
    f.write('''name: Build Data
on:
  schedule: [{ cron: '0 0 * * *' }]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm ci
      - run: npm run fetch:all || true
      - run: npm run build:data || true
''')
print("📄 Created: .github/workflows/build-data.yml")

# ========== SCRIPTS ==========
scripts = {
    "fetch-kev.ts": '''import fs from 'fs'
const URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
const res = await fetch(URL)
const data = await res.json()
fs.writeFileSync('public/data/kev.json', JSON.stringify(data, null, 2))
console.log('✅ KEV saved')
''',
    "fetch-epss.ts": '''import fs from 'fs'
const res = await fetch('https://api.first.epss.debian.org/epss')
const csv = await res.text()
const lines = csv.split('\\\\n').slice(1)
const data = lines.map(l => {
  const [cve, epss] = l.split(',')
  return { cve, epss: parseFloat(epss) }
}).filter(d => !isNaN(d.epss))
fs.writeFileSync('public/data/epss.json', JSON.stringify(data, null, 2))
console.log('✅ EPSS saved')
''',
    "build-snapshot.ts": '''import fs from 'fs'
const manifest = {
  schema_version: 1,
  built_at: new Date().toISOString(),
  sources: { kev: new Date().toISOString() }
}
fs.writeFileSync('public/data/manifest.json', JSON.stringify(manifest, null, 2))
console.log('✅ Manifest saved')
'''
}

for name, content in scripts.items():
    with open(f"scripts/{name}", 'w') as f:
        f.write(content)
    print(f"📄 Created: scripts/{name}")

# ========== PUBLIC FILES ==========
with open("public/favicon.svg", 'w') as f:
    f.write('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🎯</text></svg>')
print("📄 Created: public/favicon.svg")

with open("public/manifest.json", 'w') as f:
    f.write('''{
  "name": "HuntDeck",
  "short_name": "HD",
  "start_url": "/huntdeck/",
  "display": "standalone",
  "icons": [{ "src": "/huntdeck/favicon.svg", "sizes": "any" }]
}''')
print("📄 Created: public/manifest.json")

# ========== DATA FILES ==========
data = {
    "hunt-hypotheses.json": '''[{
  "id": "hyp-001",
  "title": "Password Spraying Hunt",
  "origin": "template:T1110.003",
  "queries": {
    "kql": { "language": "KQL", "query": "SecurityEvent | where EventID == 4740" },
    "spl": { "language": "SPL", "query": "index=wineventlog EventCode=4740" }
  }
}]''',
    "kev.json": '[]',
    "epss.json": '[]',
    "manifest.json": '{"schema_version": 1}'
}

for name, content in data.items():
    with open(f"public/data/{name}", 'w') as f:
        f.write(content)
    print(f"📄 Created: public/data/{name}")

# ========== SRC FILES ==========
src = {
    "main.tsx": '''import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
ReactDOM.createRoot(document.getElementById('root')!).render(
  <BrowserRouter basename="/huntdeck"><App /></BrowserRouter>
)
''',
    "App.tsx": '''import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Routes, Route } from 'react-router-dom'
import Layout from './Layout'
import Home from './modules/brief/Home'
const qc = new QueryClient()
export default function App() {
  return <QueryClientProvider client={qc}><Layout><Routes>
    <Route path="/" element={<Home />} />
  </Routes></Layout></QueryClientProvider>
}
''',
    "Layout.tsx": '''import { Link, Outlet } from 'react-router-dom'
export default function Layout() {
  return <div className="min-h-screen">
    <header className="bg-gray-800 p-4"><Link to="/" className="text-white">HuntDeck</Link></header>
    <main className="p-4"><Outlet /></main>
  </div>
}
''',
    "index.css": '''@tailwind base;@tailwind components;@tailwind utilities;'''
}

for name, content in src.items():
    with open(f"src/{name}", 'w') as f:
        f.write(content)
    print(f"📄 Created: src/{name}")

# ========== MODULE FILES ==========
with open("src/modules/brief/Home.tsx", 'w') as f:
    f.write('''export default function Home() {
  return <div>
    <h1 className="text-2xl font-bold">Daily Hunt Brief</h1>
    <p>Welcome to HuntDeck</p>
  </div>
}''')
print("📄 Created: src/modules/brief/Home.tsx")

# ========== TYPES ==========
with open("src/types/index.ts", 'w') as f:
    f.write('''export interface HuntHypothesis {
  id: string; title: string;
  queries: Record<string, { language: string; query: string }>
}''')
print("📄 Created: src/types/index.ts")

print("\n✅ ALL FILES CREATED!")
print("✅ Now run: npm install && npm run dev")