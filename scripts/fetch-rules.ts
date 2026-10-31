import { execFile } from 'node:child_process'
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'

interface DetectionRule {
  id: string
  title: string
  attack_techniques: string[]
  log_source?: string
  language: string
  license: string
  url: string
  severity?: string
}

const execFileAsync = promisify(execFile)
const repository = 'https://github.com/SigmaHQ/sigma.git'
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'huntdeck-sigma-'))
const rulesDirectory = path.join(temporaryDirectory, 'rules')

async function walk(directory: string): Promise<string[]> {
  const files: string[] = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await walk(fullPath))
    else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) files.push(fullPath)
  }
  return files
}

function scalar(text: string, key: string): string | undefined {
  const match = text.match(new RegExp(`^[ \\t]*${key}:[ \\t]*(.+?)\\s*$`, 'm'))
  return match?.[1]?.replace(/^['"]|['"]$/g, '')
}

async function readPrevious(): Promise<DetectionRule[]> {
  try {
    const value: unknown = JSON.parse(await readFile('public/data/rules.json', 'utf8'))
    if (Array.isArray(value)) return value as DetectionRule[]
    throw new Error('Existing rules snapshot is not an array')
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return []
    throw error
  }
}

let rules: DetectionRule[] = []
let warning: string | undefined

try {
  await execFileAsync('git', [
    'clone', '--depth=1', '--filter=blob:none', '--sparse', '--branch', 'master', repository, temporaryDirectory,
  ], { maxBuffer: 10 * 1024 * 1024 })
  await execFileAsync('git', ['-C', temporaryDirectory, 'sparse-checkout', 'set', 'rules'], {
    maxBuffer: 10 * 1024 * 1024,
  })
  const paths = await walk(rulesDirectory)
  const indexed: DetectionRule[] = []
  for (const file of paths) {
    const text = await readFile(file, 'utf8')
    const title = scalar(text, 'title')
    if (!title) continue
    const relative = path.relative(temporaryDirectory, file).split(path.sep).join('/')
    const id = scalar(text, 'id') ?? relative.replace(/\.ya?ml$/i, '')
    const tags = [...text.matchAll(/\battack\.(t\d{4}(?:\.\d{3})?)/gi)].map(match => match[1]?.toUpperCase())
      .filter((technique): technique is string => Boolean(technique))
    const logsource = text.match(/^logsource:\s*\n((?:^[ \t]+.+\n?)*)/m)?.[1] ?? ''
    const product = scalar(logsource, 'product')
    const service = scalar(logsource, 'service')
    const category = scalar(logsource, 'category')
    const severity = scalar(text, 'level')
    indexed.push({
      id,
      title,
      attack_techniques: [...new Set(tags)],
      log_source: [product, service, category].filter(Boolean).join(' / ') || undefined,
      language: 'Sigma',
      license: 'LGPL-2.1',
      url: `https://github.com/SigmaHQ/sigma/blob/master/${relative}`,
      severity,
    })
  }
  if (indexed.length < 100) throw new Error(`Sigma repository returned only ${indexed.length} usable rules`)
  rules = indexed
  console.log(`Sigma rule index built (${rules.length} rules; source queries link to upstream files)`)
} catch (error) {
  const previous = await readPrevious()
  warning = error instanceof Error ? error.message : String(error)
  rules = previous
  console.warn(`Sigma source unavailable; retaining last-good rule index (${rules.length} rules): ${warning}`)
} finally {
  const temporaryStat = await stat(temporaryDirectory)
  if (temporaryStat.isDirectory()) await rm(temporaryDirectory, { recursive: true, force: true })
}

await mkdir('public/data', { recursive: true })
await writeFile('public/data/rules.json', JSON.stringify(rules))
const statusPath = 'public/data/source-status.json'
let sourceStatus: { sources: Record<string, unknown>; warnings: string[] } = { sources: {}, warnings: [] }
try {
  const parsed: unknown = JSON.parse(await readFile(statusPath, 'utf8'))
  if (typeof parsed === 'object' && parsed !== null && 'sources' in parsed && 'warnings' in parsed &&
    typeof parsed.sources === 'object' && parsed.sources !== null && Array.isArray(parsed.warnings)) {
    sourceStatus = parsed as typeof sourceStatus
  }
} catch (error) {
  if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error
}
sourceStatus.sources.sigma = {
  source: 'SigmaHQ rules',
  fetched_at: new Date().toISOString(),
  status: warning ? 'stale' : 'ok',
  count: rules.length,
}
if (warning) sourceStatus.warnings.push(`SigmaHQ: ${warning}`)
await writeFile(statusPath, JSON.stringify(sourceStatus, null, 2))
