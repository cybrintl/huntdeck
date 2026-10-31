import { mkdir, readFile, writeFile } from 'node:fs/promises'

export interface SourceSyncStatus {
  kind: 'ioc' | 'detection' | 'news' | 'vulnerability' | 'attack'
  source: string
  url: string
  fetched_at: string
  status: 'ok' | 'stale'
  count: number
  published_count?: number
}

interface SourceStatusDocument {
  sources: Record<string, SourceSyncStatus | string>
  warnings: string[]
}

function sourceIdForName(name: string): string {
  return name.toLocaleLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
}

async function readSourceStatus(): Promise<SourceStatusDocument> {
  try {
    const parsed: unknown = JSON.parse(await readFile('public/data/source-status.json', 'utf8'))
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !('sources' in parsed) ||
      !('warnings' in parsed) ||
      !Array.isArray(parsed.warnings) ||
      typeof parsed.sources !== 'object' ||
      parsed.sources === null
    ) {
      throw new Error('Existing source status snapshot has an invalid format')
    }

    const sources: Record<string, SourceSyncStatus | string> = {}
    if (Array.isArray(parsed.sources)) {
      for (const entry of parsed.sources) {
        if (
          typeof entry !== 'object' ||
          entry === null ||
          !('source' in entry) ||
          typeof entry.source !== 'string' ||
          !('fetched_at' in entry) ||
          typeof entry.fetched_at !== 'string' ||
          !('status' in entry) ||
          (entry.status !== 'ok' && entry.status !== 'stale') ||
          !('count' in entry) ||
          typeof entry.count !== 'number'
        ) {
          throw new Error('Existing source status snapshot contains an invalid entry')
        }
        sources[sourceIdForName(entry.source)] = {
          kind: 'ioc',
          source: entry.source,
          url: 'url' in entry && typeof entry.url === 'string' ? entry.url : '',
          fetched_at: entry.fetched_at,
          status: entry.status,
          count: entry.count,
        }
      }
    } else {
      Object.assign(sources, parsed.sources)
    }

    return {
      sources,
      warnings: parsed.warnings.filter((warning): warning is string => typeof warning === 'string'),
    }
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      return { sources: {}, warnings: [] }
    }
    throw error
  }
}

export async function recordSourceStatus(id: string, status: SourceSyncStatus): Promise<void> {
  const snapshot = await readSourceStatus()
  snapshot.sources[id] = status
  await mkdir('public/data', { recursive: true })
  await writeFile('public/data/source-status.json', JSON.stringify(snapshot, null, 2))
}
