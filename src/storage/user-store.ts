import { openDB } from 'idb'
import type {
  CoverageOverride,
  HuntState,
  JournalDraft,
  JournalEntry,
  RuleDeploymentState,
} from '../types'

const database = openDB('huntdeck', 3, {
  upgrade(db) {
    if (!db.objectStoreNames.contains('hunt-state')) {
      db.createObjectStore('hunt-state', { keyPath: 'id' })
    }
    if (!db.objectStoreNames.contains('journal')) {
      db.createObjectStore('journal', { keyPath: 'id' })
    }
    if (!db.objectStoreNames.contains('journal-drafts')) {
      db.createObjectStore('journal-drafts', { keyPath: 'id' })
    }
    if (!db.objectStoreNames.contains('rule-state')) {
      db.createObjectStore('rule-state', { keyPath: 'id' })
    }
    if (!db.objectStoreNames.contains('coverage-overrides')) {
      db.createObjectStore('coverage-overrides', { keyPath: 'id' })
    }
  },
})

export async function getHuntStates(): Promise<HuntState[]> {
  return (await database).getAll('hunt-state')
}

export async function saveHuntState(state: HuntState): Promise<void> {
  await (await database).put('hunt-state', state)
}

export async function getJournalEntries(): Promise<JournalEntry[]> {
  const entries = await (await database).getAll('journal')
  return entries.sort((a, b) => b.date.localeCompare(a.date))
}

export async function saveJournalEntry(entry: JournalEntry): Promise<void> {
  await (await database).put('journal', entry)
}

export async function deleteJournalEntry(id: string): Promise<void> {
  await (await database).delete('journal', id)
}

export async function saveJournalDraft(draft: JournalDraft): Promise<void> {
  await (await database).put('journal-drafts', draft)
}

export async function getJournalDrafts(): Promise<JournalDraft[]> {
  const drafts = await (await database).getAll('journal-drafts')
  return drafts.sort((a, b) => b.created_at.localeCompare(a.created_at))
}

export async function getRuleStates(): Promise<RuleDeploymentState[]> {
  return (await database).getAll('rule-state')
}

export async function saveRuleState(state: RuleDeploymentState): Promise<void> {
  await (await database).put('rule-state', state)
}

export async function getCoverageOverrides(): Promise<CoverageOverride[]> {
  return (await database).getAll('coverage-overrides')
}

export async function saveCoverageOverride(override: CoverageOverride): Promise<void> {
  await (await database).put('coverage-overrides', override)
}
