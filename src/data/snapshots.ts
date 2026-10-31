import { useQuery } from '@tanstack/react-query'
import type {
  DataManifest,
  AttackTechnique,
  DetectionRule,
  EpssEntry,
  HuntHypothesis,
  IOCRecord,
  KevSnapshot,
  NewsSnapshot,
} from '../types'

async function fetchSnapshot<T>(path: string): Promise<T> {
  const url = new URL(`${import.meta.env.BASE_URL}data/${path}`, window.location.origin)
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Could not load ${path}: ${response.status} ${response.statusText}`)
  }
  return response.json() as Promise<T>
}

export function useManifest() {
  return useQuery({
    queryKey: ['snapshot', 'manifest'],
    queryFn: () => fetchSnapshot<DataManifest>('manifest.json'),
    staleTime: 5 * 60 * 1000,
  })
}

export function useKev() {
  return useQuery({
    queryKey: ['snapshot', 'kev'],
    queryFn: () => fetchSnapshot<KevSnapshot>('kev.json'),
    staleTime: 30 * 60 * 1000,
  })
}

export function useEpss() {
  return useQuery({
    queryKey: ['snapshot', 'epss'],
    queryFn: () => fetchSnapshot<EpssEntry[]>('epss.json'),
    staleTime: 30 * 60 * 1000,
  })
}

export function useHypotheses() {
  return useQuery({
    queryKey: ['snapshot', 'hypotheses'],
    queryFn: () => fetchSnapshot<HuntHypothesis[]>('hunt-hypotheses.json'),
    staleTime: 30 * 60 * 1000,
  })
}

export function useIocs() {
  return useQuery({
    queryKey: ['snapshot', 'iocs'],
    queryFn: () => fetchSnapshot<IOCRecord[]>('iocs.json'),
    staleTime: 30 * 60 * 1000,
  })
}

export function useRules() {
  return useQuery({
    queryKey: ['snapshot', 'rules'],
    queryFn: () => fetchSnapshot<DetectionRule[]>('rules.json'),
    staleTime: 30 * 60 * 1000,
  })
}

export function useTechniques() {
  return useQuery({
    queryKey: ['snapshot', 'techniques'],
    queryFn: () => fetchSnapshot<AttackTechnique[]>('techniques.json'),
    staleTime: 30 * 60 * 1000,
  })
}

export function useNews() {
  return useQuery({
    queryKey: ['snapshot', 'news'],
    queryFn: () => fetchSnapshot<NewsSnapshot>('news.json'),
    staleTime: 30 * 60 * 1000,
  })
}
