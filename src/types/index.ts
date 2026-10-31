export interface HuntHypothesis {
  id: string; title: string;
  queries: Record<string, { language: string; query: string }>
}