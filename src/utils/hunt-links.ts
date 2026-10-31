import type { HuntHypothesis } from '../types'

export interface RelatedHunt {
  hypothesis: HuntHypothesis
  technique: string
}

export function findRelatedHunts(
  techniques: string[],
  hypotheses: HuntHypothesis[],
): RelatedHunt[] {
  const related = new Map<string, RelatedHunt>()
  for (const technique of techniques) {
    for (const hypothesis of hypotheses) {
      if (hypothesis.attack_techniques?.includes(technique) && !related.has(hypothesis.id)) {
        related.set(hypothesis.id, { hypothesis, technique })
      }
    }
  }
  return [...related.values()]
}
