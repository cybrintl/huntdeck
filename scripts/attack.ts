interface StixObject {
  type?: string
  id?: string
  revoked?: boolean
  x_mitre_deprecated?: boolean
  name?: string
  description?: string
  x_mitre_detection?: string
  x_mitre_data_sources?: string[]
  x_mitre_analytic_refs?: string[]
  x_mitre_log_source_references?: Array<{ name?: string; channel?: string }>
  x_mitre_platforms?: string[]
  kill_chain_phases?: Array<{ kill_chain_name?: string; phase_name?: string }>
  external_references?: Array<{ source_name?: string; external_id?: string; url?: string }>
  relationship_type?: string
  source_ref?: string
  target_ref?: string
}

interface AttackTechniqueRecord {
  id: string
  name: string
  tactics: string[]
  data_sources: string[]
  description: string
  detection: string
  detection_strategies: Array<{
    id: string
    name: string
    url: string
    analytics: Array<{
      name: string
      description: string
      platforms: string[]
      log_sources: string[]
    }>
  }>
}

function isStixObject(value: unknown): value is StixObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string' && item.length > 0)
    : []
}

function referenceId(object: StixObject): string | undefined {
  return object.external_references?.find(reference => reference.source_name === 'mitre-attack')?.external_id
}

function strategyUrl(strategy: StixObject): string | undefined {
  return strategy.external_references?.find(reference => reference.source_name === 'mitre-attack')?.url
}

export function buildAttackTechniques(values: unknown[]): AttackTechniqueRecord[] {
  const objects = values.filter(isStixObject)
  const objectById = new Map(
    objects.filter((object): object is StixObject & { id: string } => Boolean(object.id))
      .map(object => [object.id, object])
  )

  const techniques = objects.filter((object): object is StixObject & { id: string; name: string } =>
    object.type === 'attack-pattern' &&
    !object.revoked &&
    !object.x_mitre_deprecated &&
    Boolean(object.id && object.name) &&
    /^T\d{4}(?:\.\d{3})?$/.test(referenceId(object) ?? '')
  )
  const strategiesByTechnique = new Map<string, StixObject[]>()

  for (const relationship of objects) {
    if (relationship.type !== 'relationship' || relationship.relationship_type !== 'detects') continue
    const strategy = objectById.get(relationship.source_ref ?? '')
    const technique = objectById.get(relationship.target_ref ?? '')
    const techniqueExternalId = technique ? referenceId(technique) : undefined
    if (
      strategy?.type !== 'x-mitre-detection-strategy' ||
      technique?.type !== 'attack-pattern' ||
      !techniqueExternalId
    ) continue
    strategiesByTechnique.set(techniqueExternalId, [
      ...(strategiesByTechnique.get(techniqueExternalId) ?? []),
      strategy,
    ])
  }

  const analytics = new Map(
    objects.filter((object): object is StixObject & { id: string } =>
      object.type === 'x-mitre-analytic' && Boolean(object.id)
    ).map(object => [object.id, object])
  )

  return techniques.map(object => {
    const id = referenceId(object)
    if (!id) throw new Error(`ATT&CK technique ${object.name} has no MITRE ID`)
    const detectionStrategies = (strategiesByTechnique.get(id) ?? [])
      .map(strategy => {
        const strategyId = referenceId(strategy) ?? strategy.id ?? ''
        const analyticItems = strings(strategy.x_mitre_analytic_refs).flatMap(analyticId => {
          const analytic = analytics.get(analyticId)
          if (!analytic) return []
          return [{
            name: analytic.name ?? 'ATT&CK analytic',
            description: analytic.description ?? '',
            platforms: strings(analytic.x_mitre_platforms),
            log_sources: (analytic.x_mitre_log_source_references ?? [])
              .flatMap(source => {
                if (!source.name) return []
                return [source.channel ? `${source.name} (${source.channel})` : source.name]
              }),
          }]
        })
        return {
          id: strategyId,
          name: strategy.name ?? 'ATT&CK detection strategy',
          url: strategyUrl(strategy) ??
            (strategyId ? `https://attack.mitre.org/detectionstrategies/${strategyId}/` : ''),
          analytics: analyticItems,
        }
      })
      .sort((a, b) => a.name.localeCompare(b.name))

    return {
      id,
      name: object.name,
      tactics: [...new Set(
        (object.kill_chain_phases ?? [])
          .filter(phase => phase.kill_chain_name === 'mitre-attack')
          .flatMap(phase => phase.phase_name ? [phase.phase_name] : [])
      )],
      data_sources: strings(object.x_mitre_data_sources),
      description: object.description ?? '',
      detection: object.x_mitre_detection ?? '',
      detection_strategies: detectionStrategies,
    }
  })
}
