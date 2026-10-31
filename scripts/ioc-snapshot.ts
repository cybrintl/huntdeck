export function selectIocSample(values: string[], limit = 100): string[] {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new Error('IOC sample limit must be a positive integer')
  }
  return [...new Set(values)].slice(0, limit)
}
