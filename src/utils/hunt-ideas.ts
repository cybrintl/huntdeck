import { extractIndicators } from './indicators'

export interface MentionedContext {
  industries: string[]
  geographies: string[]
}

const industryTerms: Array<[string, RegExp]> = [
  ['Agriculture', /\b(?:agriculture|agricultural|agribusiness|farming)\b/i],
  ['Defense', /\b(?:defen[cs]e|military|armed forces)\b/i],
  ['Education', /\b(?:education|educational|university|universities|school district)\b/i],
  ['Energy and utilities', /\b(?:energy sector|utilities|electric grid|oil and gas|power grid)\b/i],
  ['Financial services', /\b(?:financial services|banking|banks|credit union|insurance)\b/i],
  ['Government', /\b(?:government|public sector|federal agency|municipal)\b/i],
  ['Healthcare', /\b(?:healthcare|health care|hospital|medical provider|pharmaceutical)\b/i],
  ['Hospitality and travel', /\b(?:hospitality|hotel chain|airline|travel industry)\b/i],
  ['Legal services', /\b(?:law firm|legal services|legal sector)\b/i],
  ['Manufacturing', /\b(?:manufacturing|manufacturer|industrial control|factory)\b/i],
  ['Media and communications', /\b(?:news media|broadcasting|media company|publisher)\b/i],
  ['Retail and commerce', /\b(?:retail(?:er|ers)?|e-commerce|online marketplace)\b/i],
  ['Technology', /\b(?:technology company|software vendor|IT provider|tech company)\b/i],
  ['Telecommunications', /\b(?:telecommunications|telecom(?:s)? provider|mobile carrier)\b/i],
  ['Transportation and logistics', /\b(?:transportation|logistics|shipping company|railway)\b/i],
]

const geographyTerms: Array<[string, RegExp]> = [
  ['Africa', /\bAfrica(?:n)?\b/i],
  ['Asia-Pacific', /\b(?:Asia[ -]Pacific|APAC|Indo[ -]Pacific)\b/i],
  ['Europe', /\bEurope(?:an)?\b/i],
  ['Latin America', /\b(?:Latin America|South America|Central America)\b/i],
  ['Middle East', /\bMiddle East(?:ern)?\b/i],
  ['North America', /\bNorth America(?:n)?\b/i],
  ['Australia', /\bAustralia\b/i],
  ['Brazil', /\bBrazil(?:ian)?\b/i],
  ['Canada', /\bCanada\b/i],
  ['China', /\bChina\b/i],
  ['France', /\bFrance\b/i],
  ['Germany', /\bGermany\b/i],
  ['India', /\bIndia\b/i],
  ['Iran', /\bIran(?:ian)?\b/i],
  ['Israel', /\bIsrael\b/i],
  ['Japan', /\bJapan\b/i],
  ['Mexico', /\bMexico\b/i],
  ['Netherlands', /\bNetherlands\b/i],
  ['North Korea', /\bNorth Korea\b/i],
  ['Pakistan', /\bPakistan\b/i],
  ['Philippines', /\bPhilippines\b/i],
  ['Poland', /\bPoland\b/i],
  ['Russia', /\bRussia(?:n)?\b/i],
  ['Saudi Arabia', /\bSaudi Arabia\b/i],
  ['Singapore', /\bSingapore\b/i],
  ['South Korea', /\bSouth Korea\b/i],
  ['Taiwan', /\bTaiwan\b/i],
  ['Türkiye', /\b(?:Türkiye|Turkey)\b/i],
  ['Ukraine', /\bUkraine\b/i],
  ['United Arab Emirates', /\b(?:United Arab Emirates|UAE)\b/i],
  ['United Kingdom', /\b(?:United Kingdom|UK|Britain|British)\b/i],
  ['United States', /\b(?:United States|USA|U\.S\.)\b/i],
  ['Vietnam', /\bVietnam\b/i],
]

export function classifyMentionedContext(text: string): MentionedContext {
  return {
    industries: industryTerms
      .filter(([, pattern]) => pattern.test(text))
      .map(([industry]) => industry),
    geographies: geographyTerms
      .filter(([, pattern]) => pattern.test(text))
      .map(([geography]) => geography),
  }
}

export function extractReportIndicators(title: string, summary: string) {
  return extractIndicators(`${title}\n${summary}`)
    .filter(indicator => indicator.type !== 'attack' && indicator.type !== 'cve')
}

export function suggestionForReport(input: {
  title: string
  cves: string[]
  techniques: Array<{ id: string; name: string }>
}): string {
  if (input.cves.length > 0) {
    const cves = input.cves.slice(0, 3).join(', ')
    return `Establish whether your environment contains assets affected by ${cves}, then review the report for concrete exploitation behavior and search relevant network, application, identity, and endpoint telemetry for related activity.`
  }
  if (input.techniques.length > 0) {
    const techniques = input.techniques.slice(0, 3).map(item => `${item.id} (${item.name})`).join(', ')
    return `Use the behavior in this report to scope a hunt for ${techniques}. Search the telemetry available for those techniques, then pivot across related processes, identities, hosts, and network activity.`
  }
  return `Read the linked report for affected products, adversary behavior, and observables; turn those claims into a scoped hunt across the relevant identity, endpoint, email, and network telemetry available in your environment.`
}
