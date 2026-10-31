import assert from 'node:assert/strict'
import test from 'node:test'
import { parseNewsFeed } from './news'

const source = {
  id: 'test',
  name: 'Test Feed',
  url: 'https://feed.example.test/rss',
}

test('parses RSS headlines and extracts hunt-relevant CVEs, techniques, and topics', () => {
  const articles = parseNewsFeed(`<?xml version="1.0"?>
    <rss version="2.0"><channel><item>
      <title><![CDATA[Actively exploited CVE-2026-12345 in cloud gateway &amp; T1059.001]]></title>
      <link>https://research.example.test/story</link>
      <pubDate>Sat, 31 Oct 2026 12:00:00 GMT</pubDate>
      <category>Vulnerability</category>
      <description>Unauthenticated exploitation documented in cloud gateway; CVSS: 9.8.</description>
    </item></channel></rss>`, source)

  assert.equal(articles.length, 1)
  assert.equal(articles[0]?.title, 'Actively exploited CVE-2026-12345 in cloud gateway & T1059.001')
  assert.deepEqual(articles[0]?.cves, ['CVE-2026-12345'])
  assert.deepEqual(articles[0]?.techniques, ['T1059.001'])
  assert.deepEqual(articles[0]?.topics, ['Exploitation', 'Vulnerability', 'Cloud and identity'])
  assert.equal(articles[0]?.published_at, '2026-10-31T12:00:00.000Z')
  assert.equal(articles[0]?.severity, 'unknown')
  assert.equal(articles[0]?.cvss, 9.8)
  assert.match(articles[0]?.summary ?? '', /Unauthenticated exploitation/)
})

test('parses OffSec Radar severity, vendor tags, CVEs, CVSS, and a safe summary', () => {
  const articles = parseNewsFeed(`<rss><channel><item>
    <title>CVE-2026-120135 in Apache Thrift</title>
    <link>https://radar.offseq.com/threat/example</link>
    <description><![CDATA[Remote code execution in Apache Thrift. <script>alert(1)</script> (CVSS: 8.2)]]></description>
    <pubDate>Sat, 31 Oct 2026 20:33:00 GMT</pubDate>
    <category>high</category><category>Apache Software Foundation</category>
  </item></channel></rss>`, source)

  assert.equal(articles[0]?.severity, 'high')
  assert.equal(articles[0]?.cvss, 8.2)
  assert.deepEqual(articles[0]?.cves, ['CVE-2026-120135'])
  assert.deepEqual(articles[0]?.tags, ['high', 'Apache Software Foundation'])
  assert.equal(articles[0]?.summary.includes('script'), false)
})

test('maps Radar severity categories and omits invalid CVSS scores', () => {
  const articles = parseNewsFeed(`<rss><channel><item>
    <title>Critical Apache vulnerability</title>
    <link>https://radar.offseq.com/threat/critical</link>
    <description>Arbitrary code execution.</description>
    <category>critical</category>
    <category>Apache</category>
  </item></channel></rss>`, source)

  assert.equal(articles[0]?.severity, 'critical')
  assert.equal(articles[0]?.cvss, undefined)
})

test('supports Atom links and rejects unsafe article URLs and entity declarations', () => {
  const articles = parseNewsFeed(`<feed xmlns="http://www.w3.org/2005/Atom">
    <entry><title>Ransomware intrusion campaign</title>
      <link href="https://research.example.test/atom" rel="alternate"/>
      <updated>2026-10-30T12:00:00Z</updated>
    </entry>
    <entry><title>Unsafe item</title><link href="javascript:alert(1)"/></entry>
  </feed>`, source)

  assert.equal(articles.length, 1)
  assert.equal(articles[0]?.url, 'https://research.example.test/atom')
  assert.deepEqual(articles[0]?.topics, ['Malware', 'Threat activity'])
  assert.throws(
    () => parseNewsFeed('<!DOCTYPE feed [<!ENTITY x "x">]><rss/>', source),
    /forbidden XML declaration/
  )
})

test('excludes headlines without a deterministic hunt-relevant signal', () => {
  const articles = parseNewsFeed(`<rss><channel>
    <item><title>A quiet week in infosec</title><link>https://research.example.test/quiet</link></item>
    <item><title>Actively exploited CVE-2026-12345</title><link>https://research.example.test/cve</link></item>
  </channel></rss>`, source)

  assert.deepEqual(articles.map(article => article.title), ['Actively exploited CVE-2026-12345'])
})
