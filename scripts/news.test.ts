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
      <description>This full article body must not be stored.</description>
    </item></channel></rss>`, source)

  assert.equal(articles.length, 1)
  assert.equal(articles[0]?.title, 'Actively exploited CVE-2026-12345 in cloud gateway & T1059.001')
  assert.deepEqual(articles[0]?.cves, ['CVE-2026-12345'])
  assert.deepEqual(articles[0]?.techniques, ['T1059.001'])
  assert.deepEqual(articles[0]?.topics, ['Exploitation', 'Vulnerability', 'Cloud and identity'])
  assert.equal(articles[0]?.published_at, '2026-10-31T12:00:00.000Z')
  assert.equal(JSON.stringify(articles).includes('full article body'), false)
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
