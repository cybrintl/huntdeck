# HuntDeck

HuntDeck is a public, browser-based threat-hunting and threat-intelligence reference. It is designed for hunting teams, threat intelligence analysts, detection engineers, and SOC analysts—not as a personal hunt tracker.

The site is static: no account, application server, analytics, or server-side user data. The browser reads published JSON snapshots. IOC text submitted to the triage page is processed in memory in that browser and is not uploaded. The only saved browser preference is the selected visual theme.

HuntDeck takes product inspiration from [OffSec Radar](https://radar.offseq.com/) and other public threat-intelligence tools. Its priority is actionable hunting context: hypotheses, telemetry guidance, reusable queries, ATT&CK references, detection content, and supporting vulnerability, indicator, and threat-report data.

## What it provides

- **Daily brief:** current snapshot counts and freshness, high-priority hunt ideas, KEV/EPSS context, and recent threat-report leads.
- **Hunt library:** searchable hypotheses with ATT&CK mappings, telemetry guidance, investigation pivots, validation caveats, false-positive considerations, and KQL/SPL/Elastic/Sigma examples. Export the currently filtered hunts as a portable Markdown hunt pack.
- **Technique map:** ATT&CK techniques linked to indexed hypotheses and detection rules. This is a content index, not a claim about any organization's deployed coverage.
- **IOC triage:** extract and compare indicators in the browser with published IOC/KEV snapshots; export results as CSV or STIX 2.1.
- **Detection rules:** search Sigma metadata, ATT&CK references, and available query examples.
- **Intel leads:** recent OffSec Radar threat reports with short summaries, severity/CVSS, CVEs, and links to the source. Extracted ATT&CK references link directly to matching hypotheses when available.
- **Themes:** Light, Dark, Ocean, and Forest, with the selected appearance stored only in local browser preferences.

Data is informational and may be incomplete. Verify source reports, validate query fields against your own telemetry, and do not treat an IOC absent from a snapshot as safe.

## Run locally

```sh
npm ci
npm run dev
```

Quality checks:

```sh
npm test
npm run validate:snapshots
npm run typecheck
npm run build
```

## Static data and deployment

The client uses only static JSON from `public/data/`; it makes no runtime intelligence-feed API calls. Report-to-hypothesis relationships are derived in the browser from exact ATT&CK technique IDs in the snapshots; no backend or user tracking is involved. The **Build Data** GitHub Actions workflow runs daily at 00:00 UTC or can be started manually. It fetches KEV, EPSS, ATT&CK, IOC, Sigma, and the [OffSec Radar RSS feed](https://radar.offseq.com/rss.xml), generates hunt templates and the manifest, validates the snapshots, and publishes the static site. If an optional feed is unavailable, the workflow reports it and retains last-good data where available.

Changes pushed to `main` run CI and the GitHub Pages deployment workflow. Configure Pages to use **GitHub Actions** as its source.

## Privacy and licensing

The service worker caches the application shell and public data for offline use. Theme preference is stored in this browser only. Triage input is not persisted or sent to HuntDeck. Feed and detection data have their own attribution and reuse terms; check [docs/ATTRIBUTION.md](./docs/ATTRIBUTION.md) before redistribution or commercial use.

HuntDeck's own code is licensed under [Apache-2.0](./LICENSE). This does not relicense third-party snapshots, feeds, or detection content.

## Inspiration

- [OffSec Radar](https://radar.offseq.com/) — threat context and the RSS feed used by HuntDeck.
- [ThreatFeed](https://github.com/jozeta/ThreatFeed) — client-side intelligence briefing concept.
- [KQL threat-hunting queries](https://github.com/cyb3rmik3/KQL-threat-hunting-queries) — query-library direction.
- [IntelOwl](https://github.com/intelowlproject/IntelOwl) — public threat-intelligence workflow ideas.
