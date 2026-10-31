# HuntDeck

HuntDeck is a static, browser-based threat-hunting workspace. It has no application server, credentials, analytics, or runtime calls to third-party intelligence services. Analyst notes, status, and evidence are stored in the browser's IndexedDB.

The product takes inspiration from [ThreatFeed](https://github.com/jozeta/ThreatFeed)'s client-side security intelligence briefing concept. HuntDeck is a separate, hunt-first implementation: research headlines are supporting signals for analyst workflows, not a general-purpose news reader.

## Local development

```sh
npm ci
npm run dev
```

Quality checks:

```sh
npm test
npm run typecheck
npm run build
```

## Current workspace modules

- **Daily brief:** snapshot freshness, priority hunt queries, recent KEV entries, and Markdown/print exports.
- **Intel leads:** a small curated set of recent security research headlines, with CVE/KEV/EPSS and ATT&CK references linked to the hunt workspaces.
- **Hypotheses:** typo-tolerant search, technique/severity/status filters, KQL/SPL/Elastic/Sigma tabs, and local hunt status.
- **Coverage:** ATT&CK technique coverage derived from hunt and deployed-rule status, with Navigator layer import/export.
- **IOC triage:** local extraction and snapshot lookups, with CSV and STIX 2.1 export.
- **Rules:** searchable Sigma metadata with local deployment tracking.
- **Journal:** private local hunt logs, evidence, drafts, filters, and Markdown export.

Every page surfaces missing or stale snapshot data rather than labeling unindexed indicators as safe. Feed inventory and terms are in [docs/ATTRIBUTION.md](./docs/ATTRIBUTION.md).

## Data pipeline and deployment

The client reads only static JSON from `public/data/`. The **Build Data** GitHub Actions workflow runs daily at 00:00 UTC or can be started manually. It fetches KEV, EPSS, ATT&CK, IOC, Sigma, and curated RSS headline snapshots, builds deterministic analyst-authored hypothesis templates and the manifest, validates the snapshots and size budget, then deploys the resulting static site. Failed optional IOC, rule, and news sources retain their last-good records and are reported in the manifest.

Changes pushed to `main` run CI and the GitHub Pages deployment workflow. Pages must use **GitHub Actions** as its source.

## Privacy and offline use

The service worker caches the app shell and static snapshots for offline use. News snapshots store headlines and links rather than article bodies. Triage input, journal evidence, and analyst state are not sent to any service. Clearing this site's browser storage deletes local analyst data; export journal notes to Markdown for a backup.

## Important limitations

Hunt queries are deterministic authored templates, not AI-generated. Validate table names and fields against your own telemetry before running them. The pipeline currently indexes Sigma metadata and a limited set of IOC sources; see the attribution page and manifest warnings for source availability.
