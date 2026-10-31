# HuntDeck

Client-side threat hunting platform.

## Local development

```sh
npm ci
npm run dev
```

## Threat data and deployment

The site deploys to GitHub Pages when changes are pushed to `main`. To populate or refresh the KEV and EPSS feeds, run **Actions → Build Data → Run workflow**. The workflow fetches both feeds, builds the data manifest, and deploys the updated site. It also runs daily at 00:00 UTC.
