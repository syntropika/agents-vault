# Agents Vault public website

An independent static Astro + Starlight site. It has no connection to the broker or operator-console API. Authored documentation lives in `../docs/public/`; generated content is ignored by Git.

## Run locally

Use Node.js 22.12 or newer:

```sh
npm ci
npm run dev
```

Open `http://localhost:4321/`. The dev server binds to loopback. Restart it after editing `docs/public/` to regenerate the documentation. Pagefind's production search index is generated during a build; use the built preview to verify search.

```sh
npm run verify
npm run preview
```

`verify` runs Astro's strict checks, builds static output, and checks human pages, Markdown routes, agent indexes, local links, and search output. The build writes `dist/`, which can be served by an ordinary static HTTP server. No Node process is needed to serve the resulting files.

## Content and exports

`scripts/prepare-content.mjs` reads the eight public Markdown files, adds generated Starlight metadata, maps internal guide links to website routes, and maps repository evidence links to public GitHub files. The original authored files are the only maintained content source.

| Output | Purpose |
| --- | --- |
| `/` | Landing page |
| `/docs/` and `/docs/<slug>/` | Human guides with navigation and local search |
| `/index.md` and `/docs/<slug>.md` | Direct Markdown copies |
| `/llms.txt` | Short discovery index |
| `/llms-full.txt` | Complete Markdown bundle |

The Markdown endpoints are generated static files. **Read Markdown** and **Copy page** use those same files. Copies include absolute links for use outside the site. The indexes do not grant access, fetch credentials, or promise adoption by every agent client.

Before a public deployment, set the actual origin when checking and building:

```sh
WEBSITE_ORIGIN=https://your-chosen-host.example npm run verify
```

Replace that example with the approved origin. This sets canonical URLs, the sitemap, and absolute links in machine output. The default origin is the local preview, not a reserved public domain. Root-path hosting is the current configuration; hosting under a URL subpath needs a coordinated base-path update.

## Scope

The site preserves the existing neutral palette, rounded controls, system typography, and flat surfaces. Dark is the initial appearance; documentation readers can select light or system appearance. Search assets, fonts, and styles are local. No hosted search, analytics, AI chat widget, React runtime, or Tailwind dependency is added.

The product is an alpha with one active broker recipe and synthetic-only proxy credentials. Execution authority belongs to the original live IPC connection; shared sockets and copied proxy capabilities remain limits. The site does not claim exclusive process identity, original-PID-death detection, production custody, installed macOS acceptance, or compatibility with a named installed MCP client.
