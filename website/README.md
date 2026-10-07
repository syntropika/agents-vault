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

Replace that example with the approved origin. This sets canonical URLs, the sitemap, and absolute links in machine output. The default origin is the local preview. Root-path hosting is the current configuration; hosting under a URL subpath needs a coordinated base-path update.

## Cloudflare deployment

The public target is `https://av.syntropika.ai`. The site uses [Workers Static Assets](https://developers.cloudflare.com/workers/framework-guides/web-apps/astro/) to serve the static build without a server-side Astro adapter. `wrangler.jsonc` defines the custom domain, real 404 responses, and directory-style HTML URLs. Workers development and preview URLs are disabled.

The `Documentation website` GitHub Actions workflow checks public documentation and website changes on pull requests and `main`, and supports manual dispatch. It installs the locked dependencies, runs the strict checks and output verification, validates Wrangler with a dry run, and retains the built site as a five-day artifact. Production deployment consumes that same verified artifact. Pull requests cannot deploy or receive the Cloudflare token.

Configure these repository settings, or the equivalent settings in the `documentation` GitHub environment:

| Setting | Kind | Value |
| --- | --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | Variable | The account owning the site's Cloudflare zone |
| `CLOUDFLARE_API_TOKEN` | Secret | A deployment token scoped to the intended account and zone |
| `CLOUDFLARE_DEPLOY_ENABLED` | Repository variable | `true` to enable production deployment |

Create the deployment token using Cloudflare's [Edit Cloudflare Workers template](https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/), restricting its account and zone resources. Store it directly in GitHub Actions secrets. The token is available only to the deployment step. Add required reviewers to the `documentation` environment if publication needs an approval gate.

Leave `CLOUDFLARE_DEPLOY_ENABLED` unset until the credentials and domain are ready; validation runs and deployment is visibly skipped. Once enabled, successful relevant pushes to `main` deploy automatically. A manual dispatch from `main` can deploy the current revision without a source change. Cloudflare provisions the custom domain's DNS and TLS certificate on the first deployment; an existing conflicting DNS record must be resolved first.

To check a deployment locally without publishing:

```sh
WEBSITE_ORIGIN=https://av.syntropika.ai npm run verify
npm run deploy:check
```

For an authenticated local deployment, set `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` in your shell and run `npm run deploy` after those checks. To change the public domain, update the workflow origin and environment URL together with the Wrangler custom-domain route, then rebuild.

## Scope

The public site uses flat neutral surfaces, rounded windows and controls, Geist typography, and a lavender accent for actions, focus, selection, and delivery traces. The landing pairs overlapping project and credential-reference windows with a separate command → broker → HTTPS provider flow. CSS geometry and inline SVG supply the scenes; compact screens stack the windows and flow. Structural page rails and boundary dividers organize the reading grid, while credential-reference details sit in separated rows on their shared window surface. [DESIGN.md](../DESIGN.md) records the shared system and website-scoped tokens, and the [registered surface brief](../.impeccable/surfaces/website-src-pages-index-astro.md) records the public composition. The operator console retains its neutral design roles.

The landing and documentation self-host Geist variable sans and Geist Mono from the official `geist` npm package (1.7.2). `src/styles/fonts.css` loads `public/fonts/geist-sans.woff2` and `public/fonts/geist-mono.woff2` with `font-display: swap`; the shared fonts support weights (100–900). Their SIL Open Font License (1.1) is included in `public/fonts/LICENSE.txt`. The operator console retains its existing system font stack.

The public mark is a compact closed A/V formed by two interlocking filled pieces, with a symmetric A roof, triangular aperture, and rounded junctions. `public/brand/av-mark.svg` is the canonical lavender tile with dark ink. `public/brand/av-symbol.svg` uses the exact same two paths in pale white without the tile. Both are native SVG and font-independent. The landing header, delivery broker node, and documentation title use static tile instances. Content preparation copies the canonical tile into the generated `/favicon.svg`; reuse the canonical asset when updating public icons.

The local Development/Production selector changes only the public `APP_ENV` example and announces the selected illustrative state. The credential remains a placeholder and no vault is accessed. Animated connection traces have a Pause/Resume animations control, pause when offscreen or when the document is hidden, and become static under reduced motion. Reduced motion also removes transitions and smooth scrolling.

The landing serves a 37-second silent English Forma explainer locally, with MP4/WebM sources, a poster, native playback controls, English captions, a selectable WebVTT track, and a separate Markdown transcript. Media files live in `public/media/`; [media-source/README.md](media-source/README.md) describes `agents-vault-explainer-source.zip`, the caption script, and media provenance. Keep captions, transcript, and editable source synchronized with exported media. The video does not autoplay.

Dark is the landing's initial appearance; documentation readers can select dark, light, or system appearance. Search assets, fonts, styles, and explainer media are local. No hosted search, analytics, AI chat widget, React runtime, or Tailwind dependency is added.

The implementation has one active broker recipe and synthetic-only proxy credentials. Execution authority belongs to the original live IPC connection; shared sockets and copied proxy capabilities remain limits. The site does not claim exclusive process identity, original-PID-death detection, production custody, installed macOS acceptance, or compatibility with a named installed MCP client.
