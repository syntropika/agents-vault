import assert from 'node:assert/strict';
import { access, readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { humanRoute, markdownRoute, origin, readPages, websiteRoot } from './prepare-content.mjs';

const output = path.join(websiteRoot, 'dist');
const pages = await readPages();
for (const page of pages) {
  const route = humanRoute(page.slug);
  const html = await readFile(path.join(output, route, 'index.html'), 'utf8');
  assert(html.includes('<h1'), `${route}: missing page title`);
  assert(!html.includes('Execution-boundary draft') && !html.includes('Synchronize this section'), `${route}: editorial text`);
  const markdown = await readFile(path.join(output, markdownRoute(page.slug)), 'utf8');
  assert(markdown.startsWith(`# ${page.title}\n`), `${page.slug}: missing Markdown title`);
  assert(!/\]\((?:\.\.\/|[^/]+\.md\))/.test(markdown), `${page.slug}: unresolved repository links`);
  for (const match of html.matchAll(/(?:href|src)="(\/[^"#?]*)(?:[^\"]*)"/g)) {
    const url = match[1];
    if (url === '/') continue;
    const local = path.join(output, decodeURIComponent(url));
    await access(url.endsWith('/') ? path.join(local, 'index.html') : local).catch(() => {
      throw new Error(`${route}: broken local URL ${url}`);
    });
  }
}
const index = await readFile(path.join(output, 'llms.txt'), 'utf8');
const full = await readFile(path.join(output, 'llms-full.txt'), 'utf8');
for (const page of pages) {
  assert(index.includes(`${origin}${markdownRoute(page.slug)}`), `LLM index missing ${page.slug}`);
  assert(full.includes(`# ${page.title}\n`), `LLM bundle missing ${page.slug}`);
}
const searchFiles = await readdir(path.join(output, 'pagefind'));
assert(searchFiles.includes('pagefind.js'), 'Missing local search bundle');
const quickstart = await readFile(path.join(output, 'docs/quickstart.md'), 'utf8');
assert(quickstart.includes('cargo build --locked -p av --bin av'), 'Missing source-build command');
assert(quickstart.includes('https://github.com/syntropika/agents-vault/blob/main/docs/prototype-status.md'), 'Missing mapped evidence link');
console.log(`Verified ${pages.length} human pages, ${pages.length} Markdown routes, two agent indexes, local links, and Pagefind output.`);
