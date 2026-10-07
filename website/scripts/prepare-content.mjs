import { copyFile, cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const websiteRoot = fileURLToPath(new URL('../', import.meta.url));
export const sourceRoot = path.resolve(websiteRoot, '../docs/public');
export const origin = (process.env.WEBSITE_ORIGIN ?? 'http://localhost:4321').replace(/\/$/, '');
export const repository = 'https://github.com/syntropika/agents-vault';

const descriptions = {
  index: 'Find the right workflow for configuration, credentials, actions, and trust.',
  installation: 'Install and update agents-vault from crates.io, with platform build prerequisites.',
  concepts: 'Understand project references, credentials, permissions, approvals, and delivery modes.',
  'cli-reference': 'Find CLI commands, global options, and installed-service entry points.',
  'mcp-apps': 'Install the approval adapter and enroll a compatible MCP Apps harness.',
  quickstart: 'Install the CLI, run public configuration, and authorize direct secret delivery.',
  'configuration-and-delivery': 'Choose between environment values and the synthetic broker proxy.',
  'credential-lifecycle': 'Manage credentials, versions, grants, storage, and recovery.',
  'actions-and-approvals': 'Configure one active recipe and review requests through the console or MCP Apps.',
  'limits-and-trust': 'Understand direct delivery, capabilities, harness authority, and platform limits.',
  troubleshooting: 'Resolve configuration, connection, approval, and client errors.',
  landing: 'Local configuration and explicit credential access with Agents Vault.',
};

export function humanRoute(slug) {
  return slug === 'landing' ? '/' : slug === 'index' ? '/docs/' : `/docs/${slug}/`;
}

export function markdownRoute(slug) {
  return slug === 'landing' ? '/index.md' : `/docs/${slug}.md`;
}

export function mapLinks(markdown, slug, machine = false) {
  return markdown.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (full, label, destination) => {
    if (destination.startsWith('/')) return machine ? `[${label}](${origin}${destination})` : full;
    if (/^(?:[a-z]+:|#)/i.test(destination)) return full;
    const [file, fragment] = destination.split('#');
    const resolved = path.resolve(sourceRoot, file);
    let target;
    if (path.dirname(resolved) === sourceRoot && file.endsWith('.md')) {
      const linkedSlug = path.basename(file, '.md');
      target = machine ? markdownRoute(linkedSlug) : humanRoute(linkedSlug);
    } else {
      const repoPath = path.relative(path.resolve(websiteRoot, '..'), resolved).split(path.sep).join('/');
      if (repoPath.startsWith('../')) throw new Error(`Link escapes repository: ${slug}: ${destination}`);
      target = `${repository}/blob/main/${repoPath}`;
    }
    if (fragment) target += `#${fragment}`;
    if (machine && target.startsWith('/')) target = origin + target;
    return `[${label}](${target})`;
  });
}

export async function readPages() {
  const pages = [];
  for (const name of (await readdir(sourceRoot)).filter((name) => name.endsWith('.md')).sort()) {
    const source = await readFile(path.join(sourceRoot, name), 'utf8');
    const match = source.match(/^# ([^\n]+)\n/);
    if (!match) throw new Error(`Missing title: ${name}`);
    const slug = name.slice(0, -3);
    if (!descriptions[slug]) throw new Error(`Missing description: ${name}`);
    pages.push({ slug, title: match[1], body: source.slice(match[0].length).trim(), source, description: descriptions[slug] });
  }
  return pages;
}

export async function prepareContent() {
  const pages = await readPages();
  const generated = path.join(websiteRoot, '.generated');
  await rm(generated, { force: true, recursive: true });
  await mkdir(path.join(generated, 'content/docs'), { recursive: true });
  await mkdir(path.join(generated, 'public/docs'), { recursive: true });
  await cp(path.join(websiteRoot, 'public'), path.join(generated, 'public'), { recursive: true });
  await copyFile(path.join(websiteRoot, 'public/brand/av-mark.svg'), path.join(generated, 'public/favicon.svg'));
  await writeFile(path.join(generated, 'pages.json'), JSON.stringify(pages.map((page) => ({ ...page, humanBody: mapLinks(page.body, page.slug) }))));
  for (const page of pages) {
    if (page.slug !== 'landing') {
      const frontmatter = `---\ntitle: ${JSON.stringify(page.title)}\ndescription: ${JSON.stringify(page.description)}\n---\n\n`;
      const name = page.slug === 'index' ? 'index' : page.slug;
      await writeFile(path.join(generated, `content/docs/${name}.md`), frontmatter + mapLinks(page.body, page.slug) + '\n');
    }
    await writeFile(path.join(generated, 'public', markdownRoute(page.slug)), mapLinks(page.source, page.slug, true));
  }
  const status = '> Agents Vault runs locally. Direct delivery gives trusted code real values. Broker proxy actions use synthetic credentials; protected production custody and installed macOS acceptance remain open.\n';
  const links = pages.map((page) => `- [${page.title}](${origin}${markdownRoute(page.slug)}): ${page.description}`).join('\n');
  await writeFile(path.join(generated, 'public/llms.txt'), `# Agents Vault\n\n${status}\n## Documentation\n\n${links}\n\n## Complete text\n\n- [All documentation](${origin}/llms-full.txt): The same published pages as a single Markdown bundle.\n`);
  await writeFile(path.join(generated, 'public/llms-full.txt'), `# Agents Vault — complete documentation\n\n${status}\n` + pages.map((page) => `${mapLinks(page.source, page.slug, true)}\n\n---\n\n`).join(''));
  console.log(`Prepared ${pages.length} source pages, Markdown routes, and LLM indexes.`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await prepareContent();
