import { copyFile, cp, mkdir, readFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
for (const entry of await readdir(path.join(root, 'crates'), { withFileTypes: true })) {
  if (entry.isDirectory()) {
    await copyFile(path.join(root, 'LICENSE'), path.join(root, 'crates', entry.name, 'LICENSE'));
  }
}
const bundles = [
  ['web/dist', 'crates/avd/assets', 'index.html'],
  ['web/dist-mcp', 'crates/av-mcp/assets', 'mcp-app.html'],
];

for (const [source, destination, entry] of bundles) {
  const sourcePath = path.join(root, source);
  const destinationPath = path.join(root, destination);
  const html = await readFile(path.join(sourcePath, entry), 'utf8');
  if (!html.includes('<html')) throw new Error(`Missing production entry: ${source}/${entry}`);
  await rm(destinationPath, { recursive: true, force: true });
  await mkdir(destinationPath, { recursive: true });
  await cp(sourcePath, destinationPath, { recursive: true, dereference: false });
  console.log(`Prepared embedded release assets: ${destination}`);
}
