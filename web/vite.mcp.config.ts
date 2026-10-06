import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
// A fixed entry needs no glob matching or external asset permissions.
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    {
      name: 'embedded-mcp-app',
      enforce: 'post',
      generateBundle(_options, bundle) {
        const html = bundle['mcp-app.html'];
        if (html?.type !== 'asset' || typeof html.source !== 'string')
          throw new Error('MCP App HTML missing');
        const scripts = Object.values(bundle).filter((entry) => entry.type === 'chunk');
        if (scripts.length !== 1) throw new Error('MCP App must have one embedded script');
        const script = scripts[0];
        if (!script) throw new Error('MCP App script missing');
        html.source = html.source.replace(
          /<script\b[^>]*src=["'][^"']+["'][^>]*><\/script>/u,
          () =>
            `<script type="module">${script.code.replace(/<\/script/giu, '<\\/script')}</script>`,
        );
        for (const entry of Object.values(bundle)) {
          if (entry.type === 'asset' && entry.fileName.endsWith('.css')) {
            const css =
              typeof entry.source === 'string'
                ? entry.source
                : new TextDecoder().decode(entry.source);
            html.source = html.source.replace(
              /<link\b[^>]*rel="stylesheet"[^>]*>/u,
              () => `<style>${css}</style>`,
            );
            Reflect.deleteProperty(bundle, entry.fileName);
          }
        }
        Reflect.deleteProperty(bundle, script.fileName);
        if (/<(?:script|link)\b[^>]*(?:src|href)=/u.test(html.source))
          throw new Error('MCP App contains external assets');
      },
    },
  ],
  build: {
    outDir: 'dist-mcp',
    sourcemap: false,
    modulePreload: false,
    rolldownOptions: { input: 'mcp-app.html', output: { codeSplitting: false } },
  },
});
