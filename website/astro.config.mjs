import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: process.env.WEBSITE_ORIGIN ?? 'http://localhost:4321',
  output: 'static',
  publicDir: './.generated/public',
  integrations: [
    starlight({
      title: 'Agents Vault',
      logo: { src: './public/brand/av-mark.svg', alt: '', replacesTitle: false },
      description: 'Local project configuration, encrypted credentials, and reviewed CLI actions.',
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'Source on GitHub', href: 'https://github.com/syntropika/agents-vault' }],
      customCss: ['./src/styles/docs.css'],
      components: {
        PageTitle: './src/components/PageTitle.astro',
        ThemeProvider: './src/components/ThemeProvider.astro',
      },
      sidebar: [
        { label: 'Getting started', items: [
          { label: 'Introduction', slug: 'docs' },
          { label: 'Installation', slug: 'docs/installation' },
          { label: 'Quickstart', slug: 'docs/quickstart' },
          { label: 'Core concepts', slug: 'docs/concepts' },
        ] },
        { label: 'Guides', items: [
          { label: 'Configuration and delivery', slug: 'docs/configuration-and-delivery' },
          { label: 'Credentials', slug: 'docs/credential-lifecycle' },
          { label: 'Actions and approvals', slug: 'docs/actions-and-approvals' },
          { label: 'MCP Apps', slug: 'docs/mcp-apps' },
        ] },
        { label: 'Reference', items: [
          { label: 'CLI commands', slug: 'docs/cli-reference' },
          { label: 'Limits and trust', slug: 'docs/limits-and-trust' },
        ] },
        { label: 'Help', items: [
          { label: 'Troubleshooting', slug: 'docs/troubleshooting' },
        ] },
      ],
      head: [{ tag: 'link', attrs: { rel: 'preload', href: '/fonts/geist-sans.woff2', as: 'font', type: 'font/woff2', crossorigin: '' } }, { tag: 'link', attrs: { rel: 'alternate', type: 'text/plain', href: '/llms.txt', title: 'Agent documentation index' } }],
    }),
  ],
});
