import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: process.env.WEBSITE_ORIGIN ?? 'http://localhost:4321',
  output: 'static',
  publicDir: './.generated/public',
  integrations: [
    starlight({
      title: 'Agents Vault',
      description: 'Local project configuration, encrypted credentials, and reviewed CLI actions. An alpha prototype.',
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'Source on GitHub', href: 'https://github.com/syntropika/agents-vault' }],
      customCss: ['./src/styles/docs.css'],
      components: {
        PageTitle: './src/components/PageTitle.astro',
        ThemeProvider: './src/components/ThemeProvider.astro',
      },
      sidebar: [
        { label: 'Start', items: [{ label: 'Overview', slug: 'docs' }, { label: 'Quickstart', slug: 'docs/quickstart' }] },
        { label: 'Use Agents Vault', items: [
          { label: 'Configuration and delivery', slug: 'docs/configuration-and-delivery' },
          { label: 'Credential lifecycle', slug: 'docs/credential-lifecycle' },
          { label: 'Actions and approvals', slug: 'docs/actions-and-approvals' },
        ] },
        { label: 'Understand the boundary', items: [
          { label: 'Limits and trust', slug: 'docs/limits-and-trust' },
          { label: 'Troubleshooting', slug: 'docs/troubleshooting' },
        ] },
      ],
      head: [{ tag: 'link', attrs: { rel: 'alternate', type: 'text/plain', href: '/llms.txt', title: 'Agent documentation index' } }],
    }),
  ],
});
