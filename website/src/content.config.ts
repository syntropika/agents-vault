import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema, i18nSchema } from '@astrojs/starlight/schema';

export const collections = {
  docs: defineCollection({
    loader: glob({
      pattern: '**/*.md',
      base: './.generated/content',
      generateId: ({ entry }) => entry.replace(/\/index\.md$/, '').replace(/\.md$/, ''),
    }),
    schema: docsSchema(),
  }),
  i18n: defineCollection({ schema: i18nSchema() }),
};
