// @ts-nocheck
import { defineConfig } from 'vitepress';
export default defineConfig({
  lang: 'en-US',
  title: 'VexaHub',
  description: 'Documentation for VexaHub to follow best practices.',
  themeConfig: {
    nav: [
      { text: 'Home', link: '/' },
    ],
    sidebar: [
      {
        text: 'Documentation',
        items: [
          { text: 'Authentication', link: '/AUTHENTICATION' },
          { text: 'Cryptography', link: '/CRYPTO' },
        ],
      },
      {
        text: 'Project',
        items: [
          { text: 'Author', link: '/AUTHOR' },
        ],
      },
    ],
  },
});
