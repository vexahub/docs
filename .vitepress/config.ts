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
          { text: 'Author', link: '/AUTHOR' },
          { text: 'Cryptography', link: '/CRYPTO' },
        ],
      },
    ],
  },
});