// @ts-nocheck
import { defineConfig } from "vitepress";

const slugify = (s: string) =>
  s
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^\w\s-]/g, "")
    .replace(/\s+/g, "-")
    .toLowerCase()
    .replace(/^-+|-+$/g, "")
    .replace(/^(\d)/, "_$1");

export default defineConfig({
  lang: "en",
  title: "VexaHub",
  description: "Documentation for VexaHub to follow best practices.",
  head: [["link", { rel: "icon", href: "/favicon.ico" }]],
  lastUpdated: true,
  cleanUrls: true,
  themeConfig: {
    nav: [{ text: "Home", link: "/" }],
    logo: "/logo.svg",
    outline: {
      level: [2, 3],
    },
    externalLinkIcon: true,
    socialLinks: [{ icon: "github", link: "https://github.com/vexahub" }],
    sidebar: [
      {
        text: "Documentation",
        items: [
          { text: "Authentication", link: "/AUTHENTICATION" },
          {
            text: "Cryptography",
            collapsed: false,
            items: [
              { text: "Specification", link: "/CRYPTO" },
              { text: "Addendum", link: "/CRYPTO_ADDENDUM" },
            ],
          },
        ],
      },
      {
        text: "Project",
        items: [{ text: "Author", link: "/AUTHOR" }],
      },
    ],
    footer: {
      message: "Released under the AGPL-3.0-or-later License.",
      copyright: "Copyright © 2026-present VexaHub",
    },
  },
  markdown: {
    anchor: {
      slugify,
    },
  },
});
