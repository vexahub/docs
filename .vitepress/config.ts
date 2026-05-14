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
        items: [
          { text: "Security", link: "/SECURITY" },
          { text: "Author", link: "/AUTHOR" },
        ],
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
    config: (md) => {
      // Strip /public/ prefix from image src for MD compatibility
      const defaultImageRenderer = md.renderer.rules.image!;
      md.renderer.rules.image = (tokens, idx, options, env, self) => {
        const token = tokens[idx];
        const srcIndex = token.attrIndex("src");
        if (srcIndex >= 0) {
          const src = token.attrs![srcIndex][1];
          if (src.startsWith("/public/")) {
            token.attrs![srcIndex][1] = src.replace("/public/", "/");
          }
        }
        return defaultImageRenderer
          ? defaultImageRenderer(tokens, idx, options, env, self)
          : self.renderToken(tokens, idx, options);
      };
    },
  },
});
