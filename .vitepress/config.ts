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
  title: "VexaHub",
  description: "Documentation for VexaHub to follow best practices.",
  head: [["link", { rel: "icon", href: "/favicon.ico" }]],
  lastUpdated: true,
  cleanUrls: true,
  rewrites: {
    "AUTHENTICATION.md": "authentication.md",
    "CRYPTO.md": "crypto.md",
    "CRYPTO_ADDENDUM.md": "crypto-addendum.md",
    "SECURITY.md": "security.md",
    "AUTHOR.md": "author.md",
    "fr/AUTHENTICATION.md": "fr/authentication.md",
    "fr/CRYPTO.md": "fr/crypto.md",
    "fr/CRYPTO_ADDENDUM.md": "fr/crypto-addendum.md",
    "fr/SECURITY.md": "fr/security.md",
    "fr/AUTHOR.md": "fr/author.md",
  },
  locales: {
    root: {
      label: "English",
      lang: "en",
    },
    fr: {
      label: "Français",
      lang: "fr",
      description:
        "Documentation VexaHub pour suivre les meilleures pratiques.",
      themeConfig: {
        nav: [{ text: "Accueil", link: "/fr/" }],
        sidebar: [
          {
            text: "Documentation",
            items: [
              { text: "Authentification", link: "/fr/authentication" },
              {
                text: "Cryptographie",
                collapsed: false,
                items: [
                  { text: "Spécification", link: "/fr/crypto" },
                  { text: "Addenda", link: "/fr/crypto-addendum" },
                ],
              },
            ],
          },
          {
            text: "Projet",
            items: [
              { text: "Sécurité", link: "/fr/security" },
              { text: "Auteur", link: "/fr/author" },
            ],
          },
        ],
        footer: {
          message: "Publié sous la licence AGPL-3.0-or-later.",
          copyright: "Copyright © 2026-present VexaHub",
        },
      },
    },
  },

  themeConfig: {
    nav: [{ text: "Home", link: "/" }],
    logo: "/logo.svg",
    outline: { level: [2, 3] },
    externalLinkIcon: true,
    socialLinks: [{ icon: "github", link: "https://github.com/vexahub" }],
    sidebar: [
      {
        text: "Documentation",
        items: [
          { text: "Authentication", link: "/authentication" },
          {
            text: "Cryptography",
            collapsed: false,
            items: [
              { text: "Specification", link: "/crypto" },
              { text: "Addendum", link: "/crypto-addendum" },
            ],
          },
        ],
      },
      {
        text: "Project",
        items: [
          { text: "Security", link: "/security" },
          { text: "Author", link: "/author" },
        ],
      },
    ],
    footer: {
      message: "Released under the AGPL-3.0-or-later License.",
      copyright: "Copyright © 2026-present VexaHub",
    },
  },

  markdown: {
    anchor: { slugify },
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

      // Rewrite relative .md links to kebab-case lowercase URLs, preserving locale
      const defaultLinkRenderer = md.renderer.rules.link_open!;
      md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
        const token = tokens[idx];
        const hrefIndex = token.attrIndex("href");
        if (hrefIndex >= 0) {
          const href = token.attrs![hrefIndex][1];
          if (!href.startsWith("http") && /^\.?\/?\w+[#.]/.test(href)) {
            const [path, fragment] = href.split("#");
            const clean = path
              .replace(/\.md$/, "")
              .replace(/_/g, "-")
              .toLowerCase();
            const locale = env?.relativePath?.includes("/")
              ? "/" + env.relativePath.split("/")[0]
              : "";
            const cleanPath = clean.startsWith("/")
              ? clean
              : `${locale}/${clean.replace(/^\.\//, "")}`;
            token.attrs![hrefIndex][1] = fragment
              ? `${cleanPath}#${fragment}`
              : cleanPath;
          }
        }
        return defaultLinkRenderer
          ? defaultLinkRenderer(tokens, idx, options, env, self)
          : self.renderToken(tokens, idx, options);
      };
    },
  },
});
