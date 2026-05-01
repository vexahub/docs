// @ts-nocheck
import { defineConfig } from "vitepress";
export default defineConfig({
  lang: "en-GB",
  title: "VexaHub",
  description: "Documentation for VexaHub to follow best practices.",
  head: [["link", { rel: "icon", href: "/favicon.ico" }]],
  vite: {
    build: {
      rollupOptions: {
        output: {
          manualChunks: undefined,
        },
      },
    },
  },
  themeConfig: {
    nav: [{ text: "Home", link: "/" }],
    aside: true,
    outline: {
      level: [2, 3],
      label: "On this page",
    },
    sidebar: [
      {
        text: "Documentation",
        items: [
          { text: "Authentication", link: "/AUTHENTICATION" },
          { text: "Cryptography", link: "/CRYPTO" },
        ],
      },
      {
        text: "Project",
        items: [{ text: "Author", link: "/AUTHOR" }],
      },
    ],
  },
});
