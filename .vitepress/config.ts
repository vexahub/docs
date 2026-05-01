// @ts-nocheck
import { defineConfig } from "vitepress";
export default defineConfig({
  lang: "en-GB",
  title: "VexaHub",
  description: "Documentation for VexaHub to follow best practices.",
  head: [["link", { rel: "icon", href: "/favicon.ico" }]],
  themeConfig: {
    nav: [{ text: "Home", link: "/" }],
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
