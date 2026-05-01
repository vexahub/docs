// @ts-nocheck
import { defineConfig } from "vitepress";
export default defineConfig({
  lang: "en",
  title: "VexaHub",
  description: "Documentation for VexaHub to follow best practices.",
  head: [["link", { rel: "icon", href: "/favicon.ico" }]],
  vite: {
    build: {
      rolldownOptions: {
        output: {
          minify: true,
        },
      },
    },
  },
  themeConfig: {
    nav: [{ text: "Home", link: "/" }],
    logo: "/logo.svg",
    outline: {
      level: [2, 3],
    },
    socialLinks: [{ icon: "github", link: "https://github.com/vexahub" }],
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
