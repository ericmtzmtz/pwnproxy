import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import preact from "@astrojs/preact";

export default defineConfig({
  vite: {
    plugins: [
      {
        name: "fix-preact-virtual-module",
        transform(code, id) {
          if (id.includes("@astrojs/preact/dist/server.js") && code.includes('astro:preact:opts')) {
            return code.replace(
              'import opts from "astro:preact:opts"',
              "const opts = {};",
            );
          }
        },
      },
      tailwindcss(),
    ],
    optimizeDeps: {
      exclude: ["@astrojs/preact"],
    },
  },
  integrations: [preact({ include: ["**/*.tsx", "**/*.ts"] })],
  server: {
    port: 4321,
  },
});
