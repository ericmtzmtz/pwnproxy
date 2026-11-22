import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import preact from "@astrojs/preact";

export default defineConfig({
  vite: {
    resolve: {
      alias: {
        react: "preact/compat",
        "react-dom": "preact/compat",
        "react/jsx-runtime": "preact/jsx-runtime",
        "react/jsx-dev-runtime": "preact/jsx-dev-runtime",
      },
    },
    plugins: [
      tailwindcss(),
    ],
    optimizeDeps: {
      exclude: ["@astrojs/preact"],
      include: ["preact", "preact/hooks", "preact/jsx-runtime", "preact/compat"],
    },
  },
  integrations: [preact({ include: ["**/*.tsx", "**/*.ts"] })],
  server: {
    port: 17172,
  },
});
