// apps/web/scripts/dev.mjs
// Dev-server wrapper: `npm run dev --prefix apps/web -- --backend IP:PORT`
// Parses `--backend <host>:<port>` (or a full http(s) URL), derives
// PUBLIC_API_BASE, then starts `astro dev` passing through any extra args
// (e.g. `--host`, `--port`). Without `--backend` it behaves exactly like
// `astro dev` and keeps whatever PUBLIC_API_BASE is already set.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, "..");
const DEFAULT_API_BASE = "http://127.0.0.1:8000/api/v1";

function buildApiBase(backend) {
  let url = backend.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = `http://${url}`;
  }
  if (!url.includes("/api/v1")) {
    url = url.replace(/\/+$/, "") + "/api/v1";
  }
  return url;
}

const args = process.argv.slice(2);
let backend = null;
const rest = [];

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--backend") {
    backend = args[++i];
    if (backend === undefined) {
      console.error("[web] --backend requires a value: --backend IP:PORT");
      process.exit(1);
    }
  } else if (a.startsWith("--backend=")) {
    backend = a.slice("--backend=".length);
  } else {
    rest.push(a);
  }
}

if (backend) {
  process.env.PUBLIC_API_BASE = buildApiBase(backend);
  console.log(`[web] Backend -> ${process.env.PUBLIC_API_BASE}`);
} else {
  console.log(
    `[web] Backend -> ${process.env.PUBLIC_API_BASE ?? DEFAULT_API_BASE} ` +
      `(default; use --backend IP:PORT to override)`,
  );
}

const astroBin = path.join(webRoot, "node_modules", "astro", "bin", "astro.mjs");
const child = spawn(process.execPath, [astroBin, "dev", ...rest], {
  cwd: webRoot,
  env: process.env,
  stdio: "inherit",
});

child.on("error", (err) => {
  console.error(`[web] Failed to start astro: ${err.message}`);
  process.exit(1);
});

child.on("exit", (code) => process.exit(code ?? 0));

process.on("SIGINT", () => child.kill("SIGINT"));
process.on("SIGTERM", () => child.kill("SIGTERM"));
