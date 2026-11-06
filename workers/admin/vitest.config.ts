import { mkdirSync } from "node:fs";
import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// The assets binding needs its directory to exist; tests inject a fake ASSETS, so it can be empty.
mkdirSync(path.resolve(import.meta.dirname, "dist"), { recursive: true });

export default defineConfig({
  plugins: [
    cloudflareTest(async () => {
      const migrations = await readD1Migrations(path.resolve(import.meta.dirname, "../../migrations"));
      return {
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: { bindings: { TEST_MIGRATIONS: migrations } },
      };
    }),
  ],
  test: {
    name: "admin",
    include: ["test/**/*.test.ts", "ui/test/**/*.test.ts"],
    setupFiles: ["./test/apply-migrations.ts"],
  },
});
