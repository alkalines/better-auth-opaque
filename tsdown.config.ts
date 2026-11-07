import { defineConfig } from "tsdown";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    client: "src/client/index.ts",
    cli: "src/cli.ts",
  },
  format: "esm",
  platform: "neutral",
  target: "es2022",
  fixedExtension: false,
  // Declarations come from the TypeScript 7 (tsgo) CLI: the Better Auth plugin and zod schemas
  // rely on inferred types, which `isolatedDeclarations` would force us to restate by hand.
  dts: {
    generator: "tsgo",
    tsconfig: "tsconfig.build.json",
  },
  clean: true,
  sourcemap: false,
});
