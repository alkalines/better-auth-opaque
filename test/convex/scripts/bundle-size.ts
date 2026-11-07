import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { brotliCompressSync, gzipSync } from "node:zlib";

export type BundleSize = {
  /** Number of JavaScript files the entry module loads, including the entry itself. */
  files: number;
  rawBytes: number;
  /** Sum of each file compressed on its own. */
  gzipBytes: number;
  brotliBytes: number;
};

const STATIC_AND_DYNAMIC_IMPORT = /(?:\bfrom|\bimport)\s*\(?\s*["'](\.{1,2}\/[^"']+\.js)["']/g;

/**
 * Size of the code one Convex module loads: the module from `convex --debug-bundle-path` plus
 * every chunk reachable through its relative imports. Convex bundles each module with esbuild
 * code splitting, so the HTTP router's size is the closure of `http.js`, not the file itself.
 * Source maps are not counted.
 */
export function measureBundle(isolateDir: string, entry: string): BundleSize {
  const seen = new Set<string>();
  const pending = [resolve(isolateDir, entry)];
  let rawBytes = 0;
  let gzipBytes = 0;
  let brotliBytes = 0;

  for (let file = pending.pop(); file !== undefined; file = pending.pop()) {
    if (seen.has(file)) {
      continue;
    }
    seen.add(file);

    const source = readFileSync(file);
    rawBytes += source.length;
    gzipBytes += gzipSync(source).length;
    brotliBytes += brotliCompressSync(source).length;

    for (const match of source.toString("utf8").matchAll(STATIC_AND_DYNAMIC_IMPORT)) {
      pending.push(resolve(dirname(file), match[1]!));
    }
  }

  return { files: seen.size, rawBytes, gzipBytes, brotliBytes };
}
