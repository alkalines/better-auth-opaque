import { client, ready } from "@serenity-kit/opaque";

const WARM_SAMPLES = 10;

type BundleSize = { files: number; rawBytes: number; gzipBytes: number; brotliBytes: number };

/** Milliseconds one request takes, from sending it to reading the whole response body. */
async function timedRequest(url: string, init?: RequestInit): Promise<number> {
  const started = performance.now();
  const response = await fetch(url, init);
  await response.arrayBuffer();
  return performance.now() - started;
}

function median(values: number[]): number {
  const sorted = values.toSorted((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)]!;
}

function format(milliseconds: number): string {
  return `${milliseconds.toFixed(0)} ms`;
}

/** A sign-in challenge for an email that has no user; the response is a fake, same cost as real. */
function unknownUserChallenge(): RequestInit {
  return {
    method: "POST",
    headers: { "content-type": "application/json", origin: "http://localhost:3000" },
    body: JSON.stringify({
      email: "cold-start@example.com",
      loginRequest: client.startLogin({ password: "cold-start" }).startLoginRequest,
    }),
  };
}

/**
 * Cold start of the auth HTTP action: the very first requests after the push, before any test ran.
 * `GET /api/auth/ok` loads the bundle and builds Better Auth; the first sign-in challenge also
 * loads serenity's WASM (`WebAssembly.compile` at runtime). Warm numbers are the median of the
 * following requests to the same endpoints. Unknown email, so no user is needed.
 */
export default async function globalSetup(): Promise<void> {
  const siteUrl = process.env.CONVEX_SITE_URL;
  if (!siteUrl) {
    throw new Error("CONVEX_SITE_URL is not set; run the suite with `bun run test:convex`");
  }
  const authUrl = `${siteUrl}/api/auth`;
  await ready;

  const coldOk = await timedRequest(`${authUrl}/ok`);
  const coldChallenge = await timedRequest(
    `${authUrl}/sign-in/opaque/challenge`,
    unknownUserChallenge(),
  );

  const warmOk: number[] = [];
  const warmChallenge: number[] = [];
  for (let sample = 0; sample < WARM_SAMPLES; sample++) {
    warmOk.push(await timedRequest(`${authUrl}/ok`));
    warmChallenge.push(
      await timedRequest(`${authUrl}/sign-in/opaque/challenge`, unknownUserChallenge()),
    );
  }

  const bundle = JSON.parse(process.env.CONVEX_TEST_BUNDLE ?? "null") as BundleSize | null;
  console.log("\n[measurements] Convex default runtime, local anonymous backend");
  if (bundle) {
    console.log(
      `[measurements] auth HTTP action bundle: ${bundle.rawBytes} bytes raw, ` +
        `${bundle.gzipBytes} bytes gzip, ${bundle.brotliBytes} bytes brotli ` +
        `(http.js + ${bundle.files - 1} shared chunks, from convex dev --debug-bundle-path)`,
    );
  }
  console.log(
    `[measurements] first request after push: GET /ok ${format(coldOk)}, ` +
      `then first sign-in challenge ${format(coldChallenge)}`,
  );
  console.log(
    `[measurements] warm (median of ${WARM_SAMPLES}): GET /ok ${format(median(warmOk))}, ` +
      `sign-in challenge ${format(median(warmChallenge))}\n`,
  );
}
