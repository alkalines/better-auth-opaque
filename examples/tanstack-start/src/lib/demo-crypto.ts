/**
 * Demo client-side key hierarchy, all Web Crypto:
 * export key (from OPAQUE) -> HKDF-SHA-256 -> KEK -> AES-GCM wraps a random data key.
 * The server only ever stores the wrapped key, so it cannot recover the data key.
 */

const KEK_INFO = new TextEncoder().encode("better-auth-opaque demo");
const DATA_KEY_STORAGE = "demo-data-key";

/** Wrapped data key as stored by the server payload hooks (base64url fields). */
export type WrappedDataKey = { iv: string; wrappedKey: string };

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function deriveKek(exportKey: string): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", fromBase64Url(exportKey), "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: KEK_INFO },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

/** Generates a fresh extractable AES-GCM data key. */
export function generateDataKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

/** Wraps `dataKey` under the KEK derived from `exportKey` (base64url). */
export async function wrapDataKey(dataKey: CryptoKey, exportKey: string): Promise<WrappedDataKey> {
  const kek = await deriveKek(exportKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.wrapKey("raw", dataKey, kek, { name: "AES-GCM", iv });
  return { iv: toBase64Url(iv), wrappedKey: toBase64Url(new Uint8Array(wrapped)) };
}

/** Unwraps a payload from the server; rejects when the export key does not match. */
export async function unwrapDataKey(payload: unknown, exportKey: string): Promise<CryptoKey> {
  const { iv, wrappedKey } = payload as WrappedDataKey;
  const kek = await deriveKek(exportKey);
  return crypto.subtle.unwrapKey(
    "raw",
    fromBase64Url(wrappedKey),
    kek,
    { name: "AES-GCM", iv: fromBase64Url(iv) },
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
}

/** First 8 bytes of SHA-256 over the raw data key, hex. Safe to display. */
export async function fingerprint(dataKey: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", dataKey);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  return Array.from(digest.slice(0, 8), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Keeps the data key in sessionStorage so change-password can rewrap it. Demo only. */
export async function storeDataKey(dataKey: CryptoKey): Promise<void> {
  const raw = await crypto.subtle.exportKey("raw", dataKey);
  sessionStorage.setItem(DATA_KEY_STORAGE, toBase64Url(new Uint8Array(raw)));
}

/** Returns the stored data key, or `null` when the user has not signed in in this tab. */
export function loadDataKey(): Promise<CryptoKey> | null {
  const stored = sessionStorage.getItem(DATA_KEY_STORAGE);
  if (!stored) {
    return null;
  }
  return crypto.subtle.importKey("raw", fromBase64Url(stored), { name: "AES-GCM" }, true, [
    "encrypt",
    "decrypt",
  ]);
}

export function clearDataKey(): void {
  sessionStorage.removeItem(DATA_KEY_STORAGE);
}
