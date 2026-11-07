/**
 * Web Crypto helpers for identifiers, state references, and reset tokens. Everything is encoded
 * as unpadded base64url so values are URL-safe and match serenity's encoding.
 */

const RANDOM_TOKEN_BYTES = 32;

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** 256 random bits from the platform CSPRNG, base64url. Used for state ids, credential ids and versions, and reset tokens. */
export function randomToken(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(RANDOM_TOKEN_BYTES)));
}

/** SHA-256 of the UTF-8 text, base64url. Reset tokens are stored only in this form. */
export async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return toBase64Url(new Uint8Array(digest));
}

/** HMAC-SHA-256 of `message` under the UTF-8 `key`, base64url. */
export async function hmacSha256(key: string, message: string): Promise<string> {
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message));
  return toBase64Url(new Uint8Array(signature));
}
