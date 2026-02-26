import { BASE64_URL_SEGMENT_PATTERN } from "./constants";

export function base64UrlEncodeBytes(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  if (typeof btoa !== "function") {
    throw new Error("Base64 encoder is unavailable in this environment");
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function decodeBase64ToBytes(base64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(base64, "base64"));
  }

  if (typeof atob === "function") {
    const binary = atob(base64);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }

  throw new Error("Base64 decoder runtime not supported in this environment");
}

function decodeUtf8(bytes: Uint8Array): string {
  if (typeof TextDecoder === "function") {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("utf8");
  }

  throw new Error("UTF-8 decoder runtime not supported in this environment");
}

export function base64UrlDecode(encoded: string): string {
  if (encoded === "") {
    return "";
  }

  if (!BASE64_URL_SEGMENT_PATTERN.test(encoded)) {
    throw new Error("Invalid Base64URL input: unsupported characters");
  }

  if (typeof Buffer !== "undefined") {
    try {
      return Buffer.from(encoded, "base64url").toString("utf8");
    } catch (error) {
      throw new Error(
        `Failed to decode Base64URL: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = base64.length % 4;

  if (remainder === 1) {
    throw new Error("Invalid Base64URL input length");
  }

  const paddedBase64 =
    remainder === 0 ? base64 : `${base64}${"=".repeat(4 - remainder)}`;

  try {
    const bytes = decodeBase64ToBytes(paddedBase64);
    return decodeUtf8(bytes);
  } catch (error) {
    throw new Error(
      `Failed to decode Base64URL: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}
