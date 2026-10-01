import {
  validateAndNormalizeRedirectUri,
  validateResourceIndicator,
} from "../security";

import { STATE_TOKEN_PATTERN } from "./constants";
import type { AuthorizationTransaction } from "./types";

const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
const PKCE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;
const NONCE_PATTERN = /^[A-Za-z0-9._~-]{16,512}$/;
const MAX_TRANSACTION_LIFETIME_MS = 60 * 60 * 1000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function canonicalizeIssuer(value: string): string {
  const parsed = new URL(value.trim());
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("Issuer must not contain credentials, query, or fragment");
  }
  return parsed.href;
}

function optionalString(
  record: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = record[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`Authorization transaction ${key} is invalid`);
  }
  return value;
}

export function restoreAuthorizationTransaction(
  value: unknown,
  expected: { issuer: string; clientId: string },
  now = Date.now(),
): AuthorizationTransaction {
  if (!isRecord(value) || value["version"] !== 2) {
    throw new Error("Authorization transaction is not a supported v2 record");
  }

  const stringKeys = [
    "issuer",
    "clientId",
    "redirectUri",
    "state",
    "codeVerifier",
    "codeChallenge",
    "nonce",
    "requestedScope",
    "responseMode",
  ] as const;
  for (const key of stringKeys) {
    if (typeof value[key] !== "string" || value[key].trim() === "") {
      throw new Error(`Authorization transaction ${key} is invalid`);
    }
  }

  const issuer = canonicalizeIssuer(value["issuer"] as string);
  if (issuer !== canonicalizeIssuer(expected.issuer)) {
    throw new Error("Authorization transaction issuer does not match this client");
  }

  const clientId = (value["clientId"] as string).trim();
  if (clientId !== expected.clientId.trim()) {
    throw new Error("Authorization transaction client ID does not match this client");
  }

  const state = value["state"] as string;
  const codeVerifier = value["codeVerifier"] as string;
  const codeChallenge = value["codeChallenge"] as string;
  const nonce = value["nonce"] as string;
  if (!STATE_TOKEN_PATTERN.test(state)) {
    throw new Error("Authorization transaction state is invalid");
  }
  if (!PKCE_VERIFIER_PATTERN.test(codeVerifier)) {
    throw new Error("Authorization transaction PKCE verifier is invalid");
  }
  if (!PKCE_CHALLENGE_PATTERN.test(codeChallenge)) {
    throw new Error("Authorization transaction PKCE challenge is invalid");
  }
  if (!NONCE_PATTERN.test(nonce)) {
    throw new Error("Authorization transaction nonce is invalid");
  }

  const redirectUri = validateAndNormalizeRedirectUri(
    value["redirectUri"] as string,
  );
  const responseMode = value["responseMode"];
  if (responseMode !== "query" && responseMode !== "form_post") {
    throw new Error("Authorization transaction response mode is invalid");
  }

  const createdAt = value["createdAt"];
  const expiresAt = value["expiresAt"];
  if (
    typeof createdAt !== "number" ||
    !Number.isFinite(createdAt) ||
    !Number.isInteger(createdAt) ||
    typeof expiresAt !== "number" ||
    !Number.isFinite(expiresAt) ||
    !Number.isInteger(expiresAt) ||
    expiresAt <= createdAt ||
    expiresAt - createdAt > MAX_TRANSACTION_LIFETIME_MS
  ) {
    throw new Error("Authorization transaction lifetime is invalid");
  }
  if (now < createdAt - 60_000 || now >= expiresAt) {
    throw new Error("Authorization transaction has expired or is not yet valid");
  }

  const resources = value["requestedResources"];
  if (
    !Array.isArray(resources) ||
    resources.length > 16
  ) {
    throw new Error("Authorization transaction resources are invalid");
  }
  let validatedResources: string[];
  try {
    validatedResources = resources.map((entry) =>
      validateResourceIndicator(entry as string),
    );
  } catch {
    throw new Error("Authorization transaction resources are invalid");
  }
  const readStringArray = (key: string): readonly string[] => {
    const field = value[key];
    if (
      !Array.isArray(field) ||
      field.some((entry) => typeof entry !== "string" || entry.trim() === "")
    ) {
      throw new Error(`Authorization transaction ${key} is invalid`);
    }
    return Object.freeze([...field] as string[]);
  };
  const maxAgeSeconds = value["maxAgeSeconds"];
  if (
    maxAgeSeconds !== undefined &&
    (typeof maxAgeSeconds !== "number" ||
      !Number.isInteger(maxAgeSeconds) ||
      maxAgeSeconds < 0)
  ) {
    throw new Error("Authorization transaction max age is invalid");
  }
  if (typeof value["issRequired"] !== "boolean") {
    throw new Error("Authorization transaction issuer requirement is invalid");
  }

  return Object.freeze({
    version: 2 as const,
    issuer,
    clientId,
    redirectUri,
    state,
    codeVerifier,
    codeChallenge,
    nonce,
    requestedScope: value["requestedScope"] as string,
    requestedAudience: optionalString(value, "requestedAudience"),
    requestedResources: Object.freeze(validatedResources),
    requiredAcrValues: readStringArray("requiredAcrValues"),
    requiredAmrValues: readStringArray("requiredAmrValues"),
    prompt: optionalString(value, "prompt"),
    maxAgeSeconds,
    responseMode,
    applicationState: value["applicationState"],
    createdAt,
    expiresAt,
    issRequired: value["issRequired"],
  });
}
