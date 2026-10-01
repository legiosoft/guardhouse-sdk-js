import { OidcIdTokenVerifier, type VerifiedIdToken } from "@guardhouse/core";

import { createReactNativeLogger } from "../debug";

export interface RedirectUriDescriptor {
  protocol: string;
  hostname: string;
  port: string;
  pathname: string;
}

export interface IdTokenValidatorOptions {
  authority: string;
  clientId: string;
  jwksUri?: string;
  requiredAcrValues?: string[];
  requiredAmrValues?: string[];
  /** @deprecated Insecure claims-only ID-token validation is no longer supported. */
  allowInsecureIdTokenValidation?: boolean;
  debug?: boolean;
}

function normalizePathname(pathname: string): string {
  if (!pathname || pathname === "/") return "/";
  return pathname.replace(/\/+$/, "");
}

function normalizeStringValues(values: string[] | undefined): string[] {
  return Array.from(
    new Set(
      (values ?? []).map((value) => value.trim()).filter((value) => value),
    ),
  );
}

export function createRedirectUriDescriptor(
  redirectUri: string,
): RedirectUriDescriptor {
  const parsed = new URL(redirectUri);

  return {
    protocol: parsed.protocol,
    hostname: parsed.hostname.toLowerCase(),
    port: parsed.port,
    pathname: normalizePathname(parsed.pathname),
  };
}

export function matchesRedirectUri(
  callbackUrl: string,
  expected: RedirectUriDescriptor,
): boolean {
  try {
    const callback = new URL(callbackUrl);

    return (
      callback.protocol === expected.protocol &&
      callback.hostname.toLowerCase() === expected.hostname &&
      callback.port === expected.port &&
      normalizePathname(callback.pathname) === expected.pathname
    );
  } catch {
    return false;
  }
}

export class IdTokenValidator {
  private readonly verifier: OidcIdTokenVerifier;
  private readonly requiredAcrValues: string[];
  private readonly requiredAmrValues: string[];
  private readonly logger: ReturnType<typeof createReactNativeLogger>;

  constructor(options: IdTokenValidatorOptions) {
    if (options.allowInsecureIdTokenValidation) {
      throw new Error(
        "allowInsecureIdTokenValidation is no longer supported; ID tokens must always be cryptographically verified",
      );
    }

    this.requiredAcrValues = normalizeStringValues(options.requiredAcrValues);
    this.requiredAmrValues = normalizeStringValues(options.requiredAmrValues);
    this.logger = createReactNativeLogger("IdToken", options.debug ?? false);
    this.verifier = new OidcIdTokenVerifier({
      authority: options.authority,
      clientId: options.clientId,
      jwksUri: options.jwksUri,
    });
  }

  async validate(idToken: string, nonce: string): Promise<VerifiedIdToken> {
    const normalizedNonce = nonce.trim();
    if (!normalizedNonce) {
      throw new Error(
        "A non-empty nonce is required for authorization ID tokens",
      );
    }
    const result = await this.verifier.verify(idToken, {
      purpose: "authorization_code",
      nonce: normalizedNonce,
      requiredAcrValues: this.requiredAcrValues,
      requiredAmrValues: this.requiredAmrValues,
    });

    this.logger.debug("ID token signature and claims validated", {
      kid: result.header.kid,
      algorithm: result.header.alg,
      requiredAmrCount: this.requiredAmrValues.length,
      requiredAcrCount: this.requiredAcrValues.length,
    });

    return result;
  }
}
