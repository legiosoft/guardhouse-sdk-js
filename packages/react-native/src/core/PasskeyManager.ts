import type {
  GuardhouseAuthResult,
  GuardhousePasskeyAdapter,
  GuardhouseTokenResponse,
  LoginWithPasskeyOptions,
  PasskeyAssertionResult,
  PasskeyCredentialRequestOptions,
} from "../types/index";
import { GuardhouseAuthError, GuardhouseNetworkError } from "../types/errors";
import type { FetchLike } from "../types/index";
import type { GuardhouseLogger } from "../utils/logger";
import { compactRecord, trimToUndefined } from "../utils/url";
import { parseTokenResponsePayload } from "./AuthManager";

interface ParsedPasskeyChallenge {
  challengeId?: string;
  requestOptions: PasskeyCredentialRequestOptions;
}

interface PasskeyManagerConfig {
  clientId: string;
  defaultScope: string;
  defaultAudience?: string;
  passkeyChallengeEndpoint: string;
  passkeyAssertionEndpoint: string;
  fetch: FetchLike;
  passkey?: GuardhousePasskeyAdapter;
  logger: GuardhouseLogger;
  persistTokenResponse: (
    tokenResponse: GuardhouseTokenResponse,
  ) => Promise<GuardhouseAuthResult>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Handles headless WebAuthn challenge/assertion authentication.
 */
export class PasskeyManager {
  private readonly clientId: string;
  private readonly defaultScope: string;
  private readonly defaultAudience?: string;
  private readonly passkeyChallengeEndpoint: string;
  private readonly passkeyAssertionEndpoint: string;
  private readonly fetchFn: FetchLike;
  private readonly passkey?: GuardhousePasskeyAdapter;
  private readonly logger: GuardhouseLogger;
  private readonly persistTokenResponse: (
    tokenResponse: GuardhouseTokenResponse,
  ) => Promise<GuardhouseAuthResult>;

  constructor(config: PasskeyManagerConfig) {
    this.clientId = config.clientId;
    this.defaultScope = config.defaultScope;
    this.defaultAudience = config.defaultAudience;
    this.passkeyChallengeEndpoint = config.passkeyChallengeEndpoint;
    this.passkeyAssertionEndpoint = config.passkeyAssertionEndpoint;
    this.fetchFn = config.fetch;
    this.passkey = config.passkey;
    this.logger = config.logger;
    this.persistTokenResponse = config.persistTokenResponse;
  }

  /**
   * Executes Guardhouse headless WebAuthn flow and delegates token persistence
   * to `AuthManager` through the provided callback.
   */
  async loginWithPasskey(
    options: LoginWithPasskeyOptions = {},
  ): Promise<GuardhouseAuthResult> {
    const passkeyAdapter = this.requirePasskeyAdapter();
    const scope = trimToUndefined(options.scope) ?? this.defaultScope;
    const audience = trimToUndefined(options.audience) ?? this.defaultAudience;

    const challengeRequestBody = compactRecord({
      client_id: this.clientId,
      scope,
      audience,
      ...(options.challengeBody ?? {}),
    });

    const challengePayload = await this.postJson(
      this.passkeyChallengeEndpoint,
      challengeRequestBody,
      "Passkey challenge request",
    );
    const challenge = this.parsePasskeyChallenge(challengePayload);

    const assertion = await passkeyAdapter.get(challenge.requestOptions);
    this.validatePasskeyAssertion(assertion);

    const assertionBody = compactRecord({
      client_id: this.clientId,
      scope,
      audience,
      challenge_id: challenge.challengeId,
      challengeId: challenge.challengeId,
      credential: assertion,
      assertion,
      ...(options.assertionBody ?? {}),
    });

    const verificationPayload = await this.postJson(
      this.passkeyAssertionEndpoint,
      assertionBody,
      "Passkey assertion verification",
    );

    const tokenResponse = parseTokenResponsePayload(verificationPayload);
    return this.persistTokenResponse(tokenResponse);
  }

  private requirePasskeyAdapter(): GuardhousePasskeyAdapter {
    if (this.passkey) {
      return this.passkey;
    }

    throw new GuardhouseAuthError(
      "No passkey adapter configured",
      "PASSKEY_ADAPTER_MISSING",
    );
  }

  private parsePasskeyChallenge(payload: unknown): ParsedPasskeyChallenge {
    if (!isRecord(payload)) {
      throw new GuardhouseAuthError(
        "Passkey challenge response is not a JSON object",
        "PASSKEY_ERROR",
        undefined,
        payload,
      );
    }

    const requestOptionsCandidate = [
      payload.publicKey,
      payload.public_key,
      payload.publicKeyCredentialRequestOptions,
      payload.requestOptions,
      payload.options,
    ].find((entry) => isRecord(entry));

    const requestOptionsRecord = isRecord(requestOptionsCandidate)
      ? requestOptionsCandidate
      : typeof payload.challenge === "string"
        ? payload
        : null;

    if (!requestOptionsRecord) {
      throw new GuardhouseAuthError(
        "Passkey challenge response is missing request options",
        "PASSKEY_ERROR",
        undefined,
        payload,
      );
    }

    const challenge = trimToUndefined(
      typeof requestOptionsRecord.challenge === "string"
        ? requestOptionsRecord.challenge
        : undefined,
    );

    if (!challenge) {
      throw new GuardhouseAuthError(
        "Passkey request options are missing a challenge",
        "PASSKEY_ERROR",
        undefined,
        payload,
      );
    }

    const challengeId = this.readStringFromCandidates(payload, [
      "challenge_id",
      "challengeId",
      "request_id",
      "requestId",
      "id",
    ]);

    return {
      challengeId,
      requestOptions: {
        ...(requestOptionsRecord as PasskeyCredentialRequestOptions),
        challenge,
      },
    };
  }

  private validatePasskeyAssertion(assertion: PasskeyAssertionResult): void {
    if (!isRecord(assertion)) {
      throw new GuardhouseAuthError(
        "Passkey assertion result is invalid",
        "PASSKEY_ERROR",
      );
    }

    const assertionId = trimToUndefined(
      typeof assertion.id === "string" ? assertion.id : undefined,
    );

    if (!assertionId) {
      throw new GuardhouseAuthError(
        "Passkey assertion result is missing credential id",
        "PASSKEY_ERROR",
      );
    }

    const response = assertion.response;

    if (!isRecord(response)) {
      throw new GuardhouseAuthError(
        "Passkey assertion result is missing response payload",
        "PASSKEY_ERROR",
      );
    }

    const clientDataJSON = trimToUndefined(
      typeof response.clientDataJSON === "string"
        ? response.clientDataJSON
        : undefined,
    );
    const authenticatorData = trimToUndefined(
      typeof response.authenticatorData === "string"
        ? response.authenticatorData
        : undefined,
    );
    const signature = trimToUndefined(
      typeof response.signature === "string" ? response.signature : undefined,
    );

    if (!clientDataJSON || !authenticatorData || !signature) {
      throw new GuardhouseAuthError(
        "Passkey assertion result is missing required WebAuthn fields",
        "PASSKEY_ERROR",
      );
    }
  }

  private readStringFromCandidates(
    source: Record<string, unknown>,
    keys: string[],
  ): string | undefined {
    for (const key of keys) {
      const candidate = source[key];

      if (typeof candidate !== "string") {
        continue;
      }

      const normalized = trimToUndefined(candidate);

      if (normalized) {
        return normalized;
      }
    }

    return undefined;
  }

  private async postJson(
    url: string,
    body: Record<string, unknown>,
    operationLabel: string,
  ): Promise<unknown> {
    let response: Response;

    try {
      response = await this.fetchFn(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
      });
    } catch (error) {
      throw new GuardhouseNetworkError(
        `${operationLabel} failed due to a network error`,
        error,
      );
    }

    const payload = await this.readResponsePayload(response);

    if (response.ok) {
      return payload;
    }

    this.logger.warn(`${operationLabel} failed`, {
      status: response.status,
    });

    throw new GuardhouseAuthError(
      `${operationLabel} failed`,
      "PASSKEY_ERROR",
      response.status,
      payload,
    );
  }

  private async readResponsePayload(response: Response): Promise<unknown> {
    const text = await response.text();

    if (!text) {
      return undefined;
    }

    try {
      return JSON.parse(text) as unknown;
    } catch {
      return text;
    }
  }
}
