import {
  MAX_CLOCK_SKEW_TOLERANCE_SECONDS,
  MAX_TRACKED_NONCE_AND_JTI,
} from "./constants";

const DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS = 60;

export interface JtiReplayCacheOptions {
  maxTrackedJti?: number;
  clockSkewToleranceSeconds?: number;
}

export interface IdTokenReplayEntry {
  readonly issuer: string;
  readonly jti: string;
  /** Token expiration as a Unix timestamp in seconds. */
  readonly expiresAt: number;
}

export interface IdTokenReplayCache {
  consume(entry: IdTokenReplayEntry): boolean | Promise<boolean>;
}

export class JtiReplayCache implements IdTokenReplayCache {
  private readonly entries = new Map<string, number>();
  private readonly maxTrackedJti: number;
  private readonly clockSkewToleranceSeconds: number;

  constructor(options: JtiReplayCacheOptions = {}) {
    const maxTrackedJti = options.maxTrackedJti ?? MAX_TRACKED_NONCE_AND_JTI;
    const clockSkewToleranceSeconds =
      options.clockSkewToleranceSeconds ?? DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS;

    if (!Number.isInteger(maxTrackedJti) || maxTrackedJti <= 0) {
      throw new Error("maxTrackedJti must be a positive integer");
    }
    if (
      !Number.isFinite(clockSkewToleranceSeconds) ||
      clockSkewToleranceSeconds < 0 ||
      clockSkewToleranceSeconds > MAX_CLOCK_SKEW_TOLERANCE_SECONDS
    ) {
      throw new Error(
        `clockSkewToleranceSeconds must be between 0 and ${MAX_CLOCK_SKEW_TOLERANCE_SECONDS}`,
      );
    }

    this.maxTrackedJti = maxTrackedJti;
    this.clockSkewToleranceSeconds = clockSkewToleranceSeconds;
  }

  consume(entry: IdTokenReplayEntry): boolean {
    const issuer = entry.issuer.trim();
    const jti = entry.jti.trim();
    const now = Math.floor(Date.now() / 1000);

    if (
      !issuer ||
      !jti ||
      !Number.isFinite(entry.expiresAt) ||
      entry.expiresAt <= now
    ) {
      return false;
    }

    this.purgeExpiredEntries(now);
    const key = `${issuer.length}:${issuer}${jti}`;

    if (this.entries.has(key)) {
      return false;
    }

    // Saturation must not silently evict a still-live replay marker.
    if (this.entries.size >= this.maxTrackedJti) {
      return false;
    }

    const retentionExpiresAt = entry.expiresAt + this.clockSkewToleranceSeconds;
    if (!Number.isFinite(retentionExpiresAt)) return false;

    this.entries.set(key, retentionExpiresAt);
    return true;
  }

  reset(): void {
    this.entries.clear();
  }

  private purgeExpiredEntries(now: number): void {
    for (const [key, expiresAt] of this.entries.entries()) {
      if (expiresAt <= now) {
        this.entries.delete(key);
      }
    }
  }
}
