import { MAX_TRACKED_NONCE_AND_JTI } from "./constants";

export const DEFAULT_JTI_REPLAY_TTL_MS = 300_000;

export interface JtiReplayCacheOptions {
  maxTrackedJti?: number;
  ttlMs?: number;
}

export class JtiReplayCache {
  private readonly entries = new Map<string, number>();
  private readonly maxTrackedJti: number;
  private readonly ttlMs: number;

  constructor(options: JtiReplayCacheOptions = {}) {
    const maxTrackedJti = options.maxTrackedJti ?? MAX_TRACKED_NONCE_AND_JTI;
    const ttlMs = options.ttlMs ?? DEFAULT_JTI_REPLAY_TTL_MS;

    if (!Number.isInteger(maxTrackedJti) || maxTrackedJti <= 0) {
      throw new Error("maxTrackedJti must be a positive integer");
    }

    if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
      throw new Error("ttlMs must be a positive integer");
    }

    this.maxTrackedJti = maxTrackedJti;
    this.ttlMs = ttlMs;
  }

  consume(jti: string): boolean {
    const normalizedJti = jti.trim();
    if (!normalizedJti) {
      return false;
    }

    const now = Date.now();
    this.purgeExpiredEntries(now);

    if (this.entries.has(normalizedJti)) {
      return false;
    }

    this.entries.set(normalizedJti, now + this.ttlMs);
    this.evictOverflowEntries();
    return true;
  }

  reset(): void {
    this.entries.clear();
  }

  private purgeExpiredEntries(now: number): void {
    for (const [jti, expiresAt] of this.entries.entries()) {
      if (now > expiresAt) {
        this.entries.delete(jti);
      } else {
        break;
      }
    }
  }

  private evictOverflowEntries(): void {
    while (this.entries.size > this.maxTrackedJti) {
      const oldestJti = this.entries.keys().next().value;
      if (!oldestJti) {
        break;
      }

      this.entries.delete(oldestJti);
    }
  }
}
