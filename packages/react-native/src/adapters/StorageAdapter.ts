import { GuardhouseStorageError } from "../types/errors";
import { SecureStorage } from "../utils/storage";

const CHUNK_COUNT_SUFFIX = "__chunk_count";
const CHUNK_KEY_SUFFIX = "__chunk_";

/**
 * Minimal async key-value storage adapter contract.
 */
export interface GuardhouseStorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

/**
 * Default secure storage adapter using react-native-keychain.
 */
export class KeychainStorageAdapter implements GuardhouseStorageAdapter {
  private readonly storage: SecureStorage;

  constructor(requireBiometrics = false, debug = false) {
    this.storage = new SecureStorage(requireBiometrics, debug);
  }

  async getItem(key: string): Promise<string | null> {
    return this.storage.getItem(key);
  }

  async setItem(key: string, value: string): Promise<void> {
    await this.storage.setItem(key, value);
  }

  async removeItem(key: string): Promise<void> {
    await this.storage.removeItem(key);
  }
}

/**
 * Chunking wrapper that transparently stores large values across multiple keys.
 */
export class ChunkedSecureStore implements GuardhouseStorageAdapter {
  constructor(
    private readonly storage: GuardhouseStorageAdapter,
    private readonly chunkSize = 2000,
  ) {}

  async getItem(key: string): Promise<string | null> {
    try {
      const chunkCount = await this.readChunkCount(key);

      if (chunkCount === 0) {
        return this.storage.getItem(key);
      }

      const chunks = await Promise.all(
        Array.from({ length: chunkCount }, (_, index) =>
          this.storage.getItem(this.chunkKey(key, index)),
        ),
      );

      if (chunks.some((chunk) => chunk === null)) {
        return null;
      }

      return chunks.join("");
    } catch (error) {
      throw new GuardhouseStorageError(
        `Failed to read chunked value for key '${key}'`,
        error,
      );
    }
  }

  async setItem(key: string, value: string): Promise<void> {
    try {
      const previousChunkCount = await this.readChunkCount(key);

      if (value.length <= this.chunkSize) {
        await this.storage.setItem(key, value);
        await this.deleteChunkKeys(key, previousChunkCount);
        return;
      }

      const chunks = this.splitChunks(value, this.chunkSize);

      await this.storage.removeItem(key);
      await this.storage.setItem(this.countKey(key), String(chunks.length));

      await Promise.all(
        chunks.map((chunk, index) =>
          this.storage.setItem(this.chunkKey(key, index), chunk),
        ),
      );

      if (previousChunkCount > chunks.length) {
        await Promise.all(
          Array.from({ length: previousChunkCount - chunks.length }, (_, i) =>
            this.storage.removeItem(this.chunkKey(key, chunks.length + i)),
          ),
        );
      }
    } catch (error) {
      throw new GuardhouseStorageError(
        `Failed to write chunked value for key '${key}'`,
        error,
      );
    }
  }

  async removeItem(key: string): Promise<void> {
    try {
      const chunkCount = await this.readChunkCount(key);

      await this.storage.removeItem(key);
      await this.deleteChunkKeys(key, chunkCount);
    } catch (error) {
      throw new GuardhouseStorageError(
        `Failed to remove chunked value for key '${key}'`,
        error,
      );
    }
  }

  private splitChunks(value: string, chunkSize: number): string[] {
    const chunks: string[] = [];

    for (let index = 0; index < value.length; index += chunkSize) {
      chunks.push(value.slice(index, index + chunkSize));
    }

    return chunks;
  }

  private async readChunkCount(key: string): Promise<number> {
    const storedCount = await this.storage.getItem(this.countKey(key));

    if (!storedCount) {
      return 0;
    }

    const parsed = Number.parseInt(storedCount, 10);

    if (!Number.isInteger(parsed) || parsed <= 0) {
      return 0;
    }

    return parsed;
  }

  private async deleteChunkKeys(
    key: string,
    chunkCount: number,
  ): Promise<void> {
    await this.storage.removeItem(this.countKey(key));

    if (chunkCount <= 0) {
      return;
    }

    await Promise.all(
      Array.from({ length: chunkCount }, (_, index) =>
        this.storage.removeItem(this.chunkKey(key, index)),
      ),
    );
  }

  private countKey(key: string): string {
    return `${key}${CHUNK_COUNT_SUFFIX}`;
  }

  private chunkKey(key: string, index: number): string {
    return `${key}${CHUNK_KEY_SUFFIX}${index}`;
  }
}
