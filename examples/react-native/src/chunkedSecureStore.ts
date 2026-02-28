import * as SecureStore from "expo-secure-store";

const MAX_CHUNK_SIZE = 2000;
const CHUNK_COUNT_SUFFIX = "__chunk_count";
const CHUNK_KEY_PREFIX = "__chunk_";

function splitIntoChunks(value: string, chunkSize: number): string[] {
  const chunks: string[] = [];

  for (let index = 0; index < value.length; index += chunkSize) {
    chunks.push(value.slice(index, index + chunkSize));
  }

  return chunks;
}

export class ChunkedSecureStore {
  constructor(
    private readonly options: SecureStore.SecureStoreOptions,
    private readonly chunkSize = MAX_CHUNK_SIZE,
  ) {}

  async setItem(key: string, value: string): Promise<void> {
    const existingChunkCount = await this.readChunkCount(key);

    if (value.length <= this.chunkSize) {
      await SecureStore.setItemAsync(key, value, this.options);
      await this.removeChunkKeys(key, existingChunkCount);
      return;
    }

    const chunks = splitIntoChunks(value, this.chunkSize);

    await SecureStore.deleteItemAsync(key, this.options);
    await SecureStore.setItemAsync(
      this.getChunkCountKey(key),
      String(chunks.length),
      this.options,
    );

    await Promise.all(
      chunks.map((chunk, index) =>
        SecureStore.setItemAsync(
          this.getChunkKey(key, index),
          chunk,
          this.options,
        ),
      ),
    );

    if (existingChunkCount > chunks.length) {
      const staleKeys: Promise<void>[] = [];

      for (let index = chunks.length; index < existingChunkCount; index += 1) {
        staleKeys.push(
          SecureStore.deleteItemAsync(
            this.getChunkKey(key, index),
            this.options,
          ),
        );
      }

      await Promise.all(staleKeys);
    }
  }

  async getItem(key: string): Promise<string | null> {
    const chunkCount = await this.readChunkCount(key);

    if (chunkCount > 0) {
      const chunkReads: Promise<string | null>[] = [];

      for (let index = 0; index < chunkCount; index += 1) {
        chunkReads.push(
          SecureStore.getItemAsync(this.getChunkKey(key, index), this.options),
        );
      }

      const chunks = await Promise.all(chunkReads);

      if (chunks.some((chunk) => chunk === null)) {
        return null;
      }

      return chunks.join("");
    }

    const value = await SecureStore.getItemAsync(key, this.options);
    return value ?? null;
  }

  async removeItem(key: string): Promise<void> {
    const chunkCount = await this.readChunkCount(key);

    await SecureStore.deleteItemAsync(key, this.options);
    await this.removeChunkKeys(key, chunkCount);
  }

  private getChunkCountKey(key: string): string {
    return `${key}${CHUNK_COUNT_SUFFIX}`;
  }

  private getChunkKey(key: string, index: number): string {
    return `${key}${CHUNK_KEY_PREFIX}${index}`;
  }

  private async readChunkCount(key: string): Promise<number> {
    const storedCount = await SecureStore.getItemAsync(
      this.getChunkCountKey(key),
      this.options,
    );

    if (!storedCount) {
      return 0;
    }

    const count = Number.parseInt(storedCount, 10);

    if (!Number.isInteger(count) || count <= 0) {
      return 0;
    }

    return count;
  }

  private async removeChunkKeys(
    key: string,
    chunkCount: number,
  ): Promise<void> {
    const removals: Promise<void>[] = [
      SecureStore.deleteItemAsync(this.getChunkCountKey(key), this.options),
    ];

    for (let index = 0; index < chunkCount; index += 1) {
      removals.push(
        SecureStore.deleteItemAsync(this.getChunkKey(key, index), this.options),
      );
    }

    await Promise.all(removals);
  }
}
