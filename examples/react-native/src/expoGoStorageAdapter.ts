import * as SecureStore from "expo-secure-store";
import type { GuardhouseStorageAdapter } from "@guardhouse/react-native";
import { ChunkedSecureStore } from "./chunkedSecureStore";

const secureStoreOptions: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

const chunkedSecureStore = new ChunkedSecureStore(secureStoreOptions);

export const expoRefreshTokenStorageAdapter: GuardhouseStorageAdapter = {
  async getItem(key: string): Promise<string | null> {
    return chunkedSecureStore.getItem(key);
  },

  async setItem(key: string, value: string): Promise<void> {
    await chunkedSecureStore.setItem(key, value);
  },

  async removeItem(key: string): Promise<void> {
    await chunkedSecureStore.removeItem(key);
  },
};

export const expoGoStorageAdapter = expoRefreshTokenStorageAdapter;
