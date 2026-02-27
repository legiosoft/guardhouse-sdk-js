import * as SecureStore from "expo-secure-store";
import type { GuardhouseStorageAdapter } from "@guardhouse/react-native";

const secureStoreOptions: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export const expoRefreshTokenStorageAdapter: GuardhouseStorageAdapter = {
  async getItem(key: string): Promise<string | null> {
    const value = await SecureStore.getItemAsync(key, secureStoreOptions);
    return value ?? null;
  },

  async setItem(key: string, value: string): Promise<void> {
    await SecureStore.setItemAsync(key, value, secureStoreOptions);
  },

  async removeItem(key: string): Promise<void> {
    await SecureStore.deleteItemAsync(key, secureStoreOptions);
  },
};

export const expoGoStorageAdapter = expoRefreshTokenStorageAdapter;
