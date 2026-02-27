import AsyncStorage from "@react-native-async-storage/async-storage";
import type { GuardhouseStorageAdapter } from "@guardhouse/react-native";

export const asyncSessionStorageAdapter: GuardhouseStorageAdapter = {
  async getItem(key: string): Promise<string | null> {
    const value = await AsyncStorage.getItem(key);
    return value ?? null;
  },

  async setItem(key: string, value: string): Promise<void> {
    await AsyncStorage.setItem(key, value);
  },

  async removeItem(key: string): Promise<void> {
    await AsyncStorage.removeItem(key);
  },
};
