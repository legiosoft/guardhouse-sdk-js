/**
 * useAuth Hook
 *
 * SECURITY DECISIONS:
 *
 * 1. Why derive isAuthenticated from state instead of token?
 *    - State is single source of truth
 *    - Prevents race conditions between token check and state update
 *    - Simplifies logic (no need to check token validity everywhere)
 *
 * 2. Why return full AuthContextValue?
 *    - Provides access to all auth state and methods
 *    - Consistent API (everything from useAuth)
 *    - No need to destructure or access context separately
 *
 * 3. Why throw error if used outside Provider?
 *    - Catches developer errors early
 *    - Prevents undefined state (hard to debug)
 *    - Standard React pattern for hooks
 */

import { useContext } from "react";
import { AuthContext } from "./GuardhouseProvider";
import type { AuthContextValue } from "./types";

/**
 * useAuth Hook
 *
 * Provides access to authentication state and actions
 *
 * @example
 * ```tsx
 * import { useAuth } from '@guardhouse/react-native';
 *
 * function MyComponent() {
 *   const { user, isAuthenticated, login, logout, getAccessToken } = useAuth();
 *
 *   return (
 *     <View>
 *       {isAuthenticated ? (
 *         <Text>Welcome, {user?.name}</Text>
 *       ) : (
 *         <Button onPress={login} title="Login" />
 *       )}
 *     </View>
 *   );
 * }
 * ```
 *
 * @throws {Error} If used outside GuardhouseProvider
 */
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);

  // SECURITY: Early error detection for developer mistakes
  if (!context) {
    throw new Error(
      "useAuth must be used within a GuardhouseProvider component",
    );
  }

  return context;
}

export default useAuth;
