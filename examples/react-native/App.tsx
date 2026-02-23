import React from "react";
import { GuardhouseProvider } from "@guardhouse/react-native";
import AppNavigator from "./src/AppNavigator";
import { appConfig } from "./src/config";
import { expoCryptoAdapter } from "./src/cryptoAdapter";

function App(): React.JSX.Element {
  return (
    <GuardhouseProvider
      authority={appConfig.authority}
      clientId={appConfig.clientId}
      redirectUri={appConfig.redirectUri}
      scopes={appConfig.scopes}
      cryptoAdapter={expoCryptoAdapter}
    >
      <AppNavigator />
    </GuardhouseProvider>
  );
}

export default App;
