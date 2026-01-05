import React from "react";
import { GuardhouseProvider } from "@guardhouse/react-native";
import AppNavigator from "./src/AppNavigator";

const AUTHORITY = "https://your-guardhouse-domain.com";
const CLIENT_ID = "your-client-id";
const REDIRECT_URI = "com.example.guardhouse://callback";

function App(): React.JSX.Element {
  return (
    <GuardhouseProvider
      authority={AUTHORITY}
      clientId={CLIENT_ID}
      redirectUri={REDIRECT_URI}
      scopes={["openid", "profile", "offline_access"]}
    >
      <AppNavigator />
    </GuardhouseProvider>
  );
}

export default App;
