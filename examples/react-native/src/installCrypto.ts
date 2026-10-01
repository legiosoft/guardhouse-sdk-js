// Load before the SDK/App: PKCE adapters alone cannot verify signed ID tokens.
import { install } from "react-native-quick-crypto";

install();
