import {
  GuardhouseNodeClient,
  GuardhouseAdminClient,
  type GuardhouseClientOptions,
} from "@guardhouse/node";
import { GuardhouseClient } from "@guardhouse/core";
import dotenv from "dotenv";

dotenv.config();

const AUTHORITY = process.env.AUTHORITY || "https://auth.example.com";
const CLIENT_ID = process.env.CLIENT_ID || "your-client-id";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "your-client-secret";
const SCOPE = process.env.SCOPE;

async function main() {
  console.log("Guardhouse Client Example (Client Credentials Flow)\n");

  console.log("1. Using GuardhouseNodeClient for Client Credentials flow:");

  const nodeClientOptions: GuardhouseClientOptions = {
    authority: AUTHORITY,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  };

  if (SCOPE) {
    nodeClientOptions.scope = SCOPE;
  }

  const nodeClient = new GuardhouseNodeClient(nodeClientOptions);

  try {
    const accessToken = await nodeClient.getAccessToken();
    console.log("   Access Token:", accessToken.substring(0, 20) + "...");

    console.log("\n2. Using GuardhouseClient directly:");

    const client = new GuardhouseClient({
      authority: AUTHORITY,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    const introspection = await client.introspectToken(accessToken);
    console.log("   Active:", introspection.active);
    console.log("   Client ID:", introspection.client_id);
    console.log("   Scope:", introspection.scope);

    console.log(
      "\n3. Using GuardhouseNodeClient to make authenticated requests:",
    );

    const data = await nodeClient.get<{ sub?: string }>(
      `${AUTHORITY}/connect/userinfo`,
    );
    console.log("   User info fetched:", data.sub);
  } catch (error) {
    console.error("   Error:", error instanceof Error ? error.message : error);
  }

  console.log("\n4. Using GuardhouseAdminClient for administrative tasks:");

  const adminClientOptions: GuardhouseClientOptions = {
    authority: AUTHORITY,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  };

  if (SCOPE) {
    adminClientOptions.scope = SCOPE;
  }

  const adminClient = new GuardhouseAdminClient(adminClientOptions);

  console.log("   Example operations:");
  console.log("   - await adminClient.listUsers();");
  console.log("   - await adminClient.getUser('user-id');");
  console.log("   - await adminClient.createUser(userData);");
  console.log("   - await adminClient.updateUser('user-id', userData);");
  console.log("   - await adminClient.deleteUser('user-id');");

  console.log(
    "\nNote: For authorization code flow (with user login), see the full example at src/index.ts",
  );
}

main().catch(console.error);
