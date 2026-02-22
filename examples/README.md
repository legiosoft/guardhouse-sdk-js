# Guardhouse SDK Examples

This folder contains runnable integration examples for:

- `examples/node` - backend OAuth/token server example
- `examples/react` - web SPA example using `@guardhouse/react`
- `examples/temp-react-auth-example` - web SPA example using `react-oidc-context` + `oidc-client-ts`
- `examples/react-native` - mobile example using `@guardhouse/react-native`

## Shared test identity server setup

Each example has its own `.env.example` template. Copy it to `.env` and fill your real test identity server values.

## Run order for end-to-end testing

1. Start backend:

```bash
cd examples/node
npm install
npm run dev
```

2. Start React web app:

```bash
cd examples/react
npm install
npm start
```

3. (Optional) Start temporary React OIDC app:

```bash
cd examples/temp-react-auth-example
npm install
npm start
```

4. Start React Native app (Expo SDK 54+):

```bash
cd examples/react-native
npm install
npm start

# in another terminal (Expo development build)
npm run android
# or
npm run ios
```

The React, temp React OIDC, and React Native API demo screens call the Node example `/protected` endpoint.
