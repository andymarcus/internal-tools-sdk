# me&u Internal Tools SDK

Helpers for me&u internal tools that sit behind the central internal tools gateway.

The gateway authenticates users once with Google SSO, then forwards signed identity headers to downstream tools. This SDK verifies those headers so a downstream app can reject direct traffic that bypasses the gateway.

## Install from GitHub

```bash
npm install github:andymarcus/internal-tools-sdk#v0.2.0
```

## Required environment variable

```env
INTERNAL_AUTH_SHARED_SECRET=
```

This value must match the secret configured in the gateway. Do not commit it to GitHub.

## Next.js usage

Create a helper in the downstream app:

```ts
import { headers } from "next/headers";
import { requireGatewayHeaders } from "@meandu/internal-tools-sdk";

export async function requireInternalToolUser() {
  return requireGatewayHeaders(await headers(), {
    secret: process.env.INTERNAL_AUTH_SHARED_SECRET!,
  });
}
```

Then call that helper from protected server components, layouts, route handlers, or server actions before returning private content.

Example protected page:

```tsx
import { requireInternalToolUser } from "@/lib/require-internal-tool-user";

export default async function Page() {
  const user = await requireInternalToolUser();

  return <main>Signed in as {user.email}</main>;
}
```

## MCP and OAuth calls

Since 0.2.0 the gateway payload also says how the gateway authenticated the request:

- `authMethod: "session"`: a person using the tool in their browser through Google SSO.
- `authMethod: "oauth"`: an MCP client (such as Claude) calling the tool's MCP endpoint with a gateway-issued access token on the user's behalf. `clientId` identifies the client and `scopes` lists the OAuth scopes the user granted.

Payloads from gateways older than 0.2.0 have no `authMethod`. Treat that as a browser session. The gateway never forwards the client's access token, so the tool only ever sees the signed headers.

```ts
const user = await requireInternalToolUser();

if (user.authMethod === "oauth" && !user.scopes?.includes("write")) {
  throw new Error("This MCP client only has read access.");
}
```

## Direct-access protection

Downstream apps should reject requests that do not include valid gateway headers. This prevents someone from opening the downstream deployment URL directly and bypassing the gateway.

## Next.js base path

If the gateway mounts the tool at `/example-tool`, configure the downstream Next.js app with the same base path:

```ts
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  basePath: "/example-tool",
};

export default nextConfig;
```

## Security notes

- Keep `INTERNAL_AUTH_SHARED_SECRET` out of source control.
- Share the secret through an approved secrets manager.
- Use HTTPS for gateway and downstream traffic.
- Avoid logging `x-meandu-gateway-payload` or `x-meandu-gateway-signature`.
- Rotate the shared secret if it is exposed.

## API

### `requireGatewayHeaders(headers, options)`

Verifies the signed gateway headers and returns the gateway payload. Throws `GatewayAuthError` when headers are missing, expired, or invalid.

```ts
const user = await requireGatewayHeaders(headers, {
  secret: process.env.INTERNAL_AUTH_SHARED_SECRET!,
  maxAgeSeconds: 60,
});
```

### `verifyGatewayHeaders(headers, options)`

Verifies the signed gateway headers and returns the gateway payload, or `null` when headers are missing, expired, or invalid.

### `createGatewayHeaders(input)`

Creates signed gateway headers. This is primarily for the gateway app itself and for tests.
