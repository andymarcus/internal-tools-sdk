# me&u Internal Tools SDK

Helpers for me&u internal tools that sit behind the central internal tools gateway.

The gateway authenticates users once with Google SSO, then forwards a signed identity with each request to downstream tools. This SDK verifies that identity so a downstream app can reject direct traffic that bypasses the gateway. It also lets a tool's backend call another tool's service API through the gateway.

Zero dependencies: WebCrypto and `fetch` only, so it runs on Node 22+ and edge runtimes.

In the examples below, replace `https://<gateway>` with your gateway's origin.

## Install from GitHub

```bash
npm install github:andymarcus/internal-tools-sdk#v0.3.0
```

## Verifying requests (recommended)

Since 0.3.0 the gateway signs each request with an ES256 token (`x-meandu-gateway-token`, "v2") that tools verify against the gateway's public keys. No shared secret is needed.

Create a helper in the downstream app:

```ts
import { headers } from "next/headers";
import { requireGatewayHeaders } from "@meandu/internal-tools-sdk";

const gateway = {
  tool: "example-tool", // this tool's slug; tokens for other tools are rejected
  jwksUrl: "https://<gateway>/.well-known/gateway-jwks.json",
  issuer: "https://<gateway>",
};

export async function requireInternalToolUser() {
  return requireGatewayHeaders(await headers(), gateway);
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

Keys are fetched once and cached in memory. An unknown key id triggers at most one refetch per 30 seconds, and the tool fails closed if the keys cannot be fetched.

`requireGatewayHeaders` throws `GatewayAuthError` (`reason: "unauthenticated"`, `status: 401`) when the request has no valid identity. `verifyGatewayHeaders` returns `null` instead. Both throw a plain `Error` for configuration bugs, such as `jwksUrl` without `tool`.

## Migrating from the shared secret

Before 0.3.0, tools verified HMAC headers ("v1") with a shared secret:

```env
INTERNAL_AUTH_SHARED_SECRET=
```

The gateway sends both the v1 headers and the v2 token while tools migrate.

1. Add `tool`, `jwksUrl` and `issuer`, and keep `secret` for now:

   ```ts
   requireGatewayHeaders(await headers(), {
     ...gateway,
     secret: process.env.INTERNAL_AUTH_SHARED_SECRET,
   });
   ```

   When the v2 token is present, only v2 is checked (a bad token never falls back to v1). Requests without it, from an older gateway, are checked with the secret.
2. Once the gateway sends v2 everywhere, remove `secret` and the env var.

Secret-only calls (`{ secret }`) still work as before. Pass `tool` too so payloads signed for another tool are rejected.

## Who is calling

The payload's `authMethod` says how the gateway authenticated the request:

- `"session"`: a person using the tool in their browser through Google SSO.
- `"oauth"`: an MCP client (such as Claude) calling the tool's MCP endpoint with a gateway-issued access token on the user's behalf. `clientId` identifies the client and `scopes` lists what the user granted.
- `"service"`: another tool's backend calling as itself, with no user. See below.

v1 payloads from gateways older than 0.2.0 have no `authMethod`. Treat that as a browser session. The gateway never forwards the caller's access token, so the tool only ever sees the signed identity.

```ts
const user = await requireInternalToolUser();

if (user.authMethod === "oauth" && !user.scopes?.includes("write")) {
  throw new Error("This MCP client only has read access.");
}
```

`verifyGatewayHeaders` and `requireGatewayHeaders` reject service callers unless you pass `allowService: true`, so user-facing pages never mistake a tool for a person.

## Service APIs

Tools can expose endpoints for other tools under `/api/service/...`. The gateway checks the caller's identity and forwards a v2 token with `authMethod: "service"`, the calling tool's slug in `callerTool`, and the granted `scopes`.

### Providing a service API

```ts
// app/api/service/orders/route.ts
import { GatewayAuthError, requireServiceCaller } from "@meandu/internal-tools-sdk";

export async function GET(request: Request) {
  try {
    const caller = await requireServiceCaller(request.headers, {
      ...gateway,
      allowedCallers: ["other-tool"],
      requiredScopes: ["orders:read"],
    });

    return Response.json({ orders: [], caller: caller.callerTool });
  } catch (error) {
    if (error instanceof GatewayAuthError) {
      // 401 for a missing or invalid token, 403 for the wrong caller or missing scopes.
      return Response.json({ error: error.reason }, { status: error.status });
    }

    throw error;
  }
}
```

### Calling another tool

On Vercel, the calling tool authenticates with its deployment's OIDC token. Tokens are cached until 30 seconds before they expire, and a `401` is retried once with a fresh token. Create the client once at module scope, but call `fetch` inside a route handler or server action: `getVercelOidcToken()` reads the token from the request context.

```ts
// lib/example-tool.ts
import { getVercelOidcToken } from "@vercel/oidc";
import { createToolClient } from "@meandu/internal-tools-sdk";

export const exampleTool = createToolClient({
  gatewayOrigin: "https://<gateway>",
  targetTool: "example-tool",
  getOidcToken: getVercelOidcToken,
  scope: ["orders:read"],
});

// app/api/orders/route.ts
import { exampleTool } from "@/lib/example-tool";

export async function GET() {
  // GET https://<gateway>/example-tool/api/service/orders?limit=10
  const response = await exampleTool.fetch("/orders?limit=10");
  return Response.json(await response.json(), { status: response.status });
}
```

Paths must start with `/` and cannot leave the target tool's service API. If the provider narrows this tool's scopes, the gateway answers `403` with `error="insufficient_scope"`. The client then drops its cached token, so the next call gets one with the scopes still granted. If an explicit `scope` is no longer granted, the next token request fails with `invalid_scope`.

## Direct-access protection

Downstream apps should reject requests that do not carry a valid gateway identity. This prevents someone from opening the downstream deployment URL directly and bypassing the gateway.

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

- Use HTTPS for gateway and downstream traffic.
- Always pass `tool` so identities signed for another tool are rejected.
- Only accept service callers (`allowService: true` or `requireServiceCaller`) on endpoints meant for other tools, and list the callers you expect in `allowedCallers`.
- Avoid logging `x-meandu-gateway-token`, `x-meandu-gateway-payload` or `x-meandu-gateway-signature`.
- While you still use the shared secret, keep `INTERNAL_AUTH_SHARED_SECRET` out of source control, share it through an approved secrets manager, and rotate it if it is exposed. Remove it once the gateway sends v2 everywhere.

## API

### `requireGatewayHeaders(headers, options)`

Verifies the gateway identity and returns the payload. Throws `GatewayAuthError` when it is missing, expired, or invalid. Options: `tool`, `jwksUrl` or `jwks`, `issuer`, `secret` (v1), `allowService`, `maxAgeSeconds`, `clockToleranceSeconds`.

### `verifyGatewayHeaders(headers, options)`

Same as `requireGatewayHeaders`, but returns `null` instead of throwing.

### `verifyGatewayToken(headers, options)`

Verifies only the v2 token (`tool` and `jwksUrl` or `jwks` are required). Returns the payload, including service payloads, or `null`.

### `requireServiceCaller(headers, options)`

Verifies a v2 service token and returns the service payload. Throws `GatewayAuthError` with status 401 for a missing or invalid token, and 403 for a user identity, a caller not in `allowedCallers`, or missing `requiredScopes`.

### `createToolClient(options)`

Returns `{ fetch(path, init?), getAccessToken() }` for calling another tool's service API through the gateway. Options: `gatewayOrigin`, `targetTool`, `getOidcToken`, and optionally `scope`, `servicePath` (default `/api/service`) and `fetch`.

### Gateway side: `createGatewayToken`, `createGatewayRequestHeaders`, `createGatewayHeaders`

Used by the gateway app itself and in tests. `createGatewayToken` signs a v2 token with an ECDSA P-256 private key. `createGatewayRequestHeaders` builds v1 and v2 headers together and never builds v1 for service calls. `createGatewayHeaders` builds v1 headers only.
