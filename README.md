# me&u Internal Tools SDK

Helpers for me&u internal tools that sit behind the central internal tools gateway.

The gateway authenticates users once with Google SSO, then forwards a signed identity with each request to downstream tools. This SDK verifies that identity so a downstream app can reject direct traffic that bypasses the gateway. It also lets a tool's backend call another tool's service API through the gateway.

Zero dependencies: WebCrypto and `fetch` only, so it runs on Node 22+ and edge runtimes.

In the examples below, replace `https://<gateway>` with your gateway's origin.

## Install from GitHub

```bash
npm install github:andymarcus/internal-tools-sdk#v0.4.0
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

A service API lets one tool's backend call another tool directly, with no person signed in. For example, `other-tool` can ask `example-tool` for a list of orders. Every request goes through the gateway, which checks which tool is calling and passes that on to the tool being called.

- The tool being called is the **provider**. Its service API lives under `/api/service/...`.
- The tool making the call is the **caller**.
- Access is decided in the provider's code: each route lists the tools allowed to call it.

### Providing a service API

Nothing to set up in the gateway: any route under `/api/service/` is a service API.

1. Create your routes under `app/api/service/...` (Next.js) or `api/service/...` (plain Vercel Functions).
2. Start each route with `requireServiceCaller`, listing the tools allowed to call it in `allowedCallers`. It is required: without it, the route throws an error on its first request.
3. Return the status from `GatewayAuthError`: `401` when there is no valid gateway token, `403` when the calling tool is not in `allowedCallers`.

```ts
// app/api/service/orders/route.ts
import { GatewayAuthError, requireServiceCaller } from "@meandu/internal-tools-sdk";

export async function GET(request: Request) {
  try {
    const caller = await requireServiceCaller(request.headers, {
      tool: "example-tool", // your tool's slug
      jwksUrl: "https://<gateway>/.well-known/gateway-jwks.json",
      issuer: "https://<gateway>",
      allowedCallers: ["other-tool"],
    });

    return Response.json({ orders: [], calledBy: caller.callerTool });
  } catch (error) {
    if (error instanceof GatewayAuthError) {
      return Response.json({ error: error.reason }, { status: error.status });
    }

    throw error;
  }
}
```

**Paste this into your AI coding assistant** (replace `https://<gateway>` with your gateway's origin first):

```text
Add a service API to this app so other internal tools can call it through the internal tools
gateway (https://<gateway>).
- Install the SDK: npm install github:andymarcus/internal-tools-sdk#v0.4.0
- Put each endpoint under app/api/service/... (Next.js) or api/service/... (plain Vercel
  Functions). Do not put user-facing pages there.
- Start every handler with requireServiceCaller(request.headers, { tool: "<my-tool-slug>",
  jwksUrl: "https://<gateway>/.well-known/gateway-jwks.json", issuer: "https://<gateway>",
  allowedCallers: ["<calling-tool-slug>"] }) from "@meandu/internal-tools-sdk".
- Catch GatewayAuthError and return JSON { error: error.reason } with status error.status (401
  or 403). Rethrow any other error.
- Use caller.callerTool if the endpoint needs to know which tool called it.
The endpoint I need: <describe what it should return or do>.
```

### Calling another tool

Before your tool can call a service API:

- It must be registered in the gateway, and deployed on the team's Vercel account.
- Its Vercel project must use OIDC Federation in **Team** issuer mode (the default for new projects).
- Calls only work from the **production** deployment. Preview and local builds are refused.
- The provider must list your tool's slug in `allowedCallers`.

Install `@vercel/oidc` 4.0.9 or later and this SDK:

```bash
npm install @vercel/oidc@^4.0.9 github:andymarcus/internal-tools-sdk#v0.4.0
```

Create the client once, then call `fetch` inside a route handler or server action: `getVercelOidcToken()` reads your deployment's token from the incoming request.

```ts
// lib/example-tool.ts
import { getVercelOidcToken } from "@vercel/oidc";
import { createToolClient } from "@meandu/internal-tools-sdk";

export const exampleTool = createToolClient({
  gatewayOrigin: "https://<gateway>",
  targetTool: "example-tool", // the provider's slug
  getOidcToken: getVercelOidcToken,
});

// app/api/orders/route.ts
import { exampleTool } from "@/lib/example-tool";

export async function GET() {
  // Calls https://<gateway>/example-tool/api/service/orders?limit=10
  const response = await exampleTool.fetch("/orders?limit=10");
  return Response.json(await response.json(), { status: response.status });
}
```

The client caches its gateway token and retries once with a fresh token on a `401`. Paths start with `/` and are relative to the provider's `/api/service`. A `403` means the provider has not listed your tool in `allowedCallers`. The client never follows redirects: if the gateway redirects a call (for example to its login page), `fetch` throws an error saying so.

**Paste this into your AI coding assistant** (replace `https://<gateway>` with your gateway's origin first):

```text
Call the "<provider-slug>" internal tool's service API from this app's backend through the
internal tools gateway (https://<gateway>).
- Install: npm install @vercel/oidc@^4.0.9 github:andymarcus/internal-tools-sdk#v0.4.0
- In lib/<provider-slug>.ts, create and export a client with createToolClient({ gatewayOrigin:
  "https://<gateway>", targetTool: "<provider-slug>", getOidcToken: getVercelOidcToken }) from
  "@meandu/internal-tools-sdk" and "@vercel/oidc".
- Only call client.fetch("/<path>") inside a route handler or server action, never at module
  top level or in client components. Paths are relative to the provider's /api/service.
- Handle non-2xx responses: 401 means the gateway rejected this deployment, 403 means the
  provider has not allowed this tool.
- This only works on the production deployment on Vercel.
The endpoint I need: <path and what to do with the result>.
```

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
- Only accept service callers on endpoints meant for other tools: use `requireServiceCaller` with the callers you expect in `allowedCallers`.
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

Verifies a v2 service token and returns the service payload (`callerTool`, `tool`, `host`, `path`, `iat`). `allowedCallers` (a non-empty list of tool slugs) is required; without it, it throws a plain `Error` before checking anything. Throws `GatewayAuthError` with status 401 for a missing or invalid token, and 403 for a user identity or a caller not in `allowedCallers`.

### `createToolClient(options)`

Returns `{ fetch(path, init?), getAccessToken() }` for calling another tool's service API through the gateway. Options: `gatewayOrigin`, `targetTool`, `getOidcToken`, and optionally `fetch`. Requests go to `/<targetTool>/api/service/...` (`SERVICE_API_PATH_PREFIX`). Redirects are never followed and throw an error.

### Gateway side: `createGatewayToken`, `createGatewayRequestHeaders`, `createGatewayHeaders`

Used by the gateway app itself and in tests. `createGatewayToken` signs a v2 token with an ECDSA P-256 private key. `createGatewayRequestHeaders` builds v1 and v2 headers together and never builds v1 for service calls. `createGatewayHeaders` builds v1 headers only.
