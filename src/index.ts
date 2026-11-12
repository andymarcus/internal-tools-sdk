const encoder = new TextEncoder();
const decoder = new TextDecoder();

// v1: HMAC-SHA256 over a base64url JSON payload, keyed with the secret every tool shares.
export const GATEWAY_AUTH_PAYLOAD_HEADER = "x-meandu-gateway-payload";
export const GATEWAY_AUTH_SIGNATURE_HEADER = "x-meandu-gateway-signature";
export const GATEWAY_AUTH_VERSION = "v1";

// v2: an ES256 compact JWS signed by the gateway and verified against its public JWKS.
export const GATEWAY_TOKEN_HEADER = "x-meandu-gateway-token";
export const GATEWAY_TOKEN_VERSION = "v2";
export const GATEWAY_TOKEN_TYPE = "gateway+jwt";

const DEFAULT_MAX_AGE_SECONDS = 60;
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 5;
const DEFAULT_TOKEN_TTL_SECONDS = 60;
const JWKS_REFETCH_INTERVAL_MS = 30_000;
const JWKS_CACHE_TTL_MS = 5 * 60_000;
const JWKS_FETCH_TIMEOUT_MS = 5_000;
const ACCESS_TOKEN_REFRESH_SKEW_MS = 30_000;

export type GatewayIdentity = {
  email: string;
  image?: string | null;
  name?: string | null;
};

// "session": a person in their browser through Google SSO. "oauth": an MCP client calling the
// tool with a gateway-issued access token on behalf of the user. "service": another tool's
// backend calling as itself, with no end user.
export type GatewayAuthMethod = "session" | "oauth" | "service";
export type GatewayUserAuthMethod = Exclude<GatewayAuthMethod, "service">;

// How the gateway authenticated the request.
export type GatewayAuthInfo = {
  // The calling tool's slug. Set only for "service".
  callerTool?: string | null;
  clientId?: string | null;
  method: GatewayAuthMethod;
  scopes?: string[];
};

export type GatewayPayloadVersion = typeof GATEWAY_AUTH_VERSION | typeof GATEWAY_TOKEN_VERSION;

export type GatewayUserPayload = GatewayIdentity & {
  // Optional so v1 payloads from older gateways still verify.
  authMethod?: GatewayUserAuthMethod;
  clientId?: string | null;
  host: string;
  iat: number;
  path: string;
  scopes?: string[];
  tool: string;
  version: GatewayPayloadVersion;
};

// Service payloads are only ever v2 and never carry an end user.
export type GatewayServicePayload = {
  authMethod: "service";
  callerTool: string;
  clientId?: string | null;
  host: string;
  iat: number;
  path: string;
  scopes: string[];
  tool: string;
  version: typeof GATEWAY_TOKEN_VERSION;
};

export type GatewayPayload = GatewayUserPayload | GatewayServicePayload;

// A public JWK as served by the gateway JWKS endpoint. Only EC P-256 keys are used.
export type GatewayJwk = {
  alg?: string;
  crv?: string;
  kid?: string;
  kty?: string;
  use?: string;
  x?: string;
  y?: string;
};

export type GatewayJwks = { keys: GatewayJwk[] };

// "unauthenticated" maps to HTTP 401, "forbidden" to HTTP 403.
export type GatewayAuthErrorReason = "unauthenticated" | "forbidden";

export class GatewayAuthError extends Error {
  readonly reason: GatewayAuthErrorReason;
  readonly status: 401 | 403;

  constructor(message: string, reason: GatewayAuthErrorReason = "unauthenticated") {
    super(message);
    this.name = "GatewayAuthError";
    this.reason = reason;
    this.status = reason === "forbidden" ? 403 : 401;
  }
}

type HeadersLike = Headers | Pick<Headers, "get">;

// ---------------------------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------------------------

function toBase64Url(input: ArrayBuffer | Uint8Array) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string) {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("Invalid base64url value.");
  }

  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const binary = atob(`${normalized}${padding}`);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

function encodeJsonBase64Url(value: unknown) {
  return toBase64Url(encoder.encode(JSON.stringify(value)));
}

function decodeJsonBase64Url(value: string): unknown {
  return JSON.parse(decoder.decode(fromBase64Url(value)));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isOptionalNullableString(value: unknown) {
  return value === undefined || value === null || typeof value === "string";
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

// Rejects payloads stamped too far in the future or older than maxAgeSeconds.
function isFreshIssuedAt(iat: number, nowSeconds: number, maxAgeSeconds: number, toleranceSeconds: number) {
  return (
    Number.isFinite(iat) &&
    iat <= nowSeconds + toleranceSeconds &&
    nowSeconds - iat <= maxAgeSeconds
  );
}

// ---------------------------------------------------------------------------------------------
// v1: shared-secret HMAC headers
// ---------------------------------------------------------------------------------------------

async function importHmacKey(secret: string, usage: "sign" | "verify") {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage],
  );
}

async function signValue(value: string, secret: string) {
  const key = await importHmacKey(secret, "sign");
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return toBase64Url(signature);
}

// crypto.subtle.verify compares in constant time, unlike comparing signature strings.
async function verifyValue(value: string, signature: string, secret: string) {
  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    signatureBytes = fromBase64Url(signature);
  } catch {
    return false;
  }

  const key = await importHmacKey(secret, "verify");
  return crypto.subtle.verify("HMAC", key, signatureBytes, encoder.encode(value));
}

function isV1UserPayload(value: unknown): value is GatewayUserPayload {
  if (!isRecord(value)) {
    return false;
  }

  // v1 never carries service identities, so "service" (or anything unknown) is rejected here.
  return (
    (value.authMethod === undefined ||
      value.authMethod === "session" ||
      value.authMethod === "oauth") &&
    isOptionalNullableString(value.clientId) &&
    (value.scopes === undefined || isStringArray(value.scopes)) &&
    value.version === GATEWAY_AUTH_VERSION &&
    typeof value.email === "string" &&
    isOptionalNullableString(value.name) &&
    isOptionalNullableString(value.image) &&
    typeof value.host === "string" &&
    typeof value.iat === "number" &&
    typeof value.path === "string" &&
    typeof value.tool === "string"
  );
}

export async function createGatewayHeaders(input: {
  auth?: GatewayAuthInfo;
  host: string;
  now?: number;
  path: string;
  secret: string;
  tool: string;
  user: GatewayIdentity;
}) {
  if (input.auth?.method === "service" || input.auth?.callerTool) {
    throw new Error("v1 gateway headers cannot carry service identities. Use createGatewayToken.");
  }

  const payload: GatewayUserPayload = {
    email: input.user.email,
    host: input.host,
    iat: Math.floor((input.now ?? Date.now()) / 1000),
    image: input.user.image ?? null,
    name: input.user.name ?? null,
    path: input.path,
    tool: input.tool,
    version: GATEWAY_AUTH_VERSION,
    ...(input.auth
      ? {
          authMethod: input.auth.method,
          clientId: input.auth.clientId ?? null,
          scopes: [...(input.auth.scopes ?? [])],
        }
      : {}),
  };

  const encodedPayload = encodeJsonBase64Url(payload);
  const signature = await signValue(encodedPayload, input.secret);

  return {
    [GATEWAY_AUTH_PAYLOAD_HEADER]: encodedPayload,
    [GATEWAY_AUTH_SIGNATURE_HEADER]: signature,
  };
}

async function verifyV1Headers(
  headers: HeadersLike,
  input: {
    clockToleranceSeconds: number;
    maxAgeSeconds: number;
    now: number;
    secret: string;
    tool?: string;
  },
): Promise<GatewayUserPayload | null> {
  const encodedPayload = headers.get(GATEWAY_AUTH_PAYLOAD_HEADER);
  const signature = headers.get(GATEWAY_AUTH_SIGNATURE_HEADER);

  if (!encodedPayload || !signature) {
    return null;
  }

  try {
    if (!(await verifyValue(encodedPayload, signature, input.secret))) {
      return null;
    }

    const payload = decodeJsonBase64Url(encodedPayload);

    if (!isV1UserPayload(payload)) {
      return null;
    }

    if (
      !isFreshIssuedAt(
        payload.iat,
        input.now / 1000,
        input.maxAgeSeconds,
        input.clockToleranceSeconds,
      )
    ) {
      return null;
    }

    if (input.tool !== undefined && payload.tool !== input.tool) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------------
// v2: ES256 gateway tokens (gateway side)
// ---------------------------------------------------------------------------------------------

export type GatewayTokenSigningKey = {
  issuer: string;
  kid: string;
  // ECDSA P-256 private key.
  privateKey: CryptoKey;
  ttlSeconds?: number;
};

function randomId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

function buildTokenClaims(input: {
  auth: GatewayAuthInfo;
  host: string;
  iat: number;
  issuer: string;
  path: string;
  tool: string;
  ttlSeconds: number;
  user?: GatewayIdentity;
}) {
  const { auth, user } = input;

  if (!isNonEmptyString(input.issuer) || !isNonEmptyString(input.tool)) {
    throw new Error("Gateway tokens need an issuer and a tool.");
  }

  if (typeof input.host !== "string" || typeof input.path !== "string") {
    throw new Error("Gateway tokens need a host and a path.");
  }

  if (!Number.isFinite(input.ttlSeconds) || input.ttlSeconds <= 0) {
    throw new Error("Gateway token ttlSeconds must be a positive number.");
  }

  if (auth.scopes !== undefined && !isStringArray(auth.scopes)) {
    throw new Error("Gateway token scopes must be strings.");
  }

  const claims: Record<string, unknown> = {
    aud: input.tool,
    authMethod: auth.method,
    exp: input.iat + Math.floor(input.ttlSeconds),
    host: input.host,
    iat: input.iat,
    iss: input.issuer,
    jti: randomId(),
    path: input.path,
  };

  if (auth.method === "service") {
    if (!isNonEmptyString(auth.callerTool)) {
      throw new Error("Service gateway tokens need auth.callerTool.");
    }

    if (user) {
      throw new Error("Service gateway tokens cannot carry a user.");
    }

    claims.callerTool = auth.callerTool;
    claims.scopes = [...(auth.scopes ?? [])];

    if (auth.clientId !== undefined) {
      claims.clientId = auth.clientId;
    }

    return claims;
  }

  if (auth.method !== "session" && auth.method !== "oauth") {
    throw new Error("Unknown gateway auth method.");
  }

  if (!isNonEmptyString(user?.email)) {
    throw new Error("User gateway tokens need user.email.");
  }

  if (auth.callerTool) {
    throw new Error("Only service gateway tokens can carry auth.callerTool.");
  }

  claims.email = user.email;
  claims.name = user.name ?? null;
  claims.image = user.image ?? null;
  claims.clientId = auth.clientId ?? null;
  claims.scopes = [...(auth.scopes ?? [])];

  return claims;
}

export async function createGatewayToken(input: {
  auth: GatewayAuthInfo;
  host: string;
  issuer: string;
  kid: string;
  // Milliseconds since the epoch. Defaults to Date.now().
  now?: number;
  path: string;
  privateKey: CryptoKey;
  tool: string;
  ttlSeconds?: number;
  user?: GatewayIdentity;
}): Promise<string> {
  if (!isNonEmptyString(input.kid)) {
    throw new Error("Gateway tokens need a kid.");
  }

  if (input.privateKey?.type !== "private") {
    throw new Error("Gateway tokens need an ECDSA P-256 private key.");
  }

  const claims = buildTokenClaims({
    auth: input.auth,
    host: input.host,
    iat: Math.floor((input.now ?? Date.now()) / 1000),
    issuer: input.issuer,
    path: input.path,
    tool: input.tool,
    ttlSeconds: input.ttlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS,
    user: input.user,
  });

  const signingInput = `${encodeJsonBase64Url({
    alg: "ES256",
    kid: input.kid,
    typ: GATEWAY_TOKEN_TYPE,
  })}.${encodeJsonBase64Url(claims)}`;

  // WebCrypto ECDSA signatures are raw r||s, which is exactly the JWS ES256 encoding.
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    input.privateKey,
    encoder.encode(signingInput),
  );

  return `${signingInput}.${toBase64Url(signature)}`;
}

// Builds every identity header the gateway forwards to a tool. v1 headers are added only when
// `secret` is given and never for service calls; v2 is added whenever `token` is given.
export async function createGatewayRequestHeaders(input: {
  auth: GatewayAuthInfo;
  host: string;
  now?: number;
  path: string;
  secret?: string;
  token?: GatewayTokenSigningKey;
  tool: string;
  user?: GatewayIdentity;
}): Promise<Record<string, string>> {
  const isService = input.auth.method === "service";
  const headers: Record<string, string> = {};

  if (isService && !input.token) {
    throw new Error("Service calls need a gateway token signing key.");
  }

  if (!input.token && !input.secret) {
    throw new Error("Gateway headers need a secret, a token signing key, or both.");
  }

  if (input.token) {
    headers[GATEWAY_TOKEN_HEADER] = await createGatewayToken({
      auth: input.auth,
      host: input.host,
      issuer: input.token.issuer,
      kid: input.token.kid,
      now: input.now,
      path: input.path,
      privateKey: input.token.privateKey,
      tool: input.tool,
      ttlSeconds: input.token.ttlSeconds,
      user: input.user,
    });
  }

  if (input.secret && !isService) {
    if (!input.user) {
      throw new Error("User gateway headers need a user.");
    }

    Object.assign(
      headers,
      await createGatewayHeaders({
        auth: input.auth,
        host: input.host,
        now: input.now,
        path: input.path,
        secret: input.secret,
        tool: input.tool,
        user: input.user,
      }),
    );
  }

  return headers;
}

// ---------------------------------------------------------------------------------------------
// v2: JWKS lookup and caching (tool side)
// ---------------------------------------------------------------------------------------------

type KeyLookup = Promise<CryptoKey | null>;

type RemoteJwksEntry = {
  fetchedAt: number;
  inFlight: Promise<boolean> | null;
  jwks: GatewayJwks | null;
  keys: Map<string, KeyLookup>;
  lastAttemptAt: number;
};

// Module memory, so keys survive across requests in the same server instance or isolate.
const remoteJwksCache = new Map<string, RemoteJwksEntry>();
const staticJwksCache = new WeakMap<GatewayJwks, Map<string, KeyLookup>>();

function findUsableJwk(jwks: GatewayJwks | null, kid: string) {
  if (!jwks || !Array.isArray(jwks.keys)) {
    return null;
  }

  return (
    jwks.keys.find(
      (key) =>
        isRecord(key) &&
        key.kid === kid &&
        key.kty === "EC" &&
        key.crv === "P-256" &&
        (key.alg === undefined || key.alg === "ES256") &&
        (key.use === undefined || key.use === "sig"),
    ) ?? null
  );
}

async function importVerifyKey(jwk: GatewayJwk) {
  try {
    // Copy only the public members so a stray private "d" is never imported.
    return await crypto.subtle.importKey(
      "jwk",
      { crv: "P-256", kty: "EC", x: jwk.x as string, y: jwk.y as string },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    return null;
  }
}

function lookupKey(cache: Map<string, KeyLookup>, jwks: GatewayJwks | null, kid: string) {
  const cached = cache.get(kid);
  if (cached) {
    return cached;
  }

  const jwk = findUsableJwk(jwks, kid);
  if (!jwk) {
    return null;
  }

  const lookup = importVerifyKey(jwk);
  cache.set(kid, lookup);
  return lookup;
}

async function fetchJwks(url: string, fetchImpl: typeof fetch): Promise<GatewayJwks | null> {
  try {
    const response = await fetchImpl(url, {
      headers: { accept: "application/json" },
      signal:
        typeof AbortSignal !== "undefined" && "timeout" in AbortSignal
          ? AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS)
          : undefined,
    });

    if (!response.ok) {
      return null;
    }

    const body: unknown = await response.json();
    return isRecord(body) && Array.isArray(body.keys) ? (body as GatewayJwks) : null;
  } catch {
    return null;
  }
}

function refreshRemoteJwks(entry: RemoteJwksEntry, url: string, fetchImpl: typeof fetch, now: number) {
  if (entry.inFlight) {
    return entry.inFlight;
  }

  entry.lastAttemptAt = now;
  entry.inFlight = fetchJwks(url, fetchImpl)
    .then((jwks) => {
      if (!jwks) {
        return false;
      }

      entry.jwks = jwks;
      entry.fetchedAt = now;
      entry.keys = new Map();
      return true;
    })
    .finally(() => {
      entry.inFlight = null;
    });

  return entry.inFlight;
}

async function getRemoteKey(url: string, kid: string, fetchImpl: typeof fetch, now: number) {
  let entry = remoteJwksCache.get(url);

  if (!entry) {
    entry = { fetchedAt: 0, inFlight: null, jwks: null, keys: new Map(), lastAttemptAt: 0 };
    remoteJwksCache.set(url, entry);
  }

  const canRefetch = now - entry.lastAttemptAt >= JWKS_REFETCH_INTERVAL_MS;

  if (!entry.jwks) {
    // Nothing cached yet: fetch (deduped across concurrent requests). Fails closed on error.
    await refreshRemoteJwks(entry, url, fetchImpl, now);
  } else if (now - entry.fetchedAt >= JWKS_CACHE_TTL_MS && canRefetch) {
    // Stale cache: refresh so revoked keys drop out. Keep the old keys if the gateway is down.
    await refreshRemoteJwks(entry, url, fetchImpl, now);
  }

  const found = lookupKey(entry.keys, entry.jwks, kid);
  if (found) {
    return found;
  }

  // Unknown kid, probably a key rotation. Refetch at most once per interval per URL.
  if (entry.jwks && now - entry.lastAttemptAt >= JWKS_REFETCH_INTERVAL_MS) {
    await refreshRemoteJwks(entry, url, fetchImpl, now);
    return lookupKey(entry.keys, entry.jwks, kid);
  }

  return null;
}

async function getVerifyKey(
  kid: string,
  input: { fetch?: typeof fetch; jwks?: GatewayJwks; jwksUrl?: string; now: number },
) {
  if (input.jwks) {
    let cache = staticJwksCache.get(input.jwks);
    if (!cache) {
      cache = new Map();
      staticJwksCache.set(input.jwks, cache);
    }

    return lookupKey(cache, input.jwks, kid);
  }

  if (input.jwksUrl) {
    return getRemoteKey(input.jwksUrl, kid, input.fetch ?? fetch, input.now);
  }

  return null;
}

// ---------------------------------------------------------------------------------------------
// v2: token verification (tool side)
// ---------------------------------------------------------------------------------------------

export type GatewayTokenVerifyOptions = {
  clockToleranceSeconds?: number;
  fetch?: typeof fetch;
  issuer?: string;
  jwks?: GatewayJwks;
  // Recommended: "https://<gateway>/.well-known/gateway-jwks.json".
  jwksUrl?: string;
  maxAgeSeconds?: number;
  // Milliseconds since the epoch. Defaults to Date.now().
  now?: number;
  // This tool's slug. Tokens are only accepted when their audience matches it.
  tool: string;
};

function toTokenPayload(claims: Record<string, unknown>): GatewayPayload | null {
  const base = {
    host: claims.host,
    iat: claims.iat,
    path: claims.path,
    tool: claims.aud,
  };

  if (
    typeof base.host !== "string" ||
    typeof base.path !== "string" ||
    typeof base.tool !== "string" ||
    typeof base.iat !== "number" ||
    !isOptionalNullableString(claims.clientId)
  ) {
    return null;
  }

  const clientId = claims.clientId as string | null | undefined;

  if (claims.authMethod === "service") {
    if (
      !isNonEmptyString(claims.callerTool) ||
      !isStringArray(claims.scopes) ||
      claims.email !== undefined
    ) {
      return null;
    }

    return {
      authMethod: "service",
      callerTool: claims.callerTool,
      ...(clientId !== undefined ? { clientId } : {}),
      host: base.host,
      iat: base.iat,
      path: base.path,
      scopes: [...claims.scopes],
      tool: base.tool,
      version: GATEWAY_TOKEN_VERSION,
    };
  }

  if (claims.authMethod !== "session" && claims.authMethod !== "oauth") {
    return null;
  }

  if (
    !isNonEmptyString(claims.email) ||
    !isOptionalNullableString(claims.name) ||
    !isOptionalNullableString(claims.image) ||
    claims.callerTool !== undefined ||
    (claims.scopes !== undefined && !isStringArray(claims.scopes))
  ) {
    return null;
  }

  return {
    authMethod: claims.authMethod,
    clientId: clientId ?? null,
    email: claims.email,
    host: base.host,
    iat: base.iat,
    image: (claims.image as string | null | undefined) ?? null,
    name: (claims.name as string | null | undefined) ?? null,
    path: base.path,
    scopes: [...((claims.scopes as string[] | undefined) ?? [])],
    tool: base.tool,
    version: GATEWAY_TOKEN_VERSION,
  };
}

async function verifyToken(
  token: string,
  input: GatewayTokenVerifyOptions,
): Promise<GatewayPayload | null> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }

  const [encodedHeader, encodedClaims, encodedSignature] = parts;
  const header = decodeJsonBase64Url(encodedHeader);

  // ES256 only: this rejects "none", HMAC algorithms and anything else by construction.
  if (
    !isRecord(header) ||
    header.alg !== "ES256" ||
    header.typ !== GATEWAY_TOKEN_TYPE ||
    !isNonEmptyString(header.kid) ||
    header.crit !== undefined
  ) {
    return null;
  }

  const now = input.now ?? Date.now();
  const key = await getVerifyKey(header.kid, { ...input, now });
  if (!key) {
    return null;
  }

  const signature = fromBase64Url(encodedSignature);
  if (signature.length !== 64) {
    return null;
  }

  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    signature,
    encoder.encode(`${encodedHeader}.${encodedClaims}`),
  );
  if (!valid) {
    return null;
  }

  const claims = decodeJsonBase64Url(encodedClaims);
  if (!isRecord(claims)) {
    return null;
  }

  const nowSeconds = now / 1000;
  const tolerance = input.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS;
  const maxAge = input.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;

  if (
    claims.aud !== input.tool ||
    !isNonEmptyString(claims.iss) ||
    (input.issuer !== undefined && claims.iss !== input.issuer) ||
    !isNonEmptyString(claims.jti) ||
    typeof claims.iat !== "number" ||
    typeof claims.exp !== "number" ||
    !Number.isFinite(claims.exp) ||
    claims.exp < claims.iat ||
    nowSeconds > claims.exp + tolerance ||
    !isFreshIssuedAt(claims.iat, nowSeconds, maxAge, tolerance)
  ) {
    return null;
  }

  return toTokenPayload(claims);
}

function assertTokenOptions(input: { jwks?: GatewayJwks; jwksUrl?: string; tool?: string }) {
  if (!isNonEmptyString(input.tool)) {
    throw new Error("Gateway token verification needs the `tool` slug this app serves.");
  }

  if (!input.jwks && !input.jwksUrl) {
    throw new Error("Gateway token verification needs `jwks` or `jwksUrl`.");
  }
}

// Verifies the v2 gateway token header. Returns null for a missing or invalid token, and
// throws only for configuration bugs (no tool, no key material).
export async function verifyGatewayToken(
  headers: HeadersLike,
  input: GatewayTokenVerifyOptions,
): Promise<GatewayPayload | null> {
  assertTokenOptions(input);

  const token = headers.get(GATEWAY_TOKEN_HEADER);
  if (!token) {
    return null;
  }

  try {
    return await verifyToken(token, input);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------------
// Combined verification
// ---------------------------------------------------------------------------------------------

export type GatewayVerifyOptions = {
  // Service payloads (tool-to-tool calls without a user) are rejected unless this is true.
  allowService?: boolean;
  clockToleranceSeconds?: number;
  fetch?: typeof fetch;
  issuer?: string;
  jwks?: GatewayJwks;
  jwksUrl?: string;
  maxAgeSeconds?: number;
  now?: number;
  // v1 shared secret. Keep it during migration; remove it once the gateway sends v2 tokens.
  secret?: string;
  // This tool's slug. Required with jwks/jwksUrl, optional (but recommended) for v1.
  tool?: string;
};

// When v2 key material is configured and the v2 header is present, only v2 is checked (a
// failed v2 token never falls back to v1). Otherwise v1 is checked when `secret` is given.
export function verifyGatewayHeaders(
  headers: HeadersLike,
  input: GatewayVerifyOptions & { allowService: true },
): Promise<GatewayPayload | null>;
export function verifyGatewayHeaders(
  headers: HeadersLike,
  input: GatewayVerifyOptions & { allowService?: false },
): Promise<GatewayUserPayload | null>;
export function verifyGatewayHeaders(
  headers: HeadersLike,
  input: GatewayVerifyOptions,
): Promise<GatewayPayload | null>;
export async function verifyGatewayHeaders(
  headers: HeadersLike,
  input: GatewayVerifyOptions,
): Promise<GatewayPayload | null> {
  const hasV2Keys = Boolean(input.jwks || input.jwksUrl);

  if (hasV2Keys && !isNonEmptyString(input.tool)) {
    throw new Error("Gateway token verification needs the `tool` slug this app serves.");
  }

  if (!hasV2Keys && !input.secret) {
    throw new Error("Gateway verification needs `secret`, `jwks` or `jwksUrl`.");
  }

  const now = input.now ?? Date.now();
  let payload: GatewayPayload | null = null;

  if (hasV2Keys && headers.get(GATEWAY_TOKEN_HEADER)) {
    payload = await verifyGatewayToken(headers, {
      clockToleranceSeconds: input.clockToleranceSeconds,
      fetch: input.fetch,
      issuer: input.issuer,
      jwks: input.jwks,
      jwksUrl: input.jwksUrl,
      maxAgeSeconds: input.maxAgeSeconds,
      now,
      tool: input.tool as string,
    });
  } else if (input.secret) {
    payload = await verifyV1Headers(headers, {
      clockToleranceSeconds: input.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS,
      maxAgeSeconds: input.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS,
      now,
      secret: input.secret,
      tool: input.tool,
    });
  }

  if (payload?.authMethod === "service" && !input.allowService) {
    return null;
  }

  return payload;
}

export function requireGatewayHeaders(
  headers: HeadersLike,
  input: GatewayVerifyOptions & { allowService: true },
): Promise<GatewayPayload>;
export function requireGatewayHeaders(
  headers: HeadersLike,
  input: GatewayVerifyOptions & { allowService?: false },
): Promise<GatewayUserPayload>;
export function requireGatewayHeaders(
  headers: HeadersLike,
  input: GatewayVerifyOptions,
): Promise<GatewayPayload>;
export async function requireGatewayHeaders(headers: HeadersLike, input: GatewayVerifyOptions) {
  const payload = await verifyGatewayHeaders(headers, input);

  if (!payload) {
    throw new GatewayAuthError("Missing or invalid gateway auth headers.");
  }

  return payload;
}

// For service APIs: accepts only v2 service tokens addressed to this tool. Throws
// GatewayAuthError with reason "unauthenticated" (401) or "forbidden" (403).
export async function requireServiceCaller(
  headers: HeadersLike,
  input: GatewayTokenVerifyOptions & {
    allowedCallers?: string[];
    requiredScopes?: string[];
  },
): Promise<GatewayServicePayload> {
  const payload = await verifyGatewayToken(headers, input);

  if (!payload) {
    throw new GatewayAuthError("Missing or invalid gateway service token.", "unauthenticated");
  }

  if (payload.authMethod !== "service") {
    throw new GatewayAuthError("This endpoint only accepts service callers.", "forbidden");
  }

  if (input.allowedCallers && !input.allowedCallers.includes(payload.callerTool)) {
    throw new GatewayAuthError(`Tool "${payload.callerTool}" may not call this endpoint.`, "forbidden");
  }

  const missing = (input.requiredScopes ?? []).filter((scope) => !payload.scopes.includes(scope));
  if (missing.length > 0) {
    throw new GatewayAuthError(`Missing required scopes: ${missing.join(", ")}.`, "forbidden");
  }

  return payload;
}

// ---------------------------------------------------------------------------------------------
// Caller helper: a tool's backend calling another tool's service API through the gateway
// ---------------------------------------------------------------------------------------------

export type ToolClient = {
  fetch(path: string, init?: RequestInit): Promise<Response>;
  getAccessToken(): Promise<string>;
};

export type ToolClientOptions = {
  fetch?: typeof fetch;
  // e.g. "https://<gateway>".
  gatewayOrigin: string;
  // Returns this deployment's OIDC token, e.g. getVercelOidcToken from @vercel/oidc.
  getOidcToken: () => Promise<string>;
  // Milliseconds since the epoch. Defaults to Date.now.
  now?: () => number;
  scope?: string | string[];
  servicePath?: string;
  targetTool: string;
};

type CachedAccessToken = { expiresAt: number; token: string };

function normalizeGatewayOrigin(value: string) {
  const url = new URL(value);

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("gatewayOrigin must be an http(s) URL.");
  }

  if (url.pathname !== "/" || url.search || url.hash) {
    throw new Error("gatewayOrigin must be an origin without a path, e.g. https://gateway.example.com.");
  }

  return url.origin;
}

function normalizeServicePath(value: string) {
  if (!/^(\/[A-Za-z0-9._~-]+)+\/?$/.test(value) || hasDotSegment(value)) {
    throw new Error('servicePath must be an absolute path such as "/api/service".');
  }

  return value.replace(/\/$/, "");
}

function hasDotSegment(path: string) {
  return path.split("/").some((segment) => /^(\.|%2e){1,2}$/i.test(segment));
}

function assertRelativeServicePath(path: string) {
  if (
    typeof path !== "string" ||
    !path.startsWith("/") ||
    path.startsWith("//") ||
    path.includes("\\") ||
    hasDotSegment(path.split(/[?#]/, 1)[0])
  ) {
    throw new Error('Tool client paths must start with "/" and stay inside the service API.');
  }
}

function isReplayableBody(body: RequestInit["body"]) {
  return !(typeof ReadableStream !== "undefined" && body instanceof ReadableStream);
}

async function readTokenError(response: Response) {
  try {
    const body: unknown = await response.json();

    if (isRecord(body) && typeof body.error === "string") {
      return typeof body.error_description === "string"
        ? `${body.error}: ${body.error_description}`
        : body.error;
    }
  } catch {
    // Fall through to the status-only message.
  }

  return "unknown_error";
}

export function createToolClient(options: ToolClientOptions): ToolClient {
  const origin = normalizeGatewayOrigin(options.gatewayOrigin);

  if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(options.targetTool)) {
    throw new Error("targetTool must be a tool slug.");
  }

  const servicePath = normalizeServicePath(options.servicePath ?? "/api/service");
  const baseUrl = `${origin}/${options.targetTool}${servicePath}`;
  const fetchImpl = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const now = options.now ?? Date.now;
  const scope = Array.isArray(options.scope) ? options.scope.join(" ") : options.scope;

  let cached: CachedAccessToken | null = null;
  let inFlight: Promise<CachedAccessToken> | null = null;

  async function requestAccessToken(): Promise<CachedAccessToken> {
    const assertion = await options.getOidcToken();
    const body = new URLSearchParams({
      client_assertion: assertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      grant_type: "client_credentials",
      resource: baseUrl,
    });

    if (scope) {
      body.set("scope", scope);
    }

    const response = await fetchImpl(`${origin}/oauth/token`, {
      body,
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      method: "POST",
    });

    if (!response.ok) {
      throw new Error(
        `Gateway token request failed (HTTP ${response.status}): ${await readTokenError(response)}.`,
      );
    }

    const json: unknown = await response.json().catch(() => null);

    if (
      !isRecord(json) ||
      !isNonEmptyString(json.access_token) ||
      typeof json.token_type !== "string" ||
      json.token_type.toLowerCase() !== "bearer"
    ) {
      throw new Error("Gateway token response was not a bearer access token.");
    }

    const expiresInSeconds =
      typeof json.expires_in === "number" && json.expires_in > 0 ? json.expires_in : 60;
    // Refresh 30s early, or halfway through very short lifetimes so tokens stay usable.
    const skew = Math.min(ACCESS_TOKEN_REFRESH_SKEW_MS, (expiresInSeconds * 1000) / 2);

    return { expiresAt: now() + expiresInSeconds * 1000 - skew, token: json.access_token };
  }

  async function getAccessToken() {
    if (cached && now() < cached.expiresAt) {
      return cached.token;
    }

    if (!inFlight) {
      inFlight = requestAccessToken()
        .then((result) => {
          cached = result;
          return result;
        })
        .finally(() => {
          inFlight = null;
        });
    }

    return (await inFlight).token;
  }

  async function send(url: string, init: RequestInit | undefined, token: string) {
    const headers = new Headers(init?.headers);
    headers.set("authorization", `Bearer ${token}`);
    return fetchImpl(url, { ...init, headers });
  }

  return {
    async fetch(path, init) {
      assertRelativeServicePath(path);

      const url = `${baseUrl}${path}`;
      const token = await getAccessToken();
      const response = await send(url, init, token);

      if (response.status !== 401 || !isReplayableBody(init?.body)) {
        return response;
      }

      // The token may have been revoked or the gateway's keys rotated: retry once with a new one.
      await response.body?.cancel().catch(() => undefined);

      if (cached?.token === token) {
        cached = null;
      }

      return send(url, init, await getAccessToken());
    },
    getAccessToken,
  };
}
