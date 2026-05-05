const encoder = new TextEncoder();

export const GATEWAY_AUTH_PAYLOAD_HEADER = "x-meandu-gateway-payload";
export const GATEWAY_AUTH_SIGNATURE_HEADER = "x-meandu-gateway-signature";
export const GATEWAY_AUTH_VERSION = "v1";

export type GatewayIdentity = {
  email: string;
  image?: string | null;
  name?: string | null;
};

export type GatewayPayload = GatewayIdentity & {
  host: string;
  iat: number;
  path: string;
  tool: string;
  version: typeof GATEWAY_AUTH_VERSION;
};

export class GatewayAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GatewayAuthError";
  }
}

type HeadersLike = Headers | Pick<Headers, "get">;

function toBase64Url(input: ArrayBuffer | Uint8Array) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const binary = atob(`${normalized}${padding}`);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

async function importSigningKey(secret: string) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function signValue(value: string, secret: string) {
  const key = await importSigningKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return toBase64Url(signature);
}

function parsePayload(encodedPayload: string) {
  const payloadJson = new TextDecoder().decode(fromBase64Url(encodedPayload));
  return JSON.parse(payloadJson) as GatewayPayload;
}

function isGatewayPayload(value: unknown): value is GatewayPayload {
  if (!value || typeof value !== "object") {
    return false;
  }

  const candidate = value as Record<string, unknown>;

  return (
    candidate.version === GATEWAY_AUTH_VERSION &&
    typeof candidate.email === "string" &&
    typeof candidate.host === "string" &&
    typeof candidate.iat === "number" &&
    typeof candidate.path === "string" &&
    typeof candidate.tool === "string"
  );
}

export async function createGatewayHeaders(input: {
  host: string;
  path: string;
  secret: string;
  tool: string;
  user: GatewayIdentity;
}) {
  const payload: GatewayPayload = {
    email: input.user.email,
    host: input.host,
    iat: Math.floor(Date.now() / 1000),
    image: input.user.image ?? null,
    name: input.user.name ?? null,
    path: input.path,
    tool: input.tool,
    version: GATEWAY_AUTH_VERSION,
  };

  const encodedPayload = toBase64Url(encoder.encode(JSON.stringify(payload)));
  const signature = await signValue(encodedPayload, input.secret);

  return {
    [GATEWAY_AUTH_PAYLOAD_HEADER]: encodedPayload,
    [GATEWAY_AUTH_SIGNATURE_HEADER]: signature,
  };
}

export async function verifyGatewayHeaders(
  headers: HeadersLike,
  input: {
    maxAgeSeconds?: number;
    secret: string;
  },
) {
  const encodedPayload = headers.get(GATEWAY_AUTH_PAYLOAD_HEADER);
  const signature = headers.get(GATEWAY_AUTH_SIGNATURE_HEADER);

  if (!encodedPayload || !signature) {
    return null;
  }

  const expectedSignature = await signValue(encodedPayload, input.secret);

  if (signature !== expectedSignature) {
    return null;
  }

  try {
    const payload = parsePayload(encodedPayload);

    if (!isGatewayPayload(payload)) {
      return null;
    }

    const maxAgeSeconds = input.maxAgeSeconds ?? 60;
    if (Date.now() / 1000 - payload.iat > maxAgeSeconds) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export async function requireGatewayHeaders(
  headers: HeadersLike,
  input: {
    maxAgeSeconds?: number;
    secret: string;
  },
) {
  const payload = await verifyGatewayHeaders(headers, input);

  if (!payload) {
    throw new GatewayAuthError("Missing or invalid gateway auth headers.");
  }

  return payload;
}
