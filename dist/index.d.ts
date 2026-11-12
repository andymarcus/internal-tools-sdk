export declare const GATEWAY_AUTH_PAYLOAD_HEADER = "x-meandu-gateway-payload";
export declare const GATEWAY_AUTH_SIGNATURE_HEADER = "x-meandu-gateway-signature";
export declare const GATEWAY_AUTH_VERSION = "v1";
export declare const GATEWAY_TOKEN_HEADER = "x-meandu-gateway-token";
export declare const GATEWAY_TOKEN_VERSION = "v2";
export declare const GATEWAY_TOKEN_TYPE = "gateway+jwt";
export declare const SERVICE_API_PATH_PREFIX = "/api/service";
export type GatewayIdentity = {
    email: string;
    image?: string | null;
    name?: string | null;
};
export type GatewayAuthMethod = "session" | "oauth" | "service";
export type GatewayUserAuthMethod = Exclude<GatewayAuthMethod, "service">;
export type GatewayAuthInfo = {
    callerTool?: string | null;
    clientId?: string | null;
    method: GatewayAuthMethod;
    scopes?: string[];
};
export type GatewayPayloadVersion = typeof GATEWAY_AUTH_VERSION | typeof GATEWAY_TOKEN_VERSION;
export type GatewayUserPayload = GatewayIdentity & {
    authMethod?: GatewayUserAuthMethod;
    clientId?: string | null;
    host: string;
    iat: number;
    path: string;
    scopes?: string[];
    tool: string;
    version: GatewayPayloadVersion;
};
export type GatewayServicePayload = {
    authMethod: "service";
    callerTool: string;
    clientId?: string | null;
    host: string;
    iat: number;
    path: string;
    tool: string;
    version: typeof GATEWAY_TOKEN_VERSION;
};
export type GatewayPayload = GatewayUserPayload | GatewayServicePayload;
export type GatewayJwk = {
    alg?: string;
    crv?: string;
    kid?: string;
    kty?: string;
    use?: string;
    x?: string;
    y?: string;
};
export type GatewayJwks = {
    keys: GatewayJwk[];
};
export type GatewayAuthErrorReason = "unauthenticated" | "forbidden";
export declare class GatewayAuthError extends Error {
    readonly reason: GatewayAuthErrorReason;
    readonly status: 401 | 403;
    constructor(message: string, reason?: GatewayAuthErrorReason);
}
type HeadersLike = Headers | Pick<Headers, "get">;
export declare function createGatewayHeaders(input: {
    auth?: GatewayAuthInfo;
    host: string;
    now?: number;
    path: string;
    secret: string;
    tool: string;
    user: GatewayIdentity;
}): Promise<{
    "x-meandu-gateway-payload": string;
    "x-meandu-gateway-signature": string;
}>;
export type GatewayTokenSigningKey = {
    issuer: string;
    kid: string;
    privateKey: CryptoKey;
    ttlSeconds?: number;
};
export declare function createGatewayToken(input: {
    auth: GatewayAuthInfo;
    host: string;
    issuer: string;
    kid: string;
    now?: number;
    path: string;
    privateKey: CryptoKey;
    tool: string;
    ttlSeconds?: number;
    user?: GatewayIdentity;
}): Promise<string>;
export declare function createGatewayRequestHeaders(input: {
    auth: GatewayAuthInfo;
    host: string;
    now?: number;
    path: string;
    secret?: string;
    token?: GatewayTokenSigningKey;
    tool: string;
    user?: GatewayIdentity;
}): Promise<Record<string, string>>;
export type GatewayTokenVerifyOptions = {
    clockToleranceSeconds?: number;
    fetch?: typeof fetch;
    issuer?: string;
    jwks?: GatewayJwks;
    jwksUrl?: string;
    maxAgeSeconds?: number;
    now?: number;
    tool: string;
};
export declare function verifyGatewayToken(headers: HeadersLike, input: GatewayTokenVerifyOptions): Promise<GatewayPayload | null>;
export type GatewayVerifyOptions = {
    allowService?: boolean;
    clockToleranceSeconds?: number;
    fetch?: typeof fetch;
    issuer?: string;
    jwks?: GatewayJwks;
    jwksUrl?: string;
    maxAgeSeconds?: number;
    now?: number;
    secret?: string;
    tool?: string;
};
export declare function verifyGatewayHeaders(headers: HeadersLike, input: GatewayVerifyOptions & {
    allowService: true;
}): Promise<GatewayPayload | null>;
export declare function verifyGatewayHeaders(headers: HeadersLike, input: GatewayVerifyOptions & {
    allowService?: false;
}): Promise<GatewayUserPayload | null>;
export declare function verifyGatewayHeaders(headers: HeadersLike, input: GatewayVerifyOptions): Promise<GatewayPayload | null>;
export declare function requireGatewayHeaders(headers: HeadersLike, input: GatewayVerifyOptions & {
    allowService: true;
}): Promise<GatewayPayload>;
export declare function requireGatewayHeaders(headers: HeadersLike, input: GatewayVerifyOptions & {
    allowService?: false;
}): Promise<GatewayUserPayload>;
export declare function requireGatewayHeaders(headers: HeadersLike, input: GatewayVerifyOptions): Promise<GatewayPayload>;
export declare function requireServiceCaller(headers: HeadersLike, input: GatewayTokenVerifyOptions & {
    allowedCallers: string[];
}): Promise<GatewayServicePayload>;
export type ToolClient = {
    fetch(path: string, init?: RequestInit): Promise<Response>;
    getAccessToken(): Promise<string>;
};
export type ToolClientOptions = {
    fetch?: typeof fetch;
    gatewayOrigin: string;
    getOidcToken: () => Promise<string>;
    now?: () => number;
    targetTool: string;
};
export declare function createToolClient(options: ToolClientOptions): ToolClient;
export {};
//# sourceMappingURL=index.d.ts.map