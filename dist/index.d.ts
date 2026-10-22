export declare const GATEWAY_AUTH_PAYLOAD_HEADER = "x-meandu-gateway-payload";
export declare const GATEWAY_AUTH_SIGNATURE_HEADER = "x-meandu-gateway-signature";
export declare const GATEWAY_AUTH_VERSION = "v1";
export type GatewayIdentity = {
    email: string;
    image?: string | null;
    name?: string | null;
};
export type GatewayAuthMethod = "session" | "oauth";
export type GatewayAuthInfo = {
    clientId?: string | null;
    method: GatewayAuthMethod;
    scopes?: string[];
};
export type GatewayPayload = GatewayIdentity & {
    authMethod?: GatewayAuthMethod;
    clientId?: string | null;
    host: string;
    iat: number;
    path: string;
    scopes?: string[];
    tool: string;
    version: typeof GATEWAY_AUTH_VERSION;
};
export declare class GatewayAuthError extends Error {
    constructor(message: string);
}
type HeadersLike = Headers | Pick<Headers, "get">;
export declare function createGatewayHeaders(input: {
    auth?: GatewayAuthInfo;
    host: string;
    path: string;
    secret: string;
    tool: string;
    user: GatewayIdentity;
}): Promise<{
    "x-meandu-gateway-payload": string;
    "x-meandu-gateway-signature": string;
}>;
export declare function verifyGatewayHeaders(headers: HeadersLike, input: {
    maxAgeSeconds?: number;
    secret: string;
}): Promise<GatewayPayload | null>;
export declare function requireGatewayHeaders(headers: HeadersLike, input: {
    maxAgeSeconds?: number;
    secret: string;
}): Promise<GatewayPayload>;
export {};
//# sourceMappingURL=index.d.ts.map