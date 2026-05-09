import type { IntrospectionResponse } from 'oauth4webapi';
import { TokenValidationError } from '../types/index.js';
import type { UserClaims } from '../types/index.js';

export const JWT_METADATA_CLAIMS = [
    'client_id',
    'scope',
    'token_type',
    'nbf',
    'jti',
] as const;

export const INTROSPECTION_METADATA_CLAIMS = [
    'active',
    'client_id',
    'scope',
    'token_type',
    'nbf',
    'jti',
] as const;

/**
 * Extracts user claims from a payload, filtering out metadata claims and undefined values.
 * @param payload - Raw payload object from a JWT or introspection response
 * @param metadataClaims - Claim keys to exclude from the result
 * @returns Validated user claims object with `sub` guaranteed present
 */
export function extractUserClaims(
    payload: Record<string, unknown>,
    metadataClaims: string[] | Readonly<string[]> = [],
): UserClaims {
    const sub = (payload['sub'] as string) || '';
    if (!sub) {
        throw new TokenValidationError('Payload missing required "sub" claim');
    }

    const userClaims: UserClaims = { sub };

    for (const [key, value] of Object.entries(payload)) {
        if (
            key !== 'sub' &&
            !metadataClaims.includes(key) &&
            value !== undefined
        ) {
            userClaims[key] = value;
        }
    }

    return userClaims;
}

/**
 * Extracts user-facing claims from a JWT payload, stripping JWT-specific metadata fields.
 * @param payload - Claims from a verified JWT
 * @returns User claims with JWT metadata fields removed
 */
export function extractFromJwt(payload: UserClaims): UserClaims {
    return extractUserClaims(payload, JWT_METADATA_CLAIMS);
}

/**
 * Extracts user-facing claims from a token introspection response, stripping introspection metadata fields.
 * @param response - Response from the token introspection endpoint
 * @returns User claims with introspection metadata fields removed
 */
export function extractFromIntrospection(
    response: IntrospectionResponse,
): UserClaims {
    return extractUserClaims(response, INTROSPECTION_METADATA_CLAIMS);
}

/**
 * Merges two claims objects, with `priorityClaims` overriding any overlapping keys from `baseClaims`.
 * @param baseClaims - Base set of user claims (e.g. from JWT payload)
 * @param priorityClaims - Claims that take precedence (e.g. from UserInfo endpoint)
 * @returns Merged claims object with priority claims winning on conflicts
 */
export function combineClaimsWithPriority(
    baseClaims: UserClaims,
    priorityClaims: UserClaims,
): UserClaims {
    const combinedClaims: UserClaims = { sub: baseClaims.sub };

    for (const [key, value] of Object.entries(baseClaims)) {
        if (key !== 'sub' && value !== undefined) {
            combinedClaims[key] = value;
        }
    }

    for (const [key, value] of Object.entries(priorityClaims)) {
        if (key !== 'sub' && value !== undefined) {
            combinedClaims[key] = value;
        }
    }

    return combinedClaims;
}

/**
 * Throws a `TokenValidationError` if the introspection result indicates the token is inactive.
 * @param result - Introspection response to check
 */
export function validateIntrospectionResult(
    result: IntrospectionResponse,
): void {
    if (!result.active) {
        throw new TokenValidationError('Token is not active');
    }
}
