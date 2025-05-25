import { TokenType } from '../types/index.js';
import type { UserClaims } from '../types/index.js';

/**
 * Determines if a token is a JWT by checking its structure
 * @param token - The token to check
 * @returns true if the token appears to be a JWT
 */
export function isJwtToken(token: string): boolean {
    // JWT tokens have three parts separated by dots
    const parts = token.split('.');
    return parts.length === 3;
}

/**
 * Determines the token type
 * @param token - The token to analyze
 * @returns The token type
 */
export function getTokenType(token: string): TokenType {
    return isJwtToken(token) ? TokenType.JWT : TokenType.OPAQUE;
}

/**
 * Decodes a JWT token payload without verification
 * @param token - The JWT token
 * @returns The decoded payload
 * @throws Error if the token is not a valid JWT
 */
export function decodeJwtPayload(token: string): UserClaims {
    if (!isJwtToken(token)) {
        throw new Error('Token is not a valid JWT');
    }

    const parts = token.split('.');
    const payload = parts[1]!;

    try {
        // Decode base64url
        const decoded = Buffer.from(payload, 'base64url').toString('utf8');
        return JSON.parse(decoded) as UserClaims;
    } catch (error) {
        throw new Error(
            'Failed to decode JWT payload: ' + (error as Error).message,
        );
    }
}

/**
 * Extracts the subject (sub) claim from a JWT token
 * @param token - The JWT token
 * @returns The subject identifier
 * @throws Error if the token is invalid or missing sub claim
 */
export function extractSubFromJwt(token: string): string {
    const payload = decodeJwtPayload(token);

    if (!payload.sub) {
        throw new Error('JWT token is missing sub claim');
    }

    return payload.sub;
}
