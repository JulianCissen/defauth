import * as jose from 'jose';
import { TokenType } from '../types/index.js';

/**
 * Determines if a token is a valid JWT by attempting to decode its header and payload
 * @param token - The token to check
 * @returns True if the token appears to be a valid JWT structure
 */
export const isJwtToken = (token: string): boolean => {
    if (!token || typeof token !== 'string') {
        return false;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
        return false;
    }

    try {
        // Try to decode the header
        const header = jose.decodeProtectedHeader(token);

        // Check for required JWT header fields
        if (!header.alg || typeof header.alg !== 'string') {
            return false;
        }

        // Try to decode the payload
        const payload = jose.decodeJwt(token);

        // Check for basic JWT payload structure
        // A valid JWT should have some standard claims structure
        if (typeof payload !== 'object' || payload === null) {
            return false;
        }

        return true;
    } catch {
        // If decoding fails, it's not a valid JWT
        return false;
    }
};

/**
 * Determines the type of token (JWT or opaque)
 * @param token - The token to analyze
 * @returns TokenType enum value
 */
export const getTokenType = (token: string): TokenType => {
    return isJwtToken(token) ? TokenType.JWT : TokenType.OPAQUE;
};
