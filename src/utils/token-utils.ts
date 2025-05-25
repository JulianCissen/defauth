import { TokenType } from '../types/index.js';

/**
 * Determines if a token is a JWT by checking its structure
 * @param token - The token to check
 * @returns true if the token appears to be a JWT
 */
export function isJwtToken(token: string): boolean {
    // JWT tokens have three parts separated by dots
    const parts = token.split('.');
    // Must have exactly 3 parts, and the token cannot be just dots
    return parts.length === 3 && token.length > 2;
}

/**
 * Determines the token type
 * @param token - The token to analyze
 * @returns The token type
 */
export function getTokenType(token: string): TokenType {
    return isJwtToken(token) ? TokenType.JWT : TokenType.OPAQUE;
}
