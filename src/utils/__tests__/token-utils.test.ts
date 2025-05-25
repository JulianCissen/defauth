import { describe, expect, it } from '@jest/globals';
import { getTokenType, isJwtToken } from '../token-utils.js';
import { TokenType } from '../../types/index.js';

describe('token-utils', () => {
    describe('isJwtToken', () => {
        it('should return true for valid JWT token structure', () => {
            const validJwt =
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
            expect(isJwtToken(validJwt)).toBe(true);
        });

        it('should return true for any string with exactly 3 dot-separated parts', () => {
            expect(isJwtToken('part1.part2.part3')).toBe(true);
            expect(isJwtToken('a.b.c')).toBe(true);
            expect(isJwtToken('header.payload.signature')).toBe(true);
        });

        it('should return false for opaque tokens', () => {
            expect(isJwtToken('opaque-token-12345')).toBe(false);
            expect(isJwtToken('simple-token')).toBe(false);
            expect(isJwtToken('bearer-token-without-dots')).toBe(false);
        });

        it('should return false for tokens with incorrect number of parts', () => {
            expect(isJwtToken('only-one-part')).toBe(false);
            expect(isJwtToken('two.parts')).toBe(false);
            expect(isJwtToken('four.parts.here.extra')).toBe(false);
            expect(isJwtToken('five.parts.here.extra.more')).toBe(false);
        });

        it('should return false for empty or invalid inputs', () => {
            expect(isJwtToken('')).toBe(false);
            expect(isJwtToken('.')).toBe(false);
            expect(isJwtToken('..')).toBe(false);
            expect(isJwtToken('...')).toBe(false);
        });

        it('should handle tokens with empty parts', () => {
            expect(isJwtToken('..')).toBe(false); // 3 empty parts
            expect(isJwtToken('header..signature')).toBe(true); // Empty payload
            expect(isJwtToken('.payload.signature')).toBe(true); // Empty header
            expect(isJwtToken('header.payload.')).toBe(true); // Empty signature
        });

        it('should be case-sensitive', () => {
            const jwt = 'HEADER.PAYLOAD.SIGNATURE';
            expect(isJwtToken(jwt)).toBe(true);
        });
    });

    describe('getTokenType', () => {
        it('should return JWT for valid JWT tokens', () => {
            const validJwt =
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
            expect(getTokenType(validJwt)).toBe(TokenType.JWT);
        });

        it('should return JWT for any three-part token', () => {
            expect(getTokenType('a.b.c')).toBe(TokenType.JWT);
            expect(getTokenType('header.payload.signature')).toBe(
                TokenType.JWT,
            );
        });

        it('should return OPAQUE for non-JWT tokens', () => {
            expect(getTokenType('opaque-token-12345')).toBe(TokenType.OPAQUE);
            expect(getTokenType('simple-token')).toBe(TokenType.OPAQUE);
            expect(getTokenType('bearer-token')).toBe(TokenType.OPAQUE);
        });

        it('should return OPAQUE for tokens with incorrect number of parts', () => {
            expect(getTokenType('one-part')).toBe(TokenType.OPAQUE);
            expect(getTokenType('two.parts')).toBe(TokenType.OPAQUE);
            expect(getTokenType('four.parts.here.extra')).toBe(
                TokenType.OPAQUE,
            );
        });

        it('should return OPAQUE for empty string', () => {
            expect(getTokenType('')).toBe(TokenType.OPAQUE);
        });

        it('should handle various token formats consistently', () => {
            // Common opaque token formats
            expect(getTokenType('ya29.a0ARrdaM-...')).toBe(TokenType.OPAQUE);
            expect(getTokenType('ghp_xxxxxxxxxxxxxxxxxxxx')).toBe(
                TokenType.OPAQUE,
            );
            expect(getTokenType('pk_test_xxxxxxxxxxxxxxxx')).toBe(
                TokenType.OPAQUE,
            );

            // JWT-like but incorrect format
            expect(getTokenType('header.payload')).toBe(TokenType.OPAQUE);
            expect(getTokenType('header.payload.signature.extra')).toBe(
                TokenType.OPAQUE,
            );
        });
    });
});
