import { beforeEach, describe, expect, it, jest } from '@jest/globals';

// Mock jose module for ESM compatibility
jest.unstable_mockModule('jose', () => ({
    decodeProtectedHeader: jest.fn(),
    decodeJwt: jest.fn(),
}));

// Import modules after mocking
const { getTokenType, isJwtToken } = await import('../token-utils.js');
const { TokenType } = await import('../../types/index.js');

// Get the mocked functions for test setup
const jose = await import('jose');
const mockDecodeProtectedHeader =
    jose.decodeProtectedHeader as jest.MockedFunction<
        typeof jose.decodeProtectedHeader
    >;
const mockDecodeJwt = jose.decodeJwt as jest.MockedFunction<
    typeof jose.decodeJwt
>;

describe('token-utils', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('isJwtToken', () => {
        it('should return true for valid JWT token structure', () => {
            // Setup mocks for successful JWT decoding
            mockDecodeProtectedHeader.mockReturnValue({
                alg: 'HS256',
                typ: 'JWT',
            });
            mockDecodeJwt.mockReturnValue({
                sub: '1234567890',
                name: 'John Doe',
                iat: 1516239022,
            });

            const validJwt =
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
            expect(isJwtToken(validJwt)).toBe(true);
        });

        it('should return false for strings with dots that are not valid JWTs', () => {
            // Setup mocks to throw errors for invalid JWT structure
            mockDecodeProtectedHeader.mockImplementation(() => {
                throw new Error('Invalid JWT header');
            });

            expect(isJwtToken('part1.part2.part3')).toBe(false);
            expect(isJwtToken('a.b.c')).toBe(false);
            expect(isJwtToken('header.payload.signature')).toBe(false);
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

        it('should return false for JWT with missing algorithm', () => {
            // Mock header without 'alg' field
            mockDecodeProtectedHeader.mockReturnValue({ typ: 'JWT' });
            mockDecodeJwt.mockReturnValue({ sub: '123' });

            expect(isJwtToken('header.payload.signature')).toBe(false);
        });

        it('should return false for JWT with invalid payload', () => {
            // Mock valid header but invalid payload
            mockDecodeProtectedHeader.mockReturnValue({ alg: 'HS256' });
            mockDecodeJwt.mockImplementation(() => {
                throw new Error('Invalid payload');
            });

            expect(isJwtToken('header.invalidpayload.signature')).toBe(false);
        });
    });

    describe('getTokenType', () => {
        it('should return JWT for valid JWT tokens', () => {
            // Setup mocks for successful JWT decoding
            mockDecodeProtectedHeader.mockReturnValue({
                alg: 'HS256',
                typ: 'JWT',
            });
            mockDecodeJwt.mockReturnValue({ sub: '1234567890' });

            const validJwt =
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
            expect(getTokenType(validJwt)).toBe(TokenType.JWT);
        });

        it('should return OPAQUE for strings with dots that are not valid JWTs', () => {
            // Setup mocks to throw errors for invalid JWT structure
            mockDecodeProtectedHeader.mockImplementation(() => {
                throw new Error('Invalid JWT header');
            });

            expect(getTokenType('a.b.c')).toBe(TokenType.OPAQUE);
            expect(getTokenType('header.payload.signature')).toBe(
                TokenType.OPAQUE,
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
            // Common opaque token formats that might contain dots
            expect(getTokenType('ya29.a0ARrdaM-google-token')).toBe(
                TokenType.OPAQUE,
            );
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
