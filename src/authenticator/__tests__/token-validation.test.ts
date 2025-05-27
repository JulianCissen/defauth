import type { AuthenticatorConfig, UserRecord } from '../../types/index.js';
import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

// Mock external dependencies using ESM mocking
jest.unstable_mockModule('jose', () => ({
    jwtVerify: jest.fn(),
    createRemoteJWKSet: jest.fn(),
    decodeProtectedHeader: jest.fn(),
    decodeJwt: jest.fn(),
}));

jest.unstable_mockModule('openid-client', () => ({
    discovery: jest.fn(),
    tokenIntrospection: jest.fn(),
    fetchUserInfo: jest.fn(),
}));

// Import modules after mocking
const { Authenticator } = await import('../authenticator.js');

// Type alias for the authenticated Authenticator with UserRecord
type UserRecordAuthenticator = InstanceType<typeof Authenticator<UserRecord>>;
const {
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_INTROSPECTION_INACTIVE,
    MOCK_JWT_TOKEN,
    MOCK_OPAQUE_TOKEN,
    MOCK_USERINFO_RESPONSE,
    MOCK_USER_CLAIMS,
    MockLogger,
    MockStorageAdapter,
    createMockConfig,
    createMockJwtVerifyResult,
    createMockOpenidClient,
    waitForAsync,
} = await import('./test-utils.js');

// Get mocked modules
const joseMock = jest.mocked(await import('jose'));
const openidMock = jest.mocked(await import('openid-client'));

describe('Authenticator - Token Validation and Processing', () => {
    let mockStorageAdapter: InstanceType<typeof MockStorageAdapter>;
    let mockLogger: InstanceType<typeof MockLogger>;
    let mockConfig: AuthenticatorConfig<UserRecord>;

    beforeEach(() => {
        jest.clearAllMocks();
        mockStorageAdapter = new MockStorageAdapter();
        mockLogger = new MockLogger();
        mockConfig = createMockConfig({
            storageAdapter: mockStorageAdapter,
            logger: mockLogger,
        });

        // Setup default mocks
        openidMock.discovery.mockResolvedValue(
            createMockOpenidClient() as never,
        );
        joseMock.createRemoteJWKSet.mockReturnValue(jest.fn() as never);
        joseMock.jwtVerify.mockResolvedValue(
            createMockJwtVerifyResult() as never,
        );

        // Setup jose mocks for JWT detection
        joseMock.decodeProtectedHeader.mockReturnValue({
            alg: 'RS256',
            typ: 'JWT',
        } as never);
        joseMock.decodeJwt.mockReturnValue({
            sub: 'user123',
            name: 'Test User',
            email: 'test@example.com',
            iat: 1630000000,
            exp: 9999999999,
            aud: 'test-client-id',
            iss: 'https://mock-oidc-provider.com',
        } as never);

        openidMock.tokenIntrospection.mockResolvedValue(
            MOCK_INTROSPECTION_ACTIVE as never,
        );
        openidMock.fetchUserInfo.mockResolvedValue(
            MOCK_USERINFO_RESPONSE as never,
        );
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('Token Validation', () => {
        let authenticator: UserRecordAuthenticator;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync(); // Wait for initialization
        });

        it('should throw error for empty token', async () => {
            await expect(authenticator.getUser('')).rejects.toThrow(
                'Token is required',
            );
        });

        it('should throw error for null token', async () => {
            await expect(authenticator.getUser(null as any)).rejects.toThrow(
                'Token is required',
            );
        });

        it('should throw error when client not initialized', async () => {
            // Mock a failed initialization
            openidMock.discovery.mockRejectedValue(new Error('Init failed'));

            const failedAuthenticator = new Authenticator(mockConfig);

            // Wait for the async initialization to fail
            await waitForAsync();

            await expect(
                failedAuthenticator.getUser(MOCK_JWT_TOKEN),
            ).rejects.toThrow(
                'Failed to initialize OIDC client: Failed to discover OIDC issuer or create client: Init failed',
            );
        });
    });

    describe('JWT Token Handling', () => {
        let authenticator: UserRecordAuthenticator;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync();
        });

        it('should successfully process valid JWT token', async () => {
            const result = await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(result).toEqual(
                expect.objectContaining({
                    sub: MOCK_USER_CLAIMS.sub,
                    name: expect.any(String),
                    email: expect.any(String),
                }),
            );
            expect(joseMock.jwtVerify).toHaveBeenCalledWith(
                MOCK_JWT_TOKEN,
                expect.any(Function),
                expect.objectContaining({
                    clockTolerance: '1 minute',
                    requiredClaims: ['sub', 'exp'],
                }),
            );
        });

        it('should fallback to introspection when JWT signature verification fails', async () => {
            const verificationError = new Error('Invalid signature');
            joseMock.jwtVerify.mockRejectedValue(verificationError);

            const result = await authenticator.getUser(MOCK_JWT_TOKEN);

            // Should fallback to introspection
            expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
            );
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });

        it('should force introspection when requested', async () => {
            const result = await authenticator.getUser(MOCK_JWT_TOKEN, {
                forceIntrospection: true,
            });

            expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
            );
            expect(joseMock.jwtVerify).not.toHaveBeenCalled();
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });

        it('should fallback to introspection when JWKS URI is missing', async () => {
            const mockClientWithoutJwks = {
                serverMetadata: jest.fn().mockReturnValue({}),
            };
            openidMock.discovery.mockResolvedValue(
                mockClientWithoutJwks as any,
            );

            const authenticator = new Authenticator(mockConfig);
            await waitForAsync();

            const result = await authenticator.getUser(MOCK_JWT_TOKEN);

            // Should fallback to introspection when JWT verification fails
            expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
            );
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });
    });

    describe('Opaque Token Handling', () => {
        let authenticator: UserRecordAuthenticator;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync();
        });

        it('should successfully process valid opaque token', async () => {
            const result = await authenticator.getUser(MOCK_OPAQUE_TOKEN);

            expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_OPAQUE_TOKEN,
            );
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });

        it('should handle inactive opaque token', async () => {
            openidMock.tokenIntrospection.mockResolvedValue(
                MOCK_INTROSPECTION_INACTIVE as any,
            );

            await expect(
                authenticator.getUser(MOCK_OPAQUE_TOKEN),
            ).rejects.toThrow('Token is not active');
        });

        it('should handle introspection failure', async () => {
            const introspectionError = new Error('Introspection failed');
            openidMock.tokenIntrospection.mockRejectedValue(introspectionError);

            await expect(
                authenticator.getUser(MOCK_OPAQUE_TOKEN),
            ).rejects.toThrow('Failed to introspect token');
        });
    });
});
