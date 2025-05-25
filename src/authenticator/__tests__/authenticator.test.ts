import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

import type { AuthenticatorConfig } from '../../types/index.js';

// Mock external dependencies using ESM mocking
jest.unstable_mockModule('jose', () => ({
    jwtVerify: jest.fn(),
    createRemoteJWKSet: jest.fn(),
}));

jest.unstable_mockModule('openid-client', () => ({
    discovery: jest.fn(),
    tokenIntrospection: jest.fn(),
    fetchUserInfo: jest.fn(),
}));

// Import modules after mocking
const { Authenticator } = await import('../authenticator.js');
const { InMemoryStorageAdapter } = await import('../../storage/index.js');
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

describe('Authenticator', () => {
    let mockStorageAdapter: InstanceType<typeof MockStorageAdapter>;
    let mockLogger: InstanceType<typeof MockLogger>;
    let mockConfig: AuthenticatorConfig;

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

    describe('Constructor and Initialization', () => {
        it('should create authenticator with default configuration', async () => {
            const config = createMockConfig();
            const authenticator = new Authenticator(config);

            // Wait for async initialization
            await waitForAsync();

            // Verify authenticator was created successfully
            expect(authenticator).toBeDefined();
            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
            );
        });

        it('should use provided storage adapter', () => {
            const customAdapter = new InMemoryStorageAdapter();
            const config = createMockConfig({ storageAdapter: customAdapter });

            new Authenticator(config);

            // The authenticator should use the provided adapter
            expect(config.storageAdapter).toBe(customAdapter);
        });

        it('should handle OIDC discovery failure', async () => {
            const discoveryError = new Error('Discovery failed');
            openidMock.discovery.mockRejectedValue(discoveryError);

            const authenticator = new Authenticator(mockConfig);
            
            // Wait for initialization to complete (or fail)
            await waitForAsync();
            
            // The authenticator should throw the specific initialization error
            await expect(authenticator.getUser(MOCK_JWT_TOKEN)).rejects.toThrow(
                'Failed to initialize OIDC client: Failed to discover OIDC issuer or create client: Discovery failed',
            );
        });
    });

    describe('Token Validation', () => {
        let authenticator: InstanceType<typeof Authenticator>;

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
            ).rejects.toThrow('Failed to initialize OIDC client: Failed to discover OIDC issuer or create client: Init failed');
        });
    });

    describe('JWT Token Handling', () => {
        let authenticator: InstanceType<typeof Authenticator>;

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
            );
        });

        it('should handle JWT signature verification failure', async () => {
            const verificationError = new Error('Invalid signature');
            joseMock.jwtVerify.mockRejectedValue(verificationError);

            await expect(authenticator.getUser(MOCK_JWT_TOKEN)).rejects.toThrow(
                'Failed to process JWT token',
            );
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

        it('should handle missing JWKS URI', async () => {
            const mockClientWithoutJwks = {
                serverMetadata: jest.fn().mockReturnValue({}),
            };
            openidMock.discovery.mockResolvedValue(
                mockClientWithoutJwks as any,
            );

            const authenticator = new Authenticator(mockConfig);
            await waitForAsync();

            await expect(authenticator.getUser(MOCK_JWT_TOKEN)).rejects.toThrow(
                'No JWKS URI found in server metadata',
            );
        });
    });

    describe('Opaque Token Handling', () => {
        let authenticator: InstanceType<typeof Authenticator>;

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

    describe('UserInfo Integration', () => {
        let authenticator: InstanceType<typeof Authenticator>;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync();
        });

        it('should fetch UserInfo for new users', async () => {
            const result = await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(openidMock.fetchUserInfo).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
                MOCK_USER_CLAIMS.sub,
            );
            expect(result['name']).toBe(MOCK_USERINFO_RESPONSE.name);
            expect(result['email']).toBe(MOCK_USERINFO_RESPONSE.email);
        });

        it('should handle UserInfo fetch failure gracefully', async () => {
            const userInfoError = new Error('UserInfo failed');
            openidMock.fetchUserInfo.mockRejectedValue(userInfoError);

            const result = await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
            expect(mockLogger.getLogsForLevel('warn')).toHaveLength(1);
            const warningLog = mockLogger.getLogsForLevel('warn')[0];
            if (warningLog) {
                expect(warningLog.message).toContain(
                    'Failed to fetch UserInfo',
                );
            }
        });

        it('should throw on UserInfo failure when configured', async () => {
            const config = createMockConfig({
                storageAdapter: mockStorageAdapter,
                logger: mockLogger,
                throwOnUserInfoFailure: true,
            });

            const userInfoError = new Error('UserInfo failed');
            openidMock.fetchUserInfo.mockRejectedValue(userInfoError);

            const authenticator = new Authenticator(config);
            await waitForAsync();

            await expect(authenticator.getUser(MOCK_JWT_TOKEN)).rejects.toThrow(
                'Failed to fetch UserInfo',
            );
        });
    });

    describe('Storage Integration', () => {
        let authenticator: InstanceType<typeof Authenticator>;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync();
        });

        it('should store user data after successful processing', async () => {
            await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(mockStorageAdapter.storeUserCalls).toHaveLength(1);
            const storedUser = mockStorageAdapter.storeUserCalls[0];
            if (storedUser) {
                expect(storedUser.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(storedUser).toHaveProperty('lastUserInfoRefresh');
            }
        });

        it('should retrieve existing user data from storage', async () => {
            await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(mockStorageAdapter.findUserCalls).toContain(
                MOCK_USER_CLAIMS.sub,
            );
        });

        it('should update timestamps correctly for JWT tokens', async () => {
            const startTime = Date.now();

            await authenticator.getUser(MOCK_JWT_TOKEN);

            const storedUser = mockStorageAdapter.storeUserCalls[0];
            if (storedUser) {
                expect(storedUser.lastUserInfoRefresh).toBeGreaterThanOrEqual(
                    startTime,
                );
                expect(storedUser.lastIntrospection).toBeUndefined();
            }
        });

        it('should update timestamps correctly for opaque tokens', async () => {
            const startTime = Date.now();

            await authenticator.getUser(MOCK_OPAQUE_TOKEN);

            const storedUser = mockStorageAdapter.storeUserCalls[0];
            if (storedUser) {
                expect(storedUser.lastUserInfoRefresh).toBeGreaterThanOrEqual(
                    startTime,
                );
                expect(storedUser.lastIntrospection).toBeGreaterThanOrEqual(
                    startTime,
                );
            }
        });
    });

    describe('Error Handling', () => {
        let authenticator: InstanceType<typeof Authenticator>;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync();
        });

        it('should handle malformed JWT payload', async () => {
            joseMock.jwtVerify.mockResolvedValue({
                payload: { invalid: 'payload' }, // Missing 'sub'
                protectedHeader: { alg: 'RS256', typ: 'JWT' },
            } as any);

            await expect(
                authenticator.getUser(MOCK_JWT_TOKEN),
            ).rejects.toThrow();
        });

        it('should handle storage adapter failures', async () => {
            const storageError = new Error('Storage failed');
            jest.spyOn(mockStorageAdapter, 'findUser').mockRejectedValue(
                storageError,
            );

            await expect(authenticator.getUser(MOCK_JWT_TOKEN)).rejects.toThrow(
                'Storage failed',
            );
        });

        it('should handle network failures gracefully', async () => {
            const networkError = new Error('Network error');
            openidMock.fetchUserInfo.mockRejectedValue(networkError);

            // Should not throw when throwOnUserInfoFailure is false (default)
            const result = await authenticator.getUser(MOCK_JWT_TOKEN);
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });
    });

    describe('Cache Management', () => {
        it('should clear cache when using InMemoryStorageAdapter', async () => {
            const inMemoryConfig = createMockConfig({
                storageAdapter: new InMemoryStorageAdapter(),
            });
            const inMemoryAuthenticator = new Authenticator(inMemoryConfig);
            await waitForAsync();

            // Store some data
            await inMemoryAuthenticator.getUser(MOCK_JWT_TOKEN);

            // Clear cache
            await expect(
                inMemoryAuthenticator.clearCache(),
            ).resolves.not.toThrow();
        });
    });

    describe('Edge Cases', () => {
        let authenticator: InstanceType<typeof Authenticator>;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync();
        });

        it('should handle tokens with empty claims', async () => {
            joseMock.jwtVerify.mockResolvedValue({
                payload: { sub: 'user123' }, // Minimal payload
                protectedHeader: { alg: 'RS256', typ: 'JWT' },
            } as any);

            openidMock.fetchUserInfo.mockResolvedValue({
                sub: 'user123',
            } as any);

            const result = await authenticator.getUser(MOCK_JWT_TOKEN);
            expect(result.sub).toBe('user123');
        });

        it('should handle very long tokens', async () => {
            const longToken =
                'a'.repeat(1000) +
                '.' +
                'b'.repeat(1000) +
                '.' +
                'c'.repeat(1000);

            await expect(
                authenticator.getUser(longToken),
            ).resolves.toBeDefined();
        });

        it('should preserve claim types correctly', async () => {
            const complexClaims = {
                sub: 'user123',
                age: 25,
                active: true,
                roles: ['admin', 'user'],
                metadata: {
                    nested: 'value',
                    number: 42,
                },
            };

            joseMock.jwtVerify.mockResolvedValue({
                payload: complexClaims,
                protectedHeader: { alg: 'RS256', typ: 'JWT' },
            } as any);

            const result = await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(result['age']).toBe(25);
            expect(result['active']).toBe(true);
            expect(Array.isArray(result['roles'])).toBe(true);
            expect(result['roles']).toEqual(['admin', 'user']);
            expect(typeof result['metadata']).toBe('object');
        });
    });
});
