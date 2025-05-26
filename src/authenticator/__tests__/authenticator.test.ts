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
    MOCK_JWT_PAYLOAD,
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
            ).rejects.toThrow(
                'Failed to initialize OIDC client: Failed to discover OIDC issuer or create client: Init failed',
            );
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

            expect(
                mockStorageAdapter.findUserCalls.some(
                    (call) => call.sub === MOCK_USER_CLAIMS.sub,
                ),
            ).toBe(true);
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

    describe('Error Handling', () => {
        let authenticator: InstanceType<typeof Authenticator>;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync();
        });

        describe('General Error Handling', () => {
            it('should handle storage adapter failures', async () => {
                const storageError = new Error('Storage failed');
                jest.spyOn(mockStorageAdapter, 'findUser').mockRejectedValue(
                    storageError,
                );

                await expect(
                    authenticator.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('Storage failed');
            });

            it('should handle network failures gracefully', async () => {
                const networkError = new Error('Network error');
                openidMock.fetchUserInfo.mockRejectedValue(networkError);

                // Should not throw when throwOnUserInfoFailure is false (default)
                const result = await authenticator.getUser(MOCK_JWT_TOKEN);
                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
            });
        });

        describe('Client Initialization Errors', () => {
            it('should throw error when client config missing during JWT verification', async () => {
                // Create authenticator that will have no clientConfig
                const brokenAuthenticator = new Authenticator(mockConfig);
                // Access private property to force the condition
                (brokenAuthenticator as any).clientConfig = undefined;
                (brokenAuthenticator as any).isInitialized = true; // bypass initialization check

                await expect(
                    brokenAuthenticator.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('OIDC client is not initialized yet');
            });

            it('should throw error when client config missing during token introspection', async () => {
                // Create authenticator and force missing clientConfig during introspection
                const brokenAuthenticator = new Authenticator(mockConfig);
                (brokenAuthenticator as any).clientConfig = undefined;
                (brokenAuthenticator as any).isInitialized = true;

                await expect(
                    brokenAuthenticator.getUser(MOCK_OPAQUE_TOKEN),
                ).rejects.toThrow('OIDC client is not initialized yet');
            });

            it('should throw error when client config missing during UserInfo fetch', async () => {
                // Set up scenario where UserInfo refresh is needed but clientConfig is missing
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'existing user',
                    lastUserInfoRefresh: Date.now() - 2 * 60 * 60 * 1000, // 2 hours ago
                };
                mockStorageAdapter.setUser(existingUser);

                const brokenAuthenticator = new Authenticator(mockConfig);
                await waitForAsync();

                // Force clientConfig to be undefined after initialization
                (brokenAuthenticator as any).clientConfig = undefined;

                await expect(
                    brokenAuthenticator.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('OIDC client is not initialized yet');
            });

            it('should throw error when initial discovery fails for token introspection', async () => {
                // Mock discovery to fail so client config won't be set
                openidMock.discovery.mockRejectedValue(
                    new Error('Discovery failed'),
                );

                const authenticator = new Authenticator(mockConfig);
                await waitForAsync(); // Let initialization fail

                // Try to get user with opaque token (which requires introspection)
                await expect(
                    authenticator.getUser(MOCK_OPAQUE_TOKEN),
                ).rejects.toThrow('Failed to initialize OIDC client');
            });

            it('should throw error when initial discovery fails for UserInfo fetch', async () => {
                // Mock discovery to fail so client config won't be set
                openidMock.discovery.mockRejectedValue(
                    new Error('Discovery failed'),
                );

                const authenticator = new Authenticator(mockConfig);
                await waitForAsync(); // Let initialization fail

                // Set up a user that needs UserInfo refresh
                const staleUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Stale User',
                    lastUserInfoRefresh: Date.now() - 25 * 60 * 60 * 1000, // 25 hours ago, beyond refresh threshold
                };
                mockStorageAdapter.setUser(staleUser);

                // Mock JWT verification to bypass token validation
                joseMock.jwtVerify.mockResolvedValue(
                    createMockJwtVerifyResult() as never,
                );

                // Attempt to get user - this should trigger UserInfo refresh attempt
                await expect(
                    authenticator.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('Failed to initialize OIDC client');
            });

            it('should log warning when UserInfo endpoint is missing from server metadata', async () => {
                const mockClientNoUserInfo = {
                    serverMetadata: jest.fn().mockReturnValue({
                        jwks_uri: 'https://example.com/.well-known/jwks.json',
                        // No userinfo_endpoint
                    }),
                };
                openidMock.discovery.mockResolvedValue(
                    mockClientNoUserInfo as any,
                );

                const noUserInfoAuth = new Authenticator(mockConfig);
                await waitForAsync();

                // Force UserInfo refresh by having old timestamp
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    lastUserInfoRefresh: Date.now() - 2 * 60 * 60 * 1000,
                };
                mockStorageAdapter.setUser(existingUser);

                // Should handle gracefully by default (throwOnUserInfoFailure: false)
                const result = await noUserInfoAuth.getUser(MOCK_JWT_TOKEN);

                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(mockLogger.getLogsForLevel('warn')).toHaveLength(1);
                const warningLog = mockLogger.getLogsForLevel('warn')[0];
                if (warningLog) {
                    expect(warningLog.message).toContain(
                        'Failed to fetch UserInfo: Failed to fetch user info: No UserInfo endpoint found in server metadata',
                    );
                }
            });

            it('should throw error when UserInfo endpoint is missing and throwOnUserInfoFailure is enabled', async () => {
                const throwConfig = createMockConfig({
                    storageAdapter: mockStorageAdapter,
                    logger: mockLogger,
                    throwOnUserInfoFailure: true,
                });

                const mockClientNoUserInfo = {
                    serverMetadata: jest.fn().mockReturnValue({
                        jwks_uri: 'https://example.com/.well-known/jwks.json',
                        // No userinfo_endpoint
                    }),
                };
                openidMock.discovery.mockResolvedValue(
                    mockClientNoUserInfo as any,
                );

                const noUserInfoAuth = new Authenticator(throwConfig);
                await waitForAsync();

                // Force UserInfo refresh by having old timestamp
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    lastUserInfoRefresh: Date.now() - 2 * 60 * 60 * 1000,
                };
                mockStorageAdapter.setUser(existingUser);

                await expect(
                    noUserInfoAuth.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow(
                    'Failed to fetch UserInfo: Failed to fetch user info: No UserInfo endpoint found in server metadata',
                );
            });
        });

        describe('Missing Sub Claim Validation', () => {
            it('should reject JWT tokens with missing sub claim', async () => {
                joseMock.jwtVerify.mockResolvedValue({
                    payload: { name: 'John Doe' }, // Missing 'sub' claim
                    protectedHeader: { alg: 'RS256', typ: 'JWT' },
                } as any);

                await expect(
                    authenticator.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('Failed to process JWT token');
            });

            it('should reject JWT tokens with empty sub claim', async () => {
                joseMock.jwtVerify.mockResolvedValue({
                    payload: { sub: '', name: 'John Doe' }, // Empty 'sub' claim
                    protectedHeader: { alg: 'RS256', typ: 'JWT' },
                } as any);

                await expect(
                    authenticator.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('Payload missing required "sub" claim');
            });

            it('should reject introspection responses with missing sub claim', async () => {
                openidMock.tokenIntrospection.mockResolvedValue({
                    active: true,
                    client_id: 'test-client',
                    // Missing 'sub' claim
                } as any);

                await expect(
                    authenticator.getUser(MOCK_OPAQUE_TOKEN),
                ).rejects.toThrow('Payload missing required "sub" claim');
            });
        });

        describe('UserInfo Endpoint Failures', () => {
            it('should continue gracefully when UserInfo fails but existing user data is available', async () => {
                // Set up existing user record
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Existing User',
                    email: 'existing@example.com',
                    lastUserInfoRefresh: Date.now() - 2 * 60 * 60 * 1000, // Force refresh
                };
                mockStorageAdapter.setUser(existingUser);

                // Mock UserInfo failure
                const userInfoError = new Error('UserInfo endpoint failed');
                openidMock.fetchUserInfo.mockRejectedValue(userInfoError);

                const result = await authenticator.getUser(MOCK_JWT_TOKEN);

                // Should combine existing user record with new token claims
                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
                // The result should have the token claims (from JWT), not the existing user claims
                // because combineClaimsWithPriority prioritizes the second parameter (userClaims from token)
                expect(result['name']).toBe(MOCK_USER_CLAIMS['name']); // From token claims
                expect(mockLogger.getLogsForLevel('warn')).toHaveLength(1);

                // Verify combineClaimsWithPriority was called
                expect(mockStorageAdapter.storeUserCalls).toHaveLength(1);
                const storedUser = mockStorageAdapter.storeUserCalls[0];
                expect(storedUser?.['name']).toBe(MOCK_USER_CLAIMS['name']);
            });

            it('should throw error when UserInfo fails and throwOnUserInfoFailure is enabled', async () => {
                const throwConfig = createMockConfig({
                    storageAdapter: mockStorageAdapter,
                    logger: mockLogger,
                    throwOnUserInfoFailure: true,
                });

                const throwAuth = new Authenticator(throwConfig);
                await waitForAsync();

                // Set up existing user record
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Existing User',
                    lastUserInfoRefresh: Date.now() - 2 * 60 * 60 * 1000,
                };
                mockStorageAdapter.setUser(existingUser);

                // Mock UserInfo failure
                openidMock.fetchUserInfo.mockRejectedValue(
                    new Error('UserInfo failed'),
                );

                await expect(throwAuth.getUser(MOCK_JWT_TOKEN)).rejects.toThrow(
                    'Failed to fetch UserInfo: Failed to fetch user info: UserInfo failed',
                );
            });
        });

        describe('UserInfo Refresh Conditions', () => {
            it('should refresh UserInfo when user record has no refresh timestamp', async () => {
                const userWithoutTimestamp = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'User',
                    // Missing lastUserInfoRefresh
                };
                mockStorageAdapter.setUser(userWithoutTimestamp);

                const result = await authenticator.getUser(MOCK_JWT_TOKEN);

                expect(openidMock.fetchUserInfo).toHaveBeenCalled();
                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
            });

            it('should refresh UserInfo when custom refresh condition returns true', async () => {
                // Create config with custom refresh condition that always returns true
                const alwaysRefreshConfig = createMockConfig({
                    storageAdapter: mockStorageAdapter,
                    logger: mockLogger,
                    userInfoRefreshCondition: () => true,
                });

                const alwaysRefreshAuth = new Authenticator(
                    alwaysRefreshConfig,
                );
                await waitForAsync();

                const recentUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Recent User',
                    lastUserInfoRefresh: Date.now(), // Very recent
                };
                mockStorageAdapter.setUser(recentUser);

                const result = await alwaysRefreshAuth.getUser(MOCK_JWT_TOKEN);

                expect(openidMock.fetchUserInfo).toHaveBeenCalled();
                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
            });

            it('should skip UserInfo refresh when refresh is not needed', async () => {
                const authenticator = new Authenticator(mockConfig);
                await waitForAsync(); // Wait for initialization

                // Set up a user that does NOT need UserInfo refresh (recent refresh)
                const freshUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Fresh User',
                    email: 'fresh@example.com',
                    lastUserInfoRefresh: Date.now() - 1 * 60 * 60 * 1000, // 1 hour ago, within threshold
                    lastIntrospection: Date.now() - 30 * 60 * 1000, // 30 minutes ago
                };
                mockStorageAdapter.setUser(freshUser);

                // Mock JWT verification to return claims that will get combined with existing user
                const tokenClaims = {
                    ...MOCK_JWT_PAYLOAD,
                    name: 'Updated Test User', // Different from stored user
                };
                joseMock.jwtVerify.mockResolvedValue(
                    createMockJwtVerifyResult(tokenClaims) as never,
                );

                const result = await authenticator.getUser(MOCK_JWT_TOKEN);

                // Should use the path where UserInfo refresh is NOT needed
                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
                // Token claims take priority over stored user claims in combineClaimsWithPriority
                expect(result['name']).toBe('Updated Test User'); // Should use token name (priority)

                // Verify user was stored
                const storedUser = mockStorageAdapter.getStoredUser(
                    MOCK_USER_CLAIMS.sub,
                );
                expect(storedUser?.sub).toBe(MOCK_USER_CLAIMS.sub);
            });

            it('should preserve timestamps when UserInfo refresh is not needed', async () => {
                const authenticator = new Authenticator(mockConfig);
                await waitForAsync(); // Wait for initialization

                // Set up a user that does NOT need UserInfo refresh due to very recent refresh
                const recentUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Existing User',
                    email: 'existing@example.com',
                    lastUserInfoRefresh: Date.now() - 30 * 1000, // 30 seconds ago (very recent)
                    lastIntrospection: Date.now() - 30 * 1000, // 30 seconds ago
                };
                mockStorageAdapter.setUser(recentUser);

                // Clear any previous fetchUserInfo calls and mock JWT verification
                openidMock.fetchUserInfo.mockClear();
                joseMock.jwtVerify.mockResolvedValue(
                    createMockJwtVerifyResult() as never,
                );

                const result = await authenticator.getUser(MOCK_JWT_TOKEN);

                // Should use the path where UserInfo refresh is NOT needed (the "else" path)
                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(openidMock.fetchUserInfo).not.toHaveBeenCalled(); // UserInfo should not be fetched

                // Verify user was stored
                const storedUser = mockStorageAdapter.getStoredUser(
                    MOCK_USER_CLAIMS.sub,
                );
                expect(storedUser?.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(storedUser?.lastUserInfoRefresh).toBe(
                    recentUser.lastUserInfoRefresh,
                ); // Should preserve existing timestamp
            });
        });

        describe('Claims Merging', () => {
            it('should merge user data from multiple sources with correct priority', async () => {
                // Set up existing user with different data
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Old Name',
                    email: 'old@example.com',
                    role: 'user',
                    lastUserInfoRefresh: Date.now() - 2 * 60 * 60 * 1000,
                };
                mockStorageAdapter.setUser(existingUser);

                // Mock UserInfo with updated data
                openidMock.fetchUserInfo.mockResolvedValue({
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Updated Name',
                    email: 'updated@example.com',
                    department: 'Engineering',
                } as any);

                const result = await authenticator.getUser(MOCK_JWT_TOKEN);

                // Should have priority claims (UserInfo) override base claims (existing user)
                expect(result['name']).toBe('Updated Name'); // From UserInfo
                expect(result['email']).toBe('updated@example.com'); // From UserInfo
                expect(result['department']).toBe('Engineering'); // New from UserInfo
                // The role from existing user is not preserved because UserInfo overrides token claims completely
                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
            });

            it('should create new user when no existing record is found', async () => {
                // Ensure no existing user
                mockStorageAdapter.clear();

                const result = await authenticator.getUser(MOCK_JWT_TOKEN);

                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(mockStorageAdapter.storeUserCalls).toHaveLength(1);
            });
        });

        describe('Initialization Edge Cases', () => {
            it('should reject requests when OIDC client is not initialized', async () => {
                const uninitializedAuth = new Authenticator(mockConfig);
                // Don't wait for initialization

                await expect(
                    uninitializedAuth.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('OIDC client is not initialized yet');
            });

            it('should reject requests when client is in partially initialized state', async () => {
                const partialAuth = new Authenticator(mockConfig);
                // Force partial initialization state
                (partialAuth as any).isInitialized = true;
                (partialAuth as any).clientConfig = null;

                await expect(
                    partialAuth.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('OIDC client is not initialized yet');
            });

            it('should continue with token claims when UserInfo fails for opaque tokens', async () => {
                // Ensure no existing user
                mockStorageAdapter.clear();

                // Mock UserInfo failure
                openidMock.fetchUserInfo.mockRejectedValue(
                    new Error('UserInfo failed'),
                );

                const result = await authenticator.getUser(MOCK_OPAQUE_TOKEN);

                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(mockLogger.getLogsForLevel('warn')).toHaveLength(1);
            });

            it('should handle UserInfo failure during forced introspection', async () => {
                // Force introspection path with existing user
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Existing',
                    lastUserInfoRefresh: Date.now() - 2 * 60 * 60 * 1000,
                };
                mockStorageAdapter.setUser(existingUser);

                // Mock UserInfo failure
                openidMock.fetchUserInfo.mockRejectedValue(
                    new Error('UserInfo failed'),
                );

                const result = await authenticator.getUser(MOCK_JWT_TOKEN, {
                    forceIntrospection: true,
                });

                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(openidMock.tokenIntrospection).toHaveBeenCalled();
                expect(joseMock.jwtVerify).not.toHaveBeenCalled();
            });
        });
    });

    describe('API Call Limiting', () => {
        let authenticator: InstanceType<typeof Authenticator>;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync();
        });

        describe('Token Introspection Call Limiting', () => {
            it('should call tokenIntrospection exactly once per getUser call for opaque tokens', async () => {
                openidMock.tokenIntrospection.mockClear();

                await authenticator.getUser(MOCK_OPAQUE_TOKEN);

                expect(openidMock.tokenIntrospection).toHaveBeenCalledTimes(1);
                expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                    expect.any(Object),
                    MOCK_OPAQUE_TOKEN,
                );
            });

            it('should call tokenIntrospection exactly once per getUser call for JWT with forced introspection', async () => {
                openidMock.tokenIntrospection.mockClear();

                await authenticator.getUser(MOCK_JWT_TOKEN, {
                    forceIntrospection: true,
                });

                expect(openidMock.tokenIntrospection).toHaveBeenCalledTimes(1);
                expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                    expect.any(Object),
                    MOCK_JWT_TOKEN,
                );
            });

            it('should not call tokenIntrospection for JWT tokens without forced introspection', async () => {
                openidMock.tokenIntrospection.mockClear();

                await authenticator.getUser(MOCK_JWT_TOKEN);

                expect(openidMock.tokenIntrospection).not.toHaveBeenCalled();
            });

            it('should call tokenIntrospection only once even when UserInfo also needs fetching for opaque tokens', async () => {
                openidMock.tokenIntrospection.mockClear();
                openidMock.fetchUserInfo.mockClear();

                // Ensure UserInfo will be fetched by clearing storage
                mockStorageAdapter.clear();

                await authenticator.getUser(MOCK_OPAQUE_TOKEN);

                expect(openidMock.tokenIntrospection).toHaveBeenCalledTimes(1);
                expect(openidMock.fetchUserInfo).toHaveBeenCalledTimes(1);
            });
        });

        describe('UserInfo Call Limiting', () => {
            it('should call fetchUserInfo exactly once per getUser call when refresh is needed', async () => {
                openidMock.fetchUserInfo.mockClear();

                // Ensure UserInfo refresh is needed by clearing storage
                mockStorageAdapter.clear();

                await authenticator.getUser(MOCK_JWT_TOKEN);

                expect(openidMock.fetchUserInfo).toHaveBeenCalledTimes(1);
                expect(openidMock.fetchUserInfo).toHaveBeenCalledWith(
                    expect.any(Object),
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS.sub,
                );
            });

            it('should not call fetchUserInfo when refresh is not needed', async () => {
                openidMock.fetchUserInfo.mockClear();

                // Set up recent UserInfo refresh to avoid refresh
                const recentUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Recent User',
                    lastUserInfoRefresh: Date.now() - 30 * 60 * 1000, // 30 minutes ago
                };
                mockStorageAdapter.setUser(recentUser);

                await authenticator.getUser(MOCK_JWT_TOKEN);

                expect(openidMock.fetchUserInfo).not.toHaveBeenCalled();
            });

            it('should call fetchUserInfo exactly once for opaque tokens when refresh is needed', async () => {
                openidMock.fetchUserInfo.mockClear();

                // Ensure UserInfo refresh is needed by clearing storage
                mockStorageAdapter.clear();

                await authenticator.getUser(MOCK_OPAQUE_TOKEN);

                expect(openidMock.fetchUserInfo).toHaveBeenCalledTimes(1);
                expect(openidMock.fetchUserInfo).toHaveBeenCalledWith(
                    expect.any(Object),
                    MOCK_OPAQUE_TOKEN,
                    MOCK_USER_CLAIMS.sub,
                );
            });

            it('should call fetchUserInfo only once even with forced JWT introspection', async () => {
                openidMock.fetchUserInfo.mockClear();
                openidMock.tokenIntrospection.mockClear();

                // Ensure UserInfo refresh is needed by clearing storage
                mockStorageAdapter.clear();

                await authenticator.getUser(MOCK_JWT_TOKEN, {
                    forceIntrospection: true,
                });

                expect(openidMock.fetchUserInfo).toHaveBeenCalledTimes(1);
                expect(openidMock.tokenIntrospection).toHaveBeenCalledTimes(1);
            });

            it('should not call fetchUserInfo multiple times for consecutive calls when cached', async () => {
                openidMock.fetchUserInfo.mockClear();

                // First call should trigger UserInfo fetch
                await authenticator.getUser(MOCK_JWT_TOKEN);
                const firstCallCount = openidMock.fetchUserInfo.mock.calls.length;

                // Second call should use cached data
                await authenticator.getUser(MOCK_JWT_TOKEN);
                const secondCallCount = openidMock.fetchUserInfo.mock.calls.length;

                expect(firstCallCount).toBe(1);
                expect(secondCallCount).toBe(1); // Should not increase
            });
        });

        describe('Combined API Call Limiting', () => {
            it('should limit both tokenIntrospection and fetchUserInfo calls for opaque tokens', async () => {
                openidMock.tokenIntrospection.mockClear();
                openidMock.fetchUserInfo.mockClear();

                // Ensure both calls are needed
                mockStorageAdapter.clear();

                await authenticator.getUser(MOCK_OPAQUE_TOKEN);

                expect(openidMock.tokenIntrospection).toHaveBeenCalledTimes(1);
                expect(openidMock.fetchUserInfo).toHaveBeenCalledTimes(1);
            });

            it('should limit both tokenIntrospection and fetchUserInfo calls for JWT with forced introspection', async () => {
                openidMock.tokenIntrospection.mockClear();
                openidMock.fetchUserInfo.mockClear();

                // Ensure both calls are needed
                mockStorageAdapter.clear();

                await authenticator.getUser(MOCK_JWT_TOKEN, {
                    forceIntrospection: true,
                });

                expect(openidMock.tokenIntrospection).toHaveBeenCalledTimes(1);
                expect(openidMock.fetchUserInfo).toHaveBeenCalledTimes(1);
            });

            it('should handle API call failures without duplicate calls', async () => {
                openidMock.tokenIntrospection.mockClear();
                openidMock.fetchUserInfo.mockClear();

                // Mock introspection failure
                openidMock.tokenIntrospection.mockRejectedValueOnce(
                    new Error('Introspection failed'),
                );

                await expect(
                    authenticator.getUser(MOCK_OPAQUE_TOKEN),
                ).rejects.toThrow('Failed to introspect token');

                // Should have called introspection exactly once
                expect(openidMock.tokenIntrospection).toHaveBeenCalledTimes(1);
                // Should not have called fetchUserInfo due to early failure
                expect(openidMock.fetchUserInfo).not.toHaveBeenCalled();
            });

            it('should handle UserInfo failure without affecting introspection call count', async () => {
                openidMock.tokenIntrospection.mockClear();
                openidMock.fetchUserInfo.mockClear();

                // Mock UserInfo failure
                openidMock.fetchUserInfo.mockRejectedValue(
                    new Error('UserInfo failed'),
                );

                // Ensure UserInfo is attempted
                mockStorageAdapter.clear();

                const result = await authenticator.getUser(MOCK_OPAQUE_TOKEN);

                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(openidMock.tokenIntrospection).toHaveBeenCalledTimes(1);
                expect(openidMock.fetchUserInfo).toHaveBeenCalledTimes(1);

                // Verify warning was logged
                expect(mockLogger.getLogsForLevel('warn')).toHaveLength(1);
            });
        });

        describe('API Call Efficiency with Storage', () => {
            it('should minimize API calls when user data is cached and fresh', async () => {
                openidMock.tokenIntrospection.mockClear();
                openidMock.fetchUserInfo.mockClear();

                // Set up fresh cached user data
                const freshUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Cached User',
                    email: 'cached@example.com',
                    lastUserInfoRefresh: Date.now() - 30 * 60 * 1000, // 30 minutes ago
                    lastIntrospection: Date.now() - 30 * 60 * 1000,
                };
                mockStorageAdapter.setUser(freshUser);

                // Call with JWT (no introspection needed, no UserInfo refresh needed)
                await authenticator.getUser(MOCK_JWT_TOKEN);

                expect(openidMock.tokenIntrospection).not.toHaveBeenCalled();
                expect(openidMock.fetchUserInfo).not.toHaveBeenCalled();
                expect(joseMock.jwtVerify).toHaveBeenCalledTimes(1); // Only JWT verification
            });

            it('should make minimal API calls when only UserInfo refresh is needed', async () => {
                openidMock.tokenIntrospection.mockClear();
                openidMock.fetchUserInfo.mockClear();
                joseMock.jwtVerify.mockClear();

                // Set up user with stale UserInfo but recent other data
                const staleUserInfoUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Stale UserInfo User',
                    lastUserInfoRefresh: Date.now() - 2 * 60 * 60 * 1000, // 2 hours ago
                    lastIntrospection: Date.now() - 30 * 60 * 1000, // 30 minutes ago
                };
                mockStorageAdapter.setUser(staleUserInfoUser);

                await authenticator.getUser(MOCK_JWT_TOKEN);

                expect(openidMock.tokenIntrospection).not.toHaveBeenCalled();
                expect(openidMock.fetchUserInfo).toHaveBeenCalledTimes(1);
                expect(joseMock.jwtVerify).toHaveBeenCalledTimes(1);
            });
        });
    });
});
