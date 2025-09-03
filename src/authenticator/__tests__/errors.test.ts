import type { AuthenticatorConfig, UserClaims } from '../../types/index.js';
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

// Type alias for the authenticated Authenticator with UserClaims
type UserClaimsAuthenticator = InstanceType<typeof Authenticator<UserClaims>>;
const {
    MOCK_INTROSPECTION_ACTIVE,
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
} = await import('./test-utils.js');

// Get mocked modules
const joseMock = jest.mocked(await import('jose'));
const openidMock = jest.mocked(await import('openid-client'));

describe('Authenticator - Error Handling and Edge Cases', () => {
    let mockStorageAdapter: InstanceType<typeof MockStorageAdapter<UserClaims>>;
    let mockLogger: InstanceType<typeof MockLogger>;
    let mockConfig: AuthenticatorConfig<UserClaims>;

    beforeEach(() => {
        jest.clearAllMocks();
        mockStorageAdapter = new MockStorageAdapter<UserClaims>();
        mockLogger = new MockLogger();
        mockConfig = createMockConfig<UserClaims>({
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

    describe('Error Handling', () => {
        let authenticator: UserClaimsAuthenticator;

        beforeEach(async () => {
            authenticator = await Authenticator.create(mockConfig);
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
                const brokenAuthenticator = await Authenticator.create(mockConfig);
                
                // Now force the broken state and remove initialization config
                (brokenAuthenticator as any).clientConfig = undefined;
                (brokenAuthenticator as any).initializationConfig = undefined;

                await expect(
                    brokenAuthenticator.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('OIDC client is not initialized');
            });

            it('should throw error when client config missing during token introspection', async () => {
                // Create authenticator and force missing clientConfig during introspection
                const brokenAuthenticator = await Authenticator.create(mockConfig);
                
                // Now force the broken state and remove initialization config
                (brokenAuthenticator as any).clientConfig = undefined;
                (brokenAuthenticator as any).initializationConfig = undefined;

                await expect(
                    brokenAuthenticator.getUser(MOCK_OPAQUE_TOKEN),
                ).rejects.toThrow('OIDC client is not initialized');
            });

            it('should throw error when client config missing during UserInfo fetch', async () => {
                // Set up scenario where UserInfo refresh is needed but clientConfig is missing
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'existing user',
                };
                const existingMetadata = {
                    lastUserInfoRefresh: new Date(
                        Date.now() - 2 * 60 * 60 * 1000,
                    ), // 2 hours ago
                };
                mockStorageAdapter.setUser(existingUser, existingMetadata);

                const brokenAuthenticator = await Authenticator.create(mockConfig);

                // Force clientConfig to be undefined after initialization and remove fallback
                (brokenAuthenticator as any).clientConfig = undefined;
                (brokenAuthenticator as any).initializationConfig = undefined;

                await expect(
                    brokenAuthenticator.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('OIDC client is not initialized');
            });

            it('should throw error when initial discovery fails for token introspection', async () => {
                // Mock discovery to fail so client config won't be set
                openidMock.discovery.mockRejectedValue(
                    new Error('Discovery failed'),
                );

                await expect(
                    Authenticator.create(mockConfig),
                ).rejects.toThrow('Failed to discover OIDC issuer or create client: Discovery failed');
            });

            it('should throw error when initial discovery fails for UserInfo fetch', async () => {
                // Mock discovery to fail so client config won't be set
                openidMock.discovery.mockRejectedValue(
                    new Error('Discovery failed'),
                );

                await expect(
                    Authenticator.create(mockConfig),
                ).rejects.toThrow('Failed to discover OIDC issuer or create client: Discovery failed');
            });            it('should log warning when UserInfo endpoint is missing from server metadata', async () => {
                const mockClientNoUserInfo = {
                    serverMetadata: jest.fn().mockReturnValue({
                        jwks_uri: 'https://example.com/.well-known/jwks.json',
                        // No userinfo_endpoint
                    }),
                };
                openidMock.discovery.mockResolvedValue(
                    mockClientNoUserInfo as any,
                );

                const noUserInfoAuth = await Authenticator.create(mockConfig);

                // Force UserInfo refresh by having old timestamp
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                };
                const existingMetadata = {
                    lastUserInfoRefresh: new Date(
                        Date.now() - 2 * 60 * 60 * 1000,
                    ),
                };
                mockStorageAdapter.setUser(existingUser, existingMetadata);

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

                const noUserInfoAuth = await Authenticator.create(throwConfig);

                // Force UserInfo refresh by having old timestamp
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                };
                const existingMetadata = {
                    lastUserInfoRefresh: new Date(
                        Date.now() - 2 * 60 * 60 * 1000,
                    ),
                };
                mockStorageAdapter.setUser(existingUser, existingMetadata);

                await expect(
                    noUserInfoAuth.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow(
                    'Failed to fetch UserInfo: Failed to fetch user info: No UserInfo endpoint found in server metadata',
                );
            });
        });

        describe('Missing Sub Claim Validation', () => {
            it('should fallback to introspection when JWT tokens have missing sub claim', async () => {
                joseMock.jwtVerify.mockResolvedValue({
                    payload: { name: 'John Doe' }, // Missing 'sub' claim
                    protectedHeader: { alg: 'RS256', typ: 'JWT' },
                } as any);

                const result = await authenticator.getUser(MOCK_JWT_TOKEN);

                // Should fallback to introspection when JWT validation fails
                expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                    expect.any(Object),
                    MOCK_JWT_TOKEN,
                );
                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
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
                };
                const existingMetadata = {
                    lastUserInfoRefresh: new Date(
                        Date.now() - 2 * 60 * 60 * 1000,
                    ), // 2 hours ago
                };
                mockStorageAdapter.setUser(existingUser, existingMetadata);

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
                const storedCall = mockStorageAdapter.storeUserCalls[0];
                expect(storedCall?.claims['name']).toBe(
                    MOCK_USER_CLAIMS['name'],
                );
            });

            it('should throw error when UserInfo fails and throwOnUserInfoFailure is enabled', async () => {
                const throwConfig = createMockConfig({
                    storageAdapter: mockStorageAdapter,
                    logger: mockLogger,
                    throwOnUserInfoFailure: true,
                });

                const throwAuth = await Authenticator.create(throwConfig);

                // Set up existing user record
                const existingUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Existing User',
                };
                const existingMetadata = {
                    lastUserInfoRefresh: new Date(
                        Date.now() - 2 * 60 * 60 * 1000,
                    ),
                };
                mockStorageAdapter.setUser(existingUser, existingMetadata);

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
                };
                const metadataWithoutTimestamp = {
                    // Missing lastUserInfoRefresh
                };
                mockStorageAdapter.setUser(
                    userWithoutTimestamp,
                    metadataWithoutTimestamp,
                );

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

                const alwaysRefreshAuth = await Authenticator.create(
                    alwaysRefreshConfig,
                );

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
                const authenticator = await Authenticator.create(mockConfig);

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
                expect(storedUser?.user.sub).toBe(MOCK_USER_CLAIMS.sub);
            });

            it('should preserve timestamps when UserInfo refresh is not needed', async () => {
                const authenticator = await Authenticator.create(mockConfig);

                // Set up a user that does NOT need UserInfo refresh due to very recent refresh
                const recentUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Existing User',
                    email: 'existing@example.com',
                };
                const recentMetadata = {
                    lastUserInfoRefresh: new Date(Date.now() - 30 * 1000), // 30 seconds ago (very recent)
                    lastIntrospection: new Date(Date.now() - 30 * 1000), // 30 seconds ago
                };
                mockStorageAdapter.setUser(recentUser, recentMetadata);

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
                expect(storedUser?.user.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(storedUser?.metadata.lastUserInfoRefresh).toEqual(
                    recentMetadata.lastUserInfoRefresh,
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
                };
                const existingMetadata = {
                    lastUserInfoRefresh: new Date(
                        Date.now() - 2 * 60 * 60 * 1000,
                    ),
                };
                mockStorageAdapter.setUser(existingUser, existingMetadata);

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
            it('should fail to create authenticator when OIDC discovery fails', async () => {
                // Mock discovery to fail
                openidMock.discovery.mockRejectedValue(
                    new Error('Discovery failed'),
                );

                await expect(
                    Authenticator.create(mockConfig),
                ).rejects.toThrow('Failed to discover OIDC issuer or create client: Discovery failed');
            });

            it('should reject requests when client config is manually corrupted', async () => {
                const authenticator = await Authenticator.create(mockConfig);

                // Force partial initialization state after successful init
                (authenticator as any).clientConfig = null;
                (authenticator as any).initializationConfig = null;

                await expect(
                    authenticator.getUser(MOCK_JWT_TOKEN),
                ).rejects.toThrow('OIDC client is not initialized');
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

    describe('Edge Cases', () => {
        let authenticator: UserClaimsAuthenticator;

        beforeEach(async () => {
            authenticator = await Authenticator.create(mockConfig);
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
