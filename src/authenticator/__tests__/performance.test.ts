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

describe('Authenticator - Performance and API Call Optimization', () => {
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

    describe('API Call Limiting', () => {
        let authenticator: UserRecordAuthenticator;

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

                // Set up a user that does NOT need UserInfo refresh (recent refresh)
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
                const firstCallCount =
                    openidMock.fetchUserInfo.mock.calls.length;

                // Second call should use cached data
                await authenticator.getUser(MOCK_JWT_TOKEN);
                const secondCallCount =
                    openidMock.fetchUserInfo.mock.calls.length;

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
