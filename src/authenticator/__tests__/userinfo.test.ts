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
    MOCK_CLIENT_ID,
    MOCK_CLIENT_SECRET,
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_ISSUER,
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

describe('Authenticator - UserInfo Integration and Management', () => {
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

    describe('UserInfo Integration', () => {
        let authenticator: UserClaimsAuthenticator;

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

    describe('UserInfo Strategy', () => {
        let authenticator: UserClaimsAuthenticator;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync();
        });

        describe('afterUserRetrieval (default strategy)', () => {
            it('should fetch UserInfo after user retrieval by default', async () => {
                // Default behavior should be afterUserRetrieval
                const result = await authenticator.getUser(MOCK_JWT_TOKEN);

                expect(result).toEqual(
                    expect.objectContaining({
                        sub: MOCK_USER_CLAIMS.sub,
                        name: MOCK_USERINFO_RESPONSE.name,
                        email: MOCK_USERINFO_RESPONSE.email,
                    }),
                );

                // Verify storage lookup happened first
                expect(mockStorageAdapter.findUserCalls).toHaveLength(1);

                // Verify UserInfo was called after storage lookup (in processUserClaims)
                expect(openidMock.fetchUserInfo).toHaveBeenCalledWith(
                    expect.any(Object),
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS.sub,
                );

                // In afterUserRetrieval strategy, UserInfo is not fetched before storage lookup
                // so TokenContext doesn't have userInfoResult
                const tokenContext = mockStorageAdapter.findUserCalls[0];
                expect(tokenContext?.userInfoResult).toBeUndefined();
            });

            it('should respect userInfoRefreshCondition in afterUserRetrieval strategy', async () => {
                const customCondition = jest.fn().mockReturnValue(false);
                const authenticatorWithCondition = new Authenticator({
                    issuer: MOCK_ISSUER,
                    clientId: MOCK_CLIENT_ID,
                    clientSecret: MOCK_CLIENT_SECRET,
                    storageAdapter: mockStorageAdapter,
                    userInfoRefreshCondition: customCondition as any,
                    userInfoStrategy: 'afterUserRetrieval',
                });

                // Store a user first
                await authenticatorWithCondition.getUser(MOCK_JWT_TOKEN);
                jest.clearAllMocks();

                // Second call should not fetch UserInfo due to condition
                await authenticatorWithCondition.getUser(MOCK_JWT_TOKEN);

                expect(openidMock.fetchUserInfo).not.toHaveBeenCalled();
                expect(customCondition).toHaveBeenCalled();
            });
        });

        describe('beforeUserRetrieval strategy', () => {
            let beforeRetrievalAuthenticator: UserClaimsAuthenticator;

            beforeEach(() => {
                beforeRetrievalAuthenticator = new Authenticator({
                    issuer: MOCK_ISSUER,
                    clientId: MOCK_CLIENT_ID,
                    clientSecret: MOCK_CLIENT_SECRET,
                    storageAdapter: mockStorageAdapter,
                    userInfoStrategy: 'beforeUserRetrieval',
                });
            });

            it('should fetch UserInfo before user retrieval', async () => {
                const result =
                    await beforeRetrievalAuthenticator.getUser(MOCK_JWT_TOKEN);

                expect(result).toEqual(
                    expect.objectContaining({
                        sub: MOCK_USER_CLAIMS.sub,
                        name: MOCK_USERINFO_RESPONSE.name,
                        email: MOCK_USERINFO_RESPONSE.email,
                    }),
                );

                // Verify UserInfo was called before storage lookup
                expect(openidMock.fetchUserInfo).toHaveBeenCalledWith(
                    expect.any(Object),
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS.sub,
                );

                // Verify TokenContext includes userInfoResult
                expect(mockStorageAdapter.findUserCalls).toHaveLength(1);
                const tokenContext = mockStorageAdapter.findUserCalls[0];
                expect(tokenContext?.userInfoResult).toEqual(
                    MOCK_USERINFO_RESPONSE,
                );
            });

            it('should handle UserInfo failure gracefully in beforeUserRetrieval strategy', async () => {
                openidMock.fetchUserInfo.mockRejectedValueOnce(
                    new Error('UserInfo failed'),
                );

                const result =
                    await beforeRetrievalAuthenticator.getUser(MOCK_JWT_TOKEN);

                // Should still return user with JWT claims
                expect(result).toEqual(
                    expect.objectContaining({
                        sub: MOCK_USER_CLAIMS.sub,
                    }),
                );

                // Verify UserInfo failure was handled
                expect(openidMock.fetchUserInfo).toHaveBeenCalled();

                // Verify TokenContext doesn't have userInfoResult when failed
                const tokenContext = mockStorageAdapter.findUserCalls[0];
                expect(tokenContext?.userInfoResult).toBeUndefined();
            });

            it('should always fetch UserInfo in beforeUserRetrieval strategy (condition ignored)', async () => {
                const mockCondition = jest.fn().mockReturnValue(false);
                const conditionalAuthenticator = new Authenticator({
                    issuer: MOCK_ISSUER,
                    clientId: MOCK_CLIENT_ID,
                    clientSecret: MOCK_CLIENT_SECRET,
                    storageAdapter: mockStorageAdapter,
                    userInfoStrategy: 'beforeUserRetrieval',
                    userInfoRefreshCondition: mockCondition as any,
                });

                await conditionalAuthenticator.getUser(MOCK_JWT_TOKEN);

                // In beforeUserRetrieval strategy, UserInfo is always fetched regardless of condition
                expect(openidMock.fetchUserInfo).toHaveBeenCalled();
                // The condition is not checked in beforeUserRetrieval strategy for simplicity
                expect(mockCondition).not.toHaveBeenCalled();

                // Verify TokenContext DOES have userInfoResult since it was fetched
                const tokenContext = mockStorageAdapter.findUserCalls[0];
                expect(tokenContext?.userInfoResult).toEqual(
                    MOCK_USERINFO_RESPONSE,
                );
            });

            it('should work with opaque tokens in beforeUserRetrieval strategy', async () => {
                const result =
                    await beforeRetrievalAuthenticator.getUser(
                        MOCK_OPAQUE_TOKEN,
                    );

                expect(result).toEqual(
                    expect.objectContaining({
                        sub: MOCK_USER_CLAIMS.sub,
                        name: MOCK_USERINFO_RESPONSE.name,
                        email: MOCK_USERINFO_RESPONSE.email,
                    }),
                );

                // Verify UserInfo was called
                expect(openidMock.fetchUserInfo).toHaveBeenCalledWith(
                    expect.any(Object),
                    MOCK_OPAQUE_TOKEN,
                    MOCK_USER_CLAIMS.sub,
                );

                // Verify TokenContext includes userInfoResult
                const tokenContext = mockStorageAdapter.findUserCalls[0];
                expect(tokenContext?.userInfoResult).toEqual(
                    MOCK_USERINFO_RESPONSE,
                );
                expect(tokenContext?.introspectionResponse).toBeDefined();
            });

            it('should combine claims correctly with UserInfo taking priority', async () => {
                const jwtClaimsWithEmail = {
                    ...MOCK_JWT_PAYLOAD,
                    email: 'jwt@example.com',
                    name: 'JWT Name',
                };

                joseMock.jwtVerify.mockResolvedValueOnce(
                    createMockJwtVerifyResult(jwtClaimsWithEmail) as never,
                );

                const userInfoClaims = {
                    sub: MOCK_USER_CLAIMS.sub,
                    email: 'userinfo@example.com',
                    name: 'UserInfo Name',
                    phone: '+1234567890',
                };

                openidMock.fetchUserInfo.mockResolvedValueOnce(userInfoClaims);

                const result =
                    await beforeRetrievalAuthenticator.getUser(MOCK_JWT_TOKEN);

                // UserInfo claims should take priority
                expect(result).toEqual(
                    expect.objectContaining({
                        sub: MOCK_USER_CLAIMS.sub,
                        email: 'userinfo@example.com', // UserInfo priority
                        name: 'UserInfo Name', // UserInfo priority
                        phone: '+1234567890', // Only in UserInfo
                    }),
                );
            });
        });

        describe('Configuration', () => {
            it('should default to afterUserRetrieval strategy when not specified', () => {
                const defaultAuthenticator = new Authenticator({
                    issuer: MOCK_ISSUER,
                    clientId: MOCK_CLIENT_ID,
                    clientSecret: MOCK_CLIENT_SECRET,
                });

                // The userInfoStrategy should be set to default value
                expect((defaultAuthenticator as any).userInfoStrategy).toBe(
                    'afterUserRetrieval',
                );
            });

            it('should accept beforeUserRetrieval strategy in configuration', () => {
                const beforeAuthenticator = new Authenticator({
                    issuer: MOCK_ISSUER,
                    clientId: MOCK_CLIENT_ID,
                    clientSecret: MOCK_CLIENT_SECRET,
                    userInfoStrategy: 'beforeUserRetrieval',
                });

                expect((beforeAuthenticator as any).userInfoStrategy).toBe(
                    'beforeUserRetrieval',
                );
            });
        });
    });
});
