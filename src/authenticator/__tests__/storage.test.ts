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
const { InMemoryStorageAdapter } = await import('../../storage/index.js');

// Type alias for the authenticated Authenticator with UserClaims
type UserClaimsAuthenticator = InstanceType<typeof Authenticator<UserClaims>>;
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

describe('Authenticator - Storage and Caching', () => {
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

    describe('Storage Integration', () => {
        let authenticator: UserClaimsAuthenticator;

        beforeEach(async () => {
            authenticator = new Authenticator(mockConfig);
            await waitForAsync();
        });

        it('should store user data after successful processing', async () => {
            await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(mockStorageAdapter.storeUserCalls).toHaveLength(1);
            const storedCall = mockStorageAdapter.storeUserCalls[0];
            if (storedCall) {
                expect(storedCall.claims.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(storedCall.metadata.lastUserInfoRefresh).toBeInstanceOf(
                    Date,
                );
                expect(storedCall.metadata.lastIntrospection).toBeUndefined();
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
            const startTime = new Date();

            await authenticator.getUser(MOCK_JWT_TOKEN);

            const storedCall = mockStorageAdapter.storeUserCalls[0];
            if (storedCall) {
                expect(storedCall.metadata.lastUserInfoRefresh).toBeInstanceOf(
                    Date,
                );
                expect(
                    storedCall.metadata.lastUserInfoRefresh!.getTime(),
                ).toBeGreaterThanOrEqual(startTime.getTime());
                expect(storedCall.metadata.lastIntrospection).toBeUndefined();
            }
        });

        it('should update timestamps correctly for opaque tokens', async () => {
            const startTime = new Date();

            await authenticator.getUser(MOCK_OPAQUE_TOKEN);

            const storedCall = mockStorageAdapter.storeUserCalls[0];
            if (storedCall) {
                expect(storedCall.metadata.lastUserInfoRefresh).toBeInstanceOf(
                    Date,
                );
                expect(
                    storedCall.metadata.lastUserInfoRefresh!.getTime(),
                ).toBeGreaterThanOrEqual(startTime.getTime());
                expect(storedCall.metadata.lastIntrospection).toBeInstanceOf(
                    Date,
                );
                expect(
                    storedCall.metadata.lastIntrospection!.getTime(),
                ).toBeGreaterThanOrEqual(startTime.getTime());
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
});
