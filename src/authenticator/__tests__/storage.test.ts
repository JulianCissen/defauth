import type {
    DefauthConfig,
    StorageMetadata,
    UserClaims,
} from '../../types/index.js';
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
const { Defauth } = await import('../defauth.js');
const { InMemoryStorageAdapter } = await import('../../storage/index.js');

// Type alias for the authenticated Defauth with UserClaims
type UserClaimsDefauth = Awaited<ReturnType<typeof Defauth.create<UserClaims>>>;
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
} = await import('./test-utils.js');

// Get mocked modules
const joseMock = jest.mocked(await import('jose'));
const openidMock = jest.mocked(await import('openid-client'));

describe('Defauth - Storage and Caching', () => {
    let mockStorageAdapter: InstanceType<typeof MockStorageAdapter<UserClaims>>;
    let mockLogger: InstanceType<typeof MockLogger>;
    let mockConfig: DefauthConfig<UserClaims>;

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
        let authenticator: UserClaimsDefauth;

        beforeEach(async () => {
            authenticator = await Defauth.create(mockConfig);
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

        it('should update lastIntrospection when existing metadata is found for opaque tokens', async () => {
            // This test verifies the bug fix where lastIntrospection metadata would not be set
            // in handleOpaqueToken when a metadata object was returned from storage (only when null was returned).
            // The bug was that `metadata.lastIntrospection = new Date()` was only set in the else branch
            // when userRecord?.metadata was null, but not when existing metadata was found.

            // Set up existing user with existing metadata (the bug scenario)
            const existingUser = {
                sub: MOCK_USER_CLAIMS.sub,
                name: 'Existing User',
                email: 'existing@example.com',
            };
            const existingMetadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
                lastIntrospection: new Date(Date.now() - 10 * 60 * 1000), // 10 minutes ago
            };
            mockStorageAdapter.setUser(existingUser, existingMetadata);

            const startTime = new Date();

            // Process opaque token - this should update lastIntrospection even with existing metadata
            await authenticator.getUser(MOCK_OPAQUE_TOKEN);

            // Verify that lastIntrospection was set in the stored call
            const storedCall = mockStorageAdapter.storeUserCalls[0];
            expect(storedCall).toBeDefined();
            if (storedCall) {
                // The key assertion: lastIntrospection should be defined and updated
                // even when existing metadata was found from storage
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
            const inMemoryDefauth = await Defauth.create(inMemoryConfig);

            // Store some data
            await inMemoryDefauth.getUser(MOCK_JWT_TOKEN);

            // Clear cache
            await expect(inMemoryDefauth.clearCache()).resolves.not.toThrow();
        });
    });
});
