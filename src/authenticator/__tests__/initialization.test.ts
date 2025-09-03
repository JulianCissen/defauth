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

const {
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_JWT_TOKEN,
    MOCK_USERINFO_RESPONSE,
    MockLogger,
    MockStorageAdapter,
    createMockConfig,
    createMockJwtVerifyResult,
    createMockOpenidClient,
} = await import('./test-utils.js');

// Get mocked modules
const joseMock = jest.mocked(await import('jose'));
const openidMock = jest.mocked(await import('openid-client'));

describe('Authenticator - Initialization and Configuration', () => {
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

    describe('Static Create Method and Initialization', () => {
        it('should create authenticator with default configuration using static method', async () => {
            const config = createMockConfig();
            const authenticator = await Authenticator.create(config);

            expect(authenticator).toBeDefined();
            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
            );

            // Should be ready to use immediately
            const result = await authenticator.getUser(MOCK_JWT_TOKEN);
            expect(result).toBeDefined();
        });

        it('should create authenticator using static create method', async () => {
            const config = createMockConfig();
            const authenticator = await Authenticator.create(config);

            // Verify authenticator was created successfully and is ready
            expect(authenticator).toBeDefined();
            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
            );

            // Should be able to call getUser immediately without race conditions
            const result = await authenticator.getUser(MOCK_JWT_TOKEN);
            expect(result).toBeDefined();
        });

        it('should throw InitializationError from static create method on discovery failure', async () => {
            const discoveryError = new Error('Discovery failed');
            openidMock.discovery.mockRejectedValue(discoveryError);

            await expect(Authenticator.create(mockConfig)).rejects.toThrow(
                'Failed to discover OIDC issuer or create client: Discovery failed',
            );
        });

        it('should use provided storage adapter with static create method', async () => {
            const customAdapter = new InMemoryStorageAdapter();
            const config = createMockConfig({ storageAdapter: customAdapter });

            const authenticator = await Authenticator.create(config);

            expect(authenticator).toBeDefined();
            expect(config.storageAdapter).toBe(customAdapter);
        });
    });
});
