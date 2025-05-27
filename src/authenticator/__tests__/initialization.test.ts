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
const { InMemoryStorageAdapter } = await import('../../storage/index.js');

const {
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_JWT_TOKEN,
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

describe('Authenticator - Initialization and Configuration', () => {
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

        it('should handle getUser called immediately during initialization (race condition)', async () => {
            // Set up a slower initialization to simulate race condition
            let resolveDiscovery: (value: any) => void = () => {};
            const discoveryPromise = new Promise((resolve) => {
                resolveDiscovery = resolve;
            });
            openidMock.discovery.mockReturnValue(discoveryPromise as never);

            // Create authenticator (initialization starts immediately)
            const authenticator = new Authenticator(mockConfig);

            // Call getUser immediately without waiting for initialization
            // This should wait for initialization to complete, not throw an error
            const getUserPromise = authenticator.getUser(MOCK_JWT_TOKEN);

            // Complete the initialization
            resolveDiscovery(createMockOpenidClient());

            // getUser should now succeed after waiting for initialization
            const result = await getUserPromise;

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
    });
});
