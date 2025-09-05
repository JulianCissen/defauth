import type { DefauthConfig, UserClaims } from '../../types/index.js';
import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

const {
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_JWT_TOKEN,
    MOCK_USERINFO_RESPONSE,
    MockLogger,
    MockStorageAdapter,
    createMockConfig,
    createMockJwtVerifyResult,
    createMockOpenidClient,
    setupModuleMocks,
} = await import('./test-utils.js');

// Get mocked modules
const { joseMock, openidMock } = await setupModuleMocks();

// Import modules after mocking
const { Defauth } = await import('../defauth.js');
const { InMemoryStorageAdapter } = await import('../../storage/index.js');

describe('Defauth - Initialization and Configuration', () => {
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

    describe('Static Create Method and Initialization', () => {
        it('should create authenticator with default configuration using static method', async () => {
            const config = createMockConfig();
            const authenticator = await Defauth.create(config);

            expect(authenticator).toBeDefined();
            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
                expect.any(Function),
                { execute: [] },
            );

            // Should be ready to use immediately
            const result = await authenticator.getUser(MOCK_JWT_TOKEN);
            expect(result).toBeDefined();
        });

        it('should create authenticator using static create method', async () => {
            const config = createMockConfig();
            const authenticator = await Defauth.create(config);

            // Verify authenticator was created successfully and is ready
            expect(authenticator).toBeDefined();
            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
                expect.any(Function),
                { execute: [] },
            );

            // Should be able to call getUser immediately without race conditions
            const result = await authenticator.getUser(MOCK_JWT_TOKEN);
            expect(result).toBeDefined();
        });

        it('should throw InitializationError from static create method on discovery failure', async () => {
            const discoveryError = new Error('Discovery failed');
            openidMock.discovery.mockRejectedValue(discoveryError);

            await expect(Defauth.create(mockConfig)).rejects.toThrow(
                'Failed to discover OIDC issuer or create client: Discovery failed',
            );
        });

        it('should use provided storage adapter with static create method', async () => {
            const customAdapter = new InMemoryStorageAdapter();
            const config = createMockConfig({ storageAdapter: customAdapter });

            const authenticator = await Defauth.create(config);

            expect(authenticator).toBeDefined();
            expect(config.storageAdapter).toBe(customAdapter);
        });
    });

    describe('Authentication Method and Security Configuration', () => {
        it('should use client_secret_post as default authentication method when client secret is provided', async () => {
            const config = createMockConfig({
                clientSecret: 'test-secret',
                // No authenticationMethod specified, should default to client_secret_post
            });

            await Defauth.create(config);

            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
                expect.any(Function),
                { execute: [] },
            );

            // Verify ClientSecretPost constructor was called with the client secret
            expect(openidMock.ClientSecretPost).toHaveBeenCalledTimes(1);
            expect(openidMock.ClientSecretPost).toHaveBeenCalledWith(
                config.clientSecret,
            );
        });

        it('should use none authentication method as default when no client secret is provided', async () => {
            const config = createMockConfig({
                clientSecret: undefined,
                // Should default to 'none' authentication method
            } as any);

            await Defauth.create(config);

            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                undefined,
                expect.any(Function),
                { execute: [] },
            );

            // Verify None constructor was called
            expect(openidMock.None).toHaveBeenCalledTimes(1);
            expect(openidMock.None).toHaveBeenCalledWith();
        });

        it('should use custom authentication method when explicitly specified', async () => {
            const config = createMockConfig({
                clientSecret: 'test-secret',
                authenticationMethod: 'client_secret_basic',
            } as any);

            await Defauth.create(config);

            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
                expect.any(Function),
                { execute: [] },
            );

            // Verify ClientSecretBasic constructor was called with the client secret
            expect(openidMock.ClientSecretBasic).toHaveBeenCalledTimes(1);
            expect(openidMock.ClientSecretBasic).toHaveBeenCalledWith(
                config.clientSecret,
            );
        });

        it('should allow all authentication methods with client secret', async () => {
            const testCases = [
                {
                    method: 'client_secret_post',
                    constructor: 'ClientSecretPost',
                    expectSecret: true,
                },
                {
                    method: 'client_secret_basic',
                    constructor: 'ClientSecretBasic',
                    expectSecret: true,
                },
                {
                    method: 'client_secret_jwt',
                    constructor: 'ClientSecretJwt',
                    expectSecret: true,
                },
                { method: 'none', constructor: 'None', expectSecret: false },
            ] as const;

            for (const { method, constructor, expectSecret } of testCases) {
                jest.clearAllMocks();

                const config = createMockConfig({
                    clientSecret: 'test-secret',
                    authenticationMethod: method,
                } as any);

                await Defauth.create(config);

                expect(openidMock.discovery).toHaveBeenCalledWith(
                    new URL(config.issuer),
                    config.clientId,
                    config.clientSecret,
                    expect.any(Function),
                    { execute: [] },
                );

                // Verify the correct authentication method constructor was called
                expect(openidMock[constructor]).toHaveBeenCalledTimes(1);
                if (expectSecret) {
                    expect(openidMock[constructor]).toHaveBeenCalledWith(
                        config.clientSecret,
                    );
                } else {
                    expect(openidMock[constructor]).toHaveBeenCalledWith();
                }
            }
        });

        it('should not allow insecure requests by default', async () => {
            const config = createMockConfig({
                // allowInsecureRequests not specified, should default to false
            });

            await Defauth.create(config);

            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
                expect.any(Function),
                { execute: [] },
            );

            // Verify default authentication method is used
            expect(openidMock.ClientSecretPost).toHaveBeenCalledTimes(1);
            expect(openidMock.ClientSecretPost).toHaveBeenCalledWith(
                config.clientSecret,
            );
        });

        it('should allow insecure requests when explicitly enabled', async () => {
            const config = createMockConfig({
                allowInsecureRequests: true,
            } as any);

            await Defauth.create(config);

            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
                expect.any(Function),
                { execute: [openidMock.allowInsecureRequests] },
            );

            // Verify default authentication method is still used
            expect(openidMock.ClientSecretPost).toHaveBeenCalledTimes(1);
            expect(openidMock.ClientSecretPost).toHaveBeenCalledWith(
                config.clientSecret,
            );
        });

        it('should disable insecure requests when explicitly disabled', async () => {
            const config = createMockConfig({
                allowInsecureRequests: false,
            } as any);

            await Defauth.create(config);

            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
                expect.any(Function),
                { execute: [] },
            );

            // Verify default authentication method is used
            expect(openidMock.ClientSecretPost).toHaveBeenCalledTimes(1);
            expect(openidMock.ClientSecretPost).toHaveBeenCalledWith(
                config.clientSecret,
            );
        });

        it('should combine custom authentication method with insecure requests', async () => {
            const config = createMockConfig({
                clientSecret: 'test-secret',
                authenticationMethod: 'client_secret_jwt',
                allowInsecureRequests: true,
            } as any);

            await Defauth.create(config);

            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
                expect.any(Function),
                { execute: [openidMock.allowInsecureRequests] },
            );

            // Verify ClientSecretJwt constructor was called
            expect(openidMock.ClientSecretJwt).toHaveBeenCalledTimes(1);
            expect(openidMock.ClientSecretJwt).toHaveBeenCalledWith(
                config.clientSecret,
            );
        });
    });
});
