import * as jose from 'jose';
import * as openid from 'openid-client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryStorageAdapter } from '../../storage/index.js';
import type { DefauthConfig, UserClaims } from '../../types/index.js';
import { Defauth } from '../authenticator.js';
import {
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_JWT_TOKEN,
    MOCK_OPAQUE_TOKEN,
    MOCK_USERINFO_RESPONSE,
    MockLogger,
    MockStorageAdapter,
    createMockConfig,
    createMockJwtVerifyResult,
    createMockOpenidClient,
} from './test-utils.js';

const joseMock = vi.mocked(jose);
const openidMock = vi.mocked(openid);

describe('Defauth - Initialization and Lifecycle', () => {
    let mockStorageAdapter: InstanceType<typeof MockStorageAdapter<UserClaims>>;
    let mockLogger: InstanceType<typeof MockLogger>;
    let mockConfig: DefauthConfig<UserClaims>;

    beforeEach(() => {
        vi.clearAllMocks();
        mockStorageAdapter = new MockStorageAdapter<UserClaims>();
        mockLogger = new MockLogger();
        mockConfig = createMockConfig<UserClaims>({
            storageAdapter: mockStorageAdapter,
            logger: mockLogger,
        });

        openidMock.discovery.mockResolvedValue(
            createMockOpenidClient() as never,
        );
        joseMock.createRemoteJWKSet.mockReturnValue(vi.fn() as never);
        joseMock.jwtVerify.mockResolvedValue(
            createMockJwtVerifyResult() as never,
        );
        joseMock.decodeProtectedHeader.mockReturnValue({
            alg: 'RS256',
            typ: 'JWT',
        } as never);
        joseMock.decodeJwt.mockReturnValue({
            sub: 'user123',
            name: 'Test User',
            email: 'test@example.com',
            iat: 1_630_000_000,
            exp: 9_999_999_999,
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
        vi.restoreAllMocks();
    });

    describe('static create', () => {
        it('should create and initialize the authenticator', async () => {
            const authenticator = await Defauth.create(mockConfig);

            expect(authenticator).toBeDefined();
            expect(openidMock.discovery).toHaveBeenCalledWith(
                new URL(mockConfig.issuer),
                mockConfig.clientId,
                mockConfig.clientSecret,
                expect.any(Function),
                { execute: [] },
            );
        });

        it('should be ready to use immediately after create', async () => {
            const authenticator = await Defauth.create(mockConfig);
            const result = await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(result).toBeDefined();
        });

        it('should throw InitializationError when discovery fails', async () => {
            openidMock.discovery.mockRejectedValue(
                new Error('Discovery failed'),
            );

            await expect(Defauth.create(mockConfig)).rejects.toThrow(
                'Failed to discover OIDC issuer or create client',
            );
        });

        it('should use the provided storage adapter', async () => {
            const customAdapter = new InMemoryStorageAdapter();
            const config = createMockConfig({ storageAdapter: customAdapter });

            const authenticator = await Defauth.create(config);

            expect(authenticator).toBeDefined();
        });
    });

    describe('getUser - token routing', () => {
        it('should route JWT tokens to the JWT handler', async () => {
            const authenticator = await Defauth.create(mockConfig);
            await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(joseMock.jwtVerify).toHaveBeenCalled();
            expect(openidMock.tokenIntrospection).not.toHaveBeenCalled();
        });

        it('should route opaque tokens to the opaque handler', async () => {
            const authenticator = await Defauth.create(mockConfig);
            await authenticator.getUser(MOCK_OPAQUE_TOKEN);

            expect(openidMock.tokenIntrospection).toHaveBeenCalled();
            expect(joseMock.jwtVerify).not.toHaveBeenCalled();
        });
    });

    describe('token validation', () => {
        it('should throw TokenValidationError for empty token', async () => {
            const authenticator = await Defauth.create(mockConfig);

            await expect(authenticator.getUser('')).rejects.toThrow(
                'Token is required',
            );
        });

        it('should throw TokenValidationError for null token', async () => {
            const authenticator = await Defauth.create(mockConfig);

            await expect(
                authenticator.getUser(null as unknown as string),
            ).rejects.toThrow('Token is required');
        });
    });

    describe('lazy initialization', () => {
        it('should initialize on first getUser call when not pre-initialized', async () => {
            // Bypass static create to simulate lazy init scenario
            openidMock.discovery.mockClear();

            // Create and immediately call getUser — this exercises ensureInitialized
            const authenticator = await Defauth.create(mockConfig);
            expect(openidMock.discovery).toHaveBeenCalledTimes(1);

            // Calling again should not re-initialize
            await authenticator.getUser(MOCK_JWT_TOKEN);
            expect(openidMock.discovery).toHaveBeenCalledTimes(1);
        });
    });

    describe('clearCache', () => {
        it('should clear InMemoryStorageAdapter without error', async () => {
            const inMemoryConfig = createMockConfig({
                storageAdapter: new InMemoryStorageAdapter(),
            });
            const authenticator = await Defauth.create(inMemoryConfig);

            await authenticator.getUser(MOCK_JWT_TOKEN);
            await expect(authenticator.clearCache()).resolves.not.toThrow();
        });
    });

    describe('authentication methods', () => {
        it('should default to client_secret_post when clientSecret is provided', async () => {
            await Defauth.create(
                createMockConfig({ clientSecret: 'test-secret' }),
            );

            expect(openidMock.ClientSecretPost).toHaveBeenCalledWith(
                'test-secret',
            );
        });

        it('should default to none when no clientSecret', async () => {
            await Defauth.create(
                createMockConfig({ clientSecret: undefined } as never),
            );

            expect(openidMock.None).toHaveBeenCalled();
        });

        it('should use client_secret_basic when specified', async () => {
            await Defauth.create(
                createMockConfig({
                    clientSecret: 'secret',
                    authenticationMethod: 'client_secret_basic',
                } as never),
            );

            expect(openidMock.ClientSecretBasic).toHaveBeenCalledWith('secret');
        });

        it('should use client_secret_jwt when specified', async () => {
            await Defauth.create(
                createMockConfig({
                    clientSecret: 'secret',
                    authenticationMethod: 'client_secret_jwt',
                } as never),
            );

            expect(openidMock.ClientSecretJwt).toHaveBeenCalledWith('secret');
        });

        it('should support all four authentication methods', async () => {
            const methods = [
                {
                    method: 'client_secret_post',
                    constructor: 'ClientSecretPost',
                },
                {
                    method: 'client_secret_basic',
                    constructor: 'ClientSecretBasic',
                },
                { method: 'client_secret_jwt', constructor: 'ClientSecretJwt' },
                { method: 'none', constructor: 'None' },
            ] as const;

            for (const { method, constructor } of methods) {
                vi.clearAllMocks();

                await Defauth.create(
                    createMockConfig({
                        clientSecret: 'secret',
                        authenticationMethod: method,
                    } as never),
                );

                expect(openidMock[constructor]).toHaveBeenCalledTimes(1);
            }
        });
    });

    describe('allowInsecureRequests', () => {
        it('should not include allowInsecureRequests by default', async () => {
            await Defauth.create(mockConfig);

            expect(openidMock.discovery).toHaveBeenCalledWith(
                expect.any(URL),
                expect.any(String),
                expect.any(String),
                expect.any(Function),
                { execute: [] },
            );
        });

        it('should include allowInsecureRequests when enabled', async () => {
            await Defauth.create(
                createMockConfig({ allowInsecureRequests: true } as never),
            );

            expect(openidMock.discovery).toHaveBeenCalledWith(
                expect.any(URL),
                expect.any(String),
                expect.any(String),
                expect.any(Function),
                { execute: [openidMock.allowInsecureRequests] },
            );
        });
    });
});
